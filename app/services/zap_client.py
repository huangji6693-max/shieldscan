import asyncio
import logging
from typing import Any, Callable

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

ZAP_SCAN_POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "scan_policy_name": "",
        "spider_max_children": 30,
        "ajax_spider_enabled": False,
        "ajax_max_duration_mins": 2,
        "spider_timeout": 90,
        "active_timeout": 180,
        "passive_timeout": 45,
        "attack_strength": "LOW",
        "alert_threshold": "MEDIUM",
    },
    "standard": {
        "scan_policy_name": "",
        "spider_max_children": 100,
        "ajax_spider_enabled": True,
        "ajax_max_duration_mins": 5,
        "spider_timeout": 300,
        "active_timeout": 600,
        "passive_timeout": 90,
        "attack_strength": "MEDIUM",
        "alert_threshold": "MEDIUM",
    },
    "deep": {
        "scan_policy_name": "",
        "spider_max_children": 250,
        "ajax_spider_enabled": True,
        "ajax_max_duration_mins": 10,
        "spider_timeout": 600,
        "active_timeout": 1200,
        "passive_timeout": 180,
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
    },
}


class ZAPClient:
    """Client for OWASP ZAP REST API with timeout hardening and policy profiles."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
        poll_interval: float = 2.0,
    ):
        self.base_url = settings.zap_api_url.rstrip("/")
        self.api_key = settings.zap_api_key
        self.policy_name = getattr(settings, "zap_scan_policy", "standard").strip().lower()
        self.policy = self.get_policy_config(self.policy_name)
        self.spider_timeout = getattr(settings, "scan_spider_timeout", self.policy["spider_timeout"])
        self.ajax_spider_timeout = getattr(settings, "scan_ajax_spider_timeout", 120)
        self.passive_timeout = getattr(settings, "scan_passive_timeout", self.policy["passive_timeout"])
        self.active_timeout = getattr(settings, "scan_active_timeout", self.policy["active_timeout"])
        self.transport = transport
        self.poll_interval = poll_interval

    @staticmethod
    def get_policy_config(profile: str = "standard") -> dict[str, Any]:
        key = (profile or "standard").strip().lower()
        return dict(ZAP_SCAN_POLICY_PROFILES.get(key, ZAP_SCAN_POLICY_PROFILES["standard"]))

    def _client(self, timeout: float = 30.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self.transport)

    def _params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        params = {"apikey": self.api_key}
        if extra:
            params.update(extra)
        return params

    async def is_available(self) -> bool:
        try:
            async with self._client(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/JSON/core/view/version/", params=self._params())
                return resp.status_code == 200 and "version" in resp.json()
        except Exception as exc:
            logger.warning("ZAP unavailable at %s: %s", self.base_url, exc)
            return False

    async def _get(self, path: str, params: dict[str, Any] | None = None, timeout: float = 60.0) -> dict[str, Any]:
        async with self._client(timeout=timeout) as client:
            resp = await client.get(f"{self.base_url}{path}", params=self._params(params))
            resp.raise_for_status()
            return resp.json()

    async def new_session(self, name: str = "shieldscan") -> None:
        await self._get("/JSON/core/action/newSession/", {"name": name, "overwrite": "true"})

    async def access_url(self, url: str) -> None:
        await self._get("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"})

    async def spider(self, url: str, on_progress: Callable[[str], None] | None = None) -> str:
        max_children = str(self.policy["spider_max_children"])
        data = await self._get(
            "/JSON/spider/action/scan/",
            {"url": url, "maxChildren": max_children, "recurse": "true", "subtreeOnly": "false"},
        )
        scan_id = str(data["scan"])
        await self._wait_scan(
            status_path="/JSON/spider/view/status/",
            stop_path="/JSON/spider/action/stop/",
            scan_id=scan_id,
            timeout=self.spider_timeout,
            on_progress=on_progress,
            label="Spidering",
        )
        return scan_id

    async def ajax_spider(self, url: str, on_progress: Callable[[str], None] | None = None) -> None:
        """Optional AJAX spider for JavaScript-heavy apps (Juice Shop, SPAs) with timeout hardening."""
        if not self.policy.get("ajax_spider_enabled", True):
            if on_progress:
                on_progress("AJAX spider skipped for quick policy profile")
            return

        try:
            max_mins = str(self.policy.get("ajax_max_duration_mins", 5))
            await self._get("/JSON/ajaxSpider/action/setOptionMaxDuration/", {"Integer": max_mins})
            await self._get("/JSON/ajaxSpider/action/scan/", {"url": url, "inScope": "true"})
            if on_progress:
                on_progress("AJAX spider started for JavaScript pages")

            elapsed = 0.0
            step = min(3.0, self.poll_interval)
            while elapsed < self.ajax_spider_timeout:
                status = await self._get("/JSON/ajaxSpider/view/status/", timeout=15.0)
                state = str(status.get("status", "")).lower()
                if state == "stopped":
                    if on_progress:
                        on_progress("AJAX spider complete")
                    return
                if on_progress:
                    on_progress(f"AJAX spider running ({int(elapsed)}s/{self.ajax_spider_timeout}s)...")
                await asyncio.sleep(step)
                elapsed += step

            logger.warning("AJAX spider timed out after %ss; stopping gracefully", self.ajax_spider_timeout)
            try:
                await self._get("/JSON/ajaxSpider/action/stop/", timeout=10.0)
            except Exception:
                pass
            if on_progress:
                on_progress(f"AJAX spider timed out after {self.ajax_spider_timeout}s (stopped gracefully)")
        except Exception as exc:
            logger.debug("AJAX spider skipped: %s", exc)

    async def passive_scan_wait(self, on_progress: Callable[[str], None] | None = None) -> None:
        """Wait for passive scan to finish processing spider traffic with adaptive progress callbacks."""
        if on_progress:
            on_progress("Passive scan analysing discovered traffic")
        elapsed = 0.0
        initial_records: int | None = None

        while elapsed < self.passive_timeout:
            try:
                data = await self._get("/JSON/pscan/view/recordsToScan/", timeout=15.0)
                remaining = int(data.get("recordsToScan", 0))
                if initial_records is None:
                    initial_records = max(remaining, 1)

                if remaining <= 0:
                    if on_progress:
                        on_progress("Passive scan: 0 records remaining (100%)")
                    return

                done = max(0, initial_records - remaining)
                pct = min(99, int((done / initial_records) * 100))
                if on_progress:
                    on_progress(f"Passive scan: {remaining} records remaining ({pct}%)")
            except Exception as exc:
                logger.debug("Passive scan poll interrupted: %s", exc)
                return

            step = min(1.0 if remaining < 10 else 2.0, self.poll_interval)
            await asyncio.sleep(step)
            elapsed += step

        logger.warning("Passive scan wait timed out after %ss", self.passive_timeout)
        if on_progress:
            on_progress(f"Passive scan wait reached {self.passive_timeout}s budget; proceeding")

    async def active_scan(
        self,
        url: str,
        on_progress: Callable[[str], None] | None = None,
        policy_profile: str | None = None,
    ) -> str:
        policy = self.get_policy_config(policy_profile or self.policy_name)
        data = await self._get(
            "/JSON/ascan/action/scan/",
            {
                "url": url,
                "recurse": "true",
                "inScopeOnly": "false",
                "scanPolicyName": policy["scan_policy_name"],
                "method": "",
                "postData": "",
            },
        )
        scan_id = str(data["scan"])
        await self._wait_scan(
            status_path="/JSON/ascan/view/status/",
            stop_path="/JSON/ascan/action/stop/",
            scan_id=scan_id,
            timeout=self.active_timeout,
            on_progress=on_progress,
            label=f"Active scanning ({policy_profile or self.policy_name})",
        )
        return scan_id

    async def _wait_scan(
        self,
        status_path: str,
        stop_path: str,
        scan_id: str,
        timeout: int,
        on_progress: Callable[[str], None] | None,
        label: str,
    ) -> None:
        elapsed = 0.0
        while elapsed < timeout:
            try:
                data = await self._get(status_path, {"scanId": scan_id}, timeout=20.0)
                status = int(data.get("status", 100))
            except Exception as exc:
                logger.warning("%s status poll failed for scan %s: %s", label, scan_id, exc)
                break

            if on_progress:
                on_progress(f"{label}: {status}%")
            if status >= 100:
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        logger.warning("%s timed out after %ss; stopping ZAP scan %s", label, timeout, scan_id)
        try:
            await self._get(stop_path, {"scanId": scan_id}, timeout=10.0)
        except Exception:
            pass
        if on_progress:
            on_progress(f"{label}: timed out after {timeout}s (stopped gracefully)")

    async def get_alerts(self, base_url: str) -> list[dict[str, Any]]:
        all_alerts: list[dict[str, Any]] = []
        start = 0
        page_size = 500
        while start < 2000:
            data = await self._get(
                "/JSON/alert/view/alerts/",
                {"baseurl": base_url, "start": str(start), "count": str(page_size)},
            )
            batch = data.get("alerts", [])
            if not batch:
                break
            all_alerts.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size
        return all_alerts

    async def run_full_scan(
        self,
        target_url: str,
        on_progress: Callable[[str], None] | None = None,
        policy_profile: str | None = None,
    ) -> list[dict[str, Any]]:
        if policy_profile:
            self.policy_name = policy_profile.strip().lower()
            self.policy = self.get_policy_config(self.policy_name)

        await self.new_session()
        if on_progress:
            on_progress(f"Initialising ZAP session (policy: {self.policy_name})")
        await self.access_url(target_url)
        if on_progress:
            on_progress(f"Starting spider (up to {self.policy['spider_max_children']} children per node)")
        await self.spider(target_url, on_progress)
        await self.ajax_spider(target_url, on_progress)
        await self.passive_scan_wait(on_progress)
        if on_progress:
            on_progress(f"Starting active scan ({self.policy_name} profile)")
        await self.active_scan(target_url, on_progress, policy_profile=self.policy_name)
        if on_progress:
            on_progress("Collecting alerts")
        return await self.get_alerts(target_url)
