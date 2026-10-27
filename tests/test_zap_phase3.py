"""Phase 3 tests: ZAP DAST integration, timeout hardening, policy profiles, and DEPENDENCY_UNAVAILABLE readiness contract."""

import asyncio
import logging
from urllib.parse import urlparse

import httpx
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.database import SessionLocal
from app.main import app
from app.models import Scan, ScanStatus
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.zap_client import ZAPClient

client = TestClient(app)


def test_zap_policy_profiles():
    quick = ZAPClient.get_policy_config("quick")
    standard = ZAPClient.get_policy_config("standard")
    deep = ZAPClient.get_policy_config("deep")

    assert quick["spider_max_children"] == 30
    assert quick["ajax_spider_enabled"] is False
    assert standard["spider_max_children"] == 100
    assert standard["ajax_spider_enabled"] is True
    assert deep["spider_max_children"] == 250
    assert deep["attack_strength"] == "HIGH"


def test_zap_client_full_scan_with_mocked_zap_api():
    state = {"spider_polls": 0, "pscan_polls": 0, "ascan_polls": 0, "ajax_polls": 0}
    progress_messages: list[str] = []

    def zap_mock(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path.endswith("/core/view/version/"):
            return httpx.Response(200, json={"version": "2.15.0"})
        if path.endswith("/core/action/newSession/"):
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/core/action/accessUrl/"):
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/spider/action/scan/"):
            return httpx.Response(200, json={"scan": "1"})
        if path.endswith("/spider/view/status/"):
            state["spider_polls"] += 1
            pct = "50" if state["spider_polls"] == 1 else "100"
            return httpx.Response(200, json={"status": pct})
        if path.endswith("/ajaxSpider/action/setOptionMaxDuration/"):
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/ajaxSpider/action/scan/"):
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/ajaxSpider/view/status/"):
            state["ajax_polls"] += 1
            st = "running" if state["ajax_polls"] == 1 else "stopped"
            return httpx.Response(200, json={"status": st})
        if path.endswith("/pscan/view/recordsToScan/"):
            state["pscan_polls"] += 1
            rem = "4" if state["pscan_polls"] == 1 else "0"
            return httpx.Response(200, json={"recordsToScan": rem})
        if path.endswith("/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "2"})
        if path.endswith("/ascan/view/status/"):
            state["ascan_polls"] += 1
            pct = "60" if state["ascan_polls"] == 1 else "100"
            return httpx.Response(200, json={"status": pct})
        if path.endswith("/alert/view/alerts/"):
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "pluginId": "40012",
                            "alert": "Cross Site Scripting (Reflected)",
                            "risk": "High",
                            "confidence": "Medium",
                            "url": "http://127.0.0.1:4280/vulnerabilities/xss_r/",
                            "param": "name",
                            "evidence": "<script>alert(1)</script>",
                            "cweid": "79",
                            "description": "Reflected XSS in name parameter.",
                            "solution": "Encode output.",
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"Result": "OK"})

    settings = Settings(zap_scan_policy="standard")
    zap = ZAPClient(settings, transport=httpx.MockTransport(zap_mock), poll_interval=0.01)

    async def _run():
        assert await zap.is_available() is True
        return await zap.run_full_scan("http://127.0.0.1:4280", on_progress=progress_messages.append)

    alerts = asyncio.run(_run())
    assert len(alerts) == 1
    assert alerts[0]["alert"] == "Cross Site Scripting (Reflected)"
    assert any("Passive scan: 4 records remaining" in m for m in progress_messages)
    assert any("Passive scan: 0 records remaining (100%)" in m for m in progress_messages)
    assert any("Active scanning (standard): 100%" in m for m in progress_messages)


def test_zap_spider_and_ajax_timeout_hardening_stops_gracefully():
    stopped_endpoints: list[str] = []

    def hung_zap_mock(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path.endswith("/action/stop/"):
            stopped_endpoints.append(path)
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/spider/action/scan/"):
            return httpx.Response(200, json={"scan": "7"})
        if path.endswith("/spider/view/status/"):
            return httpx.Response(200, json={"status": "25"})
        if path.endswith("/ajaxSpider/view/status/"):
            return httpx.Response(200, json={"status": "running"})
        return httpx.Response(200, json={"Result": "OK"})

    settings = Settings(
        scan_spider_timeout=1,
        scan_ajax_spider_timeout=1,
        zap_scan_policy="standard",
    )
    zap = ZAPClient(settings, transport=httpx.MockTransport(hung_zap_mock), poll_interval=0.4)
    msgs: list[str] = []

    async def _run():
        await zap.spider("http://127.0.0.1:4280", on_progress=msgs.append)
        await zap.ajax_spider("http://127.0.0.1:4280", on_progress=msgs.append)

    asyncio.run(_run())
    assert "/JSON/spider/action/stop/" in stopped_endpoints
    assert "/JSON/ajaxSpider/action/stop/" in stopped_endpoints
    assert any("timed out" in m for m in msgs)


def test_ready_dependency_unavailable_contract_when_zap_down(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("SCANNER_MODE", "zap")
    monkeypatch.setenv("ZAP_API_URL", "http://127.0.0.1:59999")
    get_settings.cache_clear()

    try:
        resp = client.get("/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert body["zap"] == "unavailable"
        assert "error" in body
        assert body["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert body["error"]["details"]["dependency"] == "zap"
    finally:
        monkeypatch.setenv("SCANNER_MODE", "builtin")
        get_settings.cache_clear()


def test_orchestrator_logs_fallback_to_builtin_when_zap_unreachable(caplog, monkeypatch):
    async def fake_builtin_scan(target_url: str, on_progress=None):
        if on_progress:
            on_progress("Mock builtin scan complete")
        return []

    monkeypatch.setattr("app.services.scan_orchestrator.run_builtin_scan", fake_builtin_scan)

    settings = Settings(
        scanner_mode="zap",
        zap_api_url="http://127.0.0.1:59999",
        anthropic_api_key="",
    )

    with SessionLocal() as db:
        scan = Scan(
            target_url="http://127.0.0.1:4280",
            status=ScanStatus.QUEUED,
            status_message="Queued",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        orchestrator = ScanOrchestrator(settings, db)
        with caplog.at_level(logging.WARNING):
            asyncio.run(orchestrator.run(scan_id))

        db.refresh(scan)
        assert scan.status == ScanStatus.COMPLETE
        assert scan.scanner_used == "builtin"
        assert any("Fallback to builtin scanner" in rec.message for rec in caplog.records)
