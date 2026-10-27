import logging

import httpx

from app.config import get_settings
from app.schemas import Finding
from app.services.crawler import crawl_site
from app.services.deep_probes import run_deep_probes
from app.services.extended_checks import run_extended_checks
from app.services.finding_utils import enrich_findings
from app.services.owasp_top10 import run_owasp_top10_probes
from app.services.passive_checks import check_security_headers

logger = logging.getLogger(__name__)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    return enrich_findings(findings)


async def run_builtin_scan(target_url: str, on_progress=None) -> list[Finding]:
    """Full built-in scan: crawl, OWASP Top 10 probes, headers, extended checks."""
    settings = get_settings()
    budget = settings.get_fuzz_budget()
    findings: list[Finding] = []

    async with httpx.AsyncClient(
        timeout=20.0,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "ShieldScan/1.0 (Educational Security Assessment)"},
    ) as client:
        if on_progress:
            on_progress("Phase 1: Crawling pages, forms, and endpoints")
        crawl = await crawl_site(
            target_url,
            client,
            max_pages=budget["max_pages"],
            max_depth=budget["max_depth"],
        )
        if on_progress:
            on_progress(
                f"Discovered {len(crawl.pages)} pages, {len(crawl.forms)} forms, "
                f"{len(crawl.param_urls)} parameterised URLs"
            )

        if on_progress:
            on_progress("Phase 2: Security headers and TLS")
        findings.extend(await check_security_headers(target_url, client))

        if on_progress:
            on_progress("Phase 3: OWASP Top 10 active probes")
        findings.extend(
            await run_owasp_top10_probes(target_url, client, crawl, on_progress=on_progress)
        )

        if on_progress:
            on_progress("Phase 4: Extended configuration checks")
        findings.extend(await run_extended_checks(target_url, client, crawl))

        if on_progress:
            on_progress("Phase 5: Deep probes — traversal, SSTI, APIs, sensitive files")
        findings.extend(
            await run_deep_probes(
                target_url,
                client,
                crawl,
                on_progress=on_progress,
                fuzz_max_params=budget["max_params"],
            )
        )

        deduped = _dedupe_findings(findings)
        if on_progress:
            on_progress(f"Scan complete — {len(deduped)} findings")

    return deduped
