"""Phase 2 tests: OWASP Top 10 probe expansion, false-positive tuning, fuzz budgets, SARIF v2.1.0, and DVWA/Juice Shop regression fixtures."""

import asyncio
import json
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.database import SessionLocal
from app.main import app
from app.models import Scan, ScanStatus
from app.schemas import Finding
from app.services.crawler import CrawlResult, FormInfo
from app.services.extended_checks import run_extended_checks
from app.services.finding_utils import (
    calibrate_finding_severity,
    deduplicate_findings,
    enrich_findings,
    filter_false_positives,
)
from app.services.owasp_top10 import (
    check_insecure_design,
    check_subresource_integrity,
    fuzz_url_parameters,
    run_owasp_top10_probes,
)
from app.services.passive_checks import check_security_headers
from app.services.sarif_exporter import SARIF_SCHEMA_URL

client = TestClient(app)


def _dvwa_mock_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    parsed = urlparse(url)
    path = parsed.path
    qs = parse_qs(parsed.query)

    headers = {
        "Server": "Apache/2.4.38 (Debian)",
        "X-Powered-By": "PHP/7.3.14",
        "Set-Cookie": "PHPSESSID=dvwa123; path=/",
        "Access-Control-Allow-Origin": "*",
    }

    if path == "/admin":
        return httpx.Response(200, text="<html><body><h1>Admin Panel — Manage Users</h1></body></html>", headers=headers)

    if path in ("/login.php", "/login"):
        return httpx.Response(
            200,
            text=(
                "<html><head><script src='https://cdn.example.org/jquery-1.8.3.min.js'></script></head>"
                "<body><form action='/login.php' method='get'>"
                "<input name='username' type='text'><input name='password' type='password' autocomplete='on'>"
                "</form></body></html>"
            ),
            headers=headers,
        )

    if path == "/.env":
        return httpx.Response(200, text="DB_PASSWORD=supersecret\nAPI_KEY=12345", headers=headers)

    if path == "/.git/HEAD":
        return httpx.Response(200, text="ref: refs/heads/main\n", headers=headers)

    if path == "/uploads/":
        return httpx.Response(200, text="<html><title>Index of /uploads</title><body>Index of /uploads/</body></html>", headers=headers)

    if "shieldscan-nonexistent-page-404-test" in path:
        return httpx.Response(500, text="Fatal error: Uncaught Exception in /var/www/html/index.php on line 42\nStack trace:", headers=headers)

    # Parameter reflection / vuln triggers on base or dvwa endpoints
    for param, vals in qs.items():
        val = vals[0] if vals else ""
        if "<script>shieldscan7</script>" in val:
            return httpx.Response(200, text=f"<html><body>Hello {val}</body></html>", headers=headers)
        if "' OR '1'='1" in val:
            return httpx.Response(
                200,
                text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                headers=headers,
            )
        if ";id" in val or "|id" in val:
            return httpx.Response(200, text="uid=33(www-data) gid=33(www-data) groups=33(www-data)", headers=headers)
        if "shieldscan-probe.example" in val:
            return httpx.Response(302, headers={**headers, "Location": val})

    if path == "/vulnerabilities/idor":
        item_id = qs.get("id", ["1"])[0]
        if item_id == "1":
            return httpx.Response(200, text="A" * 350, headers=headers)
        return httpx.Response(200, text="B" * 500, headers=headers)

    return httpx.Response(
        200,
        text=(
            "<html><head>"
            "<script src='https://cdn.thirdparty.example/jquery-1.9.1.min.js'></script>"
            "</head><body>"
            "<h1>Welcome to DVWA (Low)</h1>"
            "<form action='/vulnerabilities/csrf/' method='post'>"
            "<input name='password_new' type='password'><input name='password_conf' type='password'>"
            "</form>"
            "<form action='/vulnerabilities/xss_s/' method='post'>"
            "<input name='txtName' type='text'><input name='mtxMessage' type='text'>"
            "</form>"
            "</body></html>"
        ),
        headers=headers,
    )


def _juice_shop_mock_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    parsed = urlparse(url)
    path = parsed.path
    qs = parse_qs(parsed.query)

    headers = {
        "X-Powered-By": "Express",
        "Access-Control-Allow-Origin": "https://shieldscan-probe.example",
        "Access-Control-Allow-Credentials": "true",
    }

    if path.startswith("/api"):
        q = qs.get("q", [""])[0]
        if "<script>" in q:
            return httpx.Response(200, text=f'{{"status":"success","data":"{q}"}}', headers=headers)
        return httpx.Response(200, text='{"status":"success","data":[]}', headers=headers)

    if path == "/ftp" or path == "/backup.zip":
        return httpx.Response(200, content=b"PK\x03\x04juice-backup", headers=headers)

    return httpx.Response(
        200,
        text=(
            "<html><head><script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.0/angular.min.js'></script></head>"
            "<body><div ng-app='juiceShop'>OWASP Juice Shop</div>"
            "<form action='/rest/user/login' method='post'>"
            "<input name='email' type='email'><input name='password' type='password'>"
            "</form>"
            "<form action='/rest/user/reset-password' method='post'>"
            "<input name='email' type='email'><input name='password_new' type='password'>"
            "</form>"
            "</body></html>"
        ),
        headers=headers,
    )


def test_fuzz_budget_profiles():
    s = Settings(fuzz_profile="quick")
    assert s.get_fuzz_budget()["max_params"] == 15
    assert s.get_fuzz_budget()["max_pages"] == 25
    assert s.get_fuzz_budget()["max_depth"] == 2

    s_std = Settings(fuzz_profile="standard", fuzz_max_params=45)
    assert s_std.get_fuzz_budget()["max_params"] == 45
    assert s_std.get_fuzz_budget()["max_pages"] == 80

    s_deep = Settings(fuzz_profile="deep")
    assert s_deep.get_fuzz_budget()["max_params"] == 80
    assert s_deep.get_fuzz_budget()["max_pages"] == 120
    assert s_deep.get_fuzz_budget()["max_depth"] == 5


def test_false_positive_filtering_and_severity_calibration():
    encoded_xss = Finding(
        id="xss-encoded-fp",
        name="Reflected Cross-Site Scripting (XSS)",
        risk="High",
        confidence="Medium",
        url="http://127.0.0.1:4280/search",
        parameter="q",
        evidence="Reflected: &lt;script&gt;shieldscan7&lt;/script&gt;",
    )
    verified_cmdi = Finding(
        id="cmdi-ip",
        name="Command Injection",
        risk="High",
        confidence="Firm",
        url="http://127.0.0.1:4280/vulnerabilities/exec/",
        parameter="ip",
        evidence="OS output pattern after ?ip=: uid=33(www-data) gid=33(www-data)",
        cwe="78",
    )
    duplicate_sqli_1 = Finding(
        id="sqli-1",
        name="SQL Injection",
        risk="High",
        confidence="Medium",
        url="http://127.0.0.1:4280/vulnerabilities/sqli/",
        parameter="id",
        evidence="SQL error",
        cwe="89",
    )
    duplicate_sqli_2 = Finding(
        id="sqli-2",
        name="SQL Injection in URL Parameter",
        risk="High",
        confidence="Firm",
        url="http://127.0.0.1:4280/vulnerabilities/sqli",
        parameter="id",
        evidence="SQL syntax error in MySQL",
        cwe="89",
    )

    filtered = filter_false_positives([encoded_xss, verified_cmdi, duplicate_sqli_1, duplicate_sqli_2])
    assert len(filtered) == 3

    calibrated = [calibrate_finding_severity(f) for f in filtered]
    cmdi_cal = next(f for f in calibrated if f.id == "cmdi-ip")
    assert cmdi_cal.risk == "Critical"

    deduped = deduplicate_findings(calibrated)
    assert len(deduped) == 2


def test_baseline_sql_keyword_not_false_positive():
    def baseline_sql_article(request: httpx.Request) -> httpx.Response:
        # Page naturally discusses MySQL and PostgreSQL even without payload
        return httpx.Response(200, text="<html><body>Tutorial on MySQL and PostgreSQL database queries.</body></html>")

    async def _run():
        transport = httpx.MockTransport(baseline_sql_article)
        async with httpx.AsyncClient(transport=transport) as http_client:
            return await fuzz_url_parameters("http://127.0.0.1:4280/blog", http_client, max_params=3)

    findings = asyncio.run(_run())
    sqli_findings = [f for f in findings if "sql injection" in f.name.lower()]
    assert sqli_findings == []


def test_owasp_a04_and_a08_probes():
    async def _run():
        transport = httpx.MockTransport(_dvwa_mock_handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            forms = [
                FormInfo(
                    page_url="http://127.0.0.1:4280/vulnerabilities/csrf/",
                    action_url="http://127.0.0.1:4280/vulnerabilities/csrf/",
                    method="post",
                    fields=["password_new", "password_conf"],
                    has_csrf_token=False,
                ),
                FormInfo(
                    page_url="http://127.0.0.1:4280/vulnerabilities/xss_s/",
                    action_url="http://127.0.0.1:4280/vulnerabilities/xss_s/",
                    method="post",
                    fields=["txtName", "mtxMessage"],
                    has_csrf_token=False,
                ),
            ]
            a04 = await check_insecure_design(forms, ["http://127.0.0.1:4280/"], http_client)
            a08 = await check_subresource_integrity("http://127.0.0.1:4280/", http_client)
            return a04, a08

    a04_findings, a08_findings = asyncio.run(_run())
    assert any("A04:2021" in f.owasp_category for f in a04_findings)
    assert any("A08:2021" in f.owasp_category for f in a08_findings)


def test_dvwa_low_regression_fixture_produces_at_least_15_findings():
    async def _run():
        transport = httpx.MockTransport(_dvwa_mock_handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            base_url = "http://127.0.0.1:4280"
            crawl = CrawlResult(
                pages=[base_url, f"{base_url}/login.php", f"{base_url}/vulnerabilities/idor?id=1"],
                forms=[
                    FormInfo(
                        page_url=base_url,
                        action_url=f"{base_url}/vulnerabilities/csrf/",
                        method="post",
                        fields=["password_new", "password_conf"],
                        has_csrf_token=False,
                    )
                ],
                param_urls=[(f"{base_url}/vulnerabilities/idor?id=1", "id", "1")],
            )
            raw: list[Finding] = []
            raw.extend(await check_security_headers(base_url, http_client))
            raw.extend(await run_owasp_top10_probes(base_url, http_client, crawl))
            raw.extend(await run_extended_checks(base_url, http_client, crawl))
            enriched = enrich_findings(raw)
            return raw, enriched

    raw_findings, final_findings = asyncio.run(_run())
    assert len(final_findings) >= 15
    # Verify post-deduplication has 0 duplicates (< 20% duplicate rate threshold)
    keys = {(f.name.lower(), f.url, f.parameter.lower()) for f in final_findings}
    duplicate_rate = (len(final_findings) - len(keys)) / max(len(final_findings), 1)
    assert duplicate_rate < 0.20


def test_juice_shop_regression_fixture():
    async def _run():
        transport = httpx.MockTransport(_juice_shop_mock_handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            base_url = "http://127.0.0.1:3000"
            crawl = CrawlResult(
                pages=[base_url],
                forms=[
                    FormInfo(
                        page_url=base_url,
                        action_url=f"{base_url}/rest/user/reset-password",
                        method="post",
                        fields=["email", "password_new"],
                        has_csrf_token=False,
                    )
                ],
                param_urls=[(f"{base_url}/api/Products?q=apple", "q", "apple")],
            )
            raw: list[Finding] = []
            raw.extend(await check_security_headers(base_url, http_client))
            raw.extend(await run_owasp_top10_probes(base_url, http_client, crawl))
            raw.extend(await run_extended_checks(base_url, http_client, crawl))
            return enrich_findings(raw)

    findings = asyncio.run(_run())
    assert len(findings) >= 10
    categories = {f.owasp_category.split(" ")[0] for f in findings if f.owasp_category}
    assert len(categories) >= 4


def test_sarif_export_endpoint_and_schema_validation():
    sample_findings = [
        Finding(
            id="sqli-fuzz-id",
            name="SQL Injection",
            risk="Critical",
            confidence="Firm",
            url="http://127.0.0.1:4280/vulnerabilities/sqli/",
            parameter="id",
            evidence="SQL syntax error near MySQL",
            description="Parameter 'id' triggers database error messages.",
            solution="Use parameterised queries.",
            cwe="89",
            owasp_category="A03:2021 — Injection",
            source="owasp-probe",
        ),
        Finding(
            id="sri-missing-1",
            name="Subresource Integrity (SRI) Missing on External Script",
            risk="Medium",
            confidence="High",
            url="http://127.0.0.1:4280/",
            parameter="https://cdn.example.org/app.js",
            evidence="<script src='https://cdn.example.org/app.js'>",
            description="External script loaded without integrity attribute.",
            solution="Add integrity='sha384-...' attribute.",
            cwe="353",
            owasp_category="A08:2021 — Software and Data Integrity Failures",
            source="owasp-probe",
        ),
    ]

    with SessionLocal() as db:
        scan = Scan(
            target_url="http://127.0.0.1:4280",
            status=ScanStatus.COMPLETE,
            status_message="Scan complete",
            scanner_used="builtin",
            findings_json=json.dumps([f.model_dump() for f in sample_findings]),
            finding_count=len(sample_findings),
            critical_count=1,
            high_count=0,
            risk_grade="D",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    resp = client.get(f"/api/scans/{scan_id}/report/sarif")
    assert resp.status_code == 200
    assert "application/sarif+json" in resp.headers["content-type"]

    sarif = resp.json()
    assert sarif["$schema"] == SARIF_SCHEMA_URL
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ShieldScan"
    assert len(driver["rules"]) == 2
    assert len(run["results"]) == 2

    first_rule = driver["rules"][0]
    assert "security-severity" in first_rule["properties"]
    assert "external/cwe/cwe-89" in first_rule["properties"]["tags"]

    first_result = run["results"][0]
    assert first_result["level"] == "error"
    assert first_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert "primaryLocationLineHash" in first_result["partialFingerprints"]

    missing_resp = client.get("/api/scans/999999/report/sarif")
    assert missing_resp.status_code == 404
    assert missing_resp.json()["error"]["code"] == "NOT_FOUND"
