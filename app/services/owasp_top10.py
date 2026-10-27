"""OWASP Top 10 oriented active probes — injection, auth, access control, components."""

import logging
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.config import get_settings
from app.schemas import Finding
from app.services.constants import (
    CMD_PAYLOADS,
    COMMON_FUZZ_PARAMS,
    COMMON_PROBE_PATHS,
    JQUERY_VULN_PATTERNS,
    SQLI_PAYLOADS,
    XSS_PAYLOADS,
)
from app.services.crawler import CrawlResult, FormInfo
from app.services.owasp import classify_owasp

logger = logging.getLogger(__name__)

SQL_ERROR_SIGNS = (
    "sql syntax", "mysql", "sqlite", "postgresql", "ora-", "syntax error",
    "unclosed quotation", "quoted string not properly terminated", "odbc",
    "sqlstate", "database error", "pg_query", "mysqli", "sql server",
    "warning: pg_", "valid mysql result", "sqlite3.operationalerror",
)

CMD_SIGNS = ("uid=", "gid=", "groups=", "root:x:0", "/bin/bash")

CSRF_TOKEN_PATTERNS = re.compile(
    r"name=[\"'](csrf|_csrf|csrfmiddlewaretoken|token|_token|authenticity_token|"
    r"__requestverificationtoken|anti-forgery-token|csrftoken)[\"']",
    re.I,
)

LOGIN_MARKERS = re.compile(
    r"type=[\"']password[\"']|name=[\"'](password|passwd|pass)[\"']|login|sign\s*in",
    re.I,
)

ADMIN_MARKERS = re.compile(
    r"dashboard|admin\s*panel|control\s*panel|manage\s*users|backend",
    re.I,
)

JQUERY_VULN = JQUERY_VULN_PATTERNS


def _f(
    fid: str,
    name: str,
    risk: str,
    url: str,
    description: str,
    solution: str,
    evidence: str = "",
    parameter: str = "",
    cwe: str = "",
    confidence: str = "Medium",
    owasp: str = "",
) -> Finding:
    cat = owasp or classify_owasp(cwe, name)
    return Finding(
        id=fid,
        name=name,
        risk=risk,
        confidence=confidence,
        url=url,
        parameter=parameter,
        evidence=evidence[:500],
        description=description,
        solution=solution,
        cwe=cwe,
        owasp_category=cat,
        source="owasp-probe",
    )


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


async def discover_robots_sitemap(base_url: str, client: httpx.AsyncClient) -> list[str]:
    """Extra URLs from robots.txt and sitemap.xml."""
    urls: list[str] = []
    origin = _origin(base_url)
    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        try:
            resp = await client.get(origin + path, timeout=8.0)
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            if path.endswith("robots.txt"):
                for line in text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:")):
                        part = line.split(":", 1)[1].strip()
                        if part and part != "/" and "*" not in part:
                            urls.append(urljoin(origin, part))
            else:
                urls.extend(re.findall(r"<loc>([^<]+)</loc>", text, re.I))
        except Exception:
            pass
    return urls[:30]


async def probe_common_paths(base_url: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str], list[FormInfo]]:
    """Probe admin/login/API paths — access control & auth surface."""
    findings: list[Finding] = []
    extra_pages: list[str] = []
    forms: list[FormInfo] = []
    origin = _origin(base_url)

    for path in COMMON_PROBE_PATHS:
        test_url = urljoin(origin, path)
        try:
            resp = await client.get(test_url, follow_redirects=True, timeout=10.0)
        except Exception:
            continue

        if resp.status_code not in (200, 201, 301, 302, 401, 403):
            continue

        final = str(resp.url)
        body = resp.text or ""
        extra_pages.append(final)

        # Broken Access Control — admin area without auth challenge
        if path in ("/admin", "/administrator", "/dashboard", "/wp-admin") and resp.status_code == 200:
            if ADMIN_MARKERS.search(body) and not LOGIN_MARKERS.search(body):
                findings.append(
                    _f(
                        f"bac-admin-{path.replace('/', '-')}",
                        "Broken Access Control — Admin Area Without Authentication",
                        "High",
                        final,
                        "An administrative interface appears accessible without login.",
                        "Require authentication and authorisation for all admin routes.",
                        evidence=f"GET {test_url} returned HTTP 200 with admin content",
                        cwe="284",
                        confidence="Firm",
                        owasp="A01:2021 — Broken Access Control",
                    )
                )
            elif resp.status_code == 200:
                findings.append(
                    _f(
                        f"bac-path-{path.replace('/', '-')}",
                        "Sensitive Path Discovered — Requires Access Review",
                        "Low",
                        final,
                        f"Path {path} is reachable. Verify only authorised users can access it.",
                        "Restrict admin paths by IP allowlist or strong authentication.",
                        evidence=f"HTTP {resp.status_code}",
                        owasp="A01:2021 — Broken Access Control",
                    )
                )

        # Authentication endpoints
        if LOGIN_MARKERS.search(body) and resp.status_code == 200:
            forms.extend(_extract_forms_from_html(final, body))
            findings.extend(_analyse_login_page(final, body, client))

        # API surface
        if path.startswith("/api") and resp.status_code in (200, 401, 403):
            findings.append(
                _f(
                    f"api-surface-{path.replace('/', '-')}",
                    "API Endpoint Discovered",
                    "Informational",
                    final,
                    "Exposed API endpoints should enforce authentication, rate limiting, and input validation.",
                    "Document APIs, require auth tokens, and validate all inputs.",
                    evidence=f"HTTP {resp.status_code}, {len(body)} bytes",
                    owasp="A01:2021 — Broken Access Control",
                )
            )

    return findings, extra_pages, forms


def _extract_forms_from_html(page_url: str, html: str) -> list[FormInfo]:
    forms: list[FormInfo] = []
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        block = m.group(0)
        action_m = re.search(r"""action=["']([^"']*)["']""", block, re.I)
        method_m = re.search(r"""method=["']([^"']*)["']""", block, re.I)
        action = urljoin(page_url, action_m.group(1)) if action_m else page_url
        method = (method_m.group(1) if method_m else "get").lower()
        fields = re.findall(r"""<(?:input|textarea|select)[^>]*name=["']([^"']+)["']""", block, re.I)
        csrf = bool(CSRF_TOKEN_PATTERNS.search(block))
        if fields:
            forms.append(FormInfo(page_url, action, method, fields, csrf))
    return forms


def _analyse_login_page(url: str, html: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    lower = html.lower()

    if urlparse(url).scheme == "http":
        findings.append(
            _f(
                "auth-http-login",
                "Broken Authentication — Login Page Served Over HTTP",
                "High",
                url,
                "Credentials submitted over HTTP can be intercepted on the network.",
                "Serve all authentication pages exclusively over HTTPS.",
                cwe="319",
                confidence="Firm",
                owasp="A07:2021 — Identification and Authentication Failures",
            )
        )

    if re.search(r"""autocomplete=["']?on""", html, re.I) or (
        "password" in lower and 'autocomplete="off"' not in lower and "autocomplete='off'" not in lower
    ):
        findings.append(
            _f(
                f"auth-autocomplete-{urlparse(url).path}",
                "Broken Authentication — Password Autocomplete Enabled",
                "Low",
                url,
                "Browsers may cache credentials on shared devices.",
                'Set autocomplete="off" on password fields or use autocomplete="new-password".',
                cwe="522",
                owasp="A07:2021 — Identification and Authentication Failures",
            )
        )

    for m in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        block = m.group(0)
        if "password" not in block.lower():
            continue
        method = re.search(r"""method=["']([^"']*)["']""", block, re.I)
        if method and method.group(1).lower() == "get":
            findings.append(
                _f(
                    "auth-get-login",
                    "Broken Authentication — Login Form Uses GET Method",
                    "High",
                    url,
                    "Credentials may appear in browser history, logs, and referrer headers.",
                    "Change login forms to use POST over HTTPS.",
                    cwe="598",
                    confidence="Firm",
                    owasp="A07:2021 — Identification and Authentication Failures",
                )
            )
        if not CSRF_TOKEN_PATTERNS.search(block):
            findings.append(
                _f(
                    f"csrf-login-{urlparse(url).path}",
                    "Cross-Site Request Forgery (CSRF) — Login Form Missing Token",
                    "Medium",
                    url,
                    "Login forms without CSRF tokens may be vulnerable to cross-site login attacks.",
                    "Add a unique CSRF token to all authentication forms.",
                    cwe="352",
                    confidence="Medium",
                    owasp="A01:2021 — Broken Access Control",
                )
            )

    return findings


async def fuzz_url_parameters(base_url: str, client: httpx.AsyncClient, max_params: int | None = None) -> list[Finding]:
    """Fuzz common parameter names on the base URL — injection, XSS, redirect."""
    if max_params is None:
        max_params = get_settings().get_fuzz_budget()["max_params"]
    findings: list[Finding] = []
    ssrf_params: list[str] = []
    parsed = urlparse(base_url)
    base = urlunparse(parsed._replace(query="", fragment=""))

    baseline_lower = ""
    try:
        base_resp = await client.get(base, timeout=8.0)
        baseline_lower = (base_resp.text or "").lower()
    except Exception:
        pass

    for param in COMMON_FUZZ_PARAMS[:max_params]:
        # XSS — only flag unencoded reflection of active tags/vectors
        for payload in XSS_PAYLOADS[1:6]:
            probe = f"{base}?{urlencode({param: payload})}"
            try:
                resp = await client.get(probe, timeout=10.0)
                body = resp.text or ""
                if payload in body:
                    findings.append(
                        _f(
                            f"xss-fuzz-{param}",
                            "Reflected Cross-Site Scripting (XSS)",
                            "High",
                            base,
                            f"Parameter '{param}' reflects user input without encoding.",
                            "Apply context-aware output encoding and Content-Security-Policy.",
                            evidence=f"Payload {payload[:40]} reflected via ?{param}=",
                            parameter=param,
                            cwe="79",
                            confidence="Firm",
                            owasp="A03:2021 — Injection",
                        )
                    )
                    break
            except Exception:
                pass

        # SQLi — compare against baseline to avoid false positives on pages discussing SQL
        for payload in SQLI_PAYLOADS[:5]:
            probe = f"{base}?{urlencode({param: payload})}"
            try:
                resp = await client.get(probe, timeout=12.0)
                bl = (resp.text or "").lower()
                matched_sigs = [s for s in SQL_ERROR_SIGNS if s in bl and s not in baseline_lower]
                if matched_sigs:
                    findings.append(
                        _f(
                            f"sqli-fuzz-{param}",
                            "SQL Injection",
                            "High",
                            base,
                            f"Parameter '{param}' triggers database error messages.",
                            "Use parameterised queries. Never concatenate SQL with user input.",
                            evidence=f"SQL error ({matched_sigs[0]}) after ?{param}=",
                            parameter=param,
                            cwe="89",
                            confidence="Firm",
                            owasp="A03:2021 — Injection",
                        )
                    )
                    break
            except Exception:
                pass

        # Command injection (params like cmd, exec, file, path)
        if param in ("cmd", "exec", "command", "file", "path", "page", "dir", "folder", "ip", "host"):
            for payload in CMD_PAYLOADS[:4]:
                probe = f"{base}?{urlencode({param: payload})}"
                try:
                    resp = await client.get(probe, timeout=10.0)
                    bl = (resp.text or "").lower()
                    if any(s in bl for s in CMD_SIGNS):
                        findings.append(
                            _f(
                                f"cmdi-fuzz-{param}",
                                "Command Injection",
                                "High",
                                base,
                                f"Parameter '{param}' may pass input to an OS command interpreter.",
                                "Never pass user input to shell commands. Use safe APIs.",
                                evidence=f"OS output pattern after ?{param}=",
                                parameter=param,
                                cwe="78",
                                confidence="Firm",
                                owasp="A03:2021 — Injection",
                            )
                        )
                        break
                except Exception:
                    pass

        # Open redirect
        if param in ("redirect", "url", "next", "return", "goto", "dest", "redir", "continue", "target"):
            probe = f"{base}?{urlencode({param: 'https://shieldscan-probe.example/out'})}"
            try:
                resp = await client.get(probe, follow_redirects=False, timeout=10.0)
                loc = resp.headers.get("location", "")
                if "shieldscan-probe.example" in loc:
                    findings.append(
                        _f(
                            f"redirect-fuzz-{param}",
                            "Open Redirect",
                            "Medium",
                            base,
                            f"Parameter '{param}' redirects to attacker-controlled URLs.",
                            "Allowlist redirect destinations.",
                            evidence=f"Location: {loc[:200]}",
                            parameter=param,
                            cwe="601",
                            owasp="A01:2021 — Broken Access Control",
                        )
                    )
            except Exception:
                pass

        # SSRF attack surface — one combined finding per scan
        if param in ("url", "uri", "path", "file", "fetch", "src", "load", "callback"):
            ssrf_params.append(param)

    if ssrf_params:
        findings.append(
            _f(
                "ssrf-surface-combined",
                "SSRF Attack Surface — URL-Accepting Parameters Detected",
                "Low",
                base,
                "Parameters that accept URLs can enable server-side request forgery if not validated.",
                "Validate and allowlist URLs. Block requests to internal IPs (127.0.0.1, 169.254.x.x).",
                evidence=f"Tested parameters: {', '.join(dict.fromkeys(ssrf_params))}",
                cwe="918",
                owasp="A10:2021 — Server-Side Request Forgery (SSRF)",
            )
        )

    return findings


async def collect_forms_from_pages(pages: list[str], client: httpx.AsyncClient) -> list[FormInfo]:
    """Re-fetch crawled pages and extract all HTML forms."""
    forms: list[FormInfo] = []
    seen: set[str] = set()
    for page in pages[:40]:
        if page in seen:
            continue
        seen.add(page)
        try:
            resp = await client.get(page, timeout=10.0)
            forms.extend(_extract_forms_from_html(str(resp.url), resp.text or ""))
        except Exception:
            pass
    return forms


async def check_idor(crawl: CrawlResult, client: httpx.AsyncClient) -> list[Finding]:
    """Detect potential IDOR when numeric IDs return different content."""
    findings: list[Finding] = []

    checked: set[str] = set()
    for page_url, param, value in crawl.param_urls:
        if not value.isdigit():
            continue
        key = f"{urlparse(page_url).path}:{param}"
        if key in checked:
            continue
        checked.add(key)

        parsed = urlparse(page_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        orig_id = int(value)
        test_id = orig_id + 1 if orig_id < 9999 else orig_id - 1
        params[param] = str(test_id)
        test_url = urlunparse(parsed._replace(query=urlencode(params)))

        try:
            r1 = await client.get(page_url, timeout=10.0)
            r2 = await client.get(test_url, timeout=10.0)
            if r1.status_code == 200 and r2.status_code == 200:
                len1, len2 = len(r1.text or ""), len(r2.text or "")
                if abs(len1 - len2) > 50 and len1 > 200:
                    findings.append(
                        _f(
                            f"idor-{param}-{orig_id}",
                            "Broken Access Control — Potential IDOR",
                            "High",
                            page_url,
                            f"Changing '{param}' from {orig_id} to {test_id} returns different content without auth.",
                            "Verify the user is authorised to access each object ID.",
                            evidence=f"Response sizes: {len1} vs {len2} bytes",
                            parameter=param,
                            cwe="639",
                            confidence="Medium",
                            owasp="A01:2021 — Broken Access Control",
                        )
                    )
        except Exception:
            pass

    # Path-based numeric IDs: /user/1 vs /user/2
    for page in crawl.pages:
        m = re.search(r"/(user|users|account|order|item|product|profile)s?/(\d+)", page, re.I)
        if not m:
            continue
        num = int(m.group(2))
        alt = page.replace(f"/{num}", f"/{num + 1}")
        if alt == page:
            continue
        try:
            r1 = await client.get(page, timeout=10.0)
            r2 = await client.get(alt, timeout=10.0)
            if r1.status_code == 200 and r2.status_code == 200 and len(r1.text) != len(r2.text):
                findings.append(
                    _f(
                        f"idor-path-{num}",
                        "Broken Access Control — Potential IDOR in URL Path",
                        "High",
                        page,
                        "Sequential resource IDs return different data without authentication.",
                        "Enforce object-level authorisation on every request.",
                        evidence=f"/{num} vs /{num+1} — different responses",
                        cwe="639",
                        owasp="A01:2021 — Broken Access Control",
                    )
                )
        except Exception:
            pass

    return findings


async def check_vulnerable_components(url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url, timeout=12.0)
        html = resp.text or ""
        for pattern, max_minor, msg in JQUERY_VULN:
            m = re.search(pattern, html, re.I)
            if m:
                if max_minor is not None and m.lastindex:
                    minor = int(m.group(1))
                    if minor > max_minor:
                        continue
                findings.append(
                    _f(
                        f"vuln-lib-{pattern[:20]}",
                        f"Vulnerable and Outdated Component — {msg}",
                        "Medium",
                        url,
                        "Outdated JavaScript libraries may contain known CVEs exploitable via XSS.",
                        "Upgrade to the latest stable version and monitor dependencies.",
                        evidence=m.group(0)[:100],
                        cwe="1104",
                        owasp="A06:2021 — Vulnerable and Outdated Components",
                    )
                )
    except Exception:
        pass
    return findings


async def check_error_disclosure(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    probes = [
        urljoin(base_url, "/shieldscan-nonexistent-page-404-test"),
        f"{base_url.rstrip('/')}?id=1'",
        urljoin(base_url, "/%00"),
    ]
    leak_patterns = (
        "stack trace", "exception", "traceback", "fatal error", "syntax error",
        "undefined index", "warning:", "notice:", "at line", ".php on line",
        "microsoft ole db", "odbc sql server", "internal server error",
    )
    for probe in probes:
        try:
            resp = await client.get(probe, timeout=10.0)
            bl = (resp.text or "").lower()
            for pat in leak_patterns:
                if pat in bl:
                    findings.append(
                        _f(
                            f"error-leak-{hash(probe) % 10000}",
                            "Security Logging and Monitoring — Verbose Error Disclosure",
                            "Medium",
                            probe,
                            "Detailed error messages help attackers understand application internals.",
                            "Use custom error pages. Log details server-side only.",
                            evidence=bl[bl.find(pat) : bl.find(pat) + 120],
                            cwe="209",
                            owasp="A09:2021 — Security Logging and Monitoring Failures",
                        )
                    )
                    break
        except Exception:
            pass
    return findings


async def check_csrf_all_forms(forms: list[FormInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for i, form in enumerate(forms):
        if form.method != "post":
            continue
        sensitive = any(
            k in f.lower()
            for f in form.fields
            for k in ("password", "email", "user", "amount", "transfer", "delete", "submit")
        )
        if not form.has_csrf_token:
            risk = "Medium" if sensitive else "Low"
            findings.append(
                _f(
                    f"csrf-form-{i}",
                    "Cross-Site Request Forgery (CSRF) — Form Missing Token",
                    risk,
                    form.page_url,
                    "POST form lacks a visible CSRF token — state-changing actions may be forged.",
                    "Add and validate CSRF tokens on all POST/PUT/DELETE forms.",
                    evidence=f"action={form.action_url}, fields={form.fields[:6]}",
                    parameter=form.action_url,
                    cwe="352",
                    owasp="A01:2021 — Broken Access Control",
                )
            )
    return findings


async def check_insecure_design(forms: list[FormInfo], pages: list[str], client: httpx.AsyncClient) -> list[Finding]:
    """OWASP A04:2021 — Insecure Design checks (weak recovery flows, missing anti-automation)."""
    findings: list[Finding] = []
    captcha_re = re.compile(r"captcha|recaptcha|hcaptcha|turnstile|cf-turnstile", re.I)

    for i, form in enumerate(forms):
        action_lower = (form.action_url or "").lower()
        fields_lower = [f.lower() for f in form.fields]
        is_recovery_or_reset = any(
            k in action_lower or any(k in fl for fl in fields_lower)
            for k in ("reset", "forgot", "recover", "password_new", "password_conf")
        )
        if is_recovery_or_reset and not any(
            k in fl for fl in fields_lower for k in ("password_current", "old_password", "token", "reset_token", "code", "otp")
        ):
            findings.append(
                _f(
                    f"insecure-design-reset-{i}",
                    "Insecure Design — Password Change/Reset Without Current Password or Verification Token",
                    "High",
                    form.page_url,
                    "Password change or recovery form does not require the current password or a one-time reset token.",
                    "Require the existing password or a time-limited cryptographic reset token before changing credentials.",
                    evidence=f"action={form.action_url}, fields={form.fields[:6]}",
                    parameter=form.action_url,
                    cwe="640",
                    confidence="Firm",
                    owasp="A04:2021 — Insecure Design",
                )
            )

        is_high_abuse_form = any(
            k in action_lower or any(k in fl for fl in fields_lower)
            for k in ("register", "signup", "contact", "feedback", "comment", "guestbook", "mtxmessage")
        )
        if is_high_abuse_form:
            try:
                resp = await client.get(form.page_url, timeout=8.0)
                if not captcha_re.search(resp.text or ""):
                    findings.append(
                        _f(
                            f"insecure-design-automation-{i}",
                            "Insecure Design — Public Form Lacks Anti-Automation / Rate Control",
                            "Low",
                            form.page_url,
                            "Public submission or registration workflow has no visible CAPTCHA or anti-automation challenge.",
                            "Add rate limiting and CAPTCHA/bot protection on public submission and signup forms.",
                            evidence=f"Form at {form.action_url} has no CAPTCHA markers",
                            parameter=form.action_url,
                            cwe="799",
                            confidence="Medium",
                            owasp="A04:2021 — Insecure Design",
                        )
                    )
            except Exception:
                pass

    return findings


async def check_subresource_integrity(url: str, client: httpx.AsyncClient) -> list[Finding]:
    """OWASP A08:2021 — Software and Data Integrity Failures (external scripts/styles without SRI)."""
    findings: list[Finding] = []
    parsed_target = urlparse(url)
    target_host = (parsed_target.hostname or "").lower()

    try:
        resp = await client.get(url, timeout=10.0)
        html = resp.text or ""
        for m in re.finditer(r"<script\b[^>]*\bsrc=[\"'](https?://[^\"']+)[\"'][^>]*>", html, re.I):
            tag = m.group(0)
            src = m.group(1)
            src_host = (urlparse(src).hostname or "").lower()
            if src_host and src_host != target_host and "integrity=" not in tag.lower():
                findings.append(
                    _f(
                        f"sri-missing-{hash(src) % 10000}",
                        "Subresource Integrity (SRI) Missing on External Script",
                        "Medium",
                        url,
                        "External JavaScript is loaded from a third-party origin without an integrity hash.",
                        "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" attributes to third-party script tags.",
                        evidence=tag[:180],
                        parameter=src[:120],
                        cwe="353",
                        confidence="High",
                        owasp="A08:2021 — Software and Data Integrity Failures",
                    )
                )
    except Exception:
        pass

    return findings


async def run_owasp_top10_probes(
    target_url: str,
    client: httpx.AsyncClient,
    crawl: CrawlResult,
    on_progress=None,
) -> list[Finding]:
    """Full OWASP Top 10 oriented probe suite."""
    findings: list[Finding] = []
    all_forms = list(crawl.forms)

    if on_progress:
        on_progress("OWASP A01/A07: Probing login, admin, and API paths")
    path_findings, extra_pages, path_forms = await probe_common_paths(target_url, client)
    findings.extend(path_findings)
    all_forms.extend(path_forms)

    if on_progress:
        on_progress("Collecting forms from all crawled pages")
    all_forms.extend(await collect_forms_from_pages(crawl.pages + extra_pages, client))
    # Deduplicate forms by action+page
    seen_forms: set[str] = set()
    unique_forms: list[FormInfo] = []
    for form in all_forms:
        key = f"{form.page_url}|{form.action_url}|{form.method}"
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(form)
    all_forms = unique_forms

    # Auth analysis on any page with a login form
    for form in all_forms:
        if any("pass" in f.lower() for f in form.fields):
            try:
                resp = await client.get(form.page_url, timeout=10.0)
                findings.extend(_analyse_login_page(form.page_url, resp.text or "", client))
            except Exception:
                pass

    if on_progress:
        on_progress("OWASP A03: Fuzzing URL parameters on homepage and crawled pages")
    settings = get_settings()
    budget = settings.get_fuzz_budget()
    fuzz_targets = [target_url] + [p for p in crawl.pages[:12] if p != target_url]
    seen_fuzz: set[str] = set()
    for ft in fuzz_targets:
        norm = ft.split("#")[0]
        if norm in seen_fuzz:
            continue
        seen_fuzz.add(norm)
        findings.extend(await fuzz_url_parameters(norm, client, max_params=budget["max_params"]))

    if on_progress:
        on_progress("OWASP A01: Testing for IDOR and access control issues")
    findings.extend(await check_idor(crawl, client))

    if on_progress:
        on_progress("OWASP A04: Checking workflow forms for insecure design patterns")
    findings.extend(await check_insecure_design(all_forms, crawl.pages, client))

    if on_progress:
        on_progress("OWASP A06: Checking for outdated JavaScript components")
    findings.extend(await check_vulnerable_components(target_url, client))
    for page in extra_pages[:12]:
        findings.extend(await check_vulnerable_components(page, client))
    for page in crawl.pages[:8]:
        findings.extend(await check_vulnerable_components(page, client))

    if on_progress:
        on_progress("OWASP A08: Checking subresource integrity on external scripts")
    findings.extend(await check_subresource_integrity(target_url, client))
    for page in crawl.pages[:8]:
        if page != target_url:
            findings.extend(await check_subresource_integrity(page, client))

    if on_progress:
        on_progress("OWASP A09: Checking for verbose error disclosure")
    findings.extend(await check_error_disclosure(target_url, client))

    if on_progress:
        on_progress("OWASP A01: Analysing forms for CSRF protection")
    findings.extend(await check_csrf_all_forms(all_forms))

    # Probe forms on discovered pages
    if on_progress:
        on_progress("OWASP A03: Testing discovered forms for injection")
    from app.services.extended_checks import probe_forms_extended

    findings.extend(await probe_forms_extended(all_forms, client))

    # Re-probe crawl param URLs with full probe suite
    if crawl.param_urls:
        from app.services.extended_checks import probe_url_parameters

        findings.extend(await probe_url_parameters(crawl.param_urls, client, max_probes=budget["max_params"]))

    return findings
