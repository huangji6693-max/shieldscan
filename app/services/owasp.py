"""Map CWE and alert names to OWASP Top 10 2021 categories."""

OWASP_MAP = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

CWE_TO_OWASP = {
    "79": "A03:2021",
    "89": "A03:2021",
    "78": "A03:2021",
    "94": "A03:2021",
    "98": "A03:2021",
    "22": "A01:2021",
    "284": "A01:2021",
    "352": "A01:2021",
    "601": "A01:2021",
    "639": "A01:2021",
    "287": "A07:2021",
    "306": "A07:2021",
    "307": "A07:2021",
    "798": "A07:2021",
    "311": "A02:2021",
    "319": "A02:2021",
    "326": "A02:2021",
    "327": "A02:2021",
    "640": "A04:2021",
    "799": "A04:2021",
    "840": "A04:2021",
    "614": "A05:2021",
    "693": "A05:2021",
    "1021": "A05:2021",
    "829": "A06:2021",
    "1104": "A06:2021",
    "353": "A08:2021",
    "494": "A08:2021",
    "502": "A08:2021",
    "209": "A09:2021",
    "918": "A10:2021",
}


def classify_owasp(cwe: str = "", alert_name: str = "") -> str:
    cwe_num = "".join(ch for ch in cwe if ch.isdigit())
    if cwe_num in CWE_TO_OWASP:
        code = CWE_TO_OWASP[cwe_num]
        return f"{code} — {OWASP_MAP[code]}"

    name = alert_name.lower()
    if any(k in name for k in ("sql", "injection", "xss", "script", "command", "ldap", "xpath", "ssti", "lfi")):
        return "A03:2021 — Injection"
    if any(k in name for k in ("subresource integrity", "sri", "deserialization", "integrity")):
        return "A08:2021 — Software and Data Integrity Failures"
    if any(k in name for k in ("insecure design", "business logic", "password reset", "anti-automation")):
        return "A04:2021 — Insecure Design"
    if any(k in name for k in ("cookie", "ssl", "tls", "crypto", "hash", "password")):
        return "A02:2021 — Cryptographic Failures"
    if any(k in name for k in ("auth", "session", "login", "credential")):
        return "A07:2021 — Identification and Authentication Failures"
    if any(k in name for k in ("header", "csp", "cors", "config", "disclosure", "path")):
        return "A05:2021 — Security Misconfiguration"
    if any(k in name for k in ("csrf", "cross-site request")):
        return "A01:2021 — Broken Access Control"
    if any(k in name for k in ("idor", "access control", "open redirect", "redirect")):
        return "A01:2021 — Broken Access Control"
    if "ssrf" in name:
        return "A10:2021 — Server-Side Request Forgery (SSRF)"
    return "A05:2021 — Security Misconfiguration"


def risk_grade(critical: int, high: int, medium: int) -> str:
    if critical > 0:
        return "F" if critical > 2 else "D"
    if high > 3:
        return "D"
    if high > 0:
        return "C"
    if medium > 5:
        return "C"
    if medium > 0:
        return "B"
    return "A"


def progress_for_status(status: str) -> int:
    return {
        "queued": 5,
        "running": 10,
        "spidering": 25,
        "passive_scan": 45,
        "active_scan": 70,
        "ai_reporting": 90,
        "complete": 100,
        "failed": 100,
    }.get(status, 0)
