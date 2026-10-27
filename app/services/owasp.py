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
    "22": "A01:2021",
    "287": "A07:2021",
    "306": "A07:2021",
    "798": "A07:2021",
    "311": "A02:2021",
    "319": "A02:2021",
    "326": "A02:2021",
    "327": "A02:2021",
    "614": "A05:2021",
    "693": "A05:2021",
    "1021": "A05:2021",
    "829": "A06:2021",
    "918": "A10:2021",
}


def classify_owasp(cwe: str = "", alert_name: str = "") -> str:
    cwe_num = "".join(ch for ch in cwe if ch.isdigit())
    if cwe_num in CWE_TO_OWASP:
        code = CWE_TO_OWASP[cwe_num]
        return f"{code} — {OWASP_MAP[code]}"

    name = alert_name.lower()
    if any(k in name for k in ("sql", "injection", "xss", "script", "command", "ldap", "xpath")):
        return "A03:2021 — Injection"
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
    """Calculate the letter safety grade (A-F) from severity counts.

    Algorithm:
    - Critical > 2 -> F; Critical >= 1 -> D
    - High > 3 -> D; High >= 1 -> C
    - Medium > 5 -> C; Medium >= 1 -> B
    - 0 Critical, 0 High, 0 Medium -> A
    """
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


def explain_risk_rule(critical: int, high: int, medium: int, low: int = 0) -> dict[str, str | int]:
    """Return the letter grade, numeric safety score (0-100), and plain-English explanation."""
    grade = risk_grade(critical, high, medium)
    penalty = (critical * 25) + (high * 12) + (medium * 4) + (low * 1)
    numeric_score = max(0, 100 - penalty)
    reasons = {
        "A": "No critical, high, or medium risks detected.",
        "B": "Only moderate configuration issues found (1-5 medium findings, 0 high/critical).",
        "C": "Serious or numerous moderate issues require developer attention (1-3 high or >5 medium).",
        "D": "High-risk vulnerabilities present (1-2 critical or >3 high findings).",
        "F": "Urgent intervention required (>2 critical vulnerabilities).",
    }
    return {
        "grade": grade,
        "numeric_score": numeric_score,
        "explanation": reasons[grade],
    }


OWASP_REMEDIATION_CARDS: dict[str, dict[str, str]] = {
    "A01:2021": {
        "code": "A01:2021",
        "title": "Access Control & Form Protection",
        "what_it_means": "Pages or actions that should be private can be opened or triggered without proper checks.",
        "how_to_fix": "Require login on admin/user pages, verify user ownership for every record ID, and add CSRF tokens to all POST forms.",
    },
    "A02:2021": {
        "code": "A02:2021",
        "title": "Data & Connection Encryption",
        "what_it_means": "Passwords or cookies may travel over unencrypted connections where attackers on Wi-Fi can read them.",
        "how_to_fix": "Enable HTTPS across your entire website, redirect HTTP to HTTPS, and mark login cookies with Secure and HttpOnly.",
    },
    "A03:2021": {
        "code": "A03:2021",
        "title": "Input & Database Injection",
        "what_it_means": "Search boxes, URL parameters, or forms accept untrusted commands that can read your database or run scripts.",
        "how_to_fix": "Use prepared/parameterised database queries and escape all user text before displaying it on a page.",
    },
    "A04:2021": {
        "code": "A04:2021",
        "title": "Safe Workflow Design",
        "what_it_means": "Important business forms (like password resets or public submissions) lack verification steps or spam protection.",
        "how_to_fix": "Require one-time reset tokens for password recovery and add CAPTCHA or rate limits to public forms.",
    },
    "A05:2021": {
        "code": "A05:2021",
        "title": "Website Security Settings",
        "what_it_means": "Browser safety headers are missing or internal folders/files (.env, backups) are publicly visible.",
        "how_to_fix": "Add standard security headers (CSP, HSTS, X-Frame-Options), disable directory listing, and block access to dotfiles and backups.",
    },
    "A06:2021": {
        "code": "A06:2021",
        "title": "Outdated Website Libraries",
        "what_it_means": "Your website loads older JavaScript or framework versions that have publicly known security bugs.",
        "how_to_fix": "Update jQuery, Bootstrap, WordPress plugins, and frontend packages to their current stable versions.",
    },
    "A07:2021": {
        "code": "A07:2021",
        "title": "Login & Account Protection",
        "what_it_means": "Login forms allow unlimited password guessing or expose credentials in browser history.",
        "how_to_fix": "Serve login forms over HTTPS POST only, limit failed login attempts, and enable two-factor authentication for admins.",
    },
    "A08:2021": {
        "code": "A08:2021",
        "title": "Software & Script Integrity",
        "what_it_means": "External scripts loaded from third-party CDNs are not verified with cryptographic hashes.",
        "how_to_fix": "Add Subresource Integrity (integrity='sha384-...') attributes to third-party script tags.",
    },
    "A09:2021": {
        "code": "A09:2021",
        "title": "Error Messages & Monitoring",
        "what_it_means": "Detailed technical error messages or stack traces are shown to visitors when something breaks.",
        "how_to_fix": "Show friendly generic error pages to visitors and keep technical stack traces in private server logs only.",
    },
    "A10:2021": {
        "code": "A10:2021",
        "title": "Outbound Server Requests (SSRF)",
        "what_it_means": "URL parameters accept external web addresses that could trick your server into fetching internal resources.",
        "how_to_fix": "Allowlist trusted domains and block requests to internal/private IP addresses (127.0.0.1, 169.254.x.x).",
    },
}


def get_remediation_card(owasp_category: str) -> dict[str, str]:
    code = (owasp_category or "").split(" ")[0].strip()
    return dict(OWASP_REMEDIATION_CARDS.get(code, OWASP_REMEDIATION_CARDS["A05:2021"]))


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
