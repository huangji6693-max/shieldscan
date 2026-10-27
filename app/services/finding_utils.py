"""Normalise findings for display — fill missing parameter labels, filter false positives, and calibrate severity."""

from urllib.parse import urlparse

from app.schemas import Finding
from app.services.owasp import classify_owasp

VALID_RISKS = ("Critical", "High", "Medium", "Low", "Informational")
RISK_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}

CONFIDENCE_MAP = {
    "high": "High",
    "firm": "Firm",
    "medium": "Medium",
    "low": "Low",
    "confirmed": "High",
}


def is_false_positive(finding: Finding) -> bool:
    """Detect common scanner false positives before reporting."""
    name = (finding.name or "").lower()
    ev = (finding.evidence or "").lower()

    # Reflected XSS where angle brackets were HTML-entity encoded and not executable
    if "xss" in name or "cross-site scripting" in name:
        if ("&lt;script" in ev or "&lt;svg" in ev or "&lt;img" in ev) and "<script" not in ev and "<svg" not in ev and "<img" not in ev:
            return True

    # Noise jQuery 3.x informational pattern without CVE match
    if "jquery version detected — verify against cve database" in name and finding.confidence.lower() == "low":
        return True

    return False


def filter_false_positives(findings: list[Finding]) -> list[Finding]:
    """Filter out known false-positive findings."""
    return [f for f in findings if not is_false_positive(f)]


def calibrate_finding_severity(finding: Finding) -> Finding:
    """Calibrate risk level and confidence based on evidence and vulnerability class."""
    raw_risk = (finding.risk or "Informational").strip().lower()
    risk = RISK_MAP.get(raw_risk, "Informational")

    raw_conf = (finding.confidence or "Medium").strip().lower()
    confidence = CONFIDENCE_MAP.get(raw_conf, "Medium")

    name = (finding.name or "").lower()
    ev = (finding.evidence or "").lower()
    owasp_cat = finding.owasp_category or classify_owasp(finding.cwe, finding.name)

    # Upgrade verified RCE / Command Injection / LFI / SQLi with concrete OS/DB proof to Critical
    if confidence in ("High", "Firm"):
        if any(k in name for k in ("command injection", "local file inclusion", "path traversal")) and any(
            sig in ev for sig in ("uid=", "gid=", "root:x:0", "os output pattern", "system file content")
        ):
            risk = "Critical"
        elif "sql injection" in name and any(
            sig in ev for sig in ("sql syntax", "mysql", "sqlite", "postgresql", "database error", "sql error")
        ):
            risk = "Critical" if "union" in ev or "syntax" in ev else max_risk(risk, "High")

    # Downgrade speculative High findings when confidence is Low and evidence is weak
    if risk == "High" and confidence == "Low" and not ev:
        risk = "Medium"

    # Passive informational headers should never exceed Medium
    if finding.source == "passive" and "header" in name and risk in ("Critical", "High"):
        risk = "Medium"

    return finding.model_copy(
        update={
            "risk": risk,
            "confidence": confidence,
            "owasp_category": owasp_cat,
        }
    )


def max_risk(r1: str, r2: str) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    return r1 if order.get(r1, 0) >= order.get(r2, 0) else r2


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings across phases by normalised vulnerability class, URL path, and parameter."""
    seen: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        parsed = urlparse(f.url or "")
        norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/') or '/'}"
        norm_name = (f.name or "").strip().lower()
        # Consolidate Reflected XSS / SQLi across builtin, owasp-probe, and deep-probe on the same parameter
        if "reflected cross-site scripting" in norm_name or "reflected xss" in norm_name:
            norm_name = "reflected cross-site scripting (xss)"
        elif norm_name.startswith("sql injection"):
            norm_name = "sql injection"
        elif "missing" in norm_name and "csrf" in norm_name:
            norm_name = "csrf form missing token"

        norm_param = (f.parameter or "").strip().lower()
        key = (norm_name, norm_url, norm_param)
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            if max_risk(f.risk, existing.risk) != existing.risk:
                seen[key] = f
    return list(seen.values())


def enrich_finding_parameter(finding: Finding) -> Finding:
    """Assign a meaningful parameter label when scanners leave it blank."""
    if finding.parameter and finding.parameter.strip():
        return finding

    name = finding.name.lower()
    fid = finding.id.lower()

    if fid.startswith("header-") or "header" in name or "content-security-policy" in name:
        param = "Site security settings"
    elif "cookie" in name:
        param = "Login cookies"
    elif any(k in name for k in ("tls", "certificate", "ssl", "https")):
        param = "Secure connection (HTTPS)"
    elif "cors" in name:
        param = "Access-Control-Allow-Origin"
    elif "csrf" in name:
        param = "HTML form (no CSRF token)"
    elif "subresource integrity" in name or "sri" in name:
        param = "External script/stylesheet tag"
    elif "insecure design" in name:
        param = "Business workflow form"
    elif "directory listing" in name:
        param = urlparse(finding.url).path or "URL path"
    elif any(k in name for k in ("exposed", "disclosure", "backup", "git", ".env")):
        param = urlparse(finding.url).path or "URL path"
    elif "redirect" in name:
        param = "redirect URL parameter"
    elif "authentication" in name or "login" in name:
        param = "Login endpoint"
    elif finding.source == "passive":
        param = "HTTP response"
    elif finding.evidence:
        param = "(see evidence)"
    else:
        param = "Whole site"

    return finding.model_copy(update={"parameter": param})


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Filter false positives, calibrate severity, deduplicate, and enrich parameter labels."""
    filtered = filter_false_positives(findings)
    calibrated = [calibrate_finding_severity(f) for f in filtered]
    deduped = deduplicate_findings(calibrated)
    return [enrich_finding_parameter(f) for f in deduped]
