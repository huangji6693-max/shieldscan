"""SARIF v2.1.0 report exporter compatible with GitHub Code Scanning."""

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from app.schemas import Finding

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"

RISK_TO_SARIF_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "note",
}

RISK_TO_SECURITY_SEVERITY = {
    "Critical": "9.5",
    "High": "8.0",
    "Medium": "5.5",
    "Low": "3.0",
    "Informational": "1.0",
}

CONFIDENCE_TO_PRECISION = {
    "High": "very-high",
    "Firm": "high",
    "Medium": "medium",
    "Low": "low",
}


def _rule_id_for_finding(finding: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (finding.name or "shieldscan-finding").lower()).strip("-")
    if finding.cwe:
        cwe_digits = "".join(ch for ch in finding.cwe if ch.isdigit())
        if cwe_digits:
            return f"SHIELDSCAN-CWE-{cwe_digits}-{slug[:40]}"
    return f"SHIELDSCAN-{slug[:50]}"


def _artifact_uri(url: str) -> str:
    parsed = urlparse(url or "")
    path = (parsed.path or "/").lstrip("/")
    return path if path else "index.html"


def generate_sarif_report(
    scan_id: int,
    target_url: str,
    findings: list[Finding],
    scanner_version: str = "3.0",
) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 dictionary for a scan's findings."""
    rules: list[dict[str, Any]] = []
    rule_index_by_id: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id_for_finding(finding)
        level = RISK_TO_SARIF_LEVEL.get(finding.risk, "note")
        sec_severity = RISK_TO_SECURITY_SEVERITY.get(finding.risk, "1.0")
        precision = CONFIDENCE_TO_PRECISION.get(finding.confidence, "medium")

        if rule_id not in rule_index_by_id:
            tags = ["security", "dast"]
            if finding.owasp_category:
                tags.append(finding.owasp_category)
            cwe_digits = "".join(ch for ch in (finding.cwe or "") if ch.isdigit())
            if cwe_digits:
                tags.append(f"external/cwe/cwe-{cwe_digits}")

            rule_index_by_id[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": re.sub(r"[^A-Za-z0-9]", "", finding.name.title()) or "ShieldScanRule",
                    "shortDescription": {"text": finding.name},
                    "fullDescription": {
                        "text": finding.description or finding.name,
                    },
                    "help": {
                        "text": finding.solution or "Review and remediate this finding.",
                        "markdown": (
                            f"**Description:** {finding.description or finding.name}\n\n"
                            f"**Remediation:** {finding.solution or 'Review and remediate this finding.'}\n\n"
                            f"**OWASP Category:** {finding.owasp_category or 'Unclassified'}"
                        ),
                    },
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": tags,
                        "precision": precision,
                        "security-severity": sec_severity,
                    },
                }
            )

        rule_idx = rule_index_by_id[rule_id]
        artifact_uri = _artifact_uri(finding.url or target_url)
        fp_seed = f"{rule_id}|{finding.url}|{finding.parameter}"
        fp_hash = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]

        msg_parts = [f"{finding.name} at {finding.url}"]
        if finding.parameter:
            msg_parts.append(f"(parameter: {finding.parameter})")
        if finding.description:
            msg_parts.append(f"— {finding.description}")

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {"text": " ".join(msg_parts)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": fp_hash,
                },
                "properties": {
                    "finding_id": finding.id,
                    "url": finding.url,
                    "parameter": finding.parameter,
                    "risk": finding.risk,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "owasp_category": finding.owasp_category,
                    "evidence": finding.evidence,
                    "source": finding.source,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShieldScan",
                        "informationUri": "https://github.com/BreachDirect/shieldscan",
                        "version": scanner_version,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"shieldscan/scan-{scan_id}",
                },
                "results": results,
                "properties": {
                    "scan_id": scan_id,
                    "target_url": target_url,
                },
            }
        ],
    }
