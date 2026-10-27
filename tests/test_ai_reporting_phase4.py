"""Phase 4 tests: grounded AI reporting, anti-hallucination filter, OWASP remediation cards, safety score algorithm, and passphrase-encrypted secrets."""

import re

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app
from app.schemas import Finding
from app.services.ai_reporter import (
    CITATION_PATTERN,
    CVE_PATTERN,
    generate_template_report,
    sanitize_grounded_report,
)
from app.services.owasp import (
    OWASP_REMEDIATION_CARDS,
    explain_risk_rule,
    get_remediation_card,
    risk_grade,
)
from app.services.secrets import (
    decrypt_secret,
    encrypt_secret,
    is_encrypted_secret,
    resolve_anthropic_api_key,
    validate_settings,
)

client = TestClient(app)


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            id="sqli-fuzz-id",
            name="SQL Injection",
            risk="High",
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
            id="header-content-security-policy",
            name="Missing Content-Security-Policy Header",
            risk="Medium",
            confidence="High",
            url="http://127.0.0.1:4280/",
            parameter="Site security settings",
            evidence="Response headers missing content-security-policy",
            description="CSP helps prevent XSS.",
            solution="Add a Content-Security-Policy header.",
            owasp_category="A05:2021 — Security Misconfiguration",
            source="passive",
        ),
    ]


def test_template_report_cites_only_present_findings_and_no_hallucinated_cves():
    findings = _sample_findings()
    executive, grade, report = generate_template_report("http://127.0.0.1:4280", findings)

    assert grade == "C"
    assert "safety score of **C**" in executive
    cited_ids = {m.strip() for m in CITATION_PATTERN.findall(report)}
    valid_ids = {f.id for f in findings}
    assert cited_ids == valid_ids
    assert CVE_PATTERN.findall(report) == []
    assert "Plain-English Remediation Guide by Category" in report


def test_sanitize_grounded_report_strips_hallucinated_ids_and_cves():
    findings = _sample_findings()
    raw_ai_output = (
        "1. Fix SQL Injection [ID: sqli-fuzz-id] and phantom bug [ID: hallucinated-id-999]. "
        "This relates to CVE-2099-12345 which was never in the scan."
    )
    cleaned = sanitize_grounded_report(raw_ai_output, findings)
    assert "[ID: sqli-fuzz-id]" in cleaned
    assert "hallucinated-id-999" not in cleaned
    assert "CVE-2099-12345" not in cleaned
    assert "a known security advisory" in cleaned


def test_owasp_remediation_cards_and_dashboard_ux():
    assert len(OWASP_REMEDIATION_CARDS) == 10
    card_a03 = get_remediation_card("A03:2021 — Injection")
    assert card_a03["code"] == "A03:2021"
    assert "parameterised" in card_a03["how_to_fix"].lower()

    resp = client.get("/")
    assert resp.status_code == 200
    assert 'id="remediation-cards"' in resp.text
    assert "Plain-English Fix Guide by Category" in resp.text


def test_safety_score_algorithm_grades_a_through_f():
    assert risk_grade(0, 0, 0) == "A"
    assert risk_grade(0, 0, 2) == "B"
    assert risk_grade(0, 1, 0) == "C"
    assert risk_grade(0, 0, 6) == "C"
    assert risk_grade(1, 0, 0) == "D"
    assert risk_grade(0, 4, 0) == "D"
    assert risk_grade(3, 0, 0) == "F"

    explained = explain_risk_rule(1, 2, 1, 0)
    assert explained["grade"] == "D"
    assert explained["numeric_score"] == 100 - (25 + 24 + 4)
    assert re.search(r"High-risk vulnerabilities", str(explained["explanation"]))


def test_passphrase_encrypted_api_key_storage_and_production_warning(monkeypatch):
    plaintext_key = "sk-ant-api03-test-secret-key-value-123456"
    passphrase = "correct-horse-battery-staple"

    encrypted = encrypt_secret(plaintext_key, passphrase)
    assert is_encrypted_secret(encrypted)
    assert plaintext_key not in encrypted
    assert decrypt_secret(encrypted, passphrase) == plaintext_key

    with pytest.raises(ValueError, match="Invalid passphrase"):
        decrypt_secret(encrypted, "wrong-passphrase")

    settings_enc = Settings(anthropic_api_key=encrypted)
    assert resolve_anthropic_api_key(settings_enc, passphrase=passphrase) == plaintext_key

    # Production warning when ANTHROPIC_API_KEY is stored in plaintext without encryption
    monkeypatch.setenv("SHIELDSCAN_ENV", "production")
    settings_plain = Settings(
        zap_api_key="strong-prod-zap-key-999",
        anthropic_api_key=plaintext_key,
    )
    warnings = validate_settings(settings_plain)
    assert any("stored in plaintext without encryption" in w for w in warnings)

    # Encrypted key with passphrase set in production produces no plaintext warning
    monkeypatch.setenv("SHIELDSCAN_SECRET_PASSPHRASE", passphrase)
    settings_secure = Settings(
        zap_api_key="strong-prod-zap-key-999",
        anthropic_api_key=encrypted,
    )
    warnings_secure = validate_settings(settings_secure)
    assert not any("stored in plaintext" in w for w in warnings_secure)
