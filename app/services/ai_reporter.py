import json
import logging
import re

from app.config import Settings
from app.schemas import Finding
from app.services.owasp import explain_risk_rule, get_remediation_card, risk_grade
from app.services.secrets import resolve_anthropic_api_key

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
CITATION_PATTERN = re.compile(r"\[ID:\s*([^\]]+)\]")


def _count_by_risk(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        key = f.risk if f.risk in counts else "Informational"
        counts[key] += 1
    return counts


def friendly_category_label(owasp: str) -> str:
    if not owasp:
        return "General security"
    if "—" in owasp:
        return owasp.split("—", 1)[1].strip()
    return owasp


def sanitize_grounded_report(report_text: str, findings: list[Finding]) -> str:
    """Ensure the report cites only valid finding IDs and contains no hallucinated CVE numbers."""
    valid_ids = {f.id for f in findings}
    allowed_cves: set[str] = set()
    for f in findings:
        blob = f"{f.name} {f.description} {f.evidence}"
        for m in CVE_PATTERN.findall(blob):
            allowed_cves.add(m.upper())

    def _replace_cve(match: re.Match[str]) -> str:
        cve = match.group(0).upper()
        return match.group(0) if cve in allowed_cves else "a known security advisory"

    cleaned = CVE_PATTERN.sub(_replace_cve, report_text)

    def _replace_citation(match: re.Match[str]) -> str:
        cited_id = match.group(1).strip()
        return f"[ID: {cited_id}]" if cited_id in valid_ids else ""

    cleaned = CITATION_PATTERN.sub(_replace_citation, cleaned)
    return cleaned


def generate_template_report(target_url: str, findings: list[Finding]) -> tuple[str, str, str]:
    """Grounded fallback report when no AI API key is configured (no hallucinated CVEs)."""
    counts = _count_by_risk(findings)
    grade = risk_grade(counts["Critical"], counts["High"], counts["Medium"])
    score_info = explain_risk_rule(counts["Critical"], counts["High"], counts["Medium"], counts["Low"])

    executive = (
        f"We checked {target_url} and gave it a safety score of **{grade}** "
        f"({score_info['numeric_score']}/100 — A is best, F needs urgent attention). "
        f"We found {len(findings)} issue(s): "
        f"{counts['Critical']} critical, {counts['High']} serious, {counts['Medium']} moderate, "
        f"{counts['Low']} minor, and {counts['Informational']} low-priority notes. "
    )
    if counts["High"] or counts["Critical"]:
        executive += (
            "Please fix the serious issues first — they could let someone steal data "
            "or break into your site."
        )
    else:
        executive += (
            "We did not find serious break-in risks, but improving your site settings "
            "and security headers is still recommended."
        )

    lines = [
        "# ShieldScan Security Report\n",
        f"**Target:** {target_url}\n",
        f"**Risk Grade:** {grade} ({score_info['numeric_score']}/100 — {score_info['explanation']})\n",
        f"**Total Findings:** {len(findings)}\n",
        "## Executive Summary\n",
        executive,
        "\n## Prioritised Findings\n",
    ]

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.risk, 5))

    seen_categories: list[str] = []
    for i, f in enumerate(sorted_findings[:20], 1):
        card = get_remediation_card(f.owasp_category)
        if card["code"] not in seen_categories:
            seen_categories.append(card["code"])
        lines.append(f"### {i}. [{f.risk}] {f.name} [ID: {f.id}]\n")
        lines.append(f"- **Finding ID:** `{f.id}`\n")
        lines.append(f"- **URL:** {f.url}\n")
        if f.parameter:
            lines.append(f"- **Parameter:** {f.parameter}\n")
        lines.append(f"- **Category:** {friendly_category_label(f.owasp_category)}\n")
        lines.append(f"- **What it means:** {f.description or card['what_it_means']}\n")
        lines.append(f"- **How to fix:** {f.solution or card['how_to_fix']}\n")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence[:200]}`\n")
        lines.append("\n")

    if seen_categories:
        lines.append("## Plain-English Remediation Guide by Category\n")
        for code in seen_categories:
            card = get_remediation_card(code)
            lines.append(f"### {card['code']} — {card['title']}\n")
            lines.append(f"- **Plain-English Meaning:** {card['what_it_means']}\n")
            lines.append(f"- **Recommended Fix:** {card['how_to_fix']}\n\n")

    lines.append("## Tips for small business owners\n")
    lines.append(
        "1. Fix serious problems within 48 hours if you handle customer data.\n"
        "2. Ask your developer to add basic security headers (your host can often help).\n"
        "3. Keep WordPress, plugins, and any shop software up to date.\n"
        "4. Run another scan after changes to confirm fixes worked.\n"
        "5. Before launching payments or personal data, consider a professional security review.\n"
    )

    full_report = sanitize_grounded_report("".join(lines), findings)
    return executive, grade, full_report


async def generate_ai_report(
    settings: Settings,
    target_url: str,
    findings: list[Finding],
) -> tuple[str, str, str]:
    api_key = resolve_anthropic_api_key(settings)
    if not api_key:
        return generate_template_report(target_url, findings)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        findings_payload = [f.model_dump() for f in findings]
        counts = _count_by_risk(findings)
        grade = risk_grade(counts["Critical"], counts["High"], counts["Medium"])

        prompt = f"""You are a friendly cybersecurity advisor writing a website security report for a small business owner (e.g. a shop, salon, or restaurant) with no IT background.

Target URL: {target_url}
Safety score (pre-calculated, A=best, F=urgent): {grade}
Findings (JSON): {json.dumps(findings_payload[:30], indent=2)}

Write a report with these sections:
1. EXECUTIVE SUMMARY (3-4 short sentences, everyday language, no acronyms unless you explain them)
2. TOP PRIORITIES (numbered list, most urgent first, max 5 items — cite each finding with [ID: <finding.id>])
3. DETAILED FINDINGS (for each finding: cite [ID: <finding.id>], plain explanation, business impact, simple fix steps)
4. NEXT STEPS (short checklist the owner can give their developer or host)

Rules:
- Only discuss findings in the JSON and cite their exact [ID: <id>]. Do NOT invent problems or hallucinate CVE numbers.
- Write like you're explaining to a smart non-technical person.
- Give practical fixes, not vague advice.
- Mention actual page URLs from the data."""

        message = client.messages.create(
            model=settings.ai_model,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_report = message.content[0].text
        full_report = sanitize_grounded_report(raw_report, findings)
        executive = full_report.split("TOP PRIORITIES")[0].replace("EXECUTIVE SUMMARY", "").strip()
        if len(executive) > 600:
            executive = executive[:600] + "..."
        return executive, grade, full_report
    except Exception as exc:
        logger.warning("AI report failed, using template: %s", exc)
        return generate_template_report(target_url, findings)
