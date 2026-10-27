import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Scan, ScanStatus
from app.schemas import Finding
from app.services.ai_reporter import generate_ai_report
from app.services.builtin_scanner import run_builtin_scan
from app.services.finding_utils import enrich_findings
from app.services.passive_checks import zap_alert_to_finding
from app.services.zap_client import ZAPClient

logger = logging.getLogger(__name__)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f"{f.source}:{f.name}:{f.url}:{f.parameter}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


class ScanOrchestrator:
    def __init__(self, settings: Settings, db: Session):
        self.settings = settings
        self.db = db

    def _update(self, scan: Scan, status: ScanStatus, message: str) -> None:
        scan.status = status
        scan.status_message = message
        self.db.commit()

    async def run(self, scan_id: int) -> None:
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        target = scan.target_url
        findings: list[Finding] = []

        try:
            self._update(scan, ScanStatus.RUNNING, "Initialising scan")
            zap = ZAPClient(self.settings)
            zap_configured = self.settings.scanner_mode.strip().lower() == "zap"
            use_zap = zap_configured and await zap.is_available()

            if zap_configured and not use_zap:
                logger.warning(
                    "Fallback to builtin scanner for scan %s: OWASP ZAP unreachable at %s (SCANNER_MODE=zap)",
                    scan_id,
                    self.settings.zap_api_url,
                )

            if use_zap:
                scan.scanner_used = "zap+builtin"
                self.db.commit()

                def zap_progress(msg: str) -> None:
                    if "Spider" in msg or "spider" in msg:
                        self._update(scan, ScanStatus.SPIDERING, msg)
                    elif "Active" in msg or "active" in msg:
                        self._update(scan, ScanStatus.ACTIVE_SCAN, msg)
                    else:
                        self._update(scan, ScanStatus.PASSIVE_SCAN, msg)

                try:
                    alerts = await zap.run_full_scan(
                        target,
                        on_progress=zap_progress,
                        policy_profile=getattr(self.settings, "zap_scan_policy", "standard"),
                    )
                    findings = [zap_alert_to_finding(a, i) for i, a in enumerate(alerts)]
                except Exception as zap_exc:
                    logger.warning(
                        "ZAP scan interrupted for scan %s (%s); falling back to builtin scanner",
                        scan_id,
                        zap_exc,
                    )
                    use_zap = False
                    scan.scanner_used = "builtin"
                    self.db.commit()
            else:
                scan.scanner_used = "builtin"
                self.db.commit()

            # Always run built-in extended checks (headers, crawl, CORS, paths, injection, etc.)
            def builtin_progress(msg: str) -> None:
                if not use_zap:
                    self._update(scan, ScanStatus.PASSIVE_SCAN, msg)
                else:
                    self._update(scan, ScanStatus.PASSIVE_SCAN, f"Built-in checks: {msg}")

            builtin_findings = await run_builtin_scan(target, on_progress=builtin_progress)
            findings.extend(builtin_findings)

            findings = enrich_findings(_dedupe_findings(findings))

            self._update(scan, ScanStatus.AI_REPORTING, "Generating AI security report")
            executive, grade, report = await generate_ai_report(self.settings, target, findings)

            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for f in findings:
                key = f.risk if f.risk in counts else "Informational"
                counts[key] += 1

            scan.status = ScanStatus.COMPLETE
            scan.status_message = "Scan complete"
            scan.findings_json = json.dumps([f.model_dump() for f in findings])
            scan.executive_summary = executive
            scan.ai_report = report
            scan.risk_grade = grade
            scan.finding_count = len(findings)
            scan.critical_count = counts["Critical"]
            scan.high_count = counts["High"]
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            logger.info("Scan %s complete: %d findings, grade %s", scan_id, len(findings), grade)

        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.status_message = "Scan failed"
            scan.error_message = str(exc)[:1000]
            scan.completed_at = datetime.utcnow()
            self.db.commit()
