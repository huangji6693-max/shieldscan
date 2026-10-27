# Safety Score Algorithm, Encrypted Key Storage & Viva Demo Guide (Phase 4)

**Project:** ShieldScan — AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses  
**References:** PRD §4 · FUT Minna Thesis Chapter 5 · Presentation Slides 9–10

---

## 1. Documented Safety Score Algorithm (A–F Grading)

ShieldScan computes both a **letter grade (`A`–`F`)** (`risk_grade` in `app/services/owasp.py`) and a **numeric safety score (`0`–`100`)** (`explain_risk_rule`) so non-specialist SMB owners immediately understand urgency while technical reviewers can inspect deterministic thresholds.

### 1.1 Deterministic Letter Grade Decision Table

Evaluated in strict priority order from highest severity to lowest:

| Condition | Grade | Plain-English Meaning |
|---|---|---|
| `Critical > 2` | **F** | Urgent intervention required (> 2 critical vulnerabilities) |
| `Critical >= 1` (1–2 Critical) | **D** | High-risk vulnerabilities present |
| `High > 3` | **D** | Multiple serious vulnerabilities present |
| `High >= 1` (1–3 High) | **C** | Serious issues require developer attention |
| `Medium > 5` | **C** | Numerous moderate configuration issues require attention |
| `Medium >= 1` (1–5 Medium) | **B** | Only moderate configuration issues found (0 High/Critical) |
| `Critical == 0` and `High == 0` and `Medium == 0` | **A** | No critical, high, or medium risks detected |

### 1.2 Numeric Penalty Formula (`0`–`100`)

```text
penalty = (25 × Critical) + (12 × High) + (4 × Medium) + (1 × Low)
numeric_score = max(0, 100 - penalty)
```

---

## 2. Grounded AI Reporting & Anti-Hallucination Quality Gate

To guarantee zero hallucinated vulnerabilities or fabricated CVE numbers (`app/services/ai_reporter.py`):

1. **Mandatory Finding ID Citations (`[ID: <finding.id>]`)**:
   - Every finding in both the Claude AI prompt and the deterministic template fallback is cited by its exact `finding.id` (e.g. `[ID: sqli-fuzz-id]`).
2. **Post-Generation Grounding Sanitizer (`sanitize_grounded_report`)**:
   - Verifies every `[ID: ...]` citation against the scan's actual `findings` list and strips any citation not present in the scan results.
   - Scans the generated report for `CVE-YYYY-NNNN+` identifiers and replaces any CVE not present in the underlying finding evidence/description with `"a known security advisory"`.
3. **Per-OWASP-Category Plain-English Remediation Cards**:
   - Both the web dashboard (`#remediation-cards` in `static/index.html` & `static/js/app.js`) and the Markdown/HTML report render plain-English "What it means" and "How to fix" cards for `A01:2021` through `A10:2021`.

---

## 3. Passphrase-Encrypted API Key Storage (`app/services/secrets.py`)

Aligned with Stellar Wave #29 secure key storage:

- `encrypt_secret(plaintext, passphrase)` derives a 256-bit encryption key and a 256-bit MAC key using **PBKDF2-HMAC-SHA256** (`100,000` iterations, 16-byte random salt) and produces an authenticated `enc:v1:<salt_b64>:<ct_b64>:<mac_b64>` token.
- `decrypt_secret(token, passphrase)` verifies the HMAC-SHA256 tag in constant time (`hmac.compare_digest`) before decrypting.
- `validate_settings(settings)` logs a warning when `SHIELDSCAN_ENV=production` and `ANTHROPIC_API_KEY` is stored in plaintext without `enc:v1:` encryption.

---

## 4. Presentation Slides 9–10 & Under-5-Minute Viva Demo Script

### Slide 9 — Live Dashboard & Safety Score Breakdown
- **Visual:** ShieldScan Results Card displaying Grade Badge (`D` / `F` on DVWA Low), Severity Counters (`Critical`, `High`, `Medium`, `Low`), OWASP Category Breakdown bars, and Plain-English Fix Guide Cards (`#remediation-cards`).
- **Talking Point:** *"Every technical finding from the 5-phase engine is paired with a plain-English remediation card so a small business owner knows what to hand their web developer."*

### Slide 10 — Grounded AI Report & Export Verification
- **Visual:** Full Report & Fix Guide panel showing `[ID: ...]` grounded citations alongside exported HTML/Markdown reports.
- **Talking Point:** *"Reports cite only verified scan finding IDs and pass through `sanitize_grounded_report` so neither the AI model nor the template fallback can hallucinate unverified CVEs."*

### < 5-Minute Viva Demo Checklist
1. **0:00–0:45** — Verify lab containers: `./start-lab.sh full && docker compose ps`
2. **0:45–1:15** — Start ShieldScan (`./start.sh`) and open `http://127.0.0.1:8000`
3. **1:15–2:30** — Click **DVWA** preset (`http://127.0.0.1:4280`), check authorisation box, click **Run security scan**
4. **2:30–3:45** — Walk through Safety Score Grade, OWASP Category Remediation Cards, and per-finding "How to fix" column
5. **3:45–4:30** — Show Grounded Report (`[ID: ...]`) and click **Export HTML Report** / **Download Markdown**
