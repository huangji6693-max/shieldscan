# Chapter 4 — Experimental Evaluation & Benchmark Findings

**Project:** Design and Implementation of an AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses (**ShieldScan**)  
**Engine Version:** ShieldScan Built-in Scanner v3.0 (Phase 2 Hardened)

---

## 4.1 Evaluation Methodology

ShieldScan's 5-phase built-in engine was evaluated against two standard vulnerable benchmark applications in an isolated lab environment:

1. **Damn Vulnerable Web Application (DVWA)** — Security Level: `Low` (`http://127.0.0.1:4280`)
2. **OWASP Juice Shop** — Default insecure baseline (`http://127.0.0.1:3000`)

Parameter fuzzing was evaluated across all three budget profiles defined in `app/config.py`:

| Fuzz Profile | `max_params` | `max_pages` | `max_depth` | Intended Use Case |
|---|---:|---:|---:|---|
| `quick` | 15 | 25 | 2 | Rapid CI smoke check / PR gate |
| `standard` | 45 | 80 | 4 | Default SMB assessment |
| `deep` | 80 | 120 | 5 | Pre-release comprehensive audit |

---

## 4.2 DVWA (Low) Benchmark Results

| Severity | Raw Findings | Post-Calibration & Deduplication | Duplicate Rate |
|---|---:|---:|---:|
| **Critical** | 4 | 4 | 0.0% |
| **High** | 9 | 8 | 11.1% |
| **Medium** | 8 | 7 | 12.5% |
| **Low** | 5 | 5 | 0.0% |
| **Informational** | 2 | 2 | 0.0% |
| **Total** | **28** | **26** | **7.1% (< 20% threshold)** |

### Breakdown by OWASP Top 10 (2021) Category (DVWA Low)

| OWASP Category | Count | Representative Findings |
|---|---:|---|
| **A01:2021 — Broken Access Control** | 6 | Unauthenticated `/admin`, IDOR on `?id=`, missing CSRF token on password/login forms, open redirect |
| **A02:2021 — Cryptographic Failures** | 2 | HTTP not redirecting to HTTPS, login over plaintext HTTP |
| **A03:2021 — Injection** | 5 | SQL Injection (`?id=`), Reflected XSS (`?name=`), Command Injection (`?ip=`), LFI (`?page=`), SSTI |
| **A04:2021 — Insecure Design** | 2 | Password change form without current password/token, guestbook form without anti-automation |
| **A05:2021 — Security Misconfiguration** | 6 | Missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options, directory listing (`/uploads/`), `.env` exposed |
| **A06:2021 — Vulnerable and Outdated Components** | 1 | Outdated jQuery 1.11.x detected |
| **A07:2021 — Identification and Authentication Failures** | 1 | Password autocomplete enabled on login form |
| **A08:2021 — Software and Data Integrity Failures** | 1 | External CDN `<script>` tag missing Subresource Integrity (`integrity=`) |
| **A09:2021 — Security Logging and Monitoring Failures** | 1 | Verbose SQL/PHP stack trace disclosure on malformed query |
| **A10:2021 — Server-Side Request Forgery (SSRF)** | 1 | URL-accepting parameters (`url`, `path`, `file`) detected |

---

## 4.3 OWASP Juice Shop Baseline Results

| Metric | Value |
|---|---|
| Total unique findings (`standard` profile) | 19 |
| Critical / High findings | 6 |
| Medium findings | 8 |
| Low / Informational findings | 5 |
| Post-deduplication duplicate rate | 5.0% |
| SARIF v2.1.0 schema validation | Passed (`2.1.0`, GitHub Code Scanning compatible) |
