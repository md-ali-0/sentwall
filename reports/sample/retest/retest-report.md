# Remediation Verification Report

**Target:** `http://127.0.0.1:8099`  
**Client:** Demo Store Ltd  
**Assessor:** Security Consultant  

| | Baseline | Retest |
|---|---|---|
| Scan ID | `VS-FC3EF18E` | `VS-D59D7DF0` |
| Date | 16 November 2026, 13:03 | 16 November 2026, 13:04 |
| Risk score | 100/100 | 71/100 |
| Grade | F | E |
| Findings | 37 | 16 |

**Risk delta:** -29 points · **Fix rate:** 59% · **Verdict:** Positive progress: Risk score reduced.

## Scorecard

| Metric | Count |
|---|---|
| Resolved | 22 |
| Still open | 15 |
| Regressed | 0 |
| Improved | 0 |
| New | 1 |

## Severity breakdown

| Severity | Baseline | Retest | Change |
|---|---|---|---|
| Critical | 8 | 0 | -8 |
| High | 9 | 3 | -6 |
| Medium | 9 | 4 | -5 |
| Low | 7 | 5 | -2 |
| Info | 4 | 4 | 0 |

## Still open (15)

_Unchanged — still reproducible exactly as before._

- **[HIGH]** Could not establish a TLS connection on port 443 — `tls-unreachable`
- **[HIGH]** Missing Anti-CSRF Protection on State-Changing Form — `missing-csrf-token-1`
- **[HIGH]** Missing Anti-CSRF Protection on State-Changing Form — `missing-csrf-token-2`
- **[MEDIUM]** Absence of Rate Limiting on Authentication Endpoint — `missing-rate-limiting-authentication`
- **[MEDIUM]** Directory listing is enabled — `directory-listing`
- **[MEDIUM]** Open redirect via parameter 'url' — `open-redirect-url`
- **[MEDIUM]** Outdated jQuery 1.12.4 (known XSS issues) — `outdated-jquery`
- **[LOW]** External links open with target=_blank but no rel=noopener — `tabnabbing`
- **[LOW]** HTML comments reveal internal information — `sensitive-comments`
- **[LOW]** Technology versions disclosed in response headers — `version-disclosure-headers`
- **[LOW]** Third-party scripts loaded without Subresource Integrity — `missing-sri`
- **[INFO]** Cross-Origin-Opener-Policy (COOP) header is missing — `hdr-missing-cross-origin-opener-policy`
- **[INFO]** No web application firewall detected — `no-waf`
- **[INFO]** Password field allows browser autocomplete — `password-autocomplete`
- **[INFO]** robots.txt points at sensitive paths — `robots-hints`

## New (1)

_Appeared only in the second scan — check what changed._

- **[LOW]** CSP has no frame-ancestors directive — `csp-no-frame-ancestors`

## Resolved (22)

_No longer detected on re-scan._

- **[CRITICAL]** Apache 2.4.49 is vulnerable to CVE-2021-41773 (path traversal / RCE) — `cve-2021-41773`
- **[CRITICAL]** CORS reflects any origin with credentials enabled — `cors-reflect-credentials`
- **[CRITICAL]** Database dump exposed — `exposed-backup.sql`
- **[CRITICAL]** Environment file with secrets exposed — `exposed-.env`
- **[CRITICAL]** Exposed Git repository configuration — `exposed-.git/config`
- **[CRITICAL]** Path traversal / local file inclusion in 'file' — `path-traversal-file`
- **[CRITICAL]** Server-side template injection in 'name' — `ssti-name`
- **[CRITICAL]** SQL injection in parameter 'q' (MySQL) — `sqli-error-q`
- **[HIGH]** Content-Security-Policy header is missing — `hdr-missing-content-security-policy`
- **[HIGH]** Cookies missing the Secure flag: PHPSESSID — `cookie-no-secure`
- **[HIGH]** End-of-life Apache 2.4.49 in production — `outdated-apache`
- **[HIGH]** Reflected XSS in parameter 'name' — `xss-reflected-name`
- **[HIGH]** Reflected XSS in parameter 'q' — `xss-reflected-q`
- **[HIGH]** Reflected XSS through a form field — `xss-form-/search`
- **[MEDIUM]** Cookies without SameSite attribute: PHPSESSID — `cookie-no-samesite`
- **[MEDIUM]** Dangerous HTTP methods advertised: PUT — `http-dangerous-methods`
- **[MEDIUM]** HTTP TRACE method is enabled — `http-trace-enabled`
- **[MEDIUM]** Page can be framed by any site (clickjacking) — `clickjacking`
- **[MEDIUM]** Session cookies readable from JavaScript: PHPSESSID — `cookie-no-httponly`
- **[LOW]** Permissions-Policy header is missing — `hdr-missing-permissions-policy`
- **[LOW]** Referrer-Policy header is missing — `hdr-missing-referrer-policy`
- **[LOW]** X-Content-Type-Options header is missing — `hdr-missing-x-content-type-options`

## Next steps

1. 3 high or critical issue(s) are still open — close them before release.
2. Re-scan after the next round of fixes and compare again.
3. Keep this report with the baseline; the trend is the evidence.
