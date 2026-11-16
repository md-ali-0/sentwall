# Security Assessment Report

**Target:** http://127.0.0.1:8099  
**Report ID:** VS-4AC52381  
**Date:** 16 November 2026  
**Risk score:** 100/100 (grade F)  
**Findings:** 8 critical, 6 high, 8 medium, 7 low, 4 info

---

## Findings

| # | Severity | Finding | Category | CVSS |
|---|----------|---------|----------|------|
| 1 | Critical | Apache 2.4.49 is vulnerable to CVE-2021-41773 (path traversal / RCE) | Outdated Software | 9.8 |
| 2 | Critical | CORS reflects any origin with credentials enabled | Misconfiguration | 9.3 |
| 3 | Critical | Database dump exposed | Sensitive File Exposure | 9.8 |
| 4 | Critical | Environment file with secrets exposed | Sensitive File Exposure | 9.8 |
| 5 | Critical | Exposed Git repository configuration | Sensitive File Exposure | 9.8 |
| 6 | Critical | Path traversal / local file inclusion in 'file' | Injection | 9.1 |
| 7 | Critical | SQL injection in parameter 'q' (MySQL) | Injection | 9.8 |
| 8 | Critical | Server-side template injection in 'name' | Injection | 9.8 |
| 9 | High | Content-Security-Policy header is missing | Security Headers | 6.1 |
| 10 | High | Cookies missing the Secure flag: PHPSESSID | Session Management | 7.1 |
| 11 | High | Could not establish a TLS connection on port 443 | Encryption | 7.5 |
| 12 | High | End-of-life Apache 2.4.49 in production | Outdated Software | 7.5 |
| 13 | High | Reflected XSS in parameter 'name' | Injection | 6.1 |
| 14 | High | Reflected XSS in parameter 'q' | Injection | 6.1 |
| 15 | Medium | Cookies without SameSite attribute: PHPSESSID | Session Management | 6.5 |
| 16 | Medium | Directory listing is enabled | Misconfiguration | 5.3 |
| 17 | Medium | HTTP TRACE method is enabled | Misconfiguration | 5.3 |
| 18 | Medium | Open redirect via parameter 'url' | Injection | 6.1 |
| 19 | Medium | Outdated jQuery 1.12.4 (known XSS issues) | Outdated Software | 6.1 |
| 20 | Medium | Page can be framed by any site (clickjacking) | Security Headers | 4.3 |
| 21 | Medium | Session cookies readable from JavaScript: PHPSESSID | Session Management | 6.5 |
| 22 | Medium | Dangerous HTTP methods advertised: PUT | Misconfiguration | 5.3 |
| 23 | Low | External links open with target=_blank but no rel=noopener | Client-Side | 3.1 |
| 24 | Low | HTML comments reveal internal information | Information Disclosure | 3.1 |
| 25 | Low | Permissions-Policy header is missing | Security Headers | 3.1 |
| 26 | Low | Referrer-Policy header is missing | Security Headers | 3.1 |
| 27 | Low | Technology versions disclosed in response headers | Information Disclosure | 3.7 |
| 28 | Low | Third-party scripts loaded without Subresource Integrity | Supply Chain | 3.7 |
| 29 | Low | X-Content-Type-Options header is missing | Security Headers | 3.1 |
| 30 | Info | Cross-Origin-Opener-Policy (COOP) header is missing | Security Headers | 3.1 |
| 31 | Info | No web application firewall detected | Defence in Depth | - |
| 32 | Info | Password field allows browser autocomplete | Client-Side | - |
| 33 | Info | robots.txt points at sensitive paths | Information Disclosure | - |

## 1. Apache 2.4.49 is vulnerable to CVE-2021-41773 (path traversal / RCE)

**Severity:** Critical · **CVSS:** 9.8 · **CWE-22** · A06:2021 Vulnerable and Outdated Components

**What we found:** This exact Apache version is affected by CVE-2021-41773 / CVE-2021-42013: a path traversal flaw in mod_proxy that allows reading files outside the document root and, with mod_cgi enabled, remote code execution.

**Impact:** Unauthenticated remote code execution on the web server.

**Evidence:**
- `Server: Apache/2.4.49`

**Remediation:**

```
Upgrade to Apache 2.4.51 or later immediately. As an interim mitigation, disable mod_cgi and require 'Require all denied' on the default filesystem path.
```

## 2. CORS reflects any origin with credentials enabled

**Severity:** Critical · **CVSS:** 9.3 · **CWE-942** · A01:2021 Broken Access Control

**What we found:** http://127.0.0.1:8099/ returned Access-Control-Allow-Origin: https://vulnscope-canary.example together with Access-Control-Allow-Credentials: true. Any website on the internet can therefore make authenticated cross-origin requests and read the responses as the logged-in victim.

**Impact:** Complete account takeover from a single malicious link: the attacker reads profile data, API tokens and personal information, and can perform actions on the victim's behalf.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Origin: https://vulnscope-canary.example`
- `Access-Control-Allow-Origin: https://vulnscope-canary.example`
- `Access-Control-Allow-Credentials: true`

**Remediation:**

```
Never reflect the Origin header blindly. Use a strict allow-list:
if origin in TRUSTED_ORIGINS: set ACAO=origin, ACAC=true
else: do not send CORS headers at all.
Also reject the 'null' origin.
```

## 3. Database dump exposed

**Severity:** Critical · **CVSS:** 9.8 · **CWE-530** · A01:2021 Broken Access Control

**What we found:** A SQL dump is downloadable. It contains full table data plus schema.

**Impact:** Mass disclosure of customer records, password hashes and business data - usually a reportable data breach.

**Evidence:**
- `GET http://127.0.0.1:8099/backup.sql -> HTTP 200 (71 bytes)`
- `First lines: INSERT INTO users VALUES(1);`

**Remediation:**

```
Delete the dump from the web root, store backups outside the document root or in object storage with signed URLs, and assess breach-notification obligations.
```

## 4. Environment file with secrets exposed

**Severity:** Critical · **CVSS:** 9.8 · **CWE-538** · A02:2021 Cryptographic Failures

**What we found:** The .env file is downloadable. It normally contains database credentials, the application encryption key, mail passwords and third-party API keys.

**Impact:** Direct database access, ability to forge session cookies with the app key, and full compromise of every integrated service.

**Evidence:**
- `GET http://127.0.0.1:8099/.env -> HTTP 200 (68 bytes)`
- `First lines: APP_NAME=TestShop | APP_KEY=base64:abcd1234SECRET`

**Remediation:**

```
Deny access to dotfiles at the server, move the file above the web root, and rotate every credential it contains:
location ~ /\.(?!well-known) { deny all; }
```

## 5. Exposed Git repository configuration

**Severity:** Critical · **CVSS:** 9.8 · **CWE-538** · A05:2021 Security Misconfiguration

**What we found:** The .git directory is publicly readable. An attacker can download the entire source history - including secrets that were committed and later 'removed' - and then reconstruct the full application source.

**Impact:** Complete source code disclosure, plus every credential, API key and database password that ever appeared in a commit. This typically leads to full server compromise.

**Evidence:**
- `GET http://127.0.0.1:8099/.git/config -> HTTP 200 (50 bytes)`

**Remediation:**

```
Block access at the web server and rotate any secret that was ever committed:
location ~ /\.git { deny all; return 404; }
Then rebuild the repository without the leaked secrets and force-push.
```

## 6. Path traversal / local file inclusion in 'file'

**Severity:** Critical · **CVSS:** 9.1 · **CWE-22** · A01:2021 Broken Access Control

**What we found:** A relative path payload caused the server to return the contents of /etc/passwd. The parameter is used to build a filesystem path without validation or confinement to a base directory.

**Impact:** Read of arbitrary server files - configuration, private keys, database credentials - and often escalation to remote code execution by including a file the attacker can upload.

**Evidence:**
- `GET http://127.0.0.1:8099/download?file=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
- `Response contained 'root:x:0:0:'`

**Remediation:**

```
Never pass user input to file APIs. Resolve the path and verify it stays inside the allowed directory:
real = os.path.realpath(os.path.join(BASE, name))
if not real.startswith(BASE + os.sep): abort(400)
Better: map an opaque ID to a stored path instead of accepting names.
```

## 7. SQL injection in parameter 'q' (MySQL)

**Severity:** Critical · **CVSS:** 9.8 · **CWE-89** · A03:2021 Injection

**What we found:** Appending a single quote to 'q' produced a raw MySQL database error that does not appear on the normal page. The value is being concatenated directly into a SQL statement instead of being sent as a bound parameter.

**Impact:** Full database read and write: customer records, password hashes, payment data and admin credentials. Depending on database privileges this often escalates to remote code execution on the server. This is a reportable data-breach risk.

**Evidence:**
- `GET http://127.0.0.1:8099/search?q=1%27`
- `Database error signature: you have an error in your sql syntax`

**Remediation:**

```
Use parameterised queries / prepared statements everywhere. Never build SQL by string concatenation.
PHP: $stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');
Java: PreparedStatement with setInt/setString
Also apply least-privilege DB accounts and disable detailed DB errors in production.
```

## 8. Server-side template injection in 'name'

**Severity:** Critical · **CVSS:** 9.8 · **CWE-94** · A03:2021 Injection

**What we found:** A template expression was evaluated server-side: the payload {{1506*868}} was rendered as 1307208. User input is being compiled as template code.

**Impact:** Depending on the template engine this escalates to arbitrary command execution on the server - typically full infrastructure compromise.

**Evidence:**
- `GET http://127.0.0.1:8099/render?name=%7B%7B1506%2A868%7D%7D`
- `{{1506*868}} -> 1307208`

**Remediation:**

```
Never render user input as a template. Pass it as a variable, and use logic-less templates or sandboxed rendering.
```

## 9. Content-Security-Policy header is missing

**Severity:** High · **CVSS:** 6.1 · **CWE-693** · A05:2021 Security Misconfiguration

**What we found:** Without a CSP the browser will execute any script that reaches the page. This is the single most effective defence-in-depth control against cross-site scripting (XSS), malicious third-party scripts and data injection.

**Impact:** Raises the likelihood and blast radius of any injection flaw on the site; an attacker who lands one script gets a durable foothold in users' browsers.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Response headers did not include: content-security-policy`

**Remediation:**

```
Publish a restrictive CSP, starting in report-only mode:
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'
```

## 10. Cookies missing the Secure flag: PHPSESSID

**Severity:** High · **CVSS:** 7.1 · **CWE-614** · A05:2021 Security Misconfiguration

**What we found:** These cookies can be sent over plain HTTP. A single unencrypted request - a mistyped URL, an http:// link, a shared network - exposes them to anyone listening on the wire.

**Impact:** Session hijacking: an attacker who captures the cookie becomes the user without needing any password.

**Evidence:**
- `PHPSESSID: path`

**Remediation:**

```
Set the Secure attribute on every cookie:
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

## 11. Could not establish a TLS connection on port 443

**Severity:** High · **CVSS:** 7.5 · **CWE-319** · A02:2021 Cryptographic Failures

**What we found:** No TLS handshake could be completed with the server on port 443. Either the site is HTTP-only, or the TLS stack is misconfigured.

**Impact:** All traffic - including logins and payment data - travels unencrypted.

**Evidence:**
- `Error: [WinError 10061] No connection could be made because the target machine actively refused it`

**Remediation:**

```
Install a valid certificate (Let's Encrypt is free) and serve the site exclusively over HTTPS.
```

## 12. End-of-life Apache 2.4.49 in production

**Severity:** High · **CVSS:** 7.5 · **CWE-1104** · A06:2021 Vulnerable and Outdated Components

**What we found:** The server reports Apache 2.4.49. Apache httpd below 2.4.55 has multiple published CVEs. Once a branch is end-of-life it receives no security patches, so every newly discovered vulnerability in it stays exploitable forever.

**Impact:** Known vulnerabilities in the runtime can be exploited at leisure; attackers actively scan for these versions.

**Evidence:**
- `Apache 2.4.49 reported in response headers`

**Remediation:**

```
Upgrade Apache to a currently supported release and put a patch cadence in place (monthly minimum, plus out-of-band for critical advisories). Test on staging first.
```

## 13. Reflected XSS in parameter 'name'

**Severity:** High · **CVSS:** 6.1 · **CWE-79** · A03:2021 Injection

**What we found:** User input supplied in 'name' is written back into the HTML page without encoding. The probe string was returned with its angle brackets intact, which means an attacker can inject any HTML tag - including <script> - and it will execute in the victim's browser.

**Impact:** Session theft, credential phishing rendered inside your own page, silent actions on behalf of the user, and malware delivery. Chained with a missing HttpOnly flag this is immediate account takeover.

**Evidence:**
- `GET http://127.0.0.1:8099/render?name=vswfr6d8f0%3Cvswfr6d8f0%3E`
- `Payload fragment reflected verbatim: <vswfr6d8f0>`
- `Response length: 54 bytes`

**Remediation:**

```
Context-aware output encoding on every sink:
- HTML body: encode & < > " '
- attributes: quote and encode
- JavaScript/URL contexts: use the framework's escaper
Also validate input against an allow-list and add a strict CSP as defence in depth.
```

## 14. Reflected XSS in parameter 'q'

**Severity:** High · **CVSS:** 6.1 · **CWE-79** · A03:2021 Injection

**What we found:** User input supplied in 'q' is written back into the HTML page without encoding. The probe string was returned with its angle brackets intact, which means an attacker can inject any HTML tag - including <script> - and it will execute in the victim's browser.

**Impact:** Session theft, credential phishing rendered inside your own page, silent actions on behalf of the user, and malware delivery. Chained with a missing HttpOnly flag this is immediate account takeover.

**Evidence:**
- `GET http://127.0.0.1:8099/search?q=vs5shc8lmo%3Cvs5shc8lmo%3E`
- `Payload fragment reflected verbatim: <vs5shc8lmo>`
- `Response length: 65 bytes`

**Remediation:**

```
Context-aware output encoding on every sink:
- HTML body: encode & < > " '
- attributes: quote and encode
- JavaScript/URL contexts: use the framework's escaper
Also validate input against an allow-list and add a strict CSP as defence in depth.
```

## 15. Cookies without SameSite attribute: PHPSESSID

**Severity:** Medium · **CVSS:** 6.5 · **CWE-1275** · A01:2021 Broken Access Control

**What we found:** With no SameSite attribute, browsers fall back to their default behaviour and the cookie is attached to cross-site requests. That is exactly what a CSRF attack needs.

**Impact:** State-changing actions (password change, transfer, delete) can be triggered from an attacker's page while the victim is logged in.

**Evidence:**
- `PHPSESSID: path`

**Remediation:**

```
Add SameSite=Lax to normal session cookies; use SameSite=Strict for admin or high-value actions. Pair with anti-CSRF tokens.
```

## 16. Directory listing is enabled

**Severity:** Medium · **CVSS:** 5.3 · **CWE-548** · A05:2021 Security Misconfiguration

**What we found:** The web server returns an auto-generated file index for http://127.0.0.1:8099/uploads/. Visitors can browse the contents of these folders directly, including files that were never meant to be linked.

**Impact:** Disclosure of uploaded documents, backups, temporary files and sometimes personal data belonging to other users.

**Evidence:**
- `GET http://127.0.0.1:8099/uploads/ -> 200 Index of ...`

**Remediation:**

```
Disable autoindex:
nginx: autoindex off;
Apache: Options -Indexes
and move non-public files outside the web root.
```

## 17. HTTP TRACE method is enabled

**Severity:** Medium · **CVSS:** 5.3 · **CWE-749** · A05:2021 Security Misconfiguration

**What we found:** The server answers TRACE by echoing the full request back, including headers. Combined with a scripting flaw this enables Cross-Site Tracing (XST), which can read HttpOnly cookies.

**Impact:** Bypasses the HttpOnly protection on session cookies in some browsers.

**Evidence:**
- `TRACE http://127.0.0.1:8099 -> HTTP 200`

**Remediation:**

```
Disable TRACE at the web server:
Apache: TraceEnable Off
nginx: if ($request_method = TRACE) { return 405; }
```

## 18. Open redirect via parameter 'url'

**Severity:** Medium · **CVSS:** 6.1 · **CWE-601** · A01:2021 Broken Access Control

**What we found:** The 'url' parameter controls where the user is sent, and it accepts any external host. The application will happily redirect visitors to an attacker-controlled site while the link still starts with your domain.

**Impact:** Highly effective phishing: 'https://yourdomain/login?next=evil.com' looks trustworthy, and is also used to steal OAuth tokens and bypass allow-lists.

**Evidence:**
- `GET http://127.0.0.1:8099/redirect?url=https%3A%2F%2Fvulnscope-canary.invalid%2Fpoc`
- `Location: https://vulnscope-canary.invalid/poc`

**Remediation:**

```
Accept only relative paths, or validate against an allow-list of permitted hosts before redirecting. Reject values containing '://' and '//'.
```

## 19. Outdated jQuery 1.12.4 (known XSS issues)

**Severity:** Medium · **CVSS:** 6.1 · **CWE-1104** · A06:2021 Vulnerable and Outdated Components

**What we found:** jQuery 1.12.4 predates fixes for CVE-2020-11022 / CVE-2020-11023 (XSS via htmlPrefilter) and, below 3.4.0, CVE-2019-11358 (prototype pollution in jQuery.extend).

**Impact:** Untrusted HTML passed to .html()/.append() can execute script, re-enabling XSS even where the application escapes correctly.

**Evidence:**
- `jQuery 1.12.4 referenced in page source`

**Remediation:**

```
Upgrade to jQuery 3.7.x and audit any .html() call that receives user data.
```

## 20. Page can be framed by any site (clickjacking)

**Severity:** Medium · **CVSS:** 4.3 · **CWE-1021** · A05:2021 Security Misconfiguration

**What we found:** Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be embedded in an invisible iframe on an attacker's page. Users can be tricked into clicking 'Delete account', 'Pay' or 'Grant access' while believing they are on a harmless page.

**Impact:** Account actions and payment flows can be hijacked through UI redressing.

**Evidence:**
- `X-Frame-Options: (absent)`
- `CSP frame-ancestors: (absent)`

**Remediation:**

```
Add Content-Security-Policy: frame-ancestors 'self' (preferred) and X-Frame-Options: SAMEORIGIN for older browsers.
```

## 21. Session cookies readable from JavaScript: PHPSESSID

**Severity:** Medium · **CVSS:** 6.5 · **CWE-1004** · A05:2021 Security Misconfiguration

**What we found:** Without HttpOnly, any JavaScript running on the page - including code injected through an XSS flaw or a compromised third-party script - can read the session cookie with document.cookie.

**Impact:** A single XSS anywhere on the site escalates from 'script execution' to full, persistent account takeover.

**Evidence:**
- `PHPSESSID: path`

**Remediation:**

```
Add HttpOnly to all session and authentication cookies.
```

## 22. Dangerous HTTP methods advertised: PUT

**Severity:** Medium · **CVSS:** 5.3 · **CWE-749** · A05:2021 Security Misconfiguration

**What we found:** The server advertises write-capable methods on a public endpoint. If the application layer does not authorise them, an attacker can upload or delete content directly.

**Impact:** Potential unauthorised file upload, overwrite or deletion.

**Evidence:**
- `Allow: GET, POST, OPTIONS, TRACE, PUT`

**Remediation:**

```
Restrict allowed methods to GET/POST/HEAD (plus OPTIONS if needed) and return 405 for the rest. Verify authorisation on every verb.
```

## 23. External links open with target=_blank but no rel=noopener

**Severity:** Low · **CVSS:** 3.1 · **CWE-1022** · A05:2021 Security Misconfiguration

**What we found:** A link opened in a new tab keeps a reference to your page through window.opener. The destination site can use it to redirect the original tab to a phishing page.

**Impact:** Users who return to the original tab land on an attacker-controlled clone.

**Evidence:**
- `href=https://example.com`

**Remediation:**

```
Add rel="noopener noreferrer" to every target="_blank" link, or set it globally in the framework.
```

## 24. HTML comments reveal internal information

**Severity:** Low · **CVSS:** 3.1 · **CWE-615** · A05:2021 Security Misconfiguration

**What we found:** Developer comments are shipped to production. They often contain credentials, internal hostnames, TODO notes about unpatched areas, or hints about hidden admin paths.

**Impact:** Free reconnaissance for an attacker, sometimes including direct credentials.

**Evidence:**
- `<!-- TODO: remove test admin:admin before launch -->`

**Remediation:**

```
Strip comments in the build step (HTML minification does this automatically) and review what is deployed.
```

## 25. Permissions-Policy header is missing

**Severity:** Low · **CVSS:** 3.1 · **CWE-693** · A05:2021 Security Misconfiguration

**What we found:** Powerful browser features (camera, microphone, geolocation, clipboard) stay available to any embedded third-party frame unless explicitly disabled.

**Impact:** Raises the likelihood and blast radius of any injection flaw on the site; an attacker who lands one script gets a durable foothold in users' browsers.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Response headers did not include: permissions-policy`

**Remediation:**

```
Add a deny-by-default policy, e.g.:
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

## 26. Referrer-Policy header is missing

**Severity:** Low · **CVSS:** 3.1 · **CWE-200** · A01:2021 Broken Access Control

**What we found:** Full URLs - including tokens and internal identifiers - leak to third parties through the Referer header when users click external links.

**Impact:** Raises the likelihood and blast radius of any injection flaw on the site; an attacker who lands one script gets a durable foothold in users' browsers.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Response headers did not include: referrer-policy`

**Remediation:**

```
Add:
Referrer-Policy: strict-origin-when-cross-origin
```

## 27. Technology versions disclosed in response headers

**Severity:** Low · **CVSS:** 3.7 · **CWE-200** · A05:2021 Security Misconfiguration

**What we found:** Response headers advertise the exact server and framework versions. An attacker can match these against public CVE databases and pick exploits that are known to work, skipping the reconnaissance phase entirely.

**Impact:** Faster, more reliable targeting of version-specific vulnerabilities.

**Evidence:**
- `Server: Apache/2.4.49 (Unix)`

**Remediation:**

```
Suppress or genericise version strings: nginx `server_tokens off;`, Apache `ServerTokens Prod` / `ServerSignature Off`, PHP `expose_php = Off`, and remove X-Powered-By at the reverse proxy.
```

## 28. Third-party scripts loaded without Subresource Integrity

**Severity:** Low · **CVSS:** 3.7 · **CWE-353** · A08:2021 Software and Data Integrity Failures

**What we found:** 1 script tag(s) load code from an external host without an integrity hash. If that CDN or vendor is compromised, the modified script runs with full access to your users' sessions.

**Impact:** One compromised third-party host becomes a compromise of your site.

**Evidence:**
- `External scripts: 1`
- `Without integrity: 1`

**Remediation:**

```
Add integrity and crossorigin attributes:
<script src="https://cdn.example/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>
```

## 29. X-Content-Type-Options header is missing

**Severity:** Low · **CVSS:** 3.1 · **CWE-693** · A05:2021 Security Misconfiguration

**What we found:** Browsers may 'sniff' a response into a different content type than declared, which can turn an uploaded file or user-controlled endpoint into executable script (MIME confusion attacks).

**Impact:** Raises the likelihood and blast radius of any injection flaw on the site; an attacker who lands one script gets a durable foothold in users' browsers.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Response headers did not include: x-content-type-options`

**Remediation:**

```
Add to every response:
X-Content-Type-Options: nosniff
```

## 30. Cross-Origin-Opener-Policy (COOP) header is missing

**Severity:** Info · **CVSS:** 3.1 · **CWE-693** · A05:2021 Security Misconfiguration

**What we found:** COOP isolates your browsing context from cross-origin windows, closing cross-window attacks such as Spectre-style leaks and tabnabbing chains.

**Impact:** Raises the likelihood and blast radius of any injection flaw on the site; an attacker who lands one script gets a durable foothold in users' browsers.

**Evidence:**
- `GET http://127.0.0.1:8099/`
- `Response headers did not include: cross-origin-opener-policy`

**Remediation:**

```
Add:
Cross-Origin-Opener-Policy: same-origin
```

## 31. No web application firewall detected

**Severity:** Info · **CVSS:** - · **CWE-693** · A05:2021 Security Misconfiguration

**What we found:** No WAF or CDN filtering layer was identified in front of the application. Nothing sits between the internet and the code to block obvious attack patterns.

**Impact:** Every malicious request reaches the application directly; there is no virtual patching option when a CVE drops.

**Evidence:**
- `No WAF signature headers observed`

**Remediation:**

```
Consider a WAF/CDN (Cloudflare, AWS WAF, or a managed service). Treat it as defence in depth only - it never replaces fixing the underlying code.
```

## 32. Password field allows browser autocomplete

**Severity:** Info · **CVSS:** - · **CWE-522** · A07:2021 Identification and Authentication Failures

**What we found:** The login form does not set autocomplete="off" or a credential-manager hint. On shared devices this can leave credentials stored in the browser.

**Impact:** Minor credential exposure on shared computers.

**Evidence:**
- `Form action: http://127.0.0.1:8099/login`

**Remediation:**

```
Use autocomplete="current-password" on login and "new-password" on registration so password managers behave correctly, and avoid autocomplete="off" on login (it breaks managers).
```

## 33. robots.txt points at sensitive paths

**Severity:** Info · **CVSS:** - · **CWE-200** · A05:2021 Security Misconfiguration

**What we found:** robots.txt lists directories that look sensitive. Bots ignore this file, and it is often the first thing an attacker reads - it works as a signpost rather than a control.

**Impact:** Guides attackers to admin, backup or internal paths.

**Evidence:**
- `Disallow entries: /admin/, /backup/, /internal-api/`

**Remediation:**

```
Do not rely on robots.txt for access control. Protect these paths with real authentication and remove the hints.
```
