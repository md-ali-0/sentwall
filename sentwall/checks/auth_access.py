"""Authentication, authorization, CSRF, and rate limiting resilience assessment."""
from __future__ import annotations

import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..context import ScanContext
from ..crawl import Form
from ..models import Finding, Severity

NAME = "auth_access"
LABEL = "Authentication & Access Control (Rate limiting, CSRF protection, Verb tampering)"

AUTH_PATHS = [
    "/login",
    "/api/login",
    "/auth/login",
    "/signin",
    "/api/auth",
    "/user/login",
    "/api/v1/auth/login",
]

CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token", "authenticity_token",
    "xsrf", "xsrf_token", "_xsrf", "antiforgery", "token"
}


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_auth:
        return out

    out += _check_csrf_protection(ctx)
    out += _check_rate_limiting(ctx)
    out += _check_verb_tampering(ctx)
    return out


def _check_csrf_protection(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    seen_actions: Set[str] = set()

    for page in ctx.pages:
        for form in page.forms:
            if form.method.upper() != "POST":
                continue
            action = form.action or page.url
            if action in seen_actions:
                continue
            seen_actions.add(action)

            # Check if form has password or state-changing field
            has_token = any(name.lower() in CSRF_TOKEN_NAMES for name in form.param_names)
            # If form has password or sensitive inputs but no CSRF token
            if not has_token and (form.has_password or any(k in action.lower() for k in ["login", "account", "user", "update", "profile", "password"])):
                f = Finding(
                    key=f"missing-csrf-token-{len(findings)+1}",
                    title="Missing Anti-CSRF Protection on State-Changing Form",
                    severity=Severity.HIGH,
                    category="Authentication & Session",
                    description=(
                        f"A sensitive POST form at action '{action}' on page {page.url} "
                        "does not contain an anti-Cross-Site Request Forgery (CSRF) token."
                    ),
                    impact=(
                        "An attacker can host a malicious webpage that silently submits requests on behalf of "
                        "authenticated users without their consent, potentially altering account details, emails, or settings."
                    ),
                    remediation=(
                        "Implement unpredictable, cryptographically strong anti-CSRF synchronizer tokens "
                        "for all state-changing POST/PUT/DELETE requests. "
                        "Additionally, configure session cookies with `SameSite=Lax` or `SameSite=Strict`."
                    ),
                    evidence=[
                        f"Page URL: {page.url}",
                        f"Form Action: {action}",
                        f"Detected Form Fields: {', '.join(form.param_names) if form.param_names else 'None'}",
                    ],
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                    cwe="CWE-352",
                    owasp="A01:2021-Broken Access Control",
                    confidence="certain",
                    effort="moderate",
                    cvss=7.5,
                    location=action,
                    title_bn="গুরুত্বপূর্ণ ফর্মে অ্যান্টি-CSRF টোকেনের অনুপস্থিতি",
                    description_bn=f"{page.url} পেজের ফর্মে কোনো CSRF প্রটেকশন টোকেন নেই।",
                    impact_bn="অন্য কোনো ক্ষতিকর ওয়েবসাইট থেকে ব্যবহারকারীর অজান্তেই প্রোফাইল আপডেট বা পাসওয়ার্ড পরিবর্তন করে ফেলা সম্ভব।",
                    fix_patches={
                        "code": "<!-- Include CSRF Token in Form -->\n<form method=\"POST\" action=\"/account/update\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <!-- inputs -->\n</form>",
                    },
                )
                findings.append(f)
                break  # One finding per scan is sufficient

    return findings


def _check_rate_limiting(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    # Identify login endpoint from discovered forms or common paths
    login_url = None
    for page in ctx.pages:
        for form in page.forms:
            if form.has_password and form.action:
                login_url = urljoin(page.url, form.action)
                break
        if login_url:
            break

    if not login_url:
        for p in AUTH_PATHS:
            test_url = urljoin(ctx.base_url, p)
            resp = ctx.http.get(test_url)
            if resp.status in (200, 401, 403):
                login_url = test_url
                break

    if not login_url:
        return findings

    # Send 6 rapid lightweight probes to test for rate-limit protection
    rate_limited = False
    rate_limit_headers = False
    last_status = 0

    for _ in range(6):
        r = ctx.http.get(login_url)
        last_status = r.status
        if r.status == 429:
            rate_limited = True
            break
        for h in r.headers:
            if "ratelimit" in h.lower() or "retry-after" in h.lower():
                rate_limit_headers = True
                break
        time.sleep(0.05)

    if not rate_limited and not rate_limit_headers:
        f = Finding(
            key="missing-rate-limiting-authentication",
            title="Absence of Rate Limiting on Authentication Endpoint",
            severity=Severity.MEDIUM,
            category="Authentication & Session",
            description=(
                f"The authentication endpoint at {login_url} showed no evidence of rate limiting or brute-force throttling "
                "after rapid successive queries (no 429 status code or standard RateLimit-* headers detected)."
            ),
            impact=(
                "Allows malicious actors to perform automated credential stuffing, dictionary password attacks, "
                "or distributed brute-force attacks against user accounts without triggering throttling."
            ),
            remediation=(
                "Enforce strict IP and account-based rate limiting on all login, registration, and password recovery endpoints. "
                "Return HTTP 429 (Too Many Requests) with a `Retry-After` header when thresholds are exceeded. "
                "Implement account lockouts or progressive CAPTCHA challenges after consecutive failed attempts."
            ),
            evidence=[
                f"Endpoint: {login_url}",
                f"Tested 6 rapid requests; all returned status {last_status}",
                "No 'Retry-After' or 'X-RateLimit-*' headers observed",
            ],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/307.html",
            ],
            cwe="CWE-307",
            owasp="A07:2021-Identification and Authentication Failures",
            confidence="firm",
            effort="moderate",
            cvss=5.3,
            location=login_url,
            title_bn="অথেনটিকেশন এন্ডপয়েন্টে রেট লিমিটিং (Rate Limiting) এর অভাব",
            description_bn=f"{login_url} এ কোনো রেট লিমিটিং নেই, ফলে হ্যাকাররা স্বয়ংক্রিয়ভাবে হাজার হাজার পাসওয়ার্ড ট্রাই করতে পারবে।",
            impact_bn="সহজেই ব্রুট-ফোর্স (Brute-Force) বা ক্রেডেনশিয়াল স্টাফিং অ্যাটাক চালিয়ে ইউজারের অ্যাকাউন্ট হ্যাক করা সম্ভব।",
            fix_patches={
                "nginx": "# In nginx http context:\nlimit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;\n\n# In location block:\nlocation /login {\n  limit_req zone=login_limit burst=3 nodelay;\n  proxy_pass http://backend;\n}",
            },
            poc_curl_template=f"for i in {{1..10}}; do curl -s -o /dev/null -w '%{{http_code}}\\n' '{login_url}'; done",
        )
        findings.append(f)

    return findings


def _check_verb_tampering(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    admin_paths = ["/admin", "/admin/", "/administrator", "/dashboard"]

    for path in admin_paths:
        url = urljoin(ctx.base_url, path)
        get_resp = ctx.http.get(url)
        # If GET returns 401 Unauthorized or 403 Forbidden
        if get_resp.status in (401, 403):
            # Try HEAD or OPTIONS
            head_resp = ctx.http.request("HEAD", url)
            if head_resp.status == 200:
                f = Finding(
                    key="http-verb-tampering-bypass",
                    title="Potential HTTP Verb Tampering Authorization Bypass",
                    severity=Severity.HIGH,
                    category="Authentication & Access Control",
                    description=(
                        f"Access to {url} returned HTTP {get_resp.status} for standard GET requests, "
                        "but returned HTTP 200 OK when requested with the HEAD verb."
                    ),
                    impact=(
                        "Indicates authorization filters are applied only to specific HTTP verbs (e.g. GET/POST), "
                        "potentially allowing attackers to bypass authentication or access control constraints."
                    ),
                    remediation=(
                        "Configure access control constraints to apply to all HTTP methods unconditionally "
                        "unless explicitly intended otherwise."
                    ),
                    evidence=[
                        f"Endpoint: {url}",
                        f"GET response: {get_resp.status}",
                        f"HEAD response: {head_resp.status}",
                    ],
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering",
                        "https://cwe.mitre.org/data/definitions/654.html",
                    ],
                    cwe="CWE-654",
                    owasp="A01:2021-Broken Access Control",
                    confidence="certain",
                    effort="quick",
                    cvss=7.5,
                    location=url,
                    title_bn="HTTP Verb Tampering এর মাধ্যমে অথরাইজেশন বাইপাস ঝুঁকি",
                    description_bn=f"GET রিকোয়েস্টে {get_resp.status} বাধা আসলেও HEAD মেথডে রিকোয়েস্ট পাঠালে সার্ভার রেসপন্স করছে।",
                    impact_bn="ভুল মেথড ফিল্টারিংয়ের সুযোগ নিয়ে রেস্ট্রিকশন বাইপাস করা সম্ভব হতে পারে।",
                    poc_curl_template=f"curl -I -X HEAD '{url}'",
                )
                findings.append(f)
                break

    return findings
