"""Cookie flag analysis (Secure / HttpOnly / SameSite / scope / lifetime)."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "cookies"
LABEL = "Cookie security attributes"

_SESSION_HINT = re.compile(r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|user)", re.I)


def parse_cookie(raw: str) -> Dict[str, Optional[str]]:
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return {}
    name, value = parts[0].split("=", 1)
    out: Dict[str, Optional[str]] = {"name": name.strip(), "value": value.strip()}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[p.strip().lower()] = None
    return out


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    resp = ctx.http.get(ctx.base_url, allow_redirects=True)
    raws: List[str] = list(resp.set_cookie)
    if not raws:
        return out

    cookies = [c for c in (parse_cookie(r) for r in raws) if c]
    ctx.add_meta("cookies", [
        {"name": c.get("name"), "secure": "secure" in c, "httponly": "httponly" in c,
         "samesite": c.get("samesite") or "(none)"} for c in cookies
    ])

    insecure: List[str] = []
    no_httponly: List[str] = []
    no_samesite: List[str] = []
    same_none_no_secure: List[str] = []
    long_lived: List[str] = []
    broad_scope: List[str] = []

    for c in cookies:
        name = c.get("name", "?")
        sensitive = bool(_SESSION_HINT.search(name))
        if "secure" not in c:
            insecure.append(name)
        if "httponly" not in c and sensitive:
            no_httponly.append(name)
        ss = (c.get("samesite") or "").lower()
        if not ss and sensitive:
            no_samesite.append(name)
        if ss == "none" and "secure" not in c:
            same_none_no_secure.append(name)
        if sensitive and c.get("max-age"):
            try:
                if int(c["max-age"]) > 60 * 60 * 24 * 365:
                    long_lived.append(f"{name} (max-age={c['max-age']})")
            except ValueError:
                pass
        if sensitive and c.get("domain", "").startswith("."):
            broad_scope.append(f"{name} (domain={c['domain']})")

    evidence = [f"{c.get('name')}: " + ", ".join(k for k in c if k not in ("name", "value")) for c in cookies]

    if insecure:
        out.append(
            Finding(
                key="cookie-no-secure",
                title="Cookies missing the Secure flag: " + ", ".join(insecure[:6]),
                severity=Severity.HIGH if any(_SESSION_HINT.search(n) for n in insecure) else Severity.MEDIUM,
                category="Session Management",
                description="These cookies can be sent over plain HTTP. A single unencrypted "
                "request - a mistyped URL, an http:// link, a shared network - exposes them "
                "to anyone listening on the wire.",
                impact="Session hijacking: an attacker who captures the cookie becomes the user "
                "without needing any password.",
                remediation="Set the Secure attribute on every cookie:\n"
                "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
                evidence=evidence,
                cwe="CWE-614",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=7.1,
                location=ctx.base_url,
            )
        )

    if no_httponly:
        out.append(
            Finding(
                key="cookie-no-httponly",
                title="Session cookies readable from JavaScript: " + ", ".join(no_httponly[:6]),
                severity=Severity.MEDIUM,
                category="Session Management",
                description="Without HttpOnly, any JavaScript running on the page - including "
                "code injected through an XSS flaw or a compromised third-party script - can "
                "read the session cookie with document.cookie.",
                impact="A single XSS anywhere on the site escalates from 'script execution' to "
                "full, persistent account takeover.",
                remediation="Add HttpOnly to all session and authentication cookies.",
                evidence=evidence,
                cwe="CWE-1004",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=6.5,
                location=ctx.base_url,
            )
        )

    if no_samesite:
        out.append(
            Finding(
                key="cookie-no-samesite",
                title="Cookies without SameSite attribute: " + ", ".join(no_samesite[:6]),
                severity=Severity.MEDIUM,
                category="Session Management",
                description="With no SameSite attribute, browsers fall back to their default "
                "behaviour and the cookie is attached to cross-site requests. That is exactly "
                "what a CSRF attack needs.",
                impact="State-changing actions (password change, transfer, delete) can be "
                "triggered from an attacker's page while the victim is logged in.",
                remediation="Add SameSite=Lax to normal session cookies; use SameSite=Strict "
                "for admin or high-value actions. Pair with anti-CSRF tokens.",
                evidence=evidence,
                cwe="CWE-1275",
                owasp="A01:2021 Broken Access Control",
                effort="quick",
                cvss=6.5,
                location=ctx.base_url,
            )
        )

    if same_none_no_secure:
        out.append(
            Finding(
                key="cookie-samesite-none-insecure",
                title="SameSite=None used without Secure: " + ", ".join(same_none_no_secure),
                severity=Severity.HIGH,
                category="Session Management",
                description="SameSite=None explicitly re-enables cross-site sending, and modern "
                "browsers reject such cookies unless Secure is also set. The result is either a "
                "broken login flow or an unprotected cookie.",
                impact="Either authentication breaks intermittently, or the cookie is exposed "
                "over HTTP.",
                remediation="Set both attributes together: Secure; SameSite=None (only when "
                "genuinely required for cross-site embedding).",
                evidence=evidence,
                cwe="CWE-614",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=7.1,
                location=ctx.base_url,
            )
        )

    if long_lived:
        out.append(
            Finding(
                key="cookie-long-lived",
                title="Long-lived authentication cookies",
                severity=Severity.LOW,
                category="Session Management",
                description="Session cookies stay valid for more than a year. A stolen cookie "
                "remains usable long after the user has forgotten about that device.",
                impact="Extended window of opportunity for stolen-token reuse.",
                remediation="Shorten session lifetime (e.g. 7-30 days), rotate the session ID on "
                "login and privilege change, and offer a 'log out of all devices' control.",
                evidence=long_lived,
                cwe="CWE-613",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="moderate",
                cvss=3.1,
                location=ctx.base_url,
            )
        )

    if broad_scope:
        out.append(
            Finding(
                key="cookie-broad-domain",
                title="Session cookies scoped to the whole parent domain",
                severity=Severity.LOW,
                category="Session Management",
                description="A Domain attribute such as .example.com shares the cookie with every "
                "subdomain, including staging, marketing and third-party-hosted subdomains that "
                "may be less well maintained.",
                impact="One compromised subdomain is enough to steal the main site's session.",
                remediation="Host-only cookies (omit the Domain attribute) for the primary site; "
                "use a dedicated parent-domain cookie only where SSO genuinely requires it.",
                evidence=broad_scope,
                cwe="CWE-565",
                owasp="A05:2021 Security Misconfiguration",
                effort="moderate",
                cvss=3.5,
                location=ctx.base_url,
            )
        )
    return out
