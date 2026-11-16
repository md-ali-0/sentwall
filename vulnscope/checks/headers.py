"""HTTP security header analysis: CSP, HSTS, framing, sniffing, referrer, permissions."""
from __future__ import annotations

from typing import Dict, List

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "headers"
LABEL = "Security headers & browser hardening"

# header -> (severity when missing, title, why it matters, how to fix)
CHECKS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy header is missing",
        "Without a CSP the browser will execute any script that reaches the page. "
        "This is the single most effective defence-in-depth control against cross-site "
        "scripting (XSS), malicious third-party scripts and data injection.",
        "Publish a restrictive CSP, starting in report-only mode:\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "CWE-693",
        "A05:2021 Security Misconfiguration",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS) header is missing",
        "Without HSTS a user's first request can be sent over plain HTTP, where it can "
        "be intercepted and downgraded (SSL-stripping). Session cookies and credentials "
        "can be captured in transit.",
        "Add on every HTTPS response:\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "Roll it out gradually (start with max-age=300) and only add 'preload' once "
        "you are certain every subdomain supports HTTPS.",
        "CWE-319",
        "A02:2021 Cryptographic Failures",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options header is missing",
        "Browsers may 'sniff' a response into a different content type than declared, "
        "which can turn an uploaded file or user-controlled endpoint into executable "
        "script (MIME confusion attacks).",
        "Add to every response:\nX-Content-Type-Options: nosniff",
        "CWE-693",
        "A05:2021 Security Misconfiguration",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy header is missing",
        "Full URLs - including tokens and internal identifiers - leak to third parties "
        "through the Referer header when users click external links.",
        "Add:\nReferrer-Policy: strict-origin-when-cross-origin",
        "CWE-200",
        "A01:2021 Broken Access Control",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Permissions-Policy header is missing",
        "Powerful browser features (camera, microphone, geolocation, clipboard) stay "
        "available to any embedded third-party frame unless explicitly disabled.",
        "Add a deny-by-default policy, e.g.:\n"
        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
        "CWE-693",
        "A05:2021 Security Misconfiguration",
    ),
    "cross-origin-opener-policy": (
        Severity.INFO,
        "Cross-Origin-Opener-Policy (COOP) header is missing",
        "COOP isolates your browsing context from cross-origin windows, closing "
        "cross-window attacks such as Spectre-style leaks and tabnabbing chains.",
        "Add:\nCross-Origin-Opener-Policy: same-origin",
        "CWE-693",
        "A05:2021 Security Misconfiguration",
    ),
}


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    home = ctx.homepage()
    if not home:
        return out

    h = {k.lower(): v for k, v in home.headers.items()}
    ctx.add_meta("response_headers", dict(home.headers))
    has_login = bool(home.password_forms)

    for name, (sev, title, why, fix, cwe, owasp) in CHECKS.items():
        if name in h:
            continue
        if name == "strict-transport-security" and not home.url.startswith("https://"):
            continue
        s = sev
        # A missing CSP on a page that handles credentials is materially worse.
        if name == "content-security-policy" and has_login:
            s = Severity.HIGH
        out.append(
            Finding(
                key=f"hdr-missing-{name}",
                title=title,
                severity=s,
                category="Security Headers",
                description=why,
                impact=(
                    "Raises the likelihood and blast radius of any injection flaw on the site; "
                    "an attacker who lands one script gets a durable foothold in users' browsers."
                ),
                remediation=fix,
                evidence=[f"GET {home.url}", "Response headers did not include: " + name],
                cwe=cwe,
                owasp=owasp,
                effort="quick",
                cvss={Severity.HIGH: 6.1, Severity.MEDIUM: 5.3}.get(s, 3.1),
                location=home.url,
            )
        )

    out += _check_hsts(h, home.url)
    out += _check_csp(h, home.url, has_login)
    out += _check_framing(h, home.url)
    out += _check_banners(h, home.url)
    return out


def _check_hsts(h: Dict[str, str], url: str) -> List[Finding]:
    out: List[Finding] = []
    val = h.get("strict-transport-security")
    if not val:
        return out
    low = val.lower()
    max_age = 0
    for part in low.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    if max_age == 0:
        out.append(
            Finding(
                key="hsts-max-age-zero",
                title="HSTS is present but disabled (max-age=0)",
                severity=Severity.MEDIUM,
                category="Security Headers",
                description="The HSTS header is sent with max-age=0, which actively instructs "
                "browsers to forget the HTTPS-only policy. This is usually left over from "
                "debugging and silently disables downgrade protection.",
                impact="Users remain exposed to SSL-stripping attacks on every visit.",
                remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
                evidence=[f"Strict-Transport-Security: {val}"],
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=5.9,
                location=url,
            )
        )
    elif max_age < 15552000:
        out.append(
            Finding(
                key="hsts-short-max-age",
                title=f"HSTS max-age is short ({max_age}s)",
                severity=Severity.LOW,
                category="Security Headers",
                description="An HSTS lifetime below six months gives browsers only a narrow "
                "window of protection and does not qualify for preload.",
                impact="Downgrade protection expires quickly and cannot be preloaded.",
                remediation="Raise to max-age=31536000 (one year) once verified in production.",
                evidence=[f"Strict-Transport-Security: {val}"],
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=3.7,
                location=url,
            )
        )
    if "includesubdomains" not in low:
        out.append(
            Finding(
                key="hsts-no-subdomains",
                title="HSTS does not cover subdomains",
                severity=Severity.LOW,
                category="Security Headers",
                description="Without includeSubDomains, an attacker can still downgrade or "
                "intercept requests to subdomains such as api., cdn. or mail.",
                impact="Cookie-scoping and subdomain interception attacks stay possible.",
                remediation="Add includeSubDomains to the HSTS header once all subdomains serve HTTPS.",
                evidence=[f"Strict-Transport-Security: {val}"],
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=3.1,
                location=url,
            )
        )
    return out


def _check_csp(h: Dict[str, str], url: str, has_login: bool) -> List[Finding]:
    out: List[Finding] = []
    raw = h.get("content-security-policy", "")
    if not raw:
        if "content-security-policy-report-only" in h:
            out.append(
                Finding(
                    key="csp-report-only",
                    title="CSP is deployed in report-only mode",
                    severity=Severity.LOW,
                    category="Security Headers",
                    description="Content-Security-Policy-Report-Only collects violation reports "
                    "but blocks nothing. It is a valid rollout step, yet offers no protection "
                    "while it stays in that state.",
                    impact="No XSS mitigation is actually enforced.",
                    remediation="After the report stream is clean, switch the header to the "
                    "enforcing Content-Security-Policy.",
                    evidence=[f"Content-Security-Policy-Report-Only: {raw[:300]}"],
                    cwe="CWE-693",
                    owasp="A05:2021 Security Misconfiguration",
                    effort="quick",
                    cvss=3.1,
                    location=url,
                )
            )
        return out

    low = raw.lower()
    problems = []
    if "'unsafe-inline'" in low:
        problems.append("'unsafe-inline'")
    if "'unsafe-eval'" in low:
        problems.append("'unsafe-eval'")
    if " *" in low or "default-src *" in low or "script-src *" in low:
        problems.append("wildcard *")
    if "http:" in low and url.startswith("https://"):
        problems.append("http: sources")
    if "script-src" not in low and "default-src" not in low:
        problems.append("no script-src / default-src")

    if problems:
        sev = Severity.MEDIUM if any(p in ("'unsafe-inline'", "wildcard *") for p in problems) else Severity.LOW
        out.append(
            Finding(
                key="csp-weak",
                title="Content-Security-Policy is too permissive",
                severity=sev,
                category="Security Headers",
                description="The policy allows directives that defeat its purpose: "
                + ", ".join(problems)
                + ". A CSP containing 'unsafe-inline' does not stop reflected XSS at all, "
                "because injected inline script still executes.",
                impact="The main browser-side control against XSS provides little real protection.",
                remediation="Remove 'unsafe-inline'/'unsafe-eval', use nonces or hashes for inline "
                "scripts, and replace wildcards with explicit hostnames. Add "
                "object-src 'none' and base-uri 'self'.",
                evidence=[f"Content-Security-Policy: {raw[:400]}"],
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                confidence="certain",
                effort="involved",
                cvss=5.4 if sev is Severity.MEDIUM else 3.7,
                location=url,
            )
        )

    if "object-src" not in low and "default-src" not in low:
        out.append(
            Finding(
                key="csp-no-object-src",
                title="CSP does not restrict plugin content (object-src)",
                severity=Severity.LOW,
                category="Security Headers",
                description="Without object-src 'none' (or a default-src fallback), legacy "
                "plugin content such as Flash/Java applets can be embedded.",
                impact="Widens the injection surface for content-based attacks.",
                remediation="Add object-src 'none' and base-uri 'self' to the policy.",
                evidence=[f"Content-Security-Policy: {raw[:300]}"],
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=2.6,
                location=url,
            )
        )
    if "frame-ancestors" not in low:
        out.append(
            Finding(
                key="csp-no-frame-ancestors",
                title="CSP has no frame-ancestors directive",
                severity=Severity.LOW,
                category="Security Headers",
                description="frame-ancestors is the modern replacement for X-Frame-Options. "
                "Its absence means clickjacking protection depends on a legacy header alone.",
                impact="Weaker, browser-dependent clickjacking defence.",
                remediation="Add frame-ancestors 'self' (or 'none' where framing is not needed).",
                evidence=[f"Content-Security-Policy: {raw[:300]}"],
                cwe="CWE-1021",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=2.6,
                location=url,
            )
        )
    return out


def _check_framing(h: Dict[str, str], url: str) -> List[Finding]:
    xfo = h.get("x-frame-options", "").strip().lower()
    csp = h.get("content-security-policy", "").lower()
    if "frame-ancestors" in csp:
        return []
    if not xfo:
        return [
            Finding(
                key="clickjacking",
                title="Page can be framed by any site (clickjacking)",
                severity=Severity.MEDIUM,
                category="Security Headers",
                description="Neither X-Frame-Options nor CSP frame-ancestors is set, so the "
                "site can be embedded in an invisible iframe on an attacker's page. Users "
                "can be tricked into clicking 'Delete account', 'Pay' or 'Grant access' "
                "while believing they are on a harmless page.",
                impact="Account actions and payment flows can be hijacked through UI redressing.",
                remediation="Add Content-Security-Policy: frame-ancestors 'self' "
                "(preferred) and X-Frame-Options: SAMEORIGIN for older browsers.",
                evidence=["X-Frame-Options: (absent)", "CSP frame-ancestors: (absent)"],
                cwe="CWE-1021",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=4.3,
                location=url,
            )
        ]
    if xfo not in ("deny", "sameorigin"):
        return [
            Finding(
                key="xfo-invalid",
                title=f"Invalid X-Frame-Options value: {xfo}",
                severity=Severity.LOW,
                category="Security Headers",
                description="Browsers only honour DENY or SAMEORIGIN. Any other value is "
                "ignored, which silently removes clickjacking protection.",
                impact="The intended clickjacking defence is not applied.",
                remediation="Use X-Frame-Options: SAMEORIGIN (or DENY) plus CSP frame-ancestors.",
                evidence=[f"X-Frame-Options: {xfo}"],
                cwe="CWE-1021",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=3.1,
                location=url,
            )
        ]
    return []


_BANNER_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
    "x-generator": "X-Generator",
    "x-drupal-cache": "X-Drupal-Cache",
    "x-runtime": "X-Runtime",
    "x-version": "X-Version",
}


def _check_banners(h: Dict[str, str], url: str) -> List[Finding]:
    found = {label: h[key] for key, label in _BANNER_HEADERS.items() if key in h}
    if not found:
        return []
    evidence = [f"{k}: {v}" for k, v in found.items()]
    return [
        Finding(
            key="version-disclosure-headers",
            title="Technology versions disclosed in response headers",
            severity=Severity.LOW,
            category="Information Disclosure",
            description="Response headers advertise the exact server and framework versions. "
            "An attacker can match these against public CVE databases and pick exploits that "
            "are known to work, skipping the reconnaissance phase entirely.",
            impact="Faster, more reliable targeting of version-specific vulnerabilities.",
            remediation="Suppress or genericise version strings: nginx `server_tokens off;`, "
            "Apache `ServerTokens Prod` / `ServerSignature Off`, PHP `expose_php = Off`, "
            "and remove X-Powered-By at the reverse proxy.",
            evidence=evidence,
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            effort="quick",
            cvss=3.7,
            location=url,
        )
    ]
