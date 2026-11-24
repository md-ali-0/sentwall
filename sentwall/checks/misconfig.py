"""Server-level misconfiguration: HTTP methods, CORS, verbose errors, host header."""
from __future__ import annotations

import random
import re
import string
from typing import List

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "misconfig"
LABEL = "Server & application misconfiguration"

CANARY_ORIGIN = "https://sentwall-canary.example"
CANARY_HOST = "sentwall-canary.example"

_STACK_TRACE_MARKERS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)", "Java stack trace"),
    (r"org\.springframework\.[a-z.]+Exception", "Spring exception"),
    (r"Warning: (mysql_|mysqli_|pg_|oci_)", "PHP database warning"),
    (r"Fatal error:.{0,120}on line \d+", "PHP fatal error"),
    (r"You have an error in your SQL syntax", "MySQL error"),
    (r"ORA-\d{4,5}", "Oracle error"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB error"),
    (r"System\.Data\.SqlClient\.SqlException", ".NET SQL exception"),
    (r"System\.(Web|Data|IO)\.[A-Za-z.]*Exception", ".NET exception"),
    (r"Microsoft \.NET Framework Version", ".NET version banner"),
    (r"<b>Notice</b>:\s+Undefined", "PHP notice"),
    (r"SQLSTATE\[", "PDO SQLSTATE error"),
    (r"django\.(core|db)\.", "Django debug page"),
    (r"werkzeug\.debug", "Werkzeug debugger"),
    (r"Whoops! There was an error", "Laravel Whoops page"),
    (r"ActionController::", "Ruby on Rails error"),
    (r"express\s+\d+\.\d+\.\d+", "Express version leak"),
]


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    out += _check_methods(ctx)
    out += _check_cors(ctx)
    out += _check_verbose_errors(ctx)
    out += _check_host_header(ctx)
    return out


def _check_methods(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    resp = ctx.http.request("OPTIONS", ctx.base_url, allow_redirects=False)
    allow = resp.header("allow")
    if allow:
        ctx.add_meta("allowed_methods", allow)
    methods = {m.strip().upper() for m in allow.split(",")} if allow else set()

    # TRACE is safe to test: it only echoes the request back.
    trace = ctx.http.request("TRACE", ctx.base_url, allow_redirects=False)
    if trace.status == 200 and "TRACE" in trace.text.upper()[:2000]:
        out.append(
            Finding(
                key="http-trace-enabled",
                title="HTTP TRACE method is enabled",
                severity=Severity.MEDIUM,
                category="Misconfiguration",
                description="The server answers TRACE by echoing the full request back, including "
                "headers. Combined with a scripting flaw this enables Cross-Site Tracing (XST), "
                "which can read HttpOnly cookies.",
                impact="Bypasses the HttpOnly protection on session cookies in some browsers.",
                remediation="Disable TRACE at the web server:\n"
                "Apache: TraceEnable Off\nnginx: if ($request_method = TRACE) { return 405; }",
                evidence=[f"TRACE {ctx.base_url} -> HTTP {trace.status}"],
                cwe="CWE-749",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=5.3,
                location=ctx.base_url,
            )
        )

    dangerous = methods & {"PUT", "DELETE", "PATCH", "PROPFIND", "COPY", "MOVE", "MKCOL"}
    if dangerous:
        out.append(
            Finding(
                key="http-dangerous-methods",
                title="Dangerous HTTP methods advertised: " + ", ".join(sorted(dangerous)),
                severity=Severity.MEDIUM,
                category="Misconfiguration",
                description="The server advertises write-capable methods on a public endpoint. "
                "If the application layer does not authorise them, an attacker can upload or "
                "delete content directly.",
                impact="Potential unauthorised file upload, overwrite or deletion.",
                remediation="Restrict allowed methods to GET/POST/HEAD (plus OPTIONS if needed) "
                "and return 405 for the rest. Verify authorisation on every verb.",
                evidence=[f"Allow: {allow}"],
                cwe="CWE-749",
                owasp="A05:2021 Security Misconfiguration",
                confidence="tentative",
                effort="moderate",
                cvss=5.3,
                location=ctx.base_url,
            )
        )
    return out


def _check_cors(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    paths = ["/", "/api", "/api/v1", "/api/user", "/graphql", "/login"]
    tested = []
    for path in paths:
        url = ctx.base_url.rstrip("/") + path
        r = ctx.http.get(url, headers={"Origin": CANARY_ORIGIN}, allow_redirects=False)
        if not r.status or r.status >= 400:
            continue
        acao = r.header("access-control-allow-origin")
        if not acao:
            continue
        acac = r.header("access-control-allow-credentials").lower() == "true"
        tested.append((url, acao, acac))

        if acao == CANARY_ORIGIN and acac:
            out.append(
                Finding(
                    key="cors-reflect-credentials",
                    title="CORS reflects any origin with credentials enabled",
                    severity=Severity.CRITICAL,
                    category="Misconfiguration",
                    description=f"{url} returned Access-Control-Allow-Origin: {CANARY_ORIGIN} "
                    "together with Access-Control-Allow-Credentials: true. Any website on the "
                    "internet can therefore make authenticated cross-origin requests and read "
                    "the responses as the logged-in victim.",
                    impact="Complete account takeover from a single malicious link: the attacker "
                    "reads profile data, API tokens and personal information, and can perform "
                    "actions on the victim's behalf.",
                    remediation="Never reflect the Origin header blindly. Use a strict allow-list:\n"
                    "if origin in TRUSTED_ORIGINS: set ACAO=origin, ACAC=true\n"
                    "else: do not send CORS headers at all.\n"
                    "Also reject the 'null' origin.",
                    evidence=[
                        f"GET {url}",
                        f"Origin: {CANARY_ORIGIN}",
                        f"Access-Control-Allow-Origin: {acao}",
                        "Access-Control-Allow-Credentials: true",
                    ],
                    cwe="CWE-942",
                    owasp="A01:2021 Broken Access Control",
                    effort="quick",
                    cvss=9.3,
                    location=url,
                )
            )
        elif acao == CANARY_ORIGIN:
            out.append(
                Finding(
                    key="cors-reflect",
                    title="CORS allows arbitrary origins",
                    severity=Severity.MEDIUM,
                    category="Misconfiguration",
                    description=f"{url} reflects any supplied Origin in Access-Control-Allow-Origin. "
                    "Without credentials the impact is limited, but any sensitive unauthenticated "
                    "data on this endpoint can be read by third-party sites.",
                    impact="Cross-origin data theft where the endpoint returns sensitive data "
                    "without authentication.",
                    remediation="Replace the reflection with a static allow-list of trusted origins.",
                    evidence=[f"Origin: {CANARY_ORIGIN} -> ACAO: {acao}"],
                    cwe="CWE-942",
                    owasp="A01:2021 Broken Access Control",
                    confidence="firm",
                    effort="quick",
                    cvss=5.3,
                    location=url,
                )
            )
        elif acao == "*" and acac:
            out.append(
                Finding(
                    key="cors-wildcard-credentials",
                    title="CORS wildcard combined with credentials",
                    severity=Severity.LOW,
                    category="Misconfiguration",
                    description="The endpoint sends ACAO: * with Allow-Credentials: true. Browsers "
                    "reject this combination, so the configuration is broken rather than directly "
                    "exploitable - but it signals an ad-hoc CORS setup.",
                    impact="Cross-origin requests that the developers expect to work will fail, "
                    "and the intent is unclear to future maintainers.",
                    remediation="Use an explicit origin allow-list instead of '*' when credentials "
                    "are required.",
                    evidence=[f"ACAO: {acao}", "ACAC: true"],
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                    effort="quick",
                    cvss=3.1,
                    location=url,
                )
            )
        elif acao == "null":
            out.append(
                Finding(
                    key="cors-null-origin",
                    title="CORS accepts the 'null' origin",
                    severity=Severity.HIGH,
                    category="Misconfiguration",
                    description="Access-Control-Allow-Origin: null is honoured for sandboxed "
                    "iframes and data: URLs, both of which an attacker can create freely.",
                    impact="Bypasses the origin allow-list and enables cross-origin data theft.",
                    remediation="Reject 'null' explicitly; only allow known https origins.",
                    evidence=[f"Origin: {CANARY_ORIGIN} -> ACAO: null"],
                    cwe="CWE-942",
                    owasp="A01:2021 Broken Access Control",
                    effort="quick",
                    cvss=7.4,
                    location=url,
                )
            )
    if tested:
        ctx.add_meta("cors", [{"url": u, "acao": a, "credentials": c} for u, a, c in tested])
    return out


def _check_verbose_errors(ctx: ScanContext) -> List[Finding]:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    url = ctx.base_url.rstrip("/") + f"/sentwall-{token}.php"
    r = ctx.http.get(url, allow_redirects=True)
    if not r.status or r.status < 400:
        return []
    body = r.text[:60000]
    hits = []
    for pattern, label in _STACK_TRACE_MARKERS:
        m = re.search(pattern, body, re.I)
        if m:
            start = max(0, m.start() - 60)
            hits.append(f"{label}: ...{body[start:m.end() + 80].strip()[:220]}...")
    if not hits:
        return []
    return [
        Finding(
            key="verbose-error-pages",
            title="Application leaks internal details in error pages",
            severity=Severity.MEDIUM,
            category="Information Disclosure",
            description="Requesting a non-existent path produced a response containing stack "
            "traces or framework internals. This hands an attacker the exact framework, "
            "library versions, file paths and sometimes database credentials.",
            impact="Massively shortens the attack path: the attacker no longer needs to guess "
            "the stack, and file paths are directly usable in local file inclusion attacks.",
            remediation="Turn off debug mode in production (DEBUG=False, APP_DEBUG=false, "
            "customErrors mode=\"On\"), return a generic error page, and log the details "
            "server-side only.",
            evidence=hits[:3],
            cwe="CWE-209",
            owasp="A05:2021 Security Misconfiguration",
            effort="quick",
            cvss=5.3,
            location=url,
        )
    ]


def _check_host_header(ctx: ScanContext) -> List[Finding]:
    r = ctx.http.get(ctx.base_url, headers={"Host": CANARY_HOST}, allow_redirects=False)
    if not r.status:
        return []
    loc = r.header("location")
    if CANARY_HOST in loc:
        return [
            Finding(
                key="host-header-injection",
                title="Host header is used to build redirect URLs",
                severity=Severity.MEDIUM,
                category="Misconfiguration",
                description="Supplying a forged Host header changed the redirect target, which "
                "means the application trusts client-supplied hostnames. This is the root cause "
                "of password-reset poisoning and cache-poisoning attacks.",
                impact="Attackers can send password-reset links pointing at their own domain and "
                "harvest tokens, or poison shared caches with malicious content.",
                remediation="Use a fixed, configured hostname for absolute URLs (APP_URL / "
                "server_name), validate the Host header against an allow-list, and never build "
                "reset links from it.",
                evidence=[f"Host: {CANARY_HOST}", f"Location: {loc}"],
                cwe="CWE-20",
                owasp="A05:2021 Security Misconfiguration",
                effort="moderate",
                cvss=6.1,
                location=ctx.base_url,
            )
        ]
    return []
