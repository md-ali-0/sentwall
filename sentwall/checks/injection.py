"""Active, non-destructive injection probes.

Design rules:
  * every payload is a *detection canary*, never a destructive action;
  * no time-based payloads unless --deep is passed;
  * forms are only submitted with --test-forms, and never when they contain
    file inputs, passwords, or destructive action names.
"""
from __future__ import annotations

import random
import re
import string
import time
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from ..context import ScanContext
from ..crawl import collect_params, inject_param
from ..models import Finding, Severity

NAME = "injection"
LABEL = "Injection flaws (XSS, SQLi, redirect, traversal)"

SQL_ERRORS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql(i)?_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"system\.data\.sqlclient\.sqlexception", "MSSQL"),
    (r"pg_query\(\)|postgresql.*error", "PostgreSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"ora-\d{4,5}", "Oracle"),
    (r"sqlite3?\.(operationalerror|error)", "SQLite"),
    (r"sqlite error", "SQLite"),
    (r"sqlstate\[", "PDO"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"division by zero", "generic"),
]

REDIRECT_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "next", "continue", "dest", "destination", "target", "r", "go",
    "out", "link", "callback", "forward", "view",
}

TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
]

UNIX_PASSWD = re.compile(r"root:[x*]?:0:0:")
WIN_INI = re.compile(r"\[(extensions|fonts|mci extensions)\]", re.I)


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    params = collect_params(ctx.pages)
    if not params:
        return out

    out += _reflected_xss(ctx, params)
    out += _sqli_errors(ctx, params)
    if ctx.options.deep:
        out += _sqli_time(ctx, params)
    out += _open_redirect(ctx, params)
    out += _traversal(ctx, params)
    out += _ssti(ctx, params)
    out += _crlf(ctx, params)
    if ctx.options.test_forms:
        out += _form_checks(ctx)
    return out


def _rand(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _body_similar(a: str, b: str) -> bool:
    if not a or not b:
        return False
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return True
    return abs(la - lb) / max(la, lb) < 0.02


# --------------------------------------------------------------------- XSS
def _reflected_xss(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    tested = 0
    for page_url, name, value in params:
        if tested >= 40:
            break
        tested += 1
        canary = "vs" + _rand(8)
        tag = f"<{canary}>"
        url = inject_param(page_url, name, f"{canary}{tag}")

        base = ctx.http.get(page_url, allow_redirects=True)
        resp = ctx.http.get(url, allow_redirects=True)
        if resp.error or not resp.status:
            continue
        if canary not in resp.text:
            continue  # not reflected at all

        # angle brackets survived unencoded -> arbitrary tag injection possible
        if tag in resp.text:
            ctx.log(f"  ! reflected XSS candidate on {name}")
            out.append(
                Finding(
                    key=f"xss-reflected-{name}",
                    title=f"Reflected XSS in parameter '{name}'",
                    severity=Severity.HIGH,
                    category="Injection",
                    description=f"User input supplied in '{name}' is written back into the HTML "
                    "page without encoding. The probe string was returned with its angle "
                    "brackets intact, which means an attacker can inject any HTML tag - "
                    "including <script> - and it will execute in the victim's browser.",
                    impact="Session theft, credential phishing rendered inside your own page, "
                    "silent actions on behalf of the user, and malware delivery. Chained with "
                    "a missing HttpOnly flag this is immediate account takeover.",
                    remediation="Context-aware output encoding on every sink:\n"
                    "- HTML body: encode & < > \" '\n"
                    "- attributes: quote and encode\n"
                    "- JavaScript/URL contexts: use the framework's escaper\n"
                    "Also validate input against an allow-list and add a strict CSP as "
                    "defence in depth.",
                    evidence=[
                        f"GET {url}",
                        f"Payload fragment reflected verbatim: {tag}",
                        f"Response length: {len(resp.text)} bytes",
                    ],
                    cwe="CWE-79",
                    owasp="A03:2021 Injection",
                    confidence="firm",
                    effort="moderate",
                    cvss=6.1,
                    location=page_url,
                )
            )
    return out


# --------------------------------------------------------------------- SQLi
def _sqli_errors(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    tested = 0
    for page_url, name, value in params:
        if tested >= 30:
            break
        tested += 1
        base = ctx.http.get(page_url, allow_redirects=True)
        if base.error or not base.status:
            continue
        base_low = base.text.lower()

        for payload in ("'", '"', "')", "';"):
            url = inject_param(page_url, name, (value or "1") + payload)
            r = ctx.http.get(url, allow_redirects=True)
            if r.error or not r.status:
                continue
            low = r.text.lower()
            for pattern, dbms in SQL_ERRORS:
                if re.search(pattern, low) and not re.search(pattern, base_low):
                    out.append(
                        Finding(
                            key=f"sqli-error-{name}",
                            title=f"SQL injection in parameter '{name}' ({dbms})",
                            severity=Severity.CRITICAL,
                            category="Injection",
                            description=f"Appending a single quote to '{name}' produced a raw "
                            f"{dbms} database error that does not appear on the normal page. "
                            "The value is being concatenated directly into a SQL statement "
                            "instead of being sent as a bound parameter.",
                            impact="Full database read and write: customer records, password "
                            "hashes, payment data and admin credentials. Depending on database "
                            "privileges this often escalates to remote code execution on the "
                            "server. This is a reportable data-breach risk.",
                            remediation="Use parameterised queries / prepared statements "
                            "everywhere. Never build SQL by string concatenation.\n"
                            "PHP: $stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n"
                            "Java: PreparedStatement with setInt/setString\n"
                            "Also apply least-privilege DB accounts and disable detailed DB "
                            "errors in production.",
                            evidence=[
                                f"GET {url}",
                                f"Database error signature: {pattern}",
                            ],
                            cwe="CWE-89",
                            owasp="A03:2021 Injection",
                            effort="involved",
                            cvss=9.8,
                            location=page_url,
                        )
                    )
                    return out  # one confirmed instance is enough to stop probing
    return out


def _sqli_time(ctx: ScanContext, params) -> List[Finding]:
    """Blind time-based check. Only runs with --deep because it is slow."""
    out: List[Finding] = []
    delay = 4
    for page_url, name, value in params[:8]:
        base_start = time.time()
        ctx.http.get(page_url, allow_redirects=True)
        baseline = time.time() - base_start
        if baseline > delay:
            continue
        payload = f"1' AND (SELECT {delay} FROM (SELECT SLEEP({delay}))x)-- -"
        url = inject_param(page_url, name, payload)
        start = time.time()
        r = ctx.http.get(url, allow_redirects=True, timeout=delay + 15)
        elapsed = time.time() - start
        if r.status and elapsed > baseline + delay - 1:
            out.append(
                Finding(
                    key=f"sqli-blind-{name}",
                    title=f"Blind time-based SQL injection in '{name}'",
                    severity=Severity.CRITICAL,
                    category="Injection",
                    description="Injecting a conditional database sleep delayed the response "
                    f"from {baseline:.1f}s to {elapsed:.1f}s, proving the input reaches the SQL "
                    "engine even though no error is shown. This is the signature of blind SQL "
                    "injection, which can be exploited to extract the entire database.",
                    impact="Complete database disclosure through automated blind extraction.",
                    remediation="Parameterise the query. Then remove detailed timing/error "
                    "differences and apply a WAF rule as a stop-gap.",
                    evidence=[f"GET {url}", f"Baseline {baseline:.2f}s -> injected {elapsed:.2f}s"],
                    cwe="CWE-89",
                    owasp="A03:2021 Injection",
                    confidence="firm",
                    effort="involved",
                    cvss=9.1,
                    location=page_url,
                )
            )
            break
    return out


# --------------------------------------------------------------- redirect
def _open_redirect(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    canary_host = "sentwall-canary.invalid"
    for page_url, name, value in params:
        if name.lower() not in REDIRECT_PARAMS:
            continue
        url = inject_param(page_url, name, f"https://{canary_host}/poc")
        r = ctx.http.get(url, allow_redirects=False)
        if r.error or not r.status:
            continue
        loc = r.header("location")
        hit = canary_host in loc
        if not hit and r.status == 200:
            hit = canary_host in r.text and ("window.location" in r.text or "http-equiv" in r.text.lower())
        if hit:
            out.append(
                Finding(
                    key=f"open-redirect-{name}",
                    title=f"Open redirect via parameter '{name}'",
                    severity=Severity.MEDIUM,
                    category="Injection",
                    description=f"The '{name}' parameter controls where the user is sent, and it "
                    "accepts any external host. The application will happily redirect visitors "
                    "to an attacker-controlled site while the link still starts with your domain.",
                    impact="Highly effective phishing: 'https://yourdomain/login?next=evil.com' "
                    "looks trustworthy, and is also used to steal OAuth tokens and bypass "
                    "allow-lists.",
                    remediation="Accept only relative paths, or validate against an allow-list of "
                    "permitted hosts before redirecting. Reject values containing '://' and '//'.",
                    evidence=[f"GET {url}", f"Location: {loc}"],
                    cwe="CWE-601",
                    owasp="A01:2021 Broken Access Control",
                    effort="quick",
                    cvss=6.1,
                    location=page_url,
                )
            )
    return out


# -------------------------------------------------------------- traversal
def _traversal(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    for page_url, name, value in params[:20]:
        if not re.search(r"(file|path|page|doc|img|image|download|template|view|load|include|url)", name, re.I):
            continue
        for payload in TRAVERSAL_PAYLOADS:
            url = inject_param(page_url, name, payload)
            r = ctx.http.get(url, allow_redirects=True)
            if r.error or not r.status:
                continue
            if UNIX_PASSWD.search(r.text):
                out.append(
                    Finding(
                        key=f"path-traversal-{name}",
                        title=f"Path traversal / local file inclusion in '{name}'",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        description="A relative path payload caused the server to return the "
                        "contents of /etc/passwd. The parameter is used to build a filesystem "
                        "path without validation or confinement to a base directory.",
                        impact="Read of arbitrary server files - configuration, private keys, "
                        "database credentials - and often escalation to remote code execution "
                        "by including a file the attacker can upload.",
                        remediation="Never pass user input to file APIs. Resolve the path and "
                        "verify it stays inside the allowed directory:\n"
                        "real = os.path.realpath(os.path.join(BASE, name))\n"
                        "if not real.startswith(BASE + os.sep): abort(400)\n"
                        "Better: map an opaque ID to a stored path instead of accepting names.",
                        evidence=[f"GET {url}", "Response contained 'root:x:0:0:'"],
                        cwe="CWE-22",
                        owasp="A01:2021 Broken Access Control",
                        effort="involved",
                        cvss=9.1,
                        location=page_url,
                    )
                )
                return out
            if WIN_INI.search(r.text):
                out.append(
                    Finding(
                        key=f"path-traversal-{name}",
                        title=f"Path traversal / local file inclusion in '{name}'",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        description="A relative path payload returned the Windows win.ini file, "
                        "proving the parameter controls a filesystem path directly.",
                        impact="Arbitrary file read on the server.",
                        remediation="Confine file access to a base directory and validate the "
                        "resolved real path.",
                        evidence=[f"GET {url}", "Response contained win.ini sections"],
                        cwe="CWE-22",
                        owasp="A01:2021 Broken Access Control",
                        effort="involved",
                        cvss=9.1,
                        location=page_url,
                    )
                )
                return out
    return out


# ------------------------------------------------------------------- SSTI
def _ssti(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    a, b = random.randint(1000, 9999), random.randint(100, 999)
    expected = str(a * b)
    for page_url, name, value in params[:20]:
        base = ctx.http.get(page_url, allow_redirects=True)
        if base.error or expected in base.text:
            continue
        for payload in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"<%= {a}*{b} %>"):
            url = inject_param(page_url, name, payload)
            r = ctx.http.get(url, allow_redirects=True)
            if r.error or not r.status:
                continue
            if expected in r.text and expected not in base.text:
                out.append(
                    Finding(
                        key=f"ssti-{name}",
                        title=f"Server-side template injection in '{name}'",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        description=f"A template expression was evaluated server-side: the "
                        f"payload {payload} was rendered as {expected}. User input is being "
                        "compiled as template code.",
                        impact="Depending on the template engine this escalates to arbitrary "
                        "command execution on the server - typically full infrastructure "
                        "compromise.",
                        remediation="Never render user input as a template. Pass it as a "
                        "variable, and use logic-less templates or sandboxed rendering.",
                        evidence=[f"GET {url}", f"{payload} -> {expected}"],
                        cwe="CWE-94",
                        owasp="A03:2021 Injection",
                        effort="involved",
                        cvss=9.8,
                        location=page_url,
                    )
                )
                return out
    return out


# ------------------------------------------------------------------- CRLF
def _crlf(ctx: ScanContext, params) -> List[Finding]:
    out: List[Finding] = []
    marker = "Sentwall-Canary"
    for page_url, name, value in params[:20]:
        payload = f"%0d%0a{marker}%3a%201"
        url = inject_param(page_url, name, payload)
        r = ctx.http.get(url, allow_redirects=False)
        if r.error or not r.status:
            continue
        if any(k.lower() == marker.lower() for k in r.headers):
            out.append(
                Finding(
                    key=f"crlf-{name}",
                    title=f"HTTP response splitting / header injection in '{name}'",
                    severity=Severity.HIGH,
                    category="Injection",
                    description="A CRLF sequence in the parameter produced an extra HTTP header "
                    "in the response. Input is being written into response headers without "
                    "sanitisation.",
                    impact="Response splitting enables cache poisoning, cookie injection and "
                    "cross-user script injection through a single crafted link.",
                    remediation="Strip CR/LF from any value used in a header, or use the "
                    "framework's header API which rejects them. Never place user input in "
                    "Location/Set-Cookie without validation.",
                    evidence=[f"GET {url}", f"Injected header '{marker}' observed in response"],
                    cwe="CWE-113",
                    owasp="A03:2021 Injection",
                    effort="moderate",
                    cvss=7.4,
                    location=page_url,
                )
            )
            return out
    return out


# ------------------------------------------------------------------ forms
def _form_checks(ctx: ScanContext) -> List[Finding]:
    """Very conservative form testing: text inputs only, no destructive actions."""
    out: List[Finding] = []
    canary = "vs" + _rand(8)
    tag = f"<{canary}>"
    done = 0
    for page in ctx.pages:
        for form in page.forms:
            if done >= 6:
                return out
            if form.has_file or form.has_password:
                continue
            if re.search(r"(delete|remove|logout|signout|unsubscribe|checkout|pay)", form.action, re.I):
                continue
            data = {}
            for name, itype in form.inputs:
                if itype in ("hidden", "submit", "button", "checkbox", "radio"):
                    continue
                data[name] = f"{canary}{tag}"
            if not data:
                continue
            done += 1
            if form.method == "POST":
                r = ctx.http.request("POST", form.action, data=data, allow_redirects=True)
            else:
                r = ctx.http.get(form.action, params=data, allow_redirects=True)
            if r.error or not r.status:
                continue
            if tag in r.text:
                out.append(
                    Finding(
                        key=f"xss-form-{urlparse(form.action).path}",
                        title="Reflected XSS through a form field",
                        severity=Severity.HIGH,
                        category="Injection",
                        description="Submitting a harmless HTML tag in this form's text field "
                        "caused it to be rendered back unencoded.",
                        impact="Script execution in the context of the site whenever a crafted "
                        "form submission is processed.",
                        remediation="Encode all user input on output and validate it on input.",
                        evidence=[f"{form.method} {form.action}", f"Fields: {', '.join(data)}"],
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        confidence="firm",
                        effort="moderate",
                        cvss=6.1,
                        location=form.action,
                    )
                )
    return out
