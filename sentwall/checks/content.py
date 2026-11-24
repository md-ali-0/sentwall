"""Content-level issues: mixed content, leaked secrets, SRI, comments, tabnabbing."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "content"
LABEL = "Page content, secrets in JavaScript & third-party assets"

SECRET_PATTERNS: List[Tuple[str, str, Severity, str]] = [
    ("AWS access key ID", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL,
     "An AWS access key ID is embedded in client-side code."),
    ("AWS secret access key", r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]([0-9a-zA-Z/+=]{40})['\"]",
     Severity.CRITICAL, "An AWS secret key appears in client-side code."),
    ("Stripe live secret key", r"sk_live_[0-9a-zA-Z]{20,}", Severity.CRITICAL,
     "A live Stripe secret key is exposed to every visitor."),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{30,}", Severity.CRITICAL,
     "A GitHub access token is exposed in the page source."),
    ("Slack token", r"xox[baprs]-[0-9a-zA-Z-]{10,}", Severity.CRITICAL,
     "A Slack API token is exposed in client-side code."),
    ("SendGrid API key", r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", Severity.CRITICAL,
     "A SendGrid API key is exposed, allowing mail sending as your domain."),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", Severity.CRITICAL,
     "A private key is embedded in a public file."),
    ("OpenAI API key", r"sk-[A-Za-z0-9]{32,}", Severity.HIGH,
     "An API key with the OpenAI format is exposed in client-side code."),
    ("Twilio API key", r"\bSK[0-9a-f]{32}\b", Severity.HIGH,
     "A Twilio API key is exposed in client-side code."),
    ("Google / Firebase API key", r"AIza[0-9A-Za-z\-_]{35}", Severity.MEDIUM,
     "A Google API key is exposed. These are often public by design, but must be restricted "
     "by HTTP referrer and API scope or they can be abused on your quota."),
    ("Hardcoded credential in JavaScript", r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
     Severity.HIGH, "A hardcoded password or secret literal is present in client-side code."),
    ("JSON Web Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     Severity.INFO, "A JWT literal appears in the page source. Verify it is a public/demo token "
     "and not a valid session token."),
]

_SENSITIVE_COMMENT = re.compile(
    r"(?i)(password|passwd|secret|api[_ -]?key|token|todo|fixme|hack|internal|staging|dev only|"
    r"backdoor|debug|admin:|username)"
)
_IP_RE = re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    home = ctx.homepage()
    if not home:
        return out
    out += _mixed_content(ctx, home)
    out += _leaked_secrets(ctx, home)
    out += _sri(ctx, home)
    out += _comments(ctx, home)
    out += _tabnabbing(ctx, home)
    out += _autocomplete(ctx)
    return out


def _mixed_content(ctx: ScanContext, home) -> List[Finding]:
    if not home.url.startswith("https://"):
        return []
    urls = sorted(set(home.mixed_content))[:6]
    if not urls:
        return []
    return [
        Finding(
            key="mixed-content",
            title="Page loads insecure HTTP resources over HTTPS",
            severity=Severity.MEDIUM,
            category="Encryption",
            description="The page is served over HTTPS but pulls scripts, styles or images over "
            "plain HTTP. Browsers block active mixed content, so parts of the page break - and "
            "where it is not blocked, an attacker on the network can modify the resource.",
            impact="Broken functionality, a broken padlock icon, and a path for injecting "
            "script into an otherwise secure page.",
            remediation="Serve every asset over HTTPS (protocol-relative // or explicit https://), "
            "then add Content-Security-Policy: upgrade-insecure-requests.",
            evidence=[f"Insecure resource: {u}" for u in urls],
            cwe="CWE-311",
            owasp="A02:2021 Cryptographic Failures",
            effort="quick",
            cvss=4.3,
            location=home.url,
        )
    ]


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return secret[:2] + "*" * 6
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _leaked_secrets(ctx: ScanContext, home) -> List[Finding]:
    out: List[Finding] = []
    blobs: List[Tuple[str, str]] = [(home.url, home.text)]

    scripts = [s for s in home.scripts if urlparse(s).hostname][:8]
    for src in scripts:
        r = ctx.http.get(src, allow_redirects=True, limit=400000)
        if r.status == 200 and r.text:
            blobs.append((src, r.text))

    seen = set()
    for source, text in blobs:
        for label, pattern, severity, desc in SECRET_PATTERNS:
            m = re.search(pattern, text)
            if not m:
                continue
            if label in seen:
                continue
            seen.add(label)
            raw = m.group(1) if m.groups() else m.group(0)
            out.append(
                Finding(
                    key=f"secret-{label.lower().replace(' ', '-')}",
                    title=f"{label} exposed in client-side code",
                    severity=severity,
                    category="Information Disclosure",
                    description=desc + f" Found in {source}.",
                    impact=(
                        "Anyone can copy this value from the browser and use it directly against "
                        "the provider - reading or deleting data, sending mail as your domain, or "
                        "running up your bill."
                        if severity in (Severity.CRITICAL, Severity.HIGH)
                        else "Potential unauthorised API usage against your quota."
                    ),
                    remediation="Remove the secret from client-side code and proxy the call "
                    "through your backend. Rotate the exposed credential immediately - assume "
                    "it is already compromised. Store secrets in environment variables or a "
                    "secrets manager, and add a pre-commit secret scanner.",
                    evidence=[f"Source: {source}", f"Match: {_mask(raw)}"],
                    cwe="CWE-798",
                    owasp="A02:2021 Cryptographic Failures",
                    confidence="firm" if severity is not Severity.INFO else "tentative",
                    effort="moderate",
                    cvss=9.1 if severity is Severity.CRITICAL else 6.5,
                    location=source,
                )
            )
    return out


def _sri(ctx: ScanContext, home) -> List[Finding]:
    external = [
        s for s in home.scripts
        if urlparse(s).hostname and (urlparse(s).hostname or "") not in (urlparse(home.url).hostname or "")
    ]
    if not external:
        return []
    # crude SRI detection: script tags with integrity=
    without = len(re.findall(r"<script[^>]+src=[\"']https?://", home.text, re.I)) - len(
        re.findall(r"<script[^>]+integrity=", home.text, re.I)
    )
    if without <= 0:
        return []
    return [
        Finding(
            key="missing-sri",
            title="Third-party scripts loaded without Subresource Integrity",
            severity=Severity.LOW,
            category="Supply Chain",
            description=f"{without} script tag(s) load code from an external host without an "
            "integrity hash. If that CDN or vendor is compromised, the modified script runs "
            "with full access to your users' sessions.",
            impact="One compromised third-party host becomes a compromise of your site.",
            remediation='Add integrity and crossorigin attributes:\n'
            '<script src="https://cdn.example/lib.js" integrity="sha384-..." '
            'crossorigin="anonymous"></script>',
            evidence=[f"External scripts: {len(external)}", f"Without integrity: {without}"],
            cwe="CWE-353",
            owasp="A08:2021 Software and Data Integrity Failures",
            effort="quick",
            cvss=3.7,
            location=home.url,
        )
    ]


def _comments(ctx: ScanContext, home) -> List[Finding]:
    hits = [c for c in home.comments if _SENSITIVE_COMMENT.search(c)]
    if not hits:
        return []
    return [
        Finding(
            key="sensitive-comments",
            title="HTML comments reveal internal information",
            severity=Severity.LOW,
            category="Information Disclosure",
            description="Developer comments are shipped to production. They often contain "
            "credentials, internal hostnames, TODO notes about unpatched areas, or hints about "
            "hidden admin paths.",
            impact="Free reconnaissance for an attacker, sometimes including direct credentials.",
            remediation="Strip comments in the build step (HTML minification does this "
            "automatically) and review what is deployed.",
            evidence=[f"<!-- {c[:160]} -->" for c in hits[:3]],
            cwe="CWE-615",
            owasp="A05:2021 Security Misconfiguration",
            effort="quick",
            cvss=3.1,
            location=home.url,
        )
    ]


def _tabnabbing(ctx: ScanContext, home) -> List[Finding]:
    links = home.blank_links_noopener
    if not links:
        return []
    return [
        Finding(
            key="tabnabbing",
            title="External links open with target=_blank but no rel=noopener",
            severity=Severity.LOW,
            category="Client-Side",
            description="A link opened in a new tab keeps a reference to your page through "
            "window.opener. The destination site can use it to redirect the original tab to a "
            "phishing page.",
            impact="Users who return to the original tab land on an attacker-controlled clone.",
            remediation='Add rel="noopener noreferrer" to every target="_blank" link, or set it '
            "globally in the framework.",
            evidence=[f"href={l}" for l in links[:3]],
            cwe="CWE-1022",
            owasp="A05:2021 Security Misconfiguration",
            effort="quick",
            cvss=3.1,
            location=home.url,
        )
    ]


def _autocomplete(ctx: ScanContext) -> List[Finding]:
    for page in ctx.pages:
        for form in page.password_forms:
            if "autocomplete" not in page.text.lower():
                return [
                    Finding(
                        key="password-autocomplete",
                        title="Password field allows browser autocomplete",
                        severity=Severity.INFO,
                        category="Client-Side",
                        description="The login form does not set autocomplete=\"off\" or a "
                        "credential-manager hint. On shared devices this can leave credentials "
                        "stored in the browser.",
                        impact="Minor credential exposure on shared computers.",
                        remediation='Use autocomplete="current-password" on login and '
                        '"new-password" on registration so password managers behave correctly, '
                        'and avoid autocomplete="off" on login (it breaks managers).',
                        evidence=[f"Form action: {form.action}"],
                        cwe="CWE-522",
                        owasp="A07:2021 Identification and Authentication Failures",
                        effort="quick",
                        cvss=0.0,
                        location=page.url,
                    )
                ]
    return []
