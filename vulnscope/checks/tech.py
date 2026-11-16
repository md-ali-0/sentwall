"""Technology fingerprinting plus outdated-version / EOL heuristics."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "tech"
LABEL = "Technology fingerprint & outdated software"

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "AWS CloudFront / WAF": ["x-amz-cf-id", "x-amz-cf-pop", "awselb"],
    "Fastly": ["x-served-by", "x-fastly-request-id"],
    "Sucuri": ["x-sucuri-id", "sucuri/cloudproxy"],
    "Imperva Incapsula": ["x-iinfo", "incap_ses"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
    "Azure Front Door": ["x-azure-ref", "azurefd"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Wordfence": ["wordfence"],
}

# (name, version_regex, eol_versions, note)
SERVER_RULES = [
    ("PHP", r"PHP/(\d+\.\d+\.\d+)", lambda v: _lt(v, (8, 1)), "PHP 8.1 reached end-of-life in December 2025."),
    ("nginx", r"nginx/(\d+\.\d+\.\d+)", lambda v: _lt(v, (1, 20, 0)), "nginx releases older than 1.20 no longer receive security fixes."),
    ("Apache", r"Apache/(\d+\.\d+\.\d+)", lambda v: _lt(v, (2, 4, 55)), "Apache httpd below 2.4.55 has multiple published CVEs."),
    ("IIS", r"Microsoft-IIS/(\d+\.\d+)", lambda v: _lt(v, (10, 0)), "IIS versions below 10 ship with unsupported Windows Server releases."),
    ("OpenSSL", r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", lambda v: _lt(v, (1, 1, 1)), "OpenSSL 1.1.1 and older are end-of-life."),
]

APACHE_TRAVERSAL = {"2.4.49", "2.4.50"}


def _lt(version: str, target: Tuple[int, ...]) -> bool:
    try:
        parts = [int(x) for x in re.findall(r"\d+", version)[: len(target)]]
        while len(parts) < len(target):
            parts.append(0)
        return tuple(parts) < target
    except Exception:
        return False


def run(ctx: ScanContext) -> List[Finding]:
    home = ctx.homepage()
    if not home:
        return []
    tech = fingerprint(ctx, home)
    ctx.add_meta("technology", tech)

    out: List[Finding] = []
    out += _outdated(ctx, tech)
    out += _waf(ctx, home)
    return out


def fingerprint(ctx: ScanContext, home) -> Dict[str, str]:
    tech: Dict[str, str] = {}
    h = {k.lower(): v for k, v in home.headers.items()}
    body = home.text[:200000]
    cookies = " ".join(c.get("name", "") for c in (ctx.meta.get("cookies") or []))

    # --- servers ------------------------------------------------------------
    server = h.get("server", "")
    if server:
        tech["Server"] = server
    for name, rx, _, _ in SERVER_RULES:
        for blob in (server, h.get("x-powered-by", ""), h.get("x-aspnet-version", "")):
            m = re.search(rx, blob, re.I)
            if m:
                tech[name] = m.group(1)
                break

    # --- frameworks / CMS ---------------------------------------------------
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        gen = m.group(1)
        tech["Generator"] = gen

    if "/wp-content/" in body or "/wp-includes/" in body or "wp-json" in body:
        tech.setdefault("CMS", "WordPress")
        mv = re.search(r'content=["\']WordPress\s+([\d.]+)', gen, re.I)
        if not mv:
            mv = re.search(r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)", body)
        if mv:
            tech["WordPress"] = mv.group(1)
    elif "/sites/default/files" in body or "Drupal.settings" in body:
        tech.setdefault("CMS", "Drupal")
        mv = re.search(r'content=["\']Drupal\s+([\d.]+)', gen, re.I)
        if mv:
            tech["Drupal"] = mv.group(1)
    elif "/media/jui/" in body or "com_content" in body:
        tech.setdefault("CMS", "Joomla")
        mv = re.search(r'content=["\']Joomla!\s*([\d.]+)', gen, re.I)
        if mv:
            tech["Joomla"] = mv.group(1)
    elif "shopify" in body.lower() and "cdn.shopify.com" in body:
        tech.setdefault("CMS", "Shopify")
    elif "_next/static" in body:
        tech.setdefault("Framework", "Next.js")
    elif "__NEXT_DATA__" in body:
        tech.setdefault("Framework", "Next.js")
    elif "laravel_session" in cookies or "XSRF-TOKEN" in cookies:
        tech.setdefault("Framework", "Laravel (PHP)")
    elif "csrftoken" in cookies and "csrfmiddlewaretoken" in body:
        tech.setdefault("Framework", "Django (Python)")
    elif "ASP.NET_SessionId" in cookies:
        tech.setdefault("Framework", "ASP.NET")
    elif "JSESSIONID" in cookies:
        tech.setdefault("Framework", "Java (Servlet)")

    # --- front-end libraries ------------------------------------------------
    m = re.search(r"jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", body, re.I)
    if m:
        tech["jQuery"] = m.group(1)
    m = re.search(r"bootstrap[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.(?:css|js)", body, re.I)
    if m:
        tech["Bootstrap"] = m.group(1)
    if re.search(r"react(?:-dom)?[.-][\d.]*(?:production|development)", body, re.I) or "__REACT" in body:
        tech.setdefault("Frontend", "React")
    if "ng-version=" in body:
        tech.setdefault("Frontend", "Angular")
    if "vue.js" in body.lower() or "__vue__" in body:
        tech.setdefault("Frontend", "Vue.js")

    if not tech:
        tech["Server"] = h.get("server", "unknown")
    return tech


def _outdated(ctx: ScanContext, tech: Dict[str, str]) -> List[Finding]:
    out: List[Finding] = []

    # PHP / nginx / Apache / IIS / OpenSSL EOL
    for name, _, is_eol, note in SERVER_RULES:
        version = tech.get(name)
        if not version:
            continue
        if is_eol(version):
            out.append(
                Finding(
                    key=f"outdated-{name.lower()}",
                    title=f"End-of-life {name} {version} in production",
                    severity=Severity.HIGH,
                    category="Outdated Software",
                    description=f"The server reports {name} {version}. {note} Once a branch is "
                    "end-of-life it receives no security patches, so every newly discovered "
                    "vulnerability in it stays exploitable forever.",
                    impact="Known vulnerabilities in the runtime can be exploited at leisure; "
                    "attackers actively scan for these versions.",
                    remediation=f"Upgrade {name} to a currently supported release and put a "
                    "patch cadence in place (monthly minimum, plus out-of-band for critical "
                    "advisories). Test on staging first.",
                    evidence=[f"{name} {version} reported in response headers"],
                    cwe="CWE-1104",
                    owasp="A06:2021 Vulnerable and Outdated Components",
                    effort="involved",
                    cvss=7.5,
                    location=ctx.base_url,
                )
            )

    apache = tech.get("Apache")
    if apache in APACHE_TRAVERSAL:
        out.append(
            Finding(
                key="cve-2021-41773",
                title=f"Apache {apache} is vulnerable to CVE-2021-41773 (path traversal / RCE)",
                severity=Severity.CRITICAL,
                category="Outdated Software",
                description="This exact Apache version is affected by CVE-2021-41773 / "
                "CVE-2021-42013: a path traversal flaw in mod_proxy that allows reading files "
                "outside the document root and, with mod_cgi enabled, remote code execution.",
                impact="Unauthenticated remote code execution on the web server.",
                remediation="Upgrade to Apache 2.4.51 or later immediately. As an interim "
                "mitigation, disable mod_cgi and require 'Require all denied' on the default "
                "filesystem path.",
                evidence=[f"Server: Apache/{apache}"],
                cwe="CWE-22",
                owasp="A06:2021 Vulnerable and Outdated Components",
                effort="quick",
                cvss=9.8,
                location=ctx.base_url,
            )
        )

    jq = tech.get("jQuery")
    if jq and _lt(jq, (3, 5, 0)):
        out.append(
            Finding(
                key="outdated-jquery",
                title=f"Outdated jQuery {jq} (known XSS issues)",
                severity=Severity.MEDIUM,
                category="Outdated Software",
                description=f"jQuery {jq} predates fixes for CVE-2020-11022 / CVE-2020-11023 "
                "(XSS via htmlPrefilter) and, below 3.4.0, CVE-2019-11358 (prototype pollution "
                "in jQuery.extend).",
                impact="Untrusted HTML passed to .html()/.append() can execute script, "
                "re-enabling XSS even where the application escapes correctly.",
                remediation="Upgrade to jQuery 3.7.x and audit any .html() call that receives "
                "user data.",
                evidence=[f"jQuery {jq} referenced in page source"],
                cwe="CWE-1104",
                owasp="A06:2021 Vulnerable and Outdated Components",
                effort="quick",
                cvss=6.1,
                location=ctx.base_url,
            )
        )

    bs = tech.get("Bootstrap")
    if bs and _lt(bs, (4, 3, 1)):
        out.append(
            Finding(
                key="outdated-bootstrap",
                title=f"Outdated Bootstrap {bs}",
                severity=Severity.LOW,
                category="Outdated Software",
                description=f"Bootstrap {bs} is affected by CVE-2019-8331 (XSS in tooltip and "
                "popover data attributes).",
                impact="Script injection where tooltip/popover content is user-controlled.",
                remediation="Upgrade to Bootstrap 4.3.1+ or 5.x.",
                evidence=[f"Bootstrap {bs} referenced in page source"],
                cwe="CWE-1104",
                owasp="A06:2021 Vulnerable and Outdated Components",
                effort="moderate",
                cvss=4.3,
                location=ctx.base_url,
            )
        )

    wp = tech.get("WordPress")
    if wp and _lt(wp, (6, 0)):
        out.append(
            Finding(
                key="outdated-wordpress",
                title=f"WordPress core {wp} is behind the supported branch",
                severity=Severity.MEDIUM,
                category="Outdated Software",
                description=f"WordPress {wp} is several major releases behind. Core versions "
                "before 6.0 have accumulated publicly documented vulnerabilities, and plugins "
                "on such an installation are usually stale as well.",
                impact="Known exploit code for old core and plugin versions is freely available "
                "and mass-exploited by bots.",
                remediation="Update core, then every theme and plugin. Enable auto-updates for "
                "minor releases, remove unused plugins entirely, and keep an off-site backup "
                "before upgrading.",
                evidence=[f"WordPress {wp} detected"],
                cwe="CWE-1104",
                owasp="A06:2021 Vulnerable and Outdated Components",
                effort="moderate",
                cvss=6.5,
                location=ctx.base_url,
            )
        )
    return out


def _waf(ctx: ScanContext, home) -> List[Finding]:
    h = {k.lower(): v for k, v in home.headers.items()}
    blob = " ".join(f"{k}:{v}" for k, v in h.items()).lower()
    found = [name for name, sigs in WAF_SIGNATURES.items() if any(s in blob for s in sigs)]
    ctx.add_meta("waf", found)
    if found:
        return []
    return [
        Finding(
            key="no-waf",
            title="No web application firewall detected",
            severity=Severity.INFO,
            category="Defence in Depth",
            description="No WAF or CDN filtering layer was identified in front of the "
            "application. Nothing sits between the internet and the code to block obvious "
            "attack patterns.",
            impact="Every malicious request reaches the application directly; there is no "
            "virtual patching option when a CVE drops.",
            remediation="Consider a WAF/CDN (Cloudflare, AWS WAF, or a managed service). Treat "
            "it as defence in depth only - it never replaces fixing the underlying code.",
            evidence=["No WAF signature headers observed"],
            cwe="CWE-693",
            owasp="A05:2021 Security Misconfiguration",
            effort="moderate",
            cvss=0.0,
            location=ctx.base_url,
        )
    ]
