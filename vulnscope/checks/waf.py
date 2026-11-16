"""Web Application Firewall (WAF) fingerprinting and origin server IP exposure detection."""
from __future__ import annotations

import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "waf"
LABEL = "WAF & Firewall Fingerprinting & Origin IP Discovery"

WAF_SIGNATURES: List[Tuple[str, str, str]] = [
    ("Cloudflare", "cf-ray", "header"),
    ("Cloudflare", "__cf_bm", "cookie"),
    ("AWS WAF", "x-amzn-requestid", "header"),
    ("AWS CloudFront", "x-amz-cf-id", "header"),
    ("Akamai", "x-akamai-transformed", "header"),
    ("Imperva Incapsula", "x-iinfo", "header"),
    ("Imperva Incapsula", "incap_ses", "cookie"),
    ("Fastly", "fastly-debug-digest", "header"),
    ("Fastly", "x-fastly-request-id", "header"),
    ("Sucuri CloudProxy", "x-sucuri-id", "header"),
    ("F5 BIG-IP ASM", "ts", "cookie"),
    ("F5 BIG-IP Local Traffic Manager", "bigipserver", "cookie"),
    ("Fortinet FortiWeb", "fortiwafchecksum", "cookie"),
    ("ModSecurity / OWASP CRS", "mod_security", "body"),
    ("Wordfence (WordPress)", "wordfence_verifiedhuman", "cookie"),
]

ORIGIN_CANDIDATE_PREFIXES = [
    "origin",
    "direct",
    "mail",
    "cpanel",
    "webmail",
    "ftp",
    "dev",
    "staging",
    "test",
    "backend",
    "internal",
]


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_waf:
        return out

    waf_name = _fingerprint_waf(ctx)
    if waf_name:
        ctx.add_meta("waf_detected", waf_name)
        ctx.add_node(f"waf:{waf_name}", f"WAF: {waf_name}", "waf", "info", {"provider": waf_name})
        ctx.add_link(ctx.host, f"waf:{waf_name}", "protected_by")

    out += _check_origin_ip_leak(ctx, waf_name)
    return out


def _fingerprint_waf(ctx: ScanContext) -> Optional[str]:
    home = ctx.homepage()
    if not home:
        return None

    headers_lower = {k.lower(): v.lower() for k, v in home.headers.items()}
    cookie_str = headers_lower.get("set-cookie", "")

    for name, marker, sig_type in WAF_SIGNATURES:
        if sig_type == "header" and marker.lower() in headers_lower:
            return name
        if sig_type == "cookie" and marker.lower() in cookie_str:
            return name
        if sig_type == "body" and marker.lower() in home.text.lower():
            return name

    return None


def _check_origin_ip_leak(ctx: ScanContext, detected_waf: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    # If a reverse-proxy WAF (like Cloudflare) is detected, test if subdomains expose the origin IP
    if not detected_waf or detected_waf not in ("Cloudflare", "Imperva Incapsula", "Fastly", "Sucuri CloudProxy"):
        return findings

    base_domain = ctx.domain
    main_ips = set(ctx.ips())

    leaked_candidates: List[Tuple[str, str]] = []

    for prefix in ORIGIN_CANDIDATE_PREFIXES:
        sub = f"{prefix}.{base_domain}"
        try:
            resolved_ip = socket.gethostbyname(sub)
            if resolved_ip and resolved_ip not in main_ips:
                # Test if the direct IP serves the site or responds to HTTP
                leaked_candidates.append((sub, resolved_ip))
        except Exception:
            continue

    if leaked_candidates:
        sub, ip = leaked_candidates[0]
        f = Finding(
            key="origin-server-ip-leak-waf-bypass",
            title=f"Origin Server IP Leaked via Subdomain ({sub} -> {ip})",
            severity=Severity.HIGH,
            category="Network & Infrastructure Security",
            description=(
                f"While the primary domain {ctx.host} is protected behind {detected_waf}, "
                f"the subdomain {sub} resolves to direct origin IP address {ip}."
            ),
            impact=(
                f"Attackers can bypass {detected_waf} completely by sending HTTP requests directly "
                f"to the origin IP address {ip} with a Host header set to '{ctx.host}'. "
                "This renders all WAF security rules, rate limits, and DDoS mitigations useless."
            ),
            remediation=(
                "1. Route all subdomains through the proxy WAF or place the origin server on an isolated private VPC.\n"
                "2. Configure origin firewall rules (e.g. AWS Security Groups, iptables) to drop all incoming traffic "
                f"unless it originates strictly from {detected_waf}'s published IP ranges."
            ),
            evidence=[
                f"Detected WAF: {detected_waf}",
                f"Subdomain: {sub}",
                f"Direct Origin IP: {ip}",
                f"Main Domain IPs (Proxy): {', '.join(main_ips)}",
            ],
            references=[
                "https://www.cloudflare.com/learning/security/glossary/origin-ip-leak/",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            cwe="CWE-200",
            owasp="A05:2021-Security Misconfiguration",
            confidence="firm",
            effort="quick",
            cvss=7.5,
            location=f"{sub} ({ip})",
            title_bn=f"সাবডোমেইনের মাধ্যমে মূল সার্ভারের আসল IP ফাঁস ({sub} -> {ip})",
            description_bn=(
                f"মূল সাইট {detected_waf} ফায়ারওয়ালের আড়ালে থাকলেও সাবডোমেইন {sub} "
                f"সরাসরি মেইন সার্ভারের রিয়েল আইপি {ip} ফাঁস করে দিচ্ছে।"
            ),
            impact_bn=(
                "হ্যাকাররা সরাসরি এই আসল আইপিতে রিকোয়েস্ট পাঠিয়ে ক্লাউডফ্লেয়ার বা ওয়্যাফের "
                "সব বাধা ও অ্যান্টি-ডিডস নিরাপত্তা বাইপাস করে ফেলতে পারবে।"
            ),
            fix_patches={
                "nginx": f"# Restrict origin to Cloudflare IPs only:\nset_real_ip_from 173.245.48.0/20;\nset_real_ip_from 103.21.244.0/22;\nreal_ip_header CF-Connecting-IP;\n\n# Drop all direct requests with missing CF-Ray\nif ($http_cf_ray = \"\") {{\n    return 403;\n}}",
            },
            poc_curl_template=f"curl -H 'Host: {ctx.host}' 'http://{ip}/'",
        )
        findings.append(f)
        ctx.add_node(f"ip:{ip}", f"Origin IP: {ip}", "ip", "high", {"leaked_by": sub})
        ctx.add_link(sub, f"ip:{ip}", "points_to")

    return findings
