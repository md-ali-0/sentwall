"""Advanced SSRF, Client-Side Prototype Pollution, and Web Cache Deception probes."""
from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ..context import ScanContext
from ..crawl import collect_params, inject_param
from ..models import Finding, Severity

NAME = "ssrf_traversal"
LABEL = "Advanced injection & logic flaws (SSRF, Prototype Pollution, Cache Deception)"

SSRF_PARAM_NAMES = {
    "url", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
    "target", "feed", "proxy", "webhook", "fetch", "link", "load", "uri", "source", "site"
}

CLOUD_METADATA_SIGNATURES = [
    (r"ami-[a-z0-9]{8,}", "AWS EC2 Metadata"),
    (r"instance-id", "AWS EC2 Metadata"),
    (r"computeMetadata", "Google Cloud Metadata"),
    (r"Metadata-Flavor", "Google Cloud Metadata"),
]


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_ssrf:
        return out

    params = collect_params(ctx.pages)
    out += _check_ssrf(ctx, params)
    out += _check_prototype_pollution(ctx)
    out += _check_cache_deception(ctx)
    return out


def _check_ssrf(ctx: ScanContext, params) -> List[Finding]:
    findings: List[Finding] = []
    tested: Set[str] = set()

    # Target parameters matching SSRF indicators
    for base_url, method, name, sample_val in params:
        if name.lower() not in SSRF_PARAM_NAMES:
            continue
        key = f"{base_url}|{name}"
        if key in tested:
            continue
        tested.add(key)

        # Non-destructive cloud metadata probe
        target_payload = "http://169.254.169.254/latest/meta-data/"
        probe_url = inject_param(base_url, name, target_payload)

        resp = ctx.http.get(probe_url)
        for rx_pattern, cloud_provider in CLOUD_METADATA_SIGNATURES:
            if re.search(rx_pattern, resp.text, re.I):
                f = Finding(
                    key=f"ssrf-cloud-metadata-{name}",
                    title=f"Critical Server-Side Request Forgery (SSRF) via '{name}'",
                    severity=Severity.CRITICAL,
                    category="Injection & Logic Flaws",
                    description=(
                        f"The parameter '{name}' on {base_url} is vulnerable to Server-Side Request Forgery. "
                        f"The server fetched and returned {cloud_provider} content when supplied with 169.254.169.254."
                    ),
                    impact=(
                        "An external attacker can extract IAM instance profile credentials, cloud IAM keys, "
                        "and pivot into private internal network infrastructure, completely bypassing external firewalls."
                    ),
                    remediation=(
                        "1. Avoid letting users specify arbitrary URLs to be fetched by the server.\n"
                        "2. Enforce a strict domain allowlist if fetching external resources is required.\n"
                        "3. Block access to private and link-local IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, "
                        "192.168.0.0/16, 169.254.169.254) at the application and network firewall layer."
                    ),
                    evidence=[
                        f"Vulnerable URL: {probe_url}",
                        f"Parameter: {name}",
                        f"Extracted Metadata Signature: {rx_pattern}",
                    ],
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/918.html",
                    ],
                    cwe="CWE-918",
                    owasp="A10:2021-Server-Side Request Forgery",
                    confidence="certain",
                    effort="moderate",
                    cvss=9.8,
                    location=probe_url,
                    title_bn=f"মারাত্মক Server-Side Request Forgery (SSRF) ত্রুটি ('{name}' প্যারামিটারে)",
                    description_bn=f"সার্ভারকে নির্দেশ দিয়ে ইন্টারনাল ক্লাউড মেটাডাটা বা ইন্টারনাল নেটওয়ার্কের গোপন ফাইল হাতিয়ে নেওয়া সম্ভব।",
                    impact_bn="ক্লাউডের রুট IAM কি (key) চুরি করে হ্যাকার পুরো এডাব্লিউএস/গুগল ক্লাউড অ্যাকাউন্ট দখল করতে পারে।",
                    fix_patches={
                        "code": "# Validate URL against strict whitelist\nimport ipaddress\nfrom urllib.parse import urlparse\n\ndef safe_url(url):\n    parsed = urlparse(url)\n    # Prevent private IPs\n    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n    if ip.is_private or ip.is_loopback or ip.is_link_local:\n        raise ValueError('Forbidden IP')",
                    },
                    poc_curl_template=f"curl -s '{probe_url}'",
                )
                findings.append(f)
                break

    return findings


def _check_prototype_pollution(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    if not ctx.pages:
        return findings

    target_url = ctx.pages[0].url
    canary = "vulnscope_proto_check"
    pollution_payload = f"__proto__[{canary}]=polluted&constructor.prototype.{canary}=polluted"

    parsed = urlparse(target_url)
    sep = "&" if parsed.query else ""
    test_query = f"{parsed.query}{sep}{pollution_payload}" if parsed.query else pollution_payload
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

    resp = ctx.http.get(test_url)
    if resp.status == 200 and canary in resp.text:
        # Check if reflected in a script block or JSON payload
        if re.search(rf'[\"\']?{canary}[\"\']?\s*[:=]', resp.text):
            f = Finding(
                key="client-side-prototype-pollution",
                title="Client-Side Prototype Pollution via URL Parameters",
                severity=Severity.HIGH,
                category="Injection & Logic Flaws",
                description=(
                    f"The web application reflects or parses `__proto__` properties on {target_url}. "
                    "This allows attackers to pollute the global JavaScript Object prototype."
                ),
                impact=(
                    "Can be chained with gadget functions to achieve DOM-based Cross-Site Scripting (XSS) "
                    "or bypass security logic."
                ),
                remediation=(
                    "Freeze the JavaScript Object prototype using `Object.freeze(Object.prototype)` or sanitize "
                    "query string parsing libraries to drop `__proto__` and `constructor` keys."
                ),
                evidence=[f"URL: {test_url}", "Parameter parsed into global prototype context"],
                references=[
                    "https://portswigger.net/web-security/prototype-pollution",
                    "https://cwe.mitre.org/data/definitions/1321.html",
                ],
                cwe="CWE-1321",
                owasp="A03:2021-Injection",
                confidence="firm",
                effort="moderate",
                cvss=7.5,
                location=test_url,
                title_bn="ক্লায়েন্ট-সাইড Prototype Pollution ত্রুটি",
                description_bn="ইউআরএল প্যারামিটার দিয়ে জাভাস্ক্রিপ্ট অবজেক্ট প্রোটোটাইপ পরিবর্তন করা সম্ভব।",
                impact_bn="প্রোটোটাইপ পলিউশন ব্যবহার করে যেকোনো ইউজারের ব্রাউজারে ক্ষতিকর জাভাস্ক্রিপ্ট চালানো যায়।",
            )
            findings.append(f)

    return findings


def _check_cache_deception(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    # Test path confusion with static extension
    test_path = urljoin(ctx.base_url, "/nonexistent_test_probe_123.css")
    resp = ctx.http.get(test_path)

    # Check if a 200 is returned with text/html or Cache-Control public
    if resp.status == 200 and "text/html" in resp.headers.get("content-type", "").lower():
        cache_hdr = resp.headers.get("cache-control", "").lower()
        if "public" in cache_hdr or ("no-cache" not in cache_hdr and "private" not in cache_hdr):
            f = Finding(
                key="web-cache-deception-path-confusion",
                title="Potential Web Cache Deception via Path Extension Confusion",
                severity=Severity.MEDIUM,
                category="Misconfiguration & Caching",
                description=(
                    f"Requesting a dynamic endpoint with a static `.css` extension at {test_path} "
                    "returned HTML content without explicit `private` or `no-store` cache directives."
                ),
                impact=(
                    "If authenticated user pages can be appended with `.css` and cached by intermediate CDNs, "
                    "an attacker can steal sensitive session state or CSRF tokens by tricking users into visiting the link."
                ),
                remediation=(
                    "Configure the web server and CDN to always respect `Cache-Control: no-store, private` "
                    "for dynamic endpoints, and do not rely solely on file extensions for caching decisions."
                ),
                evidence=[
                    f"Probed URL: {test_path}",
                    f"Content-Type: {resp.headers.get('content-type')}",
                    f"Cache-Control: {resp.headers.get('cache-control', 'None')}",
                ],
                references=[
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                    "https://cwe.mitre.org/data/definitions/524.html",
                ],
                cwe="CWE-524",
                owasp="A05:2021-Security Misconfiguration",
                confidence="firm",
                effort="moderate",
                cvss=5.3,
                location=test_path,
                title_bn="ওয়েব ক্যাশ ডিসেপশন ঝুঁকি (Web Cache Deception)",
                description_bn="স্ট্যাটিক এক্সটেনশন যুক্ত করে ডাইনামিক পেজের সংবেদনশীল তথ্য ক্যাশ সার্ভারে জমা করার সুযোগ রয়েছে।",
                impact_bn="অন্য ইউজারের প্রাইভেট একাউন্ট ডাটা বা সেশন টোকেন ক্যাশ থেকে ফাঁস হতে পারে।",
            )
            findings.append(f)

    return findings
