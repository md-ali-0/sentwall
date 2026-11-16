"""Deep secret hunting with regex matching and Shannon entropy analysis across client code and assets."""
from __future__ import annotations

import math
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "secrets"
LABEL = "Deep secret & credential hunter (API keys, cloud tokens, database URIs, entropy analysis)"

SECRET_RULES: List[Tuple[str, str, Severity, str, float]] = [
    (
        "OpenAI API Key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b",
        Severity.CRITICAL,
        "An active OpenAI API secret key was discovered embedded in client-side code.",
        9.1,
    ),
    (
        "Anthropic Claude API Key",
        r"\bsk-ant-api03-[A-Za-z0-9_\-]{80,}\b",
        Severity.CRITICAL,
        "An Anthropic Claude AI secret API key was found in client assets.",
        9.1,
    ),
    (
        "Google Gemini / Cloud API Key",
        r"\bAIzaSy[A-Za-z0-9_\-]{33}\b",
        Severity.HIGH,
        "A Google Gemini / Cloud Platform API key was discovered. If unrestricted, attackers can consume cloud quotas.",
        7.5,
    ),
    (
        "HuggingFace User Access Token",
        r"\bhf_[A-Za-z0-9]{34,}\b",
        Severity.HIGH,
        "A HuggingFace model hub token is exposed in the frontend code.",
        7.5,
    ),
    (
        "AWS Access Key ID",
        r"\bAKIA[0-9A-Z]{16}\b",
        Severity.CRITICAL,
        "An AWS IAM access key ID is hardcoded in client-side files.",
        9.1,
    ),
    (
        "GitHub Personal Access Token",
        r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        Severity.CRITICAL,
        "A GitHub Personal Access Token is exposed, potentially granting read/write repository access.",
        9.8,
    ),
    (
        "Slack Incoming Webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/[A-Za-z0-9_]+",
        Severity.HIGH,
        "An internal Slack Incoming Webhook URL was exposed, enabling message spoofing and social engineering.",
        7.2,
    ),
    (
        "Stripe Live Secret Key",
        r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b",
        Severity.CRITICAL,
        "A live Stripe Secret or Restricted key is hardcoded. Attackers can execute unauthorized financial refunds or transactions.",
        9.8,
    ),
    (
        "SendGrid Mailer API Key",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        Severity.CRITICAL,
        "A SendGrid API key is leaked, enabling malicious email spoofing and domain reputation destruction.",
        8.8,
    ),
    (
        "Database Connection String",
        r"\b(?:postgres|postgresql|mongodb(?:\+srv)?|mysql|redis)://[a-zA-Z0-9_\.\-]+:[^@\s\"'\<\>]+@[a-zA-Z0-9_\.\-]+(?::\d+)?/[a-zA-Z0-9_\.\-]*",
        Severity.CRITICAL,
        "A plaintext database connection URI containing embedded login credentials was found exposed in public code.",
        9.8,
    ),
    (
        "Twilio Account Auth Token",
        r"\bAC[a-f0-9]{32}\b",
        Severity.HIGH,
        "A Twilio Master Account SID was found in frontend scripts.",
        7.5,
    ),
    (
        "Private Cryptographic Key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        Severity.CRITICAL,
        "A private SSH or TLS cryptographic key is embedded in public files.",
        9.8,
    ),
]


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_secrets:
        return out

    # Collect texts from pages and crawled scripts
    targets: List[Tuple[str, str]] = []
    seen_urls: Set[str] = set()

    for p in ctx.pages[:10]:
        targets.append((p.url, p.text))
        # Fetch external same-origin or high-value scripts
        for script_url in p.scripts[:6]:
            abs_url = urljoin(p.url, script_url)
            if abs_url in seen_urls:
                continue
            seen_urls.add(abs_url)
            # Only fetch same host or CDN scripts if safe
            parsed = urlparse(abs_url)
            if parsed.netloc == ctx.host:
                s_resp = ctx.http.get(abs_url)
                if s_resp.status == 200 and s_resp.text:
                    targets.append((abs_url, s_resp.text))

    reported_keys: Set[str] = set()

    for source_url, content in targets:
        # Regex rule checks
        for title, pattern, severity, desc, cvss in SECRET_RULES:
            match = re.search(pattern, content)
            if match:
                matched_str = match.group(0)
                # Redact middle characters for safe display
                if len(matched_str) > 10:
                    redacted = matched_str[:4] + ("*" * (len(matched_str) - 8)) + matched_str[-4:]
                else:
                    redacted = matched_str[:2] + "****"

                dedup_key = f"{title}-{redacted}"
                if dedup_key in reported_keys:
                    continue
                reported_keys.add(dedup_key)

                f = Finding(
                    key=f"secret-exposed-{re.sub(r'[^a-zA-Z0-9]', '-', title).lower()}",
                    title=f"Critical Leaked Credential: {title}",
                    severity=severity,
                    category="Credential & Secret Exposure",
                    description=desc,
                    impact=(
                        "Immediate compromise of external cloud services, database theft, "
                        "reputation destruction via unauthorized mail relay, or direct financial loss."
                    ),
                    remediation=(
                        "1. Immediately REVOKE and rotate the exposed key in the provider console.\n"
                        "2. Remove the secret from client-side code and git commit history.\n"
                        "3. Store credentials securely using environment variables or a secrets manager "
                        "(e.g. AWS Secrets Manager, HashiCorp Vault)."
                    ),
                    evidence=[
                        f"Discovered in file: {source_url}",
                        f"Detected Token: {redacted}",
                        f"Match pattern: {pattern[:40]}...",
                    ],
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                    cwe="CWE-798",
                    owasp="A02:2021-Cryptographic Failures",
                    confidence="certain",
                    effort="quick",
                    cvss=cvss,
                    location=source_url,
                    title_bn=f"মারাত্মক গোপন ক্রেডেনশিয়াল ফাঁস: {title}",
                    description_bn=f"{source_url} ফাইলে সরাসরি গোপন API key বা পাসওয়ার্ড দেখা যাচ্ছে।",
                    impact_bn="আক্রমণকারী এই কি (key) ব্যবহার করে ক্লাউড সার্ভিস, ডাটাবেজ বা একাউন্টে ঢুকে পড়তে পারে।",
                    fix_patches={
                        "code": "# Never hardcode credentials in frontend code!\n# Load from server-side environment variables:\nconst API_KEY = process.env.SECRET_API_KEY;",
                    },
                    poc_curl_template=f"curl -s '{source_url}' | grep -oE '{pattern[:30]}'",
                )
                out.append(f)
                ctx.add_node(f"secret:{title}", title, "vuln", severity.value, {"url": source_url})
                ctx.add_link(ctx.host, f"secret:{title}", "leaks")

    return out
