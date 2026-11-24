"""DNS hygiene: SPF, DMARC, DKIM, CAA, DNSSEC and subdomain-takeover hints."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "dns"
LABEL = "DNS, email authentication & subdomains"

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail",
    "dkim", "smtp", "mandrill", "everlytics", "cm", "protonmail",
]

TAKEOVER_FINGERPRINTS = {
    "github.io": ["there isn't a github pages site here", "404 there is no site here"],
    "herokuapp.com": ["no such app", "there's nothing here, yet"],
    "s3.amazonaws.com": ["nosuchbucket", "the specified bucket does not exist"],
    "cloudfront.net": ["bad request", "the request could not be satisfied"],
    "azurewebsites.net": ["error 404 - web app not found", "404 web site not found"],
    "trafficmanager.net": ["not found"],
    "netlify.app": ["not found - request id"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["repository not found"],
    "unbounce.com": ["the requested url was not found"],
    "readme.io": ["project doesnt exist"],
    "wordpress.com": ["doesn’t exist", "does not exist"],
    "cargo.site": ["404 not found"],
    "pantheonsite.io": ["404 unknown site"],
    "zendesk.com": ["help center closed"],
    "statuspage.io": ["better uptime", "this page is not available"],
    "ghost.io": ["domain not configured"],
    "fly.dev": ["this app is not running"],
    "vercel.app": ["deployment not found", "not_found"],
}


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    from ..net import is_ip

    if is_ip(ctx.host):
        # IP targets have no DNS zone or mail policy to assess
        return out
    domain = ctx.domain
    txt = ctx.dns(domain, "TXT")
    out += _check_spf(ctx, domain, txt)
    out += _check_dmarc(ctx, domain)
    out += _check_dkim(ctx, domain)
    out += _check_caa(ctx, domain)
    out += _check_mx(ctx, domain)
    out += _check_dnssec(ctx, domain)
    if ctx.options.subdomains:
        out += _check_subdomains(ctx, domain)
    return out


# ---------------------------------------------------------------- SPF
def _check_spf(ctx: ScanContext, domain: str, records: List[str]) -> List[Finding]:
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    ctx.add_meta("spf", spf)
    if not spf:
        return [
            Finding(
                key="spf-missing",
                title="No SPF record: anyone can send email as " + domain,
                severity=Severity.HIGH,
                category="Email Security",
                description="There is no SPF record published for this domain. Receiving mail "
                "servers therefore have no way to check whether a message claiming to come from "
                f"@{domain} was actually sent by your infrastructure.",
                impact="Attackers can send convincing phishing email from your domain - to your "
                "customers, your suppliers and your own staff - and it will pass basic checks. "
                "This damages brand trust and is a common precursor to invoice fraud.",
                remediation="Publish an SPF record listing only the servers that legitimately "
                "send mail, ending in -all:\n"
                f"{domain}. 3600 IN TXT \"v=spf1 include:_spf.yourprovider.com -all\"\n"
                "Keep the record under the 10-DNS-lookup limit.",
                evidence=[f"TXT {domain} -> no v=spf1 record"],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=7.5,
                location=f"TXT {domain}",
            )
        ]

    out: List[Finding] = []
    if len(spf) > 1:
        out.append(
            Finding(
                key="spf-multiple",
                title="Multiple SPF records published",
                severity=Severity.MEDIUM,
                category="Email Security",
                description="More than one v=spf1 record exists. Per RFC 7208 this is a permanent "
                "error (permerror), so receivers treat the result as 'none' and SPF stops "
                "protecting the domain entirely.",
                impact="SPF is effectively disabled, allowing spoofed mail through.",
                remediation="Merge the records into one valid v=spf1 string and remove the rest.",
                evidence=[f"TXT: {r[:120]}" for r in spf],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=5.3,
                location=f"TXT {domain}",
            )
        )
    record = spf[0]
    low = record.lower()

    if re.search(r"[+\s]all\b", low) or low.endswith("+all"):
        out.append(
            Finding(
                key="spf-allow-all",
                title="SPF record authorises every server on the internet (+all)",
                severity=Severity.CRITICAL,
                category="Email Security",
                description="The SPF policy ends in +all, which tells receivers that ANY server "
                "is allowed to send mail for this domain. This is the worst possible SPF "
                "configuration - it actively authorises spoofing.",
                impact="Guaranteed phishing and business-email-compromise exposure; SPF provides "
                "zero protection and may cause legitimate mail to be marked as spam.",
                remediation="Replace +all with -all (hard fail) after listing legitimate senders.",
                evidence=[record[:200]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=8.2,
                location=f"TXT {domain}",
            )
        )
    elif "?all" in low:
        out.append(
            Finding(
                key="spf-neutral-all",
                title="SPF policy is neutral (?all) - no enforcement",
                severity=Severity.MEDIUM,
                category="Email Security",
                description="A neutral qualifier tells receivers 'I have no opinion', so SPF "
                "results are never used to reject spoofed mail.",
                impact="Domain spoofing remains possible for phishing campaigns.",
                remediation="Move to -all once all legitimate senders are covered by the record.",
                evidence=[record[:200]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=5.3,
                location=f"TXT {domain}",
            )
        )
    elif "~all" in low:
        out.append(
            Finding(
                key="spf-softfail",
                title="SPF ends in softfail (~all) rather than hard fail",
                severity=Severity.LOW,
                category="Email Security",
                description="Softfail marks unauthorised mail as suspicious but does not reject it. "
                "Many receivers still deliver it, often to the spam folder rather than the bin.",
                impact="Spoofed messages can still reach inboxes.",
                remediation="Once monitoring shows no legitimate mail failing, switch ~all to -all.",
                evidence=[record[:200]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=3.7,
                location=f"TXT {domain}",
            )
        )

    lookups = len(re.findall(r"\b(include:|a:|mx:|ptr|exists:|redirect=)", low))
    if lookups > 10:
        out.append(
            Finding(
                key="spf-lookup-limit",
                title=f"SPF record exceeds the DNS lookup limit ({lookups} mechanisms)",
                severity=Severity.MEDIUM,
                category="Email Security",
                description="SPF allows at most 10 DNS lookups. Beyond that, receivers return "
                "permerror and stop evaluating the policy.",
                impact="Legitimate mail may be rejected while spoofed mail bypasses checks.",
                remediation="Flatten includes, remove unused mechanisms, or use a hosted SPF "
                "macro service.",
                evidence=[record[:200], f"Estimated lookups: {lookups}"],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="moderate",
                cvss=4.3,
                location=f"TXT {domain}",
            )
        )
    if "ptr" in low.split():
        out.append(
            Finding(
                key="spf-ptr",
                title="SPF uses the deprecated 'ptr' mechanism",
                severity=Severity.INFO,
                category="Email Security",
                description="The ptr mechanism is deprecated by RFC 7208, is slow, and counts "
                "against the lookup limit.",
                impact="Slower SPF evaluation with no security benefit.",
                remediation="Replace ptr with explicit a:/ip4: entries.",
                evidence=[record[:200]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=0.0,
                location=f"TXT {domain}",
            )
        )
    return out


# ---------------------------------------------------------------- DMARC
def _check_dmarc(ctx: ScanContext, domain: str) -> List[Finding]:
    records = [r for r in ctx.dns(f"_dmarc.{domain}", "TXT") if r.lower().startswith("v=dmarc1")]
    ctx.add_meta("dmarc", records)
    if not records:
        return [
            Finding(
                key="dmarc-missing",
                title="No DMARC record: spoofed email is not blocked",
                severity=Severity.HIGH,
                category="Email Security",
                description="No DMARC policy is published at _dmarc." + domain + ". DMARC is what "
                "actually tells receivers to reject mail that fails SPF/DKIM alignment - without "
                "it, even a perfect SPF record only adds a 'suspicious' label.",
                impact="Phishing emails impersonating your brand are delivered to customers and "
                "staff. This is the number one enabler of invoice fraud and credential phishing.",
                remediation="Publish a DMARC record, starting in monitoring mode then tightening:\n"
                f"_dmarc.{domain}. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@"
                f"{domain}; pct=100\"\n"
                "After 2-4 weeks of clean reports, move to p=quarantine then p=reject.",
                evidence=[f"TXT _dmarc.{domain} -> (no record)"],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="moderate",
                cvss=7.5,
                location=f"TXT _dmarc.{domain}",
            )
        ]

    rec = records[0]
    low = rec.lower()
    out: List[Finding] = []
    policy = "none"
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", low)
    if m:
        policy = m.group(1)

    if policy == "none":
        out.append(
            Finding(
                key="dmarc-p-none",
                title="DMARC policy is p=none (monitor only)",
                severity=Severity.MEDIUM,
                category="Email Security",
                description="DMARC is published but set to p=none, which only asks receivers to "
                "report failures. No spoofed message is quarantined or rejected.",
                impact="The organisation sees the attacks but does not stop them; phishing still "
                "reaches inboxes.",
                remediation="Once reports are clean, change to p=quarantine (then p=reject) and "
                "add pct=100.",
                evidence=[rec[:220]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="moderate",
                cvss=5.3,
                location=f"TXT _dmarc.{domain}",
            )
        )
    if "rua=" not in low:
        out.append(
            Finding(
                key="dmarc-no-rua",
                title="DMARC has no aggregate reporting address",
                severity=Severity.LOW,
                category="Email Security",
                description="Without rua=, no aggregate reports are delivered, so the "
                "organisation has no visibility into who is sending mail as the domain.",
                impact="Blind to ongoing spoofing attempts and to legitimate senders that would "
                "break under a stricter policy.",
                remediation="Add rua=mailto:dmarc-reports@yourdomain (a dedicated mailbox).",
                evidence=[rec[:220]],
                cwe="CWE-778",
                owasp="A09:2021 Security Logging and Monitoring Failures",
                effort="quick",
                cvss=2.6,
                location=f"TXT _dmarc.{domain}",
            )
        )
    m = re.search(r"\bpct\s*=\s*(\d+)", low)
    if m and int(m.group(1)) < 100:
        out.append(
            Finding(
                key="dmarc-partial-pct",
                title=f"DMARC applies to only {m.group(1)}% of messages",
                severity=Severity.LOW,
                category="Email Security",
                description="pct= limits enforcement to a fraction of failing messages, so most "
                "spoofed mail is still delivered.",
                impact="Partial protection that is easy for an attacker to slip past by retrying.",
                remediation="Raise pct to 100 once the reporting data is clean.",
                evidence=[rec[:220]],
                cwe="CWE-290",
                owasp="A07:2021 Identification and Authentication Failures",
                effort="quick",
                cvss=3.1,
                location=f"TXT _dmarc.{domain}",
            )
        )
    return out


# ---------------------------------------------------------------- DKIM
def _check_dkim(ctx: ScanContext, domain: str) -> List[Finding]:
    found = []
    for sel in COMMON_DKIM_SELECTORS:
        recs = ctx.dns(f"{sel}._domainkey.{domain}", "TXT")
        for r in recs:
            if "p=" in r or "v=dkim1" in r.lower():
                found.append(sel)
                break
    ctx.add_meta("dkim_selectors", found)
    if found:
        return []
    return [
        Finding(
            key="dkim-not-detected",
            title="No DKIM key found on common selectors",
            severity=Severity.MEDIUM,
            category="Email Security",
            description="No DKIM public key was found on the standard selector names. DKIM "
            "cryptographically signs outgoing mail so receivers can verify it was not altered "
            "in transit, and it is required for DMARC alignment.",
            impact="Without DKIM, DMARC cannot reach p=reject safely, and message tampering "
            "cannot be detected.",
            remediation="Enable DKIM signing at your mail provider and publish the public key at "
            "<selector>._domainkey.yourdomain. Verify with a test message to a Gmail address "
            "and check 'dkim=pass' in the headers.",
            evidence=["Checked selectors: " + ", ".join(COMMON_DKIM_SELECTORS[:8])],
            cwe="CWE-347",
            owasp="A07:2021 Identification and Authentication Failures",
            confidence="tentative",
            effort="moderate",
            cvss=4.3,
            location=f"TXT *._domainkey.{domain}",
        )
    ]


# ---------------------------------------------------------------- CAA / MX / DNSSEC
def _check_caa(ctx: ScanContext, domain: str) -> List[Finding]:
    recs = ctx.dns(domain, "CAA")
    ctx.add_meta("caa", recs)
    if recs:
        return []
    return [
        Finding(
            key="caa-missing",
            title="No CAA record restricting certificate issuance",
            severity=Severity.LOW,
            category="Encryption",
            description="CAA records tell certificate authorities which CAs may issue for the "
            "domain. Without them, any CA can be tricked into issuing a certificate for it.",
            impact="Increases exposure to mis-issuance and CA compromise.",
            remediation='Publish a CAA record, e.g.:\n'
            f'{domain}. IN CAA 0 issue "letsencrypt.org"\n'
            f'{domain}. IN CAA 0 iodef "mailto:security@{domain}"',
            evidence=[f"CAA {domain} -> (no record)"],
            cwe="CWE-295",
            owasp="A02:2021 Cryptographic Failures",
            effort="quick",
            cvss=2.6,
            location=f"CAA {domain}",
        )
    ]


def _check_mx(ctx: ScanContext, domain: str) -> List[Finding]:
    mx = ctx.dns(domain, "MX")
    ctx.add_meta("mx", mx)
    if mx:
        return []
    return [
        Finding(
            key="no-mx",
            title="Domain has no MX record",
            severity=Severity.INFO,
            category="Email Security",
            description="No mail exchanger is configured. If the domain is used for email, "
            "messages will bounce; if it is not, consider publishing a null MX (0 .) so senders "
            "fail fast.",
            impact="Mail delivery failures, or unnecessary backscatter.",
            remediation='If email is not used: publish "MX 0 ." to declare it explicitly.',
            evidence=[f"MX {domain} -> (none)"],
            cwe="CWE-1059",
            owasp="A05:2021 Security Misconfiguration",
            effort="quick",
            cvss=0.0,
            location=f"MX {domain}",
        )
    ]


def _check_dnssec(ctx: ScanContext, domain: str) -> List[Finding]:
    keys = ctx.dns(domain, "DNSKEY")
    ctx.add_meta("dnssec", bool(keys))
    if keys:
        return []
    return [
        Finding(
            key="dnssec-missing",
            title="DNSSEC is not enabled",
            severity=Severity.INFO,
            category="DNS",
            description="The zone is not signed with DNSSEC, so DNS responses can be forged by "
            "anyone able to intercept traffic (cache poisoning, rogue Wi-Fi).",
            impact="An attacker on the network path can redirect users to a copy of the site "
            "and capture credentials.",
            remediation="Enable DNSSEC at the DNS provider and publish the DS record at the "
            "registrar. Verify with a DNSSEC-testing tool afterwards.",
            evidence=[f"DNSKEY {domain} -> (none)"],
            cwe="CWE-350",
            owasp="A02:2021 Cryptographic Failures",
            effort="moderate",
            cvss=0.0,
            location=f"DNSKEY {domain}",
        )
    ]


# ---------------------------------------------------------------- subdomains
def _crt_sh_subdomains(ctx: ScanContext, domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = ctx.http.get(url, timeout=25, limit=4_000_000)
    if not r.status or r.status != 200:
        return []
    try:
        data = json.loads(r.text)
    except Exception:
        return []
    names = set()
    for row in data:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            # crt.sh also returns subject email addresses; those are not hostnames
            if "@" in name or "*" in name or " " in name:
                continue
            if name.endswith(domain) and name != domain:
                names.add(name)
    return sorted(names)


def _check_subdomains(ctx: ScanContext, domain: str) -> List[Finding]:
    from ..net import resolve_host

    subs = _crt_sh_subdomains(ctx, domain)
    if not subs:
        return []
    ctx.add_meta("subdomains", subs[:200])
    ctx.log(f"  certificate transparency: {len(subs)} subdomains")

    def check(sub: str):
        cnames = ctx.dns(sub, "CNAME")
        if not cnames:
            return None
        target = cnames[0].rstrip(".").lower()
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            if service in target:
                r = ctx.http.get(f"http://{sub}/", allow_redirects=True, limit=20000, timeout=10)
                body = r.text.lower()
                if any(f in body for f in fingerprints):
                    return (sub, target, r.status)
        return None

    from concurrent.futures import ThreadPoolExecutor

    out: List[Finding] = []
    with ThreadPoolExecutor(max_workers=min(10, max(2, ctx.options.threads))) as ex:
        for res in ex.map(check, subs[:60]):
            if not res:
                continue
            sub, target, status = res
            out.append(
                Finding(
                    key=f"subdomain-takeover-{sub}",
                    title=f"Possible subdomain takeover: {sub}",
                    severity=Severity.HIGH,
                    category="DNS",
                    description=f"{sub} is a CNAME to {target}, but that service no longer "
                    "serves this project (the provider's 'not found' page is returned). Anyone "
                    "can register the same project name at the provider and take control of the "
                    "subdomain.",
                    impact="An attacker hosts content on your subdomain: phishing that carries "
                    "your brand, cookie stealing if the parent domain is in scope, and bypass of "
                    "CSP/allow-list rules that trust *.yourdomain.",
                    remediation=f"Either remove the dangling CNAME for {sub}, or re-claim the "
                    "project name at the provider. Then audit all CNAMEs for unclaimed targets.",
                    evidence=[f"CNAME {sub} -> {target}", f"HTTP {status} with provider 'not found' page"],
                    cwe="CWE-350",
                    owasp="A05:2021 Security Misconfiguration",
                    confidence="firm",
                    effort="quick",
                    cvss=8.1,
                    location=sub,
                )
            )
    return out
