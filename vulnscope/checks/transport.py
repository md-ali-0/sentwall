"""Transport-layer checks: HTTPS enforcement and TLS configuration."""
from __future__ import annotations

from typing import List

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "transport"
LABEL = "Encryption in transit (TLS)"


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    host = ctx.host

    # ---------------------------------------------------------------- HTTP
    if not host.replace(".", "").isdigit():
        http_resp = ctx.http.get(f"http://{host}/", allow_redirects=False)
        if http_resp.status and http_resp.status < 400:
            body = http_resp.text.lower()
            has_login = "<input" in body and 'type="password"' in body.replace("'", '"')
            out.append(
                Finding(
                    key="no-https-redirect",
                    title="Site answers on plain HTTP without redirecting to HTTPS",
                    severity=Severity.HIGH if has_login else Severity.MEDIUM,
                    category="Encryption",
                    description=f"http://{host}/ returned HTTP {http_resp.status} instead of "
                    "redirecting to the HTTPS version. Anyone on the same network (public Wi-Fi, "
                    "ISP, hostile proxy) can read and modify the traffic in clear text.",
                    impact="Credentials, session cookies and personal data can be captured or "
                    "altered in transit. This also enables SSL-stripping attacks.",
                    remediation="Redirect all HTTP traffic to HTTPS with a 301 at the edge, and "
                    "add HSTS so browsers never attempt plain HTTP again:\n"
                    "server { listen 80; return 301 https://$host$request_uri; }",
                    evidence=[
                        f"GET http://{host}/ -> HTTP {http_resp.status}",
                        "Location: " + (http_resp.header("location") or "(none)"),
                    ],
                    cwe="CWE-319",
                    owasp="A02:2021 Cryptographic Failures",
                    effort="quick",
                    cvss=7.4 if has_login else 5.9,
                    location=f"http://{host}/",
                )
            )

    # ---------------------------------------------------------------- TLS
    tls = ctx.tls()
    ctx.add_meta("tls", {
        "protocol": tls.protocol,
        "cipher": tls.cipher,
        "issuer": tls.issuer,
        "subject": tls.subject,
        "not_before": tls.not_before,
        "not_after": tls.not_after,
        "days_left": tls.days_left,
        "san": tls.san[:20],
        "key": f"{tls.key_type} {tls.key_bits}",
        "versions": tls.versions,
        "trusted": tls.trusted,
    })

    if not tls.reachable:
        out.append(
            Finding(
                key="tls-unreachable",
                title="Could not establish a TLS connection on port 443",
                severity=Severity.HIGH,
                category="Encryption",
                description="No TLS handshake could be completed with the server on port 443. "
                "Either the site is HTTP-only, or the TLS stack is misconfigured.",
                impact="All traffic - including logins and payment data - travels unencrypted.",
                remediation="Install a valid certificate (Let's Encrypt is free) and serve the "
                "site exclusively over HTTPS.",
                evidence=[f"Error: {tls.error or 'handshake failed'}"],
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                effort="moderate",
                cvss=7.5,
            )
        )
        return out

    if not tls.trusted:
        detail = "; ".join(tls.chain_issues) or "certificate chain not trusted"
        out.append(
            Finding(
                key="tls-untrusted",
                title="TLS certificate is not trusted by browsers",
                severity=Severity.HIGH,
                category="Encryption",
                description="The certificate presented by the server does not validate against "
                "public trust stores (" + detail + "). Visitors see a full-page browser warning "
                "and most will leave; those who click through are trained to ignore warnings.",
                impact="Loss of customer trust and conversion, plus exposure to "
                "man-in-the-middle attacks since users cannot distinguish real from forged traffic.",
                remediation="Install a certificate from a trusted CA (Let's Encrypt, ZeroSSL, or "
                "commercial) and serve the complete chain including intermediates.",
                evidence=[detail, f"Subject: {tls.subject}", f"Issuer: {tls.issuer}"],
                cwe="CWE-295",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=7.4,
            )
        )

    if tls.days_left is not None:
        if tls.days_left < 0:
            out.append(
                Finding(
                    key="tls-expired",
                    title=f"TLS certificate expired {abs(tls.days_left)} days ago",
                    severity=Severity.CRITICAL,
                    category="Encryption",
                    description="The certificate passed its expiry date on " + tls.not_after + ". "
                    "Every modern browser now blocks the site behind an interstitial warning.",
                    impact="The site is effectively unusable for customers and any API client "
                    "that validates certificates will refuse to connect.",
                    remediation="Renew the certificate immediately and automate renewal "
                    "(certbot --nginx, or your CDN's managed certificate).",
                    evidence=[f"notAfter: {tls.not_after}", f"Subject: {tls.subject}"],
                    cwe="CWE-298",
                    owasp="A02:2021 Cryptographic Failures",
                    effort="quick",
                    cvss=9.1,
                )
            )
        elif tls.days_left <= 14:
            out.append(
                Finding(
                    key="tls-expiring",
                    title=f"TLS certificate expires in {tls.days_left} days",
                    severity=Severity.HIGH,
                    category="Encryption",
                    description="The certificate expires on " + tls.not_after + ". If it is not "
                    "renewed the whole site becomes unreachable for customers.",
                    impact="Imminent outage and loss of trust if renewal is missed.",
                    remediation="Renew now and set up automated renewal with monitoring "
                    "at 30/14/7 days before expiry.",
                    evidence=[f"notAfter: {tls.not_after}"],
                    cwe="CWE-298",
                    owasp="A02:2021 Cryptographic Failures",
                    effort="quick",
                    cvss=7.5,
                )
            )
        elif tls.days_left <= 30:
            out.append(
                Finding(
                    key="tls-expiring-soon",
                    title=f"TLS certificate expires in {tls.days_left} days",
                    severity=Severity.MEDIUM,
                    category="Encryption",
                    description="The certificate expires on " + tls.not_after + " and no "
                    "automated renewal appears to be in place.",
                    impact="A missed renewal will take the site offline.",
                    remediation="Renew and automate (certbot timer or managed CDN certificate).",
                    evidence=[f"notAfter: {tls.not_after}"],
                    cwe="CWE-298",
                    owasp="A02:2021 Cryptographic Failures",
                    effort="quick",
                    cvss=5.3,
                )
            )

    if tls.self_signed:
        out.append(
            Finding(
                key="tls-self-signed",
                title="Self-signed certificate in use",
                severity=Severity.HIGH,
                category="Encryption",
                description="The certificate is issued by itself rather than a trusted authority, "
                "so browsers cannot verify the server's identity.",
                impact="Visitors are trained to bypass warnings, which removes the value of HTTPS.",
                remediation="Replace with a certificate from a publicly trusted CA.",
                evidence=[f"Issuer: {tls.issuer}"],
                cwe="CWE-295",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=6.5,
            )
        )

    weak_versions = [v for v, ok in tls.versions.items() if ok and v in ("TLS 1.0", "TLS 1.1")]
    if weak_versions:
        out.append(
            Finding(
                key="tls-weak-protocol",
                title="Deprecated TLS versions accepted (" + ", ".join(weak_versions) + ")",
                severity=Severity.MEDIUM,
                category="Encryption",
                description="The server still negotiates " + ", ".join(weak_versions) + ", both "
                "deprecated by RFC 8996 and disallowed by PCI-DSS. Known weaknesses (BEAST, "
                "POODLE) apply to these protocol versions.",
                impact="Compliance failure for any payment flow, and exposure to downgrade attacks.",
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2+ (prefer 1.3):\n"
                "ssl_protocols TLSv1.2 TLSv1.3;   # nginx",
                evidence=[f"Accepted: {', '.join(weak_versions)}"],
                cwe="CWE-326",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=5.9,
            )
        )

    if tls.weak_ciphers:
        out.append(
            Finding(
                key="tls-weak-ciphers",
                title="Weak or export-grade ciphers accepted",
                severity=Severity.MEDIUM,
                category="Encryption",
                description="The server completed a handshake using legacy ciphers "
                "(3DES / RC4 / DES / NULL / EXPORT). These are broken or severely weakened "
                "and must not be negotiable.",
                impact="Traffic can be decrypted or tampered with by a well-positioned attacker.",
                remediation="Restrict to modern AEAD suites:\n"
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';",
                evidence=["Legacy cipher handshake succeeded"],
                cwe="CWE-327",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=5.3,
            )
        )

    if tls.key_bits and tls.key_type.upper().startswith("RSA") and tls.key_bits < 2048:
        out.append(
            Finding(
                key="tls-weak-key",
                title=f"RSA key is only {tls.key_bits} bits",
                severity=Severity.MEDIUM,
                category="Encryption",
                description="RSA keys below 2048 bits are considered factorable with sufficient "
                "resources and are rejected by modern clients.",
                impact="The certificate can no longer be considered a reliable identity proof.",
                remediation="Reissue the certificate with at least a 2048-bit RSA key, or move "
                "to ECDSA P-256.",
                evidence=[f"Public key: {tls.key_type} {tls.key_bits} bits"],
                cwe="CWE-326",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=5.3,
            )
        )

    if tls.sig_alg in ("sha1", "md5"):
        out.append(
            Finding(
                key="tls-weak-signature",
                title=f"Certificate signed with {tls.sig_alg.upper()}",
                severity=Severity.MEDIUM,
                category="Encryption",
                description="SHA-1/MD5 signatures are collision-prone and rejected by current "
                "browsers and operating systems.",
                impact="Certificate may be rejected by modern clients.",
                remediation="Reissue the certificate with a SHA-256 (or stronger) signature.",
                evidence=[f"Signature algorithm: {tls.sig_alg}"],
                cwe="CWE-327",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=5.3,
            )
        )

    if tls.versions and not tls.versions.get("TLS 1.3") and tls.versions.get("TLS 1.2"):
        out.append(
            Finding(
                key="tls-no-13",
                title="TLS 1.3 is not enabled",
                severity=Severity.INFO,
                category="Encryption",
                description="The server only supports up to TLS 1.2. TLS 1.3 removes legacy "
                "cipher suites, cuts a round trip from the handshake and provides forward secrecy "
                "by default.",
                impact="Slightly higher latency and a weaker cipher baseline than necessary.",
                remediation="Enable TLS 1.3 in the web server or load balancer (nginx 1.13+, "
                "Apache 2.4.36+, or your CDN's TLS settings).",
                evidence=["Negotiated: " + (tls.protocol or "unknown")],
                cwe="CWE-326",
                owasp="A02:2021 Cryptographic Failures",
                effort="quick",
                cvss=0.0,
            )
        )
    return out
