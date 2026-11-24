"""Cloud & Infrastructure security checks: S3, Firebase, Prometheus, Docker/K8s, and Spring Actuators."""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "cloud"
LABEL = "Cloud & DevOps infrastructure exposure (S3, Firebase, Prometheus, Docker/K8s, Actuators)"

ACTUATOR_ENDPOINTS = [
    ("/actuator/env", "Spring Boot Environment Variables", Severity.CRITICAL,
     "Exposes active server configuration, environment variables, database credentials, and secret keys."),
    ("/actuator/heapdump", "Spring Boot JVM Heap Dump", Severity.CRITICAL,
     "Allows full JVM heap memory download, containing unencrypted plaintext passwords, session tokens, and keys."),
    ("/actuator", "Spring Boot Actuator Index", Severity.MEDIUM,
     "Actuator administration endpoints are exposed without authentication."),
    ("/actuator/mappings", "Spring Boot Route Mappings", Severity.MEDIUM,
     "Exposes all internal controllers, HTTP request mappings, and handler methods."),
    ("/actuator/logfile", "Spring Boot Active Application Log", Severity.HIGH,
     "Real-time server log output is publicly readable, potentially revealing errors, SQL queries, and user PII."),
]

METRICS_ENDPOINTS = [
    ("/metrics", "Prometheus Server Metrics", Severity.MEDIUM,
     "Exposes detailed system architecture metrics, thread pools, database latency, and internal subsystem IDs."),
    ("/actuator/prometheus", "Spring Boot Prometheus Metrics", Severity.MEDIUM,
     "Internal application metrics stream is exposed publicly."),
]


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_cloud:
        return out

    out += _check_actuators(ctx)
    out += _check_metrics(ctx)
    out += _check_firebase(ctx)
    out += _check_cloud_storage(ctx)
    return out


def _check_actuators(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []

    for path, title, severity, impact in ACTUATOR_ENDPOINTS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.http.get(url)
        if resp.status == 200 and resp.text:
            text_lower = resp.text.lower()
            matched = False

            if path == "/actuator/env" and any(k in text_lower for k in ["activeprofiles", "propertySources", "systemproperties"]):
                matched = True
            elif path == "/actuator/heapdump" and (len(resp.text) > 1000 or "octet-stream" in resp.headers.get("content-type", "")):
                matched = True
            elif path == "/actuator/mappings" and "dispatcherServlet" in resp.text:
                matched = True
            elif path == "/actuator/logfile" and ("error" in text_lower or "info" in text_lower):
                matched = True
            elif path == "/actuator" and "_links" in resp.text:
                matched = True

            if matched:
                f = Finding(
                    key=f"spring-boot-{path.replace('/', '-').strip('-')}",
                    title=f"Critical Spring Boot Actuator Exposed ({title})",
                    severity=severity,
                    category="DevOps & Cloud Exposure",
                    description=f"The Spring Boot management endpoint at {url} is exposed to the public internet without authentication.",
                    impact=impact,
                    remediation=(
                        "Disable or restrict actuator endpoints in application.properties or application.yml:\n"
                        "management.endpoints.web.exposure.exclude=*\n"
                        "Or restrict access to 127.0.0.1 via Spring Security / reverse proxy."
                    ),
                    evidence=[
                        f"URL: {url}",
                        f"Status: {resp.status}",
                        f"Snippet: {resp.text[:220]}...",
                    ],
                    references=[
                        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                    cwe="CWE-200",
                    owasp="A05:2021-Security Misconfiguration",
                    confidence="certain",
                    effort="quick",
                    cvss=8.6 if severity == Severity.CRITICAL else (7.2 if severity == Severity.HIGH else 5.3),
                    location=url,
                    title_bn=f"মারাত্মক স্প্রিং বুট অ্যাকচুয়েটর উন্মুক্ত ({title})",
                    description_bn=f"{url} লিঙ্কে স্প্রিং বুটের অ্যাডমিন মনিটরিং পোর্টাল পাসওয়ার্ড ছাড়াই ইন্টারনেটে উন্মুক্ত রয়েছে।",
                    impact_bn="আক্রমণকারী সার্ভারের গোপন ডাটাবেজ পাসওয়ার্ড, এনভায়রনমেন্ট ভেরিয়েবল বা মেমোরি ডাম্প চুরি করতে পারবে।",
                    fix_patches={
                        "nginx": f"location /actuator {{\n  deny all;\n  return 404;\n}}",
                        "apache": "<LocationMatch \"^/actuator\">\n  Require all denied\n</LocationMatch>",
                    },
                    poc_curl_template=f"curl -i -s '{url}'",
                )
                findings.append(f)
                ctx.add_node(f"actuator:{path}", title, "cloud", severity.value, {"url": url})
                ctx.add_link(ctx.host, f"actuator:{path}", "exposes")

    return findings


def _check_metrics(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []

    for path, title, severity, impact in METRICS_ENDPOINTS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.http.get(url)
        if resp.status == 200 and resp.text:
            if any(marker in resp.text for marker in ["# HELP ", "# TYPE ", "jvm_threads", "process_cpu_seconds"]):
                f = Finding(
                    key=f"exposed-metrics-{path.replace('/', '-').strip('-')}",
                    title=f"Exposed Infrastructure Metrics ({title})",
                    severity=severity,
                    category="DevOps & Cloud Exposure",
                    description=f"A Prometheus / OpenTelemetry telemetry endpoint is accessible at {url} without authorization.",
                    impact=impact,
                    remediation="Protect metrics endpoints behind network firewalls, VPNs, or reverse-proxy authorization.",
                    evidence=[f"URL: {url}", f"Sample: {resp.text[:200]}..."],
                    references=["https://prometheus.io/docs/operating/security/"],
                    cwe="CWE-200",
                    owasp="A05:2021-Security Misconfiguration",
                    confidence="certain",
                    effort="quick",
                    cvss=5.3,
                    location=url,
                    title_bn="পাবলিকলি উন্মুক্ত ইনফ্রাস্ট্রাকচার মেট্রিক্স",
                    description_bn=f"{url} এ Prometheus / সার্ভার পারফরম্যান্স মেট্রিক্স কোনো পাসওয়ার্ড ছাড়া যেকেউ দেখতে পাচ্ছে।",
                    impact_bn="সার্ভারের ইন্টারনাল কনফিগারেশন ও দুর্বল নোডগুলো সহজে চিহ্নিত করা যায়।",
                    fix_patches={
                        "nginx": f"location {path} {{\n  allow 10.0.0.0/8;\n  deny all;\n}}",
                    },
                )
                findings.append(f)
                break

    return findings


def _check_firebase(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    # Search for firebase database names in text
    project_names = set()
    raw_domain = ctx.domain.split(".")[0]
    if raw_domain:
        project_names.add(raw_domain)

    fb_rx = re.compile(r"https://([a-zA-Z0-9-]+)\.firebaseio\.com")
    for page in ctx.pages[:5]:
        for m in fb_rx.finditer(page.text):
            project_names.add(m.group(1))

    for name in list(project_names)[:2]:
        fb_url = f"https://{name}.firebaseio.com/.json"
        try:
            resp = ctx.http.request("GET", fb_url, timeout=5.0)
            if resp.status == 200 and resp.text and "error" not in resp.text.lower() and resp.text.strip() != "null":
                f = Finding(
                    key=f"firebase-database-open-{name}",
                    title="Critical Firebase Realtime Database Publicly Readable",
                    severity=Severity.CRITICAL,
                    category="Cloud & Database Security",
                    description=(
                        f"The Firebase Realtime Database at {fb_url} has open read permissions (.read: true). "
                        "All stored user records, documents, and credentials can be retrieved anonymously."
                    ),
                    impact="Complete disclosure of all records stored in the cloud database, leading to catastrophic data breach.",
                    remediation=(
                        "Update Firebase Security Rules immediately in the Firebase Console:\n"
                        "{\n  \"rules\": {\n    \".read\": \"auth != null\",\n    \".write\": \"auth != null\"\n  }\n}"
                    ),
                    evidence=[f"URL: {fb_url}", f"Response Data Sample: {resp.text[:200]}..."],
                    references=[
                        "https://firebase.google.com/docs/database/security",
                        "https://cwe.mitre.org/data/definitions/284.html",
                    ],
                    cwe="CWE-284",
                    owasp="A01:2021-Broken Access Control",
                    confidence="certain",
                    effort="quick",
                    cvss=9.8,
                    location=fb_url,
                    title_bn="মারাত্মক উন্মুক্ত Firebase ক্লাউড ডাটাবেজ",
                    description_bn=f"{fb_url} এ ক্লাউড ডাটাবেজ ওপেন রয়েছে, যেকেউ অনুমতি ছাড়া সব ডাটা ডাউনলোড করতে পারছে।",
                    impact_bn="গ্রাহকদের ব্যক্তিগত ডাটা, লগইন ও লেনদেনের সম্পূর্ণ ডাটাবেজ বেহাত হওয়ার ঝুঁকি।",
                    poc_curl_template=f"curl -s '{fb_url}'",
                )
                findings.append(f)
                ctx.add_node(f"cloud:{name}", f"Firebase ({name})", "cloud", "critical", {"url": fb_url})
                ctx.add_link(ctx.host, f"cloud:{name}", "uses")
        except Exception:
            pass

    return findings


def _check_cloud_storage(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    bucket_candidates = [ctx.domain, ctx.host]
    base_name = ctx.domain.split(".")[0]
    if base_name and len(base_name) > 3:
        bucket_candidates.append(f"{base_name}-assets")
        bucket_candidates.append(f"{base_name}-backup")

    for bucket in bucket_candidates[:2]:
        s3_url = f"https://{bucket}.s3.amazonaws.com"
        try:
            resp = ctx.http.request("GET", s3_url, timeout=5.0)
            if resp.status == 200 and "<ListBucketResult" in resp.text:
                f = Finding(
                    key=f"aws-s3-bucket-public-listing-{bucket}",
                    title=f"Critical Public AWS S3 Bucket Listing ({bucket})",
                    severity=Severity.CRITICAL,
                    category="Cloud Storage Misconfiguration",
                    description=(
                        f"The Amazon S3 bucket at {s3_url} allows anonymous public listing. "
                        "Any user can view and download all objects in this bucket."
                    ),
                    impact="Direct exposure of sensitive backups, customer files, private media, or proprietary source code.",
                    remediation=(
                        "Enable 'Block Public Access' (BPA) on the S3 bucket in the AWS Console immediately. "
                        "Ensure S3 bucket ACLs and Bucket Policies grant access only to authorized IAM principals."
                    ),
                    evidence=[f"S3 URL: {s3_url}", f"XML Response Sample: {resp.text[:220]}..."],
                    references=[
                        "https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
                        "https://cwe.mitre.org/data/definitions/284.html",
                    ],
                    cwe="CWE-284",
                    owasp="A05:2021-Security Misconfiguration",
                    confidence="certain",
                    effort="quick",
                    cvss=9.1,
                    location=s3_url,
                    title_bn=f"উন্মুক্ত AWS S3 ক্লাউড বাকেট ({bucket})",
                    description_bn=f"{s3_url} ক্লাউড স্টোরেজে সবার জন্য ফাইল দেখার পারমিশন দেওয়া আছে।",
                    impact_bn="কোম্পানির গোপন ব্যাকআপ ফাইল, গ্রাহকের ডকুমেন্ট ইত্যাদি ইন্টারনেটে সবার কাছে উন্মুক্ত।",
                    poc_curl_template=f"curl -s '{s3_url}'",
                )
                findings.append(f)
                ctx.add_node(f"s3:{bucket}", f"AWS S3 ({bucket})", "cloud", "critical", {"url": s3_url})
                ctx.add_link(ctx.host, f"s3:{bucket}", "stores")
        except Exception:
            pass

    return findings
