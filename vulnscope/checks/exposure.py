"""Sensitive file, backup and admin interface discovery with soft-404 suppression."""
from __future__ import annotations

import random
import re
import string
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "exposure"
LABEL = "Exposed files, backups & admin panels"


@dataclass
class Probe:
    path: str
    title: str
    severity: Severity
    category: str
    description: str
    impact: str
    remediation: str
    cwe: str
    owasp: str
    cvss: float
    confirm: Callable[[str, dict], bool]
    effort: str = "quick"


def _has(*needles: str) -> Callable[[str, dict], bool]:
    def check(text: str, headers: dict) -> bool:
        low = text.lower()
        return any(n.lower() in low for n in needles)

    return check


def _regex(pattern: str, flags: int = re.I) -> Callable[[str, dict], bool]:
    rx = re.compile(pattern, flags)

    def check(text: str, headers: dict) -> bool:
        return bool(rx.search(text))

    return check


def _binary(headers: dict) -> bool:
    ct = headers.get("content-type", "")
    return "octet-stream" in ct or "zip" in ct or "x-gzip" in ct or "sql" in ct


def _any(text: str, headers: dict) -> bool:
    return True


PROBES: List[Probe] = [
    # --- version control & secrets -----------------------------------------
    Probe(".git/config", "Exposed Git repository configuration", Severity.CRITICAL, "Sensitive File Exposure",
          "The .git directory is publicly readable. An attacker can download the entire source "
          "history - including secrets that were committed and later 'removed' - and then "
          "reconstruct the full application source.",
          "Complete source code disclosure, plus every credential, API key and database password "
          "that ever appeared in a commit. This typically leads to full server compromise.",
          "Block access at the web server and rotate any secret that was ever committed:\n"
          "location ~ /\\.git { deny all; return 404; }\n"
          "Then rebuild the repository without the leaked secrets and force-push.",
          "CWE-538", "A05:2021 Security Misconfiguration", 9.8, _has("[core]", "repositoryformatversion")),
    Probe(".git/HEAD", "Exposed Git metadata", Severity.HIGH, "Sensitive File Exposure",
          "Git internals are served publicly, confirming the repository is downloadable.",
          "Source code and commit history disclosure.",
          "Deny access to .git and redeploy from a clean build artefact rather than a working copy.",
          "CWE-538", "A05:2021 Security Misconfiguration", 8.2, _has("ref: refs/", "refs/heads/")),
    Probe(".svn/entries", "Exposed Subversion metadata", Severity.HIGH, "Sensitive File Exposure",
          "Subversion administrative files are publicly accessible.",
          "Source code disclosure.",
          "Deny access to .svn directories and deploy from an export rather than a checkout.",
          "CWE-538", "A05:2021 Security Misconfiguration", 7.5, _has("dir", "svn")),
    Probe(".env", "Environment file with secrets exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "The .env file is downloadable. It normally contains database credentials, the "
          "application encryption key, mail passwords and third-party API keys.",
          "Direct database access, ability to forge session cookies with the app key, and full "
          "compromise of every integrated service.",
          "Deny access to dotfiles at the server, move the file above the web root, and rotate "
          "every credential it contains:\n"
          "location ~ /\\.(?!well-known) { deny all; }",
          "CWE-538", "A02:2021 Cryptographic Failures", 9.8,
          _regex(r"(?m)^[A-Z0-9_]{3,}=.{2,}")),
    Probe(".env.local", "Local environment file exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A local environment override file is publicly readable.",
          "Credential and configuration disclosure.",
          "Deny access to dotfiles and remove the file from the deployed build.",
          "CWE-538", "A02:2021 Cryptographic Failures", 9.8, _regex(r"(?m)^[A-Z0-9_]{3,}=.{2,}")),
    Probe(".env.bak", "Backup of environment file exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A backup copy of the environment file is downloadable.",
          "Credential disclosure, often including credentials that are no longer rotated.",
          "Remove backup files from the web root and deny access to *.bak.",
          "CWE-530", "A02:2021 Cryptographic Failures", 9.8, _regex(r"(?m)^[A-Z0-9_]{3,}=.{2,}")),
    Probe("config.php.bak", "PHP configuration backup exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A backup of a PHP configuration file is served as plain text, so its source is readable.",
          "Database credentials and application secrets disclosure.",
          "Delete backup files, deny *.bak/*.old/*.swp at the server, and rotate credentials.",
          "CWE-530", "A02:2021 Cryptographic Failures", 9.1, _has("<?php", "password", "db_")),
    Probe("wp-config.php.bak", "WordPress config backup exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A backup of wp-config.php is downloadable.",
          "Database credentials, authentication salts and table prefix disclosure.",
          "Delete the backup, deny *.bak, and rotate the WordPress salts and DB password.",
          "CWE-530", "A02:2021 Cryptographic Failures", 9.1, _has("db_password", "define(")),
    Probe("id_rsa", "Private SSH key exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A private SSH key is downloadable from the web root.",
          "Direct shell access to the server wherever that key is authorised.",
          "Remove the key from the web root, revoke it from authorized_keys, and generate a new "
          "passphrase-protected key stored outside the document root.",
          "CWE-522", "A07:2021 Identification and Authentication Failures", 9.8, _has("PRIVATE KEY")),
    Probe(".aws/credentials", "AWS credentials file exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "AWS access keys are publicly readable.",
          "Full control of the cloud account within the key's permissions - data theft, resource "
          "abuse and potentially large bills.",
          "Immediately deactivate the key in IAM, audit CloudTrail for use, and move to instance "
          "roles or short-lived STS credentials.",
          "CWE-522", "A07:2021 Identification and Authentication Failures", 9.8, _has("aws_access_key_id")),
    Probe("sftp-config.json", "Editor SFTP credentials exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A Sublime/SFTP sync configuration file is publicly readable, usually containing a "
          "plaintext server password.",
          "Direct SSH/SFTP access to the production server.",
          "Delete the file, change the server password, and switch to key-based authentication.",
          "CWE-522", "A07:2021 Identification and Authentication Failures", 9.1,
          _has('"host"', '"password"', '"user"')),
    Probe("terraform.tfstate", "Terraform state file exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "The Terraform state is downloadable; it contains resource identifiers and often "
          "plaintext secrets for provisioned services.",
          "Cloud infrastructure mapping and credential disclosure.",
          "Store state in an encrypted remote backend with access controls and remove it from the "
          "web root.",
          "CWE-538", "A02:2021 Cryptographic Failures", 9.1, _has("terraform_version", "resources")),
    Probe("docker-compose.yml", "Docker Compose file exposed", Severity.HIGH, "Sensitive File Exposure",
          "Infrastructure definition is readable, revealing service topology, image versions, "
          "internal hostnames and often environment secrets.",
          "Detailed attack surface map and potential credential disclosure.",
          "Remove deployment files from the web root; build images from a private registry.",
          "CWE-538", "A05:2021 Security Misconfiguration", 7.5, _has("services:", "image:")),
    Probe("Dockerfile", "Dockerfile exposed", Severity.LOW, "Sensitive File Exposure",
          "The container build file is readable, disclosing base image versions and build steps.",
          "Helps an attacker identify outdated base images with known CVEs.",
          "Remove build files from the deployed artefact.",
          "CWE-538", "A05:2021 Security Misconfiguration", 5.3, _has("FROM ", "RUN ")),
    Probe("Jenkinsfile", "CI pipeline definition exposed", Severity.LOW, "Sensitive File Exposure",
          "The CI pipeline definition is readable.",
          "Reveals build and deployment mechanics, sometimes including credential IDs.",
          "Remove CI files from the web root.",
          "CWE-538", "A05:2021 Security Misconfiguration", 4.3, _has("pipeline {", "stage(")),

    # --- databases & backups ------------------------------------------------
    Probe("backup.sql", "Database dump exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A SQL dump is downloadable. It contains full table data plus schema.",
          "Mass disclosure of customer records, password hashes and business data - usually a "
          "reportable data breach.",
          "Delete the dump from the web root, store backups outside the document root or in "
          "object storage with signed URLs, and assess breach-notification obligations.",
          "CWE-530", "A01:2021 Broken Access Control", 9.8, _has("CREATE TABLE", "INSERT INTO", "-- mysql dump")),
    Probe("dump.sql", "Database dump exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A database dump is publicly downloadable.", "Full database disclosure.",
          "Remove the dump and relocate backups outside the web root.",
          "CWE-530", "A01:2021 Broken Access Control", 9.8, _has("CREATE TABLE", "INSERT INTO")),
    Probe("db.sql", "Database dump exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A database dump is publicly downloadable.", "Full database disclosure.",
          "Remove the dump and relocate backups outside the web root.",
          "CWE-530", "A01:2021 Broken Access Control", 9.8, _has("CREATE TABLE", "INSERT INTO")),
    Probe("backup.zip", "Site backup archive exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A compressed backup archive is downloadable.",
          "Full source code plus any configuration and uploads inside the archive.",
          "Delete the archive, keep backups off the web root, and rotate any credentials it held.",
          "CWE-530", "A01:2021 Broken Access Control", 9.1, _binary),
    Probe("www.zip", "Website archive exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A website archive is downloadable.", "Full source disclosure.",
          "Delete the archive and keep build artefacts outside the document root.",
          "CWE-530", "A01:2021 Broken Access Control", 9.1, _binary),
    Probe("site.zip", "Website archive exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A website archive is downloadable.", "Full source disclosure.",
          "Delete the archive and keep build artefacts outside the document root.",
          "CWE-530", "A01:2021 Broken Access Control", 9.1, _binary),
    Probe("backup.tar.gz", "Backup archive exposed", Severity.CRITICAL, "Sensitive File Exposure",
          "A tar.gz backup is downloadable.", "Full source and configuration disclosure.",
          "Delete the archive and move backups outside the web root.",
          "CWE-530", "A01:2021 Broken Access Control", 9.1, _binary),

    # --- debug & framework endpoints ---------------------------------------
    Probe("phpinfo.php", "phpinfo() page exposed", Severity.HIGH, "Information Disclosure",
          "A phpinfo() page is publicly reachable. It discloses PHP version, loaded modules, "
          "absolute file paths, environment variables and sometimes credentials.",
          "Precise version targeting plus file path disclosure usable in LFI attacks.",
          "Delete the file immediately. Never deploy diagnostic scripts to production.",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("php version", "phpinfo()")),
    Probe("info.php", "PHP information page exposed", Severity.HIGH, "Information Disclosure",
          "A PHP diagnostic page is reachable.", "Version and environment disclosure.",
          "Delete the diagnostic file from production.",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("php version", "phpinfo()")),
    Probe("server-status", "Apache server-status exposed", Severity.HIGH, "Information Disclosure",
          "mod_status is publicly readable. It lists every active request including full URLs "
          "with query strings, client IPs and internal vhosts.",
          "Session tokens in URLs, internal hostnames and traffic patterns are disclosed.",
          "Restrict /server-status to localhost:\n"
          "<Location /server-status>\n  Require local\n</Location>",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("apache server status")),
    Probe("server-info", "Apache server-info exposed", Severity.HIGH, "Information Disclosure",
          "mod_info discloses the complete server configuration.",
          "Full configuration, module list and file paths disclosure.",
          "Disable mod_info in production or restrict it to localhost.",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("apache server information")),
    Probe("actuator/env", "Spring Boot actuator /env exposed", Severity.CRITICAL, "Information Disclosure",
          "The Spring Boot environment endpoint is publicly reachable. It returns every "
          "configuration property, frequently including database passwords and API keys.",
          "Credential disclosure and, on some versions, remote property modification.",
          "Restrict actuator endpoints:\n"
          "management.endpoints.web.exposure.include=health\n"
          "management.endpoint.env.enabled=false\n"
          "and require authentication on /actuator/**.",
          "CWE-200", "A05:2021 Security Misconfiguration", 9.1, _has("propertysources", '"property"')),
    Probe("actuator/health", "Spring Boot actuator exposed", Severity.LOW, "Information Disclosure",
          "Spring Boot management endpoints are publicly exposed.",
          "Leaks component health, versions and sometimes database connectivity details.",
          "Expose only /actuator/health and protect the rest behind authentication.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has('"status"', "components")),
    Probe("actuator", "Spring Boot actuator root exposed", Severity.MEDIUM, "Information Disclosure",
          "The actuator index is reachable, advertising which management endpoints are enabled.",
          "Points an attacker directly at the most sensitive management endpoints.",
          "Disable unneeded actuator endpoints and require authentication.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has("_links", "actuator")),
    Probe("_profiler", "Symfony profiler exposed", Severity.HIGH, "Information Disclosure",
          "The Symfony web profiler is reachable in production. It exposes request data, "
          "SQL queries, configuration and often session contents.",
          "Sensitive data disclosure and a direct path to further exploitation.",
          "Disable the profiler outside dev: web_profiler: toolbar: false, and block "
          "/_profiler in the web server.",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("symfony", "profiler")),
    Probe("telescope", "Laravel Telescope exposed", Severity.HIGH, "Information Disclosure",
          "Laravel Telescope is publicly accessible, exposing requests, queries, logs, mail "
          "and sometimes job payloads with credentials.",
          "Deep insight into application internals and user data.",
          "Restrict Telescope to local or authorised users via Telescope::auth().",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("telescope", "laravel")),
    Probe("horizon", "Laravel Horizon exposed", Severity.MEDIUM, "Information Disclosure",
          "The Horizon queue dashboard is publicly reachable.",
          "Job payloads, failed job exceptions and internal hostnames are disclosed.",
          "Protect Horizon with Horizon::auth() and network restrictions.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has("horizon")),
    Probe("elmah.axd", "ELMAH error log exposed", Severity.HIGH, "Information Disclosure",
          "The ELMAH error log is publicly readable and contains full exception details, "
          "connection strings and request data.",
          "Credential and internal path disclosure.",
          "Restrict elmah.axd to localhost or remove it in production.",
          "CWE-200", "A05:2021 Security Misconfiguration", 7.5, _has("error log for")),
    Probe("trace.axd", "ASP.NET trace page exposed", Severity.MEDIUM, "Information Disclosure",
          "ASP.NET request tracing is enabled and publicly readable.",
          "Session IDs, cookies and server variables are disclosed per request.",
          "Set <trace enabled=\"false\" /> in web.config.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has("application trace", "requests to this application")),
    Probe("debug.log", "Debug log exposed", Severity.HIGH, "Information Disclosure",
          "A debug log file is downloadable. Logs routinely contain stack traces, SQL, tokens "
          "and personal data.",
          "Credential and personal data disclosure.",
          "Move logs outside the web root and deny access to *.log.",
          "CWE-532", "A09:2021 Security Logging and Monitoring Failures", 7.5,
          _regex(r"(?i)(stack trace|fatal error|exception|\[error\])")),
    Probe("error.log", "Error log exposed", Severity.HIGH, "Information Disclosure",
          "A server error log is downloadable.",
          "Internal paths, SQL and credentials disclosure.",
          "Deny access to *.log and store logs outside the document root.",
          "CWE-532", "A09:2021 Security Logging and Monitoring Failures", 7.5,
          _regex(r"(?i)(stack trace|fatal error|exception|\[error\])")),

    # --- config & metadata --------------------------------------------------
    Probe("web.config", "IIS web.config exposed", Severity.HIGH, "Sensitive File Exposure",
          "The IIS configuration file is served as text, exposing connection strings, "
          "authentication settings and rewrite rules.",
          "Database credentials and application architecture disclosure.",
          "IIS normally blocks .config; verify the request filtering rule is active and remove "
          "the file from the web root.",
          "CWE-538", "A05:2021 Security Misconfiguration", 7.5, _has("<configuration", "connectionstring")),
    Probe(".htaccess", "Apache .htaccess exposed", Severity.MEDIUM, "Sensitive File Exposure",
          "The .htaccess file is readable, disclosing rewrite rules, auth configuration and "
          "sometimes credentials for protected directories.",
          "Helps an attacker find hidden paths and authentication realms.",
          "Deny access to dotfiles: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>",
          "CWE-538", "A05:2021 Security Misconfiguration", 5.3, _has("rewriteengine", "authuserfile")),
    Probe("package.json", "package.json exposed", Severity.LOW, "Information Disclosure",
          "The npm manifest is readable, disclosing the complete dependency tree and versions.",
          "Precise identification of outdated libraries with known CVEs.",
          "Serve front-end bundles from a build directory that excludes manifests.",
          "CWE-200", "A05:2021 Security Misconfiguration", 4.3, _has('"dependencies"', '"version"')),
    Probe("composer.lock", "composer.lock exposed", Severity.LOW, "Information Disclosure",
          "The PHP dependency lock file is readable, listing exact package versions.",
          "Enables targeted exploitation of known library vulnerabilities.",
          "Exclude lock files from the public document root.",
          "CWE-200", "A05:2021 Security Misconfiguration", 4.3, _has('"packages"', '"name"')),
    Probe("swagger.json", "API documentation exposed", Severity.MEDIUM, "Information Disclosure",
          "An OpenAPI/Swagger specification is publicly available, listing every endpoint, "
          "parameter and often internal hostnames.",
          "Complete API map for an attacker, including undocumented and admin routes.",
          "Serve API docs only to authenticated developers, or generate them at build time.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has('"swagger"', '"openapi"', '"paths"')),
    Probe("openapi.json", "OpenAPI specification exposed", Severity.MEDIUM, "Information Disclosure",
          "An OpenAPI specification is publicly available.",
          "Complete API surface disclosure.",
          "Restrict API documentation to authenticated users.",
          "CWE-200", "A05:2021 Security Misconfiguration", 5.3, _has('"openapi"', '"paths"')),
    Probe("crossdomain.xml", "Permissive crossdomain.xml", Severity.LOW, "Misconfiguration",
          "A legacy Flash cross-domain policy is served. If it allows '*', any site could make "
          "authenticated requests on behalf of the user.",
          "Legacy cross-origin data access.",
          "Remove crossdomain.xml unless a legacy client genuinely requires it.",
          "CWE-942", "A05:2021 Security Misconfiguration", 4.3, _has("cross-domain-policy")),
    Probe(".DS_Store", "macOS .DS_Store exposed", Severity.LOW, "Sensitive File Exposure",
          "A .DS_Store file is downloadable; it lists the directory's file names.",
          "Reveals file names that are not otherwise linked, aiding further discovery.",
          "Deny access to dotfiles and add .DS_Store to the deploy ignore list.",
          "CWE-538", "A05:2021 Security Misconfiguration", 3.7, _binary),
    Probe(".idea/workspace.xml", "IDE project files exposed", Severity.LOW, "Sensitive File Exposure",
          "JetBrains project metadata is readable, revealing file paths and sometimes "
          "deployment credentials.",
          "Internal path disclosure.",
          "Exclude IDE directories from deployment.",
          "CWE-538", "A05:2021 Security Misconfiguration", 3.7, _has("<project", "component")),
    Probe(".vscode/settings.json", "Editor settings exposed", Severity.INFO, "Sensitive File Exposure",
          "Editor configuration is readable.", "Minor path and tooling disclosure.",
          "Exclude editor directories from deployment.",
          "CWE-538", "A05:2021 Security Misconfiguration", 3.1, _any),
    Probe("README.md", "README file exposed", Severity.INFO, "Information Disclosure",
          "A README is publicly readable and may describe internal setup, credentials or "
          "architecture.",
          "Reconnaissance value for an attacker.",
          "Review the README for sensitive details before publishing.",
          "CWE-200", "A05:2021 Security Misconfiguration", 2.6, _any),

    # --- admin interfaces ---------------------------------------------------
    Probe("admin", "Administrative interface reachable", Severity.MEDIUM, "Exposure",
          "An administrative interface is reachable from the public internet.",
          "If authentication is weak or default, this is a direct path to full control.",
          "Restrict admin panels to a VPN or IP allow-list, enforce MFA and rename predictable "
          "paths where possible.",
          "CWE-284", "A01:2021 Broken Access Control", 5.3, _any, "moderate"),
    Probe("administrator", "Administrative interface reachable", Severity.MEDIUM, "Exposure",
          "A Joomla-style administrator path is reachable.",
          "Direct target for credential stuffing and brute force.",
          "Restrict to trusted IPs, enforce MFA and rate limiting.",
          "CWE-284", "A01:2021 Broken Access Control", 5.3, _any, "moderate"),
    Probe("wp-login.php", "WordPress login reachable", Severity.LOW, "Exposure",
          "The default WordPress login endpoint is reachable and publicly known.",
          "Constant target for brute force and credential stuffing.",
          "Enforce MFA, rate limit login attempts, and consider limiting wp-login.php by IP.",
          "CWE-307", "A07:2021 Identification and Authentication Failures", 4.3, _has("wp-login", "wordpress")),
    Probe("phpmyadmin", "phpMyAdmin reachable", Severity.HIGH, "Exposure",
          "phpMyAdmin is publicly reachable. Historically it is one of the most attacked "
          "applications on the internet.",
          "Direct database access if credentials are weak or default.",
          "Remove phpMyAdmin from production or restrict it to an IP allow-list.",
          "CWE-284", "A01:2021 Broken Access Control", 7.5, _has("phpmyadmin")),
    Probe("adminer.php", "Adminer database tool reachable", Severity.HIGH, "Exposure",
          "Adminer, a single-file database client, is publicly accessible.",
          "Direct database login prompt for attackers to brute force.",
          "Delete Adminer from production or restrict by IP.",
          "CWE-284", "A01:2021 Broken Access Control", 7.5, _has("adminer")),
    Probe("xmlrpc.php", "WordPress XML-RPC enabled", Severity.LOW, "Exposure",
          "XML-RPC is enabled, which allows amplified brute-force attacks and historically "
          "pingback-based SSRF.",
          "Password guessing at scale and internal network probing.",
          "Disable XML-RPC if no legacy client needs it, or block it at the edge.",
          "CWE-307", "A07:2021 Identification and Authentication Failures", 4.3,
          _has("xml-rpc server accepts post requests only")),
]

DIR_LIST_DIRS = ["uploads", "upload", "files", "backup", "backups", "images", "img", "assets", "static", "media", "logs", "temp", "tmp", "old", "test"]


def _baseline(ctx: ScanContext):
    """Fingerprint the site's 'not found' behaviour to avoid soft-404 false positives."""
    samples = []
    for _ in range(2):
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        r = ctx.http.get(f"{ctx.base_url.rstrip('/')}/vulnscope-{token}", allow_redirects=True, limit=20000)
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            title = m.group(1).strip()[:80]
        samples.append((r.status, len(r.text), title))
    status = samples[-1][0]
    lengths = [s[1] for s in samples]
    title = samples[-1][2]
    return {
        "status": status,
        "min_len": min(lengths) * 0.9 if lengths else 0,
        "max_len": max(lengths) * 1.1 if lengths else 0,
        "title": title,
    }


def _is_soft_404(base: dict, status: int, text: str) -> bool:
    if status != base["status"]:
        return False
    if base["min_len"] <= len(text) <= base["max_len"]:
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        t = m.group(1).strip()[:80] if m else ""
        if t == base["title"]:
            return True
    return False


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    base = _baseline(ctx)
    ctx.add_meta("soft_404", base)

    def probe(p: Probe):
        url = f"{ctx.base_url.rstrip('/')}/{p.path.lstrip('/')}"
        r = ctx.http.get(url, allow_redirects=False, limit=65536)
        if r.error or not r.status:
            return None
        if r.status in (401, 403):
            return ("protected", p, url, r)
        if r.status not in (200, 206):
            return None
        if _is_soft_404(base, r.status, r.text):
            return None
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        try:
            if not p.confirm(r.text, hdrs):
                return None
        except Exception:
            return None
        return ("found", p, url, r)

    with ThreadPoolExecutor(max_workers=max(2, ctx.options.threads)) as ex:
        results = list(ex.map(probe, PROBES))

    seen_keys = set()
    for item in results:
        if not item:
            continue
        kind, p, url, r = item
        if kind == "protected":
            if p.severity.rank >= Severity.HIGH.rank and p.path in ("admin", "administrator", "phpmyadmin", "adminer.php"):
                out.append(
                    Finding(
                        key=f"admin-protected-{p.path}",
                        title=f"Administrative endpoint present but protected: /{p.path}",
                        severity=Severity.INFO,
                        category="Exposure",
                        description="The endpoint exists and returned an authorisation challenge. "
                        "This is normal, but the path is publicly discoverable and will be "
                        "targeted for credential attacks.",
                        impact="Low on its own; relevant as part of the attack surface.",
                        remediation="Keep the panel behind MFA, IP restrictions and rate limiting.",
                        evidence=[f"GET {url} -> HTTP {r.status}"],
                        cwe="CWE-284",
                        owasp="A01:2021 Broken Access Control",
                        effort="moderate",
                        cvss=0.0,
                        location=url,
                    )
                )
            continue

        if p.path in seen_keys:
            continue
        seen_keys.add(p.path)
        evidence = [f"GET {url} -> HTTP {r.status} ({len(r.text)} bytes)"]
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            evidence.append("Page title: " + m.group(1).strip()[:100])
        if p.path.endswith((".env", ".sql")):
            first = [l for l in r.text.splitlines() if "=" in l or "INSERT" in l.upper()][:2]
            if first:
                evidence.append("First lines: " + " | ".join(x[:60] for x in first))
        out.append(
            Finding(
                key=f"exposed-{p.path}",
                title=p.title,
                severity=p.severity,
                category=p.category,
                description=p.description,
                impact=p.impact,
                remediation=p.remediation,
                evidence=evidence,
                cwe=p.cwe,
                owasp=p.owasp,
                effort=p.effort,
                cvss=p.cvss,
                location=url,
            )
        )

    # ------------------------------------------------------ directory listing
    listing = []
    for d in DIR_LIST_DIRS:
        url = f"{ctx.base_url.rstrip('/')}/{d}/"
        r = ctx.http.get(url, allow_redirects=False, limit=20000)
        if r.status == 200 and re.search(r"<title>\s*Index of", r.text, re.I):
            listing.append(url)
    if listing:
        out.append(
            Finding(
                key="directory-listing",
                title="Directory listing is enabled",
                severity=Severity.MEDIUM,
                category="Misconfiguration",
                description="The web server returns an auto-generated file index for "
                + ", ".join(listing[:4])
                + ". Visitors can browse the contents of these folders directly, including "
                "files that were never meant to be linked.",
                impact="Disclosure of uploaded documents, backups, temporary files and "
                "sometimes personal data belonging to other users.",
                remediation="Disable autoindex:\nnginx: autoindex off;\n"
                "Apache: Options -Indexes\nand move non-public files outside the web root.",
                evidence=[f"GET {u} -> 200 Index of ..." for u in listing[:4]],
                cwe="CWE-548",
                owasp="A05:2021 Security Misconfiguration",
                effort="quick",
                cvss=5.3,
                location=listing[0],
            )
        )

    # ------------------------------------------------------ security.txt / robots
    sec = ctx.http.get(f"{ctx.base_url.rstrip('/')}/.well-known/security.txt", allow_redirects=True)
    ctx.add_meta("security_txt", bool(sec.status == 200 and "contact:" in sec.text.lower()))
    robots = ctx.http.get(f"{ctx.base_url.rstrip('/')}/robots.txt", allow_redirects=True)
    if robots.status == 200 and "user-agent" in robots.text.lower():
        disallowed = re.findall(r"(?im)^\s*disallow:\s*(\S+)", robots.text)
        interesting = [
            d for d in disallowed
            if d.strip("/") and re.search(r"(admin|backup|config|db|sql|test|dev|staging|private|internal|api|secret)", d, re.I)
        ]
        ctx.add_meta("robots_disallow", disallowed[:40])
        if interesting:
            out.append(
                Finding(
                    key="robots-hints",
                    title="robots.txt points at sensitive paths",
                    severity=Severity.INFO,
                    category="Information Disclosure",
                    description="robots.txt lists directories that look sensitive. Bots ignore "
                    "this file, and it is often the first thing an attacker reads - it works as "
                    "a signpost rather than a control.",
                    impact="Guides attackers to admin, backup or internal paths.",
                    remediation="Do not rely on robots.txt for access control. Protect these "
                    "paths with real authentication and remove the hints.",
                    evidence=["Disallow entries: " + ", ".join(interesting[:8])],
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    effort="quick",
                    cvss=0.0,
                    location=robots.url,
                )
            )
    return out
