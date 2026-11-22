# SiteSentinel

> **Built a website with AI? Before you ship it, check its security.**

SiteSentinel is a Python-based web security assessment toolkit for identifying common security misconfigurations and potential vulnerabilities in websites and web applications. It combines security checks, attack-surface discovery, structured reports, and before/after retesting in one command-line workflow.

Use it to review applications built with AI-assisted coding, validate security improvements, and produce reports that developers and website owners can act on.

> **Important:** SiteSentinel is intended for authorized security testing only. Scan systems that you own or have explicit, written permission to assess. It is not a substitute for a professional penetration test, manual code review, or a complete security audit.

---

## Highlights

- **Broad security coverage:** checks for common issues across HTTP security headers, TLS, cookies, exposed files, server configuration, injection indicators, API documentation exposure, and more.
- **Multiple report formats:** generate HTML, PDF, JSON, CSV, and SARIF output (depending on the selected options and installed dependencies).
- **Reconnaissance:** discover related subdomains using certificate-transparency data and DNS wordlists, then optionally assess discovered hosts.
- **Retesting and comparison:** compare baseline and follow-up scan results to track resolved, open, improved, regressed, and newly detected findings.
- **CI/CD support:** generate GitHub Actions or GitLab CI starter configuration and use retest thresholds as part of a pipeline.
- **Client-ready output:** organize reports by target and timestamp, with optional client and auditor details.

## What It Checks

SiteSentinel includes checks in the following areas. Detection coverage depends on the target, configuration, network access, and scan profile.

| Area | Examples |
|---|---|
| Security headers | CSP, HSTS, clickjacking protections, CORS configuration, server version disclosure |
| TLS and transport | HTTP-to-HTTPS enforcement, certificate validity, TLS versions, cipher configuration |
| Cookies | Secure, HttpOnly, and SameSite attributes; session cookie configuration |
| Exposure | Common sensitive paths, backup files, environment files, Git metadata, directory listing |
| Server configuration | Risky HTTP methods, verbose error responses, host-header handling |
| Web and injection indicators | Reflected XSS indicators, SQL injection signals, open redirects, path traversal, SSTI indicators |
| API and documentation | GraphQL introspection, exposed Swagger/OpenAPI or related API specifications, JWT configuration signals |
| Cloud and infrastructure | Publicly exposed storage or service endpoints and common infrastructure exposure indicators |
| Secrets | Recognizable token patterns, credential-like strings, and high-entropy values in accessible responses |
| DNS and email | SPF, DMARC, DKIM, CAA, DNSSEC, and related configuration signals |
| Technology signals | Server and framework fingerprints, including selected end-of-life version indicators |
| WAF and origin exposure | WAF fingerprinting signals and potential origin information exposure |

These are automated checks, not guaranteed exploit validation. A finding should be reviewed and confirmed in context before remediation decisions are made.

## Requirements

- Python 3.9 or later
- pip
- Network access to the authorized target
- Written authorization for every target you scan

Some optional output formats or checks may require additional system packages or dependencies. PDF generation, for example, may depend on the PDF backend configured by the project.

## Installation

Clone the repository and install its dependencies:

```bash
git clone https://github.com/md-ali-0/vulnscope.git
cd vulnscope
python -m pip install -r requirements.txt
```

Run commands from the project root.

## Quick Start

Run a standard assessment against a target you are authorized to test:

```bash
python scan.py https://your-authorized-domain.example --authorized
```

Add client and auditor details and request PDF output:

```bash
python scan.py https://your-authorized-domain.example \
  --authorized \
  --pitch \
  --client "Example Organization" \
  --auditor "Security Team" \
  --pdf
```

Use the deeper scan profile on an authorized target:

```bash
python scan.py your-authorized-domain.example --authorized --profile deep
```

Use the API-focused profile for an authorized API:

```bash
python scan.py https://api.your-domain.example --authorized --profile api
```

> Review the available command-line options before running a scan. Profiles may send additional requests and can increase load on the target.

## Reconnaissance

The reconnaissance workflow can identify related hostnames from certificate-transparency data and a DNS wordlist.

Discover hostnames and fingerprint responding hosts:

```bash
python recon.py your-authorized-domain.example --authorized
```

Optionally scan discovered live hosts, with a conservative host limit:

```bash
python recon.py your-authorized-domain.example \
  --authorized \
  --scan \
  --max-scan 15
```

Reconnaissance can generate HTML, Markdown, JSON, and CSV output. Certificate-transparency lookups and DNS discovery are best-effort: rate limits, DNS configuration, and incomplete public data can affect results.

## Retest and Compare Results

Save a baseline scan before making changes. After remediation, run a second scan with the same target and comparable options.

Compare the two JSON reports:

```bash
python retest.py path/to/baseline/report.json path/to/follow-up/report.json
```

You can also use the scan command's diff mode:

```bash
python scan.py --diff baseline.json follow-up.json --out reports
```

The comparison report groups findings into:

- **Resolved:** present in the baseline but not detected in the follow-up.
- **Still open:** detected in both scans.
- **Improved:** severity decreased but the finding remains.
- **Regressed:** severity increased.
- **New:** detected in the follow-up but not in the baseline.

Use a severity threshold to fail a CI step when high-priority findings remain:

```bash
python retest.py baseline.json follow-up.json --fail-on high
```

A scan comparison only reflects what the tool detected at each point in time. A finding disappearing from a report is not, by itself, proof that the underlying risk has been fully eliminated.

## CI/CD Configuration

Generate starter pipeline configuration:

```bash
# GitHub Actions
python scan.py --generate-ci github

# GitLab CI
python scan.py --generate-ci gitlab
```

Review generated files and adapt secrets, target configuration, permissions, and severity thresholds to your environment before enabling them in a production pipeline.

## Report Output

Scan artifacts are organized by target and timestamp under the reports directory. Depending on the selected formats and available dependencies, output can include:

| File | Purpose |
|---|---|
| `report.html` | Interactive browser-based assessment report |
| `report.pdf` | PDF report for sharing or printing |
| `report.json` | Structured scan data for automation and further analysis |
| `report.csv` | Tabular findings for spreadsheet workflows |
| `report.sarif` | SARIF output for compatible code-scanning platforms |
| `proposal.md` | Optional proposal or statement-of-work content when pitch output is enabled |

The exact files produced depend on command-line options. Treat reports as sensitive: they can contain target details, exposed paths, response snippets, or other security-relevant information. Store and share them accordingly.

## Demo: Vulnerable vs. Hardened Application

The repository includes a local test application intended for controlled testing.

Start the intentionally vulnerable demo app:

```bash
python tests/vulnerable_app.py
```

In another terminal, run a local assessment:

```bash
python scan.py http://127.0.0.1:8099 --authorized --formats json --out reports/before
```

Stop the app and start its hardened mode:

```bash
python tests/vulnerable_app.py --hardened
```

Run the follow-up assessment and compare the results:

```bash
python scan.py http://127.0.0.1:8099 --authorized --formats json --out reports/after
python retest.py reports/before/*/*/report.json reports/after/*/*/report.json
```

This local workflow demonstrates how findings can change after hardening. The exact counts and grades depend on the current test fixtures and scanner version; use the generated reports as the source of truth.

## Tests

Run the test suite from the repository root:

```bash
python -m unittest discover tests
```

The test suite includes checks for the scanner and its local demonstration application.

## Responsible Use and Limitations

- Only scan domains, applications, and infrastructure that you own or are explicitly authorized to assess.
- The `--authorized` flag is an operator acknowledgement; it does not grant permission or verify ownership.
- Automated scanners can produce false positives and false negatives. Manually validate important findings.
- Use conservative scan settings on production systems. Some checks can generate traffic or trigger application defenses.
- Do not use the tool to evade access controls, disrupt services, access data without permission, or test third-party infrastructure without authorization.
- Keep scan reports private and redact sensitive information before sharing them.
- SiteSentinel is provided for security assessment and educational use. No guarantee is made that a scan will identify every vulnerability or prevent compromise.

## Contributing

Issues, bug reports, and pull requests are welcome. When reporting a security issue, avoid publishing sensitive target information or working exploit details in a public issue. Follow responsible disclosure practices.

## License

No license is currently specified in this repository. Unless a license is added, the default copyright rules apply; do not assume that the code is available for unrestricted reuse, modification, or redistribution.
