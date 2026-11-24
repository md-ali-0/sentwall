"""CI/CD Workflow generator for automated GitHub Actions and GitLab CI security gates."""
from __future__ import annotations


def generate_github_workflow(target_secret_name: str = "TARGET_URL") -> str:
    return f"""name: Sentwall Security Gate

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]
  schedule:
    - cron: '0 4 * * 1'  # Every Monday at 04:00 UTC

jobs:
  security-audit:
    name: Automated Web Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Sentwall Dependencies
        run: |
          pip install requests cryptography

      - name: Run Sentwall Scan
        run: |
          python scan.py "${{{{ secrets.{target_secret_name} || 'http://127.0.0.1:8080' }}}}" \\
            --authorized \\
            --formats html,json,sarif \\
            --out reports

      - name: Upload SARIF Results to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/
          category: sentwall-security-assessment

      - name: Archive HTML & PDF Reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sentwall-security-reports
          path: reports/
"""


def generate_gitlab_ci() -> str:
    return """stages:
  - test
  - security

sentwall-security-scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install requests cryptography
  script:
    - python scan.py "$TARGET_URL" --authorized --formats html,json,sarif --out reports
  artifacts:
    when: always
    paths:
      - reports/
    reports:
      sast: reports/*.sarif
"""
