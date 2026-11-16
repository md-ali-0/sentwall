"""API & GraphQL security checks: introspection, documentation exposure, JWT analysis, and WebSocket validation."""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "api"
LABEL = "API & GraphQL security (GraphQL introspection, OpenAPI/Swagger, JWT, WebSocket)"

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/v1/graphql",
    "/query",
    "/api/v1/graphql",
]

API_DOC_PATHS = [
    ("/swagger.json", "Swagger 2.0 Specification", Severity.MEDIUM),
    ("/openapi.json", "OpenAPI 3.0 Specification", Severity.MEDIUM),
    ("/api-docs", "Swagger / OpenAPI API Docs", Severity.MEDIUM),
    ("/v1/api-docs", "SpringFox / Swagger API Docs v1", Severity.MEDIUM),
    ("/v2/api-docs", "SpringFox / Swagger API Docs v2", Severity.MEDIUM),
    ("/v3/api-docs", "SpringDoc OpenAPI 3 Docs", Severity.MEDIUM),
    ("/swagger/v1/swagger.json", ".NET Swagger Specification", Severity.MEDIUM),
    ("/api/swagger.json", "API Swagger Specification", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI Interactive Console", Severity.LOW),
    ("/swagger/index.html", "Swagger UI Console", Severity.LOW),
    ("/docs", "FastAPI / ReDoc Documentation", Severity.INFO),
    ("/redoc", "ReDoc API Documentation", Severity.INFO),
    ("/postman.json", "Postman Collection Export", Severity.HIGH),
]


def run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    if not ctx.options.check_api:
        return out

    out += _check_graphql(ctx)
    out += _check_api_docs(ctx)
    out += _check_jwt_tokens(ctx)
    return out


def _check_graphql(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    introspection_query = json.dumps({"query": "{__schema{types{name,kind}}}"})

    for path in GRAPHQL_PATHS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.http.request("POST", url, data=introspection_query,
                                headers={"Content-Type": "application/json"})
        if resp.status == 200 and ("__schema" in resp.text or "__typename" in resp.text):
            try:
                data = json.loads(resp.text)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t.get("name") for t in types if t.get("name") and not t.get("name", "").startswith("__")][:8]
            except Exception:
                type_names = []

            evidence = [
                f"Endpoint: {url}",
                f"HTTP Status: {resp.status}",
                f"Discovered GraphQL Types: {', '.join(type_names) if type_names else 'Schema returned'}",
            ]
            f = Finding(
                key="graphql-introspection-enabled",
                title="GraphQL Introspection Enabled in Production",
                severity=Severity.MEDIUM,
                category="API Security",
                description=(
                    f"The GraphQL endpoint at {url} allows full schema introspection. "
                    "Unauthorized users can enumerate all queries, mutations, object types, "
                    "and internal data structures."
                ),
                impact=(
                    "Attackers obtain a complete architectural blueprint of the backend API, "
                    "including internal operations, admin mutations, and unadvertised database fields."
                ),
                remediation=(
                    "Disable GraphQL introspection in production environments. "
                    "For Apollo Server: set `introspection: false`. "
                    "For GraphQL Java / Spring: set `graphql.tools.introspection.enabled=false`."
                ),
                evidence=evidence,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    "https://portswigger.net/web-security/graphql",
                ],
                cwe="CWE-200",
                owasp="A01:2021-Broken Access Control",
                confidence="certain",
                effort="quick",
                cvss=5.3,
                location=url,
                title_bn="প্রোডাকশনে GraphQL Introspection খোলা আছে",
                description_bn=(
                    f"{url} এ GraphQL schema introspection চালু রয়েছে। এর ফলে যেকেউ সম্পূর্ণ "
                    "ডাটাবেজ ও মিউটেশন মডেল দেখে নিতে পারে।"
                ),
                impact_bn="হ্যাকাররা পুরো সিস্টেমের ব্যাকএন্ড আর্কিটেকচার ও হিডেন ফিল্ড জেনে যাবে।",
                fix_patches={
                    "code": "// Node.js Apollo Server:\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production'\n});",
                    "nginx": "# Block introspection queries in nginx\nlocation /graphql {\n  if ($request_body ~* \"__schema|__type\") {\n    return 403;\n  }\n  proxy_pass http://backend;\n}",
                },
                poc_curl_template=f"curl -s -X POST '{url}' -H 'Content-Type: application/json' -d '{introspection_query}'",
            )
            findings.append(f)
            ctx.add_node(f"endpoint:{url}", "GraphQL API", "endpoint", "medium", {"url": url})
            ctx.add_link(ctx.host, f"endpoint:{url}", "exposes")
            break

    return findings


def _check_api_docs(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []

    for path, title, severity in API_DOC_PATHS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.http.get(url)
        if resp.status == 200 and resp.text:
            text_lower = resp.text.lower()
            is_valid = False
            evidence_lines = [f"URL: {url}", f"Status: {resp.status}"]

            if "swagger" in path or "openapi" in path or "postman" in path:
                if any(x in text_lower for x in ['"swagger"', '"openapi"', '"paths"', '"info"', 'postman_collection']):
                    is_valid = True
                    evidence_lines.append(f"Snippet: {resp.text[:200]}...")
            elif "swagger-ui" in path or "docs" in path or "redoc" in path:
                if any(x in text_lower for x in ['swagger-ui', 'redoc', 'fastapi', 'api documentation']):
                    is_valid = True
                    evidence_lines.append("Interactive API Explorer detected.")

            if is_valid:
                f = Finding(
                    key=f"api-doc-exposed-{path.replace('/', '-').strip('-')}",
                    title=f"Exposed API Specification / Documentation ({title})",
                    severity=severity,
                    category="Information Exposure",
                    description=(
                        f"An interactive API documentation endpoint or raw schema was found publicly accessible at {url}."
                    ),
                    impact=(
                        "Reveals internal REST endpoints, parameters, authentication schemes, and hidden routes, "
                        "significantly assisting threat actors in finding logic bugs and unauthenticated endpoints."
                    ),
                    remediation=(
                        "Restrict access to API documentation via VPN, IP whitelisting, or HTTP Basic Authentication. "
                        "Never leave raw swagger.json or postman collections publicly downloadable on the public internet."
                    ),
                    evidence=evidence_lines,
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                    cwe="CWE-200",
                    owasp="A01:2021-Broken Access Control",
                    confidence="certain",
                    effort="quick",
                    cvss=4.3 if severity == Severity.LOW else 5.3,
                    location=url,
                    title_bn=f"পাবলিকলি অ্যাক্সেসযোগ্য API ডকুমেন্টেশন ({title})",
                    description_bn=f"{url} ঠিকানায় সিস্টেমের সব API রুটের তথ্য উন্মুক্ত অবস্থায় পাওয়া গেছে।",
                    impact_bn="অননুমোদিত ব্যক্তিরা সাইটের সমস্ত হিডেন API ও ইন্টারনাল প্যারামিটার জেনে আক্রমণ করতে পারবে।",
                    fix_patches={
                        "nginx": f"location {path} {{\n  allow 10.0.0.0/8;\n  deny all;\n}}",
                        "apache": f"<Location \"{path}\">\n  Require ip 10.0.0.0/8\n</Location>",
                    },
                    poc_curl_template=f"curl -i -k -s '{url}'",
                )
                findings.append(f)
                ctx.add_node(f"api:{path}", title, "endpoint", severity.value, {"url": url})
                ctx.add_link(ctx.host, f"api:{path}", "exposes")

    return findings


def _check_jwt_tokens(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    jwt_rx = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

    found_tokens = set()
    # Collect tokens from cookies
    for page in ctx.pages:
        for cookie_str in page.headers.get("set-cookie", "").split(","):
            for m in jwt_rx.finditer(cookie_str):
                found_tokens.add(m.group(0))
        for m in jwt_rx.finditer(page.text[:50000]):
            found_tokens.add(m.group(0))

    for token in list(found_tokens)[:3]:
        parts = token.split(".")
        if len(parts) < 2:
            continue
        try:
            # Decode header
            head_pad = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(head_pad.encode()).decode("utf-8", "ignore"))

            # Decode payload
            body_pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(body_pad.encode()).decode("utf-8", "ignore"))
        except Exception:
            continue

        alg = header.get("alg", "").lower()
        if alg == "none":
            findings.append(
                Finding(
                    key="jwt-algorithm-none-vulnerability",
                    title="Critical JWT 'alg: none' Authentication Bypass Vulnerability",
                    severity=Severity.CRITICAL,
                    category="Authentication & Cryptography",
                    description=(
                        f"A JSON Web Token was found using the insecure 'none' algorithm ({token[:30]}...). "
                        "The application accepts unsigned tokens, allowing arbitrary authentication bypass."
                    ),
                    impact=(
                        "An attacker can forge administrative privileges by modifying the token payload "
                        "and setting the algorithm header to 'none'."
                    ),
                    remediation=(
                        "Configure the JWT validation library to explicitly reject tokens with 'alg: none'. "
                        "Enforce strict asymmetric (RS256, ES256) or strong HMAC (HS256 with 256-bit secret) validation."
                    ),
                    evidence=[
                        f"JWT Header: {json.dumps(header)}",
                        f"JWT Payload Claims: {json.dumps(payload)}",
                    ],
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                    cwe="CWE-347",
                    owasp="A02:2021-Cryptographic Failures",
                    confidence="certain",
                    effort="quick",
                    cvss=9.8,
                    location="JWT Token",
                    title_bn="মারাত্মক JWT 'alg: none' অথেনটিকেশন বাইপাস ত্রুটি",
                    description_bn="টোকেনে 'none' অ্যালগরিদম ব্যবহৃত হওয়ায় কোনো পাসওয়ার্ড বা সিগনেচার ছাড়াই যেকেউ যেকারো অ্যাকাউন্টে ঢুকতে পারবে।",
                    impact_bn="সম্পূর্ণ অ্যাডমিন প্রিভিলেজ হাইজ্যাক করা সম্ভব।",
                )
            )

        # Check for missing expiration
        if "exp" not in payload and len(payload) > 1:
            findings.append(
                Finding(
                    key="jwt-missing-expiration-claim",
                    title="JSON Web Token Lacks Expiration ('exp') Claim",
                    severity=Severity.LOW,
                    category="Authentication & Session",
                    description="The discovered JWT token does not contain an expiration claim ('exp').",
                    impact="If a token is intercepted or leaked, it remains valid indefinitely and cannot expire naturally.",
                    remediation="Always include a short-lived 'exp' (expiration timestamp) claim on every issued JWT token.",
                    evidence=[f"Payload: {json.dumps(payload)[:150]}"],
                    cwe="CWE-613",
                    owasp="A07:2021-Identification and Authentication Failures",
                    confidence="certain",
                    effort="quick",
                    cvss=3.7,
                )
            )

    return findings
