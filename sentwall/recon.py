"""Attack-surface reconnaissance.

Sentwall scans one host. This module answers the question a client actually
asks: "what of mine is on the internet at all?"

Pipeline: discover -> resolve -> fingerprint -> optionally scan -> one report.
"""
from __future__ import annotations

import concurrent.futures as _futures
import datetime as _dt
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .net import Http, inspect_tls, registrable_domain, resolve_host
from .styles import BASE_CSS

E = html.escape

# A deliberately short list. Big public wordlists are better fetched than
# embedded, and a 200k-line brute force against a client is not a "quick look".
COMMON_PREFIXES = """
www mail ftp webmail smtp pop imap webdisk cpanel whm autodiscover autoconfig
ns1 ns2 dns1 dns2 mx mx1 mx2 vpn remote gateway portal intranet extranet
api api1 api2 apis app apps staging stage stg dev develop development test
testing qa uat demo sandbox beta alpha preview review lab labs
admin administrator manage management dashboard console panel cp
blog shop store cart checkout payments pay billing invoice cdn static assets
media images img files download uploads docs doc help support status monitor
monitoring metrics grafana kibana jenkins git gitlab github bitbucket
jira confluence wiki internal private secure sso auth login id identity
mobile m mobile-api websocket ws socket proxy cache search analytics
old legacy backup bak archive temp tmp
""".split()

RECON_CSS = """
.rc-head{padding:24px 0 18px;border-bottom:1px solid var(--line);margin-bottom:22px}
.rc-kicker{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:var(--accent);margin-bottom:10px}
.rc-head h1{font-size:29px;letter-spacing:-0.02em;margin-bottom:6px}
.rc-sub{font-size:12.5px;color:var(--muted);font-family:"SFMono-Regular",Consolas,monospace}
.rc-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin:20px 0 26px}
.rc-stat{background:var(--card);border:1px solid var(--line);border-left-width:4px;
  border-radius:10px;padding:15px 17px}
.rc-stat .n{font-size:26px;font-weight:800;line-height:1.1;color:var(--ink)}
.rc-stat .l{font-size:11px;font-weight:600;color:var(--muted);margin-top:2px}
.rc-stat.total{border-left-color:#64748b}
.rc-stat.live{border-left-color:#10b981}
.rc-stat.risk{border-left-color:#ef4444}
.rc-stat.expiring{border-left-color:#f59e0b}
.rc-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}
.rc-table th{text-align:left;font-size:10.5px;font-weight:700;letter-spacing:.07em;
  text-transform:uppercase;color:var(--muted);padding:9px 10px;border-bottom:1px solid var(--line)}
.rc-table td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
.rc-table tr:last-child td{border-bottom:none}
.rc-host{font-family:"SFMono-Regular",Consolas,monospace;font-weight:600;color:var(--ink);font-size:12px}
.rc-mono{font-family:"SFMono-Regular",Consolas,monospace;color:var(--muted);font-size:11.5px}
.rc-title{color:var(--body);font-size:11.5px;max-width:240px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;display:block}
.rc-pill{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10.5px;font-weight:700}
.rc-pill.ok{background:rgba(16,185,129,.12);color:#047857}
.rc-pill.warn{background:rgba(245,158,11,.14);color:#92400e}
.rc-pill.bad{background:rgba(239,68,68,.12);color:#b91c1c}
.rc-pill.mute{background:rgba(100,116,139,.12);color:#475569}
.rc-dead{color:var(--muted)}
.rc-legend{font-size:11.5px;color:var(--muted);margin-top:14px}
.rc-foot{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
@media print{.top-toolbar{display:none} .rc-table tr{break-inside:avoid}}
"""


@dataclass
class HostInfo:
    host: str
    ips: List[str] = field(default_factory=list)
    scheme: str = ""
    status: int = 0
    server: str = ""
    title: str = ""
    tech: List[str] = field(default_factory=list)
    tls_trusted: Optional[bool] = None
    tls_days: Optional[int] = None
    findings: int = 0
    critical: int = 0
    high: int = 0
    score: Optional[int] = None
    grade: str = ""
    error: str = ""

    @property
    def live(self) -> bool:
        return self.status > 0

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}" if self.scheme else f"https://{self.host}"


@dataclass
class ReconResult:
    domain: str
    started: float
    hosts: List[HostInfo] = field(default_factory=list)
    sources: Dict[str, int] = field(default_factory=dict)
    discovered: List[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def live_hosts(self) -> List[HostInfo]:
        return [h for h in self.hosts if h.live]

    @property
    def risky(self) -> List[HostInfo]:
        return [h for h in self.hosts if h.critical or h.high]

    @property
    def expiring(self) -> List[HostInfo]:
        return [h for h in self.hosts if h.tls_days is not None and h.tls_days < 30]


# ---------------------------------------------------------------- discovery
_HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _valid_name(name: str) -> bool:
    """crt.sh returns subject email addresses too — they are not hostnames."""
    if not name or "@" in name or "*" in name or " " in name:
        return False
    return bool(_HOSTNAME_RE.match(name))


def crt_sh(domain: str, http: Http, attempts: int = 3) -> Set[str]:
    """Certificate transparency: every name that ever got a certificate.

    crt.sh rate-limits hard and sometimes answers 200 with an empty body, so a
    single call is not trustworthy. Retry a couple of times before giving up.
    """
    out: Set[str] = set()
    for attempt in range(attempts):
        resp = http.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                        timeout=30, limit=8_000_000)
        if resp.status == 200 and resp.text.strip():
            try:
                rows = json.loads(resp.text)
            except Exception:  # noqa: BLE001
                rows = []
            for row in rows:
                for name in str(row.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and name != domain and _valid_name(name):
                        out.add(name)
            if out:
                return out
        if attempt < attempts - 1:
            time.sleep(2 + attempt * 2)
    return out


def dns_brute(domain: str, words: List[str], threads: int = 16) -> Set[str]:
    """Resolve a small candidate list. Cheap because failures are instant."""
    found: Set[str] = set()

    def probe(prefix: str) -> Optional[str]:
        candidate = f"{prefix}.{domain}"
        try:
            return candidate if resolve_host(candidate) else None
        except Exception:  # noqa: BLE001
            return None

    with _futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for result in pool.map(probe, words):
            if result:
                found.add(result)
    return found


# ---------------------------------------------------------------- fingerprint
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_TECH_HINTS = [
    ("WordPress", ("wp-content", "wp-includes", 'name="generator" content="WordPress')),
    ("Drupal", ("drupal", "sites/default/files")),
    ("Joomla", ("/media/jui/", "joomla")),
    ("Shopify", ("cdn.shopify.com", "shopify")),
    ("Next.js", ("__next_data__", "/_next/static")),
    ("React", ("react-dom", "data-reactroot", "__react")),
    ("Vue", ("vue.js", "data-v-", "__vue__")),
    ("Angular", ("ng-version", "angular.min.js")),
    ("jQuery", ("jquery",)),
    ("Bootstrap", ("bootstrap.min.css", "bootstrap.js")),
    ("Cloudflare", ("cloudflare", "cf-ray")),
    ("Nginx", ("nginx",)),
    ("Apache", ("apache",)),
    ("IIS", ("microsoft-iis", "iis")),
    ("PHP", ("x-powered-by: php", "phpsessid")),
    ("ASP.NET", ("asp.net", "x-aspnet-version")),
    ("Java", ("jsessionid", "x-powered-by: servlet")),
]


def _detect_tech(resp, body_low: str) -> List[str]:
    haystack = body_low + " " + " ".join(
        f"{k.lower()}: {v.lower()}" for k, v in resp.headers.items()
    )
    found = []
    for name, hints in _TECH_HINTS:
        if any(h in haystack for h in hints):
            found.append(name)
    return found[:6]


def fingerprint(host: str, http: Http, do_tls: bool = True) -> HostInfo:
    info = HostInfo(host=host)
    try:
        info.ips = resolve_host(host)[:4]
    except Exception:  # noqa: BLE001
        pass

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = http.get(url, timeout=12, limit=120_000, allow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            info.error = str(exc)[:120]
            continue
        if not resp.status:
            continue
        info.scheme = scheme
        info.status = resp.status
        info.server = resp.header("server")[:60]
        body = resp.text or ""
        match = _TITLE_RE.search(body)
        if match:
            info.title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:90]
        info.tech = _detect_tech(resp, body.lower())
        break

    if do_tls and info.scheme == "https":
        try:
            tls = inspect_tls(host, timeout=8)
            info.tls_trusted = tls.trusted
            info.tls_days = tls.days_left
        except Exception:  # noqa: BLE001
            pass
    return info


# ---------------------------------------------------------------- scanning
def scan_host(host: HostInfo, profile: str = "fast", out_dir: str = "") -> None:
    """Run Sentwall against one host and fold the result back in."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scan_py = os.path.join(root, "scan.py")
    tmp = out_dir or tempfile.mkdtemp(prefix="sentwall-recon-")
    cmd = [
        sys.executable, scan_py, host.url,
        "--authorized", "--profile", profile, "--quiet",
        "--formats", "json", "--out", tmp,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=900, check=False)
    except Exception as exc:  # noqa: BLE001
        host.error = f"scan failed: {exc}"
        return

    newest = ""
    for base, _dirs, files in os.walk(tmp):
        for name in files:
            if name == "report.json":
                path = os.path.join(base, name)
                if path > newest:
                    newest = path
    if not newest:
        return
    try:
        with open(newest, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return
    host.findings = len(data.get("findings", []))
    counts = data.get("counts", {}) or {}
    host.critical = int(counts.get("critical", 0))
    host.high = int(counts.get("high", 0))
    host.score = data.get("risk_score")
    host.grade = str(data.get("grade", ""))


# ---------------------------------------------------------------- orchestrate
def run(
    domain: str,
    http: Optional[Http] = None,
    use_crt: bool = True,
    use_brute: bool = True,
    wordlist: Optional[List[str]] = None,
    threads: int = 12,
    do_tls: bool = True,
    do_scan: bool = False,
    max_scan: int = 10,
    profile: str = "fast",
    log=None,
) -> ReconResult:
    log = log or (lambda *a, **k: None)
    http = http or Http(timeout=12, delay=0.0)
    started = time.time()
    domain = registrable_domain(domain) or domain
    result = ReconResult(domain=domain, started=started)

    names: Set[str] = set()
    if use_crt:
        crt = crt_sh(domain, http)
        result.sources["certificate transparency"] = len(crt)
        if crt:
            log(f"  certificate transparency: {len(crt)} name(s)", "ok")
        else:
            log("  certificate transparency returned nothing (crt.sh rate limit?)", "warn")
        names |= crt
    if use_brute:
        words = wordlist or COMMON_PREFIXES
        brute = dns_brute(domain, words, threads=min(32, threads * 2))
        result.sources["dns brute force"] = len(brute)
        log(f"  dns brute force: {len(brute)} name(s)", "ok")
        names |= brute

    names.add(domain)
    result.discovered = sorted(names)
    log(f"  {len(names)} unique name(s) to fingerprint", "ok")

    with _futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(fingerprint, h, http, do_tls): h for h in result.discovered}
        for fut in _futures.as_completed(futures):
            try:
                result.hosts.append(fut.result())
            except Exception:  # noqa: BLE001
                result.hosts.append(HostInfo(host=futures[fut], error="fingerprint failed"))

    result.hosts.sort(key=lambda h: (not h.live, h.host))
    live = result.live_hosts
    log(f"  {len(live)} live host(s) of {len(result.hosts)}", "ok")

    if do_scan and live:
        targets = sorted(live, key=lambda h: -h.tls_days if h.tls_days is not None else 0)
        targets = live[:max_scan]
        log(f"  scanning {len(targets)} host(s) with profile '{profile}'", "ok")
        for i, host in enumerate(targets, 1):
            log(f"    [{i}/{len(targets)}] {host.host}", "")
            scan_host(host, profile=profile)

    result.elapsed = time.time() - started
    return result


# ---------------------------------------------------------------- markdown
def render_markdown(result: ReconResult) -> str:
    lines: List[str] = []
    add = lines.append
    add(f"# External Attack Surface — {result.domain}")
    add("")
    add(f"**Generated:** {_dt.datetime.fromtimestamp(result.started).strftime('%d %B %Y, %H:%M')}  ")
    add(f"**Names discovered:** {len(result.discovered)} · "
        f"**Live hosts:** {len(result.live_hosts)} · "
        f"**With high/critical findings:** {len(result.risky)}")
    add("")
    add("| Host | IP | Status | Server | Title | TLS | Crit | High |")
    add("|---|---|---|---|---|---|---|---|")
    for h in result.hosts:
        if not h.live:
            continue
        tls = "—" if h.tls_days is None else f"{h.tls_days}d"
        add(f"| `{h.host}` | {h.ips[0] if h.ips else '—'} | {h.status} | "
            f"{h.server or '—'} | {(h.title or '—')[:40]} | {tls} | {h.critical} | {h.high} |")
    add("")
    dead = [h.host for h in result.hosts if not h.live]
    if dead:
        add(f"**Not responding ({len(dead)}):** " + ", ".join(f"`{d}`" for d in dead[:60]))
        add("")
    add("## How this was built")
    add("")
    for source, count in result.sources.items():
        add(f"- {source}: {count} name(s)")
    add("")
    return "\n".join(lines)


# ---------------------------------------------------------------- html
def _pill(host: HostInfo) -> str:
    if not host.live:
        return '<span class="rc-pill mute">no response</span>'
    if host.critical:
        return f'<span class="rc-pill bad">{host.critical} critical</span>'
    if host.high:
        return f'<span class="rc-pill warn">{host.high} high</span>'
    if host.findings:
        return f'<span class="rc-pill mute">{host.findings} finding(s)</span>'
    if host.score is not None:
        return '<span class="rc-pill ok">clean</span>'
    return '<span class="rc-pill mute">not scanned</span>'


def _tls_cell(host: HostInfo) -> str:
    if host.tls_days is None:
        return '<span class="rc-mono">—</span>'
    if host.tls_trusted is False:
        return '<span class="rc-pill bad">untrusted</span>'
    if host.tls_days < 0:
        return '<span class="rc-pill bad">expired</span>'
    if host.tls_days < 30:
        return f'<span class="rc-pill warn">{host.tls_days}d left</span>'
    return f'<span class="rc-mono">{host.tls_days}d</span>'


def _plural(n: int, singular: str, plural: str = "") -> str:
    word = singular if n == 1 else (plural or singular + "s")
    return f"{n} {word}"


def render_html(result: ReconResult) -> str:
    live = result.live_hosts
    rows = ""
    for h in result.hosts:
        if not h.live:
            continue
        tech = ", ".join(h.tech[:3]) or "—"
        rows += f"""<tr>
  <td class="rc-host">{E(h.host)}</td>
  <td class="rc-mono">{E(h.ips[0] if h.ips else '—')}</td>
  <td class="rc-mono">{h.status} {E(h.scheme)}</td>
  <td class="rc-mono">{E(h.server or '—')}</td>
  <td><span class="rc-title" title="{E(h.title)}">{E(h.title or '—')}</span>
      <span class="rc-mono">{E(tech)}</span></td>
  <td>{_tls_cell(h)}</td>
  <td>{_pill(h)}</td>
</tr>"""

    dead = [h.host for h in result.hosts if not h.live]
    dead_block = ""
    if dead:
        names = "".join(f"<code>{E(d)}</code> " for d in dead[:80])
        dead_block = f"""
<section>
  <div class="sec-head"><h2>Names with no response ({len(dead)})</h2></div>
  <p style="font-size:12px;color:var(--muted);line-height:1.9">{names}</p>
</section>"""

    sources = "".join(
        f"<li>{E(k)}: <b>{v}</b> name(s)</li>" for k, v in result.sources.items()
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack surface — {E(result.domain)}</title>
<style>{BASE_CSS}{RECON_CSS}</style></head>
<body><div class="wrap">

<div class="top-toolbar">
  <div class="brand"><span class="dot"></span>Sentwall Recon</div>
  <div class="actions-bar"><button class="btn btn-primary" onclick="window.print()">Print / PDF</button></div>
</div>

<header class="rc-head">
  <div class="rc-kicker">External attack surface</div>
  <h1>{E(result.domain)}</h1>
  <div class="rc-sub">{_plural(len(result.discovered), "name")} discovered · {_plural(len(live), "responding host", "responding hosts")}</div>
</header>

<div class="rc-stats">
  <div class="rc-stat total"><div class="n">{len(result.discovered)}</div><div class="l">Names found</div></div>
  <div class="rc-stat live"><div class="n">{len(live)}</div><div class="l">Live hosts</div></div>
  <div class="rc-stat risk"><div class="n">{len(result.risky)}</div><div class="l">With crit / high</div></div>
  <div class="rc-stat expiring"><div class="n">{len(result.expiring)}</div><div class="l">Cert &lt; 30 days</div></div>
</div>

<section>
  <div class="sec-head"><h2>Live hosts</h2></div>
  <table class="rc-table">
    <thead><tr><th>Host</th><th>IP</th><th>Status</th><th>Server</th>
    <th>Title / stack</th><th>TLS</th><th>Findings</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="7" class="rc-mono">No responding hosts.</td></tr>'}</tbody>
  </table>
  <p class="rc-legend">Findings columns are only populated when the run used <code>--scan</code>.
  Every host listed here answered on HTTP or HTTPS; names that did not resolve are listed below.</p>
</section>

{dead_block}

<section>
  <div class="sec-head"><h2>How this was built</h2></div>
  <ul style="font-size:12.5px;color:var(--body)">{sources}
    <li>Each name was then resolved and requested over HTTPS, falling back to HTTP.</li>
  </ul>
</section>

<div class="rc-foot">
  Generated {_dt.datetime.fromtimestamp(result.started).strftime('%d %B %Y, %H:%M')} in
  {result.elapsed:.1f}s · passive discovery plus light active probing only ·
  no exploitation was attempted at this stage.
</div>

</div></body></html>"""


# ---------------------------------------------------------------- export
def to_dict(result: ReconResult) -> dict:
    return {
        "domain": result.domain,
        "started": _dt.datetime.fromtimestamp(result.started).isoformat(),
        "elapsed_seconds": round(result.elapsed, 1),
        "sources": result.sources,
        "discovered_count": len(result.discovered),
        "hosts": [
            {
                "host": h.host,
                "ips": h.ips,
                "scheme": h.scheme,
                "status": h.status,
                "server": h.server,
                "title": h.title,
                "tech": h.tech,
                "tls_trusted": h.tls_trusted,
                "tls_days": h.tls_days,
                "findings": h.findings,
                "critical": h.critical,
                "high": h.high,
                "risk_score": h.score,
                "grade": h.grade,
            }
            for h in result.hosts
        ],
    }


def to_csv(result: ReconResult) -> str:
    head = "host,ip,scheme,status,server,title,tech,tls_trusted,tls_days,findings,critical,high,grade"
    rows = [head]
    for h in result.hosts:
        title = (h.title or "").replace('"', "'").replace(",", " ")
        rows.append(",".join([
            h.host,
            h.ips[0] if h.ips else "",
            h.scheme,
            str(h.status or ""),
            f'"{h.server}"',
            f'"{title}"',
            f'"{" ".join(h.tech)}"',
            "" if h.tls_trusted is None else str(h.tls_trusted).lower(),
            "" if h.tls_days is None else str(h.tls_days),
            str(h.findings),
            str(h.critical),
            str(h.high),
            h.grade,
        ]))
    return "\n".join(rows)


def write_reports(result: ReconResult, out_dir: str,
                  formats: tuple = ("html", "md", "json", "csv")) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = _dt.datetime.fromtimestamp(result.started).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9.\-_]", "-", result.domain.lower())
    base = os.path.join(out_dir, f"recon-{safe}-{stamp}")
    written: List[str] = []
    if "html" in formats:
        path = base + ".html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(result))
        written.append(path)
    if "md" in formats:
        path = base + ".md"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(result))
        written.append(path)
    if "json" in formats:
        path = base + ".json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(to_dict(result), fh, indent=2, ensure_ascii=False)
        written.append(path)
    if "csv" in formats:
        path = base + ".csv"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_csv(result))
        written.append(path)
    return written
