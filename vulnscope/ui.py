"""VulnScope Terminal UI Engine.

Zero-dependency, pure Python terminal styling system featuring:
- Automatic Windows VT100 / Virtual Terminal Processing enablement.
- 24-bit TrueColor / ANSI styling and color presets.
- Rounded Unicode box-drawing cards and structured tables.
- Gradient banners, status chips, severity badges, and progress bars.
- Executive summary posture dashboard and artifact directory tree.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Windows VT100 / Virtual Terminal Support
# ---------------------------------------------------------------------------

def _enable_windows_vt() -> bool:
    """Enable VT100 and 24-bit ANSI colors in Windows cmd.exe / PowerShell."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h_out = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if h_out == -1 or h_out == 0:
            return False
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) | ENABLE_PROCESSED_OUTPUT (0x0001)
        new_mode = mode.value | 0x0004 | 0x0001
        kernel32.SetConsoleMode(h_out, new_mode)
        return True
    except Exception:
        return False

VT_ENABLED = _enable_windows_vt()
COLOR_ACTIVE = (sys.stdout.isatty() or VT_ENABLED) and os.environ.get("NO_COLOR") is None

# ---------------------------------------------------------------------------
# Color and Style Helpers
# ---------------------------------------------------------------------------

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[mK]")

def strip_ansi(s: str) -> str:
    """Return string with all ANSI escape sequences removed."""
    return ANSI_PATTERN.sub("", s)

def visual_len(s: str) -> int:
    """Calculate terminal visible character width of string."""
    clean = strip_ansi(s)
    # Emojis like 🛡️ or ⚡ may occupy 1-2 columns, strip variation selectors
    clean = clean.replace("\ufe0f", "")
    return len(clean)

def rgb(r: int, g: int, b: int, text: str) -> str:
    if not COLOR_ACTIVE:
        return text
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"

def bg_rgb(r: int, g: int, b: int, text: str) -> str:
    if not COLOR_ACTIVE:
        return text
    return f"\033[48;2;{r};{g};{b}m{text}\033[0m"

def bold(text: str) -> str:
    return f"\033[1m{text}\033[0m" if COLOR_ACTIVE else text

def dim(text: str) -> str:
    return f"\033[2m{text}\033[0m" if COLOR_ACTIVE else text

def italic(text: str) -> str:
    return f"\033[3m{text}\033[0m" if COLOR_ACTIVE else text

# Color Palette (Modern Cyber Dark Theme)
def c_cyan(t: str) -> str: return rgb(6, 182, 212, t)
def c_green(t: str) -> str: return rgb(16, 185, 129, t)
def c_emerald(t: str) -> str: return rgb(52, 211, 153, t)
def c_yellow(t: str) -> str: return rgb(245, 158, 11, t)
def c_orange(t: str) -> str: return rgb(249, 115, 22, t)
def c_red(t: str) -> str: return rgb(239, 68, 68, t)
def c_purple(t: str) -> str: return rgb(168, 85, 247, t)
def c_blue(t: str) -> str: return rgb(59, 130, 246, t)
def c_slate(t: str) -> str: return rgb(148, 163, 184, t)
def c_dark(t: str) -> str: return rgb(71, 85, 105, t)
def c_white(t: str) -> str: return rgb(248, 250, 252, t)

# ---------------------------------------------------------------------------
# Badges & Severity Chips
# ---------------------------------------------------------------------------

def badge_severity(sev: Severity) -> str:
    """Format severity as a bold, color-blocked badge."""
    if not COLOR_ACTIVE:
        return f"[{sev.value.upper()}]"
    if sev == Severity.CRITICAL:
        return "\033[48;2;185;28;28;97;1m CRITICAL \033[0m"
    if sev == Severity.HIGH:
        return "\033[48;2;194;65;12;97;1m   HIGH   \033[0m"
    if sev == Severity.MEDIUM:
        return "\033[48;2;217;119;6;97;1m  MEDIUM  \033[0m"
    if sev == Severity.LOW:
        return "\033[48;2;29;78;216;97;1m   LOW    \033[0m"
    return "\033[48;2;71;85;105;97;1m   INFO   \033[0m"

def chip_severity(sev: Severity) -> str:
    """Compact chip for tabular lists."""
    if not COLOR_ACTIVE:
        return f"[{sev.value.upper()[:4]}]"
    if sev == Severity.CRITICAL:
        return "\033[48;2;185;28;28;97;1m CRIT \033[0m"
    if sev == Severity.HIGH:
        return "\033[48;2;194;65;12;97;1m HIGH \033[0m"
    if sev == Severity.MEDIUM:
        return "\033[48;2;217;119;6;97;1m MED  \033[0m"
    if sev == Severity.LOW:
        return "\033[48;2;29;78;216;97;1m LOW  \033[0m"
    return "\033[48;2;71;85;105;97;1m INFO \033[0m"

# ---------------------------------------------------------------------------
# Box Drawing Card Engine
# ---------------------------------------------------------------------------

def draw_card(
    title: str,
    lines: List[str],
    border_color: str = "cyan",
    min_width: int = 76,
) -> str:
    """Render a rounded Unicode container card with aligned borders."""
    c_fn = {
        "cyan": c_cyan,
        "green": c_green,
        "yellow": c_yellow,
        "red": c_red,
        "purple": c_purple,
        "slate": c_slate,
        "dark": c_dark,
    }.get(border_color, c_cyan)

    max_content = max([visual_len(line) for line in lines] + [visual_len(title) + 6, min_width])
    width = max_content + 4

    # Top border with title
    if title:
        title_clean = f" {title.strip()} "
        t_len = visual_len(title_clean)
        top_dashes = width - 4 - t_len
        top_dashes = max(2, top_dashes)
        top_line = c_fn("╭─ ") + bold(c_white(title_clean)) + c_fn("─" * top_dashes + "╮")
    else:
        top_line = c_fn("╭" + "─" * (width - 2) + "╮")

    body: List[str] = []
    for line in lines:
        vlen = visual_len(line)
        pad = width - 4 - vlen
        pad = max(0, pad)
        body.append(f"{c_fn('│')}  {line}{' ' * pad}{c_fn('│')}")

    bot_line = c_fn("╰" + "─" * (width - 2) + "╯")
    return "\n".join([top_line] + body + [bot_line])

# ---------------------------------------------------------------------------
# Visual Components
# ---------------------------------------------------------------------------

def render_banner(version: str = "1.0.0") -> str:
    """Render dual-tone hacker cyberpunk ASCII banner."""
    raw_lines = [
        r" __     __      _       ____                      ",
        r" \ \   / /_   _| |_ __ / ___|  ___ ___  _ __   ___ ",
        r"  \ \ / /| | | | | '_ \\___ \ / __/ _ \| '_ \ / _ " + "\\",
        r"   \ V / | |_| | | | | |___) | (_| (_) | |_) |  __/",
        r"    \_/   \__,_|_|_| |_|____/ \___\___/| .__/ \___|",
        r"                                       |_|         ",
    ]

    out = []
    out.append("")
    # Two-tone gradient transition
    colors = [
        (6, 182, 212),
        (20, 184, 166),
        (16, 185, 129),
        (34, 197, 94),
        (52, 211, 153),
        (110, 231, 183),
    ]
    for idx, line in enumerate(raw_lines):
        r, g, b = colors[min(idx, len(colors) - 1)]
        out.append("  " + bold(rgb(r, g, b, line)))

    sub = (
        f"  {c_emerald('⚡')} {bold(c_white('VULNSCOPE ENTERPRISE'))} "
        f"{c_dark('•')} {c_slate('Autonomous Web Security & Threat Audit Engine')} "
        f"{c_dark('•')} {c_cyan('v' + version)}"
    )
    badge_line = (
        f"  {c_dark('└─▶')} {c_slate('Scope: 15 Audit Modules')} "
        f"{c_dark('•')} {c_slate('Zero Cloud Leakage')} "
        f"{c_dark('•')} {c_green('Private Local Ops')}"
    )
    out.append(sub)
    out.append(badge_line)
    out.append("")
    return "\n".join(out)


def render_legal_prompt(target: str) -> str:
    """Render legal authorisation warning box."""
    lines = [
        f"{c_yellow('⚠ LEGAL NOTICE & RULES OF ENGAGEMENT')}",
        "",
        f"Target Coordinate: {bold(c_white(target))}",
        "Active automated vulnerability scans and exploit probes will be executed.",
        "Unauthorised scanning is illegal under Computer Misuse Act, CFAA, and ICT Act.",
        "",
        f"{bold(c_white('Only proceed if you own this system or hold signed authorization.'))}",
    ]
    return draw_card("AUTHORISATION DIRECTIVE", lines, border_color="yellow", min_width=72)


def render_target_card(
    target: str,
    ips: List[str],
    profile: str,
    is_deep: bool,
    subdomains: bool,
    forms: bool,
    threads: int,
) -> str:
    """Render the assessment configuration card."""
    ip_str = ", ".join(ips) if ips else c_red("Unresolved")
    flags = [profile.upper()]
    if is_deep:
        flags.append("DEEP BLIND PROBES")
    if subdomains:
        flags.append("SUBDOMAIN TAKEOVER")
    if forms:
        flags.append("FORM CANARY INJECTION")

    lines = [
        f"{c_slate('Target URL  :')} {bold(c_cyan(target))}",
        f"{c_slate('Resolved IP :')} {c_white(ip_str)}",
        f"{c_slate('Scan Profile:')} {c_green(' + '.join(flags))}",
        f"{c_slate('Concurrency :')} {c_white(str(threads))} worker threads {c_dark('•')} Timeout: 12.0s",
    ]
    return draw_card("ATTACK SURFACE TARGET", lines, border_color="cyan", min_width=74)


def render_progress_bar(score: int, width: int = 24) -> str:
    """Render color-coded filled score progress bar."""
    filled = int(round((score / 100.0) * width))
    filled = max(0, min(width, filled))
    empty = width - filled

    if score >= 85:
        bar_color = c_green
    elif score >= 70:
        bar_color = c_emerald
    elif score >= 50:
        bar_color = c_yellow
    elif score >= 30:
        bar_color = c_orange
    else:
        bar_color = c_red

    bar = bar_color("█" * filled) + c_dark("░" * empty)
    return f"[{bar}] {bold(c_white(str(score)))}/100"


def render_summary_dashboard(result: ScanResult) -> str:
    """Render comprehensive executive posture scorecard."""
    score = result.risk_score()
    grade = result.grade()
    verdict = result.grade_verdict()
    fin = result.financial_risk()
    counts = result.counts()

    grade_colors = {
        "A+": c_green, "A": c_green, "B": c_emerald,
        "C": c_yellow, "D": c_orange, "F": c_red,
    }
    g_fn = grade_colors.get(grade, c_white)

    # Findings pills
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)
    info = counts.get("info", 0)

    pills = (
        f"{c_red(bold(f'CRITICAL: {crit}'))}  {c_dark('│')}  "
        f"{c_orange(bold(f'HIGH: {high}'))}  {c_dark('│')}  "
        f"{c_yellow(bold(f'MEDIUM: {med}'))}  {c_dark('│')}  "
        f"{c_blue(bold(f'LOW: {low}'))}  {c_dark('│')}  "
        f"{c_slate(f'INFO: {info}')}"
    )

    lines = [
        f"{bold(c_white('OVERALL SECURITY POSTURE :'))}  {render_progress_bar(score)}   {bold(g_fn(f'GRADE {grade}'))}",
        f"{c_slate('Status Assessment         :')}  {g_fn(verdict)}",
        "",
        f"{bold(c_white('OBSERVED VULNERABILITIES :'))}  {pills}",
        "",
        f"{c_slate('Breach Exposure Impact   :')}  "
        f"{c_yellow(str(fin['breach_probability_pct']) + '% probability')} {c_dark('•')} "
        f"{c_red('$' + f'{fin['estimated_financial_loss_usd']:,}' + ' USD')} estimated financial risk",
        f"{c_slate('Scan Telemetry Duration  :')}  "
        f"{c_white(str(result.requests_made))} requests {c_dark('•')} "
        f"{c_white(str(len(result.pages_scanned)))} pages crawled {c_dark('•')} "
        f"{c_emerald(f'{result.duration:.1f}s')} elapsed",
    ]

    border = "green" if grade in ("A+", "A") else ("yellow" if grade in ("B", "C") else "red")
    return draw_card("EXECUTIVE SECURITY POSTURE", lines, border_color=border, min_width=76)


def format_module_result(i: int, total: int, label: str, findings: List[Finding], took: float) -> str:
    """Format single check module completion with hacker status badge."""
    step_str = c_dark(f"[{i:02d}/{total:02d}]")
    clean_lbl = label[:36]
    lbl_pad = max(0, 38 - visual_len(clean_lbl))
    lbl_str = bold(c_white(clean_lbl)) + (" " * lbl_pad)

    if not findings:
        status_str = c_green("✔ Clean")
    else:
        crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        highs = sum(1 for f in findings if f.severity == Severity.HIGH)
        if crits > 0:
            badge = f"🔥 {crits} CRITICAL" + (f", {highs} H" if highs else "")
            status_str = c_red(bold(badge))
        elif highs > 0:
            badge = f"⚡ {highs} HIGH" + (f", +{len(findings)-highs}" if len(findings) > highs else "")
            status_str = c_orange(bold(badge))
        else:
            status_str = c_yellow(f"⚠ {len(findings)} issue(s)")

    stat_pad = max(0, 22 - visual_len(status_str))
    took_str = c_dark(f"({took:.2f}s)")
    return f"  {step_str} 🔎 {lbl_str} {status_str}{' ' * stat_pad} {took_str}"


def render_findings_table(findings: List[Finding], limit: int = 8) -> str:
    """Render top prioritized findings in a clean table format."""
    if not findings:
        return draw_card("VULNERABILITIES IDENTIFIED", [c_green("✔ Zero security vulnerabilities detected.")], border_color="green")

    top = findings[:limit]
    lines: List[str] = [
        f"{c_dark('# ')} {c_slate('SEV ')} {c_slate('FINDING TITLE' + ' ' * 27)} {c_slate('CWE        ')} {c_slate('CVSS')} {c_slate('EST. FIX EFFORT')}",
        c_dark("─" * 74),
    ]

    effort_map = {
        "quick": "Quick (<1 hr)",
        "moderate": "Moderate (half-day)",
        "involved": "Involved (1-3 days)",
        "rearchitect": "Major (architecture)",
    }

    for idx, f in enumerate(top, 1):
        num = c_dark(f"{idx:02d}")
        chip = chip_severity(f.severity)

        # Title truncation
        raw_title = f.title
        if len(raw_title) > 36:
            raw_title = raw_title[:33] + "..."
        t_pad = max(0, 37 - visual_len(raw_title))
        title_styled = bold(c_white(raw_title)) + (" " * t_pad)

        cwe_str = (f.cwe or "CWE-N/A").split(":")[0]
        cwe_pad = max(0, 10 - len(cwe_str))
        cwe_styled = c_slate(cwe_str) + (" " * cwe_pad)

        cvss_styled = c_red(f"{f.cvss:.1f}") if f.cvss >= 7.0 else (c_yellow(f"{f.cvss:.1f}") if f.cvss >= 4.0 else c_slate(f"{f.cvss:.1f}"))
        effort = c_slate(effort_map.get(f.effort, f.effort_label[:14]))

        lines.append(f"{num} {chip} {title_styled} {cwe_styled} {cvss_styled}  {effort}")

    if len(findings) > limit:
        lines.append(c_dark("─" * 74))
        lines.append(c_slate(f"... and {len(findings) - limit} additional observations documented in report files."))

    return draw_card(f"TOP PRIORITIZED VULNERABILITIES ({len(findings)} TOTAL)", lines, border_color="yellow", min_width=76)


def render_delta_card(diff: Any) -> str:
    """Render Before vs After remediation delta comparison card."""
    delta_color = c_green if diff.score_change < 0 else (c_red if diff.score_change > 0 else c_white)
    lines = [
        f"{c_slate('Target Coordinate :')} {bold(c_white(diff.target))}",
        f"{c_slate('Baseline Posture  :')} {c_white(str(diff.baseline_score))}/100 (Grade {diff.baseline_grade})",
        f"{c_slate('Current Posture   :')} {c_white(str(diff.current_score))}/100 (Grade {diff.current_grade})",
        f"{c_slate('Risk Posture Delta:')} {bold(delta_color(f'{diff.score_change:+d} points'))}",
        "",
        f"{c_green(bold(f'✔ Resolved Vulnerabilities : {len(diff.resolved)} fixed'))}",
        f"{c_yellow(f'⚠ Persistent Weaknesses    : {len(diff.persistent)} open')}",
        f"{c_red(f'✖ Newly Introduced Bugs    : {len(diff.new_findings)} new') if diff.new_findings else c_slate('✖ Newly Introduced Bugs    : 0')}",
        "",
        f"{c_slate('Remediation Verdict:')} {bold(c_white(diff.verdict))}",
    ]
    return draw_card("REMEDIATION DELTA AUDIT REPORT", lines, border_color="green" if diff.score_change <= 0 else "red", min_width=74)


def render_top_poc_spotlight(finding: Finding, target_base: str) -> Optional[str]:
    """Spotlight the #1 most dangerous vulnerability with instant PoC."""
    if finding.severity.rank < 3:
        return None  # Only spotlight critical / high vulnerabilities

    poc_curl = finding.get_poc_curl(target_base)
    remediation_preview = finding.remediation.split("\n")[0] if finding.remediation else "Apply input validation & principle of least privilege."
    if len(remediation_preview) > 68:
        remediation_preview = remediation_preview[:65] + "..."

    lines = [
        f"{c_red('Vulnerability :')} {bold(c_white(finding.title))}",
        f"{c_slate('Severity Level:')} {badge_severity(finding.severity)} {c_dark('•')} CVSS {c_red(str(finding.cvss))} {c_dark('•')} {finding.owasp or 'OWASP Top 10'}",
        f"{c_slate('Threat Impact :')} {c_white(finding.impact or 'Unauthenticated compromise or data exposure.')}",
        "",
        f"{bold(c_yellow('⚡ Instant PoC Verification Command:'))}",
        f"  {c_cyan(poc_curl)}",
        "",
        f"{bold(c_green('🛡️ Recommended Fix:'))}",
        f"  {c_slate(remediation_preview)}",
    ]
    return draw_card("CRITICAL EXPLOIT SPOTLIGHT (1-CLICK VERIFICATION)", lines, border_color="red", min_width=76)


def render_artifacts_tree(paths: List[str]) -> str:
    """Render tree view of domain and date-time organized reports."""
    lines: List[str] = [
        f"{c_emerald('📁 reports/')}",
    ]

    # Find the domain and timestamp folder from paths
    domain = ""
    dt_folder = ""
    file_entries: List[str] = []

    for p in paths:
        norm = p.replace("\\", "/")
        parts = norm.split("/")
        if len(parts) >= 3:
            domain = parts[-3]
            dt_folder = parts[-2]
            file_entries.append(parts[-1])
        else:
            file_entries.append(os.path.basename(p))

    icons = {
        "html": ("🌐", "Interactive Audit Dashboard & Live Fixes"),
        "pdf": ("📄", "Executive Client-Ready PDF Document"),
        "csv": ("📊", "Remediation Tracking Spreadsheet"),
        "sarif": ("🛡️", "OASIS SARIF 2.1.0 (GitHub/GitLab Security)"),
        "json": ("📦", "Raw Machine-Readable Telemetry"),
        "md": ("📝", "Comprehensive Markdown Documentation"),
    }

    if domain and dt_folder:
        lines.append(f"   {c_dark('└──')} {bold(c_cyan(domain))}/")
        lines.append(f"       {c_dark('└──')} {c_yellow(dt_folder)}/")
        prefix = f"           {c_dark('├──')} "
        last_prefix = f"           {c_dark('└──')} "
        for i, fname in enumerate(file_entries):
            ext = fname.split(".")[-1].lower()
            if fname == "proposal.md":
                icon, desc = "📜", "Client SOW & Commercial Engagement Proposal"
            else:
                icon, desc = icons.get(ext, ("📄", "Report Document"))
            curr_prefix = last_prefix if i == len(file_entries) - 1 else prefix
            lines.append(f"{curr_prefix}{icon} {bold(c_white(fname))}  {c_dark('—')} {c_slate(desc)}")
    else:
        for i, fname in enumerate(file_entries):
            lines.append(f"   {c_dark('└──')} 📄 {bold(c_white(fname))}")

    html_path = next((p for p in paths if p.endswith(".html")), "")
    if html_path:
        abs_html = os.path.abspath(html_path).replace("\\", "/")
        lines.append("")
        lines.append(f"{bold(c_white('Open interactive report in browser:'))}")
        lines.append(f"  {c_cyan('file:///' + abs_html)}")

    return draw_card("GENERATED AUDIT ARTIFACTS", lines, border_color="green", min_width=76)
