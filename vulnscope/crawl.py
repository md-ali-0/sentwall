"""Lightweight same-host crawler used to discover pages, parameters and forms."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from .net import Http, Resp


@dataclass
class Form:
    action: str
    method: str = "GET"
    inputs: List[Tuple[str, str]] = field(default_factory=list)  # (name, type)
    has_password: bool = False
    has_file: bool = False

    @property
    def param_names(self) -> List[str]:
        return [n for n, _ in self.inputs if n]


@dataclass
class PageData:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    title: str = ""
    requested_url: str = ""
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    inline_handlers: int = 0
    mixed_content: List[str] = field(default_factory=list)
    external_scripts_no_sri: List[str] = field(default_factory=list)
    password_forms: List[Form] = field(default_factory=list)
    blank_links_noopener: List[str] = field(default_factory=list)

    @property
    def query_params(self) -> List[Tuple[str, str]]:
        return parse_qsl(urlparse(self.url).query, keep_blank_values=True)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.stylesheets: List[str] = []
        self.forms: List[Form] = []
        self.comments: List[str] = []
        self.title = ""
        self.inline_handlers = 0
        self.blank_noopener: List[str] = []
        self._in_title = False
        self._current_form: Optional[Form] = None
        self._in_script = False
        self._script_attrs: Dict[str, str] = {}

    # -- tags ---------------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for key in a:
            if key.startswith("on"):
                self.inline_handlers += 1

        if tag == "title":
            self._in_title = True
        elif tag == "a":
            if a.get("href"):
                self.links.append(a["href"])
            if a.get("target") == "_blank" and "noopener" not in a.get("rel", "") and "noreferrer" not in a.get("rel", ""):
                self.blank_noopener.append(a.get("href", "")[:120])
        elif tag == "script":
            src = a.get("src", "")
            if src:
                self.scripts.append(src)
            self._in_script = True
            self._script_attrs = a
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel and a.get("href"):
                self.stylesheets.append(a["href"])
        elif tag == "form":
            self._current_form = Form(
                action=a.get("action", ""),
                method=(a.get("method") or "GET").upper(),
            )
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            itype = (a.get("type") or "text").lower()
            name = a.get("name") or a.get("id") or ""
            if name:
                self._current_form.inputs.append((name, itype))
            if itype == "password":
                self._current_form.has_password = True
            if itype == "file":
                self._current_form.has_file = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip()[:400])


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def parse_page(url: str, resp: Resp) -> PageData:
    page = PageData(url=url, status=resp.status, headers=resp.headers, text=resp.text)
    if "html" not in resp.content_type and resp.content_type not in ("", "text/plain"):
        return page
    ex = _Extractor()
    try:
        ex.feed(resp.text)
        ex.close()
    except Exception:
        pass
    page.links = [urljoin(url, l) for l in ex.links if not l.startswith(("javascript:", "mailto:", "tel:", "#"))]
    page.scripts = [urljoin(url, s) for s in ex.scripts]
    page.stylesheets = [urljoin(url, s) for s in ex.stylesheets]
    page.forms = [
        Form(
            action=urljoin(url, f.action) if f.action else url,
            method=f.method,
            inputs=f.inputs,
            has_password=f.has_password,
            has_file=f.has_file,
        )
        for f in ex.forms
    ]
    page.password_forms = [f for f in page.forms if f.has_password]
    page.comments = ex.comments
    page.inline_handlers = ex.inline_handlers
    page.blank_links_noopener = ex.blank_noopener
    page.title = (ex.title or "").strip() or (
        _TITLE_RE.search(resp.text).group(1).strip() if _TITLE_RE.search(resp.text) else ""
    )

    if url.startswith("https://"):
        for m in re.finditer(r"""(?:src|href|action)\s*=\s*["'](http://[^"'>\s]+)""", resp.text, re.I):
            page.mixed_content.append(m.group(1))
    return page


def normalise(url: str, base: str = "") -> str:
    """Strip fragment, sort query, drop common noise parameters."""
    if base:
        url = urljoin(base, url)
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path or "/", urlencode(q), ""))


def crawl(http: Http, start: str, max_pages: int = 25, depth: int = 2, log=None) -> List[PageData]:
    """Breadth-first crawl limited to the start host."""
    host = (urlparse(start).hostname or "").lower()
    seen: Set[str] = set()
    pages: List[PageData] = []
    queue: List[Tuple[str, int]] = [(start, 0)]
    seen.add(normalise(start))

    while queue and len(pages) < max_pages:
        url, d = queue.pop(0)
        resp = http.get(url, allow_redirects=True)
        if resp.error or not resp.status:
            if log:
                log(f"  ! could not fetch {url} ({resp.error[:60]})")
            continue
        page = parse_page(resp.url, resp)
        page.requested_url = url
        pages.append(page)
        if log:
            log(f"  [{resp.status}] {resp.url}")
        if d >= depth:
            continue
        candidates = list(page.links)
        # search / filter forms are the most common injection entry points
        for form in page.forms:
            if form.method == "GET" and not form.has_password:
                candidates.append(form.action)
        for link in candidates:
            p = urlsplit(link)
            if p.scheme not in ("http", "https"):
                continue
            if (p.hostname or "").lower() != host:
                continue
            if re.search(r"\.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf|mp4|pdf|zip|rar|gz)$", p.path, re.I):
                continue
            if re.search(r"(logout|signout|delete|remove|unsubscribe|checkout/complete)", p.path, re.I):
                continue
            n = normalise(link)
            if n in seen or len(seen) > max_pages * 6:
                continue
            seen.add(n)
            queue.append((n, d + 1))
    return pages


def collect_params(pages: List[PageData]) -> List[Tuple[str, str, str]]:
    """Unique (page_url, param_name, value) tuples for injection testing."""
    out: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for page in pages:
        param_source = page.url
        if not page.query_params and page.requested_url:
            # the URL redirected and lost its query string - keep the original for testing
            param_source = page.requested_url
        for name, value in parse_qsl(urlparse(param_source).query, keep_blank_values=True):
            key = (urlparse(param_source).path, name)
            if key in seen:
                continue
            seen.add(key)
            out.append((param_source, name, value))
        # GET forms contribute their field names even when the action has no query
        for form in page.forms:
            if form.method != "GET" or form.has_password or form.has_file:
                continue
            for name, itype in form.inputs:
                if itype in ("hidden", "submit", "button", "checkbox", "radio", "file"):
                    continue
                key = (urlparse(form.action).path, name)
                if key in seen:
                    continue
                seen.add(key)
                out.append((form.action, name, ""))
    return out


def inject_param(url: str, name: str, value: str) -> str:
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if any(k == name for k, _ in q):
        new_q = [(k, value if k == name else v) for k, v in q]
    else:
        new_q = q + [(name, value)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(new_q), ""))
