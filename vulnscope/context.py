"""Shared scan context passed to every check."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .crawl import PageData
from .net import Http, inspect_tls, registrable_domain, resolve_host
from .models import Finding


@dataclass
class Options:
    deep: bool = False
    test_forms: bool = False
    subdomains: bool = False
    max_pages: int = 25
    depth: int = 2
    delay: float = 0.0
    timeout: float = 12.0
    threads: int = 8
    skip: List[str] = field(default_factory=list)


class ScanContext:
    def __init__(
        self,
        target: str,
        base_url: str,
        host: str,
        http: Http,
        options: Options,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.target = target
        self.base_url = base_url
        self.host = host
        self.domain = registrable_domain(host)
        self.http = http
        self.options = options
        self.pages: List[PageData] = []
        self.meta: Dict[str, Any] = {}
        self.log = logger or (lambda msg: None)
        self._dns_cache: Dict[str, List[str]] = {}
        self._ips: Optional[List[str]] = None
        self._tls = None

    # ------------------------------------------------------------------ dns
    def ips(self) -> List[str]:
        if self._ips is None:
            self._ips = resolve_host(self.host)
            self.meta["ip_addresses"] = self._ips
        return self._ips

    def dns(self, name: str, qtype: str = "A") -> List[str]:
        key = f"{name}|{qtype}"
        if key not in self._dns_cache:
            from .net import dns_query

            self._dns_cache[key] = dns_query(name, qtype)
        return self._dns_cache[key]

    # ------------------------------------------------------------------ tls
    def tls(self):
        if self._tls is None:
            if self.base_url.startswith("https://"):
                self._tls = inspect_tls(self.host, 443, self.options.timeout)
            else:
                self._tls = inspect_tls(self.host, 443, self.options.timeout)
        return self._tls

    # ---------------------------------------------------------------- pages
    def homepage(self) -> Optional[PageData]:
        return self.pages[0] if self.pages else None

    def add_meta(self, key: str, value: Any) -> None:
        self.meta[key] = value
