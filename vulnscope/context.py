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
    profile: str = "standard"  # fast, standard, deep, stealth, api, redteam
    check_cloud: bool = True
    check_api: bool = True
    check_secrets: bool = True
    check_waf: bool = True
    check_auth: bool = True
    check_ssrf: bool = True
    rate_limit_probe: bool = False


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
        self.discovered_endpoints: List[str] = []
        self.discovered_tech: List[str] = []
        self.subdomains: List[str] = []
        self.attack_graph: Dict[str, List[Dict[str, Any]]] = {"nodes": [], "links": []}

        # Seed attack surface root node
        self.add_node(self.host, self.host, "target", "active", {"url": self.base_url})

    # ------------------------------------------------------------------ attack graph
    def add_node(self, node_id: str, label: str, node_type: str, status: str = "info", meta: Optional[Dict[str, Any]] = None) -> None:
        """Add a topology node to the attack surface graph."""
        for n in self.attack_graph["nodes"]:
            if n["id"] == node_id:
                if meta:
                    n.setdefault("meta", {}).update(meta)
                return
        self.attack_graph["nodes"].append({
            "id": node_id,
            "label": label,
            "type": node_type,  # target, ip, port, tech, endpoint, vuln, cloud
            "status": status,    # critical, high, medium, low, info, active
            "meta": meta or {},
        })

    def add_link(self, source: str, target: str, label: str = "") -> None:
        """Add a directional link between attack surface nodes."""
        for link in self.attack_graph["links"]:
            if link["source"] == source and link["target"] == target:
                return
        self.attack_graph["links"].append({
            "source": source,
            "target": target,
            "label": label,
        })

    # ------------------------------------------------------------------ dns
    def ips(self) -> List[str]:
        if self._ips is None:
            self._ips = resolve_host(self.host)
            self.meta["ip_addresses"] = self._ips
            for ip in self._ips:
                self.add_node(f"ip:{ip}", ip, "ip", "info")
                self.add_link(self.host, f"ip:{ip}", "resolves_to")
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
            self._tls = inspect_tls(self.host, 443, self.options.timeout)
            if self._tls and getattr(self._tls, "common_name", None):
                self.add_node(f"tls:{self.host}", f"TLS ({self._tls.protocol})", "tls", "info")
                self.add_link(self.host, f"tls:{self.host}", "cert")
        return self._tls

    # ---------------------------------------------------------------- pages
    def homepage(self) -> Optional[PageData]:
        return self.pages[0] if self.pages else None

    def add_meta(self, key: str, value: Any) -> None:
        self.meta[key] = value
