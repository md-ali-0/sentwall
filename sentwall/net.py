"""Low-level networking helpers: HTTP client, DNS resolver, TLS inspection.

Kept dependency-light on purpose: ``requests`` plus the standard library, with
``cryptography`` used only if present (for precise certificate parsing).
"""
from __future__ import annotations

import ipaddress
import random
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

try:  # keep the console clean when scanning hosts with self-signed certs
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

try:  # optional but very nice for certificate details
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 Sentwall/1.0"
)

SAFE_LIMIT = 262144  # bytes read from any single response body


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
@dataclass
class Resp:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    truncated: bool = False
    elapsed: float = 0.0
    history: List[Tuple[int, str]] = field(default_factory=list)
    set_cookie: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";")[0].strip().lower()


class Http:
    """Rate-limited requests wrapper that never follows off-host redirects."""

    def __init__(
        self,
        timeout: float = 12.0,
        delay: float = 0.0,
        verify: bool = False,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.verify = verify
        self.count = 0
        self._lock = threading.Lock()
        self._last = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=1)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            wait = self.delay - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        limit: int = SAFE_LIMIT,
        data: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Resp:
        self._throttle()
        started = time.time()
        with self._lock:
            self.count += 1
        try:
            r = self.session.request(
                method.upper(),
                url,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                data=data,
                params=params,
                headers=headers,
                verify=self.verify,
                stream=True,
            )
        except requests.exceptions.SSLError as exc:
            return Resp(url=url, error=f"TLS error: {exc}", elapsed=time.time() - started)
        except requests.exceptions.RequestException as exc:
            return Resp(url=url, error=str(exc), elapsed=time.time() - started)

        raw = b""
        truncated = False
        raw_cookies: List[str] = []
        try:
            raw_cookies = list(r.raw.headers.getlist("Set-Cookie"))
        except Exception:
            raw_cookies = []
        try:
            for chunk in r.iter_content(8192):
                raw += chunk
                if len(raw) >= limit:
                    truncated = True
                    break
        except Exception:
            pass
        finally:
            try:
                r.close()
            except Exception:
                pass

        enc = r.encoding or "utf-8"
        try:
            text = raw.decode(enc, errors="replace")
        except Exception:
            text = raw.decode("utf-8", errors="replace")

        return Resp(
            url=r.url,
            status=r.status_code,
            headers={k: v for k, v in r.headers.items()},
            text=text,
            truncated=truncated,
            elapsed=time.time() - started,
            history=[(h.status_code, h.headers.get("location", "")) for h in r.history],
            set_cookie=raw_cookies,
        )

    def get(self, url: str, **kw) -> Resp:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw) -> Resp:
        return self.request("HEAD", url, **kw)

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Minimal DNS client (no dnspython dependency)
# ---------------------------------------------------------------------------
QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257, "DNSKEY": 48, "DS": 43}
TYPE_NAME = {v: k for k, v in QTYPE.items()}

_PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]


def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.strip(".").split("."):
        if not part:
            continue
        try:
            raw = part.encode("idna")
        except Exception:
            raw = part.encode("ascii", "ignore") or b"x"
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _skip_name(buf: bytes, pos: int) -> int:
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length
    return pos


def _read_name(buf: bytes, pos: int, depth: int = 0) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original = pos
    while pos < len(buf) and depth < 12:
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                original = pos + 2
                jumped = True
            pos = pointer
            depth += 1
            continue
        labels.append(buf[pos + 1 : pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    return ".".join(labels), (original if jumped else pos)


def dns_query(name: str, qtype: str = "A", timeout: float = 3.0, server: Optional[str] = None) -> List[str]:
    """Return raw rdata strings for ``name``/``qtype``. Empty list on failure."""
    qid = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(name) + struct.pack(">HH", QTYPE.get(qtype.upper(), 1), 1)

    servers = [server] if server else _PUBLIC_RESOLVERS
    buf = b""
    for srv in servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(packet, (srv, 53))
                buf, _ = s.recvfrom(4096)
            if buf:
                break
        except Exception:
            continue
    if not buf or len(buf) < 12:
        return []

    try:
        _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", buf[:12])
        if flags & 0x000F not in (0, 3):
            return []
        pos = 12
        for _ in range(qdcount):
            pos = _skip_name(buf, pos) + 4
        answers: List[str] = []
        for _ in range(ancount):
            pos = _skip_name(buf, pos)
            if pos + 10 > len(buf):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", buf[pos : pos + 10])
            pos += 10
            rdata = buf[pos : pos + rdlen]
            try:
                if rtype == 1 and rdlen == 4:
                    answers.append(socket.inet_ntoa(rdata))
                elif rtype == 28 and rdlen == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
                elif rtype in (2, 5):
                    answers.append(_read_name(buf, pos)[0])
                elif rtype == 15:
                    pref = struct.unpack(">H", rdata[:2])[0]
                    answers.append(f"{pref} {_read_name(buf, pos + 2)[0]}")
                elif rtype == 16:
                    txt = ""
                    i = 0
                    while i < len(rdata):
                        ln = rdata[i]
                        txt += rdata[i + 1 : i + 1 + ln].decode("utf-8", "replace")
                        i += 1 + ln
                    answers.append(txt)
                elif rtype == 257:
                    answers.append(rdata.decode("utf-8", "replace").strip("\x00"))
            except Exception:
                pass
            pos += rdlen
        return answers
    except Exception:
        return []


def resolve_host(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(host, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


# ---------------------------------------------------------------------------
# TLS inspection
# ---------------------------------------------------------------------------
@dataclass
class TlsInfo:
    reachable: bool = False
    error: str = ""
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    san: List[str] = field(default_factory=list)
    key_bits: Optional[int] = None
    key_type: str = ""
    sig_alg: str = ""
    self_signed: bool = False
    trusted: bool = False
    protocol: str = ""
    cipher: str = ""
    versions: Dict[str, bool] = field(default_factory=dict)
    weak_ciphers: bool = False
    chain_issues: List[str] = field(default_factory=list)


def _parse_cert(der: bytes, info: TlsInfo) -> None:
    if not HAVE_CRYPTO:
        return
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        info.subject = cert.subject.rfc4514_string()
        info.issuer = cert.issuer.rfc4514_string()
        info.self_signed = cert.subject == cert.issuer
        info.not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d")
        info.not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        info.days_left = (cert.not_valid_after_utc - _now_utc()).days
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.san = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            info.san = []
        info.sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info.key_type = "RSA"
            info.key_bits = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info.key_type = f"EC ({pub.curve.name})"
            info.key_bits = pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            info.key_type = "DSA"
            info.key_bits = pub.key_size
    except Exception:
        pass


def _now_utc():
    import datetime as _d

    return _d.datetime.now(_d.timezone.utc)


def _ca_bundles() -> List[Optional[str]]:
    """Trust anchors to try, best coverage first."""
    bundles: List[Optional[str]] = []
    try:
        import certifi

        bundles.append(certifi.where())
    except Exception:
        pass
    bundles.append(None)  # platform default store
    return bundles


def _verified_handshake(host: str, port: int, timeout: float, cafile: Optional[str]):
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cipher = ss.cipher()
            return ss.version() or "", cipher[0] if cipher else "", ss.getpeercert(binary_form=True)


def inspect_tls(host: str, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    info = TlsInfo()

    # 1. verified handshake - tells us whether the chain is trusted
    last_error = ""
    for bundle in _ca_bundles():
        try:
            version, cipher, der = _verified_handshake(host, port, timeout, bundle)
            info.trusted = True
            info.protocol = version
            info.cipher = cipher
            _parse_cert(der, info)
            break
        except ssl.SSLCertVerificationError as exc:
            last_error = exc.verify_message or str(exc)
            info.chain_issues = [last_error]
            info.trusted = False
        except Exception as exc:
            last_error = str(exc)
            info.error = last_error

    # 2. unverified handshake - lets us still read the certificate
    if not info.protocol:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    info.reachable = True
                    info.protocol = ss.version() or ""
                    cipher = ss.cipher()
                    info.cipher = cipher[0] if cipher else ""
                    _parse_cert(ss.getpeercert(binary_form=True), info)
        except Exception as exc:
            if not info.error:
                info.error = str(exc)
            return info
    info.reachable = True

    # 3. which protocol versions are accepted
    for label, ver in (
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ):
        info.versions[label] = _supports_version(host, port, ver, timeout)

    # 4. legacy ciphers
    info.weak_ciphers = _supports_weak_cipher(host, port, timeout)
    return info


def _supports_version(host: str, port: int, ver, timeout: float) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _supports_weak_cipher(host: str, port: int, timeout: float) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("3DES:RC4:DES:NULL:EXPORT:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# misc helpers
# ---------------------------------------------------------------------------
def same_host(a: str, b: str) -> bool:
    try:
        ha = urlparse(a).hostname or ""
        hb = urlparse(b).hostname or ""
        return ha.lower().removeprefix("www.") == hb.lower().removeprefix("www.")
    except Exception:
        return False


def normalise_target(raw: str) -> Tuple[str, str]:
    """Return (base_url, host). Accepts bare domains."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    host = p.hostname or ""
    scheme = p.scheme or "https"
    netloc = p.netloc
    return f"{scheme}://{netloc}", host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def registrable_domain(host: str) -> str:
    """Good-enough eTLD+1 (handles common multi-part suffixes)."""
    host = host.lower().strip(".")
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.in", "co.jp", "com.br", "com.bd", "co.bd", "com.pk", "com.my",
        "co.za", "com.sg", "co.nz", "com.tr", "com.cn", "com.hk",
    }
    if ".".join(parts[-2:]) in two_part and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
