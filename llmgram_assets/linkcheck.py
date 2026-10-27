"""Bounded reachability check for submitted links.

The server fetches URLs chosen by an agent, so every hop is resolved once,
refused unless every address is public, then connected to that exact address
(no second DNS lookup). Only the status line is read.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

USER_AGENT = "llmgram-assets-linkcheck/1 (+https://llmgram.app)"
MAX_REDIRECTS = 5
TIMEOUT = 8.0
# The server answered but refuses bots or anonymous clients: the resource
# exists, which is all this gate checks.
RESTRICTED = {401, 403, 405, 429}


@dataclass
class LinkResult:
    ok: bool
    status: int | None
    detail: str

    def as_dict(self) -> dict:
        return {"ok": self.ok, "status": self.status, "detail": self.detail}


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _public_address(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise OSError("no address")
    for address in addresses:
        if not ipaddress.ip_address(address.split("%", 1)[0]).is_global:
            raise PermissionError("resolves to a non-public address")
    return addresses[0]


def check_url(url: str) -> LinkResult:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            return LinkResult(False, None, "redirect left https")
        port = parts.port or 443
        try:
            address = _public_address(parts.hostname, port)
        except PermissionError as exc:
            return LinkResult(False, None, str(exc))
        except OSError:
            return LinkResult(False, None, "dns failure")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn = _PinnedHTTPSConnection(parts.hostname, address, port, TIMEOUT)
        try:
            status, location = _request(conn, "HEAD", path)
            if status in (403, 404, 405, 501):
                # Many hosts refuse HEAD but serve GET.
                conn.close()
                conn = _PinnedHTTPSConnection(parts.hostname, address, port, TIMEOUT)
                status, location = _request(conn, "GET", path)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return LinkResult(False, None, type(exc).__name__)
        finally:
            conn.close()
        if 300 <= status < 400 and location:
            current = urljoin(current, location)
            continue
        if status < 300:
            return LinkResult(True, status, "reachable")
        if status in RESTRICTED:
            return LinkResult(True, status, "reachable, access restricted")
        return LinkResult(False, status, "http error")
    return LinkResult(False, None, "too many redirects")


def _request(conn: http.client.HTTPSConnection, method: str, path: str) -> tuple[int, str | None]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if method == "GET":
        headers["Range"] = "bytes=0-0"
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    return response.status, response.getheader("Location")


@dataclass
class FetchResult:
    ok: bool
    status: int | None
    content_type: str
    body: bytes
    detail: str


def fetch(url: str, *, max_bytes: int = 5_000_000, accept: str = "*/*") -> FetchResult:
    """GET with the same guards as ``check_url``; the body is capped at ``max_bytes``."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            return FetchResult(False, None, "", b"", "redirect left https")
        port = parts.port or 443
        try:
            address = _public_address(parts.hostname, port)
        except PermissionError as exc:
            return FetchResult(False, None, "", b"", str(exc))
        except OSError:
            return FetchResult(False, None, "", b"", "dns failure")
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        conn = _PinnedHTTPSConnection(parts.hostname, address, port, TIMEOUT)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": accept})
            response = conn.getresponse()
            status, location = response.status, response.getheader("Location")
            content_type = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
            body = b""
            if status < 300:
                body = response.read(max_bytes + 1)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return FetchResult(False, None, "", b"", type(exc).__name__)
        finally:
            conn.close()
        if 300 <= status < 400 and location:
            current = urljoin(current, location)
            continue
        if status >= 300:
            return FetchResult(False, status, content_type, b"", "http error")
        if len(body) > max_bytes:
            return FetchResult(False, status, content_type, b"", "too large")
        return FetchResult(True, status, content_type, body, "ok")
    return FetchResult(False, None, "", b"", "too many redirects")
