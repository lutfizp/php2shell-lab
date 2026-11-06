from __future__ import annotations

import http.client
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

READ_LIMIT = 1024 * 1024
USER_AGENT = "phpwn/0.1"


class TargetError(ValueError):
    pass


@dataclass
class Target:
    url: str
    insecure: bool = False
    allow_http: bool = False
    timeout: float = 15.0
    ca_file: str | None = None

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https"):
            raise TargetError("target must be an http(s) URL")
        if not parts.hostname:
            raise TargetError("target must include a hostname")
        if parts.scheme == "http" and not self.allow_http:
            raise TargetError("plaintext http is refused; pass --allow-http for a local lab")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.netloc = parts.netloc
        self.path = parts.path or "/"
        self.query = parts.query

    @property
    def request_path(self) -> str:
        return self.path + (("?" + self.query) if self.query else "")

    def context(self) -> ssl.SSLContext | None:
        if self.scheme == "http":
            return None
        if self.insecure:
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.create_default_context(cafile=self.ca_file)
        return ctx

    def connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.context()
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    def with_defaults(self) -> "Request":
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        headers.update(self.headers)
        return Request(self.method, self.path, headers, self.body)


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float
    truncated: bool = False

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def cookies(self) -> list[str]:
        return [value for key, value in self.headers if key.lower() == "set-cookie"]

    @property
    def text(self) -> str:
        return self.body.decode("latin-1", errors="replace")


@dataclass
class Failure:
    kind: str
    detail: str
    elapsed: float


def _classify_exception(exc: BaseException) -> str:
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, BrokenPipeError):
        return "reset"
    if isinstance(exc, http.client.RemoteDisconnected):
        return "reset"
    if isinstance(exc, http.client.HTTPException):
        return "protocol"
    if isinstance(exc, OSError):
        return "socket"
    return "unknown"


def send(conn: http.client.HTTPConnection, req: Request, read_limit: int = READ_LIMIT) -> Response | Failure:
    req = req.with_defaults()
    start = time.perf_counter()
    skip_host = any(key.lower() == "host" for key in req.headers)
    try:
        conn.putrequest(req.method, req.path, skip_host=skip_host, skip_accept_encoding=True)
        for key, value in req.headers.items():
            conn.putheader(key, value)
        if req.body is not None:
            conn.putheader("Content-Length", str(len(req.body)))
        conn.endheaders()
        if req.body:
            conn.send(req.body)
        resp = conn.getresponse()
        body = resp.read(read_limit)
        truncated = False
        if resp.length:
            truncated = True
        return Response(resp.status, resp.reason, resp.getheaders(), body, time.perf_counter() - start, truncated)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return Failure(_classify_exception(exc), repr(exc), time.perf_counter() - start)


def send_once(target: Target, req: Request, read_limit: int = READ_LIMIT) -> Response | Failure:
    conn = target.connection()
    try:
        return send(conn, req, read_limit)
    finally:
        conn.close()


def abort(
    target: Target,
    req: Request,
    fraction: float = 0.5,
    min_bytes: int = 0,
) -> tuple[int, str]:
    req = req.with_defaults()
    body = req.body or b""
    cut = max(min_bytes, int(len(body) * fraction))
    cut = max(0, min(len(body), cut))
    head = f"{req.method} {req.path} HTTP/1.1\r\nHost: {target.netloc}\r\n"
    for key, value in req.headers.items():
        if key.lower() in ("content-length", "host", "connection"):
            continue
        head += f"{key}: {value}\r\n"
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    raw = socket.create_connection((target.host, target.port), target.timeout)
    try:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        if target.scheme == "https":
            raw = target.context().wrap_socket(raw, server_hostname=target.host)
        raw.sendall(head.encode("latin-1") + body[:cut])
        return cut, "aborted"
    finally:
        raw.close()
