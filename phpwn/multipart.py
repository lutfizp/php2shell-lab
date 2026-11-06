from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterator


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass
class Part:
    head: bytes
    data: bytes


class Multipart:
    def __init__(self, boundary: str | None = None) -> None:
        self.boundary = boundary or f"----phpwn{secrets.token_hex(12)}"
        self.parts: list[Part] = []
        self._length = 0

    @property
    def content_type(self) -> str:
        return f"multipart/form-data; boundary={self.boundary}"

    def field(self, name: str, value: str | bytes, content_type: str | None = None) -> "Multipart":
        payload = value.encode() if isinstance(value, str) else value
        head = (
            f"--{self.boundary}\r\n"
            f'Content-Disposition: form-data; name="{_quote(name)}"\r\n'
        )
        if content_type:
            head += f"Content-Type: {content_type}\r\n"
        head += "\r\n"
        self._add(head.encode(), payload)
        return self

    def file(
        self,
        name: str,
        filename: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> "Multipart":
        head = (
            f"--{self.boundary}\r\n"
            f'Content-Disposition: form-data; name="{_quote(name)}"; filename="{_quote(filename)}"\r\n'
            f"Content-Type: {content_type}\r\n"
            f"\r\n"
        ).encode()
        self._add(head, data)
        return self

    def _add(self, head: bytes, data: bytes) -> None:
        self.parts.append(Part(head, data))
        self._length += len(head) + len(data) + 2

    def _tail(self) -> bytes:
        return f"--{self.boundary}--\r\n".encode()

    def __len__(self) -> int:
        return self._length + len(self._tail())

    def chunks(self) -> Iterator[bytes]:
        for part in self.parts:
            yield part.head
            yield part.data
            yield b"\r\n"
        yield self._tail()

    def to_bytes(self) -> bytes:
        return b"".join(self.chunks())

    def prefix_length(self, part_index: int) -> int:
        total = 0
        for part in self.parts[:part_index]:
            total += len(part.head) + len(part.data) + 2
        return total
