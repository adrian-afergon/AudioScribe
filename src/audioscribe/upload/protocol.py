from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class _ConnectionPermits:
    def __init__(self, maximum: int):
        if maximum < 1:
            raise ValueError("maximum connection count must be positive")
        self.maximum = maximum
        self.active = 0

    def acquire(self) -> bool:
        if self.active >= self.maximum:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        if self.active < 1:
            raise RuntimeError("connection permit released more than once")
        self.active -= 1


@dataclass
class ProtocolMetrics:
    max_transport_callback_bytes: int = 0
    max_header_prefix_bytes: int = 0
    max_delegate_feed_bytes: int = 0
    max_retained_bytes_estimate: int = 0
    max_chunk_metadata_bytes: int = 0


def make_protocol_factory(config: Any, server_state: Any, app_state: dict[str, Any],
                          max_connections: int,
                          delegate_type: type | None = None,
                          metrics: ProtocolMetrics | None = None,
                          max_body_bytes: int = 20_000_000_000) -> Callable[[], asyncio.Protocol]:
    permits = _ConnectionPermits(max_connections)
    metrics = metrics or ProtocolMetrics()
    if delegate_type is None:
        from uvicorn.protocols.http.h11_impl import H11Protocol
        delegate_type = H11Protocol

    class AdmittedDelegate(delegate_type):
        def __init__(self, release: Callable[[], None]):
            self._release_permit = release
            self._permit_released = False
            self._header_prefix = bytearray()
            self._header_validated = False
            self._header_rejected = False
            self._header_deadline = None
            self._responses_completed = 0
            self._body_kind = "headers"
            self._body_remaining = 0
            self._body_received = 0
            self._chunk_state = "size"
            self._chunk_line = bytearray()
            self._chunk_remaining = 0
            self._trailer_bytes = 0
            self._trailer_fields = 0
            super().__init__(config, server_state, app_state)

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self._upload_transport = transport
            super().connection_made(transport)
            loop = getattr(self, "loop", None)
            if loop is not None:
                self._header_deadline = loop.call_later(10, self._header_timeout)

        def connection_lost(self, error: Exception | None) -> None:
            try:
                if self._header_deadline is not None:
                    self._header_deadline.cancel()
                super().connection_lost(error)
            finally:
                self._release()

        def on_response_complete(self) -> None:
            self._responses_completed += 1
            if self._responses_completed >= 1:
                self._upload_transport.close()
            super().on_response_complete()

        def data_received(self, data: bytes) -> None:
            if self._header_rejected:
                return
            self._current_callback_bytes = len(data)
            metrics.max_transport_callback_bytes = max(metrics.max_transport_callback_bytes, len(data))
            if not self._header_validated:
                self._buffer_request_header(data)
                return
            self._feed_body(data)

        def _buffer_request_header(self, data: bytes) -> None:
            limit = 16 * 1024
            old_size = len(self._header_prefix)
            view = memoryview(data)
            remaining_capacity = max(limit - old_size, 0)
            self._header_prefix.extend(view[:remaining_capacity])
            metrics.max_header_prefix_bytes = max(metrics.max_header_prefix_bytes, len(self._header_prefix))
            marker = self._header_prefix.find(b"\r\n\r\n")
            if marker < 0:
                if len(self._header_prefix) >= limit:
                    self._reject_header()
                return
            header_end = marker + 4
            header = bytes(self._header_prefix[:header_end])
            framing = self._request_framing(header)
            if header_end > limit or framing is None:
                self._reject_header()
                return
            body_offset = header_end - old_size
            self._header_prefix.clear()
            self._header_validated = True
            self._body_kind, self._body_remaining = framing
            if self._header_deadline is not None:
                self._header_deadline.cancel()
                self._header_deadline = None
            super().data_received(header)
            self._feed_body(view[body_offset:])

        def _request_framing(self, header: bytes) -> tuple[str, int] | None:
            lines = header[:-4].split(b"\r\n")
            request_line = lines[0].split(b" ")
            if len(request_line) != 3 or len(request_line[1]) > 2 * 1024:
                return None
            fields = lines[1:]
            if len(fields) > 64 or any(b":" not in field for field in fields):
                return None
            content_lengths = []
            transfer_encodings = []
            for field in fields:
                name, value = field.split(b":", 1)
                name = name.strip().lower()
                value = value.strip().lower()
                if name == b"content-length":
                    content_lengths.append(value)
                elif name == b"transfer-encoding":
                    transfer_encodings.append(value)
            if len(content_lengths) > 1 or len(transfer_encodings) > 1:
                return None
            if content_lengths and transfer_encodings:
                return None
            if transfer_encodings:
                return ("chunked", 0) if transfer_encodings[0] == b"chunked" else None
            if not content_lengths:
                return "none", 0
            value = content_lengths[0]
            if not value or not value.isdigit():
                return None
            length = int(value)
            if length > max_body_bytes:
                return None
            return "length", length

        def _feed_body(self, data: bytes | memoryview) -> None:
            if not data:
                return
            if self._body_kind == "none":
                return
            if self._body_kind == "chunked":
                self._feed_chunked(data)
                return
            view = memoryview(data)
            amount = min(len(view), self._body_remaining)
            if amount:
                self._feed_chunks(view[:amount])
                self._body_remaining -= amount
                self._body_received += amount
            if amount < len(view):
                return

        def _feed_chunked(self, data: bytes | memoryview) -> None:
            view = memoryview(data)
            position = 0
            while position < len(view) and not self._header_rejected:
                if self._chunk_state in ("size", "trailers"):
                    line, consumed = self._take_chunk_line(view[position:])
                    if line is None:
                        return
                    position += consumed
                    if self._chunk_state == "size":
                        size_text = line[:-2].split(b";", 1)[0]
                        if (not size_text or any(byte not in b"0123456789abcdefABCDEF" for byte in size_text)):
                            self._reject_header()
                            return
                        chunk_size = int(size_text, 16)
                        if chunk_size > max_body_bytes - self._body_received:
                            self._reject_header()
                            return
                        self._feed_chunks(line)
                        self._chunk_remaining = chunk_size
                        self._chunk_state = "trailers" if chunk_size == 0 else "data"
                        continue
                    self._trailer_bytes += len(line)
                    if self._trailer_bytes > 16 * 1024:
                        self._reject_header()
                        return
                    if line == b"\r\n":
                        self._feed_chunks(line)
                        self._chunk_state = "done"
                        continue
                    self._trailer_fields += 1
                    if self._trailer_fields > 64 or b":" not in line[:-2]:
                        self._reject_header()
                        return
                    self._feed_chunks(line)
                    continue
                if self._chunk_state == "data":
                    amount = min(self._chunk_remaining, len(view) - position)
                    self._feed_chunks(view[position:position + amount])
                    position += amount
                    self._chunk_remaining -= amount
                    self._body_received += amount
                    if self._chunk_remaining == 0:
                        self._chunk_state = "data_crlf"
                        self._chunk_line.clear()
                    continue
                if self._chunk_state == "data_crlf":
                    needed = 2 - len(self._chunk_line)
                    amount = min(needed, len(view) - position)
                    self._chunk_line.extend(view[position:position + amount])
                    position += amount
                    if len(self._chunk_line) == 2:
                        if self._chunk_line != b"\r\n":
                            self._reject_header()
                            return
                        self._feed_chunks(self._chunk_line)
                        self._chunk_line.clear()
                        self._chunk_state = "size"
                    continue
                if self._chunk_state == "done":
                    return

        def _take_chunk_line(self, data: memoryview) -> tuple[bytes | None, int]:
            limit = 16 * 1024
            old_size = len(self._chunk_line)
            take = min(len(data), max(limit - old_size, 0))
            self._chunk_line.extend(data[:take])
            metrics.max_chunk_metadata_bytes = max(metrics.max_chunk_metadata_bytes, len(self._chunk_line))
            marker = self._chunk_line.find(b"\r\n")
            if marker < 0:
                if len(self._chunk_line) >= limit:
                    self._reject_header()
                return None, take
            end = marker + 2
            line = bytes(self._chunk_line[:end])
            consumed = end - old_size
            self._chunk_line.clear()
            return line, consumed

        def _feed_chunks(self, data: bytes | memoryview) -> None:
            view = memoryview(data)
            for offset in range(0, len(view), 64 * 1024):
                chunk = view[offset:offset + 64 * 1024]
                metrics.max_delegate_feed_bytes = max(metrics.max_delegate_feed_bytes, len(chunk))
                super().data_received(chunk)
                parser_buffer = getattr(getattr(self, "conn", None), "_receive_buffer", None)
                parser_bytes = len(parser_buffer) if parser_buffer is not None else 0
                cycle_body = getattr(getattr(self, "cycle", None), "body", b"")
                body_bytes = len(cycle_body)
                retained = (getattr(self, "_current_callback_bytes", 0)
                            + len(self._header_prefix) + parser_bytes + 2 * body_bytes)
                metrics.max_retained_bytes_estimate = max(metrics.max_retained_bytes_estimate, retained)

        def _header_timeout(self) -> None:
            if not self._header_validated:
                self._reject_header()

        def _reject_header(self) -> None:
            self._header_rejected = True
            self._header_prefix.clear()
            if self._header_deadline is not None:
                self._header_deadline.cancel()
                self._header_deadline = None
            self._upload_transport.close()

        def _release(self) -> None:
            if not self._permit_released:
                self._permit_released = True
                self._release_permit()

    class DeferredProtocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            if not permits.acquire():
                transport.close()
                return
            released = False

            def release() -> None:
                nonlocal released
                if not released:
                    released = True
                    permits.release()

            try:
                delegate = AdmittedDelegate(release)
                transport.set_protocol(delegate)
                delegate.connection_made(transport)
            except Exception:
                transport.close()
                if "delegate" in locals():
                    delegate._release()
                else:
                    release()

    return DeferredProtocol
