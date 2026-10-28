import asyncio
import os
import socket
import sys
import time

from audioscribe.upload.protocol import make_protocol_factory
from audioscribe.upload.protocol import ProtocolMetrics
from uvicorn import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState
import h11


def test_protocol_factory_limits_before_parser():
    created = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            created.append(self)

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

    class Transport:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    first_transport, excess_transport = Transport(), Transport()
    first, excess = factory(), factory()

    assert created == []
    first.connection_made(first_transport)
    assert len(created) == 1
    excess.connection_made(excess_transport)
    assert len(created) == 1
    assert excess_transport.closed


def test_protocol_permit_is_released_after_connection_loss():
    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

    class Transport:
        def close(self):
            pass

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    first_transport, second_transport = Transport(), Transport()
    first, second = factory(), factory()
    first.connection_made(first_transport)

    assert second.connection_made(second_transport) is None
    first_transport.protocol.connection_lost(None)
    second.connection_made(second_transport)

    assert second_transport.protocol is not first_transport.protocol


def test_preparser_gate_rejects_c_plus_one_and_two_c_connections():
    created = []
    closed = 0

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            created.append(self)

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

    class Transport:
        def close(self):
            nonlocal closed
            closed += 1

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=16, delegate_type=Delegate)
    transports = [Transport() for _ in range(32)]
    protocols = [factory() for _ in transports]
    for protocol, transport in zip(protocols, transports):
        protocol.connection_made(transport)

    assert len(created) == 16
    assert closed == 16


def test_protocol_constructor_failure_releases_acquired_permit():
    attempts = 0

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("constructor failed")

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

    class Transport:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    first_transport, second_transport = Transport(), Transport()

    factory().connection_made(first_transport)
    assert first_transport.closed
    factory().connection_made(second_transport)

    assert attempts == 2
    assert hasattr(second_transport, "protocol")


def test_transport_callback_is_fed_to_delegate_in_bounded_chunks():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(data)

    class Transport:
        def close(self):
            pass

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    transport = Transport()
    factory().connection_made(transport)
    body = b"x" * 200_000
    transport.protocol.data_received(
        b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 200000\r\n\r\n" + body
    )

    assert bytes(received[0]).endswith(b"\r\n\r\n")
    assert [len(chunk) for chunk in received[1:]] == [65_536, 65_536, 65_536, 3_392]


def test_complete_oversized_header_is_rejected_before_parser_feed():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(data)

    class Transport:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    transport = Transport()
    factory().connection_made(transport)
    transport.protocol.data_received(b"GET / HTTP/1.1\r\nX-Pad: " + b"a" * 16_384 + b"\r\n\r\n")

    assert received == []
    assert transport.closed


def test_request_target_over_two_kibibytes_is_rejected():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(data)

    class Transport:
        closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    factory().connection_made(transport)
    transport.protocol.data_received(b"GET /" + b"a" * 2048 + b" HTTP/1.1\r\nHost: x\r\n\r\n")

    assert received == []
    assert transport.closed


def test_incomplete_header_growth_is_bounded():
    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, _data):
            raise AssertionError("incomplete header must not reach h11")

    class Transport:
        closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    factory().connection_made(transport)
    transport.protocol.data_received(b"G" * (16 * 1024 + 1))

    assert transport.closed
    assert len(transport.protocol._header_prefix) == 0


def test_more_than_sixty_four_header_fields_are_rejected():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(data)

    class Transport:
        closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    factory().connection_made(transport)
    headers = b"".join(f"X-{number}: value\r\n".encode() for number in range(65))
    transport.protocol.data_received(b"GET / HTTP/1.1\r\n" + headers + b"\r\n")

    assert received == []
    assert transport.closed


def test_oversized_chunk_extension_is_rejected_before_parser_feed():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(bytes(data))

    class Transport:
        closed = False

        def close(self):
            self.closed = True

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    factory().connection_made(transport)
    transport.protocol.data_received(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
    received.clear()
    transport.protocol.data_received(b"1;" + b"x" * (16 * 1024) + b"\r\n")

    assert received == []
    assert transport.closed


def test_chunked_framing_reaches_delegate_only_after_bounded_metadata_checks():
    received = []

    class Delegate:
        def __init__(self, _config, _server_state, _app_state):
            pass

        def connection_made(self, _transport):
            pass

        def connection_lost(self, _error):
            pass

        def data_received(self, data):
            received.append(bytes(data))

    class Transport:
        def close(self):
            pass

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(None, None, {}, max_connections=1, delegate_type=Delegate)
    factory().connection_made(transport)
    transport.protocol.data_received(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3;ok=yes\r\nabc\r\n0\r\nX-Result: ok\r\n\r\n"
    )

    assert b"".join(received) == (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3;ok=yes\r\nabc\r\n0\r\nX-Result: ok\r\n\r\n"
    )


def test_instrumented_loopback_streams_opaque_body_with_bounded_retention():
    if sys.platform != "linux":
        pytest.skip("the retention instrumentation reads Linux /proc metrics")
    async def exercise():
        requested_bytes = int(os.environ.get("AUDIOSCRIBE_Q02_SIZE_BYTES", 64 * 1024 * 1024))
        concurrency = int(os.environ.get("AUDIOSCRIBE_Q02_CONCURRENCY", "1"))
        observed_bytes = 0
        callback = b"p" * (64 * 1024)

        async def app(_scope, receive, send):
            nonlocal observed_bytes
            while True:
                message = await receive()
                observed_bytes += len(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 204,
                        "headers": [(b"content-length", b"0"), (b"connection", b"close")]})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        config = Config(app, lifespan="off", access_log=False, ws="none")
        config.load()
        metrics = ProtocolMetrics()
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.setblocking(False)
        port = sock.getsockname()[1]
        server = await loop.create_server(
            make_protocol_factory(config, ServerState(), {}, max_connections=16,
                                 delegate_type=H11Protocol, metrics=metrics),
            sock=sock,
        )
        stop_samples = asyncio.Event()
        peak_rss = _rss_bytes()

        async def sample_rss():
            nonlocal peak_rss
            while not stop_samples.is_set():
                peak_rss = max(peak_rss, _rss_bytes())
                await asyncio.sleep(0.01)

        sampler = asyncio.create_task(sample_rss())
        started = time.monotonic()
        try:
            async def send_one():
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                headers = (
                    f"POST /opaque-probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    f"Content-Length: {requested_bytes}\r\nContent-Type: application/octet-stream\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(headers.encode("ascii"))
                await writer.drain()
                remaining = requested_bytes
                while remaining:
                    amount = min(remaining, len(callback))
                    writer.write(callback[:amount])
                    await writer.drain()
                    remaining -= amount
                response = await asyncio.wait_for(reader.read(), timeout=30)
                writer.close()
                await writer.wait_closed()
                return response

            responses = await asyncio.gather(*(send_one() for _ in range(concurrency)))
            assert all(response.startswith(b"HTTP/1.1 204") for response in responses)
        finally:
            stop_samples.set()
            await sampler
            server.close()
            await server.wait_closed()

        elapsed = time.monotonic() - started
        assert observed_bytes == requested_bytes * concurrency
        assert metrics.max_delegate_feed_bytes <= 64 * 1024
        assert metrics.max_transport_callback_bytes > 0
        assert metrics.max_header_prefix_bytes <= 16 * 1024
        assert metrics.max_retained_bytes_estimate <= 1024 * 1024
        assert elapsed < 30
        return metrics, peak_rss, elapsed

    metrics, peak_rss, elapsed = asyncio.run(asyncio.wait_for(exercise(), timeout=30))
    print({"wire_bytes_per_connection": int(os.environ.get("AUDIOSCRIBE_Q02_SIZE_BYTES", 64 * 1024 * 1024)),
           "concurrency": int(os.environ.get("AUDIOSCRIBE_Q02_CONCURRENCY", "1")),
           "callback_max": metrics.max_transport_callback_bytes,
           "retained_estimate_max": metrics.max_retained_bytes_estimate,
           "process_peak_rss_bytes": peak_rss, "elapsed_seconds": round(elapsed, 3)})


def _rss_bytes():
    resident_pages = int(open("/proc/self/statm", encoding="ascii").read().split()[1])
    return resident_pages * os.sysconf("SC_PAGE_SIZE")


def test_oversized_header_is_rejected_before_pinned_h11_receives_bytes():
    async def app(_scope, _receive, _send):
        raise AssertionError("invalid request must not invoke the application")

    config = Config(app, lifespan="off", access_log=False)
    config.load()
    server_state = ServerState()

    class Transport:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def get_extra_info(self, name):
            return {"sockname": ("127.0.0.1", 8765), "peername": ("127.0.0.1", 12345)}.get(name)

        def set_protocol(self, protocol):
            self.protocol = protocol

    transport = Transport()
    factory = make_protocol_factory(config, server_state, {}, max_connections=1,
                                    delegate_type=H11Protocol)
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        factory().connection_made(transport)
        delegate = transport.protocol
        assert hasattr(delegate, "conn")
        delegate.data_received(b"GET / HTTP/1.1\r\nX-Pad: " + b"x" * 16_384 + b"\r\n\r\n")

        assert transport.closed
        assert len(delegate.conn._receive_buffer) == 0
        delegate.connection_lost(None)
    finally:
        asyncio.set_event_loop(None)
        event_loop.close()


def test_giant_content_length_with_bounded_actual_prefix():
    connection = h11.Connection(h11.SERVER)
    request = (b"POST /opaque HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 20000000000\r\n\r\n")
    connection.receive_data(request)
    assert isinstance(connection.next_event(), h11.Request)
    payload = b"z" * (64 * 1024)
    connection.receive_data(payload)
    event = connection.next_event()

    assert isinstance(event, h11.Data)
    assert len(event.data) == len(payload)
    assert len(connection._receive_buffer) == 0


def test_giant_chunk_declaration_with_bounded_actual_prefix():
    connection = h11.Connection(h11.SERVER)
    request = (b"POST /opaque HTTP/1.1\r\nHost: localhost\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n")
    connection.receive_data(request)
    assert isinstance(connection.next_event(), h11.Request)
    connection.receive_data(b"4A817C800\r\n")
    payload = b"z" * (64 * 1024)
    produced = 0
    for offset in range(0, len(payload), 16 * 1024):
        connection.receive_data(payload[offset:offset + 16 * 1024])
        event = connection.next_event()
        assert isinstance(event, h11.Data)
        produced += len(event.data)

    assert produced == len(payload)
    assert len(connection._receive_buffer) == 0


def test_connection_processes_only_one_pipelined_request():
    async def exercise():
        app_requests = 0

        async def app(_scope, _receive, send):
            nonlocal app_requests
            app_requests += 1
            await send({"type": "http.response.start", "status": 204,
                        "headers": [(b"content-length", b"0")]})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        config = Config(app, lifespan="off", access_log=False, ws="none")
        config.load()
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.setblocking(False)
        port = sock.getsockname()[1]
        server = await loop.create_server(
            make_protocol_factory(config, ServerState(), {}, max_connections=16,
                                 delegate_type=H11Protocol), sock=sock
        )
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write((f"GET /one HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                      f"GET /two HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
        return app_requests, response

    app_requests, response = asyncio.run(asyncio.wait_for(exercise(), timeout=10))

    assert response.count(b"HTTP/1.1") == 1
    assert app_requests == 1


def test_real_listener_wires_preparser_admission():
    """PLAN-05 step 2: the production listener's Uvicorn config must use the
    A3 admission seam on the actual ingress path — C = max(16, 4N+8) permits
    before any H11 delegate construction, with excess loopback transports
    closed pre-parser and the configured 20 GB body bound, not a stock
    H11 configuration."""
    import functools

    from audioscribe.upload._listener import upload_http_protocol_seam

    seam = upload_http_protocol_seam(upload_concurrency=1,
                                     upload_max_bytes=20_000_000_000)
    uvicorn_config = Config(None, http=seam, lifespan="off", access_log=False, ws="none")
    uvicorn_config.load()
    assert uvicorn_config.http_protocol_class is seam, \
        "uvicorn must instantiate the admission seam as its HTTP protocol class"

    async def scenario():
        server_state = ServerState()
        factory = functools.partial(seam, config=uvicorn_config,
                                    server_state=server_state, app_state={})
        loop = asyncio.get_running_loop()
        server = await loop.create_server(factory, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        readers = []
        try:
            # C = max(16, 4*1+8) = 16: exactly one of the 17 transports must
            # close before any request bytes are sent.
            for _ in range(17):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                readers.append((reader, writer))

            async def excess_evidence(reader):
                try:
                    data = await asyncio.wait_for(reader.read(1), timeout=1)
                    return data == b""
                except asyncio.TimeoutError:
                    return False

            results = await asyncio.gather(*(excess_evidence(reader)
                                             for reader, _writer in readers))
        finally:
            for _reader, writer in readers:
                writer.close()
            server.close()
            await server.wait_closed()
        return results

    results = asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    assert sum(results) == 1, \
        f"exactly one excess connection must close pre-parser, got {sum(results)}"
