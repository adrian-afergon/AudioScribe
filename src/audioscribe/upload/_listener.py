from __future__ import annotations

"""Deferred Uvicorn listener start. Imported only when uploads are enabled so
that a disabled service never pays the Uvicorn/PyAV import cost."""

import asyncio
import threading


def upload_http_protocol_seam(upload_concurrency: int, upload_max_bytes: int):
    """A3 admission seam for the real listener. Uvicorn instantiates its HTTP
    protocol class per connection with server kwargs; this callable holds one
    C = max(16, 4N+8) permit set per server, defers H11 delegate construction
    until a permit is acquired, and bounds body framing at the configured
    maximum instead of the stock parser defaults."""
    from .protocol import make_protocol_factory

    max_connections = max(16, 4 * upload_concurrency + 8)
    holder: dict = {}

    def factory(config=None, server_state=None, app_state=None, _loop=None):
        if "factory" not in holder:
            holder["factory"] = make_protocol_factory(
                config, server_state, app_state or {},
                max_connections=max_connections, max_body_bytes=upload_max_bytes)
        return holder["factory"]()

    return factory


def start_uvicorn_listener(runtime, config):
    import uvicorn

    from .http import make_upload_app

    started = threading.Event()
    ready = threading.Event()
    holder: dict = {}

    def serve():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = uvicorn.Server(uvicorn.Config(
            make_upload_app(runtime), host="127.0.0.1", port=config.upload_port,
            log_level="warning", server_header=False, date_header=False,
            http=upload_http_protocol_seam(config.upload_concurrency,
                                           config.upload_max_bytes)))
        holder["server"] = server
        holder["loop"] = loop
        ready.set()

        async def run():
            try:
                await server.serve()
            finally:
                started.set()

        loop.run_until_complete(run())
        loop.close()

    thread = threading.Thread(target=serve, name="upload-listener", daemon=True)
    thread.start()
    if not ready.wait(5):
        raise RuntimeError("upload listener did not start")

    class Listener:
        def stop(self):
            server, loop = holder.get("server"), holder.get("loop")
            if server is not None and loop is not None and not started.is_set():
                loop.call_soon_threadsafe(setattr, server, "should_exit", True)

    return Listener()
