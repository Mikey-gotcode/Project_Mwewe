"""
Output/presentation layer for the RFeye IRC server.

Owns how state reaches the outside world — WebSocket broadcast to the
dashboard, and serving the dashboard's static files. Never parses inbound
protocol messages; controllers decide *what* to render, these classes only
handle *how*.
"""
import asyncio
import http.server
import json
import logging
import threading
from pathlib import Path

log = logging.getLogger("rfeye")


class WebSocketView:
    """Owns the set of connected dashboard WebSocket clients and broadcasts events."""

    def __init__(self):
        self.clients: set = set()

    def add_client(self, ws):
        self.clients.add(ws)

    def remove_client(self, ws):
        self.clients.discard(ws)

    def push(self, event: dict):
        """Broadcast a JSON event to all connected clients."""
        msg = json.dumps(event)
        dead = set()
        for ws in self.clients:
            try:
                asyncio.ensure_future(ws.send(msg))
            except Exception:
                dead.add(ws)
        self.clients -= dead


class DashboardHTTPView:
    """Serves the static dashboard (index.html, captures/) in a background thread."""

    def __init__(self, root: Path, port: int):
        self.root = root
        self.port = port

    def serve_forever_in_thread(self) -> threading.Thread:
        def _serve():
            import os
            os.chdir(self.root)
            handler = http.server.SimpleHTTPRequestHandler
            handler.log_message = lambda *a: None   # silence access log
            with http.server.HTTPServer(("0.0.0.0", self.port), handler) as httpd:
                log.info(f"Dashboard  http://localhost:{self.port}")
                httpd.serve_forever()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return t