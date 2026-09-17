#!/usr/bin/env python3
"""
RFeye IRC Server — entry point.

Wires the model/view/controller pieces together and runs the event loop.
This is the only file that should need to change if you add a new
model, a new view, or a new protocol port — everything else composes
here.

  UDP :5500  — receives REGISTER / ALERT / HEARTBEAT / audio_chunk from nodes
  UDP :5501  — responds to DISCOVER broadcasts with ACK
  HTTP :8080 — serves the dashboard (index.html)
  WS  :8765  — pushes live events to dashboard clients

Optional env vars:
    RFEYE_UDP_PORT          default 5500
    RFEYE_DISC_PORT         default 5501
    RFEYE_HTTP_PORT         default 8080
    DATABASE_URL            postgres DSN, e.g. postgresql://user:pass@localhost/rfeye
                            (if unset, the server runs in-memory only, as before)
    RFEYE_CONFIDENCE_GATE   default 0.0 (no gate) — alerts below this confidence
                            are logged but not raised as an incident
"""
import asyncio
import logging
import os
import socket
from pathlib import Path

try:
    import websockets
except ImportError:
    print("Install websockets:  pip install websockets")
    raise

import security

from .models import NodeStore, IncidentLog, AuditLog, AudioCaptureBuffer
from .views import WebSocketView, DashboardHTTPView
from .controllers import UDPDataController, UDPDiscoveryController, WebSocketController, Watchdog
from .db import PostgresStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("rfeye")

UDP_PORT     = int(os.getenv("RFEYE_UDP_PORT",  5500))
DISC_PORT    = int(os.getenv("RFEYE_DISC_PORT", 5501))
HTTP_PORT    = int(os.getenv("RFEYE_HTTP_PORT", 8080))
DATABASE_URL = os.getenv("DATABASE_URL")             # e.g. postgresql://user:pass@localhost/rfeye
CONFIDENCE_GATE = float(os.getenv("RFEYE_CONFIDENCE_GATE", "0.0"))

# Project root (one level up from this package) — same layout the old
# single-file server.py used, so index.html and captures/ don't move.
PROJECT_ROOT  = Path(__file__).parent.parent
CAPTURES_DIR  = PROJECT_ROOT / "captures"
CAPTURES_DIR.mkdir(exist_ok=True)


async def main():
    loop = asyncio.get_event_loop()

    allowlist = security.load_allowlist()
    if not allowlist:
        log.warning(
            "allowlist.json is empty — ALL nodes will be rejected until "
            "provisioned. Run: python3 tools/provision_node.py <node-name>"
        )
    else:
        log.info(f"Loaded {len(allowlist)} node(s) from allowlist.json")

    # ── Persistence ──
    db = None
    if DATABASE_URL:
        db = PostgresStore(DATABASE_URL)
        await db.connect()
    else:
        log.warning(
            "DATABASE_URL not set — running in-memory only. Incident/node "
            "history will not survive a restart. Set DATABASE_URL and run "
            "schema.sql to enable persistence."
        )

    # ── Models ──
    node_store   = NodeStore()
    incident_log = IncidentLog()
    audit_log    = AuditLog()
    audio_buffer = AudioCaptureBuffer()

    if db is not None:
        node_store.load(await db.load_nodes())
        incident_log.load(await db.load_recent_incidents(100))
        audit_log.load(await db.load_recent_audit(50))
        log.info(f"Loaded {len(node_store.all())} node(s), "
                 f"{len(incident_log.all())} incident(s) from Postgres")

    # ── Views ──
    ws_view   = WebSocketView()
    http_view = DashboardHTTPView(PROJECT_ROOT, HTTP_PORT)

    # ── Controllers ──
    data_controller = UDPDataController(
        node_store, incident_log, audit_log, audio_buffer, ws_view, allowlist, CAPTURES_DIR,
        db=db, confidence_threshold=CONFIDENCE_GATE,
    )
    disc_controller = UDPDiscoveryController()
    ws_controller   = WebSocketController(node_store, incident_log, audit_log, ws_view, db=db)
    watchdog        = Watchdog(node_store, audio_buffer, ws_view, db=db)

    # UDP data plane
    await loop.create_datagram_endpoint(
        lambda: data_controller, local_addr=("0.0.0.0", UDP_PORT)
    )
    log.info(f"UDP data   port {UDP_PORT}")

    # UDP discovery plane (needs SO_BROADCAST — bind with raw socket workaround)
    disc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc_sock.bind(("0.0.0.0", DISC_PORT))
    disc_sock.setblocking(False)
    await loop.create_datagram_endpoint(lambda: disc_controller, sock=disc_sock)
    log.info(f"UDP disc   port {DISC_PORT}")

    # WebSocket
    await websockets.serve(ws_controller.handle, "0.0.0.0", 8765)
    log.info("WebSocket  port 8765")

    # HTTP dashboard, in a background thread
    http_view.serve_forever_in_thread()

    # Watchdog
    asyncio.ensure_future(watchdog.run())

    log.info("RFeye IRC server running — Ctrl+C to stop")
    try:
        await asyncio.Future()   # run forever
    finally:
        if db is not None:
            await db.close()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped.")


if __name__ == "__main__":
    run()
