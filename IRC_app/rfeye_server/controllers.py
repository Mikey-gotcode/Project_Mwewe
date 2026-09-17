"""
Controllers for the RFeye IRC server.

This is the only layer that knows the wire protocol. It parses inbound
UDP/WebSocket messages, applies them to the models, and tells the views
what to render. Swap the protocol (say, TCP+length-prefixed frames instead
of UDP+JSON) and only this file should need to change.
"""
import asyncio
import json
import logging
import time

import security
import wavutil

log = logging.getLogger("rfeye")


class UDPDataController(asyncio.DatagramProtocol):
    """Handles the data-plane UDP port: register / heartbeat / alert / audio_chunk."""

    def __init__(self, node_store, incident_log, audit_log, audio_buffer, ws_view,
                 allowlist, captures_dir, db=None, confidence_threshold: float = 0.0):
        self.nodes = node_store
        self.incidents = incident_log
        self.audit = audit_log
        self.audio = audio_buffer
        self.view = ws_view
        self.allowlist = allowlist
        self.captures_dir = captures_dir
        self.db = db   # PostgresStore, or None to run in-memory only
        # Alerts below this confidence are logged but never raised as an
        # incident. Firmware doesn't send `confidence` yet — msg.get()
        # defaults to 1.0 below, so this gate is a no-op until it does.
        self.confidence_threshold = confidence_threshold

    def _persist(self, coro):
        """Fire-and-forget a DB write — datagram_received is a sync callback,
        so writes are scheduled on the loop rather than awaited here."""
        if self.db is not None:
            asyncio.ensure_future(coro)

    def datagram_received(self, data, addr):
        try:
            envelope = json.loads(data)
        except json.JSONDecodeError:
            return

        ok, msg, reason = security.decrypt_envelope(envelope, self.allowlist)
        if not ok:
            self._reject(addr, envelope.get("name"), "?", reason)
            return

        t = msg.get("type")

        if t in ("register", "heartbeat", "alert"):
            ok, reason = security.verify(msg, self.allowlist)
            if not ok:
                self._reject(addr, msg.get("name"), t, reason)
                return

        node_id = msg.get("id", addr[0])

        if t == "register":
            self._handle_register(msg, node_id, addr)
        elif t == "heartbeat":
            self._handle_heartbeat(msg, node_id)
        elif t == "alert":
            self._handle_alert(msg, node_id)
        elif t == "audio_chunk":
            self._handle_audio_chunk(msg, node_id)
        elif t == "discover":
            pass   # handled on the separate discovery port

    def error_received(self, exc):
        log.warning(f"UDP error: {exc}")

    # ── message handlers ──

    def _reject(self, addr, name, msg_type, reason):
        log.warning(f"REJECTED  {msg_type}  from={addr[0]}  name={name!r}  reason={reason}")
        self.view.push({
            "type": "security_alert",
            "ts": time.time(),
            "addr": addr[0],
            "name": name or "?",
            "msg_type": msg_type,
            "reason": reason,
        })

    def _handle_register(self, msg, node_id, addr):
        name = msg.get("name", node_id[-4:])
        lat, lon = msg.get("lat", 0), msg.get("lon", 0)
        node = self.nodes.register(node_id, name, lat, lon,
                                    battery=msg.get("battery"), mic_status=msg.get("mic_status"))
        log.info(f"REGISTER  {node['name']} ({addr[0]})")
        self.view.push({"type": "node_update", "nodes": self.nodes.all()})
        self._persist(self.db.upsert_node(node_id, name, lat, lon,
                                           online=True, battery=node["battery"], mic_status=node["mic_status"]))

    def _handle_heartbeat(self, msg, node_id):
        known = self.nodes.heartbeat(node_id)
        self.view.push({"type": "heartbeat", "id": node_id, "ts": time.time()})
        if known:
            self._persist(self.db.touch_node(node_id, online=True))

    def _handle_alert(self, msg, node_id):
        confidence = msg.get("confidence", 1.0)   # defaults to 1.0 until firmware sends a real score
        if confidence < self.confidence_threshold:
            log.info(f"ALERT     suppressed (confidence {confidence:.2f} < "
                     f"{self.confidence_threshold:.2f})  node={msg.get('name', node_id)}")
            return

        incident = self.incidents.add(
            node_id=node_id,
            node_name=msg.get("name", node_id[-4:]),
            angle=msg.get("angle"),
            tdoa12=msg.get("tdoa12"),
            tdoa13=msg.get("tdoa13"),
            lat=msg.get("lat"),
            lon=msg.get("lon"),
            classification=msg.get("classification"),   # None until a classifier exists
            confidence=confidence,
            confirming_nodes=msg.get("confirming_nodes"),
            total_nodes=msg.get("total_nodes"),
        )
        log.info(f"ALERT     {incident['id']}  node={incident['node']}  angle={incident['angle']}°")
        self.view.push({"type": "alert", "incident": incident})
        self._persist(self.db.insert_incident(incident))

        entry = self.audit.add(incident["id"], "DANGER",
                                f"{incident['id']} registered "
                                f"({incident['classification'] or 'unclassified'} detection)")
        self.view.push({"type": "audit_entry", "entry": entry})
        self._persist(self.db.add_audit_entry(incident["id"], entry["severity"], entry["message"]))

    def _handle_audio_chunk(self, msg, node_id):
        try:
            chunk_bytes = bytes.fromhex(msg.get("data", ""))
        except ValueError:
            log.warning(f"AUDIO     bad hex chunk from {msg.get('name')} mic={msg.get('mic')}")
            return

        result = self.audio.add_chunk(
            node_id, msg["mic"], msg["test_id"], msg["chunk"], msg["total"],
            msg["rate"], msg.get("name", node_id[-4:]), chunk_bytes,
        )
        if result is None:
            return   # still waiting on more chunks

        pcm, rate, name = result
        wav_bytes = wavutil.build_wav_bytes(pcm, rate)
        filename = f"{name}_mic{msg['mic']}_{msg['test_id']}.wav"
        (self.captures_dir / filename).write_bytes(wav_bytes)

        log.info(f"AUDIO     {name}  mic={msg['mic']}  {len(pcm)}B @ {rate}Hz  → {filename}")
        self.view.push({
            "type": "audio_capture",
            "node": name,
            "mic": msg["mic"],
            "rate": rate,
            "url": f"/captures/{filename}",
            "ts": time.time(),
        })


class UDPDiscoveryController(asyncio.DatagramProtocol):
    """Handles the discovery-plane UDP port: ACKs `discover` broadcasts."""

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        if msg.get("type") == "discover":
            self.transport.sendto(json.dumps({"type": "ack"}).encode(), addr)
            log.info(f"DISCOVER  ACK → {addr[0]}")

    def error_received(self, exc):
        log.warning(f"Discovery UDP error: {exc}")


class WebSocketController:
    """
    Handles the dashboard WebSocket connection lifecycle and operator
    commands — the DISPATCH UAV / RESOLVE / DISMISS buttons on the console
    each send one of these as a `type` over the socket.
    """

    # incident status -> (new status, audit severity, audit message template)
    _TRANSITIONS = {
        "dispatch_incident": ("dispatched", "SUCCESS", "UAV dispatched to {id}"),
        "resolve_incident":  ("resolved",   "SUCCESS", "{id} resolved by operator"),
        "dismiss_incident":  ("dismissed",  "INFO",    "{id} dismissed by operator"),
        "close_incident":    ("resolved",   "SUCCESS", "{id} resolved by operator"),  # legacy alias
    }

    def __init__(self, node_store, incident_log, audit_log, ws_view, db=None):
        self.nodes = node_store
        self.incidents = incident_log
        self.audit = audit_log
        self.view = ws_view
        self.db = db

    def _persist(self, coro):
        if self.db is not None:
            asyncio.ensure_future(coro)

    async def handle(self, websocket):
        self.view.add_client(websocket)
        log.info(f"WS connect  {websocket.remote_address}")
        try:
            await websocket.send(json.dumps({
                "type": "init",
                "nodes": self.nodes.all(),
                "incidents": self.incidents.recent(100),
                "audit_log": self.audit.recent(50),
            }))
            async for raw in websocket:
                await self._handle_command(raw)
        except Exception:
            pass
        finally:
            self.view.remove_client(websocket)
            log.info(f"WS disconnect  {websocket.remote_address}")

    async def _handle_command(self, raw):
        try:
            cmd = json.loads(raw)
        except Exception:
            return

        cmd_type = cmd.get("type")
        transition = self._TRANSITIONS.get(cmd_type)
        if transition is None:
            return

        new_status, severity, template = transition
        incident_id = cmd.get("id")
        incident = self.incidents.set_status(incident_id, new_status)
        if incident is None:
            return

        self.view.push({"type": "incident_update", "incident": incident})
        self._persist(self.db.update_incident_status(incident_id, new_status))

        entry = self.audit.add(incident_id, severity, template.format(id=incident_id))
        self.view.push({"type": "audit_entry", "entry": entry})
        self._persist(self.db.add_audit_entry(incident_id, entry["severity"], entry["message"]))


class Watchdog:
    """Periodically marks stale nodes offline and drops stalled audio captures."""

    def __init__(self, node_store, audio_buffer, ws_view, db=None, interval: float = 15):
        self.nodes = node_store
        self.audio = audio_buffer
        self.view = ws_view
        self.db = db
        self.interval = interval

    async def run(self):
        while True:
            await asyncio.sleep(self.interval)
            if self.nodes.sweep_offline():
                self.view.push({"type": "node_update", "nodes": self.nodes.all()})
                if self.db is not None:
                    newly_offline = [n["id"] for n in self.nodes.all() if not n["online"]]
                    asyncio.ensure_future(self.db.set_nodes_offline(newly_offline))
            for key in self.audio.sweep_stale():
                log.warning(f"AUDIO     dropping stalled capture {key}")
