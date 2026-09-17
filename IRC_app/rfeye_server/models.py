"""
Data models for the RFeye IRC server.

No networking, no protocol parsing, no logging side effects beyond what's
returned to the caller — controllers own all of that. Keeping this layer
dumb is what makes it independently testable.
"""
import time
from typing import Dict, Optional, Tuple

AUDIO_CAPTURE_TIMEOUT = 20.0   # seconds — drop an incomplete capture (dropped
                                # UDP chunk, reboot mid-test) rather than leak memory forever


class NodeStore:
    """Tracks registered nodes: id -> {name, lat, lon, last_seen, online, ...}."""

    def __init__(self):
        self._nodes: Dict[str, dict] = {}

    def register(self, node_id: str, name: str, lat, lon, battery=None, mic_status=None) -> dict:
        # battery/mic_status are optional — today's firmware doesn't send them,
        # they'll simply stay None until main.py is extended to report them.
        node = {
            "id": node_id,
            "name": name,
            "lat": lat,
            "lon": lon,
            "last_seen": time.time(),
            "online": True,
            "battery": battery,
            "mic_status": mic_status,
        }
        self._nodes[node_id] = node
        return node

    def load(self, rows: list):
        """Seed the store from persisted rows on startup (id, name, lat, lon, ...)."""
        for row in rows:
            self._nodes[row["id"]] = {
                "id": row["id"],
                "name": row["name"],
                "lat": row["lat"],
                "lon": row["lon"],
                # 0.0, not the DB timestamp: forces sweep_offline() to correctly
                # mark it offline on the first pass, until a fresh heartbeat lands.
                "last_seen": 0.0,
                "online": False,
                "battery": row.get("battery"),
                "mic_status": row.get("mic_status"),
            }

    def heartbeat(self, node_id: str) -> bool:
        """Returns True if the node was known (and its last_seen updated)."""
        node = self._nodes.get(node_id)
        if node is None:
            return False
        node["last_seen"] = time.time()
        node["online"] = True
        return True

    def sweep_offline(self, timeout: float = 30) -> bool:
        """Marks stale nodes offline. Returns True if any node's status changed."""
        changed = False
        now = time.time()
        for node in self._nodes.values():
            was_online = node["online"]
            node["online"] = (now - node["last_seen"]) < timeout
            if was_online != node["online"]:
                changed = True
        return changed

    def all(self) -> list:
        return list(self._nodes.values())

    def get(self, node_id: str) -> Optional[dict]:
        return self._nodes.get(node_id)


class IncidentLog:
    """
    Ordered list of alert/incident records.

    Lifecycle: open -> dispatched -> resolved, or open -> dismissed.
    `classification`/`confidence`/`confirming_nodes`/`total_nodes` are
    accepted as optional because today's firmware only sends angle/TDOA —
    they'll populate once main.py is extended to do on-node (or
    multi-node-corroborated) classification. See the console-parity notes.
    """

    def __init__(self, year: int = None):
        self._incidents: list = []
        self._year = year or time.gmtime().tm_year

    def add(self, node_id, node_name, angle, tdoa12, tdoa13, lat, lon,
            classification=None, confidence=None,
            confirming_nodes=None, total_nodes=None, incident_id=None) -> dict:
        incident = {
            "id": incident_id or f"INC-{self._year}-{len(self._incidents) + 1:04d}",
            "node_id": node_id,
            "node": node_name,
            "classification": classification,
            "confidence": confidence,
            "angle": angle,
            "tdoa12": tdoa12,
            "tdoa13": tdoa13,
            "lat": lat,
            "lon": lon,
            "confirming_nodes": confirming_nodes,
            "total_nodes": total_nodes,
            "ts": time.time(),
            "status": "open",
        }
        self._incidents.append(incident)
        return incident

    def set_status(self, incident_id: str, status: str) -> Optional[dict]:
        for inc in self._incidents:
            if inc["id"] == incident_id:
                inc["status"] = status
                return inc
        return None

    def close(self, incident_id: str) -> Optional[dict]:
        """Kept for backward compatibility — same as set_status(id, 'resolved')."""
        return self.set_status(incident_id, "resolved")

    def load(self, rows: list):
        """Seed the log from persisted rows on startup, newest last."""
        self._incidents = [dict(r) for r in rows]

    def recent(self, n: int = 100) -> list:
        return self._incidents[-n:]

    def all(self) -> list:
        return self._incidents


class AuditLog:
    """Structured incident audit-trail entries, matching the console's audit panel."""

    def __init__(self):
        self._entries: list = []

    def add(self, incident_id, severity: str, message: str) -> dict:
        # severity matches the console's tag styling: DANGER, SUCCESS, WARNING, INFO
        entry = {
            "incident_id": incident_id,
            "ts": time.time(),
            "severity": severity,
            "message": message,
        }
        self._entries.append(entry)
        return entry

    def load(self, rows: list):
        self._entries = [dict(r) for r in rows]

    def recent(self, n: int = 50) -> list:
        return self._entries[-n:]


class AudioCaptureBuffer:
    """Accumulates chunked mic self-test captures keyed by (node, mic, test_id)."""

    def __init__(self, timeout: float = AUDIO_CAPTURE_TIMEOUT):
        self._captures: Dict[Tuple, dict] = {}
        self.timeout = timeout

    def add_chunk(self, node_id, mic, test_id, idx, total, rate, name, chunk_bytes):
        """
        Adds one chunk. Returns (pcm_bytes, rate, name) once every chunk for
        this (node, mic, test_id) has arrived, otherwise None.
        """
        key = (node_id, mic, test_id)
        cap = self._captures.get(key)
        if cap is None:
            cap = {"total": total, "rate": rate, "name": name, "chunks": {}, "started": time.time()}
            self._captures[key] = cap

        cap["chunks"][idx] = chunk_bytes

        if len(cap["chunks"]) < cap["total"]:
            return None

        pcm = b"".join(cap["chunks"][i] for i in range(cap["total"]))
        del self._captures[key]
        return pcm, cap["rate"], cap["name"]

    def sweep_stale(self) -> list:
        """Drops captures that stalled past `timeout`. Returns the dropped keys."""
        now = time.time()
        stale = [k for k, cap in self._captures.items() if now - cap["started"] > self.timeout]
        for k in stale:
            del self._captures[k]
        return stale
