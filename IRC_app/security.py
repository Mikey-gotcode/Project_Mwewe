"""
RFeye server-side security.

Verifies HMAC-signed messages from nodes against server/allowlist.json,
rejects unknown/unsigned/replayed/rate-exceeding messages. The canonical
string builders here MUST match pico/rfeye_security.py byte-for-byte —
that's what lets the server recompute and compare the signature.

Provision a new node with:
    python3 tools/provision_node.py <node-name>
"""

import hashlib
import hmac
import json
import re
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALLOWLIST_PATH = Path(__file__).parent / "allowlist.json"

# Node names are embedded in the HMAC'd string — restrict the charset so a
# crafted name (e.g. containing "|") can't shift fields and forge a valid
# signature for different data.
_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")

ALERT_RATE_LIMIT_WINDOW = 2.0   # seconds
ALERT_RATE_LIMIT_MAX    = 1     # max alerts per window per node

MAX_AUDIO_CHUNKS   = 256    # sanity bound — real self-tests use far fewer
MAX_AUDIO_CHUNK_HEX = 4096  # 2KB raw per chunk, generous vs the ~1KB actually sent

# In-memory replay/rate state (per server process — fine for a single
# long-running server.py instance).
_last_seq: dict     = {}   # node "id" (mac) → last verified seq
_alert_times: dict  = {}   # node "id" → recent alert timestamps


def load_allowlist() -> dict:
    """{ node_name: secret_hex }. Missing file = no nodes trusted yet."""
    if not ALLOWLIST_PATH.exists():
        return {}
    return json.loads(ALLOWLIST_PATH.read_text())


def valid_name(name) -> bool:
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def _canon_register(node_id, name, lat, lon, seq):
    return "register|%s|%s|%.6f|%.6f|%d" % (node_id, name, lat, lon, seq)


def _canon_heartbeat(node_id, ts, seq):
    return "heartbeat|%s|%d|%d" % (node_id, int(ts), seq)


def _canon_alert(node_id, angle, tdoa12, tdoa13, lat, lon, ts, seq):
    return "alert|%s|%.2f|%.2f|%.2f|%.6f|%.6f|%d|%d" % (
        node_id, angle, tdoa12, tdoa13, lat, lon, int(ts), seq,
    )


def _canon_audio_chunk(node_id, mic, test_id, chunk_idx, total, rate, data_hex, seq):
    return "audio_chunk|%s|%d|%s|%d|%d|%d|%s|%d" % (
        node_id, mic, test_id, chunk_idx, total, rate, data_hex, seq,
    )


def _sign(secret: bytes, canon: str) -> str:
    digest = hmac.new(secret, canon.encode(), hashlib.sha256).digest()
    return digest[:8].hex()


# ── Decryption (AES-128-CTR — matches pico/rfeye_security.py exactly) ──────

def derive_enc_key(secret: bytes) -> bytes:
    return hashlib.sha256(secret + b":enc").digest()[:16]


def decrypt_envelope(envelope: dict, allowlist: dict):
    """
    First step for every packet on the data port: unwrap the outer
    {"name","n","ct"} envelope into the inner signed JSON message.
    Returns (ok, inner_msg_or_None, reason). verify() still needs to run
    on the returned inner message afterwards — decryption only proves the
    sender knew this node's key, not that the fields themselves are
    authentic (CTR ciphertext is malleable; the HMAC inside does that job).
    """
    name   = envelope.get("name")
    n_hex  = envelope.get("n")
    ct_hex = envelope.get("ct")

    if not valid_name(name):
        return False, None, "invalid or missing name"
    if not isinstance(n_hex, str) or not isinstance(ct_hex, str):
        return False, None, "missing nonce/ciphertext"

    secret_hex = allowlist.get(name)
    if secret_hex is None:
        return False, None, f"unknown node '{name}' — not in allowlist"

    try:
        secret = bytes.fromhex(secret_hex)
        nonce  = bytes.fromhex(n_hex)
        ct     = bytes.fromhex(ct_hex)
        if len(nonce) != 8:
            return False, None, "bad nonce length"

        key = derive_enc_key(secret)
        initial_counter = nonce + b"\x00" * 8   # matches the node's nonce||counter construction
        decryptor = Cipher(algorithms.AES(key), modes.CTR(initial_counter)).decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        inner = json.loads(plaintext.decode())
    except Exception:
        return False, None, "decryption failed"

    if not isinstance(inner, dict):
        return False, None, "decrypted payload not an object"

    return True, inner, "ok"


def verify(msg: dict, allowlist: dict):
    """
    Verify an incoming register/heartbeat/alert message.
    Returns (ok: bool, reason: str). Never raises on malformed input —
    a malformed/malicious packet is just a rejection, not a crash.
    """
    t       = msg.get("type")
    name    = msg.get("name")
    node_id = msg.get("id")
    seq     = msg.get("seq")
    sig     = msg.get("sig")

    if t not in ("register", "heartbeat", "alert", "audio_chunk"):
        return False, f"unsigned message type '{t}'"
    if not valid_name(name):
        return False, "invalid or missing name"
    if not isinstance(node_id, str) or not node_id:
        return False, "missing id"
    if not isinstance(seq, int) or not isinstance(sig, str):
        return False, "missing seq/sig"

    secret_hex = allowlist.get(name)
    if secret_hex is None:
        return False, f"unknown node '{name}' — not in allowlist"

    try:
        secret = bytes.fromhex(secret_hex)
        if t == "register":
            canon = _canon_register(node_id, name, msg.get("lat", 0), msg.get("lon", 0), seq)
        elif t == "heartbeat":
            canon = _canon_heartbeat(node_id, msg.get("ts", 0), seq)
        elif t == "alert":
            canon = _canon_alert(
                node_id, msg.get("angle", 0), msg.get("tdoa12", 0), msg.get("tdoa13", 0),
                msg.get("lat", 0), msg.get("lon", 0), msg.get("ts", 0), seq,
            )
        else:  # audio_chunk
            mic       = msg.get("mic")
            test_id   = msg.get("test_id")
            chunk_idx = msg.get("chunk")
            total     = msg.get("total")
            rate      = msg.get("rate")
            data_hex  = msg.get("data", "")
            if not isinstance(mic, int) or not isinstance(test_id, str):
                return False, "malformed audio_chunk fields"
            if not isinstance(chunk_idx, int) or not isinstance(total, int) or not isinstance(rate, int):
                return False, "malformed audio_chunk fields"
            if not (0 < total <= MAX_AUDIO_CHUNKS) or not (0 <= chunk_idx < total):
                return False, "audio_chunk index/total out of bounds"
            if len(data_hex) > MAX_AUDIO_CHUNK_HEX:
                return False, "audio_chunk data too large"
            canon = _canon_audio_chunk(node_id, mic, test_id, chunk_idx, total, rate, data_hex, seq)
    except (TypeError, ValueError):
        return False, "malformed fields"

    expected = _sign(secret, canon)
    if not hmac.compare_digest(expected, sig):
        return False, "bad signature"

    # ── Replay protection ──
    # REGISTER always re-baselines (a fresh boot legitimately restarts the
    # node's sequence space — see SeqCounter's docstring on the node side).
    if t == "register":
        _last_seq[node_id] = seq
    else:
        last = _last_seq.get(node_id, -1)
        if seq <= last:
            return False, f"replayed/old seq ({seq} <= {last})"
        _last_seq[node_id] = seq

    # ── Rate limiting (alerts only) ──
    if t == "alert":
        now = time.time()
        recent = [x for x in _alert_times.get(node_id, []) if now - x < ALERT_RATE_LIMIT_WINDOW]
        if len(recent) >= ALERT_RATE_LIMIT_MAX:
            return False, "alert rate limit exceeded"
        recent.append(now)
        _alert_times[node_id] = recent

    return True, "ok"
