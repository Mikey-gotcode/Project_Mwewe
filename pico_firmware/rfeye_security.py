# ── RFeye Node Security ───────────────────────────────────────────────────────
# Identical across all nodes (like main.py) — only config.py's NODE_SECRET
# differs per node. Provides lightweight HMAC-SHA256 message signing so the
# server can reject spoofed/rogue nodes, plus a per-boot sequence counter for
# replay protection.
#
# NOTE ON HONESTY: this is deliberately lightweight, not a full security
# stack. It gives you authenticated, integrity-checked, replay-resistant
# messages from nodes that hold the shared secret. It does NOT give you
# perfect protection against a node that has been physically captured and
# still has power (the attacker has the secret at that point) — that needs
# secure key storage hardware the Pico W doesn't have. Treat NODE_SECRET
# with the same care as a password.

try:
    import hashlib
except ImportError:
    import uhashlib as hashlib
try:
    import ubinascii as binascii
except ImportError:
    import binascii
try:
    import cryptolib
except ImportError:
    cryptolib = None
import urandom

_BLOCK_SIZE = 64


def _hmac_sha256(key, msg):
    """Manual HMAC-SHA256 (MicroPython's hashlib has no hmac module)."""
    if len(key) > _BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (_BLOCK_SIZE - len(key))
    o_pad = bytes(b ^ 0x5C for b in key)
    i_pad = bytes(b ^ 0x36 for b in key)
    inner = hashlib.sha256(i_pad + msg).digest()
    return hashlib.sha256(o_pad + inner).digest()


def sign(secret, canonical_str):
    """64-bit (16 hex char) signature — enough given rate limiting on the
    server side, and kept short to stay cheap on airtime/CPU."""
    digest = _hmac_sha256(secret, canonical_str.encode())
    return "".join("%02x" % b for b in digest[:8])


class SeqCounter:
    """
    Per-boot monotonic sequence number: (random boot nonce << 16) | counter.
    The server re-baselines its replay tracking on every verified REGISTER,
    so a reboot just establishes a fresh baseline — no persisted counter
    needed on the node itself.

    Limitation: this stops replay *within* a session and stops a stale
    REGISTER/HEARTBEAT/ALERT being replayed later, but true across-reboot
    replay protection would need NTP-synced timestamps, which is left out
    to keep this lightweight. Good enough to stop "capture one packet off
    the LAN and resend it" style attacks, which is the realistic threat here.
    """

    def __init__(self):
        self.boot_nonce = urandom.getrandbits(16)
        self.counter = 0

    def next(self):
        self.counter += 1
        return (self.boot_nonce << 16) | (self.counter & 0xFFFF)


# ── Canonical signing strings ───────────────────────────────────────────────
# MUST match server/security.py byte-for-byte. Fixed-precision "%" formatting
# is used deliberately (not str()/json dumps) because MicroPython's float
# repr can differ from CPython's — using explicit precision on both ends
# keeps the signed string identical regardless of platform.

def canonical_register(node_id, name, lat, lon, seq):
    return "register|%s|%s|%.6f|%.6f|%d" % (node_id, name, lat, lon, seq)


def canonical_heartbeat(node_id, ts, seq):
    return "heartbeat|%s|%d|%d" % (node_id, ts, seq)


def canonical_alert(node_id, angle, tdoa12, tdoa13, lat, lon, ts, seq):
    return "alert|%s|%.2f|%.2f|%.2f|%.6f|%.6f|%d|%d" % (
        node_id, angle, tdoa12, tdoa13, lat, lon, ts, seq,
    )


def canonical_audio_chunk(node_id, mic, test_id, chunk_idx, total, rate, data_hex, seq):
    return "audio_chunk|%s|%d|%s|%d|%d|%d|%s|%d" % (
        node_id, mic, test_id, chunk_idx, total, rate, data_hex, seq,
    )


# ── Encryption (AES-128-CTR, built on AES-ECB) ──────────────────────────────
# CTR mode isn't guaranteed as a cryptolib mode across every MicroPython
# port, but ECB (the underlying block primitive) is — so CTR is built
# manually here: keystream = AES_ECB(key, nonce || block_counter), XORed
# with the plaintext. This exact construction is mirrored on the server
# using the 'cryptography' package's native CTR mode, so both sides agree.
#
# NOTE ON HONESTY: this hides payload contents from a passive eavesdropper
# on the LAN (or hotspot). It's encrypt-*after*-sign, not authenticated
# encryption (AES-GCM) — the HMAC above still does all the authentication
# and integrity work; CTR ciphertext alone is malleable. That's an
# intentional, documented trade-off to keep this running on an ESP32
# without a hardware AES-GCM peripheral, not an oversight.

def derive_enc_key(secret):
    """Separate encryption key from the signing secret — a break in one
    doesn't hand over the other."""
    return hashlib.sha256(secret + b":enc").digest()[:16]


def _ctr_keystream(key16, nonce8, nbytes):
    aes = cryptolib.aes(key16, 1)  # mode 1 = ECB (the block primitive)
    nblocks = (nbytes + 15) // 16
    ks = b""
    for i in range(nblocks):
        counter_block = nonce8 + i.to_bytes(8, "big")
        ks += aes.encrypt(counter_block)
    return ks[:nbytes]


def _ctr_crypt(key16, nonce8, data):
    ks = _ctr_keystream(key16, nonce8, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))


def encrypt_message(secret, name, plaintext_bytes):
    """
    Encrypts an already-signed JSON message. Returns the outer envelope
    dict ready for json.dumps: {"name": ..., "n": nonce_hex, "ct": ct_hex}.
    'name' stays in cleartext — the server needs it to look up which
    secret to decrypt with, the same trade-off TLS makes with SNI.
    """
    enc_key = derive_enc_key(secret)
    nonce = bytes(urandom.getrandbits(8) for _ in range(8))
    ct = _ctr_crypt(enc_key, nonce, plaintext_bytes)
    return {
        "name": name,
        "n":    binascii.hexlify(nonce).decode(),
        "ct":   binascii.hexlify(ct).decode(),
    }
