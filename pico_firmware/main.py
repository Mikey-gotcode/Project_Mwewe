# ── RFeye Node Firmware v1.1 ──────────────────────────────────────────────────
# Flash this main.py + rfeye_security.py + config.py to every Pico W.
# Each node auto-discovers the IRC server, registers itself, then streams
# TDOA scream-detection alerts. All register/heartbeat/alert packets are
# HMAC-signed with config.NODE_SECRET so the server can reject spoofed nodes.
#
# Packet protocol (all UDP, JSON-encoded):
#   DISCOVERY  →  broadcast: {"type":"discover"}
#   REGISTER   →  server:    {"type":"register","id":…,"name":…,"lat":…,"lon":…,"seq":…,"sig":…}
#   ALERT      →  server:    {"type":"alert","id":…,"angle":…,"tdoa12":…,"tdoa13":…,"seq":…,"sig":…}
#   HEARTBEAT  →  server:    {"type":"heartbeat","id":…,"ts":…,"seq":…,"sig":…}
#   ACK        ←  server:    {"type":"ack","server_ip":…}   (reply to discover, unsigned)

import network
import usocket as socket
import ujson as json
import utime
import struct
import math
import ubinascii
from machine import I2S, Pin, RTC

import config
import rfeye_security as sec


# ══════════════════════════════════════════════════════════════════════════════
# 1. Identity
# ══════════════════════════════════════════════════════════════════════════════

def get_node_id():
    """Stable unique ID derived from the Pico W's MAC address."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    mac  = ubinascii.hexlify(wlan.config("mac")).decode()
    if not config.NODE_NAME:
        raise RuntimeError(
            "config.NODE_NAME is required — it's the security allowlist key. "
            "Set it before flashing."
        )
    return mac, config.NODE_NAME


# ══════════════════════════════════════════════════════════════════════════════
# 2. WiFi
# ══════════════════════════════════════════════════════════════════════════════

def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if wlan.isconnected():
        return wlan
    print(f"[wifi] connecting to {config.WIFI_SSID}…")
    wlan.connect(config.WIFI_SSID, config.WIFI_PASSWORD)
    for _ in range(30):
        if wlan.isconnected():
            print(f"[wifi] connected — {wlan.ifconfig()[0]}")
            return wlan
        utime.sleep(1)
    raise RuntimeError("WiFi connection failed")


# ══════════════════════════════════════════════════════════════════════════════
# 3. Server discovery
# ══════════════════════════════════════════════════════════════════════════════

def discover_server(node_id):
    """
    Broadcast a discover packet on the LAN subnet.
    Returns the server IP string when an ACK is received.
    If config.SERVER_IP is hardcoded, skip and return it immediately.
    Discovery itself is unsigned (nothing sensitive is exchanged) — the
    security boundary is at REGISTER, which the server verifies.
    """
    if config.SERVER_IP:
        print(f"[discovery] using hardcoded server {config.SERVER_IP}")
        return config.SERVER_IP

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2)

    payload = json.dumps({"type": "discover", "id": node_id}).encode()
    deadline = utime.time() + config.DISCOVERY_TIMEOUT

    print("[discovery] broadcasting for IRC server…")
    while utime.time() < deadline:
        try:
            sock.sendto(payload, ("255.255.255.255", config.DISCOVERY_PORT))
            data, addr = sock.recvfrom(256)
            msg = json.loads(data)
            if msg.get("type") == "ack":
                server_ip = addr[0]
                print(f"[discovery] server found at {server_ip}")
                sock.close()
                return server_ip
        except OSError:
            pass                  # timeout — retry
        utime.sleep(1)

    sock.close()
    raise RuntimeError("IRC server not found on LAN")


# ══════════════════════════════════════════════════════════════════════════════
# 4. Registration
# ══════════════════════════════════════════════════════════════════════════════

def register_node(udp_sock, server_ip, mac, name, seqc):
    """Send an HMAC-signed, AES-encrypted REGISTER packet to the IRC server."""
    seq = seqc.next()
    canon = sec.canonical_register(mac, name, config.NODE_LAT, config.NODE_LON, seq)
    msg = {
        "type": "register",
        "id":   mac,
        "name": name,
        "lat":  config.NODE_LAT,
        "lon":  config.NODE_LON,
        "seq":  seq,
        "sig":  sec.sign(config.NODE_SECRET, canon),
    }
    send_secure(udp_sock, server_ip, config.SERVER_PORT, name, msg)
    print(f"[register] sent → {server_ip}:{config.SERVER_PORT} as '{name}'")


def send_secure(udp_sock, server_ip, port, name, msg_dict):
    """Sign is already baked into msg_dict by the caller — this just
    encrypts the signed message and puts it on the wire."""
    plaintext = json.dumps(msg_dict).encode()
    envelope = sec.encrypt_message(config.NODE_SECRET, name, plaintext)
    udp_sock.sendto(json.dumps(envelope).encode(), (server_ip, port))


# ══════════════════════════════════════════════════════════════════════════════
# 5. I2S microphone interface
# ══════════════════════════════════════════════════════════════════════════════

def init_i2s():
    bus0 = I2S(
        0,
        sck=Pin(config.I2S_SCK_0),
        ws=Pin(config.I2S_WS_0),
        sd=Pin(config.I2S_SD_01),
        mode=I2S.RX,
        bits=32,
        format=I2S.STEREO,
        rate=config.SAMPLE_RATE,
        ibuf=config.BLOCK_SIZE * 8,
    )
    bus1 = I2S(
        1,
        sck=Pin(config.I2S_SCK_1),
        ws=Pin(config.I2S_WS_1),
        sd=Pin(config.I2S_SD_2),
        mode=I2S.RX,
        bits=32,
        format=I2S.MONO,
        rate=config.SAMPLE_RATE,
        ibuf=config.BLOCK_SIZE * 4,
    )
    return bus0, bus1


def read_stereo(bus, buf):
    """Read a stereo DMA block → (left_samples[], right_samples[])."""
    bus.readinto(memoryview(buf))
    left, right = [], []
    for i in range(0, len(buf), 8):
        left.append( struct.unpack_from(">i", buf, i    )[0] >> 8)
        right.append(struct.unpack_from(">i", buf, i + 4)[0] >> 8)
    return left, right


def read_mono(bus, buf):
    """Read a mono DMA block → samples[]."""
    bus.readinto(memoryview(buf))
    return [struct.unpack_from(">i", buf, i)[0] >> 8
            for i in range(0, len(buf), 4)]


# ══════════════════════════════════════════════════════════════════════════════
# 6. Signal processing
# ══════════════════════════════════════════════════════════════════════════════

def band_energy_ratio(samples):
    """
    Returns fraction of signal power in the scream band (1–5 kHz).
    Uses a lightweight DFT limited to the relevant bin range.
    """
    n        = len(samples)
    mean     = sum(samples) // n
    norm     = [s - mean for s in samples]
    freq_res = config.SAMPLE_RATE / n
    low_bin  = int(config.SCREAM_LOW  / freq_res)
    high_bin = int(config.SCREAM_HIGH / freq_res)

    band_pwr = total_pwr = 0.0
    for k in range(1, n // 2):
        re = im = 0.0
        step = 2 * math.pi * k / n
        for t, x in enumerate(norm):
            a  = step * t
            re += x * math.cos(a)
            im += x * math.sin(a)
        p = re * re + im * im
        total_pwr += p
        if low_bin <= k <= high_bin:
            band_pwr += p

    return (band_pwr / total_pwr) if total_pwr > 0 else 0.0


def cross_correlate(sig_a, sig_b):
    """
    Returns delay in samples between sig_a and sig_b.
    Searches only within the physically possible range given mic spacing.
    Positive → sig_b arrived earlier.
    """
    max_delay = int((config.MIC_SPACING / 343.0) * config.SAMPLE_RATE) + 2
    n         = len(sig_a)
    best      = -1e18
    delay     = 0
    for d in range(-max_delay, max_delay + 1):
        corr = sum(sig_a[i] * sig_b[i + d]
                   for i in range(n)
                   if 0 <= i + d < n)
        if corr > best:
            best  = corr
            delay = d
    return delay


def estimate_angle(delay_12, delay_13):
    """
    Convert two sample delays to an estimated azimuth angle (degrees).
    Assumes a linear 3-mic array with equal MIC_SPACING.
    """
    c = 343.0
    d = config.MIC_SPACING
    sr = config.SAMPLE_RATE

    def safe_acos(v):
        return math.acos(max(-1.0, min(1.0, v))) * 180 / math.pi

    a12 = safe_acos((c * delay_12 / sr) / d)
    a13 = safe_acos((c * delay_13 / sr) / d)
    return (a12 + a13) / 2.0


# ══════════════════════════════════════════════════════════════════════════════
# 6b. Hardware self-test — capture + send short mic snippets on boot
# ══════════════════════════════════════════════════════════════════════════════
# Short by design: RAM on the ESP32 is limited, and this only needs to
# confirm "is this mic actually producing signal", not deliver studio audio.
# ~10 blocks decimated by 2 ≈ 0.23s per mic at ~22kHz effective rate.

AUDIO_TEST_BLOCKS      = 10     # I2S blocks captured per mic
AUDIO_TEST_DECIMATION  = 2      # keep every Nth sample (halves data + still ≥2x scream band)
AUDIO_TEST_SHIFT       = 16     # crude fixed-gain quantization to 8-bit — tune if clips sound silent/clipped
# Kept small deliberately: raw chunk bytes get hex-encoded into the signed
# message, which then gets AES-encrypted and hex-encoded AGAIN for the wire
# — roughly a 4x blowup end to end. 128 raw bytes → ~970 bytes on the wire,
# with real margin under a typical ~1500-byte WiFi MTU (not just barely
# under it) so it never needs IP fragmentation, which hotspots often
# handle poorly for UDP.
AUDIO_TEST_CHUNK_BYTES = 128


def _clamp8(sample, shift=AUDIO_TEST_SHIFT):
    """Crude fixed-gain scaling to unsigned 8-bit PCM. Not auto-gain —
    if clips come back silent, lower `shift`; if clipped/distorted, raise it."""
    v = (sample >> shift) + 128
    if v < 0:
        return 0
    if v > 255:
        return 255
    return v


def capture_test_snippet_stereo(bus0, buf0):
    """
    Capture from the stereo bus (mic1=left, mic2=right) → two 8-bit PCM
    bytearrays. Writes directly into pre-sized buffers rather than
    accumulating into a growing Python list — a list holding thousands of
    ints needs one large contiguous allocation for its backing array
    (easy to fail on a fragmented ESP32 heap), whereas a pre-sized
    bytearray is a single small up-front allocation.
    """
    per_block = config.BLOCK_SIZE // AUDIO_TEST_DECIMATION
    n = per_block * AUDIO_TEST_BLOCKS
    left_out  = bytearray(n)
    right_out = bytearray(n)
    pos = 0
    for _ in range(AUDIO_TEST_BLOCKS):
        l, r = read_stereo(bus0, buf0)
        for i in range(0, config.BLOCK_SIZE, AUDIO_TEST_DECIMATION):
            left_out[pos]  = _clamp8(l[i])
            right_out[pos] = _clamp8(r[i])
            pos += 1
    return left_out, right_out


def capture_test_snippet_mono(bus1, buf1):
    """Capture from the mono bus (mic3) → one 8-bit PCM bytearray."""
    per_block = config.BLOCK_SIZE // AUDIO_TEST_DECIMATION
    n = per_block * AUDIO_TEST_BLOCKS
    out = bytearray(n)
    pos = 0
    for _ in range(AUDIO_TEST_BLOCKS):
        m = read_mono(bus1, buf1)
        for i in range(0, config.BLOCK_SIZE, AUDIO_TEST_DECIMATION):
            out[pos] = _clamp8(m[i])
            pos += 1
    return out


def send_audio_snippet(udp, server_ip, mac, name, mic_idx, pcm_bytes, effective_rate, seqc):
    """Signs, encrypts, and sends one mic's snippet as a series of small
    chunks (each independently signed) rather than one large packet."""
    test_id = ubinascii.hexlify(bytes(urandom_byte() for _ in range(4))).decode()
    total_chunks = (len(pcm_bytes) + AUDIO_TEST_CHUNK_BYTES - 1) // AUDIO_TEST_CHUNK_BYTES

    for idx in range(total_chunks):
        chunk = pcm_bytes[idx * AUDIO_TEST_CHUNK_BYTES : (idx + 1) * AUDIO_TEST_CHUNK_BYTES]
        data_hex = ubinascii.hexlify(chunk).decode()
        seq = seqc.next()
        canon = sec.canonical_audio_chunk(mac, mic_idx, test_id, idx, total_chunks, effective_rate, data_hex, seq)
        msg = {
            "type":    "audio_chunk",
            "id":      mac,
            "name":    name,
            "mic":     mic_idx,
            "test_id": test_id,
            "chunk":   idx,
            "total":   total_chunks,
            "rate":    effective_rate,
            "data":    data_hex,
            "seq":     seq,
            "sig":     sec.sign(config.NODE_SECRET, canon),
        }
        send_secure(udp, server_ip, config.SERVER_PORT, name, msg)
        utime.sleep_ms(15)   # brief pacing so we don't flood the WiFi/UDP stack

    print(f"[selftest] mic{mic_idx}: sent {total_chunks} chunk(s), {len(pcm_bytes)}B @ {effective_rate}Hz")


def urandom_byte():
    import urandom
    return urandom.getrandbits(8)


def run_self_test(udp, server_ip, mac, name, bus0, buf0, bus1, buf1, seqc):
    import gc
    print("[selftest] capturing mic snippets…")
    effective_rate = config.SAMPLE_RATE // AUDIO_TEST_DECIMATION

    gc.collect()
    m1, m2 = capture_test_snippet_stereo(bus0, buf0)
    send_audio_snippet(udp, server_ip, mac, name, 1, m1, effective_rate, seqc)
    send_audio_snippet(udp, server_ip, mac, name, 2, m2, effective_rate, seqc)
    del m1, m2
    gc.collect()

    m3 = capture_test_snippet_mono(bus1, buf1)
    send_audio_snippet(udp, server_ip, mac, name, 3, m3, effective_rate, seqc)
    del m3
    gc.collect()

    print("[selftest] done — check the dashboard's Mic Self-Tests panel")


# ══════════════════════════════════════════════════════════════════════════════
# 7. Main application loop
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # ── Boot ──
    buzzer = Pin(config.BUZZER_PIN, Pin.OUT)
    buzzer.off()

    # ── Network ──
    connect_wifi()
    mac, name = get_node_id()
    print(f"[node] id={mac}  name={name}")

    server_ip = discover_server(mac)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(0.5)

    seqc = sec.SeqCounter()
    register_node(udp, server_ip, mac, name, seqc)

    # Beep twice: "I'm registered"
    for _ in range(2):
        buzzer.on(); utime.sleep_ms(80)
        buzzer.off(); utime.sleep_ms(80)

    # ── I2S ──
    bus0, bus1 = init_i2s()
    buf0 = bytearray(config.BLOCK_SIZE * 8)   # stereo
    buf1 = bytearray(config.BLOCK_SIZE * 4)   # mono

    if config.SELF_TEST_ON_BOOT:
        try:
            run_self_test(udp, server_ip, mac, name, bus0, buf0, bus1, buf1, seqc)
        except Exception as e:
            # A self-test failure shouldn't block real scream detection from starting.
            print(f"[selftest] failed: {e}")

    print("[rfeye] listening…")
    last_heartbeat = utime.time()
    HEARTBEAT_INTERVAL = 10       # seconds

    while True:
        now = utime.time()

        # ── Heartbeat ──
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            seq = seqc.next()
            canon = sec.canonical_heartbeat(mac, now, seq)
            hb = {
                "type": "heartbeat",
                "id":   mac,
                "name": name,
                "ts":   now,
                "seq":  seq,
                "sig":  sec.sign(config.NODE_SECRET, canon),
            }
            try:
                send_secure(udp, server_ip, config.SERVER_PORT, name, hb)
            except OSError:
                pass
            last_heartbeat = now

        # ── Audio capture ──
        mic1, mic2 = read_stereo(bus0, buf0)
        mic3       = read_mono(bus1, buf1)

        ratio = band_energy_ratio(mic1)

        if ratio < config.SCREAM_THRESHOLD:
            continue

        # ── Scream detected ──
        print(f"[alert] scream! ratio={ratio:.3f}")
        buzzer.on(); utime.sleep_ms(200); buzzer.off()

        delay_12 = cross_correlate(mic1, mic2)
        delay_13 = cross_correlate(mic1, mic3)
        angle    = estimate_angle(delay_12, delay_13)

        angle_r  = round(angle, 2)
        tdoa12_r = round(delay_12 / config.SAMPLE_RATE * 1e6, 2)  # µs
        tdoa13_r = round(delay_13 / config.SAMPLE_RATE * 1e6, 2)  # µs

        seq = seqc.next()
        canon = sec.canonical_alert(
            mac, angle_r, tdoa12_r, tdoa13_r, config.NODE_LAT, config.NODE_LON, now, seq
        )
        alert = {
            "type":   "alert",
            "id":     mac,
            "name":   name,
            "angle":  angle_r,
            "tdoa12": tdoa12_r,
            "tdoa13": tdoa13_r,
            "lat":    config.NODE_LAT,
            "lon":    config.NODE_LON,
            "ts":     now,
            "seq":    seq,
            "sig":    sec.sign(config.NODE_SECRET, canon),
        }

        try:
            send_secure(udp, server_ip, config.SERVER_PORT, name, alert)
            print(f"[alert] sent → angle={angle:.1f}°")
        except OSError as e:
            print(f"[alert] send failed: {e}")
            # Re-discover server on next heartbeat cycle
            try:
                server_ip = discover_server(mac)
                register_node(udp, server_ip, mac, name, seqc)
            except RuntimeError:
                pass


if __name__ == "__main__":
    main()