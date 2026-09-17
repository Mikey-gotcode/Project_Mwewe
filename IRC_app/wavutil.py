"""Minimal WAV file writer — wraps raw 8-bit unsigned mono PCM samples
(what the node's self-test sends) into a header browsers can play directly."""

import struct


def build_wav_bytes(pcm_bytes: bytes, sample_rate: int) -> bytes:
    num_channels    = 1
    bits_per_sample = 8
    byte_rate       = sample_rate * num_channels * bits_per_sample // 8
    block_align     = num_channels * bits_per_sample // 8
    data_size       = len(pcm_bytes)

    header  = b"RIFF" + struct.pack("<I", 36 + data_size) + b"WAVE"
    header += b"fmt " + struct.pack(
        "<IHHIIHH", 16, 1, num_channels, sample_rate, byte_rate, block_align, bits_per_sample
    )
    header += b"data" + struct.pack("<I", data_size)
    return header + pcm_bytes
