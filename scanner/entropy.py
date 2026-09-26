"""Entropy and "shape of the text" measurements used for obfuscation hints."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol (0.0 - 8.0 for bytes)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def longest_line(text: str) -> int:
    """Length of the longest line in *text*."""
    return max(map(len, text.split("\n"))) if text else 0


def is_probably_binary(head: bytes) -> bool:
    """Heuristic binary detection on the first few KB of a file.

    NUL bytes are a strong binary signal. Otherwise, a high share of control
    characters (excluding TAB/LF/CR/FF) indicates non-text content. Bytes
    >= 0x80 are not counted, as UTF-8 text legitimately contains them.
    """
    if not head:
        return False
    if b"\x00" in head:
        return True
    control = len(head) - len(head.translate(None, _CONTROL))
    return control / len(head) > 0.10


_CONTROL = bytes(b for b in range(32) if b not in (9, 10, 12, 13, 27))
