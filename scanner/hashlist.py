"""Known-bad SHA256 hash lists (IOC files)."""

from __future__ import annotations

import re
from pathlib import Path

_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")


def load_hash_list(path: str | Path) -> dict[str, str]:
    """Load SHA256 hashes, one per line; text after the hash is a label.

    Lines starting with ``#`` are comments. ``sha256sum`` output works as-is.
    """
    out: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _SHA256.search(line)
            if not m:
                continue
            label = (line[:m.start()] + line[m.end():]).strip(" \t,;*") or Path(path).name
            out[m.group(0).lower()] = label
    return out
