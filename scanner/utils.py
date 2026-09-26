"""Small, dependency-free helpers shared by the scanner modules."""

from __future__ import annotations

import os
import re
import shlex
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.I)
_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*$", re.I)
_UNITS = {"": 1024 ** 2, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
_DUR = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_size(value: str | int | float) -> int:
    """Parse a size such as ``20M``, ``512K`` or ``1G`` into bytes.

    A bare number is interpreted as megabytes to stay compatible with the
    original prototype's ``--max-size 20`` option.
    """
    if isinstance(value, (int, float)):
        return int(value * 1024 * 1024)
    m = _SIZE_RE.match(str(value))
    if not m:
        raise ValueError(f"invalid size: {value!r}")
    number, unit = m.groups()
    return int(float(number) * _UNITS[unit.lower()])


def parse_duration(value: str) -> timedelta:
    """Parse ``30m``, ``12h``, ``7d`` or ``2w`` into a timedelta."""
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ValueError(f"invalid duration: {value!r} (examples: 12h, 7d, 2w)")
    number, unit = m.groups()
    return timedelta(seconds=float(number) * _DUR[unit.lower()])


def parse_date(value: str) -> datetime:
    """Parse an ISO date or datetime (local time when no zone is given)."""
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"invalid date: {value!r} (examples: 2026-09-20, 2026-09-20T14:00)"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def ts_to_iso(ts: float | None) -> str | None:
    """Convert a POSIX timestamp to a local ISO-8601 string."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(
            timespec="seconds"
        )
    except (OverflowError, OSError, ValueError):
        return None


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def is_within(path: str | os.PathLike, root: str | os.PathLike) -> bool:
    """Return True when *path* lies inside *root* after normalisation.

    Uses ``os.path.commonpath`` on absolute, normalised paths rather than a
    string prefix test, so ``/var/www/html2`` is *not* inside ``/var/www/html``.
    Callers are responsible for resolving symlinks first when needed.
    """
    try:
        p = os.path.normpath(os.path.abspath(os.fspath(path)))
        r = os.path.normpath(os.path.abspath(os.fspath(root)))
        return os.path.commonpath([p, r]) == r
    except ValueError:
        return False


def safe_relpath(path: str | os.PathLike, root: str | os.PathLike) -> str:
    """Relative POSIX path of *path* below *root*, or the absolute path."""
    try:
        if is_within(path, root):
            rel = os.path.relpath(os.fspath(path), os.fspath(root))
            return PurePosixPath(Path(rel)).as_posix()
    except ValueError:
        pass
    return os.fspath(path)


@lru_cache(maxsize=4096)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob with ``**`` support into a compiled regex.

    * ``**`` matches any number of path components (including none)
    * ``*`` matches within a single component
    * ``?`` matches one character within a component
    * a pattern without ``/`` matches the basename anywhere in the tree
    """
    pat = pattern.strip().replace("\\", "/")
    anchored = "/" in pat.rstrip("/")
    if pat.startswith("/"):
        pat = pat[1:]
    if pat.endswith("/"):
        pat += "**"
    out = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 2] == "**":
                i += 2
                if pat[i:i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    if anchored:
        return re.compile(f"^{body}$")
    return re.compile(f"^(?:.*/)?{body}$")


def glob_match(relpath: str, pattern: str) -> bool:
    """Match a POSIX relative path against a ``**``-aware glob."""
    return bool(glob_to_regex(pattern).match(relpath))


def shell_quote(path: str) -> str:
    """Quote a path for display in *suggested* (never executed) commands."""
    return shlex.quote(path)


def human_size(n: int | None) -> str:
    if n is None:
        return "-"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def is_hidden_name(name: str) -> bool:
    return name.startswith(".") and name not in {".", ".."}
