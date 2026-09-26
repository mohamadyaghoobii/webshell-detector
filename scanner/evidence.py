"""Sanitised evidence snippets.

Snippets are deliberately small: they explain a detection without copying
a working payload into reports or logs. Long encoded blobs and obvious
secrets are redacted and control characters are escaped.
"""

from __future__ import annotations

import bisect
import re

from .models import Evidence

_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_\-]{48,}")
_HEXESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")
_SECRET_RE = re.compile(
    r"""(?ix)
    ((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth(?:_pass)?|private[_-]?key)
     ["']?\s*(?:=>|=|:)\s*["'])([^"'\n]{4,})(["'])
    """
)


_NEWLINE = re.compile("\n")


class LineIndex:
    """Maps character offsets to 1-based line numbers."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._nl_cache: list[int] | None = None

    @property
    def _nl(self) -> list[int]:
        # Built lazily: most files never need a line number.
        if self._nl_cache is None:
            self._nl_cache = [m.start() for m in _NEWLINE.finditer(self.text)]
        return self._nl_cache

    def line_of(self, offset: int) -> int:
        return bisect.bisect_left(self._nl, offset) + 1

    def line_bounds(self, offset: int) -> tuple[int, int]:
        idx = bisect.bisect_left(self._nl, offset)
        start = self._nl[idx - 1] + 1 if idx > 0 else 0
        end = self._nl[idx] if idx < len(self._nl) else len(self.text)
        return start, end


def _redact_blob(m: re.Match[str]) -> str:
    """Redact encoded blobs but keep filesystem paths readable."""
    s = m.group(0)
    segments = [seg for seg in s.split("/") if seg]
    if s.count("/") >= 2 and segments and max(len(seg) for seg in segments) < 40:
        return s
    return f"[BLOB len={len(s)}]"


def sanitize(text: str, max_len: int = 160) -> str:
    """Redact blobs/secrets, escape control characters and cap the length."""
    text = _BLOB_RE.sub(_redact_blob, text)
    text = _HEXESC_RE.sub(lambda m: f"[HEX-ESCAPES len={len(m.group(0))}]", text)
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}[REDACTED]{m.group(3)}", text)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif o < 32 or o == 127 or (0x80 <= o < 0xA0):
            out.append(f"\\x{o:02x}")
        elif not ch.isprintable():
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    clean = re.sub(r" {2,}", " ", "".join(out)).strip()
    if len(clean) > max_len:
        clean = clean[: max_len - 3] + "..."
    return clean


def snippet_at(index: LineIndex, start: int, end: int, max_len: int = 160,
               source: str | None = None) -> Evidence:
    """Build an Evidence object for the match spanning [start, end)."""
    line_start, line_end = index.line_bounds(start)
    lo = max(line_start, start - 50)
    hi = min(line_end, max(end, start) + 90)
    text = index.text[lo:hi]
    prefix = "..." if lo > line_start else ""
    suffix = "..." if hi < line_end else ""
    return Evidence(
        line=index.line_of(start),
        snippet=prefix + sanitize(text, max_len) + suffix,
        source=source,
    )
