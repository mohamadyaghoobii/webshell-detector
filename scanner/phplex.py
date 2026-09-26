"""A small, regex-driven PHP lexer for *static* analysis.

It never evaluates code. It produces position-preserving "views" of the
source so detection rules can distinguish code from comments and strings:

* ``nocomment`` - comments blanked; strings and inline HTML kept.
* ``codeonly``  - comments, string *contents* and inline HTML blanked.

Blanking replaces characters with spaces but keeps newlines, so offsets and
line numbers are identical across all views.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_OPEN_TAG = re.compile(r"<\?(?:php(?=[\s;]|$)|=|(?![A-Za-z]))", re.I)

_PHP_TOKEN = re.compile(
    r"""
    (?P<code>[^'"`/#?<]+)
  | (?P<lc>(?://|\#(?!\[))[^\n?]*(?:\?(?!>)[^\n?]*)*)
  | (?P<bc>/\*[\s\S]*?(?:\*/|\Z))
  | (?P<sq>'(?:[^'\\]|\\[\s\S])*(?:'|\Z))
  | (?P<dq>"(?:[^"\\]|\\[\s\S])*(?:"|\Z))
  | (?P<bt>`(?:[^`\\]|\\[\s\S])*(?:`|\Z))
  | (?P<hd><<<[ \t]*(?P<hq>['"]?)(?P<hid>[A-Za-z_]\w*)(?P=hq)\r?\n[\s\S]*?\n[ \t]*(?P=hid)(?!\w))
  | (?P<close>\?>)
  | (?P<other>[\s\S])
    """,
    re.X,
)

_BLANK = re.compile(r"[^\n]")


def _blank(s: str) -> str:
    return _BLANK.sub(" ", s)


@dataclass
class StringLiteral:
    start: int
    end: int
    quote: str          # ' " ` or <<<
    body: str           # raw body (escapes not processed)

    def value(self) -> str | None:
        """Unescaped value; None for interpolated double-quoted strings."""
        if self.quote == "'":
            return self.body.replace("\\\\", "\x00").replace("\\'", "'").replace("\x00", "\\")
        if self.quote == '"':
            if re.search(r"(?<!\\)\$[A-Za-z_{]", self.body):
                return None
            return unescape_double(self.body)
        return None


@dataclass
class PHPViews:
    raw: str
    nocomment: str
    codeonly: str
    strings: list[StringLiteral] = field(default_factory=list)
    has_php: bool = False
    backticks: list[tuple[int, int]] = field(default_factory=list)


_DQ_ESC = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|u\{[0-9A-Fa-f]+\}|[nrtvef\\$\"])")
_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "v": "\v", "e": "\x1b", "f": "\f",
           "\\": "\\", "$": "$", '"': '"'}


def unescape_double(body: str) -> str:
    """Process PHP double-quoted string escapes (\\xNN, octal, \\u{...})."""

    def repl(m: re.Match[str]) -> str:
        e = m.group(1)
        if e[0] == "x":
            return chr(int(e[1:], 16))
        if e[0] == "u":
            try:
                return chr(int(e[2:-1], 16))
            except (ValueError, OverflowError):
                return m.group(0)
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF)
        return _SIMPLE.get(e, m.group(0))

    return _DQ_ESC.sub(repl, body)


def lex_php(text: str) -> PHPViews:
    """Split *text* into PHP views. Inline HTML is treated as non-code."""
    noc: list[str] = []
    code: list[str] = []
    strings: list[StringLiteral] = []
    backticks: list[tuple[int, int]] = []
    pos = 0
    n = len(text)
    has_php = False
    while pos < n:
        m = _OPEN_TAG.search(text, pos)
        if not m:
            html = text[pos:]
            noc.append(html)
            code.append(_blank(html))
            break
        html = text[pos:m.start()]
        noc.append(html)
        code.append(_blank(html))
        tag = m.group(0)
        noc.append(tag)
        code.append(tag)
        pos = m.end()
        has_php = True
        # PHP mode
        while pos < n:
            t = _PHP_TOKEN.match(text, pos)
            if t is None:  # pragma: no cover - the grammar always matches
                break
            kind = t.lastgroup
            s = t.group(0)
            if kind in ("hq", "hid"):
                kind = "hd"
            if kind == "code" or kind == "other":
                noc.append(s)
                code.append(s)
            elif kind in ("lc", "bc"):
                blank = _blank(s)
                noc.append(blank)
                code.append(blank)
            elif kind in ("sq", "dq", "bt"):
                q = s[0]
                body = s[1:-1] if len(s) >= 2 and s[-1] == q else s[1:]
                strings.append(StringLiteral(t.start(), t.end(), q, body))
                noc.append(s)
                code.append(q + _blank(s[1:-1]) + (s[-1] if len(s) >= 2 else ""))
                if q == "`":
                    backticks.append((t.start(), t.end()))
            elif t.group("hd") is not None:
                first_nl = s.find("\n")
                last_nl = s.rfind("\n")
                body = s[first_nl + 1:last_nl]
                quote = "'" if t.group("hq") == "'" else '"'
                strings.append(StringLiteral(t.start(), t.end(), quote, body))
                noc.append(s)
                code.append(s[: first_nl + 1] + _blank(s[first_nl + 1:last_nl]) + s[last_nl:])
            elif kind == "close":
                noc.append(s)
                code.append(s)
                pos = t.end()
                break
            pos = t.end()
    nocomment = "".join(noc)
    codeonly = "".join(code)
    # Defensive: views must stay aligned with the raw text.
    if len(nocomment) != n or len(codeonly) != n:  # pragma: no cover
        return PHPViews(text, text, text, [], has_php, [])
    return PHPViews(text, nocomment, codeonly, strings, has_php, backticks)


def split_top_level(expr: str, sep: str) -> list[str]:
    """Split *expr* on *sep* outside quotes and brackets (no evaluation)."""
    parts: list[str] = []
    depth = 0
    quote = ""
    buf: list[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                buf.append(expr[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


_PARENS = re.compile(r"[()]")


def matching_paren(codeonly: str, open_pos: int, limit: int = 4000) -> int | None:
    """Index of the ``)`` matching the ``(`` at *open_pos* in a codeonly view."""
    depth = 0
    for m in _PARENS.finditer(codeonly, open_pos, min(len(codeonly), open_pos + limit)):
        if m.group(0) == "(":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.start()
    return None


def statement_end(codeonly: str, start: int, limit: int = 4000) -> int:
    """Position of the ``;`` (or ``?>``) that ends the statement at *start*."""
    # Fast path: the next ';' with balanced brackets in between.
    semi = codeonly.find(";", start, start + limit)
    if semi != -1:
        seg = codeonly[start:semi]
        if "?>" not in seg and seg.count("(") == seg.count(")") and seg.count("[") == seg.count("]") \
                and seg.count("{") == seg.count("}"):
            return semi
    depth = 0
    end = min(len(codeonly), start + limit)
    for i in range(start, end):
        ch = codeonly[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif ch == ";" and depth <= 0:
            return i
        elif ch == "?" and codeonly.startswith("?>", i):
            return i
    return end
