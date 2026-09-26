"""PHP source-to-sink and dynamic-invocation heuristics.

This is *not* a PHP interpreter. It performs bounded, static reasoning:

* collects simple assignments (``$x = ...;``) in file order,
* marks variables as tainted when their right-hand side contains request
  input (``$_GET``, ``$_POST``, ``php://input`` ...) or another tainted
  variable,
* resolves string expressions built only from literals, ``chr()`` and a
  few pure decoding functions (base64/rot13/strrev/hex2bin/gzinflate...)
  so that ``$f = "sys"."tem";`` is recognised as ``system``,
* inspects the arguments of dangerous calls ("sinks") for tainted data.

Decoding literal data is safe (no code is run); every decoder is bounded.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import os
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field

from .evidence import LineIndex, snippet_at
from .models import Evidence, Indicator, Strength
from .phplex import PHPViews, matching_paren, split_top_level, statement_end, unescape_double
from .signatures import is_global_call

SOURCE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['\"](?:HTTP_\w+|QUERY_STRING|"
    r"REQUEST_URI|PATH_INFO|argv)['\"]|php://input|getallheaders\s*\(|apache_request_headers\s*\(|"
    r"\$HTTP_(?:GET|POST|COOKIE|RAW_POST_DATA)\w*|\$GLOBALS\s*\[\s*['\"]_(?:GET|POST|REQUEST|COOKIE)",
    re.I,
)
SANITIZER_RE = re.compile(
    r"\b(?:escapeshellarg|escapeshellcmd|intval|floatval|basename|in_array|preg_match|"
    r"ctype_\w+|filter_var|htmlspecialchars|is_numeric|\(int\)|\(float\)|abs)\b", re.I
)

EXEC_SINKS = {"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"}
EVAL_SINKS = {"eval", "assert", "create_function"}
INCLUDE_SINKS = {"include", "include_once", "require", "require_once"}
CALLBACK_FIRST = {"call_user_func", "call_user_func_array", "array_map", "register_shutdown_function",
                  "forward_static_call", "forward_static_call_array", "ob_start", "iterator_apply",
                  "register_tick_function"}
CALLBACK_SECOND = {"array_filter", "array_walk", "array_walk_recursive", "usort", "uasort",
                   "uksort", "array_reduce", "preg_replace_callback"}
WRITE_SINKS = {"file_put_contents", "fwrite", "fputs"}
MAIL_SINKS = {"mail"}

DANGEROUS_NAMES = EXEC_SINKS | EVAL_SINKS | {"call_user_func", "call_user_func_array",
                                             "base64_decode", "gzinflate", "gzuncompress",
                                             "str_rot13", "gzdecode", "convert_uudecode",
                                             "file_put_contents", "move_uploaded_file",
                                             "preg_replace", "array_map", "fsockopen"}
SUPERGLOBAL_NAMES = {"_POST", "_GET", "_REQUEST", "_COOKIE", "_SERVER", "_FILES", "GLOBALS"}
DECODER_FUNCS = {"base64_decode", "str_rot13", "strrev", "hex2bin", "strtolower", "strtoupper",
                 "urldecode", "rawurldecode", "gzinflate", "gzuncompress", "gzdecode",
                 "convert_uudecode", "trim", "ucfirst", "lcfirst", "str_replace", "chr",
                 "implode", "join", "dirname", "sprintf"}

_SINK_CALL = re.compile(
    r"(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|"
    r"assert|create_function|call_user_func(?:_array)?|array_map|array_filter|array_walk(?:_recursive)?|"
    r"usort|uasort|uksort|array_reduce|preg_replace_callback|register_shutdown_function|"
    r"register_tick_function|forward_static_call(?:_array)?|ob_start|iterator_apply|"
    r"file_put_contents|fwrite|fputs|mail)\s*\(",
    re.I,
)
_INCLUDE_STMT = re.compile(r"(include|include_once|require|require_once)\b", re.I)
_ASSIGN = re.compile(r"\$([A-Za-z_]\w*)\s*(\.?=)(?![=>])")
_FOREACH = re.compile(
    r"foreach\s*\(\s*(\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b[^)]*?)\s+as\s+"
    r"(?:\$([A-Za-z_]\w*)\s*=>\s*)?\$([A-Za-z_]\w*)", re.I)
_LIST_ASSIGN = re.compile(r"(?:list\s*\(|\[)\s*([^\]\)]*?)\s*(?:\)|\])\s*=(?!=)")
_VAR_CALL = re.compile(r"\$([A-Za-z_]\w*)\s*(\[[^\]\n]{0,60}\]\s*)?\(")
_INPUT_CALL = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]\n]{0,60}\]\s*(?:\[[^\]\n]{0,60}\]\s*)?\(", re.I)
_VARVAR_CALL = re.compile(r"\$\{[^}\n]{1,80}\}\s*\(|\$\$[A-Za-z_]\w*\s*\(")
_PAREN_NAME_CALL = re.compile(r"\(\s*((?:['\"][^'\"\n]{0,40}['\"]\s*\.\s*)+['\"][^'\"\n]{0,40}['\"])\s*\)\s*\(")
_VAR_REF = re.compile(r"\$([A-Za-z_]\w*)")

MAX_RESOLVED = 1 << 20
# Only right-hand sides containing literals/known constants can resolve statically.
_RESOLVABLE_HINT = re.compile(r"['\"]|\bchr\s*\(|__DIR__|__FILE__|DIRECTORY_SEPARATOR", re.I)


@dataclass
class FlowContext:
    views: PHPViews
    index: LineIndex
    file_dir: str | None = None
    file_path: str | None = None
    max_snippet: int = 160
    snippets: bool = True
    env: dict[str, str] = field(default_factory=dict)
    tainted: dict[str, int] = field(default_factory=dict)       # var -> offset of taint
    includes: list[tuple[str, Evidence]] = field(default_factory=list)
    ev_counts: dict[str, int] = field(default_factory=dict)


# --------------------------------------------------------------------- resolver

def _limit(s: str | None) -> str | None:
    if s is None or len(s) > MAX_RESOLVED:
        return None
    return s


def _b64(s: str) -> str | None:
    data = re.sub(r"\s+", "", s)
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data.encode("latin-1"), validate=False).decode("latin-1")
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def bounded_inflate(data: bytes, wbits: int, limit: int = MAX_RESOLVED) -> bytes | None:
    """Decompress at most *limit* bytes (zip-bomb safe)."""
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, limit)
        return out
    except zlib.error:
        return None


def _apply_decoder(fn: str, args: list[str | None]) -> str | None:
    if not args or args[0] is None and fn not in ("str_replace", "implode", "join", "sprintf"):
        return None
    a = args[0]
    try:
        if fn == "base64_decode":
            return _b64(a)  # type: ignore[arg-type]
        if fn == "str_rot13":
            return codecs.encode(a, "rot13")  # type: ignore[arg-type]
        if fn == "strrev":
            return a[::-1]  # type: ignore[index]
        if fn == "hex2bin":
            return bytes.fromhex(a).decode("latin-1")  # type: ignore[arg-type]
        if fn == "strtolower":
            return a.lower()  # type: ignore[union-attr]
        if fn == "strtoupper":
            return a.upper()  # type: ignore[union-attr]
        if fn == "ucfirst":
            return a[:1].upper() + a[1:]  # type: ignore[index]
        if fn == "lcfirst":
            return a[:1].lower() + a[1:]  # type: ignore[index]
        if fn == "trim":
            return a.strip()  # type: ignore[union-attr]
        if fn == "urldecode":
            return urllib.parse.unquote_plus(a)  # type: ignore[arg-type]
        if fn == "rawurldecode":
            return urllib.parse.unquote(a)  # type: ignore[arg-type]
        if fn in ("gzinflate", "gzuncompress", "gzdecode"):
            wbits = {"gzinflate": -15, "gzuncompress": 15, "gzdecode": 31}[fn]
            out = bounded_inflate(a.encode("latin-1"), wbits)  # type: ignore[union-attr]
            return out.decode("latin-1") if out is not None else None
        if fn == "convert_uudecode":
            lines = [ln for ln in a.splitlines() if ln and ln != "`"]  # type: ignore[union-attr]
            return b"".join(binascii.a2b_uu(ln) for ln in lines).decode("latin-1")
        if fn == "chr":
            num = a.strip().lower()  # type: ignore[union-attr]
            return chr(int(num, 16 if num.startswith("0x") else 10) % 256)
        if fn == "str_replace" and len(args) >= 3 and None not in args[:3]:
            return args[2].replace(args[0], args[1])  # type: ignore[union-attr,arg-type]
        if fn == "dirname":
            return os.path.dirname(a)  # type: ignore[arg-type]
    except (ValueError, binascii.Error, UnicodeError, OverflowError):
        return None
    return None


def resolve_expr(expr: str, ctx: FlowContext, depth: int = 0) -> str | None:
    """Statically resolve a PHP string expression, or return None."""
    if depth > 8 or len(expr) > 20000:
        return None
    parts = split_top_level(expr.strip(), ".")
    if len(parts) > 400:
        return None
    out = []
    for part in parts:
        v = _resolve_atom(part.strip(), ctx, depth)
        if v is None:
            return None
        out.append(v)
        if sum(len(x) for x in out) > MAX_RESOLVED:
            return None
    return "".join(out)


def _resolve_atom(p: str, ctx: FlowContext, depth: int) -> str | None:
    if not p:
        return None
    p = p.lstrip("@").strip()
    if len(p) >= 2 and p[0] == p[-1] == "'":
        return p[1:-1].replace("\\\\", "\x00").replace("\\'", "'").replace("\x00", "\\")
    if len(p) >= 2 and p[0] == p[-1] == '"':
        body = p[1:-1]
        if re.search(r"(?<!\\)\$[A-Za-z_{]", body):
            return None
        return unescape_double(body)
    if re.fullmatch(r"\$[A-Za-z_]\w*", p):
        return ctx.env.get(p[1:])
    if re.fullmatch(r"\d+", p):
        return p
    if p == "__DIR__" and ctx.file_dir:
        return ctx.file_dir
    if p == "__FILE__" and ctx.file_path:
        return ctx.file_path
    if p == "DIRECTORY_SEPARATOR":
        return "/"
    if p.startswith("(") and p.endswith(")"):
        return resolve_expr(p[1:-1], ctx, depth + 1)
    m = re.fullmatch(r"([A-Za-z_]\w*)\s*\(([\s\S]*)\)", p)
    if m:
        fn = m.group(1).lower()
        if fn not in DECODER_FUNCS:
            return None
        raw_args = split_top_level(m.group(2), ",") if m.group(2).strip() else []
        if fn == "chr":
            return _apply_decoder("chr", [raw_args[0].strip()] if raw_args else [])
        if fn in ("implode", "join") and len(raw_args) == 2:
            glue = resolve_expr(raw_args[0], ctx, depth + 1)
            arr = raw_args[1].strip()
            am = re.fullmatch(r"(?:array\s*\(|\[)([\s\S]*)(?:\)|\])", arr)
            if glue is None or not am:
                return None
            items = [resolve_expr(x, ctx, depth + 1) for x in split_top_level(am.group(1), ",") if x.strip()]
            if any(i is None for i in items):
                return None
            return _limit(glue.join(items))  # type: ignore[arg-type]
        if fn == "dirname" and raw_args and raw_args[0].strip() == "__FILE__" and ctx.file_dir:
            return ctx.file_dir
        if fn == "sprintf":
            return None
        args = [resolve_expr(a, ctx, depth + 1) for a in raw_args]
        return _limit(_apply_decoder(fn, args))
    return None


# ------------------------------------------------------------------- analysis

def _ev(ctx: FlowContext, start: int, end: int, key: str | None = None) -> list[Evidence]:
    if not ctx.snippets:
        return []
    if key is not None:
        n = ctx.ev_counts.get(key, 0)
        ctx.ev_counts[key] = n + 1
        if n >= 3:
            return []
    return [snippet_at(ctx.index, start, end, ctx.max_snippet)]


def _index_depths(text: str) -> list[int]:
    """Square-bracket nesting depth at every offset of *text*."""
    depths = []
    d = 0
    for ch in text:
        if ch == "[":
            d += 1
            depths.append(d)
            continue
        if ch == "]":
            d = max(0, d - 1)
        depths.append(d)
    return depths


def _mentions_taint(text: str, ctx: FlowContext, before: int) -> str | None:
    """Return a description of request-controlled data inside *text*, or None.

    Data used only as an array *index* (``$handlers[$_GET['a']]``) is not
    counted: that is a lookup into a program-defined table, a common and
    usually safe dispatch pattern.
    """
    depths: list[int] | None = None
    for m in SOURCE_RE.finditer(text):
        depths = depths or _index_depths(text)
        if depths[m.start()] == 0:
            return m.group(0).strip()
    for vm in _VAR_REF.finditer(text):
        name = vm.group(1)
        pos = ctx.tainted.get(name)
        if pos is not None and pos < before:
            depths = depths or _index_depths(text)
            if depths[vm.start()] == 0:
                return "$" + name
    return None


_GUARD_CALLS = re.compile(
    r"\b(?:isset|empty|array_key_exists|in_array|is_\w+|count|sizeof|strlen|ctype_\w+|"
    r"preg_match|wp_verify_nonce|check_admin_referer|current_user_can)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)",
    re.I)
_RHS_SANITIZER = re.compile(
    r"\b(?:sanitize_\w+|esc_\w+|absint|intval|floatval|boolval|wp_kses\w*|htmlspecialchars|"
    r"htmlentities|strip_tags|basename|escapeshellarg|escapeshellcmd|filter_var|filter_input|"
    r"md5|sha1|hash|crc32|json_encode|urlencode|rawurlencode|number_format)\s*\(|"
    r"\((?:int|integer|bool|boolean|float|double)\)", re.I)
_RHS_BOOLEAN = re.compile(r"[=!]==?|<=|>=|^\s*!|\bnull\s*$", re.I)


def _rhs_taints(rhs: str, ctx: FlowContext, before: int) -> bool:
    """Does an assignment's right-hand side carry request-controlled data?"""
    if re.match(r"\s*(?:static\s+)?(?:function\b|fn\s*\()", rhs, re.I):
        return False  # closure definition: its body is not the assigned value
    cleaned = _GUARD_CALLS.sub(" ", rhs)
    if _RHS_SANITIZER.search(cleaned):
        return False
    if _RHS_BOOLEAN.search(cleaned.split("?", 1)[0] if "?" in cleaned else cleaned) and "?" not in cleaned:
        return False
    return _mentions_taint(cleaned, ctx, before) is not None


def collect_assignments(ctx: FlowContext) -> None:
    """Populate ctx.env (resolvable strings) and ctx.tainted in file order."""
    code = ctx.views.codeonly
    noc = ctx.views.nocomment
    count = 0
    events: list[tuple[int, str, str, str]] = []
    for m in _ASSIGN.finditer(code):
        # Skip comparisons like "$a == " (handled by the lookahead) and
        # property/array writes are ignored on purpose.
        end = statement_end(code, m.end())
        rhs = noc[m.end():end]
        events.append((m.start(), m.group(1), m.group(2), rhs))
        count += 1
        if count > 20000:
            break
    for m in _FOREACH.finditer(noc):
        for grp in (2, 3):
            if m.group(grp):
                ctx.tainted.setdefault(m.group(grp), m.start())
    for m in _LIST_ASSIGN.finditer(code):
        end = statement_end(code, m.end())
        rhs = noc[m.end():end]
        if _rhs_taints(rhs, ctx, m.start()):
            for vm in _VAR_REF.finditer(noc[m.start():m.end()]):
                ctx.tainted.setdefault(vm.group(1), m.start())
    # Two passes let taint flow through variables assigned out of order.
    for _ in range(2):
        for pos, name, op, rhs in events:
            if name == "this" or name in ctx.tainted:
                continue
            if _rhs_taints(rhs, ctx, pos):
                ctx.tainted[name] = pos
    for pos, name, op, rhs in events:
        if len(rhs) > 20000 or name == "this":
            continue
        if not _RESOLVABLE_HINT.search(rhs) and not (name in ctx.env and op == ".="):
            ctx.env.pop(name, None)
            continue
        val = resolve_expr(rhs, ctx)
        if op == ".=":
            prev = ctx.env.get(name)
            ctx.env[name] = (prev + val) if (prev is not None and val is not None) else None  # type: ignore[assignment]
            if ctx.env[name] is None:
                del ctx.env[name]
        elif val is not None:
            ctx.env[name] = val
        else:
            ctx.env.pop(name, None)


def _call_args(ctx: FlowContext, open_paren: int) -> tuple[int, str, list[str]] | None:
    close = matching_paren(ctx.views.codeonly, open_paren)
    if close is None:
        return None
    text = ctx.views.nocomment[open_paren + 1:close]
    return close, text, split_top_level(text, ",")


def analyze_flows(ctx: FlowContext) -> list[Indicator]:
    """Source-to-sink and dynamic invocation indicators for a PHP file."""
    out: list[Indicator] = []
    code = ctx.views.codeonly
    has_source = bool(SOURCE_RE.search(ctx.views.nocomment))
    collect_assignments(ctx)

    # 1) Dangerous calls with request-controlled arguments (or resolved callbacks)
    for m in _SINK_CALL.finditer(code):
        if not has_source and m.group(1).lower() not in CALLBACK_FIRST:
            continue
        if not is_global_call(code, m.start()):
            continue
        name = m.group(1).lower()
        before = code[max(0, m.start() - 24):m.start()]
        if re.search(r"function\s*&?\s*$", before):
            continue
        parsed = _call_args(ctx, m.end() - 1)
        if parsed is None:
            continue
        close, argtext, args = parsed
        out.extend(_classify_sink(ctx, name, m.start(), close + 1, argtext, args))

    # 2) Backtick shell execution
    for start, end in ctx.views.backticks:
        body = ctx.views.nocomment[start + 1:end - 1]
        taint = _mentions_taint(body, ctx, start)
        if taint:
            out.append(Indicator(
                "php.flow.backtick_input", "source_to_sink",
                f"Request-controlled data ({taint}) executed with backtick shell operator",
                50, Strength.DEFINITIVE, _ev(ctx, start, end), min_severity="CRITICAL",
                tags=frozenset({"flow:direct", "sink:exec", "source"})))
        else:
            out.append(Indicator(
                "php.sink.backtick", "sink", "Uses the backtick shell-execution operator",
                4, Strength.WEAK, _ev(ctx, start, end), tags=frozenset({"sink:exec"})))

    # 3) include/require targets
    for m in _INCLUDE_STMT.finditer(code):
        if not is_global_call(code, m.start()):
            continue
        end = statement_end(code, m.end())
        arg = ctx.views.nocomment[m.end():end].strip()
        taint = _mentions_taint(arg, ctx, m.start())
        if taint:
            direct = bool(SOURCE_RE.search(arg))
            sanitized = bool(SANITIZER_RE.search(arg))
            w = 10 if sanitized else (26 if direct else 14)
            out.append(Indicator(
                "php.flow.include_input", "source_to_sink",
                f"include/require path controlled by request data ({taint})"
                + (" - a sanitizer is present" if sanitized else "")
                + " (remote/local file inclusion)",
                w, Strength.MODERATE if sanitized else Strength.STRONG, _ev(ctx, m.start(), end),
                min_severity="MEDIUM" if direct and not sanitized else None,
                tags=frozenset({"flow:include", "sink:include", "source"})))
        else:
            target = resolve_expr(arg.strip("()"), ctx) if len(arg) < 2000 else None
            if target:
                ctx.includes.append((target, _ev(ctx, m.start(), end)[0] if ctx.snippets else
                                     _plain_ev(ctx, m.start())))
                base = os.path.basename(target)
                if base.startswith(".") and base.lower().endswith((".php", ".ico", ".jpg", ".png",
                                                                    ".gif", ".txt", ".inc")):
                    out.append(Indicator(
                        "php.include.hidden_file", "dropper",
                        f"Includes a hidden file ({base})", 10, Strength.MODERATE,
                        _ev(ctx, m.start(), end), tags=frozenset({"include:suspicious"})))

    # 4) Variable functions: $f(...) / $a['x'](...)
    for m in _VAR_CALL.finditer(code):
        prev = code[m.start() - 1] if m.start() else " "
        if prev in "$>:\\_" or prev.isalnum():
            continue  # $$x(, ->$x(, ::$x( or part of a longer token
        name = m.group(1)
        if name == "this" or name in SUPERGLOBAL_NAMES:
            continue
        before = code[max(0, m.start() - 8):m.start()]
        if re.search(r"new\s*$", before):
            continue
        resolved = ctx.env.get(name) if not m.group(2) else None
        func_taint = name in ctx.tainted and ctx.tainted[name] < m.start()
        dangerous = bool(resolved and _is_dangerous_name(resolved))
        if not (has_source or func_taint or dangerous):
            out.append(Indicator(
                "php.dyn.varfunc", "dynamic_invocation",
                "Calls a function through a variable ($var(...))", 1, Strength.WEAK,
                _ev(ctx, m.start(), m.end(), "varfunc"), tags=frozenset({"dyn:weak"})))
            continue
        parsed = _call_args(ctx, m.end() - 1)
        argtext = parsed[1] if parsed else ""
        end = (parsed[0] + 1) if parsed else m.end()
        arg_taint = _mentions_taint(argtext, ctx, m.start()) if has_source else None
        if func_taint:
            out.append(Indicator(
                "php.dyn.function_from_input", "source_to_sink",
                f"Function name is taken from request data (${name}(...)) - arbitrary function call",
                48, Strength.DEFINITIVE, _ev(ctx, m.start(), end), min_severity="CRITICAL",
                tags=frozenset({"flow:direct", "sink:eval", "source", "dyn:strong"})))
        elif resolved and _is_dangerous_name(resolved):
            fn = resolved.strip().lower().lstrip("\\")
            if arg_taint:
                out.append(Indicator(
                    "php.dyn.resolved_call_input", "source_to_sink",
                    f"Obfuscated call to {fn}() through variable ${name} with request data ({arg_taint})",
                    50, Strength.DEFINITIVE, _ev(ctx, m.start(), end), min_severity="CRITICAL",
                    tags=frozenset({"flow:direct", "sink:exec", "source", "dyn:strong"})))
            else:
                out.append(Indicator(
                    "php.dyn.resolved_call", "dynamic_invocation",
                    f"Variable function ${name}(...) statically resolves to {fn}()",
                    26, Strength.STRONG, _ev(ctx, m.start(), end), min_severity="MEDIUM",
                    tags=frozenset({"dyn:strong", "sink:exec" if fn in EXEC_SINKS else "sink:eval"})))
        elif arg_taint:
            out.append(Indicator(
                "php.dyn.varfunc_input", "dynamic_invocation",
                f"Variable function ${name}(...) called with request data ({arg_taint})",
                14, Strength.MODERATE, _ev(ctx, m.start(), end),
                tags=frozenset({"dyn:weak", "source"})))
        else:
            out.append(Indicator(
                "php.dyn.varfunc", "dynamic_invocation",
                "Calls a function through a variable ($var(...))", 1, Strength.WEAK,
                _ev(ctx, m.start(), end, "varfunc"), tags=frozenset({"dyn:weak"})))

    # 5) $_POST['f']($_POST['a']) - callable directly from input
    for m in _INPUT_CALL.finditer(ctx.views.nocomment):
        if code[m.start()] != "$":  # inside a string literal
            continue
        out.append(Indicator(
            "php.dyn.input_callable", "source_to_sink",
            "Calls a function whose name comes directly from request data ($_POST['x'](...))",
            50, Strength.DEFINITIVE, _ev(ctx, m.start(), m.end()), min_severity="CRITICAL",
            tags=frozenset({"flow:direct", "sink:eval", "source", "dyn:strong"})))

    # 6) ${...}(...) / $$x(...)
    for m in _VARVAR_CALL.finditer(code):
        out.append(Indicator(
            "php.dyn.varvar_call", "dynamic_invocation",
            "Calls a function through variable-variable syntax (${...}(...) / $$x(...))",
            10, Strength.MODERATE, _ev(ctx, m.start(), m.end()),
            tags=frozenset({"dyn:strong", "obf:strong"})))

    # 7) ("sys"."tem")(...) - PHP 7 expression call
    for m in _PAREN_NAME_CALL.finditer(ctx.views.nocomment):
        val = resolve_expr(m.group(1), ctx)
        if val and _is_dangerous_name(val):
            out.append(Indicator(
                "php.dyn.concat_call", "dynamic_invocation",
                f"Calls {val.strip()}() through a concatenated string expression",
                28, Strength.STRONG, _ev(ctx, m.start(), m.end()), min_severity="MEDIUM",
                tags=frozenset({"dyn:strong", "obf:strong", "sink:exec"})))

    # 8) Obfuscated construction of sensitive identifiers
    out.extend(_constructed_names(ctx))
    return out


def _plain_ev(ctx: FlowContext, pos: int) -> Evidence:
    return Evidence(line=ctx.index.line_of(pos), snippet="")


def _is_dangerous_name(value: str) -> bool:
    v = value.strip().lower().lstrip("\\")
    return v in DANGEROUS_NAMES


def _classify_sink(ctx: FlowContext, name: str, start: int, end: int, argtext: str,
                   args: list[str]) -> list[Indicator]:
    """Decide whether a dangerous call receives request-controlled data."""
    if name in CALLBACK_FIRST:
        cb = args[0] if args else ""
        taint = _mentions_taint(cb, ctx, start)
        if taint:
            return [Indicator(
                "php.flow.callback_input", "source_to_sink",
                f"{name}() callback name comes from request data ({taint})",
                46, Strength.DEFINITIVE, _ev(ctx, start, end), min_severity="CRITICAL",
                tags=frozenset({"flow:direct", "sink:eval", "source", "dyn:strong"}))]
        resolved = resolve_expr(cb, ctx) if cb.strip() and len(cb) < 2000 else None
        if resolved and _is_dangerous_name(resolved) and resolved.lower() not in ("array_map",):
            rest_taint = _mentions_taint(",".join(args[1:]), ctx, start)
            if rest_taint:
                return [Indicator(
                    "php.flow.callback_resolved_input", "source_to_sink",
                    f"{name}() invokes {resolved.strip()}() with request data ({rest_taint})",
                    50, Strength.DEFINITIVE, _ev(ctx, start, end), min_severity="CRITICAL",
                    tags=frozenset({"flow:direct", "sink:exec", "source", "dyn:strong"}))]
            if not re.fullmatch(r"\s*['\"][^'\"]*['\"]\s*", cb):  # literal handled by a rule
                return [Indicator(
                    "php.dyn.callback_resolved", "dynamic_invocation",
                    f"{name}() callback statically resolves to {resolved.strip()}()",
                    24, Strength.STRONG, _ev(ctx, start, end), min_severity="MEDIUM",
                    tags=frozenset({"dyn:strong", "sink:exec"}))]
        return []
    if name in CALLBACK_SECOND:
        cb = args[1] if len(args) > 1 else ""
        taint = _mentions_taint(cb, ctx, start)
        if taint:
            return [Indicator(
                "php.flow.callback_input", "source_to_sink",
                f"{name}() callback name comes from request data ({taint})",
                46, Strength.DEFINITIVE, _ev(ctx, start, end), min_severity="CRITICAL",
                tags=frozenset({"flow:direct", "sink:eval", "source", "dyn:strong"}))]
        return []
    if name in WRITE_SINKS:
        if len(args) < 2:
            return []
        dest, data = args[0], ",".join(args[1:])
        dest_taint = _mentions_taint(dest, ctx, start)
        data_taint = _mentions_taint(data, ctx, start)
        script_dest = re.search(r"\.(?:php\d?|phtml|pht|phar|jsp|aspx?|htaccess|user\.ini)\b", dest, re.I)
        if data_taint and (dest_taint or script_dest):
            return [Indicator(
                "php.flow.write_input", "source_to_sink",
                f"Writes request-controlled content ({data_taint}) to a "
                + ("request-controlled path" if dest_taint else "server-side script file"),
                30, Strength.STRONG, _ev(ctx, start, end), min_severity="HIGH",
                tags=frozenset({"flow:write", "dropper", "source"}))]
        return []
    if name in MAIL_SINKS:
        taint = _mentions_taint(argtext, ctx, start)
        if taint and len(args) >= 3 and _mentions_taint(args[0], ctx, start):
            return [Indicator(
                "php.flow.mail_input", "source_to_sink",
                f"mail() recipient controlled by request data ({taint}) - possible spam mailer",
                10, Strength.MODERATE, _ev(ctx, start, end), tags=frozenset({"source"}))]
        return []

    # exec / eval sinks
    taint = _mentions_taint(argtext, ctx, start)
    if not taint:
        return []
    direct = bool(SOURCE_RE.search(argtext))
    sanitized = bool(SANITIZER_RE.search(argtext))
    kind = "command execution" if name in EXEC_SINKS else "code evaluation"
    tag = "sink:exec" if name in EXEC_SINKS else "sink:eval"
    if sanitized:
        return [Indicator(
            f"php.flow.{'exec' if name in EXEC_SINKS else 'eval'}_sanitized", "source_to_sink",
            f"Request data ({taint}) reaches {name}() ({kind}) through a sanitizer",
            18, Strength.MODERATE, _ev(ctx, start, end),
            tags=frozenset({"flow:sanitized", tag, "source"}))]
    if direct:
        return [Indicator(
            f"php.flow.{'exec' if name in EXEC_SINKS else 'eval'}_direct", "source_to_sink",
            f"Attacker-controlled request data ({taint}) is passed directly to {name}() ({kind})",
            55, Strength.DEFINITIVE, _ev(ctx, start, end), min_severity="CRITICAL",
            tags=frozenset({"flow:direct", tag, "source"}))]
    return [Indicator(
        f"php.flow.{'exec' if name in EXEC_SINKS else 'eval'}_indirect", "source_to_sink",
        f"Request data flows via variable {taint} into {name}() ({kind})",
        42, Strength.STRONG, _ev(ctx, start, end), min_severity="HIGH",
        tags=frozenset({"flow:indirect", tag, "source"}))]


def _constructed_names(ctx: FlowContext) -> list[Indicator]:
    """Flag variables whose *obfuscated* value is a sensitive identifier."""
    out: list[Indicator] = []
    seen: set[str] = set()
    code = ctx.views.codeonly
    for m in _ASSIGN.finditer(code):
        if m.group(2) != "=":
            continue
        name = m.group(1)
        val = ctx.env.get(name)
        if not val:
            continue
        v = val.strip().lstrip("\\")
        if v.lower() not in DANGEROUS_NAMES and v not in SUPERGLOBAL_NAMES:
            continue
        end = statement_end(code, m.end())
        rhs = ctx.views.nocomment[m.end():end].strip()
        # A plain literal ('system') is not obfuscation; concatenation/decoding is.
        if re.fullmatch(r"(['\"])[^'\"]*\1", rhs):
            continue
        key = f"{name}:{v}"
        if key in seen:
            continue
        seen.add(key)
        out.append(Indicator(
            "php.obf.constructed_name", "obfuscation",
            f"Builds the identifier '{v}' from fragments/encoded data (${name})",
            14, Strength.STRONG, _ev(ctx, m.start(), end),
            tags=frozenset({"obf:strong"})))
    return out
