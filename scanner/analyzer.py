"""Static content analysis of a single file's bytes.

This module is independent of the filesystem so that regular files,
referenced files and archive members all share one code path. Nothing
here executes, imports or evaluates the analysed content.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .configfiles import analyze_config_text, config_kind
from .entropy import is_probably_binary, longest_line, shannon_entropy
from .evidence import LineIndex, sanitize, snippet_at
from .metadata import (EXPECTED_MAGIC, MEDIA_EXT, PHP_EXT, SERVER_SIDE_EXT, UNUSUAL_PHP_EXT,
                       guess_content_type, sniff_magic)
from .models import Evidence, Indicator, Relationship, Strength
from .phpflow import FlowContext, analyze_flows, bounded_inflate
from .phplex import lex_php
from .signatures import Rule, apply_rules, compile_rules, rules_for

JSP_EXT = {".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jhtml"}
ASP_EXT = {".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".asa", ".cer", ".cshtml", ".vbhtml"}
NODE_EXT = {".js", ".mjs", ".cjs", ".ts"}
SCRIPT_LANGS = {"php", "jsp", "asp", "python", "perl", "shell"}
LOW_RISK_TEXT_EXT = {".html", ".htm", ".tpl", ".twig", ".phtml", ".xhtml", ".md", ".rst"}

# Built at run time so compiled bytecode does not contain a PHP open tag.
_PHP_OPEN = "".join(("<", "?php "))
_SERVER_JS = re.compile(r"child_process|require\s*\(\s*['\"](?:express|http|https|fs|net|koa|fastify)['\"]|"
                        r"from\s+['\"](?:express|node:|child_process|fs|http)|\bprocess\.env\b|module\.exports")
_B64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/=\s_-]+$")
_CODE_MARKERS = re.compile(
    r"<\?php|\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)|"
    r"\bfunction\s+\w+\s*\(|base64_decode|gzinflate|shell_exec|passthru|\bassert\s*\(|"
    r"create_function|preg_replace|\$\w+\s*=", re.I)
_MEDIA_PHP = re.compile(rb"<\?php[\s(/]|<\?=\s*\$[A-Za-z_]|<script\s+language\s*=\s*[\"']?php", re.I)
_LONG_B64 = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
_HEX_PAYLOAD = re.compile(r"(?:\\x[0-9a-fA-F]{2}){30,}")
_FRAGMENTS = re.compile(r"(?:(['\"])[A-Za-z0-9_]{1,3}\1\s*\.\s*){3,}(['\"])[A-Za-z0-9_]{1,3}\2")
_DOUBLE_EXT = re.compile(
    r"\.(?:jpe?g|png|gif|webp|svg|bmp|ico|txt|pdf|docx?|xlsx?|zip|rar|mp[34]|csv)\."
    r"(?:php\d?|phtml|pht|phar|asp|aspx|ashx|jsp|jspx|cgi|pl|py|shtml)$", re.I)
_SCRIPT_THEN_EXT = re.compile(r"\.(php\d?|phtml|pht|phar|asp|aspx|jsp)\.([a-z0-9]{1,6})$", re.I)
_BACKUP_EXT = {"bak", "old", "orig", "save", "swp", "tmp", "txt", "dist", "copy", "back", "sample", "example"}
_RANDOMISH = re.compile(r"^(?=.*\d)(?=.*[a-z])[a-z0-9]{6,40}$")


@dataclass
class FileContext:
    """Where a blob of content lives (real path or virtual archive path)."""

    path: Path
    relpath: str
    root: Path | None
    upload_level: str | None = None
    upload_component: str | None = None
    framework_labels: list[str] = field(default_factory=list)
    in_archive: bool = False

    @property
    def name(self) -> str:
        return PurePosixPath(self.relpath).name or self.path.name

    @property
    def ext(self) -> str:
        suffix = PurePosixPath(self.name).suffix.lower()
        if not suffix and self.name.startswith("."):
            return self.name.lower()
        return suffix


@dataclass
class ContentResult:
    indicators: list[Indicator] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    language: str | None = None
    content_type: str | None = None
    is_binary: bool = False
    entropy: float | None = None
    is_script: bool = False
    php_empty: bool = False
    text_for_iocs: str | None = None


def detect_language(ext: str, name: str, head: str, is_binary: bool) -> str | None:
    """Pick the rule set for a file from its extension, then its content."""
    if config_kind(name):
        return "config"
    if ext in PHP_EXT:
        return "php"
    if ext in JSP_EXT:
        return "jsp"
    if ext in ASP_EXT:
        return "asp"
    if ext in NODE_EXT:
        # Browser bundles vastly outnumber server code; only JavaScript that
        # looks server-side gets the Node.js rules.
        return "node" if _SERVER_JS.search(head) else None
    if ext == ".py":
        return "python"
    if ext in (".pl", ".pm"):
        return "perl"
    if ext == ".sh":
        return "shell"
    if is_binary:
        return None
    low = head[:8192].lower()
    if "<?php" in low or re.search(r"<\?=\s*[$\w]", low):
        return "php"
    if ext == ".cgi" or low.startswith("#!"):
        first = low.split("\n", 1)[0]
        if "python" in first:
            return "python"
        if "perl" in first:
            return "perl"
        if "php" in first:
            return "php"
        if "sh" in first:
            return "shell"
        return "perl" if ext == ".cgi" else None
    if re.search(r"<%@\s*page\b[^%]*import=|<jsp:", low):
        return "jsp"
    if re.search(r"<%@\s*(?:page|webhandler)\s+language\s*=\s*[\"']?(?:c#|vb|jscript)", low):
        return "asp"
    return None


class ContentAnalyzer:
    """Runs every static content check for one file."""

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        sc = cfg["scanner"]
        self.rules: list[Rule] = compile_rules(cfg["scoring"].get("weights"))
        self._rules_by_lang: dict[str | None, list[Rule]] = {}
        self.max_snippet = int(sc.get("max_snippet_length", 160))
        self.max_evidence = int(sc.get("max_evidence_per_indicator", 3))
        self.snippets = bool(sc.get("snippets", True))
        self.decode_layers = int(sc.get("decode_layers", 3))
        self.max_decoded = int(sc.get("max_decoded_bytes", 4 * 1024 * 1024))
        self.entropy_sample = int(sc.get("entropy_sample_bytes", 262144))
        fn = cfg["filenames"]
        self.known_names = {n.lower() for n in fn.get("known_webshell", [])}
        self.susp_names = {n.lower() for n in fn.get("suspicious", [])}
        self.short_len = int(fn.get("short_name_max_length", 3))
        self.hidden_ok = {n.lower() for n in cfg.get("hidden_allowlist", [])}

    def _rules(self, lang: str | None) -> list[Rule]:
        if lang not in self._rules_by_lang:
            self._rules_by_lang[lang] = rules_for(self.rules, lang)
        return self._rules_by_lang[lang]

    # ------------------------------------------------------------------ entry
    def analyze(self, data: bytes, ctx: FileContext, truncated: bool = False,
                tail: bytes | None = None) -> ContentResult:
        res = ContentResult()
        head = data[:8192]
        res.is_binary = is_probably_binary(head)
        res.content_type = guess_content_type(head, res.is_binary)
        magic = sniff_magic(head)
        text = _decode(data) if not res.is_binary else None
        res.language = detect_language(ctx.ext, ctx.name, text[:8192] if text else "", res.is_binary)
        res.is_script = res.language in SCRIPT_LANGS and (
            ctx.ext in SERVER_SIDE_EXT or res.language == "php" or ctx.ext == ".cgi")
        if res.language == "php" and res.content_type not in ("php",) and not res.is_binary:
            res.content_type = "php" if "<?" in (text or "")[:65536] else res.content_type

        self._name_checks(ctx, res)
        self._mismatch_checks(data, ctx, res, magic, text, tail)

        if data:
            res.entropy = shannon_entropy(data[: self.entropy_sample])

        if res.is_binary:
            self._binary_checks(data, ctx, res, tail)
        elif text is not None:
            self._text_checks(text, ctx, res)
        self._location_checks(ctx, res)
        return res

    # ------------------------------------------------------------ name/location
    def _name_checks(self, ctx: FileContext, res: ContentResult) -> None:
        name = ctx.name
        low = name.lower()
        stem = low.lstrip(".").split(".", 1)[0]
        script_like = res.is_script or ctx.ext in SERVER_SIDE_EXT
        ev = [Evidence(None, sanitize(name, 120))]
        if _DOUBLE_EXT.search(low):
            if low.count(".") > 2 and not low.startswith("."):
                # e.g. getID3's module.graphic.jpg.php - a dotted naming convention
                res.indicators.append(Indicator(
                    "name.double_extension_dotted", "content_mismatch",
                    "Media-type extension before the script extension in a multi-dot name", 4,
                    Strength.WEAK, ev))
            else:
                res.indicators.append(Indicator(
                    "name.double_extension", "content_mismatch",
                    "Dangerous double extension (e.g. image.jpg.php) - disguised server-side script",
                    15, Strength.STRONG, ev, min_severity="MEDIUM", tags=frozenset({"disguised"})))
        m = _SCRIPT_THEN_EXT.search(low)
        if m and not _DOUBLE_EXT.search(low):
            tail_ext = m.group(2)
            if tail_ext in _BACKUP_EXT:
                res.indicators.append(Indicator(
                    "name.script_backup", "filename",
                    f"Backup copy of a server-side script (.{m.group(1)}.{tail_ext}) - source disclosure risk",
                    3, Strength.WEAK, ev))
            else:
                res.indicators.append(Indicator(
                    "name.script_then_ext", "content_mismatch",
                    f"Script extension followed by .{tail_ext} (may execute under Apache multi-extension handling)",
                    10 if tail_ext in ("jpg", "jpeg", "png", "gif", "ico", "txt") else 6,
                    Strength.MODERATE, ev, tags=frozenset({"disguised"})))
        if re.search(r"\.(?:php\d?|phtml|asp|aspx|jsp)[.\s]+$", name, re.I):
            res.indicators.append(Indicator("name.trailing_dot", "content_mismatch",
                                            "Script extension followed by trailing dots/spaces (filter bypass)",
                                            10, Strength.MODERATE, ev))
        if ctx.ext in PHP_EXT and PurePosixPath(name).suffix not in (ctx.ext, ctx.ext.upper()):
            res.indicators.append(Indicator("name.mixed_case_ext", "filename",
                                            "Mixed-case script extension (e.g. .pHp - filter bypass)",
                                            6, Strength.WEAK, ev))
        if ctx.ext in UNUSUAL_PHP_EXT and script_like:
            w = 1 if ctx.ext == ".phtml" else 4
            res.indicators.append(Indicator("name.unusual_php_ext", "filename",
                                            f"Uncommon PHP extension ({ctx.ext}) often used to bypass upload filters",
                                            w, Strength.WEAK, ev))
        if script_like and stem in self.known_names:
            res.indicators.append(Indicator("name.known_webshell", "filename",
                                            f"File name matches a known web shell name ({stem})",
                                            8, Strength.MODERATE, ev, tags=frozenset({"name:known"})))
        elif script_like and (stem in self.susp_names):
            res.indicators.append(Indicator("name.suspicious", "filename",
                                            f"Generic suspicious script name ({stem})", 3, Strength.WEAK, ev))
        elif script_like and (len(stem) <= self.short_len and stem.isalnum()):
            res.indicators.append(Indicator("name.short", "filename",
                                            f"Very short script name ({name})", 2, Strength.WEAK, ev))
        elif script_like and (_RANDOMISH.match(stem) and _looks_random(stem)):
            res.indicators.append(Indicator("name.random", "filename",
                                            f"Random-looking script name ({name})", 3, Strength.WEAK, ev))
        if name.startswith(".") and low not in self.hidden_ok:
            if script_like:
                res.indicators.append(Indicator("name.hidden_script", "location",
                                                "Hidden server-side script (dot-file)", 10,
                                                Strength.MODERATE, ev, tags=frozenset({"loc:hidden"})))
            else:
                res.indicators.append(Indicator("name.hidden_file", "location", "Hidden file", 1,
                                                Strength.WEAK, ev))
        hidden_dirs = [c for c in PurePosixPath(ctx.relpath).parts[:-1]
                       if c.startswith(".") and c.lower() not in self.hidden_ok and c not in (".", "..")]
        if hidden_dirs and script_like:
            res.indicators.append(Indicator("name.hidden_directory", "location",
                                            f"Server-side script inside a hidden directory ({hidden_dirs[0]})",
                                            6, Strength.MODERATE, ev, tags=frozenset({"loc:hidden"})))

    def _location_checks(self, ctx: FileContext, res: ContentResult) -> None:
        if not res.is_script:
            return
        ev = [Evidence(None, sanitize(ctx.relpath, 160))]
        labels = set(ctx.framework_labels)
        weak_scale = res.php_empty
        if "laravel:generated" in labels:
            return
        if labels & {"wordpress:uploads", "laravel:public-storage", "drupal:files",
                     "joomla:user-content", "magento:media"}:
            lab = sorted(labels & {"wordpress:uploads", "laravel:public-storage", "drupal:files",
                                   "joomla:user-content", "magento:media"})[0]
            res.indicators.append(Indicator(
                "location.framework_upload", "location",
                f"Server-side script inside the framework's user-upload area ({lab})"
                + (" - file contains no executable code" if weak_scale else ""),
                3 if weak_scale else 18, Strength.WEAK if weak_scale else Strength.STRONG, ev,
                tags=frozenset() if weak_scale else frozenset({"loc:upload"})))
        elif ctx.upload_level == "strong":
            res.indicators.append(Indicator(
                "location.upload_dir", "location",
                f"Executable/server-side script inside an upload/media directory ({ctx.upload_component}/)"
                + (" - file contains no executable code" if weak_scale else ""),
                3 if weak_scale else 12, Strength.WEAK if weak_scale else Strength.MODERATE, ev,
                tags=frozenset() if weak_scale else frozenset({"loc:upload"})))
        elif ctx.upload_level == "weak":
            res.indicators.append(Indicator(
                "location.weak_upload_dir", "location",
                f"Server-side script inside a cache/temp/storage-like directory ({ctx.upload_component}/)",
                4, Strength.WEAK, ev, tags=frozenset({"loc:upload_weak"})))
        if "wordpress:mu-plugins" in labels:
            res.indicators.append(Indicator(
                "location.wp_mu_plugin", "location",
                "WordPress must-use plugin: auto-loaded on every request (frequent persistence location)",
                4, Strength.WEAK, ev, tags=frozenset({"loc:autoload"})))

    # ------------------------------------------------------------- mismatch
    def _mismatch_checks(self, data: bytes, ctx: FileContext, res: ContentResult, magic: str | None,
                         text: str | None, tail: bytes | None) -> None:
        ext = ctx.ext
        ev = [Evidence(None, f"extension {ext or '(none)'} / content {res.content_type}")]
        if ext in PHP_EXT | ASP_EXT | JSP_EXT and magic in ("gif", "jpeg", "png", "bmp", "pdf"):
            has_code = bool(_MEDIA_PHP.search(data[:1_000_000]))
            res.indicators.append(Indicator(
                "mismatch.image_header_script", "content_mismatch",
                f"Server-side script starts with a {magic.upper()} image header (polyglot used to bypass upload checks)",
                18 if has_code else 8, Strength.STRONG if has_code else Strength.MODERATE, ev,
                tags=frozenset({"polyglot"})))
        expected = EXPECTED_MAGIC.get(ext)
        if expected and data and magic not in expected:
            if magic in ("elf", "pe"):
                res.indicators.append(Indicator(
                    "mismatch.executable_disguised", "content_mismatch",
                    f"Native executable ({magic.upper()}) disguised with a {ext} extension",
                    20, Strength.STRONG, ev, min_severity="MEDIUM"))
            elif not res.is_binary and ext != ".svg":
                res.indicators.append(Indicator(
                    "mismatch.text_as_binary_ext", "content_mismatch",
                    f"File named {ext} contains text rather than {'/'.join(sorted(expected))} data",
                    4, Strength.WEAK, ev))
        if magic in ("elf", "pe") and ext not in (".exe", ".dll", ".so", ".bin") and \
                not any(i.rule_id == "mismatch.executable_disguised" for i in res.indicators):
            res.indicators.append(Indicator(
                "mismatch.native_executable", "content_mismatch",
                f"Native executable ({magic.upper()}) inside a web directory", 12, Strength.MODERATE, ev))

    # --------------------------------------------------------------- binary
    def _binary_checks(self, data: bytes, ctx: FileContext, res: ContentResult,
                       tail: bytes | None) -> None:
        """Embedded server-side code inside media/binary files."""
        chunks = [(0, data)]
        if tail:
            chunks.append((-1, tail))
        for base, chunk in chunks:
            m = _MEDIA_PHP.search(chunk)
            if not m:
                continue
            where = f"byte offset {m.start()}" if base == 0 else "end of file"
            is_media = ctx.ext in MEDIA_EXT or sniff_magic(data[:64]) in ("jpeg", "png", "gif", "webp", "bmp", "ico", "pdf")
            res.indicators.append(Indicator(
                "mismatch.php_in_media" if is_media else "mismatch.php_in_binary", "content_mismatch",
                f"PHP code embedded inside a {'image/media' if is_media else 'binary'} file ({where})",
                25 if is_media else 14, Strength.STRONG, [Evidence(None, sanitize(
                    chunk[m.start():m.start() + 120].decode("latin-1"), self.max_snippet), where)],
                min_severity="MEDIUM", tags=frozenset({"php_in_media", "hidden_code"})))
            region = chunk[m.start(): m.start() + 65536].decode("latin-1")
            end = region.find("?>")
            if end != -1:
                region = region[: end + 2]
            self._php_analysis(region, ctx, res, label=f"embedded PHP at {where}", depth=1)
            res.language = res.language or "php"
            break
        # Known web shell markers survive in binary containers (e.g. packed samples)
        latin = data[:2_000_000].decode("latin-1")
        marker_rules = [r for r in self._rules(None) if r.category == "known_marker"]
        res.indicators.extend(apply_rules(marker_rules, {"raw": latin}, LineIndex(latin),
                                          self.max_evidence, self.max_snippet, self.snippets,
                                          "binary content"))

    # ----------------------------------------------------------------- text
    def _text_checks(self, text: str, ctx: FileContext, res: ContentResult) -> None:
        lang = res.language
        kind = config_kind(ctx.name)
        if kind in ("php_ini", "htaccess"):
            ca = analyze_config_text(text, ctx.path, kind, ctx.root, ctx.upload_level == "strong",
                                     self.max_snippet)
            res.indicators.extend(ca.indicators)
            res.relationships.extend(ca.relationships)
            res.indicators.append(Indicator("config.sensitive_file", "config_persistence",
                                            "Sensitive web/PHP configuration file", 1, Strength.WEAK))
            return
        if lang is None:
            # Non-script text: look only for embedded server-side code.
            if re.search(r"<\?php|<\?=\s*[$\w]", text[:2_000_000], re.I):
                ext = ctx.ext
                w = 4 if ext in LOW_RISK_TEXT_EXT else 12
                res.indicators.append(Indicator(
                    "mismatch.php_in_text", "content_mismatch",
                    f"PHP code inside a non-PHP file ({ext or 'no extension'})", w,
                    Strength.WEAK if w < 10 else Strength.MODERATE,
                    tags=frozenset({"hidden_code"})))
                lang = res.language = "php"
            else:
                marker_rules = [r for r in self._rules(None) if r.category == "known_marker"]
                res.indicators.extend(apply_rules(marker_rules, {"raw": text}, LineIndex(text),
                                                  self.max_evidence, self.max_snippet, self.snippets))
                return
        if lang == "php":
            if ctx.ext in MEDIA_EXT or ctx.ext in (".txt", ".log", ".css", ".json", ".xml", ".ico"):
                res.indicators.append(Indicator(
                    "mismatch.php_in_media", "content_mismatch",
                    f"PHP code inside a {ctx.ext} file", 25, Strength.STRONG,
                    min_severity="MEDIUM", tags=frozenset({"php_in_media", "hidden_code"})))
            self._php_analysis(text, ctx, res)
        else:
            index = LineIndex(text)
            res.indicators.extend(apply_rules(self._rules(lang), {"raw": text}, index,
                                              self.max_evidence, self.max_snippet, self.snippets))
        if lang in SCRIPT_LANGS or lang == "node":
            self._shape_checks(text, ctx, res)
        if sum(i.weight for i in res.indicators) >= 8:
            res.text_for_iocs = text[:2_000_000]

    def _php_analysis(self, text: str, ctx: FileContext, res: ContentResult,
                      label: str | None = None, depth: int = 0) -> None:
        views = lex_php(text if "<?" in text[:65536] or depth == 0 else _PHP_OPEN + text)
        if not views.has_php and depth > 0:
            views = lex_php(_PHP_OPEN + text)
        index = LineIndex(views.raw)
        view_map = {"raw": views.raw, "nocomment": views.nocomment, "codeonly": views.codeonly}
        found = apply_rules(self._rules("php"), view_map, index, self.max_evidence,
                            self.max_snippet, self.snippets, label)
        fctx = FlowContext(views, index, file_dir=str(ctx.path.parent) if not ctx.in_archive else None,
                           file_path=str(ctx.path) if not ctx.in_archive else None,
                           max_snippet=self.max_snippet, snippets=self.snippets)
        flows = analyze_flows(fctx)
        if label:
            for f in flows:
                f.rule_id += ".decoded"
                f.description += f" [{label}]"
                for e in f.evidence:
                    e.source = label
        found.extend(flows)
        res.indicators.extend(found)
        if depth == 0:
            stripped = re.sub(r"<\?(?:php)?|\?>|<\?=", "", views.codeonly)
            res.php_empty = views.has_php and not re.search(r"[A-Za-z0-9$]", stripped)
            for target, ev in fctx.includes:
                if not ctx.in_archive and target.startswith("/"):
                    res.relationships.append(Relationship(str(ctx.path), target, "includes", ev, "file"))
        if depth < self.decode_layers:
            self._decoded_layers(views, ctx, res, depth)

    def _decoded_layers(self, views, ctx: FileContext, res: ContentResult, depth: int) -> None:
        """Statically decode Base64/gz/rot13 literals and analyse the result."""
        budget = self.max_decoded
        tried = 0
        for lit in sorted(views.strings, key=lambda s: -len(s.body))[:40]:
            body = lit.body
            if len(body) < 16 or not _B64_CANDIDATE.match(body):
                continue
            prefix = views.codeonly[max(0, lit.start - 80):lit.start].lower()
            has_decoder = bool(re.search(r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*$",
                                         prefix.replace(" ", "") + "") or
                               re.search(r"(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\([\s(]*$", prefix))
            if len(body) < 120 and not has_decoder:
                continue
            tried += 1
            if tried > 20 or budget <= 0:
                break
            decoded = _try_decode(body, "str_rot13" in prefix, budget)
            if not decoded:
                continue
            budget -= len(decoded)
            if not _CODE_MARKERS.search(decoded[:200000]):
                continue
            line = LineIndex(views.raw).line_of(lit.start)
            label = f"decoded layer {depth + 1}, string at line {line}"
            res.indicators.append(Indicator(
                "php.obf.decoded_payload", "obfuscation",
                f"Encoded string decodes to executable-looking code ({label})", 12, Strength.STRONG,
                [Evidence(line, sanitize(decoded[:200], self.max_snippet), label)],
                tags=frozenset({"obf:strong", "decoded_code"})))
            self._php_analysis(decoded, ctx, res, label=label, depth=depth + 1)

    def _shape_checks(self, text: str, ctx: FileContext, res: ContentResult) -> None:
        """Entropy, line length and blob shape checks for scripts."""
        minified = ctx.name.lower().endswith((".min.js", ".bundle.js", ".min.mjs")) or res.language == "node"
        size = len(text)
        ent = res.entropy or 0.0
        if res.is_script and size >= 512 and ent >= 5.8:
            res.indicators.append(Indicator(
                "shape.high_entropy", "obfuscation",
                f"High Shannon entropy for source code ({ent:.2f} bits/byte) - possible encoded payload",
                8 if ent >= 7.0 else 6, Strength.MODERATE, tags=frozenset({"high_entropy"})))
        if not minified:
            ll = longest_line(text[:5_000_000])
            if ll > 50000:
                res.indicators.append(Indicator("shape.very_long_line", "obfuscation",
                                                f"Extremely long line ({ll} characters)", 6,
                                                Strength.WEAK, tags=frozenset({"long_line"})))
            elif ll > 5000:
                res.indicators.append(Indicator("shape.long_line", "obfuscation",
                                                f"Very long line ({ll} characters)", 4, Strength.WEAK,
                                                tags=frozenset({"long_line"})))
        index = None
        for m in _LONG_B64.finditer(text):
            before = text[max(0, m.start() - 40):m.start()].lower()
            if "base64," in before or "data:" in before:
                continue
            index = index or LineIndex(text)
            res.indicators.append(Indicator(
                "shape.base64_blob", "obfuscation",
                f"Very long Base64-like string ({len(m.group(0))} characters)", 6, Strength.MODERATE,
                [snippet_at(index, m.start(), m.start() + 40, self.max_snippet)] if self.snippets else [],
                tags=frozenset({"blob"})))
            break
        m = _HEX_PAYLOAD.search(text)
        if m:
            index = index or LineIndex(text)
            res.indicators.append(Indicator(
                "shape.hex_escapes", "obfuscation", "Long hexadecimal-escaped payload (\\xNN sequence)",
                6, Strength.MODERATE,
                [snippet_at(index, m.start(), m.end(), self.max_snippet)] if self.snippets else [],
                tags=frozenset({"obf:strong"})))
        if res.language == "php":
            frags = len(_FRAGMENTS.findall(text[:1_000_000]))
            if frags >= 3:
                res.indicators.append(Indicator(
                    "shape.fragmented_strings", "obfuscation",
                    f"Repeated chains of 1-3 character string fragments ('a'.'b'.'c'.'d' - {frags} chains)",
                    6, Strength.MODERATE, tags=frozenset({"obf:strong"})))


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _looks_random(stem: str) -> bool:
    digits = sum(c.isdigit() for c in stem)
    letters = len(stem) - digits
    vowels = sum(c in "aeiou" for c in stem)
    return digits >= 2 and letters >= 2 and (vowels / max(letters, 1)) < 0.25 and len(stem) >= 8


def _try_decode(body: str, rot13: bool, budget: int) -> str | None:
    """Decode a Base64 literal (optionally rot13 first), then try inflating."""
    s = re.sub(r"\s+", "", body)
    candidates = [codecs.encode(s, "rot13")] if rot13 else []
    candidates.append(s)
    for cand in candidates:
        cand = cand.replace("-", "+").replace("_", "/")
        cand += "=" * (-len(cand) % 4)
        try:
            raw = base64.b64decode(cand, validate=True)
        except (binascii.Error, ValueError):
            continue
        for wbits in (None, -15, 15, 31):
            out = raw if wbits is None else bounded_inflate(raw, wbits, max(1024, min(budget, 2_000_000)))
            if not out:
                continue
            if is_probably_binary(out[:4096]):
                continue
            try:
                txt = out.decode("utf-8")
            except UnicodeDecodeError:
                txt = out.decode("latin-1")
            if sum(ch.isprintable() or ch in "\r\n\t" for ch in txt[:2000]) / max(1, len(txt[:2000])) > 0.95:
                return txt
    return None
