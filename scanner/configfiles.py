"""Static analysis of PHP and web-server configuration files.

Covers the classic "survives redeploy" persistence tricks:

* ``auto_prepend_file`` / ``auto_append_file`` in ``.user.ini``, ``php.ini``,
  ``.htaccess`` (``php_value``), PHP-FPM pools (``php_admin_value[...]``)
  and nginx (``fastcgi_param PHP_VALUE``),
* handler changes that make images or text files executable as PHP,
* PHP/CGI execution enabled inside upload directories,
* configuration pointing into /tmp, /dev/shm, hidden directories, etc.

Referenced files are *resolved and reported* - never executed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import LineIndex, snippet_at
from .models import Evidence, Indicator, Relationship, Strength
from .utils import is_within

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
NON_CODE_EXT = r"(?:jpe?g|png|gif|ico|bmp|svg|webp|txt|log|css|html?|pdf|dat|tmp|cache|zip)"

_PREPEND = re.compile(
    r"""(?imx)
    (?:^|[\s\[;"'])(auto_(?:prepend|append)_file)\]?\s*(?:=|\s)\s*["']?([^"'\s;\n]*)
    """
)
_ALLOW_URL_INCLUDE = re.compile(r"(?im)allow_url_include\]?\s*(?:=|\s)\s*[\"']?(?:on|1|true)\b")
_INCLUDE_PATH = re.compile(r"(?im)include_path\]?\s*(?:=|\s)\s*[\"']?([^\"'\n;]+)")
_DISABLE_FUNCS_EMPTY = re.compile(r"(?im)^\s*disable_functions\s*=\s*[\"']?\s*[\"']?\s*$")
_ADDTYPE_IMG = re.compile(
    r"(?im)^\s*(?:AddType|AddHandler|SetHandler|ForceType)\s+[^\n]*(?:php|x-httpd|phtml|cgi-script|"
    r"application/x-httpd)[^\n]*?(?:\.|\s)" + NON_CODE_EXT + r"\b")
_ADDTYPE_PHP_ANY = re.compile(
    r"(?im)^\s*(?:AddType|AddHandler|SetHandler|ForceType)\s+[^\n]*(?:x-httpd-php|php\d?-script|"
    r"application/x-httpd|proxy:unix:[^\n]*php)")
_FILESMATCH_IMG = re.compile(
    r"(?is)<Files(?:Match)?\s+[\"']?[^>]*" + NON_CODE_EXT + r"[^>]*>[^<]{0,400}?"
    r"(?:SetHandler|ForceType|AddHandler|AddType)[^<]{0,200}?php")
_ENGINE_ON = re.compile(r"(?im)^\s*php_(?:flag|value|admin_flag)\s+engine\s+(?:on|1)\b")
_EXEC_CGI = re.compile(r"(?im)^\s*Options\s+[^\n]*\+?ExecCGI")
_CLOAK = re.compile(
    r"(?ims)RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu|bot)"
    r"[\s\S]{0,400}?RewriteRule\s+[^\n]*(?:https?://|\.php)")
_ERRORDOC_PHP = re.compile(r"(?im)^\s*ErrorDocument\s+\d{3}\s+(\S*\.php\S*)")
_PHP_VALUE_ANY = re.compile(r"(?im)^\s*php_(?:value|admin_value|flag)\s+(\S+)")
_NGINX_PHP_VALUE = re.compile(r"(?im)fastcgi_param\s+PHP_(?:ADMIN_)?VALUE\s+[\"']?([^;\n]+)")
_NGINX_IMG_FASTCGI = re.compile(
    r"(?is)location\s+~\*?\s+[^{]*" + NON_CODE_EXT + r"[^{]*\{[^}]{0,600}?fastcgi_pass")
_LOADMODULE = re.compile(r"(?im)^\s*LoadModule\s+\S+\s+(\S+)")
_LOAD_NGINX_MODULE = re.compile(r"(?im)^\s*load_module\s+(\S+?);")
_ABS_PATH = re.compile(r"(?<![\w.:/])(/(?:[\w.@%+~-]+/)*[\w.@%+~-]+)")


@dataclass
class ConfigAnalysis:
    indicators: list[Indicator] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)


def config_kind(name: str) -> str | None:
    n = name.lower()
    if n == ".user.ini" or n == "php.ini" or (n.endswith(".ini") and "php" in n):
        return "php_ini"
    if n == ".htaccess" or n == "htaccess" or n.endswith(".htaccess"):
        return "htaccess"
    if n == "web.config":
        return "web_config"
    return None


def resolve_reference(value: str, config_path: Path) -> str:
    """Resolve a path referenced from a config file (relative to its dir)."""
    v = value.strip().strip("\"'")
    if not v:
        return v
    if os.path.isabs(v):
        return os.path.normpath(v)
    return os.path.normpath(os.path.join(str(config_path.parent), v))


def classify_target(target: str, root: Path | None) -> list[str]:
    """Why a referenced file location is suspicious (possibly empty)."""
    reasons = []
    if target.startswith(TEMP_PREFIXES) or target in ("/tmp", "/dev/shm", "/var/tmp"):
        reasons.append("a world-writable temp directory")
    parts = Path(target).parts
    if any(p.startswith(".") and p not in (".", "..") for p in parts[1:]):
        reasons.append("a hidden file/directory")
    if root is not None and not is_within(target, root) and not target.startswith(TEMP_PREFIXES):
        reasons.append("outside the scanned web root")
    if re.search(r"\." + NON_CODE_EXT + r"$", target, re.I):
        reasons.append("a non-PHP file extension")
    if re.search(r"/(?:uploads?|media|images?|files|cache)/", target, re.I):
        reasons.append("an upload/cache directory")
    return reasons


def analyze_config_text(text: str, path: Path, kind: str, root: Path | None,
                        in_upload_dir: bool, max_snippet: int = 160,
                        source_kind: str = "config") -> ConfigAnalysis:
    """Analyse a PHP ini / .htaccess / web server config file."""
    res = ConfigAnalysis()
    index = LineIndex(text)
    stripped = _strip_comments(text)

    def ev(m: re.Match[str]) -> list[Evidence]:
        return [snippet_at(index, m.start(), m.end(), max_snippet)]

    for m in _PREPEND.finditer(stripped):
        directive, value = m.group(1).lower(), m.group(2)
        if not value or value.lower() in ("none", '""', "''"):
            continue
        target = resolve_reference(value, path)
        exists = os.path.lexists(target)
        reasons = classify_target(target, root)
        benign_hint = os.path.basename(target).lower() in ("wordfence-waf.php", "wp-cerber.php",
                                                           "ninjafirewall.php", "sucuri-waf.php")
        if reasons:
            desc = (f"{directive} loads {target} - located in {', '.join(reasons)}; "
                    "code there runs before/after every PHP request")
            ind = Indicator(f"config.{directive}.suspicious", "config_persistence", desc, 34,
                            Strength.STRONG, ev(m), min_severity="HIGH",
                            tags=frozenset({"config:prepend", "persistence"}))
        else:
            desc = (f"{directive} loads {target} on every PHP request"
                    + (" (matches a known security plugin name; verify it)" if benign_hint else
                       " - a common web shell persistence mechanism; verify the target"))
            ind = Indicator(f"config.{directive}", "config_persistence", desc,
                            12 if benign_hint else 20, Strength.MODERATE, ev(m),
                            min_severity=None if benign_hint else "MEDIUM",
                            tags=frozenset({"config:prepend", "persistence"}))
        if not exists:
            ind.description += " [target not found on this host]"
        res.indicators.append(ind)
        res.relationships.append(Relationship(str(path), target, directive, ind.evidence[0] if ind.evidence else None,
                                              source_kind, exists))

    for m in _ALLOW_URL_INCLUDE.finditer(stripped):
        res.indicators.append(Indicator("config.allow_url_include", "config_persistence",
                                        "Enables allow_url_include (remote code inclusion)", 14,
                                        Strength.MODERATE, ev(m)))
    for m in _INCLUDE_PATH.finditer(stripped):
        if any(t in m.group(1) for t in TEMP_PREFIXES) or re.search(r"/\.[\w-]", m.group(1)):
            res.indicators.append(Indicator("config.include_path_suspicious", "config_persistence",
                                            "include_path contains a temp or hidden directory", 14,
                                            Strength.MODERATE, ev(m)))
    if kind == "php_ini":
        for m in _DISABLE_FUNCS_EMPTY.finditer(stripped):
            if path.name.lower() == ".user.ini":
                res.indicators.append(Indicator("config.disable_functions_cleared", "config_persistence",
                                                "Clears disable_functions in a per-directory ini", 6,
                                                Strength.WEAK, ev(m)))

    if kind in ("htaccess", "webserver"):
        for m in _ADDTYPE_IMG.finditer(stripped):
            res.indicators.append(Indicator("config.handler_nonscript_ext", "config_persistence",
                                            "Maps an image/text extension to the PHP/CGI handler "
                                            "(makes disguised files executable)", 30, Strength.STRONG,
                                            ev(m), min_severity="HIGH", tags=frozenset({"config:handler"})))
        for m in _FILESMATCH_IMG.finditer(stripped):
            res.indicators.append(Indicator("config.filesmatch_handler", "config_persistence",
                                            "<Files>/<FilesMatch> block executes non-script files as PHP",
                                            28, Strength.STRONG, ev(m), min_severity="HIGH",
                                            tags=frozenset({"config:handler"})))
        if in_upload_dir:
            for m in _ADDTYPE_PHP_ANY.finditer(stripped):
                res.indicators.append(Indicator("config.upload_php_handler", "config_persistence",
                                                "Enables a PHP handler inside an upload directory", 22,
                                                Strength.STRONG, ev(m), min_severity="MEDIUM",
                                                tags=frozenset({"config:handler"})))
            for m in _ENGINE_ON.finditer(stripped):
                res.indicators.append(Indicator("config.upload_engine_on", "config_persistence",
                                                "Turns the PHP engine on inside an upload directory", 18,
                                                Strength.STRONG, ev(m), tags=frozenset({"config:handler"})))
            for m in _EXEC_CGI.finditer(stripped):
                if "-ExecCGI" in m.group(0):
                    continue
                res.indicators.append(Indicator("config.upload_execcgi", "config_persistence",
                                                "Enables CGI execution inside an upload directory", 18,
                                                Strength.STRONG, ev(m)))
        for m in _CLOAK.finditer(stripped):
            res.indicators.append(Indicator("config.bot_cloaking", "config_persistence",
                                            "Redirects search-engine crawlers/referrers differently "
                                            "(SEO spam cloaking)", 12, Strength.MODERATE, ev(m)))
        for m in _ERRORDOC_PHP.finditer(stripped):
            base = os.path.basename(m.group(1).split("?")[0])
            if base.startswith("."):
                res.indicators.append(Indicator("config.errordoc_hidden_php", "config_persistence",
                                                "ErrorDocument routes to a hidden PHP file", 14,
                                                Strength.MODERATE, ev(m)))
            target = resolve_reference(m.group(1).split("?")[0].lstrip("/"), path) \
                if not m.group(1).startswith("http") else None
            if target:
                res.relationships.append(Relationship(str(path), target, "ErrorDocument",
                                                      ev(m)[0], source_kind, os.path.lexists(target)))

    if kind == "webserver":
        _analyze_webserver(stripped, path, index, res, max_snippet)
    return res


def _analyze_webserver(text: str, path: Path, index: LineIndex, res: ConfigAnalysis,
                       max_snippet: int) -> None:
    def ev(start: int, end: int) -> list[Evidence]:
        return [snippet_at(index, start, end, max_snippet)]

    for m in _NGINX_PHP_VALUE.finditer(text):
        res.indicators.append(Indicator("webserver.fastcgi_php_value", "config_persistence",
                                        "nginx passes PHP_VALUE overrides to PHP-FPM", 8,
                                        Strength.WEAK, ev(m.start(), m.end())))
    for m in _NGINX_IMG_FASTCGI.finditer(text):
        res.indicators.append(Indicator("webserver.nginx_image_fastcgi", "config_persistence",
                                        "nginx sends image/text extensions to the PHP FastCGI backend",
                                        28, Strength.STRONG, ev(m.start(), m.end()), min_severity="HIGH"))
    for rx in (_LOADMODULE, _LOAD_NGINX_MODULE):
        for m in rx.finditer(text):
            mod = m.group(1)
            if mod.startswith(TEMP_PREFIXES) or re.search(r"/\.[\w-]", mod) or \
                    mod.startswith(("/home/", "/var/www/", "/srv/")):
                res.indicators.append(Indicator("webserver.module_unusual_path", "config_persistence",
                                                f"Loads a server module from an unusual location ({mod})",
                                                30, Strength.STRONG, ev(m.start(), m.end()),
                                                min_severity="HIGH"))
                res.relationships.append(Relationship(str(path), mod, "loads module",
                                                      ev(m.start(), m.end())[0], "webserver",
                                                      os.path.lexists(mod)))
    seen: set[str] = set()
    for m in _ABS_PATH.finditer(text):
        p = m.group(1)
        if p in seen:
            continue
        seen.add(p)
        if p.startswith(TEMP_PREFIXES):
            res.indicators.append(Indicator("webserver.temp_path", "config_persistence",
                                            f"References a temp directory path ({p})", 14,
                                            Strength.MODERATE, ev(m.start(), m.end())))
            res.relationships.append(Relationship(str(path), p, "references", ev(m.start(), m.end())[0],
                                                  "webserver", os.path.lexists(p)))
        elif re.search(r"/\.(?!well-known|htpasswd|htaccess|user\.ini|ht\b)[\w-]+", p) and \
                not p.startswith(("/etc/", "/usr/", "/run/", "/var/run/", "/proc/")):
            res.indicators.append(Indicator("webserver.hidden_path", "config_persistence",
                                            f"References a hidden path ({p})", 6, Strength.WEAK,
                                            ev(m.start(), m.end())))


def _strip_comments(text: str) -> str:
    """Blank ``#`` / ``;`` full-line comments while keeping offsets."""
    return re.sub(r"(?m)^[ \t]*[#;][^\n]*", lambda m: " " * len(m.group(0)), text)
