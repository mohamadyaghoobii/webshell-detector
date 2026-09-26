"""Host persistence hunting (static, read-only).

Looks for mechanisms that can *re-create* a web shell after it is removed
or after a redeployment: cron jobs, systemd units, rc scripts, preload
libraries, PHP-FPM/php.ini prepend settings and deployment hooks (git
hooks, composer/npm scripts). Scripts referenced by those mechanisms are
read (never executed) and analysed as well, building evidence-backed
relationships such as ``cron -> script -> web root file``.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .configfiles import analyze_config_text
from .entropy import is_probably_binary
from .evidence import LineIndex, sanitize
from .metadata import FileChangedError, collect_metadata, read_file
from .models import Evidence, Finding, Indicator, Relationship, Strength
from .scoring import Scorer
from .utils import is_within

log = logging.getLogger(__name__)

SYSTEM_BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/",
                   "/usr/libexec/", "/usr/share/", "/lib64/", "/usr/lib64/")
DEFAULT_WEB_ROOTS = ["/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/var/lib/nginx/html"]
_WEB_HINT = re.compile(r"/home/[^/\s]+/(?:public_html|www|htdocs)|\bwp-content\b|\bpublic_html\b|\bhtdocs\b")
_ABS_PATH = re.compile(r"(?<![\w.:/-])(/(?:[\w.@%+~-]+/)*[\w.@%+~-]+)")
_SCRIPT_EXT = r"(?:php\d?|phtml|pht|phar|jsp|aspx?|sh|py|pl|cgi)"


@dataclass(frozen=True)
class LineRule:
    id: str
    pattern: re.Pattern[str]
    weight: int
    strength: Strength
    description: str
    min_severity: str | None = None


def _lr(id_: str, pattern: str, weight: int, strength: Strength, desc: str,
        min_severity: str | None = None) -> LineRule:
    return LineRule(id_, re.compile(pattern, re.I), weight, strength, desc, min_severity)


LINE_RULES: list[LineRule] = [
    _lr("persist.download", r"\b(?:curl|wget|fetch|lwp-download|lynx\s+-source)\b", 5, Strength.WEAK,
        "Downloads content from the network (curl/wget)"),
    _lr("persist.download_exec",
        r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python\d?|perl|php|ruby)\b",
        25, Strength.STRONG, "Downloads content and pipes it straight into an interpreter", "HIGH"),
    _lr("persist.download_to_script",
        r"\b(?:curl|wget)\b[^\n]*(?:-o|-O|>|--output(?:-document)?=?)\s*['\"]?\S*\." + _SCRIPT_EXT + r"\b",
        22, Strength.STRONG, "Downloads a file and saves it as a server-side script", "MEDIUM"),
    _lr("persist.base64_decode", r"\bbase64\s+(?:-d|--decode|-D)\b|\bopenssl\s+(?:enc\s+)?-d\b[^\n]*-base64",
        12, Strength.MODERATE, "Decodes Base64 data at run time"),
    _lr("persist.embedded_blob", r"\b(?:echo|printf)\s+['\"]?[A-Za-z0-9+/]{80,}={0,2}", 12, Strength.MODERATE,
        "Embeds a long encoded blob in a command"),
    _lr("persist.exec_from_temp",
        r"(?:^|[\s;&|(`])(?:(?:ba)?sh\s+|python\d?\s+|perl\s+|php\s+|nohup\s+|chmod\s+\S+\s+|\.\s+|source\s+)?"
        r"/(?:tmp|var/tmp|dev/shm)/\S+", 12, Strength.MODERATE,
        "Runs or references a file in a world-writable temp directory"),
    _lr("persist.hidden_path", r"/\.(?!well-known\b)[\w-][\w.-]*/?", 5, Strength.WEAK,
        "References a hidden file or directory"),
    _lr("persist.inline_code", r"\b(?:php\d*\s+-r|python\d?\s+-c|perl\s+-e|ruby\s+-e|node\s+-e)\b", 10,
        Strength.MODERATE, "Runs inline interpreter code (php -r / python -c / perl -e)"),
    _lr("persist.reverse_shell", r"/dev/tcp/|\bnc(?:at)?\b[^\n]*\s-e\s|\bbash\s+-i\b|\bmkfifo\b|\bsocat\b[^\n]*exec",
        30, Strength.STRONG, "Reverse-shell style command", "HIGH"),
    _lr("persist.chattr", r"\bchattr\s+[^\n]*\+[ia]\b", 22, Strength.STRONG,
        "Sets immutable/append-only attributes (prevents deletion of files)", "MEDIUM"),
    _lr("persist.timestomp", r"\btouch\s+(?:-\w*\s+)*-(?:\w*[rtd])\b", 8, Strength.MODERATE,
        "Sets file timestamps explicitly (touch -r/-t/-d: possible timestomping)"),
    _lr("persist.at_reboot", r"^\s*@reboot\b", 4, Strength.WEAK, "Runs at every boot (@reboot)"),
    _lr("persist.interpreter", r"\b(?:php\d*|python\d?(?:\.\d+)?|perl|bash|sh|ncat|nc|socat)\b", 2,
        Strength.WEAK, "Invokes a script interpreter"),
    _lr("persist.hidden_script", r"/\.[\w-]+\." + _SCRIPT_EXT + r"\b", 12, Strength.MODERATE,
        "References a hidden script file"),
    _lr("persist.world_writable", r"\bchmod\s+(?:-R\s+)?0?777\b", 4, Strength.WEAK,
        "Makes files world-writable (chmod 777)"),
    _lr("persist.write_script",
        r"(?:\b(?:cp|mv|install|rsync|tee|ln\s+-s\w*)\b[^\n]*|>{1,2}\s*)['\"]?\S*\." + _SCRIPT_EXT + r"\b",
        10, Strength.MODERATE, "Copies/writes a server-side script file"),
]


@dataclass
class PersistenceResult:
    findings: list[Finding] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_examined: int = 0


class PersistenceHunter:
    def __init__(self, cfg: dict[str, Any], web_roots: list[Path], scorer: Scorer,
                 include_host: bool = True) -> None:
        pc = cfg["persistence"]
        self.cfg = cfg
        self.locations: list[str] = list(pc["locations"])
        self.php_locations: list[str] = list(pc.get("php_config_locations", []))
        self.max_files = int(pc.get("max_files", 20000))
        self.max_size = int(pc.get("max_file_size", 1048576))
        self.report_min = int(pc.get("report_min_score", 12))
        self.follow_depth = int(pc.get("follow_scripts_depth", 2))
        self.web_roots = [str(p) for p in web_roots]
        self.scorer = scorer
        self.include_host = include_host
        self.result = PersistenceResult()
        self._visited: set[str] = set()
        self._findings_by_path: dict[str, Finding] = {}

    # ------------------------------------------------------------ discovery
    def _expand(self, patterns: list[str]) -> list[Path]:
        files: list[Path] = []
        for pat in patterns:
            for match in sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat]:
                p = Path(match)
                try:
                    st = os.lstat(p)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    self.result.errors.append(f"{p}: {exc}")
                    continue
                if stat.S_ISREG(st.st_mode):
                    files.append(p)
                elif stat.S_ISDIR(st.st_mode):
                    files.extend(self._walk(p))
                if len(files) >= self.max_files:
                    return files[: self.max_files]
        return files

    def _walk(self, top: Path, max_depth: int = 4) -> list[Path]:
        out: list[Path] = []
        for cur, dirs, names in os.walk(top, followlinks=False,
                                        onerror=lambda e: self.result.errors.append(str(e))):
            if Path(cur).relative_to(top).parts.__len__() >= max_depth:
                dirs[:] = []
            dirs.sort()
            for n in sorted(names):
                p = Path(cur) / n
                try:
                    if stat.S_ISREG(os.lstat(p).st_mode):
                        out.append(p)
                except OSError as exc:
                    self.result.errors.append(f"{p}: {exc}")
        return out

    # ----------------------------------------------------------------- main
    def run(self) -> PersistenceResult:
        if self.include_host:
            for p in self._expand(self.locations):
                self.analyze_file(p, "persistence", 0)
            for p in self._expand(self.php_locations):
                self._analyze_php_config(p)
        for root in self.web_roots:
            self._deployment_hooks(Path(root))
        return self.result

    def _read_text(self, path: Path) -> tuple[str | None, Any]:
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_size > self.max_size:
                return None, None
            r = read_file(path, self.max_size, st, want_flags=False)
        except (OSError, FileChangedError) as exc:
            self.result.errors.append(f"{path}: {exc}")
            return None, None
        if is_probably_binary(r.data[:4096]):
            return None, None
        return r.data.decode("utf-8", "replace"), (st, r)

    def _analyze_php_config(self, path: Path) -> None:
        if not (path.suffix in (".ini", ".conf") or path.name.endswith("php-fpm.conf")):
            return
        text, info = self._read_text(path)
        if text is None:
            return
        self.result.files_examined += 1
        ca = analyze_config_text(text, path, "php_ini", None, False, source_kind="config")
        if not ca.indicators:
            return
        md = collect_metadata(path, path.parent, info[0])
        md.relpath = str(path)
        md.sha256 = info[1].sha256
        f = Finding(kind="config", metadata=md, language="config")
        for ind in ca.indicators:
            f.add(ind)
        self.scorer.score(f)
        self.result.findings.append(f)
        self.result.relationships.extend(ca.relationships)

    def _deployment_hooks(self, root: Path) -> None:
        """Git hooks, composer/npm lifecycle scripts, entrypoints in a web root."""
        hooks = root / ".git" / "hooks"
        if hooks.is_dir():
            for p in sorted(hooks.iterdir()):
                if p.is_file() and not p.name.endswith(".sample"):
                    f = self.analyze_file(p, "deploy_hook", 0, force=True)
                    if f is not None:
                        f.add(Indicator("deploy.git_hook", "persistence",
                                        f"Active git hook '{p.name}' runs on git operations (e.g. every deploy pull)",
                                        10, Strength.MODERATE))
                        self.scorer.score(f)
        for name, keys in (("composer.json", None), ("package.json",
                                                     ("preinstall", "install", "postinstall", "prepare",
                                                      "prestart", "start", "postupdate"))):
            p = root / name
            if not p.is_file():
                continue
            text, info = self._read_text(p)
            if text is None:
                continue
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                continue
            scripts = doc.get("scripts") or {}
            if not isinstance(scripts, dict):
                continue
            lines = []
            for k, v in scripts.items():
                if keys and k not in keys:
                    continue
                for cmd in (v if isinstance(v, list) else [v]):
                    if isinstance(cmd, str):
                        lines.append(f"{k}: {cmd}")
            if lines:
                self._analyze_lines(p, "\n".join(lines), "deploy_hook", 0, info, min_score=10)
        for p in sorted(root.glob("*")):
            n = p.name.lower()
            if p.is_file() and (n.endswith(".sh") or n.startswith(("dockerfile", "docker-entrypoint", "deploy"))
                                or n in ("procfile", "entrypoint")):
                self.analyze_file(p, "deploy_hook", 0)

    # --------------------------------------------------------- per-file
    def analyze_file(self, path: Path, kind: str, depth: int, force: bool = False) -> Finding | None:
        key = os.path.realpath(path)
        if key in self._visited:
            return self._findings_by_path.get(key)
        self._visited.add(key)
        if path.name == "ld.so.preload":
            return self._ld_preload(path)
        text, info = self._read_text(path)
        if text is None:
            return None
        self.result.files_examined += 1
        return self._analyze_lines(path, text, kind, depth, info, force=force)

    def _ld_preload(self, path: Path) -> Finding | None:
        text, info = self._read_text(path)
        lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
        if not lines or all(ln.startswith("#") for ln in lines):
            return None
        md = collect_metadata(path, path.parent, info[0])
        md.relpath = str(path)
        md.sha256 = info[1].sha256
        f = Finding(kind="persistence", metadata=md, language="config")
        f.add(Indicator("persist.ld_preload", "persistence",
                        "/etc/ld.so.preload is set: a library is injected into every process "
                        "(rootkit technique)", 35, Strength.STRONG,
                        [Evidence(None, sanitize(text.strip()[:160]))], min_severity="HIGH"))
        self.scorer.score(f)
        self.result.findings.append(f)
        return f

    def _analyze_lines(self, path: Path, text: str, kind: str, depth: int, info: Any,
                       force: bool = False, min_score: int | None = None) -> Finding | None:
        md = collect_metadata(path, path.parent, info[0])
        md.relpath = str(path)
        md.sha256 = info[1].sha256
        f = Finding(kind="persistence", metadata=md, language=_unit_type(path))
        index = LineIndex(text)
        is_cron = _is_cron(path)
        offset = 0
        children: list[tuple[str, Evidence]] = []
        for raw_line in text.splitlines(keepends=True):
            line = raw_line.rstrip("\n")
            start = offset
            offset += len(raw_line)
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            line_inds = self._line_indicators(line, index.line_of(start))
            ev = Evidence(index.line_of(start), sanitize(stripped, 180), str(path))
            command = _command_part(stripped, path, is_cron)
            executed = _executed_paths(command) if command else []
            line_score = sum(i.weight for i in line_inds)
            for ind in line_inds:
                f.add(ind)
            relation = _relation_verb(stripped)
            for p in _ABS_PATH.findall(stripped):
                if p in executed:
                    continue
                if line_score >= 6 or self._in_web_root(p):
                    self.result.relationships.append(Relationship(
                        str(path), os.path.normpath(p), relation, ev, "persistence", os.path.lexists(p)))
            for p in executed:
                self.result.relationships.append(Relationship(
                    str(path), p, "executes", ev, "persistence", os.path.lexists(p)))
                children.append((p, ev))
        # Follow referenced scripts (read-only)
        if depth < self.follow_depth:
            for child, ev in children:
                if child.startswith(SYSTEM_BIN_DIRS) or not os.path.isfile(child):
                    continue
                cf = self.analyze_file(Path(child), "persistence_script", depth + 1)
                if cf is not None and cf.score >= self.report_min:
                    f.add(Indicator("persist.executes_suspicious_script", "persistence",
                                    f"Executes {child}, which is itself suspicious ({cf.severity})",
                                    max(10, min(cf.score, 30)), Strength.STRONG, [ev]))
        self.scorer.score(f)
        threshold = self.report_min if min_score is None else min_score
        if f.indicators and (f.score >= threshold or force):
            f.notes.append(f"Persistence source type: {kind}")
            self.result.findings.append(f)
            self._findings_by_path[os.path.realpath(path)] = f
            return f
        return None

    def _in_web_root(self, p: str) -> bool:
        return any(is_within(p, r) for r in self.web_roots + DEFAULT_WEB_ROOTS) or bool(_WEB_HINT.search(p))

    def _line_indicators(self, line: str, lineno: int) -> list[Indicator]:
        out = []
        ev = [Evidence(lineno, sanitize(line.strip(), 180))]
        for rule in LINE_RULES:
            if rule.pattern.search(line):
                out.append(Indicator(rule.id, "persistence", rule.description, rule.weight, rule.strength,
                                     list(ev), min_severity=rule.min_severity))
        webrefs = [p for p in _ABS_PATH.findall(line) if self._in_web_root(p)] or \
            ([m.group(0) for m in _WEB_HINT.finditer(line)])
        if webrefs:
            out.append(Indicator("persist.webroot_reference", "persistence",
                                 f"References the web root ({webrefs[0]})", 10, Strength.MODERATE, list(ev),
                                 tags=frozenset({"webroot"})))
            if any(i.rule_id in ("persist.download", "persist.write_script", "persist.base64_decode",
                                 "persist.embedded_blob", "persist.chattr") for i in out):
                out.append(Indicator("persist.modifies_webroot", "persistence",
                                     "Writes, downloads or protects files inside the web root from a "
                                     "scheduled/automatic job", 20, Strength.STRONG, list(ev), min_severity="HIGH"))
        return out


def _unit_type(path: Path) -> str:
    s = str(path)
    if "/cron" in s or path.name in ("crontab", "anacrontab"):
        return "cron"
    if "/systemd/" in s:
        return "systemd"
    if "/.git/hooks/" in s:
        return "git-hook"
    if path.name in ("composer.json", "package.json"):
        return "package-scripts"
    return "script"


def _is_cron(path: Path) -> bool:
    s = str(path)
    return path.name in ("crontab", "anacrontab") or "/cron.d/" in s or "/var/spool/cron" in s


def _command_part(line: str, path: Path, is_cron: bool) -> str | None:
    """Extract the command of a cron line / systemd Exec*= / script line."""
    m = re.match(r"^(?:Exec\w*|ExecStart\w*)\s*=\s*[-@+!:]*(.*)$", line)
    if m:
        return m.group(1)
    if is_cron:
        if re.match(r"^[A-Za-z_]\w*\s*=", line):
            return None
        parts = line.split()
        if parts and parts[0].startswith("@"):
            rest = parts[1:]
        elif len(parts) >= 6:
            rest = parts[5:]
        else:
            return None
        system_tab = path.name in ("crontab",) and "/spool/" not in str(path) or "/cron.d/" in str(path)
        if system_tab and rest and not rest[0].startswith("/") and re.fullmatch(r"[\w.-]+", rest[0]):
            rest = rest[1:]  # user field
        return " ".join(rest)
    return line


def _executed_paths(command: str) -> list[str]:
    """Absolute paths that a command line executes (script/program arguments)."""
    out = []
    for seg in re.split(r"&&|\|\||;|\|", command):
        tokens = seg.strip().split()
        while tokens and (tokens[0] in ("sudo", "nohup", "exec", "env", "nice", "timeout", "flock")
                          or re.match(r"^\w+=", tokens[0]) or tokens[0].startswith("-")):
            tokens = tokens[1:]
        if not tokens:
            continue
        first = tokens[0].strip("'\"")
        base = os.path.basename(first)
        if re.fullmatch(r"(?:ba|da|z|k)?sh|python\d?(?:\.\d+)?|perl|php\d*(?:\.\d+)?|ruby|node|source|\.", base):
            for t in tokens[1:]:
                t = t.strip("'\"")
                if t.startswith("-"):
                    continue
                if t.startswith("/"):
                    out.append(os.path.normpath(t))
                break
        elif first.startswith("/"):
            out.append(os.path.normpath(first))
    return out


def _relation_verb(line: str) -> str:
    low = line.lower()
    if re.search(r"\b(?:curl|wget)\b", low):
        return "downloads/references"
    if re.search(r"\bchattr\b", low):
        return "protects (chattr)"
    if re.search(r"\b(?:cp|mv|install|rsync|tee|ln)\b|>>?", low):
        return "writes/copies"
    return "references"
