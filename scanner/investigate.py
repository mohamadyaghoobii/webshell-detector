"""Single-file deep static investigation (``webshell-hunter investigate FILE``)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, TextIO

from .engine import Scanner, ScanOptions
from .filesystem import Entry, detect_frameworks, root_owner_home
from .iocs import extract_iocs
from .metadata import FileChangedError, read_file
from .models import SEVERITY_RANK, Finding
from .reporting.terminal import Painter, print_finding, supports_color
from .utils import human_size, ts_to_iso

NEARBY_LIMIT = 500


def investigate(path: Path, cfg: dict[str, Any], root: Path | None = None, yara_rules: str | None = None,
                hashes: dict[str, str] | None = None, git: bool = False) -> dict[str, Any]:
    path = Path(os.path.abspath(path))
    st = os.lstat(path)
    root = root or guess_root(path, cfg)
    opts = ScanOptions(roots=[root], yara_rules=yara_rules, hashes=hashes or {}, all_hashes=True,
                       max_size=int(cfg["scanner"]["max_file_size_mb"]) * 1024 * 1024, git=git,
                       keep_all=True, workers=1)
    scanner = Scanner(cfg, opts)
    scanner._load_yara()
    frameworks = detect_frameworks(root)
    git_state = None
    if git:
        from .gitstate import load_git_state
        try:
            git_state = load_git_state(root)
        except Exception as exc:
            scanner.result.warnings.append(f"git: {exc}")
    kind = "symlink" if stat.S_ISLNK(st.st_mode) else ("file" if stat.S_ISREG(st.st_mode) else "other")
    out = scanner.analyze_entry(Entry(path, st, kind), root, frameworks, git_state, root_owner_home(root))
    f = out.finding
    assert f is not None
    scanner.scorer.score(f, {"script"} if out.is_script else set())
    iocs: dict[str, list[str]] = {}
    if kind == "file":
        try:
            r = read_file(path, opts.max_size, st, want_flags=False)
            text = r.data.decode("utf-8", "replace")
            iocs = extract_iocs(text, cfg["iocs"].get("ignore_domains"), 200)
        except (OSError, FileChangedError):
            pass
    f.iocs = iocs
    nearby = _nearby(scanner, path, root, frameworks, st)
    return {"finding": f, "nearby": nearby, "warnings": scanner.result.warnings,
            "flows": [i for i in f.indicators if i.category == "source_to_sink"],
            "encoding": [i for i in f.indicators if i.category in ("obfuscation", "obfuscated_execution")],
            "yara": [i for i in f.indicators if i.category == "yara"]}


ROOT_MARKERS = (".git", "wp-config.php", "artisan", "composer.json", "package.json", "configuration.php")


def guess_root(path: Path, cfg: dict[str, Any]) -> Path:
    """Best-effort web root for a single file, so location rules still apply.

    Nearest ancestor holding a project marker (.git, wp-config.php...);
    otherwise the directory above the first upload-like path component.
    """
    parents = list(path.parents)[:8]
    for p in parents:
        if any((p / m).exists() for m in ROOT_MARKERS):
            return p
    upload_names = {n.lower() for n in cfg["upload_dirs"]["strong"]}
    for p in parents:
        if p.name.lower() in upload_names or p.name.lower().startswith("upload"):
            continue
        if p != path.parent:
            return p
        if not any(q.name.lower() in upload_names for q in parents):
            return p
    return path.parent


def _nearby(scanner: Scanner, path: Path, root: Path, frameworks: dict, st: os.stat_result) -> list[dict[str, Any]]:
    """Suspicious siblings and files modified within one hour of the sample."""
    out = []
    try:
        siblings = sorted(os.scandir(path.parent), key=lambda d: d.name)[:NEARBY_LIMIT]
    except OSError:
        return out
    for de in siblings:
        p = Path(de.path)
        if p == path:
            continue
        try:
            sst = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISDIR(sst.st_mode):
            continue
        kind = "symlink" if stat.S_ISLNK(sst.st_mode) else ("file" if stat.S_ISREG(sst.st_mode) else "other")
        try:
            o = scanner.analyze_entry(Entry(p, sst, kind), root, frameworks, None, None)
        except Exception:
            continue
        f = o.finding
        close_in_time = abs(sst.st_mtime - st.st_mtime) <= 3600 or abs(sst.st_ctime - st.st_ctime) <= 3600
        if f is None:
            if close_in_time:
                out.append({"path": str(p), "severity": "INFO", "score": 0, "reason": "modified within 1h"})
            continue
        scanner.scorer.score(f, {"script"} if o.is_script else set())
        if SEVERITY_RANK[f.severity] >= SEVERITY_RANK["LOW"] or close_in_time:
            out.append({"path": str(p), "severity": f.severity, "score": f.score,
                        "reason": (f.reasons()[0] if f.indicators else "") +
                                  (" (modified within 1h)" if close_in_time else "")})
    out.sort(key=lambda d: (-SEVERITY_RANK[d["severity"]], -d["score"]))
    return out


def print_investigation(data: dict[str, Any], out: TextIO, color: bool = True) -> None:
    f: Finding = data["finding"]
    paint = Painter(supports_color(out, not color))
    md = f.metadata
    print(paint("STATIC INVESTIGATION (the sample was NOT executed)", "bold"), file=out)
    rows = [("Path", md.path), ("Real path", md.realpath), ("SHA256", md.sha256), ("SHA1", md.sha1),
            ("MD5", md.md5), ("Size", f"{human_size(md.size)} ({md.size} bytes)"),
            ("Permissions", f"{md.permissions} ({md.mode})"),
            ("Owner", f"{md.owner or md.uid}:{md.group or md.gid} (uid={md.uid} gid={md.gid})"),
            ("Inode / links", f"{md.inode} / {md.nlink}"), ("Modified", ts_to_iso(md.mtime)),
            ("Changed (ctime)", ts_to_iso(md.ctime)), ("Accessed", ts_to_iso(md.atime)),
            ("Content type", md.content_type), ("Language", f.language),
            ("Entropy", f"{md.entropy:.3f} bits/byte" if md.entropy is not None else None),
            ("FS attributes", ", ".join(md.fs_flags) or "none"), ("Git", f.git_status)]
    for k, v in rows:
        if v not in (None, ""):
            print(f"{k + ':':<18}{v}", file=out)
    print("", file=out)
    print_finding(f, paint, out, show_evidence=True, commands=True)
    print("", file=out)
    print(paint("Source-to-sink relationships:", "bold"), file=out)
    for i in data["flows"] or []:
        print(f"  - {i.description}", file=out)
    if not data["flows"]:
        print("  (none found)", file=out)
    print(paint("Encoding / obfuscation indicators:", "bold"), file=out)
    for i in data["encoding"] or []:
        print(f"  - {i.description}", file=out)
    if not data["encoding"]:
        print("  (none found)", file=out)
    print(paint("YARA matches:", "bold"), file=out)
    for i in data["yara"] or []:
        print(f"  - {i.description}", file=out)
    if not data["yara"]:
        print("  (none, or YARA not enabled)", file=out)
    print(paint("Nearby files (same directory):", "bold"), file=out)
    for n in data["nearby"][:30] or []:
        print(f"  [{n['severity']}] {n['path']}  {n['reason']}", file=out)
    if not data["nearby"]:
        print("  (nothing notable)", file=out)
    for w in data["warnings"]:
        print(paint(f"[!] {w}", "MEDIUM"), file=out)


def investigation_to_dict(data: dict[str, Any]) -> dict[str, Any]:
    f: Finding = data["finding"]
    return {"finding": f.to_dict(), "nearby": data["nearby"], "warnings": data["warnings"],
            "note": "Static analysis only; the sample was not executed. IOCs are unverified."}
