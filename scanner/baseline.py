"""Known-good baselines and deployment comparison.

A baseline records, per relative path: SHA256, size, mtime, mode, uid, gid,
type and symlink target. Comparing a later state against it reveals files
that were added or changed *after* the known-good point - the core question
when a web shell keeps coming back after redeployments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .filesystem import walk
from .metadata import FileChangedError, read_file
from .models import BaselineChange
from .utils import now_iso, safe_relpath

log = logging.getLogger(__name__)

FORMAT = "webshell-hunter-baseline"
FORMAT_VERSION = 1


def entry_from_stat(st: os.stat_result, sha256: str | None, link_target: str | None = None) -> dict[str, Any]:
    if stat.S_ISLNK(st.st_mode):
        ftype = "symlink"
    elif stat.S_ISREG(st.st_mode):
        ftype = "file"
    else:
        ftype = "other"
    e: dict[str, Any] = {
        "type": ftype,
        "sha256": sha256,
        "size": st.st_size,
        "mtime": round(st.st_mtime, 3),
        "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        "uid": st.st_uid,
        "gid": st.st_gid,
    }
    if link_target is not None:
        e["link_target"] = link_target
    return e


def snapshot(root: Path, excludes: list[str], workers: int = 8,
             on_error: Callable[[str, OSError], None] | None = None) -> dict[str, dict[str, Any]]:
    """Hash every file under *root* (symlinks recorded, never followed)."""
    errors = on_error or (lambda p, e: log.warning("cannot access %s: %s", p, e))
    entries: dict[str, dict[str, Any]] = {}
    items = list(walk(root, excludes, errors))

    def one(item) -> tuple[str, dict[str, Any] | None]:
        rel = safe_relpath(item.path, root)
        if item.kind == "symlink":
            try:
                target = os.readlink(item.path)
            except OSError:
                target = None
            return rel, entry_from_stat(item.st, None, target)
        if item.kind != "file":
            return rel, entry_from_stat(item.st, None)
        try:
            r = read_file(item.path, 0, item.st, want_flags=False)
            return rel, entry_from_stat(item.st, r.sha256)
        except (OSError, FileChangedError) as exc:
            errors(str(item.path), exc if isinstance(exc, OSError) else OSError(str(exc)))
            return rel, None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for rel, entry in ex.map(one, items, chunksize=64):
            if entry is not None:
                entries[rel] = entry
    return entries


def _entries_digest(entries: dict[str, dict[str, Any]]) -> str:
    blob = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def create_baseline(root: Path, output: Path, excludes: list[str], workers: int = 8,
                    on_error: Callable[[str, OSError], None] | None = None) -> dict[str, Any]:
    entries = snapshot(root, excludes, workers, on_error)
    doc = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "tool_version": __version__,
        "created": now_iso(),
        "hostname": socket.gethostname(),
        "root": str(root),
        "excludes": excludes,
        "file_count": len(entries),
        "entries_sha256": _entries_digest(entries),
        "entries": entries,
    }
    tmp = output.with_name(output.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, output)
    return doc


class BaselineError(Exception):
    pass


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot load baseline {path}: {exc}") from exc
    if doc.get("format") != FORMAT or "entries" not in doc:
        raise BaselineError(f"{path} is not a webshell-hunter baseline")
    doc["_integrity_ok"] = doc.get("entries_sha256") == _entries_digest(doc["entries"])
    return doc


def compare_entries(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> list[BaselineChange]:
    """Diff two snapshots. Deterministic ordering (by path, then status)."""
    changes: list[BaselineChange] = []
    for rel in sorted(set(old) | set(new)):
        o, n = old.get(rel), new.get(rel)
        if o is None and n is not None:
            changes.append(BaselineChange("NEW", rel, None, n, f"new {n['type']}"))
            continue
        if n is None and o is not None:
            changes.append(BaselineChange("DELETED", rel, o, None, f"{o['type']} removed"))
            continue
        assert o is not None and n is not None
        if o["type"] != n["type"]:
            changes.append(BaselineChange("TYPE_CHANGED", rel, o, n, f"{o['type']} -> {n['type']}"))
            continue
        if o["type"] == "symlink" and o.get("link_target") != n.get("link_target"):
            changes.append(BaselineChange("SYMLINK_CHANGED", rel, o, n,
                                          f"{o.get('link_target')} -> {n.get('link_target')}"))
        if o.get("sha256") and n.get("sha256") and o["sha256"] != n["sha256"]:
            changes.append(BaselineChange("MODIFIED", rel, o, n,
                                          f"content changed (size {o['size']} -> {n['size']})"))
        if o.get("mode") != n.get("mode"):
            changes.append(BaselineChange("PERMISSION_CHANGED", rel, o, n, f"{o.get('mode')} -> {n.get('mode')}"))
        if (o.get("uid"), o.get("gid")) != (n.get("uid"), n.get("gid")):
            changes.append(BaselineChange("OWNER_CHANGED", rel, o, n,
                                          f"{o.get('uid')}:{o.get('gid')} -> {n.get('uid')}:{n.get('gid')}"))
    return changes
