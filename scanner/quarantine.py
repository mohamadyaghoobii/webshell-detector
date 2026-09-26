"""Explicit, opt-in evidence quarantine.

Never automatic: the CLI requires ``--quarantine DIR`` *and*
``--confirm-quarantine``; without confirmation only a dry run is printed.

For each file: re-hash and compare with the scan result (race detection),
copy to ``DIR/<sha256>.sample`` with mode 0400 using O_EXCL (never
overwrite), verify the copy, append a JSON manifest line, then - unless
copy-only mode is selected - remove the original. Files are never executed.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

from .metadata import FileChangedError, open_nofollow, read_file
from .models import SEVERITY_RANK, Finding
from .utils import is_within, now_iso


class QuarantineError(Exception):
    pass


def eligible(findings: list[Finding], min_severity: str) -> list[Finding]:
    rank = SEVERITY_RANK[min_severity]
    return [f for f in findings
            if not f.allowlisted and SEVERITY_RANK[f.severity] >= rank
            and f.kind in ("webshell", "referenced_file") and f.metadata.file_type == "file"
            and "!/" not in f.metadata.path]


def quarantine(findings: list[Finding], qdir: Path, roots: list[Path], copy_only: bool,
               dry_run: bool) -> list[dict[str, Any]]:
    qdir = qdir.resolve()
    for r in roots:
        if is_within(qdir, r.resolve()):
            raise QuarantineError(f"quarantine directory {qdir} must not be inside the scanned root {r}")
    records: list[dict[str, Any]] = []
    if not dry_run:
        qdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = qdir / "manifest.jsonl"
    for f in findings:
        md = f.metadata
        rec: dict[str, Any] = {"original_path": md.path, "sha256": md.sha256, "severity": f.severity,
                               "score": f.score, "reasons": f.reasons()[:10], "time": now_iso(),
                               "mode": md.mode, "uid": md.uid, "gid": md.gid, "owner": md.owner,
                               "group": md.group, "mtime": md.mtime, "ctime": md.ctime, "size": md.size,
                               "inode": md.inode, "fs_flags": md.fs_flags}
        if dry_run:
            rec["status"] = "DRY-RUN (add --confirm-quarantine to act)"
            records.append(rec)
            continue
        try:
            st = os.lstat(md.path)
            if not stat.S_ISREG(st.st_mode):
                raise QuarantineError("no longer a regular file")
            current = read_file(md.path, 0, st, want_flags=False)
            if md.sha256 and current.sha256 != md.sha256:
                raise QuarantineError("content changed since the scan; re-scan before quarantining")
            dest = qdir / f"{current.sha256}.sample"
            if dest.exists():
                rec["status"] = "ALREADY-PRESERVED"
            else:
                with os.fdopen(open_nofollow(md.path, st), "rb") as src:
                    dst_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | getattr(os, "O_NOFOLLOW", 0), 0o400)
                    with os.fdopen(dst_fd, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                check = read_file(dest, 0, want_flags=False)
                if check.sha256 != current.sha256:
                    dest.unlink(missing_ok=True)
                    raise QuarantineError("copy verification failed")
                rec["status"] = "PRESERVED"
            rec["quarantine_path"] = str(dest)
            if not copy_only:
                if md.fs_flags and "immutable" in md.fs_flags:
                    raise QuarantineError("original is immutable (chattr +i); copied but not removed")
                os.unlink(md.path)
                rec["status"] += "+REMOVED-FROM-ORIGINAL-LOCATION"
        except (OSError, FileChangedError, QuarantineError) as exc:
            rec["status"] = f"ERROR: {exc}"
        with open(manifest, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        records.append(rec)
    return records
