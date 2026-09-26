"""Directory timeline: files ordered by modification or change time."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from .filesystem import walk
from .metadata import SERVER_SIDE_EXT, collect_metadata
from .utils import is_hidden_name, ts_to_iso


@dataclass
class TimelineRow:
    path: str
    relpath: str
    mtime: float | None
    ctime: float | None
    size: int | None
    mode: str | None
    owner: str
    kind: str
    flags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "relpath": self.relpath, "mtime": ts_to_iso(self.mtime),
                "ctime": ts_to_iso(self.ctime), "size": self.size, "mode": self.mode,
                "owner": self.owner, "type": self.kind, "flags": self.flags}


def build_timeline(root: Path, excludes: list[str], after: datetime | None = None,
                   before: datetime | None = None, extensions: list[str] | None = None,
                   sort_by: str = "mtime", errors: list[str] | None = None) -> list[TimelineRow]:
    exts = {("." + x.lower().lstrip(".")) for x in (extensions or [])}
    rows: list[TimelineRow] = []
    errs = errors if errors is not None else []
    for entry in walk(root, excludes, lambda p, e: errs.append(f"{p}: {e}")):
        md = collect_metadata(entry.path, root, entry.st)
        if exts and md.extension not in exts:
            continue
        ts = md.ctime if sort_by == "ctime" else md.mtime
        if after and (ts or 0) < after.timestamp():
            continue
        if before and (ts or 0) > before.timestamp():
            continue
        flags = []
        if md.extension in SERVER_SIDE_EXT:
            flags.append("script")
        if is_hidden_name(entry.path.name):
            flags.append("hidden")
        if md.ctime and md.mtime and md.ctime - md.mtime > 86400 * 30:
            flags.append("ctime>>mtime")
        if md.mtime and md.mtime > datetime.now().timestamp() + 300:
            flags.append("future-mtime")
        if entry.kind == "symlink":
            flags.append(f"-> {md.link_target}")
        rows.append(TimelineRow(md.path, md.relpath, md.mtime, md.ctime, md.size, md.mode,
                                f"{md.owner or md.uid}:{md.group or md.gid}", md.file_type, flags))
    rows.sort(key=lambda r: ((r.ctime if sort_by == "ctime" else r.mtime) or 0, r.relpath))
    return rows


def print_timeline(rows: list[TimelineRow], out: TextIO, sort_by: str) -> None:
    print(f"{'MTIME':<25} {'CTIME':<25} {'SIZE':>10} {'MODE':<5} {'OWNER':<20} PATH  [flags]", file=out)
    for r in rows:
        flags = f"  [{', '.join(r.flags)}]" if r.flags else ""
        print(f"{ts_to_iso(r.mtime) or '-':<25} {ts_to_iso(r.ctime) or '-':<25} {r.size or 0:>10} "
              f"{r.mode or '-':<5} {r.owner[:20]:<20} {r.relpath}{flags}", file=out)
    print(f"\n{len(rows)} entries sorted by {sort_by}. Note: mtime can be forged (touch); "
          "ctime cannot be set directly by user space.", file=out)


def write_timeline(rows: list[TimelineRow], json_path: str | None, csv_path: str | None) -> None:
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump([r.to_dict() for r in rows], fh, indent=1)
    if csv_path:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["mtime", "ctime", "size", "mode", "owner", "type", "path",
                                               "relpath", "flags"])
            w.writeheader()
            for r in rows:
                d = r.to_dict()
                d["flags"] = ";".join(r.flags)
                w.writerow(d)
