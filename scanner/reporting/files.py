"""JSON and CSV report writers."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from ..models import ScanResult
from ..utils import ts_to_iso


def _atomic_write(path: str | Path, writer) -> None:
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        writer(fh)
    os.replace(tmp, p)


def write_json(result: ScanResult, path: str | Path, with_evidence: bool = True) -> None:
    _atomic_write(path, lambda fh: json.dump(result.to_dict(with_evidence), fh, indent=2,
                                             ensure_ascii=False, default=str))


CSV_FIELDS = ["severity", "confidence", "score", "kind", "path", "relpath", "sha256", "size", "owner",
              "group", "mode", "mtime", "ctime", "language", "baseline_status", "git_status",
              "allowlisted", "reasons", "rule_ids"]


def write_csv(result: ScanResult, path: str | Path) -> None:
    def writer(fh) -> None:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for f in result.findings:
            md = f.metadata
            w.writerow({
                "severity": f.severity, "confidence": f.confidence, "score": f.score, "kind": f.kind,
                "path": _csv_safe(md.path), "relpath": _csv_safe(md.relpath), "sha256": md.sha256 or "",
                "size": md.size, "owner": md.owner or md.uid, "group": md.group or md.gid, "mode": md.mode,
                "mtime": ts_to_iso(md.mtime), "ctime": ts_to_iso(md.ctime), "language": f.language or "",
                "baseline_status": ";".join(f.baseline_status), "git_status": f.git_status or "",
                "allowlisted": f.allowlisted, "reasons": _csv_safe(" | ".join(f.reasons())),
                "rule_ids": ";".join(sorted(i.rule_id for i in f.indicators)),
            })
    _atomic_write(path, writer)


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection from hostile file names."""
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value
