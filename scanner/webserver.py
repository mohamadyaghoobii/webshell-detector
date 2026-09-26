"""Optional static inspection of web server configuration (read-only)."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Any

from .configfiles import analyze_config_text
from .entropy import is_probably_binary
from .metadata import FileChangedError, collect_metadata, read_file
from .models import Finding, Relationship
from .scoring import Scorer

log = logging.getLogger(__name__)
MAX_SIZE = 2 * 1024 * 1024


def scan_webserver_configs(cfg: dict[str, Any], scorer: Scorer,
                           errors: list[str]) -> tuple[list[Finding], list[Relationship], int]:
    findings: list[Finding] = []
    rels: list[Relationship] = []
    examined = 0
    for loc in cfg["webserver_config"]["locations"]:
        top = Path(loc)
        if not top.exists():
            continue
        for cur, dirs, names in os.walk(top, followlinks=False, onerror=lambda e: errors.append(str(e))):
            dirs.sort()
            for n in sorted(names):
                p = Path(cur) / n
                try:
                    st = os.lstat(p)
                    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SIZE:
                        continue
                    r = read_file(p, MAX_SIZE, st, want_flags=False)
                except (OSError, FileChangedError) as exc:
                    errors.append(f"{p}: {exc}")
                    continue
                if is_probably_binary(r.data[:4096]):
                    continue
                examined += 1
                text = r.data.decode("utf-8", "replace")
                ca = analyze_config_text(text, p, "webserver", None, False, source_kind="webserver")
                rels.extend(ca.relationships)
                if not ca.indicators:
                    continue
                md = collect_metadata(p, top, st)
                md.relpath = str(p)
                md.sha256 = r.sha256
                f = Finding(kind="config", metadata=md, language="webserver-config")
                for ind in ca.indicators:
                    f.add(ind)
                scorer.score(f)
                if f.score >= 10 or f.severity != "INFO":
                    findings.append(f)
    return findings, rels, examined
