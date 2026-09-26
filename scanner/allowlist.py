"""Allowlisting for known-good files (false-positive handling).

Supported entries:

* ``paths``  - exact relative/absolute paths or ``**`` globs
* ``hashes`` - SHA256 of known-good files (strongest form of allowlisting)
* ``regex``  - regular expressions matched against the relative path
* ``vendor_dirs`` - globs for third-party code; findings there are only
  suppressed up to ``vendor_suppress_up_to`` (attackers hide in vendor/ too)

Hash IOC matches are never suppressed unless explicitly configured.
"""

from __future__ import annotations

import re
from typing import Any

from .models import SEVERITY_RANK, Finding
from .utils import glob_match


class Allowlist:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.mode = str(cfg.get("mode", "exclude")).lower()
        self.paths = [str(p) for p in cfg.get("paths") or []]
        self.hashes = {str(h).strip().lower() for h in cfg.get("hashes") or [] if str(h).strip()}
        self.regex = [re.compile(r) for r in cfg.get("regex") or []]
        self.vendor = [str(p) for p in cfg.get("vendor_dirs") or []]
        self.vendor_max = str(cfg.get("vendor_suppress_up_to", "LOW")).upper()
        self.never_ioc = bool(cfg.get("never_suppress_ioc_hash", True))

    def match(self, finding: Finding) -> str | None:
        """Return the allowlist reason for *finding*, or None."""
        md = finding.metadata
        if self.never_ioc and finding.has_rule("ioc.hash"):
            return None
        if md.sha256 and md.sha256.lower() in self.hashes:
            return f"SHA256 allowlisted ({md.sha256[:16]}...)"
        for p in self.paths:
            if p == md.path or p == md.relpath or glob_match(md.relpath, p) or glob_match(md.path.lstrip("/"), p.lstrip("/")):
                return f"path allowlisted ({p})"
        for rx in self.regex:
            if rx.search(md.relpath):
                return f"regex allowlisted ({rx.pattern})"
        for p in self.vendor:
            if glob_match(md.relpath, p) or glob_match("/" + md.relpath, "**/" + p):
                if SEVERITY_RANK[finding.severity] <= SEVERITY_RANK.get(self.vendor_max, 1):
                    return f"vendor directory ({p}) with severity <= {self.vendor_max}"
        return None
