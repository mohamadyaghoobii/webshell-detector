"""Shared helpers for the test-suite.

All "malicious" samples are synthetic and non-functional: every PHP sample
starts with an unconditional ``exit`` so it can never do anything even if it
were deployed, and dangerous identifiers are assembled from fragments so the
test sources themselves do not contain working one-liners.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.config import DEFAULT_CONFIG  # noqa: E402
from scanner.engine import Scanner, ScanOptions  # noqa: E402

# Fragments (joined at run time)
SYS = "sys" + "tem"
SHELL_EXEC = "shell" + "_exec"
EVAL = "ev" + "al"
GET = "$_" + "GET"
POST = "$_" + "POST"
REQUEST = "$_" + "REQUEST"
COOKIE = "$_" + "COOKIE"
B64D = "base64" + "_decode"
GZI = "gz" + "inflate"
EXIT = "<?php exit('synthetic test sample - never executes'); ?>\n"


def php(body: str) -> str:
    """Wrap *body* as an inert PHP sample."""
    return EXIT + "<?php\n" + body + "\n"


def write(root: Path, rel: str, content: str | bytes, mode: int | None = None) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    if mode is not None:
        p.chmod(mode)
    return p


def config(**overrides) -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for key, value in overrides.items():
        section, _, name = key.partition("__")
        if name:
            cfg[section][name] = value
        else:
            cfg[section] = value
    return cfg


def scan(root: Path, cfg: dict | None = None, **opts):
    cfg = cfg or config()
    opts.setdefault("workers", 1)
    opts.setdefault("report_min_severity", "INFO")
    opts.setdefault("excludes", [".git/**"])
    result = Scanner(cfg, ScanOptions(roots=[root], **opts)).run()
    by_rel = {f.metadata.relpath: f for f in result.findings}
    return result, by_rel


def rules(finding) -> set[str]:
    return {i.rule_id for i in finding.indicators}


@pytest.fixture
def webroot(tmp_path: Path) -> Path:
    root = tmp_path / "html"
    root.mkdir()
    return root
