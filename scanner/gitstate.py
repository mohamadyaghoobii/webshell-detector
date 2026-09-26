"""Git awareness without running repository-controlled code.

Only ``git ls-files`` is invoked, with a hardened environment:

* system/global config ignored, hooks path set to /dev/null,
* ``core.fsmonitor`` disabled (a malicious repo config could otherwise
  name a program to execute), no optional locks, no pager, no prompts.

"Modified" is determined by hashing file content ourselves (git blob SHA-1)
and comparing it with the index, instead of ``git status`` - that avoids
clean/smudge filters defined by the repository.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class GitState:
    top: Path
    tracked: dict[str, str] = field(default_factory=dict)     # repo-relative path -> blob sha1
    untracked: set[str] = field(default_factory=set)
    untracked_dirs: list[str] = field(default_factory=list)
    ignored: set[str] = field(default_factory=set)
    ignored_dirs: list[str] = field(default_factory=list)

    def status(self, abs_path: str, content: bytes | None) -> str | None:
        try:
            rel = os.path.relpath(abs_path, self.top).replace(os.sep, "/")
        except ValueError:
            return None
        if rel.startswith("../"):
            return None
        if rel in self.tracked:
            if content is None:
                return "tracked"
            blob = blob_sha1(content)
            if blob == self.tracked[rel]:
                return "tracked"
            if b"\r\n" in content and blob_sha1(content.replace(b"\r\n", b"\n")) == self.tracked[rel]:
                return "tracked"
            return "modified"
        if rel in self.ignored or any(rel.startswith(d) for d in self.ignored_dirs):
            return "ignored"
        if rel in self.untracked or any(rel.startswith(d) for d in self.untracked_dirs):
            return "untracked"
        return "untracked"


def blob_sha1(content: bytes) -> str:
    h = hashlib.sha1(usedforsecurity=False)
    h.update(b"blob %d\x00" % len(content))
    h.update(content)
    return h.hexdigest()


def find_repo_top(start: Path) -> Path | None:
    cur = start.resolve()
    for p in [cur, *cur.parents]:
        if (p / ".git").exists():
            return p
    return None


def _git(top: Path, *args: str, timeout: int = 300) -> bytes:
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git executable not found")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "HOME": os.devnull,
        "LC_ALL": "C",
    }
    cmd = [git, "--no-pager", "-C", str(top),
           "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
           "-c", f"safe.directory={top}", "-c", "core.untrackedCache=false",
           "-c", "core.quotePath=false", *args]
    proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip()[:500])
    return proc.stdout


def load_git_state(root: Path) -> GitState | None:
    """Read index and untracked/ignored listings for the repo containing *root*."""
    top = find_repo_top(root)
    if top is None:
        return None
    state = GitState(top=top)
    out = _git(top, "ls-files", "-z", "--stage", "--full-name")
    for rec in out.split(b"\x00"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        parts = meta.split()
        if len(parts) >= 2 and parts[0] != b"120000" and parts[0] != b"160000":
            state.tracked[path.decode("utf-8", "surrogateescape")] = parts[1].decode()
    for rec in _git(top, "ls-files", "-z", "--others", "--exclude-standard", "--directory",
                    "--full-name").split(b"\x00"):
        if rec:
            p = rec.decode("utf-8", "surrogateescape")
            (state.untracked_dirs.append(p) if p.endswith("/") else state.untracked.add(p))
    for rec in _git(top, "ls-files", "-z", "--others", "--ignored", "--exclude-standard",
                    "--directory", "--full-name").split(b"\x00"):
        if rec:
            p = rec.decode("utf-8", "surrogateescape")
            (state.ignored_dirs.append(p) if p.endswith("/") else state.ignored.add(p))
    return state
