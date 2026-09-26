"""Filesystem walking, exclusions, location context and symlink analysis."""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator

from .models import Evidence, Indicator, Strength
from .utils import glob_match, is_within, safe_relpath

log = logging.getLogger(__name__)

TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
SENSITIVE_TARGETS = ("/etc", "/root", "/proc", "/boot", "/var/lib/mysql", "/var/log")


@dataclass
class Entry:
    path: Path
    st: os.stat_result
    kind: str          # file | symlink | other


def walk(root: Path, excludes: list[str], on_error: Callable[[str, OSError], None],
         on_excluded: Callable[[str], None] | None = None) -> Iterator[Entry]:
    """Iteratively walk *root* without following symlinks.

    Symlinks (to files *and* directories) are yielded as entries so they can
    be analysed; they are never descended into.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError as exc:
            on_error(str(current), exc)
            continue
        with it:
            entries = []
            for de in it:
                entries.append(de)
        entries.sort(key=lambda d: d.name)
        for de in entries:
            p = Path(de.path)
            rel = safe_relpath(p, root)
            try:
                st = os.lstat(p)
            except OSError as exc:
                on_error(str(p), exc)
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            if excludes and is_excluded(rel, excludes, is_dir):
                if on_excluded:
                    on_excluded(rel)
                continue
            if stat.S_ISLNK(st.st_mode):
                yield Entry(p, st, "symlink")
            elif is_dir:
                stack.append(p)
            elif stat.S_ISREG(st.st_mode):
                yield Entry(p, st, "file")
            else:
                yield Entry(p, st, "other")


def is_excluded(relpath: str, patterns: list[str], is_dir: bool = False) -> bool:
    """Match against exclude globs. Directory patterns like ``vendor/**``
    also exclude the directory itself so it is never descended into."""
    for pat in patterns:
        if glob_match(relpath, pat):
            return True
        if is_dir and pat.endswith("/**") and glob_match(relpath, pat[:-3]):
            return True
        if is_dir and pat.endswith("/**") and glob_match(relpath + "/x", pat):
            return True
    return False


# ------------------------------------------------------------------ location

def dir_components(relpath: str) -> list[str]:
    parts = PurePosixPath(relpath).parts
    return [p.lower() for p in parts[:-1]]


def upload_context(relpath: str, cfg: dict) -> tuple[str | None, str | None]:
    """Return ('strong'|'weak', component) when the file lives in a user-content dir."""
    ud = cfg["upload_dirs"]
    if any(glob_match(relpath, g) for g in ud.get("benign_generated", [])):
        return None, None
    strong = set(ud["strong"])
    weak = set(ud["weak"])
    # Case matters: upload directories are conventionally lower-case, while
    # CamelCase components (src/Illuminate/Image/) are code namespaces.
    raw = list(PurePosixPath(relpath).parts[:-1])
    for c in raw:
        low = c.lower()
        if (low in strong or low.startswith("upload")) and c == low:
            return "strong", c
    for c in raw:
        if c.lower() in weak and c == c.lower():
            return "weak", c
    return None, None


FRAMEWORK_MARKERS = {
    "wordpress": ["wp-config.php", "wp-includes/version.php", "wp-login.php"],
    "laravel": ["artisan", "bootstrap/app.php"],
    "drupal": ["core/lib/Drupal.php", "sites/default"],
    "joomla": ["administrator/index.php", "libraries/src"],
    "magento": ["app/etc/env.php", "bin/magento"],
    "symfony": ["bin/console", "config/bundles.php"],
}


def detect_frameworks(root: Path, max_depth: int = 2) -> dict[str, list[str]]:
    """Find framework installations at or just below *root* (relative bases)."""
    found: dict[str, list[str]] = {}
    candidates = [root]
    frontier = [root]
    for _ in range(max_depth):
        nxt = []
        for d in frontier:
            try:
                for de in os.scandir(d):
                    if de.is_dir(follow_symlinks=False) and not de.name.startswith(".") \
                            and de.name not in ("node_modules", "vendor"):
                        nxt.append(Path(de.path))
            except OSError:
                continue
        candidates.extend(nxt[:200])
        frontier = nxt[:200]
    for base in candidates:
        for name, markers in FRAMEWORK_MARKERS.items():
            hits = sum(1 for m in markers if (base / m).exists())
            if hits >= (1 if name == "wordpress" and (base / "wp-includes").is_dir() else 2) or \
                    (name == "wordpress" and (base / "wp-includes" / "version.php").exists()):
                rel = safe_relpath(base, root)
                rel = "" if rel == "." else rel
                found.setdefault(name, [])
                if rel not in found[name]:
                    found[name].append(rel)
    return found


def framework_context(relpath: str, frameworks: dict[str, list[str]]) -> list[str]:
    """Labels such as 'wordpress:uploads' for a file's framework location."""
    labels = []
    for name, bases in frameworks.items():
        for base in bases:
            prefix = (base + "/") if base else ""
            if prefix and not relpath.startswith(prefix):
                continue
            sub = relpath[len(prefix):]
            if name == "wordpress":
                if sub.startswith("wp-content/uploads/"):
                    labels.append("wordpress:uploads")
                elif sub.startswith("wp-content/mu-plugins/"):
                    labels.append("wordpress:mu-plugins")
                elif sub.startswith(("wp-includes/", "wp-admin/")):
                    labels.append("wordpress:core")
                elif sub.startswith("wp-content/languages/") or sub.startswith("wp-content/upgrade/"):
                    labels.append("wordpress:data")
            elif name == "laravel":
                if sub.startswith(("storage/app/public/", "public/storage/", "public/uploads/")):
                    labels.append("laravel:public-storage")
                elif sub.startswith(("bootstrap/cache/", "storage/framework/")):
                    labels.append("laravel:generated")
                elif sub.startswith("vendor/"):
                    labels.append("laravel:vendor")
            elif name == "drupal" and "/files/" in "/" + sub:
                labels.append("drupal:files")
            elif name == "joomla" and sub.startswith(("images/", "media/", "tmp/")):
                labels.append("joomla:user-content")
            elif name == "magento" and sub.startswith(("pub/media/", "media/")):
                labels.append("magento:media")
    return labels


# ------------------------------------------------------------------ symlinks

def analyze_symlink(path: Path, root: Path, link_target: str | None,
                    root_owner_home: str | None = None) -> list[Indicator]:
    """Indicators for a symlink. Containment uses commonpath, not prefixes."""
    out: list[Indicator] = []
    raw = link_target or "?"
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        resolved = None
    exists = os.path.exists(path)
    ev = [Evidence(line=None, snippet=f"{path.name} -> {raw}")]
    root_real = os.path.realpath(root)
    if not exists:
        out.append(Indicator("symlink.broken", "metadata", f"Broken symlink (-> {raw})",
                             4, Strength.WEAK, ev))
    if resolved is None:
        return out
    if is_within(resolved, root_real):
        return out
    # Laravel's "php artisan storage:link" creates public/storage -> storage/app/public
    if path.name == "storage" and resolved.rstrip("/").endswith("storage/app/public"):
        out.append(Indicator("symlink.laravel_storage", "metadata",
                             "Laravel storage link points outside the scanned directory (usually benign)",
                             1, Strength.WEAK, ev))
        return out
    out.append(Indicator("symlink.outside_root", "location",
                         f"Symlink points outside the web root -> {resolved}", 8, Strength.MODERATE, ev,
                         tags=frozenset({"symlink:outside"})))
    if any(is_within(resolved, t) for t in TEMP_DIRS):
        out.append(Indicator("symlink.to_temp", "location",
                             f"Symlink points into a world-writable temp directory ({resolved})",
                             16, Strength.STRONG, ev, min_severity="MEDIUM",
                             tags=frozenset({"symlink:temp"})))
    if resolved == "/" or any(is_within(resolved, t) for t in SENSITIVE_TARGETS):
        out.append(Indicator("symlink.to_sensitive", "location",
                             f"Symlink exposes a sensitive system location ({resolved})",
                             18, Strength.STRONG, ev, min_severity="MEDIUM"))
    parts = Path(resolved).parts
    if len(parts) >= 3 and parts[1] == "home":
        other_home = f"/home/{parts[2]}"
        if not is_within(root_real, other_home) and other_home != root_owner_home:
            out.append(Indicator("symlink.other_home", "location",
                                 f"Symlink points into another user's home directory ({other_home})",
                                 12, Strength.MODERATE, ev))
        if resolved.endswith(("wp-config.php", "configuration.php", ".env", "config.php", "settings.php")):
            out.append(Indicator("symlink.config_read", "location",
                                 "Symlink to another site's configuration file (credential theft pattern)",
                                 20, Strength.STRONG, ev, min_severity="HIGH"))
    if any(seg.startswith(".") and seg not in (".", "..") for seg in parts[1:]):
        out.append(Indicator("symlink.hidden_target", "location",
                             "Symlink points to a hidden path", 4, Strength.WEAK, ev))
    return out


def root_owner_home(root: Path) -> str | None:
    parts = Path(os.path.realpath(root)).parts
    if len(parts) >= 3 and parts[1] == "home":
        return f"/home/{parts[2]}"
    return None


def relpath_or_abs(path: str, root: Path) -> str:
    return safe_relpath(path, root)
