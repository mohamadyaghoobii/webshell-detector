"""Scan orchestration.

Pipeline per root::

    walk (no symlink following) -> per-file static analysis (thread pool)
      -> baseline / git / owner / deployment-time context
      -> scoring -> persistence + config hunting -> referenced files
      -> cross-reference correlation -> chains -> allowlist -> report filter
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import stat
import time
from collections import Counter
import multiprocessing
from concurrent.futures import (FIRST_COMPLETED, Executor, Future, ProcessPoolExecutor,
                                ThreadPoolExecutor, wait)
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator

from . import __version__
from .allowlist import Allowlist
from .analyzer import ContentAnalyzer, ContentResult, FileContext
from .archives import inspect_archive, is_archive
from .baseline import compare_entries, entry_from_stat, load_baseline
from .correlation import build_chains, correlate, dedupe
from .filesystem import (Entry, analyze_symlink, detect_frameworks, framework_context,
                         root_owner_home, upload_context, walk)
from .gitstate import GitState, load_git_state
from .iocs import extract_iocs
from .metadata import (MEDIA_EXT, PHP_EXT, FileChangedError, collect_metadata, read_file,
                       read_tail)
from .models import (SEVERITY_RANK, Evidence, Finding, Indicator, Relationship,
                     ScanResult, Strength)
from .persistence import PersistenceHunter
from .scoring import Scorer
from .utils import now_iso
from .webserver import scan_webserver_configs
from .yara_engine import YaraEngine

log = logging.getLogger(__name__)

WEB_USERS = {"www-data", "apache", "nginx", "httpd", "nobody", "www", "wwwrun", "http", "daemon"}


@dataclass
class ScanOptions:
    roots: list[Path]
    baseline: Path | None = None
    baseline_doc: dict[str, Any] | None = None      # in-memory baseline (compare mode)
    hashes: dict[str, str] = field(default_factory=dict)
    yara_rules: str | None = None
    after: datetime | None = None
    before: datetime | None = None
    time_field: str = "mtime"
    persistence: bool = False
    webserver: bool = False
    git: bool = False
    archives: bool = False
    workers: int = 8
    max_size: int = 20 * 1024 * 1024
    report_min_severity: str = "LOW"
    show_allowlisted: bool = False
    excludes: list[str] = field(default_factory=list)
    all_hashes: bool = False
    keep_all: bool = False          # keep every analysed file (investigate/compare)
    persistence_host: bool = True
    executor: str = "process"       # process | thread


@dataclass
class Outcome:
    finding: Finding | None
    entry_rel: str | None = None
    entry: dict[str, Any] | None = None
    ctime: float | None = None
    is_script: bool = False
    is_php: bool = False
    skipped: str | None = None
    error: str | None = None
    bytes_read: int = 0
    text: str | None = None
    archive_findings: list[Finding] = field(default_factory=list)
    archive_scanned: bool = False
    rels: list[Relationship] = field(default_factory=list)
    yara_hits: int = 0
    ioc_hit: bool = False
    filtered: bool = False


def _batches(items: Iterable[Any], size: int) -> Iterator[list[Any]]:
    batch: list[Any] = []
    for it in items:
        batch.append(it)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def bounded_map(fn: Callable[[list[Any]], list[Any]], items: Iterable[Any], executor: Executor | None,
                window: int = 64, batch: int = 32) -> Iterator[Any]:
    """Apply a *batch* function with a bounded number of in-flight batches."""
    if executor is None:
        for b in _batches(items, batch):
            yield from fn(b)
        return
    pending: set[Future] = set()
    for b in _batches(items, batch):
        pending.add(executor.submit(fn, b))
        if len(pending) >= window:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for d in done:
                yield from d.result()
    for d in pending:
        yield from d.result()


# --------------------------------------------------------- process workers
# Static analysis is CPU-bound (regex + lexing), so the default executor is a
# process pool; each worker builds its own Scanner once in the initializer.
_WORKER: dict[str, Any] = {}


def _worker_init(cfg: dict[str, Any], opts: "ScanOptions", root: Path, frameworks: dict[str, list[str]],
                 git_state: GitState | None, home: str | None) -> None:
    scanner = Scanner(cfg, opts)
    scanner._load_yara()
    _WORKER.update(scanner=scanner, root=root, frameworks=frameworks, git=git_state, home=home)


def _worker_batch(entries: list[Entry]) -> list["Outcome"]:
    w = _WORKER
    return [w["scanner"].safe_analyze(e, w["root"], w["frameworks"], w["git"], w["home"]) for e in entries]


class Scanner:
    def __init__(self, cfg: dict[str, Any], opts: ScanOptions) -> None:
        self.cfg = cfg
        self.opts = opts
        self.analyzer = ContentAnalyzer(cfg)
        self.scorer = Scorer(cfg)
        self.allowlist = Allowlist(cfg.get("allowlist", {}))
        self.yara: YaraEngine | None = None
        self.result = ScanResult(mode="scan", roots=[str(r) for r in opts.roots], started=now_iso(),
                                 tool_version=__version__, hostname=socket.gethostname())
        self._tags: dict[int, set[str]] = {}
        self._texts: dict[int, str] = {}
        self.all_findings: list[Finding] = []
        self.relationships: list[Relationship] = []
        a = cfg["archives"]
        self.arch_limits = (int(a["max_members"]), int(a["max_member_size_mb"]) * 1024 * 1024,
                            int(a["max_total_mb"]) * 1024 * 1024, int(a["max_ratio"]))

    # ================================================================ public
    def run(self) -> ScanResult:
        t0 = time.monotonic()
        self._load_yara()
        for root in self.opts.roots:
            self._scan_root(root)
        self._host_checks()
        self._referenced_files()
        correlate(self.all_findings, dedupe(self.relationships), self.scorer, self._tags)
        self.result.relationships = dedupe(self.relationships)
        self.result.chains = build_chains(self.all_findings, self.result.relationships)
        self._finalize()
        self.result.stats.duration_seconds = round(time.monotonic() - t0, 2)
        self.result.finished = now_iso()
        return self.result

    # =============================================================== setup
    def _load_yara(self) -> None:
        if not self.opts.yara_rules:
            return
        try:
            self.yara = YaraEngine(self.opts.yara_rules, int(self.cfg["yara"].get("timeout", 30)))
            log.info("YARA rules loaded from %s", self.opts.yara_rules)
        except Exception as exc:  # missing module or compile error must not stop the scan
            msg = f"YARA disabled: {exc}"
            self.result.warnings.append(msg)
            log.warning(msg)

    # ================================================================ root
    def _scan_root(self, root: Path) -> None:
        stats = self.result.stats
        frameworks = detect_frameworks(root)
        if frameworks:
            self.result.frameworks[str(root)] = [f"{k}:{'/'.join(v) or '.'}" for k, v in frameworks.items()]
        git_state: GitState | None = None
        if self.opts.git:
            try:
                git_state = load_git_state(root)
                if git_state is None:
                    self.result.warnings.append(f"--git: no git repository found for {root}")
            except Exception as exc:
                self.result.warnings.append(f"--git disabled for {root}: {exc}")
        baseline_doc = self.opts.baseline_doc
        if baseline_doc is None and self.opts.baseline:
            baseline_doc = load_baseline(self.opts.baseline)
            if not baseline_doc.get("_integrity_ok"):
                self.result.warnings.append("Baseline integrity digest mismatch - the baseline file may "
                                            "have been modified after creation")
            if os.path.realpath(baseline_doc.get("root", "")) != os.path.realpath(root):
                self.result.warnings.append(
                    f"Baseline was created for {baseline_doc.get('root')} but scanning {root}; "
                    "comparing by relative path")
        home = root_owner_home(root)

        def on_error(p: str, exc: OSError) -> None:
            stats.errors += 1
            self.result.errors.append(f"{p}: {exc.strerror or exc}")

        def on_excluded(rel: str) -> None:
            stats.excluded += 1

        root_findings: list[Finding] = []
        entries: dict[str, dict[str, Any]] = {}
        ctimes: list[float] = []
        script_owner: Counter[tuple[int | None, int | None]] = Counter()

        dir_counts: dict[str, list[int]] = {}

        def work(batch: list[Entry]) -> list[Outcome]:
            return [self.safe_analyze(e, root, frameworks, git_state, home) for e in batch]

        executor = self._make_executor(root, frameworks, git_state, home)
        fn = _worker_batch if isinstance(executor, ProcessPoolExecutor) else work
        try:
            outcomes = list(bounded_map(fn, walk(root, self.opts.excludes, on_error, on_excluded), executor))
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
        for out in outcomes:
            stats.files_seen += 1
            stats.bytes_read += out.bytes_read
            if out.error:
                stats.errors += 1
                self.result.errors.append(out.error)
            if out.skipped:
                stats.skip(out.skipped)
            if out.filtered:
                stats.filtered_by_time += 1
            if out.entry_rel is not None and out.entry is not None:
                entries[out.entry_rel] = out.entry
            if out.ctime is not None:
                ctimes.append(out.ctime)
            if out.archive_scanned:
                stats.archives_scanned += 1
                stats.archive_members_scanned += len(out.archive_findings)
            stats.yara_matches += out.yara_hits
            stats.ioc_hash_matches += int(out.ioc_hit)
            self.relationships.extend(out.rels)
            f = out.finding
            if f is None:
                continue
            if f.kind == "symlink":
                stats.symlinks += 1
            parent = os.path.dirname(f.metadata.path)
            counts = dir_counts.setdefault(parent, [0, 0])
            counts[0] += 1
            if out.is_script:
                counts[1] += 1
                stats.server_side_scripts += 1
                script_owner[(f.metadata.uid, f.metadata.gid)] += 1
            if out.is_php:
                stats.php_files += 1
            if out.is_script or f.indicators or self.opts.keep_all:
                f.root = str(root)
                root_findings.append(f)
                if out.text:
                    self._texts[id(f)] = out.text
                if out.is_script:
                    self._tags.setdefault(id(f), set()).add("script")
            for af in out.archive_findings:
                af.root = str(root)
                root_findings.append(af)

        self._code_directories(root_findings, dir_counts)
        if baseline_doc is not None:
            self._apply_baseline(root, baseline_doc, entries, root_findings)
        self._owner_anomalies(root_findings, script_owner)
        self._deployment_time(root_findings, ctimes)
        for f in root_findings:
            self.scorer.score(f, self._tags.get(id(f)))
        self.all_findings.extend(root_findings)

    def _make_executor(self, root: Path, frameworks: dict[str, list[str]], git_state: GitState | None,
                       home: str | None) -> Executor | None:
        if self.opts.workers <= 1:
            return None
        if self.opts.executor == "process":
            try:
                ctx = multiprocessing.get_context("fork")
                return ProcessPoolExecutor(max_workers=self.opts.workers, mp_context=ctx,
                                           initializer=_worker_init,
                                           initargs=(self.cfg, self.opts, root, frameworks, git_state, home))
            except (ValueError, OSError) as exc:
                log.info("process pool unavailable (%s); using threads", exc)
        return ThreadPoolExecutor(max_workers=self.opts.workers)

    def _code_directories(self, findings: list[Finding], dir_counts: dict[str, list[int]]) -> None:
        """Directories dominated by scripts are source trees, not upload folders."""
        for f in findings:
            for ind in f.indicators:
                if ind.rule_id not in ("location.upload_dir", "location.weak_upload_dir"):
                    continue
                total, scripts = dir_counts.get(os.path.dirname(f.metadata.path), [0, 0])
                if scripts >= 5 and scripts / max(total, 1) >= 0.5:
                    ind.weight = 2
                    ind.strength = Strength.WEAK
                    ind.tags = frozenset()
                    ind.min_severity = None
                    ind.description += f" - but the directory mostly holds code ({scripts}/{total} scripts)"

    # ============================================================ per entry
    def safe_analyze(self, e: Entry, root: Path, frameworks: dict[str, list[str]],
                     git_state: GitState | None, home: str | None) -> Outcome:
        try:
            return self.analyze_entry(e, root, frameworks, git_state, home)
        except Exception as exc:  # never let one hostile file stop the scan
            log.debug("analysis failed for %s", e.path, exc_info=True)
            return Outcome(None, error=f"{e.path}: analysis error: {exc}")

    def analyze_entry(self, e: Entry, root: Path, frameworks: dict[str, list[str]],
                      git_state: GitState | None, home: str | None, kind: str = "webshell") -> Outcome:
        md = collect_metadata(e.path, root, e.st)
        rel = md.relpath
        if e.kind == "symlink":
            f = Finding(kind="symlink", metadata=md)
            for ind in analyze_symlink(e.path, root, md.link_target, home):
                f.add(ind)
            return Outcome(f, rel, entry_from_stat(e.st, None, md.link_target))
        if e.kind == "other":
            f = Finding(kind="webshell", metadata=md)
            f.add(Indicator("meta.special_file", "metadata",
                            f"Special file ({md.permissions}) inside a web directory", 6, Strength.WEAK))
            return Outcome(f, rel, entry_from_stat(e.st, None))

        f = Finding(kind=kind, metadata=md)
        out = Outcome(f, rel, None, ctime=e.st.st_ctime)
        self._metadata_indicators(f, e)

        in_window = self._in_time_window(e.st)
        need_hash_only = not in_window
        if need_hash_only:
            out.filtered = True
            if not (self.opts.baseline or self.opts.hashes):
                out.entry = entry_from_stat(e.st, None)
                out.finding = None if not f.indicators else f
                return out

        archive = is_archive(e.path.name)
        media = md.extension in MEDIA_EXT
        keep = 0 if need_hash_only else (min(self.opts.max_size, 64 * 1024) if archive else self.opts.max_size)
        try:
            r = read_file(e.path, keep, e.st, all_hashes=self.opts.all_hashes)
        except FileChangedError as exc:
            out.error = f"{e.path}: {exc}"
            f.errors.append(str(exc))
            f.add(Indicator("meta.changed_during_scan", "metadata", f"File changed during the scan ({exc})",
                            3, Strength.WEAK))
            return out
        except OSError as exc:
            out.skipped = "unreadable"
            out.error = f"{e.path}: {exc.strerror or exc}"
            f.errors.append(f"read error: {exc.strerror or exc}")
            return out
        out.bytes_read = r.size
        md.sha256, md.sha1, md.md5 = r.sha256, r.sha1, r.md5
        out.entry = entry_from_stat(e.st, r.sha256)
        self._fs_flag_indicators(f, r.fs_flags)
        if r.sha256 in self.opts.hashes:
            out.ioc_hit = True
            f.add(Indicator("ioc.hash", "ioc_hash",
                            f"SHA256 matches a known-bad hash (IOC list: {self.opts.hashes[r.sha256]})",
                            100, Strength.DEFINITIVE, [Evidence(None, r.sha256)], min_severity="CRITICAL"))
        if need_hash_only:
            out.finding = f if f.indicators else None
            return out

        upload_level, upload_comp = upload_context(rel, self.cfg)
        ctx = FileContext(e.path, rel, root, upload_level, upload_comp, framework_context(rel, frameworks))
        if archive:
            if self.opts.archives:
                self._scan_archive(e, ctx, f, out)
            else:
                out.skipped = "archive (enable --scan-archives)"
            return out

        tail = None
        if r.size > self.opts.max_size:
            f.notes.append(f"Only the first {self.opts.max_size} bytes were analysed (file is {r.size} bytes)")
            out.skipped = "partially analysed (size limit)"
            if media:
                try:
                    tail = read_tail(e.path, int(self.cfg["scanner"].get("media_tail_check_bytes", 262144)), e.st)
                except (OSError, FileChangedError):
                    tail = None
        cr = self.analyzer.analyze(r.data, ctx, truncated=r.size > self.opts.max_size, tail=tail)
        self._apply_content(f, cr)
        out.is_script = cr.is_script
        out.is_php = cr.language == "php" or md.extension in PHP_EXT
        out.text = cr.text_for_iocs
        out.rels.extend(cr.relationships)
        if self.yara is not None:
            hits = self.yara.match(r.data)
            out.yara_hits = len(hits)
            for h in hits:
                f.add(h)
        if git_state is not None:
            status = git_state.status(str(e.path), r.data if r.size <= self.opts.max_size else None)
            f.git_status = status
            self._git_indicators(f, status, cr.is_script)
        return out

    def _apply_content(self, f: Finding, cr: ContentResult) -> None:
        f.language = cr.language
        f.metadata.content_type = cr.content_type
        f.metadata.is_binary = cr.is_binary
        f.metadata.entropy = cr.entropy
        for ind in cr.indicators:
            f.add(ind)

    def _metadata_indicators(self, f: Finding, e: Entry) -> None:
        mode = e.st.st_mode
        script_ext = f.metadata.extension in PHP_EXT or f.metadata.extension in (".jsp", ".asp", ".aspx", ".cgi", ".pl", ".py")
        if mode & stat.S_IWOTH:
            f.add(Indicator("meta.world_writable", "metadata",
                            f"World-writable file ({f.metadata.permissions})",
                            10 if script_ext else 2, Strength.MODERATE if script_ext else Strength.WEAK,
                            tags=frozenset({"meta:writable"})))
        if mode & (stat.S_ISUID | stat.S_ISGID):
            f.add(Indicator("meta.setuid", "metadata", f"setuid/setgid bit set ({f.metadata.permissions})",
                            15, Strength.STRONG))
        if script_ext:
            try:
                pst = os.lstat(e.path.parent)
                if pst.st_mode & stat.S_IWOTH and not pst.st_mode & stat.S_ISVTX:
                    f.add(Indicator("meta.parent_world_writable", "metadata",
                                    "Script lives in a world-writable directory (anyone can replace it)",
                                    3, Strength.WEAK))
            except OSError:
                pass

    def _fs_flag_indicators(self, f: Finding, flags: list[str]) -> None:
        f.metadata.fs_flags = flags
        if "immutable" in flags:
            f.add(Indicator("meta.immutable", "metadata",
                            "File has the immutable attribute (chattr +i): it cannot be modified or deleted, "
                            "even by root, until the flag is removed - a common anti-cleanup technique",
                            16, Strength.STRONG, tags=frozenset({"meta:immutable", "persistence"})))
        if "append-only" in flags:
            f.add(Indicator("meta.append_only", "metadata", "File has the append-only attribute (chattr +a)",
                            8, Strength.MODERATE))

    def _git_indicators(self, f: Finding, status: str | None, is_script: bool) -> None:
        if not is_script or status in (None, "tracked"):
            return
        if status == "untracked":
            f.add(Indicator("git.untracked_script", "git",
                            "Server-side script is not tracked by Git (not part of the deployed code)",
                            8, Strength.MODERATE, tags=frozenset({"git:untracked"})))
        elif status == "modified":
            f.add(Indicator("git.modified_script", "git",
                            "Tracked script differs from the Git index (modified after checkout)",
                            8, Strength.MODERATE, tags=frozenset({"git:modified"})))
        elif status == "ignored":
            f.add(Indicator("git.ignored_script", "git", "Server-side script is Git-ignored", 3, Strength.WEAK))

    def _in_time_window(self, st: os.stat_result) -> bool:
        if not (self.opts.after or self.opts.before):
            return True
        stamps = {"mtime": [st.st_mtime], "ctime": [st.st_ctime],
                  "either": [st.st_mtime, st.st_ctime]}[self.opts.time_field]
        for ts in stamps:
            if self.opts.after and ts < self.opts.after.timestamp():
                continue
            if self.opts.before and ts > self.opts.before.timestamp():
                continue
            return True
        return False

    # ============================================================ archives
    def _scan_archive(self, e: Entry, ctx: FileContext, f: Finding, out: Outcome) -> None:
        mm, msize, mtotal, ratio = self.arch_limits
        rep = inspect_archive(str(e.path), mm, msize, mtotal, ratio)
        out.archive_scanned = True
        for ind in rep.indicators:
            f.add(ind)
        f.errors.extend(rep.errors)
        f.notes.append(f"Archive inspected in memory: {rep.member_count} member(s)")
        for m in rep.members:
            if m.data is None:
                continue
            vrel = f"{ctx.relpath}!/{m.name}"
            md = collect_metadata(e.path, ctx.root or e.path.parent, e.st)
            md.path = f"{e.path}!/{m.name}"
            md.relpath = vrel
            md.file_type = "archive_member"
            md.size = m.size
            md.extension = PurePosixPath(m.name).suffix.lower()
            md.sha256 = hashlib.sha256(m.data).hexdigest()
            mctx = FileContext(Path(md.path), m.name, None, ctx.upload_level, ctx.upload_component, [],
                               in_archive=True)
            cr = self.analyzer.analyze(m.data, mctx)
            if not cr.indicators and md.sha256 not in self.opts.hashes:
                continue
            af = Finding(kind="archive_member", metadata=md)
            self._apply_content(af, cr)
            if md.sha256 in self.opts.hashes:
                af.add(Indicator("ioc.hash", "ioc_hash", "Archive member SHA256 matches a known-bad hash",
                                 100, Strength.DEFINITIVE, min_severity="CRITICAL"))
            if cr.text_for_iocs:
                self._texts[id(af)] = cr.text_for_iocs
            out.archive_findings.append(af)

    # ======================================================= post-processing
    def _apply_baseline(self, root: Path, doc: dict[str, Any], entries: dict[str, dict[str, Any]],
                        findings: list[Finding]) -> None:
        stats = self.result.stats
        old = doc["entries"]
        if self.opts.excludes:
            from .filesystem import is_excluded
            old = {k: v for k, v in old.items() if not is_excluded(k, self.opts.excludes)}
        changes = compare_entries(old, entries)
        self.result.baseline_changes.extend(changes)
        by_rel = {f.metadata.relpath: f for f in findings}
        for c in changes:
            if c.status == "NEW":
                stats.baseline_new += 1
            elif c.status == "MODIFIED":
                stats.baseline_modified += 1
            elif c.status == "DELETED":
                stats.baseline_deleted += 1
            elif c.status == "PERMISSION_CHANGED":
                stats.baseline_perm_changed += 1
            elif c.status == "OWNER_CHANGED":
                stats.baseline_owner_changed += 1
            f = by_rel.get(c.relpath)
            if f is None:
                continue
            f.baseline_status.append(c.status)
            script = "script" in self._tags.get(id(f), set())
            if c.status == "NEW":
                f.add(Indicator("baseline.new", "baseline",
                                "New file compared with the known-good baseline"
                                + (" (server-side script)" if script else ""),
                                10 if script else 3, Strength.MODERATE if script else Strength.WEAK,
                                tags=frozenset({"baseline:new"})))
            elif c.status == "MODIFIED":
                f.add(Indicator("baseline.modified", "baseline",
                                f"Content changed since the baseline ({c.detail})",
                                10 if script else 3, Strength.MODERATE if script else Strength.WEAK,
                                tags=frozenset({"baseline:modified"})))
            elif c.status == "PERMISSION_CHANGED":
                f.add(Indicator("baseline.permission_changed", "baseline",
                                f"Permissions changed since the baseline ({c.detail})", 4, Strength.WEAK))
            elif c.status == "OWNER_CHANGED":
                f.add(Indicator("baseline.owner_changed", "baseline",
                                f"Owner changed since the baseline ({c.detail})", 4, Strength.WEAK))
            elif c.status in ("TYPE_CHANGED", "SYMLINK_CHANGED"):
                f.add(Indicator("baseline.type_changed", "baseline",
                                f"File type or symlink target changed since the baseline ({c.detail})",
                                8, Strength.MODERATE))

    def _owner_anomalies(self, findings: list[Finding], owners: Counter) -> None:
        total = sum(owners.values())
        if total < 20:
            return
        (uid, gid), count = owners.most_common(1)[0]
        share = count / total
        if share < 0.8:
            return
        dominant = next((f for f in findings if (f.metadata.uid, f.metadata.gid) == (uid, gid)), None)
        dom_label = f"{dominant.metadata.owner or uid}:{dominant.metadata.group or gid}" if dominant else f"{uid}:{gid}"
        for f in findings:
            if "script" not in self._tags.get(id(f), set()):
                continue
            if (f.metadata.uid, f.metadata.gid) == (uid, gid):
                continue
            label = f"{f.metadata.owner or f.metadata.uid}:{f.metadata.group or f.metadata.gid}"
            f.add(Indicator("meta.owner_anomaly", "metadata",
                            f"Owner {label} differs from {share:.0%} of scripts in this tree ({dom_label})",
                            4, Strength.WEAK))
            if (f.metadata.owner or "") in WEB_USERS and (dominant is None or (dominant.metadata.owner or "") not in WEB_USERS):
                f.add(Indicator("meta.webserver_owned", "metadata",
                                f"Script owned by the web server account ({f.metadata.owner}) unlike the rest "
                                "of the code - consistent with being written by the web process", 4, Strength.WEAK))

    def _deployment_time(self, findings: list[Finding], ctimes: list[float]) -> None:
        """Flag scripts changed after the dominant (bulk deployment) ctime cluster."""
        if len(ctimes) < 50:
            return
        buckets = Counter(int(c // 3600) for c in ctimes)
        hour, count = buckets.most_common(1)[0]
        if count / len(ctimes) < 0.3:
            return
        deploy_end = (hour + 1) * 3600
        for f in findings:
            if "script" not in self._tags.get(id(f), set()) or f.metadata.ctime is None:
                continue
            if f.metadata.ctime > deploy_end + 3600:
                f.add(Indicator("timeline.after_deploy", "timeline",
                                "Script created/changed after the last bulk deployment "
                                f"(most files changed around {datetime.fromtimestamp(hour * 3600).isoformat(timespec='minutes')})",
                                5, Strength.WEAK, tags=frozenset({"after_deploy"})))

    # ============================================================ host checks
    def _host_checks(self) -> None:
        stats = self.result.stats
        if self.opts.persistence:
            hunter = PersistenceHunter(self.cfg, self.opts.roots, self.scorer, self.opts.persistence_host)
            pres = hunter.run()
            self.all_findings.extend(pres.findings)
            self.relationships.extend(pres.relationships)
            self.result.errors.extend(pres.errors[:200])
            stats.persistence_indicators += len([f for f in pres.findings if f.kind == "persistence"])
            stats.config_indicators += len([f for f in pres.findings if f.kind == "config"])
        if self.opts.webserver:
            errs: list[str] = []
            wf, rels, _ = scan_webserver_configs(self.cfg, self.scorer, errs)
            self.all_findings.extend(wf)
            self.relationships.extend(rels)
            self.result.errors.extend(errs[:200])
            stats.config_indicators += len(wf)

    def _referenced_files(self) -> None:
        """Statically analyse files referenced by configs/persistence outside the roots."""
        known = {os.path.realpath(f.metadata.path) for f in self.all_findings}
        seen: set[str] = set()
        for r in list(self.relationships):
            if r.source_kind == "file":
                continue
            target = os.path.normpath(r.target)
            real = os.path.realpath(target)
            if real in known or real in seen:
                continue
            seen.add(real)
            try:
                st = os.lstat(target)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > self.opts.max_size:
                continue
            if target.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/")):
                continue
            parent = Path(target).parent
            out = self.analyze_entry(Entry(Path(target), st, "file"), parent, {}, None, None,
                                     kind="referenced_file")
            f = out.finding
            if f is None:
                continue
            f.metadata.relpath = target
            f.notes.append(f"Analysed because it is referenced by {r.source} ({r.relation})")
            tags = {"script"} if out.is_script else set()
            self._tags[id(f)] = tags
            if out.text:
                self._texts[id(f)] = out.text
            self.scorer.score(f, tags)
            self.all_findings.append(f)
            known.add(real)

    # ============================================================== finalize
    def _finalize(self) -> None:
        stats = self.result.stats
        min_rank = SEVERITY_RANK[self.opts.report_min_severity]
        ioc_cfg = self.cfg["iocs"]
        ioc_rank = SEVERITY_RANK[str(ioc_cfg.get("min_severity", "MEDIUM")).upper()]
        reported: list[Finding] = []
        for f in self.all_findings:
            reason = self.allowlist.match(f)
            if reason:
                f.allowlisted = True
                f.allowlist_reason = reason
                if SEVERITY_RANK[f.severity] >= min_rank:
                    stats.allowlisted += 1
                if self.allowlist.mode != "mark" and not self.opts.show_allowlisted:
                    continue
            if SEVERITY_RANK[f.severity] < min_rank and not self.opts.keep_all:
                continue
            if ioc_cfg.get("enabled", True) and SEVERITY_RANK[f.severity] >= ioc_rank:
                text = self._texts.get(id(f))
                if text:
                    f.iocs = extract_iocs(text, ioc_cfg.get("ignore_domains"), int(ioc_cfg.get("max_per_type", 50)))
            reported.append(f)
        reported.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -f.score, f.metadata.path))
        self.result.findings = reported
        self._texts.clear()
