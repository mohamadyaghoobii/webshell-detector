"""Data model shared by all scanner components."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Strength(IntEnum):
    """How much a single indicator says about maliciousness on its own."""

    WEAK = 1          # common in legitimate code (e.g. base64_decode())
    MODERATE = 2      # unusual; worth a look (e.g. PHP inside uploads/)
    STRONG = 3        # rarely legitimate (e.g. eval(gzinflate(base64_decode(...))))
    DEFINITIVE = 4    # practically never legitimate (e.g. system($_GET[...]), IOC hash)


SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
CONFIDENCES = ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]


def max_severity(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


@dataclass
class Evidence:
    """A small, sanitised excerpt supporting an indicator."""

    line: int | None
    snippet: str
    source: str | None = None   # e.g. "decoded layer 1" or a config path

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Indicator:
    """One explainable detection signal."""

    rule_id: str
    category: str
    description: str
    weight: int
    strength: Strength = Strength.WEAK
    evidence: list[Evidence] = field(default_factory=list)
    occurrences: int = 1
    min_severity: str | None = None
    tags: frozenset[str] = frozenset()
    effective_weight: int | None = None   # after category capping

    def to_dict(self, with_evidence: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "category": self.category,
            "description": self.description,
            "weight": self.weight,
            "effective_weight": self.effective_weight,
            "strength": self.strength.name,
            "occurrences": self.occurrences,
        }
        if self.min_severity:
            d["min_severity"] = self.min_severity
        if with_evidence and self.evidence:
            d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass
class FileMetadata:
    path: str
    relpath: str
    realpath: str | None = None
    file_type: str = "file"          # file | symlink | dir | other | archive_member
    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    owner: str | None = None
    group: str | None = None
    mode: str | None = None          # octal, e.g. "0644"
    permissions: str | None = None   # e.g. "-rw-r--r--"
    mtime: float | None = None
    ctime: float | None = None
    atime: float | None = None
    inode: int | None = None
    device: int | None = None
    nlink: int | None = None
    extension: str = ""
    content_type: str | None = None
    is_binary: bool | None = None
    entropy: float | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    link_target: str | None = None
    fs_flags: list[str] = field(default_factory=list)   # immutable, append-only

    def to_dict(self) -> dict[str, Any]:
        from .utils import ts_to_iso

        d = asdict(self)
        d["mtime_iso"] = ts_to_iso(self.mtime)
        d["ctime_iso"] = ts_to_iso(self.ctime)
        d["atime_iso"] = ts_to_iso(self.atime)
        if self.entropy is not None:
            d["entropy"] = round(self.entropy, 3)
        return {k: v for k, v in d.items() if v not in (None, [], "")}


@dataclass
class Relationship:
    """A static, evidence-backed link between two filesystem objects."""

    source: str
    target: str
    relation: str
    evidence: Evidence | None = None
    source_kind: str = "file"        # file | config | persistence | webserver
    target_exists: bool | None = None

    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.relation)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "source_kind": self.source_kind,
            "target_exists": self.target_exists,
        }
        if self.evidence:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class Finding:
    """A scored, explainable result for one object (file, config, cron job...)."""

    kind: str                              # webshell | persistence | config | symlink | archive_member | referenced_file
    metadata: FileMetadata
    indicators: list[Indicator] = field(default_factory=list)
    score: int = 0
    severity: str = "INFO"
    confidence: str = "LOW"
    confidence_reasons: list[str] = field(default_factory=list)
    language: str | None = None
    allowlisted: bool = False
    allowlist_reason: str | None = None
    baseline_status: list[str] = field(default_factory=list)
    git_status: str | None = None
    iocs: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped_reason: str | None = None
    root: str | None = None

    @property
    def path(self) -> str:
        return self.metadata.path

    def tags(self) -> set[str]:
        out: set[str] = set()
        for ind in self.indicators:
            out |= set(ind.tags)
        return out

    def has_rule(self, prefix: str) -> bool:
        return any(i.rule_id.startswith(prefix) for i in self.indicators)

    def add(self, indicator: Indicator) -> None:
        """Add an indicator, merging duplicates of the same rule."""
        for existing in self.indicators:
            if existing.rule_id == indicator.rule_id:
                existing.occurrences += indicator.occurrences
                room = 3 - len(existing.evidence)
                if room > 0:
                    existing.evidence.extend(indicator.evidence[:room])
                if indicator.weight > existing.weight:
                    existing.weight = indicator.weight
                    existing.description = indicator.description
                existing.strength = max(existing.strength, indicator.strength)
                existing.min_severity = max_severity(
                    existing.min_severity, indicator.min_severity
                )
                existing.tags = existing.tags | indicator.tags
                return
        self.indicators.append(indicator)

    def reasons(self) -> list[str]:
        ordered = sorted(
            self.indicators,
            key=lambda i: (-(i.effective_weight if i.effective_weight is not None else i.weight),
                           -int(i.strength), i.rule_id),
        )
        return [i.description for i in ordered]

    def to_dict(self, with_evidence: bool = True) -> dict[str, Any]:
        ordered = sorted(
            self.indicators,
            key=lambda i: (-(i.effective_weight or 0), -int(i.strength), i.rule_id),
        )
        d: dict[str, Any] = {
            "kind": self.kind,
            "path": self.metadata.path,
            "relpath": self.metadata.relpath,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "language": self.language,
            "reasons": [i.description for i in ordered],
            "confidence_reasons": self.confidence_reasons,
            "indicators": [i.to_dict(with_evidence) for i in ordered],
            "metadata": self.metadata.to_dict(),
            "allowlisted": self.allowlisted,
        }
        if self.allowlist_reason:
            d["allowlist_reason"] = self.allowlist_reason
        if self.baseline_status:
            d["baseline_status"] = self.baseline_status
        if self.git_status:
            d["git_status"] = self.git_status
        if self.iocs:
            d["iocs"] = {"label": "UNVERIFIED STATIC IOC", **self.iocs}
        if self.errors:
            d["errors"] = self.errors
        if self.notes:
            d["notes"] = self.notes
        if self.skipped_reason:
            d["skipped_reason"] = self.skipped_reason
        return d


@dataclass
class BaselineChange:
    status: str                      # NEW | MODIFIED | DELETED | PERMISSION_CHANGED | OWNER_CHANGED | TYPE_CHANGED | SYMLINK_CHANGED
    relpath: str
    old: dict[str, Any] | None = None
    new: dict[str, Any] | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "relpath": self.relpath,
            "detail": self.detail,
            "old": self.old,
            "new": self.new,
        }


@dataclass
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0          # content analysed
    files_skipped: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)
    bytes_read: int = 0
    dirs_seen: int = 0
    symlinks: int = 0
    server_side_scripts: int = 0
    php_files: int = 0
    errors: int = 0
    excluded: int = 0
    filtered_by_time: int = 0
    archives_scanned: int = 0
    archive_members_scanned: int = 0
    baseline_new: int = 0
    baseline_modified: int = 0
    baseline_deleted: int = 0
    baseline_perm_changed: int = 0
    baseline_owner_changed: int = 0
    yara_matches: int = 0
    ioc_hash_matches: int = 0
    persistence_indicators: int = 0
    config_indicators: int = 0
    allowlisted: int = 0
    duration_seconds: float = 0.0

    def skip(self, reason: str) -> None:
        self.files_skipped += 1
        self.skipped_reasons[reason] = self.skipped_reasons.get(reason, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    mode: str
    roots: list[str]
    started: str
    finished: str | None = None
    tool_version: str = ""
    hostname: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    stats: ScanStats = field(default_factory=ScanStats)
    findings: list[Finding] = field(default_factory=list)
    baseline_changes: list[BaselineChange] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    quarantine: list[dict[str, Any]] = field(default_factory=list)

    def reported(self, include_allowlisted: bool = False) -> list[Finding]:
        return [
            f for f in self.findings if include_allowlisted or not f.allowlisted
        ]

    def severity_counts(self, kinds: set[str] | None = None) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            if f.allowlisted:
                continue
            if kinds is not None and f.kind not in kinds:
                continue
            counts[f.severity] += 1
        return counts

    def to_dict(self, with_evidence: bool = True) -> dict[str, Any]:
        return {
            "tool": "webshell-hunter",
            "tool_version": self.tool_version,
            "mode": self.mode,
            "roots": self.roots,
            "hostname": self.hostname,
            "started": self.started,
            "finished": self.finished,
            "options": self.options,
            "disclaimer": (
                "A detection does not automatically prove that a file is malicious. "
                "IOCs are unverified static strings."
            ),
            "severity_counts": self.severity_counts(),
            "stats": self.stats.to_dict(),
            "frameworks": self.frameworks,
            "findings": [f.to_dict(with_evidence) for f in self.findings],
            "baseline_changes": [c.to_dict() for c in self.baseline_changes],
            "relationships": [r.to_dict() for r in self.relationships],
            "persistence_chains": self.chains,
            "quarantine": self.quarantine,
            "warnings": self.warnings,
            "errors": self.errors,
        }
