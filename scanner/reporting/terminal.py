"""Human-readable terminal output (ANSI colours when supported)."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from ..models import SEVERITIES, Finding, ScanResult
from ..utils import human_size, shell_quote, ts_to_iso

_COLORS = {
    "CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m",
    "LOW": "\033[36m", "INFO": "\033[2m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "reset": "\033[0m", "magenta": "\033[1;35m",
}


def supports_color(stream: TextIO, disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, style: str) -> str:
        if not self.enabled:
            return text
        return f"{_COLORS.get(style, '')}{text}{_COLORS['reset']}"


def suggested_commands(f: Finding) -> list[str]:
    """Safe, read-only commands for manual follow-up. Never executes the file."""
    p = f.metadata.path
    if "!/" in p:
        p = p.split("!/", 1)[0]
    q = shell_quote(p)
    cmds = [f"stat {q}", f"sha256sum {q}", f"ls -lah --time-style=full-iso {q}", f"lsattr {q}"]
    if f.kind != "symlink":
        cmds.append(f"head -c 2000 {q} | cat -v")
    else:
        cmds.append(f"readlink -f {q}")
    return cmds


def print_finding(f: Finding, paint: Painter, out: TextIO, show_evidence: bool = True,
                  commands: bool = True) -> None:
    sev = paint(f"[{f.severity}]", f.severity)
    label = {"persistence": "PERSISTENCE", "config": "CONFIG", "symlink": "SYMLINK",
             "archive_member": "ARCHIVE MEMBER", "referenced_file": "REFERENCED FILE"}.get(f.kind)
    kind = f" {paint(label, 'magenta')}" if label else ""
    print("=" * 80, file=out)
    print(f"{sev}{kind} {paint(f.metadata.path, 'bold')}", file=out)
    print(f"Score: {f.score}   Confidence: {f.confidence}   Language: {f.language or '-'}", file=out)
    md = f.metadata
    if md.sha256:
        print(f"SHA256: {md.sha256}", file=out)
    owner = f"{md.owner or md.uid}:{md.group or md.gid}" if md.uid is not None else "-"
    print(f"Size: {human_size(md.size)}   Mode: {md.permissions or '-'} ({md.mode or '-'})   Owner: {owner}",
          file=out)
    print(f"MTime: {ts_to_iso(md.mtime) or '-'}   CTime: {ts_to_iso(md.ctime) or '-'}", file=out)
    extras = []
    if f.baseline_status:
        extras.append("baseline=" + ",".join(f.baseline_status))
    if f.git_status:
        extras.append(f"git={f.git_status}")
    if md.fs_flags:
        extras.append("attrs=" + ",".join(md.fs_flags))
    if md.link_target:
        extras.append(f"-> {md.link_target}")
    if f.allowlisted:
        extras.append(paint(f"ALLOWLISTED ({f.allowlist_reason})", "green"))
    if extras:
        print("Context: " + "   ".join(extras), file=out)
    print("Reasons:", file=out)
    ordered = sorted(f.indicators, key=lambda i: (-(i.effective_weight or 0), -int(i.strength), i.rule_id))
    for ind in ordered:
        w = ind.effective_weight if ind.effective_weight is not None else ind.weight
        print(f"  + {ind.description} {paint(f'[{ind.strength.name.lower()}, +{w}]', 'dim')}", file=out)
        if show_evidence:
            for ev in ind.evidence[:2]:
                if not ev.snippet:
                    continue
                loc = f"line {ev.line}: " if ev.line else ""
                print(f"      {paint(loc + ev.snippet, 'dim')}", file=out)
    print(f"Confidence: {f.confidence} - {'; '.join(f.confidence_reasons)}", file=out)
    if f.iocs:
        print("UNVERIFIED STATIC IOCs (not contacted):", file=out)
        for k, vals in f.iocs.items():
            print(f"  {k}: {', '.join(vals[:8])}{' ...' if len(vals) > 8 else ''}", file=out)
    for n in f.notes:
        print(f"Note: {n}", file=out)
    if commands and f.severity in ("MEDIUM", "HIGH", "CRITICAL"):
        print("Suggested read-only follow-up:", file=out)
        for c in suggested_commands(f):
            print(f"  $ {c}", file=out)


def print_chains(result: ScanResult, paint: Painter, out: TextIO) -> None:
    if not result.chains:
        return
    print("", file=out)
    print(paint("Likely persistence chain(s) (evidence-backed relationships):", "magenta"), file=out)
    for chain in result.chains[:10]:
        print("", file=out)
        nodes = chain["nodes"]
        for i, n in enumerate(nodes):
            sev = f" [{n['severity']}]" if n.get("severity") else ""
            missing = "" if n.get("exists") else " (not present)"
            print(f"  {n['path']}{sev}{missing}", file=out)
            if i < len(chain["relations"]):
                rel = chain["relations"][i]
                ev = rel.get("evidence") or {}
                where = f" (line {ev['line']})" if ev.get("line") else ""
                print(f"        |  {rel['relation']}{where}", file=out)
                print("        v", file=out)
        print(f"  {chain['conclusion']}", file=out)


def print_summary(result: ScanResult, paint: Painter, out: TextIO) -> None:
    s = result.stats
    counts = result.severity_counts()
    print("", file=out)
    print("=" * 80, file=out)
    rows = [
        ("Files seen", s.files_seen), ("Files skipped/partial", s.files_skipped),
        ("Excluded paths", s.excluded), ("Filtered by time window", s.filtered_by_time),
        ("Server-side scripts", s.server_side_scripts), ("PHP files", s.php_files),
        ("Symlinks", s.symlinks), ("Data read", human_size(s.bytes_read)),
    ]
    if result.options.get("baseline"):
        rows += [("New files vs baseline", s.baseline_new), ("Modified files", s.baseline_modified),
                 ("Deleted files", s.baseline_deleted), ("Permission changes", s.baseline_perm_changed),
                 ("Owner changes", s.baseline_owner_changed)]
    if s.archives_scanned:
        rows += [("Archives inspected", s.archives_scanned), ("Archive members flagged", s.archive_members_scanned)]
    rows += [(None, None)]
    for sev in reversed(SEVERITIES[1:]):
        rows.append((f"{sev.title()} findings", counts[sev]))
    rows += [(None, None),
             ("Persistence indicators", s.persistence_indicators), ("Config indicators", s.config_indicators),
             ("YARA matches", s.yara_matches), ("IOC hash matches", s.ioc_hash_matches),
             ("Allowlisted", s.allowlisted), ("Access errors", s.errors),
             ("Duration (s)", s.duration_seconds)]
    for k, v in rows:
        if k is None:
            print("", file=out)
            continue
        print(f"{k + ':':<30}{v:>12}" if isinstance(v, int) else f"{k + ':':<30}{str(v):>12}", file=out)
    if s.skipped_reasons:
        print("Skip reasons: " + ", ".join(f"{k}={v}" for k, v in sorted(s.skipped_reasons.items())), file=out)
    for w in result.warnings:
        print(paint(f"[!] {w}", "MEDIUM"), file=out)
    print("", file=out)
    print(paint("A detection does not automatically prove that a file is malicious. "
                "Preserve evidence before changing anything.", "dim"), file=out)


def print_report(result: ScanResult, color: bool = True, out: TextIO | None = None,
                 show_evidence: bool = True, commands: bool = True, quiet: bool = False) -> None:
    out = out or sys.stdout
    paint = Painter(supports_color(out, not color))
    webshells = [f for f in result.findings if f.kind not in ("persistence", "config")]
    host = [f for f in result.findings if f.kind in ("persistence", "config")]
    if not quiet:
        if not result.findings:
            print(paint("[+] No findings at or above the reporting threshold.", "green"), file=out)
        for f in webshells:
            print_finding(f, paint, out, show_evidence, commands)
        if host:
            print("", file=out)
            print(paint("#" * 80, "magenta"), file=out)
            print(paint("PERSISTENCE / CONFIGURATION INDICATORS (host-level, reported separately)", "magenta"),
                  file=out)
            for f in host:
                print_finding(f, paint, out, show_evidence, commands)
        print_chains(result, paint, out)
        if result.baseline_changes:
            print("", file=out)
            print(paint("Baseline changes (first 50):", "bold"), file=out)
            for c in result.baseline_changes[:50]:
                print(f"  {c.status:<19} {c.relpath}  {c.detail}", file=out)
            if len(result.baseline_changes) > 50:
                print(f"  ... {len(result.baseline_changes) - 50} more (see JSON/HTML report)", file=out)
    print_summary(result, paint, out)
