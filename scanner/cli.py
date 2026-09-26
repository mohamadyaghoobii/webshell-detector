"""Command-line interface.

Exit codes
----------
0  no meaningful findings (INFO only)
1  LOW or MEDIUM findings
2  HIGH findings
3  CRITICAL findings
4  scanner/runtime error (bad arguments, unreadable root, invalid config...)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .baseline import BaselineError, create_baseline, load_baseline, snapshot
from .config import ConfigError, load_allowlist_file, load_config
from .engine import Scanner, ScanOptions
from .hashlist import load_hash_list
from .models import SEVERITIES, ScanResult
from .utils import parse_date, parse_duration, parse_size

EXIT_CLEAN, EXIT_LOW_MEDIUM, EXIT_HIGH, EXIT_CRITICAL, EXIT_ERROR = 0, 1, 2, 3, 4
AUTO_ROOTS = ["/var/www/html", "/var/www", "/srv/www", "/usr/share/nginx/html", "/home/*/public_html"]

log = logging.getLogger("webshell_hunter")


class CliError(Exception):
    pass


# ------------------------------------------------------------------ parser
def _common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("general")
    g.add_argument("--config", help="YAML/JSON configuration file (CLI options override it)")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    g.add_argument("--log-file", help="write a log file (no payload contents are logged)")
    g.add_argument("--verbose", "-v", action="store_true", help="informational logging")
    g.add_argument("--debug", action="store_true", help="debug logging")


def _filters(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("scope")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="exclude paths (relative globs, ** supported; repeatable)")
    g.add_argument("--no-default-excludes", action="store_true",
                   help="also walk .git/ and node_modules/ (excluded by default)")
    g.add_argument("--workers", type=int, help="parallel workers (default 8; 1 = sequential)")
    g.add_argument("--executor", choices=["process", "thread"], default="process",
                   help="parallelism model (default process: analysis is CPU-bound)")
    g.add_argument("--max-size", help="max bytes analysed per file, e.g. 20M, 512K (bare number = MB)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="webshell-hunter",
        description="Defensive, static web shell and persistence hunter for Linux web servers. "
                    "Never executes, imports or contacts anything found in scanned files.",
        epilog="Exit codes: 0 clean, 1 low/medium, 2 high, 3 critical, 4 error.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan one or more web roots")
    s.add_argument("--path", action="append", default=[], help="directory to scan (repeatable)")
    s.add_argument("--auto-roots", action="store_true", help="scan common web roots that exist: "
                   + ", ".join(AUTO_ROOTS))
    s.add_argument("--baseline", help="compare against a baseline JSON (baseline create)")
    s.add_argument("--hash-list", action="append", default=[], help="SHA256 IOC list (repeatable)")
    s.add_argument("--yara", help="YARA rule file or directory (requires yara-python)")
    s.add_argument("--allowlist", help="allowlist YAML/JSON file")
    s.add_argument("--show-allowlisted", action="store_true", help="show allowlisted findings (marked)")
    s.add_argument("--modified-within", help="only analyse files changed within e.g. 1d, 7d, 12h")
    s.add_argument("--after", help="only analyse files with time >= DATE (ISO format)")
    s.add_argument("--before", help="only analyse files with time <= DATE (ISO format)")
    s.add_argument("--time-field", choices=["mtime", "ctime", "either"], default="mtime",
                   help="timestamp used by the time filters (default mtime)")
    s.add_argument("--min-severity", choices=SEVERITIES, help="reporting threshold (default LOW)")
    s.add_argument("--persistence", action="store_true",
                   help="hunt cron/systemd/rc/php-config/deploy-hook persistence (read-only)")
    s.add_argument("--webserver-config", action="store_true",
                   help="inspect /etc/apache2, /etc/httpd, /etc/nginx ... (read-only)")
    s.add_argument("--git", action="store_true", help="compare files with Git index state (no hooks run)")
    s.add_argument("--scan-archives", action="store_true", help="inspect zip/tar archives in memory")
    s.add_argument("--json", help="write JSON report")
    s.add_argument("--csv", help="write CSV report")
    s.add_argument("--html", help="write self-contained HTML report")
    s.add_argument("--no-snippets", action="store_true", help="do not record evidence snippets")
    s.add_argument("--no-commands", action="store_true", help="do not print suggested follow-up commands")
    s.add_argument("--quiet", "-q", action="store_true", help="summary only on the terminal")
    q = s.add_argument_group("quarantine (opt-in, never automatic)")
    q.add_argument("--quarantine", metavar="DIR", help="preserve eligible files into DIR")
    q.add_argument("--confirm-quarantine", action="store_true",
                   help="required to actually copy/move files; otherwise a dry run is shown")
    q.add_argument("--quarantine-copy-only", action="store_true",
                   help="copy evidence but leave the original in place")
    q.add_argument("--quarantine-min-severity", choices=SEVERITIES[1:], help="default CRITICAL")
    _filters(s)
    _common(s)

    b = sub.add_parser("baseline", help="create or verify a known-good baseline")
    bsub = b.add_subparsers(dest="baseline_command", required=True)
    bc = bsub.add_parser("create", help="record hashes/metadata of a known-good tree")
    bc.add_argument("--path", required=True)
    bc.add_argument("--output", required=True)
    _filters(bc)
    _common(bc)
    bv = bsub.add_parser("verify", help="check a baseline's integrity digest and show a summary")
    bv.add_argument("baseline")
    _common(bv)

    c = sub.add_parser("compare", help="compare two web roots (e.g. known-good backup vs live)")
    c.add_argument("--old", required=True, help="known-good tree")
    c.add_argument("--new", required=True, help="tree to check")
    c.add_argument("--all-findings", action="store_true",
                   help="report suspicious files even if unchanged (default: changed files only)")
    c.add_argument("--hash-list", action="append", default=[])
    c.add_argument("--yara")
    c.add_argument("--json")
    c.add_argument("--csv")
    c.add_argument("--html")
    c.add_argument("--min-severity", choices=SEVERITIES)
    c.add_argument("--quiet", "-q", action="store_true")
    _filters(c)
    _common(c)

    i = sub.add_parser("investigate", help="deep static analysis of one file")
    i.add_argument("file")
    i.add_argument("--root", help="web root the file belongs to (default: its directory)")
    i.add_argument("--yara")
    i.add_argument("--hash-list", action="append", default=[])
    i.add_argument("--git", action="store_true")
    i.add_argument("--json", help="write JSON")
    _common(i)

    t = sub.add_parser("timeline", help="list files ordered by mtime/ctime")
    t.add_argument("--path", required=True)
    t.add_argument("--after")
    t.add_argument("--before")
    t.add_argument("--modified-within")
    t.add_argument("--extension", action="append", default=[], help="e.g. php (repeatable)")
    t.add_argument("--sort", choices=["mtime", "ctime"], default="mtime")
    t.add_argument("--limit", type=int, help="show only the most recent N entries")
    t.add_argument("--json")
    t.add_argument("--csv")
    t.add_argument("--exclude", action="append", default=[])
    t.add_argument("--no-default-excludes", action="store_true")
    _common(t)
    return ap


# ---------------------------------------------------------------- helpers
def setup_logging(args: argparse.Namespace) -> None:
    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if getattr(args, "log_file", None):
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
    logging.basicConfig(level=level, handlers=handlers, force=True,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def effective_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(getattr(args, "config", None))
    sc = cfg["scanner"]
    if getattr(args, "workers", None):
        sc["workers"] = args.workers
    if getattr(args, "max_size", None):
        sc["max_file_size_mb"] = parse_size(args.max_size) / (1024 * 1024)
    if getattr(args, "no_default_excludes", False):
        sc["default_excludes"] = False
    if getattr(args, "min_severity", None):
        sc["report_min_severity"] = args.min_severity
    if getattr(args, "no_snippets", False):
        sc["snippets"] = False
    if getattr(args, "allowlist", None):
        from .config import deep_merge
        cfg["allowlist"] = deep_merge(cfg["allowlist"], load_allowlist_file(args.allowlist))
    return cfg


def excludes_for(cfg: dict[str, Any], args: argparse.Namespace) -> list[str]:
    ex = list(cfg.get("exclude") or [])
    if cfg["scanner"].get("default_excludes", True):
        ex = list(cfg.get("default_excludes") or []) + ex
    ex += list(getattr(args, "exclude", []) or [])
    return ex


def load_hashes(paths: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for p in paths:
        try:
            hashes.update(load_hash_list(p))
        except OSError as exc:
            raise CliError(f"cannot read hash list {p}: {exc}") from exc
    return hashes


def time_window(args: argparse.Namespace) -> tuple[datetime | None, datetime | None]:
    after = parse_date(args.after) if getattr(args, "after", None) else None
    before = parse_date(args.before) if getattr(args, "before", None) else None
    if getattr(args, "modified_within", None):
        since = datetime.now().astimezone() - parse_duration(args.modified_within)
        after = max(after, since) if after else since
    return after, before


def resolve_roots(args: argparse.Namespace) -> list[Path]:
    import glob as _glob
    roots: list[Path] = []
    for p in args.path:
        rp = Path(p).expanduser()
        if not rp.exists():
            raise CliError(f"path does not exist: {rp}")
        if not rp.is_dir():
            raise CliError(f"not a directory: {rp} (use 'investigate' for single files)")
        roots.append(rp.resolve())
    if getattr(args, "auto_roots", False):
        for pat in AUTO_ROOTS:
            for m in sorted(_glob.glob(pat)):
                mp = Path(m).resolve()
                if mp.is_dir() and not any(mp == r or r in mp.parents for r in roots):
                    roots = [r for r in roots if mp not in r.parents]
                    roots.append(mp)
    if not roots:
        raise CliError("no scan roots: use --path DIR (or --auto-roots)")
    return roots


def exit_code_for(result: ScanResult) -> int:
    counts = result.severity_counts()
    if counts["CRITICAL"]:
        return EXIT_CRITICAL
    if counts["HIGH"]:
        return EXIT_HIGH
    if counts["MEDIUM"] or counts["LOW"]:
        return EXIT_LOW_MEDIUM
    return EXIT_CLEAN


def write_reports(result: ScanResult, args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    from .reporting import write_csv, write_html, write_json
    evidence = cfg["scanner"].get("snippets", True)
    if getattr(args, "json", None):
        write_json(result, args.json, evidence)
        print(f"[+] JSON report: {args.json}", file=sys.stderr)
    if getattr(args, "csv", None):
        write_csv(result, args.csv)
        print(f"[+] CSV report: {args.csv}", file=sys.stderr)
    if getattr(args, "html", None):
        write_html(result, args.html)
        print(f"[+] HTML report: {args.html}", file=sys.stderr)


# ---------------------------------------------------------------- commands
def cmd_scan(args: argparse.Namespace) -> int:
    from .reporting import print_report
    cfg = effective_config(args)
    roots = resolve_roots(args)
    if args.baseline and len(roots) > 1:
        raise CliError("--baseline can only be used with a single --path")
    after, before = time_window(args)
    hashes = load_hashes(list(cfg.get("hash_lists") or []) + args.hash_list)
    yara_rules = args.yara or (cfg["yara"].get("rules") if cfg["yara"].get("enabled") else None)
    opts = ScanOptions(
        roots=roots, baseline=Path(args.baseline) if args.baseline else None, hashes=hashes,
        yara_rules=yara_rules, after=after, before=before, time_field=args.time_field,
        persistence=args.persistence or bool(cfg["persistence"].get("enabled")),
        webserver=args.webserver_config or bool(cfg["webserver_config"].get("enabled")),
        git=args.git or bool(cfg["git"].get("enabled")),
        archives=args.scan_archives or bool(cfg["archives"].get("enabled")),
        workers=int(cfg["scanner"]["workers"]),
        max_size=int(float(cfg["scanner"]["max_file_size_mb"]) * 1024 * 1024),
        report_min_severity=str(cfg["scanner"]["report_min_severity"]).upper(),
        show_allowlisted=args.show_allowlisted, excludes=excludes_for(cfg, args), executor=args.executor)
    if not args.quiet:
        print(f"[+] Scanning: {', '.join(map(str, roots))}", file=sys.stderr)
        print(f"[+] Max analysed size per file: {opts.max_size // 1024} KB; workers: {opts.workers}",
              file=sys.stderr)
    scanner = Scanner(cfg, opts)
    scanner.result.options = {
        "baseline": args.baseline, "hash_lists": args.hash_list, "yara": yara_rules,
        "persistence": opts.persistence, "webserver_config": opts.webserver, "git": opts.git,
        "scan_archives": opts.archives, "after": after.isoformat() if after else None,
        "before": before.isoformat() if before else None, "excludes": opts.excludes,
        "report_min_severity": opts.report_min_severity, "max_size": opts.max_size,
    }
    result = scanner.run()
    if args.quarantine:
        _quarantine(result, args, cfg, roots)
    print_report(result, color=not args.no_color, show_evidence=cfg["scanner"].get("snippets", True),
                 commands=not args.no_commands and cfg["scanner"].get("suggest_commands", True),
                 quiet=args.quiet)
    write_reports(result, args, cfg)
    return exit_code_for(result)


def _quarantine(result: ScanResult, args: argparse.Namespace, cfg: dict[str, Any], roots: list[Path]) -> None:
    from .quarantine import QuarantineError, eligible, quarantine
    min_sev = args.quarantine_min_severity or cfg["quarantine"].get("min_severity", "CRITICAL")
    items = eligible(result.findings, min_sev)
    dry = not args.confirm_quarantine
    try:
        records = quarantine(items, Path(args.quarantine), roots, args.quarantine_copy_only, dry)
    except QuarantineError as exc:
        raise CliError(str(exc)) from exc
    result.quarantine = records
    print(f"[{'DRY-RUN' if dry else 'QUARANTINE'}] {len(records)} file(s) at or above {min_sev}:", file=sys.stderr)
    for r in records:
        print(f"  {r['status']}: {r['original_path']} ({r['sha256']})", file=sys.stderr)
    if dry and records:
        print("  Nothing was changed. Re-run with --confirm-quarantine to preserve these files.", file=sys.stderr)


def cmd_baseline(args: argparse.Namespace) -> int:
    if args.baseline_command == "verify":
        doc = load_baseline(Path(args.baseline))
        ok = doc["_integrity_ok"]
        print(json.dumps({"root": doc.get("root"), "created": doc.get("created"), "hostname": doc.get("hostname"),
                          "files": len(doc["entries"]), "integrity_ok": ok}, indent=2))
        return EXIT_CLEAN if ok else EXIT_ERROR
    cfg = effective_config(args)
    root = Path(args.path).resolve()
    if not root.is_dir():
        raise CliError(f"not a directory: {root}")
    errors: list[str] = []
    doc = create_baseline(root, Path(args.output), excludes_for(cfg, args), int(cfg["scanner"]["workers"]),
                          lambda p, e: errors.append(f"{p}: {e}"))
    print(f"[+] Baseline for {root}: {doc['file_count']} entries -> {args.output}")
    if errors:
        print(f"[!] {len(errors)} path(s) could not be read (run as a user that can read the whole tree):",
              file=sys.stderr)
        for e in errors[:20]:
            print(f"    {e}", file=sys.stderr)
    print("[i] Store the baseline off-host / read-only: an attacker with write access could alter it.")
    return EXIT_CLEAN


def cmd_compare(args: argparse.Namespace) -> int:
    from .reporting import print_report
    cfg = effective_config(args)
    old, new = Path(args.old).resolve(), Path(args.new).resolve()
    for p in (old, new):
        if not p.is_dir():
            raise CliError(f"not a directory: {p}")
    excludes = excludes_for(cfg, args)
    errors: list[str] = []
    old_entries = snapshot(old, excludes, int(cfg["scanner"]["workers"]), lambda p, e: errors.append(f"{p}: {e}"))
    doc = {"entries": old_entries, "root": str(old), "_integrity_ok": True}
    opts = ScanOptions(roots=[new], baseline_doc=doc, hashes=load_hashes(args.hash_list), yara_rules=args.yara,
                       workers=int(cfg["scanner"]["workers"]),
                       max_size=int(float(cfg["scanner"]["max_file_size_mb"]) * 1024 * 1024),
                       report_min_severity=str(cfg["scanner"]["report_min_severity"]).upper(),
                       excludes=excludes, keep_all=False, executor=args.executor)
    scanner = Scanner(cfg, opts)
    scanner.result.mode = "compare"
    scanner.result.options = {"old": str(old), "new": str(new), "baseline": str(old)}
    result = scanner.run()
    result.roots = [str(old), str(new)]
    result.errors.extend(errors)
    if not args.all_findings:
        result.findings = [f for f in result.findings if f.baseline_status or f.kind in ("persistence", "config")
                           or f.has_rule("ioc.hash")]
    summary: dict[str, int] = {}
    for c in result.baseline_changes:
        summary[c.status] = summary.get(c.status, 0) + 1
    print_report(result, color=not args.no_color, quiet=args.quiet)
    print("Change summary: " + (", ".join(f"{k}={v}" for k, v in sorted(summary.items())) or "no differences"))
    write_reports(result, args, cfg)
    code = exit_code_for(result)
    return code if code else (EXIT_LOW_MEDIUM if result.baseline_changes else EXIT_CLEAN)


def cmd_investigate(args: argparse.Namespace) -> int:
    from .investigate import investigate, investigation_to_dict, print_investigation
    cfg = effective_config(args)
    path = Path(args.file)
    if not path.exists() and not path.is_symlink():
        raise CliError(f"file not found: {path}")
    data = investigate(path, cfg, Path(args.root).resolve() if args.root else None, args.yara,
                       load_hashes(args.hash_list), args.git)
    print_investigation(data, sys.stdout, color=not args.no_color)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(investigation_to_dict(data), fh, indent=2, default=str)
        print(f"[+] JSON: {args.json}", file=sys.stderr)
    sev = data["finding"].severity
    return {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1}.get(sev, 0)


def cmd_timeline(args: argparse.Namespace) -> int:
    from .timeline import build_timeline, print_timeline, write_timeline
    cfg = effective_config(args)
    root = Path(args.path).resolve()
    if not root.is_dir():
        raise CliError(f"not a directory: {root}")
    after, before = time_window(args)
    errors: list[str] = []
    rows = build_timeline(root, excludes_for(cfg, args), after, before, args.extension, args.sort, errors)
    if args.limit:
        rows = rows[-args.limit:]
    print_timeline(rows, sys.stdout, args.sort)
    write_timeline(rows, args.json, args.csv)
    for e in errors[:20]:
        print(f"[!] {e}", file=sys.stderr)
    return EXIT_CLEAN


COMMANDS = {"scan": cmd_scan, "baseline": cmd_baseline, "compare": cmd_compare,
            "investigate": cmd_investigate, "timeline": cmd_timeline}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backwards compatibility with the prototype: "webshell_hunter.py --path X"
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args)
    try:
        return COMMANDS[args.command](args)
    except (CliError, ConfigError, BaselineError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # Output piped into e.g. "head": exit quietly.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("[!] interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - last resort
        log.debug("fatal error", exc_info=True)
        print(f"[!] fatal error: {exc} (use --debug for details)", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
