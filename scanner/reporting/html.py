"""Self-contained HTML report (inline CSS, no JavaScript, no external assets).

Every value originating from scanned files (paths, snippets, IOCs) is
HTML-escaped: file names and contents are attacker-controlled.
"""

from __future__ import annotations

import html
import os
from pathlib import Path

from ..models import SEVERITIES, Finding, ScanResult
from ..utils import human_size, ts_to_iso
from .terminal import suggested_commands

CSS = """
:root{--bg:#f7f7f9;--fg:#1d1f24;--muted:#5d6370;--card:#fff;--line:#e2e4ea;--code:#f0f1f4;
--crit:#b3261e;--high:#d9480f;--med:#b8860b;--low:#1c7ed6;--info:#868e96;--ok:#2b8a3e}
@media (prefers-color-scheme:dark){:root{--bg:#15171b;--fg:#e6e8ec;--muted:#9aa1ad;--card:#1e2127;
--line:#2d313a;--code:#262a31}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--fg)}main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--line);
padding-bottom:6px}h3{font-size:15px;margin:0}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat b{display:block;font-size:22px}.sev{display:inline-block;padding:1px 8px;border-radius:4px;color:#fff;
font-weight:600;font-size:12px}.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}
.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.INFO{background:var(--info)}
.kind{display:inline-block;padding:1px 6px;border:1px solid var(--line);border-radius:4px;font-size:12px;
margin-left:6px}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--code);padding:8px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;
word-break:break-all;margin:4px 0}.path{word-break:break-all}table{border-collapse:collapse;width:100%}
td,th{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}ul{margin:6px 0;padding-left:20px}
details summary{cursor:pointer;color:var(--muted);margin-top:6px}.chain{font-family:ui-monospace,monospace;
white-space:pre-wrap;background:var(--code);padding:10px;border-radius:6px}.note{border-left:3px solid var(--med);
padding:6px 10px;background:var(--card)}
"""


def e(v: object) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _finding_card(f: Finding) -> str:
    md = f.metadata
    parts = [f'<div class="card"><h3><span class="sev {e(f.severity)}">{e(f.severity)}</span>'
             f'<span class="kind">{e(f.kind)}</span> <span class="path">{e(md.path)}</span></h3>',
             f'<div class="muted">Score {f.score} &middot; Confidence {e(f.confidence)}'
             f'{" &middot; ALLOWLISTED: " + e(f.allowlist_reason) if f.allowlisted else ""}</div>']
    parts.append("<ul>")
    ordered = sorted(f.indicators, key=lambda i: (-(i.effective_weight or 0), -int(i.strength)))
    for ind in ordered:
        parts.append(f"<li>{e(ind.description)} <span class='muted'>[{e(ind.strength.name.lower())}, "
                     f"+{e(ind.effective_weight)} &middot; {e(ind.rule_id)}]</span>")
        for ev in ind.evidence[:3]:
            if ev.snippet:
                loc = f"Line {ev.line}: " if ev.line else ""
                parts.append(f"<pre>{e(loc + ev.snippet)}</pre>")
        parts.append("</li>")
    parts.append("</ul>")
    parts.append(f"<div class='muted'>Confidence rationale: {e('; '.join(f.confidence_reasons))}</div>")
    rows = [("SHA256", md.sha256), ("SHA1", md.sha1), ("MD5", md.md5), ("Real path", md.realpath),
            ("Size", f"{human_size(md.size)} ({md.size} bytes)" if md.size is not None else None),
            ("Owner", f"{md.owner or md.uid}:{md.group or md.gid} (uid {md.uid}, gid {md.gid})"
             if md.uid is not None else None),
            ("Permissions", f"{md.permissions} ({md.mode})" if md.mode else None),
            ("Modified", ts_to_iso(md.mtime)), ("Changed (ctime)", ts_to_iso(md.ctime)),
            ("Inode", md.inode), ("Content type", md.content_type),
            ("Entropy", f"{md.entropy:.2f}" if md.entropy is not None else None),
            ("FS attributes", ", ".join(md.fs_flags) if md.fs_flags else None),
            ("Symlink target", md.link_target), ("Baseline", ", ".join(f.baseline_status) or None),
            ("Git", f.git_status), ("Language", f.language)]
    parts.append("<details><summary>File metadata</summary><table>")
    for k, v in rows:
        if v not in (None, ""):
            parts.append(f"<tr><th>{e(k)}</th><td><code>{e(v)}</code></td></tr>")
    parts.append("</table></details>")
    if f.iocs:
        parts.append("<details><summary>UNVERIFIED STATIC IOCs (never contacted)</summary><table>")
        for k, vals in f.iocs.items():
            parts.append(f"<tr><th>{e(k)}</th><td><code>{e(', '.join(vals))}</code></td></tr>")
        parts.append("</table></details>")
    if f.severity in ("MEDIUM", "HIGH", "CRITICAL"):
        cmds = "\n".join("$ " + c for c in suggested_commands(f))
        parts.append(f"<details><summary>Suggested read-only follow-up</summary><pre>{e(cmds)}</pre></details>")
    for n in f.notes:
        parts.append(f"<div class='muted'>Note: {e(n)}</div>")
    parts.append("</div>")
    return "".join(parts)


def render_html(result: ScanResult) -> str:
    counts = result.severity_counts()
    s = result.stats
    web = [f for f in result.findings if f.kind not in ("persistence", "config")]
    host = [f for f in result.findings if f.kind in ("persistence", "config")]
    top = counts["CRITICAL"] and "CRITICAL" or counts["HIGH"] and "HIGH" or counts["MEDIUM"] and "MEDIUM" \
        or counts["LOW"] and "LOW" or None
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           "<title>WebShell Hunter Report</title>", f"<style>{CSS}</style></head><body><main>",
           "<h1>WebShell Hunter Report</h1>",
           f"<div class='muted'>{e(', '.join(result.roots))} &middot; {e(result.hostname)} &middot; "
           f"{e(result.started)}</div>"]
    # Executive summary
    out.append("<h2>Executive Summary</h2><div class='card'>")
    if top:
        out.append(f"<p>Highest severity observed: <span class='sev {top}'>{top}</span>. "
                   f"{counts['CRITICAL']} critical and {counts['HIGH']} high findings across "
                   f"{s.files_seen:,} examined files.</p>")
    else:
        out.append("<p>No findings at or above the reporting threshold.</p>")
    if result.chains:
        out.append(f"<p>{len(result.chains)} evidence-backed persistence chain(s) were reconstructed "
                   "(see <a href='#chains'>Persistence Chains</a>).</p>")
    if s.baseline_new or s.baseline_modified:
        out.append(f"<p>Compared with the baseline: {s.baseline_new} new and {s.baseline_modified} "
                   "modified files.</p>")
    out.append("<p class='note'>A detection does not automatically prove that a file is malicious. "
               "Recommended response: <b>report, hash, preserve, investigate</b> - not delete.</p></div>")
    # Scan information
    out.append("<h2>Scan Information</h2><div class='card'><table>")
    info = [("Mode", result.mode), ("Roots", ", ".join(result.roots)), ("Host", result.hostname),
            ("Started", result.started), ("Finished", result.finished),
            ("Tool version", result.tool_version), ("Duration", f"{s.duration_seconds} s"),
            ("Frameworks", "; ".join(f"{k}: {', '.join(v)}" for k, v in result.frameworks.items()) or "-")]
    info += [(k, v) for k, v in sorted(result.options.items()) if v not in (None, False, [], "")]
    for k, v in info:
        out.append(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>")
    out.append("</table></div>")
    # Severity counts
    out.append("<h2>Severity Counts</h2><div class='grid'>")
    for sev in reversed(SEVERITIES):
        out.append(f"<div class='stat'><span class='sev {sev}'>{sev}</span><b>{counts[sev]}</b></div>")
    for label, v in (("Files seen", s.files_seen), ("Scripts", s.server_side_scripts),
                     ("PHP files", s.php_files), ("Skipped", s.files_skipped),
                     ("Persistence", s.persistence_indicators), ("YARA matches", s.yara_matches),
                     ("IOC hash hits", s.ioc_hash_matches), ("Allowlisted", s.allowlisted),
                     ("Errors", s.errors)):
        out.append(f"<div class='stat'><span class='muted'>{e(label)}</span><b>{v:,}</b></div>")
    out.append("</div>")
    for sev, title in (("CRITICAL", "Critical Findings"), ("HIGH", "High Findings"),
                       ("MEDIUM", "Medium Findings"), ("LOW", "Low Findings"), ("INFO", "Informational")):
        items = [f for f in web if f.severity == sev]
        if not items and sev not in ("CRITICAL", "HIGH"):
            continue
        out.append(f"<h2>{e(title)} ({len(items)})</h2>")
        if not items:
            out.append("<p class='muted'>None.</p>")
        if sev in ("CRITICAL", "HIGH"):
            out.extend(_finding_card(f) for f in items)
        else:
            out.append(f"<details><summary>Show {len(items)} finding(s)</summary>")
            out.extend(_finding_card(f) for f in items)
            out.append("</details>")
    out.append(f"<h2>Persistence Indicators ({len(host)})</h2>")
    out.append("<p class='muted'>Host-level mechanisms (cron, systemd, PHP/web server configuration, "
               "deployment hooks), reported separately from web shell findings.</p>")
    if host:
        out.extend(_finding_card(f) for f in host)
    else:
        out.append("<p class='muted'>None found (or persistence hunting not enabled).</p>")
    out.append("<h2 id='chains'>Persistence Chains</h2>")
    if result.chains:
        for c in result.chains[:20]:
            lines = []
            for i, n in enumerate(c["nodes"]):
                sev = f" [{n['severity']}]" if n.get("severity") else ""
                lines.append(f"{n['path']}{sev}")
                if i < len(c["relations"]):
                    ev = c["relations"][i].get("evidence") or {}
                    ln = f" (line {ev['line']})" if ev.get("line") else ""
                    lines.append(f"      |  {c['relations'][i]['relation']}{ln}\n      v")
            out.append(f"<div class='card'><div class='chain'>{e(chr(10).join(lines))}</div>"
                       f"<p>{e(c['conclusion'])}</p></div>")
    else:
        out.append("<p class='muted'>No evidence-backed chains.</p>")
    out.append(f"<h2>Baseline Changes ({len(result.baseline_changes)})</h2>")
    if result.baseline_changes:
        out.append("<div class='card'><table><tr><th>Status</th><th>Path</th><th>Detail</th></tr>")
        for c in result.baseline_changes[:5000]:
            out.append(f"<tr><td>{e(c.status)}</td><td class='path'>{e(c.relpath)}</td><td>{e(c.detail)}</td></tr>")
        out.append("</table></div>")
    else:
        out.append("<p class='muted'>No baseline comparison performed or no changes.</p>")
    if result.quarantine:
        out.append("<h2>Quarantine Actions</h2><div class='card'><table>")
        for q in result.quarantine:
            out.append(f"<tr><td>{e(q.get('status'))}</td><td class='path'>{e(q.get('original_path'))}</td>"
                       f"<td><code>{e(q.get('sha256'))}</code></td></tr>")
        out.append("</table></div>")
    if result.warnings or result.errors:
        out.append("<h2>Warnings and Errors</h2><div class='card'><ul>")
        for w in result.warnings:
            out.append(f"<li>{e(w)}</li>")
        for er in result.errors[:500]:
            out.append(f"<li class='muted'>{e(er)}</li>")
        out.append("</ul></div>")
    out.append("<p class='muted'>Generated by webshell-hunter. All IOCs are unverified static strings.</p>")
    out.append("</main></body></html>")
    return "\n".join(out)


def write_html(result: ScanResult, path: str | Path) -> None:
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(render_html(result), encoding="utf-8")
    os.replace(tmp, p)
