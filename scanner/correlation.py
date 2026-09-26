"""Cross-reference analysis and persistence-chain construction.

Only relationships backed by static evidence (a config directive, a cron
line, an include statement...) are used. Chains are reported only when
every hop is such a relationship and the final node is independently
classified as suspicious.
"""

from __future__ import annotations

import os
from typing import Any

from .models import SEVERITY_RANK, Evidence, Finding, Indicator, Relationship, Strength
from .scoring import Scorer
from .utils import is_within

_XREF_BY_KIND = {
    "persistence": ("xref.persistence", 20, "xref:persistence"),
    "config": ("xref.config", 16, "xref:persistence"),
    "webserver": ("xref.webserver", 16, "xref:persistence"),
    "file": ("xref.included_by", 8, "xref:include"),
}


def _norm(p: str) -> str:
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return os.path.normpath(p)


def dedupe(rels: list[Relationship]) -> list[Relationship]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for r in rels:
        k = r.key()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def correlate(findings: list[Finding], rels: list[Relationship], scorer: Scorer,
              tag_sets: dict[int, set[str]]) -> None:
    """Add cross-reference indicators to findings and re-score them in place."""
    by_path: dict[str, Finding] = {}
    for f in findings:
        by_path.setdefault(_norm(f.metadata.path), f)
        if f.metadata.realpath:
            by_path.setdefault(f.metadata.realpath, f)

    touched: set[int] = set()
    # 1) targets referenced by persistence/config/other files
    for r in rels:
        tgt = by_path.get(_norm(r.target))
        src = by_path.get(_norm(r.source))
        if tgt is None or tgt is src:
            continue
        rule, weight, tag = _XREF_BY_KIND.get(r.source_kind, _XREF_BY_KIND["file"])
        if r.source_kind == "file" and (src is None or SEVERITY_RANK[src.severity] < SEVERITY_RANK["HIGH"]):
            continue
        line = f", line {r.evidence.line}" if r.evidence and r.evidence.line else ""
        tgt.add(Indicator(rule, "cross_reference",
                          f"Referenced by {r.source} ({r.relation}{line})", weight, Strength.STRONG
                          if r.source_kind != "file" else Strength.MODERATE,
                          [r.evidence] if r.evidence else [], tags=frozenset({tag})))
        touched.add(id(tgt))

    # 2) handler configs (.htaccess making images executable) -> files beneath
    handler_dirs = [os.path.dirname(f.metadata.path) for f in findings
                    if any("config:handler" in i.tags for i in f.indicators)]
    if handler_dirs:
        for f in findings:
            if not ({"php_in_media", "hidden_code", "disguised"} & f.tags()):
                continue
            for d in handler_dirs:
                if is_within(f.metadata.path, d):
                    f.add(Indicator("xref.handler", "cross_reference",
                                    f"A handler configuration in {d} makes this kind of file executable",
                                    12, Strength.STRONG, tags=frozenset({"xref:handler"})))
                    touched.add(id(f))
                    break
    for f in findings:
        if id(f) in touched:
            scorer.score(f, tag_sets.get(id(f)))

    # 3) sources pointing at high-severity targets gain confidence too
    for r in rels:
        tgt = by_path.get(_norm(r.target))
        src = by_path.get(_norm(r.source))
        if tgt is None or src is None or tgt is src:
            continue
        if r.source_kind != "file" and SEVERITY_RANK[tgt.severity] >= SEVERITY_RANK["HIGH"]:
            src.add(Indicator("xref.points_to_malicious", "cross_reference",
                              f"{r.relation} {tgt.metadata.path}, which is classified {tgt.severity}",
                              22, Strength.STRONG, [r.evidence] if r.evidence else [],
                              min_severity="HIGH"))
            scorer.score(src, tag_sets.get(id(src)))


def build_chains(findings: list[Finding], rels: list[Relationship], max_depth: int = 6,
                 min_final: str = "MEDIUM") -> list[dict[str, Any]]:
    """Enumerate evidence-backed chains ending at a suspicious finding."""
    by_path: dict[str, Finding] = {}
    for f in findings:
        by_path.setdefault(_norm(f.metadata.path), f)
    edges: dict[str, list[Relationship]] = {}
    incoming: set[str] = set()
    for r in rels:
        s, t = _norm(r.source), _norm(r.target)
        if s == t:
            continue
        edges.setdefault(s, []).append(r)
        incoming.add(t)
    chains: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()

    def is_final(node: str) -> bool:
        f = by_path.get(node)
        return f is not None and f.kind not in ("persistence", "config") and \
            SEVERITY_RANK[f.severity] >= SEVERITY_RANK[min_final]

    def dfs(node: str, path: list[str], hops: list[Relationship]) -> None:
        if len(path) > max_depth:
            return
        if len(path) >= 2 and is_final(node):
            key = tuple(path)
            if key not in seen:
                seen.add(key)
                chains.append(_chain_dict(path, hops, by_path))
        for r in edges.get(node, []):
            t = _norm(r.target)
            if t in path:
                continue
            dfs(t, path + [t], hops + [r])

    starts = [s for s in edges if s not in incoming] or list(edges)
    for s in sorted(starts):
        dfs(s, [s], [])
    chains.sort(key=lambda c: (-SEVERITY_RANK[c["final_severity"]], -len(c["nodes"])))
    return chains


def _chain_dict(path: list[str], hops: list[Relationship], by_path: dict[str, Finding]) -> dict[str, Any]:
    nodes = []
    for p in path:
        f = by_path.get(p)
        nodes.append({"path": p, "kind": f.kind if f else "unscanned",
                      "severity": f.severity if f else None, "exists": os.path.lexists(p)})
    final = by_path[path[-1]]
    independent = sorted((i for i in final.indicators if i.category not in ("cross_reference", "combination")),
                         key=lambda i: (-i.weight, -int(i.strength)))
    top = [i.description for i in independent[:2]]
    return {
        "nodes": nodes,
        "relations": [{"relation": h.relation,
                       "evidence": h.evidence.to_dict() if isinstance(h.evidence, Evidence) else None}
                      for h in hops],
        "final_severity": final.severity,
        "conclusion": (f"The destination file is independently classified as {final.severity} "
                       f"because: {'; '.join(top)}." if top else ""),
    }
