"""Deterministic, documented scoring model.

score = sum over categories of min(category_cap, sum of rule weights)

* each rule is counted once per finding (duplicates only raise the
  occurrence counter),
* each category is capped (``scoring.category_caps``) so that many weak hits
  of one kind can never add up to a critical finding,
* combination rules add points when independent signals co-occur,
* some indicators carry a *severity floor* (``min_severity``): e.g. request
  data passed directly into ``system()`` is CRITICAL regardless of score.

Severity bands (default): INFO < 10 <= LOW < 20 <= MEDIUM < 35 <= HIGH < 60 <= CRITICAL
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import SEVERITY_RANK, Finding, Indicator, Strength, max_severity


@dataclass(frozen=True)
class Combination:
    id: str
    description: str
    weight: int
    strength: Strength
    all_of: tuple[frozenset[str], ...]      # every group must intersect the tag set
    none_of: frozenset[str] = frozenset()
    min_severity: str | None = None


EXEC_OR_EVAL = frozenset({"sink:exec", "sink:eval"})
NEW_OR_UNTRACKED = frozenset({"baseline:new", "git:untracked"})
CHANGED = frozenset({"baseline:new", "baseline:modified", "git:untracked", "git:modified"})

COMBINATIONS: list[Combination] = [
    Combination("combo.decoder_eval", "Decoding functions combined with dynamic code evaluation",
                12, Strength.MODERATE, (frozenset({"decoder"}), frozenset({"sink:eval"})),
                none_of=frozenset({"loader"})),
    Combination("combo.input_exec", "Reads request input and can execute OS commands "
                "(no direct data flow proven)", 8, Strength.MODERATE,
                (frozenset({"source"}), frozenset({"sink:exec"})),
                none_of=frozenset({"flow:direct", "flow:indirect"})),
    Combination("combo.input_eval", "Reads request input and evaluates code dynamically "
                "(no direct data flow proven)", 6, Strength.MODERATE,
                (frozenset({"source"}), frozenset({"sink:eval"})),
                none_of=frozenset({"flow:direct", "flow:indirect"})),
    Combination("combo.obfuscated_exec", "Strong obfuscation combined with code/command execution",
                10, Strength.STRONG, (frozenset({"obf:strong"}), EXEC_OR_EVAL)),
    Combination("combo.entropy_eval", "High-entropy content combined with dynamic evaluation",
                6, Strength.MODERATE, (frozenset({"high_entropy", "blob"}), frozenset({"sink:eval"}))),
    Combination("combo.upload_exec", "Server-side script with execution capability inside an upload directory",
                15, Strength.STRONG, (frozenset({"loc:upload"}), EXEC_OR_EVAL | {"dyn:strong"}),
                min_severity="HIGH"),
    Combination("combo.hidden_exec", "Hidden script with execution capability or strong obfuscation",
                8, Strength.MODERATE, (frozenset({"loc:hidden"}), EXEC_OR_EVAL | {"obf:strong"})),
    Combination("combo.new_exec", "Script that is new/untracked or modified also contains execution capability",
                10, Strength.STRONG, (CHANGED, frozenset({"script"}), EXEC_OR_EVAL | {"dyn:strong"})),
    Combination("combo.new_upload_exec",
                "New/untracked script inside an upload directory with code/command execution",
                12, Strength.DEFINITIVE,
                (NEW_OR_UNTRACKED, frozenset({"loc:upload"}), EXEC_OR_EVAL | {"dyn:strong", "flow:direct"}),
                min_severity="CRITICAL"),
    Combination("combo.marker_exec", "Known web shell marker together with execution capability",
                15, Strength.DEFINITIVE, (frozenset({"marker"}), EXEC_OR_EVAL), min_severity="HIGH"),
    Combination("combo.media_code_exec", "Code hidden inside a media/non-script file with execution capability",
                12, Strength.STRONG, (frozenset({"php_in_media", "polyglot", "hidden_code", "disguised"}),
                                      EXEC_OR_EVAL | {"dyn:strong"}), min_severity="HIGH"),
    Combination("combo.persistence_referenced_script",
                "Script is written/referenced by a persistence mechanism (cron/systemd/config)",
                15, Strength.STRONG, (frozenset({"xref:persistence"}), frozenset({"script", "php_in_media"})),
                min_severity="HIGH"),
    Combination("combo.handler_media", "Media file with embedded code while a handler makes such files executable",
                20, Strength.DEFINITIVE, (frozenset({"xref:handler"}), frozenset({"php_in_media", "hidden_code"})),
                min_severity="CRITICAL"),
    Combination("combo.respawn_writer", "Self-respawning loop that writes files (re-infection loop)",
                10, Strength.STRONG, (frozenset({"respawn"}), frozenset({"dropper", "flow:write"}))),
]


class Scorer:
    def __init__(self, cfg: dict[str, Any]) -> None:
        sc = cfg["scoring"]
        self.thresholds: dict[str, int] = dict(sc["thresholds"])
        self.caps: dict[str, int] = dict(sc["category_caps"])
        self.weights: dict[str, int] = dict(sc.get("weights") or {})

    def severity_for(self, score: int) -> str:
        sev = "INFO"
        for name in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            if score >= int(self.thresholds[name]):
                sev = name
        return sev

    def apply_combinations(self, finding: Finding, extra_tags: set[str] | None = None) -> None:
        # Drop earlier combination results so re-scoring is idempotent.
        finding.indicators = [i for i in finding.indicators if i.category != "combination"]
        tags = finding.tags() | (extra_tags or set())
        for combo in COMBINATIONS:
            if combo.none_of & tags:
                continue
            if all(group & tags for group in combo.all_of):
                finding.indicators.append(Indicator(
                    combo.id, "combination", combo.description,
                    int(self.weights.get(combo.id, combo.weight)), combo.strength,
                    min_severity=combo.min_severity))

    def score(self, finding: Finding, extra_tags: set[str] | None = None) -> None:
        """Compute score, severity and confidence in place."""
        self.apply_combinations(finding, extra_tags)
        by_cat: dict[str, list[Indicator]] = {}
        for ind in finding.indicators:
            by_cat.setdefault(ind.category, []).append(ind)
        total = 0
        floor: str | None = None
        for cat, inds in by_cat.items():
            cap = int(self.caps.get(cat, 20))
            remaining = cap
            for ind in sorted(inds, key=lambda i: -i.weight):
                eff = max(0, min(ind.weight, remaining))
                ind.effective_weight = eff
                remaining -= eff
            total += min(cap, sum(i.weight for i in inds))
            for ind in inds:
                floor = max_severity(floor, ind.min_severity)
        finding.score = total
        sev = self.severity_for(total)
        if floor and SEVERITY_RANK[floor] > SEVERITY_RANK[sev]:
            sev = floor
        finding.severity = sev
        finding.confidence, finding.confidence_reasons = confidence(finding.indicators)


def confidence(indicators: list[Indicator]) -> tuple[str, list[str]]:
    """Confidence reflects how *independent* and *strong* the evidence is."""
    if not indicators:
        return "LOW", ["No indicators"]
    definitive = [i for i in indicators if i.strength == Strength.DEFINITIVE]
    strong = [i for i in indicators if i.strength == Strength.STRONG]
    moderate = [i for i in indicators if i.strength == Strength.MODERATE]
    weak = [i for i in indicators if i.strength == Strength.WEAK]
    strong_cats = {i.category for i in strong}
    mod_cats = {i.category for i in moderate} | strong_cats
    reasons: list[str] = []
    if definitive:
        reasons.append(f"Definitive indicator: {definitive[0].description}")
        return "VERY_HIGH", reasons
    if len(strong_cats) >= 2:
        reasons.append(f"{len(strong)} strong indicators from {len(strong_cats)} independent categories "
                       f"({', '.join(sorted(strong_cats))})")
        return "VERY_HIGH", reasons
    if strong and len(mod_cats) >= 3:
        reasons.append("A strong indicator corroborated by moderate indicators in "
                       f"{len(mod_cats) - 1} other categories")
        return "VERY_HIGH", reasons
    if strong:
        reasons.append(f"Strong indicator: {strong[0].description}")
        return "HIGH", reasons
    if len({i.category for i in moderate}) >= 3:
        reasons.append(f"{len(moderate)} moderate indicators across {len({i.category for i in moderate})} categories")
        return "HIGH", reasons
    if moderate:
        reasons.append(f"{len(moderate)} moderate indicator(s); no strong evidence")
        return "MEDIUM", reasons
    if len(weak) >= 3:
        reasons.append(f"{len(weak)} weak indicators only")
        return "MEDIUM", reasons
    reasons.append("Only weak indicators, which are common in legitimate code")
    return "LOW", reasons
