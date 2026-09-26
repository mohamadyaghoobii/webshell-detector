"""Optional YARA integration (``pip install yara-python``).

If yara-python is missing or the rules fail to compile, the scanner keeps
working and records a warning. Rules are matched against in-memory data
already read by the scanner - YARA never opens scanned paths itself.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .models import Evidence, Indicator, Strength

log = logging.getLogger(__name__)

try:  # pragma: no cover - depends on the environment
    import yara  # type: ignore
    YARA_AVAILABLE = True
except Exception:  # ImportError or a broken libyara
    yara = None
    YARA_AVAILABLE = False

_STRENGTH = {"weak": Strength.WEAK, "moderate": Strength.MODERATE,
             "strong": Strength.STRONG, "definitive": Strength.DEFINITIVE}


class YaraEngine:
    def __init__(self, rules_path: str | Path, timeout: int = 30) -> None:
        if not YARA_AVAILABLE:
            raise RuntimeError("yara-python is not installed (pip install yara-python)")
        p = Path(rules_path)
        if p.is_dir():
            files = sorted(list(p.rglob("*.yar")) + list(p.rglob("*.yara")))
            if not files:
                raise RuntimeError(f"no .yar/.yara files under {p}")
            self.rules = yara.compile(filepaths={f"r{i}": str(f) for i, f in enumerate(files)})
            self.sources = [str(f) for f in files]
        else:
            self.rules = yara.compile(filepath=str(p))
            self.sources = [str(p)]
        self.timeout = timeout

    def match(self, data: bytes) -> list[Indicator]:
        try:
            matches = self.rules.match(data=data, timeout=self.timeout)
        except Exception as exc:  # yara.Error / TimeoutError
            log.debug("yara match failed: %s", exc)
            return []
        out = []
        for m in matches:
            meta: dict[str, Any] = dict(getattr(m, "meta", {}) or {})
            weight = int(meta.get("weight", 15))
            strength = _STRENGTH.get(str(meta.get("strength", "moderate")).lower(), Strength.MODERATE)
            desc = str(meta.get("description", m.rule))
            sev = meta.get("min_severity")
            tags = {f"yara:{t}" for t in getattr(m, "tags", [])}
            for t in str(meta.get("tags", "")).split(","):
                if t.strip():
                    tags.add(t.strip())
            out.append(Indicator(f"yara.{m.rule}", "yara", f"YARA rule {m.rule}: {desc}", weight,
                                 strength, [Evidence(None, f"rule {m.rule} ({m.namespace})")],
                                 min_severity=str(sev).upper() if sev else None, tags=frozenset(tags)))
        return out
