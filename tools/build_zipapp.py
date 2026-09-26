#!/usr/bin/env python3
"""Build a single-file release: dist/webshell-hunter.pyz

The zipapp bundles the ``scanner`` package, rules and default config. Run it
with ``python3 webshell-hunter.pyz scan --path /var/www/html``.
"""

import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        shutil.copytree(ROOT / "scanner", stage / "scanner",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(ROOT / "rules", stage / "rules")
        shutil.copytree(ROOT / "config", stage / "config")
        (stage / "__main__.py").write_text(
            "import sys\nfrom scanner.cli import main\nsys.exit(main())\n", encoding="utf-8")
        target = dist / "webshell-hunter.pyz"
        zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3", compressed=True)
    print(f"built {target}")


if __name__ == "__main__":
    main()
