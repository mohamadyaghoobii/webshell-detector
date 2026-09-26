#!/usr/bin/env python3
"""WebShell Hunter - defensive filesystem-based web shell / backdoor detection.

Usage: python3 webshell_hunter.py scan --path /var/www/html
       python3 webshell_hunter.py --help
"""

import sys

if sys.version_info < (3, 10):  # pragma: no cover
    sys.exit("webshell-hunter requires Python 3.10+")

from scanner.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
