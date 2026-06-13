"""Enable ``python -m mnemosyne`` as an alternative to the ``mnemosyne`` command."""

from __future__ import annotations

import sys

from mnemosyne.cli import main

if __name__ == "__main__":
    sys.exit(main())
