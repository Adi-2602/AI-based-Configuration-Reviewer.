"""Allow running the tool with ``python -m config_reviewer``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
