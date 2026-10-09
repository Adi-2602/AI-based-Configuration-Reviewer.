"""Run the web UI: ``python -m config_reviewer.web`` (or ``config-reviewer-web``)."""

import sys

from .app import main

if __name__ == "__main__":
    sys.exit(main())
