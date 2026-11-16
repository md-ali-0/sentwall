#!/usr/bin/env python3
"""VulnScope CLI entrypoint for `python -m vulnscope`."""
import os
import sys

# Ensure parent directory is on sys.path so scan.py can be loaded
_parent = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from scan import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
