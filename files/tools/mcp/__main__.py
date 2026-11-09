"""Carbon MCP entrypoint: one per-role stdio server instance.

Run as ``python files/tools/mcp/__main__.py`` (argv only, no shell).
The role is bound from CARBON_ROLE env via ``files.tools.mcp.stdio``;
see stdio.py for the protocol. This file only fixes sys.path so
``core``, ``git``, ``files.tools.mcp.core`` etc. import cleanly both
as a script file and as ``python -m files.tools.mcp``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_root = _here.parents[2]
for _p in (str(_here), str(_root)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:  # ``python -m files.tools.mcp`` carries a package context
    from . import stdio  # type: ignore
except ImportError:
    import stdio  # type: ignore

if __name__ == "__main__":
    raise SystemExit(stdio.main())
