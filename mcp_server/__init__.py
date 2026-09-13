"""AuthScope MCP server: expose the scan API to agents over MCP.

See ``docs/MCP.md``. The package is an optional extra:

    pip install 'authscope[mcp]'

Run over stdio (default)::

    authscope-mcp

Run over Streamable HTTP / SSE::

    authscope-mcp --transport http --host 127.0.0.1 --port 8765
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
