"""CLI entry point for audit-mcp."""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="audit-mcp — graph-first source code audit server")
    parser.add_argument("--mode", choices=["mcp", "http"], default="mcp", help="Transport mode")
    parser.add_argument("--port", type=int, default=18822, help="HTTP port (http mode only)")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address")
    parser.add_argument(
        "--workers", type=int, default=None,
        help=(
            "uvicorn worker count (http mode only). Defaults to "
            "AUDIT_MCP_WORKERS env or 1. >1 spawns separate Python "
            "processes — each holds its own engine + semble + GPU "
            "caches so peak RAM scales linearly."
        ),
    )
    args = parser.parse_args()

    if args.mode == "http":
        from audit_mcp.http_api import run_http
        run_http(host=args.host, port=args.port, workers=args.workers)
    else:
        from audit_mcp.server import run_mcp
        run_mcp()
    return 0


if __name__ == "__main__":
    sys.exit(main())
