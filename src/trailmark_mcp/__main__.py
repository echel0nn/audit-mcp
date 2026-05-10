"""CLI entry point for trailmark-mcp."""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Trailmark MCP — code graph server")
    parser.add_argument("--mode", choices=["mcp", "http"], default="mcp", help="Transport mode")
    parser.add_argument("--port", type=int, default=18822, help="HTTP port (http mode only)")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address")
    args = parser.parse_args()

    if args.mode == "http":
        from trailmark_mcp.http_api import run_http
        run_http(host=args.host, port=args.port)
    else:
        from trailmark_mcp.server import run_mcp
        run_mcp()
    return 0


if __name__ == "__main__":
    sys.exit(main())
