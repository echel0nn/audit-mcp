"""HTTP transport for Trailmark MCP tools.

Auto-introspects every ``@mcp.tool()``-registered tool from
:mod:`audit_mcp.server` and exposes it as ``POST /tools/{name}``. The
``mcp`` and ``index_manager`` singletons are shared with the stdio path so
HTTP and stdio callers see the same in-memory index registry.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from fastapi import Body, FastAPI

from audit_mcp.server import index_manager, mcp

__all__ = ["create_app", "run_http"]

_log = logging.getLogger(__name__)

_TOOL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    RuntimeError,
    KeyError,
    TypeError,
    OSError,
    LookupError,
)


def _tool_index() -> dict[str, Any]:
    """Build a name->tool dict from FastMCP's local provider."""
    import asyncio

    tools = asyncio.run(mcp._local_provider.list_tools())
    return {t.name: t for t in tools}

def _make_handler(fn: Callable[..., Any], tool_name: str) -> Callable[..., Any]:
    """Build a FastAPI POST handler that proxies a single tool function."""

    def handler(payload: dict[str, Any] | None = Body(default=None)) -> Any:
        params = payload if payload is not None else {}
        if not isinstance(params, dict):
            return {
                "status": "error",
                "error": (
                    f"Tool {tool_name} expects a JSON object body; "
                    f"got {type(params).__name__}"
                ),
            }
        try:
            return fn(**params)
        except _TOOL_EXCEPTIONS as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    handler.__name__ = f"call_{tool_name}"
    return handler


def create_app() -> FastAPI:
    """Build a FastAPI app with one POST route per MCP tool."""
    app = FastAPI(
        title="Trailmark MCP — HTTP API",
        description="HTTP transport mirroring the MCP stdio tool surface.",
        version="0.1.0",
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "tools": len(_tool_index()),
            "indexes": len(index_manager.list_indexes()),
        }

    @app.get("/tools")
    def list_tools() -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            }
            for tool in _tool_index().values()
        ]

    for name, tool in _tool_index().items():
        if getattr(tool, "is_async", False):
            raise RuntimeError(
                f"Async tools are not supported by the HTTP transport: {name}"
            )
        summary = (tool.description or name).strip().splitlines()[0]
        app.add_api_route(
            path=f"/tools/{name}",
            endpoint=_make_handler(tool.fn, name),
            methods=["POST"],
            name=name,
            summary=summary[:120],
            response_model=None,
        )

    return app


def run_http(host: str | None = None, port: int | None = None) -> None:
    """Run the HTTP API server with uvicorn.

    Host/port may be overridden via env vars ``AUDIT_MCP_HTTP_HOST``
    (default ``127.0.0.1``) and ``AUDIT_MCP_HTTP_PORT`` (default ``18822``).

    Worker count is controlled by ``AUDIT_MCP_WORKERS`` (default 1).
    When >1, each worker is a separate Python process with its own
    GIL — slow CPU-bound calls in one worker (e.g. read_function on
    a giant firefox function) no longer block other workers from
    serving requests. Trade-off: every worker maintains its own
    in-memory caches (TypeResolver, semble index, GPU CSR) so peak
    RAM scales linearly with worker count, and the first call to
    each worker pays the cold-build cost independently.

    AILA's AuditMcpBridgeTool addresses the cold-build issue by
    issuing a parallel pre-warm fan-out on the first call to a new
    index_id, so all workers warm together rather than serially as
    requests trickle in.
    """
    import uvicorn  # local import: stdio path doesn't need uvicorn loaded

    resolved_host = host or os.environ.get("AUDIT_MCP_HTTP_HOST", "127.0.0.1")
    resolved_port = port or int(os.environ.get("AUDIT_MCP_HTTP_PORT", "18822"))
    workers = int(os.environ.get("AUDIT_MCP_WORKERS", "1"))
    if workers > 1:
        # Multi-worker: uvicorn requires a string import path + factory
        # flag so each worker process can re-import + call create_app.
        uvicorn.run(
            "audit_mcp.http_api:create_app",
            factory=True,
            host=resolved_host,
            port=resolved_port,
            workers=workers,
            log_level="info",
        )
    else:
        # Single worker: passing the app instance directly avoids the
        # import-path overhead and works for stdio + dev setups.
        uvicorn.run(
            create_app(),
            host=resolved_host,
            port=resolved_port,
            log_level="info",
        )
