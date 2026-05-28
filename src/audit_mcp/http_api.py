"""HTTP transport for Trailmark MCP tools (async-first).

Auto-introspects every ``@mcp.tool()``-registered tool from
:mod:`audit_mcp.server` and exposes it as ``POST /tools/{name}``. The
``mcp`` and ``index_manager`` singletons are shared with the stdio path
so HTTP and stdio callers see the same in-memory index registry.

Concurrency model (revision: async-first, 2026-05-28)
─────────────────────────────────────────────────────
Every handler is ``async def`` and offloads the underlying sync tool
function to anyio's worker-thread pool via :func:`audit_mcp.async_runtime.run_tool`.
That runtime layer adds three things the original sync handler lacked:

  * **Per-tool semaphores** — caps concurrent calls per tool name so
    one expensive tool (``index_codebase``) cannot starve every other
    tool by saturating the threadpool.
  * **In-flight dedup** — sibling investigation branches firing
    identical ``(tool_name, kwargs)`` collapse onto the same in-flight
    work item, amortising the cost across all waiters.
  * **Wall-clock timeouts** — every tool has a per-name timeout
    (configurable via env). A stuck call returns a timeout-shaped
    error envelope instead of pinning a worker forever.

Async tools (``tool.is_async == True``) are now supported transparently
— they're awaited directly without thread offload, but still gated by
the same semaphore + dedup + timeout. Previously the HTTP transport
refused them outright at startup.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from fastapi import Body, FastAPI

from audit_mcp.async_runtime import (
    configure_thread_pool,
    run_tool,
    runtime_stats,
)
from audit_mcp.server import index_manager, mcp

__all__ = ["create_app", "run_http"]

_log = logging.getLogger(__name__)

# Errors here are surfaced as ``{"status": "error", ...}`` dicts by
# :func:`audit_mcp.async_runtime.run_tool`. We list the canonical
# tool-side exceptions so we don't accidentally trap programmer
# errors (e.g. ``SystemExit`` from a test harness) inside the same
# net.
_TOOL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    RuntimeError,
    KeyError,
    TypeError,
    OSError,
    LookupError,
)


_TOOL_INDEX_CACHE: dict[str, Any] | None = None


def _tool_index() -> dict[str, Any]:
    """Build a name->tool dict from FastMCP's local provider, cached.

    Loop-aware: in single-worker mode uvicorn loads the app BEFORE
    starting its event loop, so ``asyncio.run`` works. In multi-worker
    (factory=True) mode each spawned worker calls ``create_app`` from
    INSIDE its event loop — ``asyncio.run`` raises
    ``RuntimeError: cannot be called from a running event loop``.
    Fall through to a worker thread in that case.

    The result is cached at module level after first build — tool
    decorators register at import time so the tool set never changes
    after that. /health and /tools used to pay the asyncio dance on
    every request (~670ms per /health on a multi-worker setup); now
    they're a dict lookup.
    """
    global _TOOL_INDEX_CACHE
    if _TOOL_INDEX_CACHE is not None:
        return _TOOL_INDEX_CACHE

    import asyncio
    import concurrent.futures

    try:
        asyncio.get_running_loop()
        in_loop = True
    except RuntimeError:
        in_loop = False

    if in_loop:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            tools = pool.submit(
                lambda: asyncio.run(mcp._local_provider.list_tools()),
            ).result()
    else:
        tools = asyncio.run(mcp._local_provider.list_tools())
    _TOOL_INDEX_CACHE = {t.name: t for t in tools}
    return _TOOL_INDEX_CACHE

def _make_handler(
    fn: Callable[..., Any],
    tool_name: str,
    *,
    is_async: bool,
) -> Callable[..., Any]:
    """Build an async FastAPI POST handler that proxies a single MCP tool.

    The returned handler is always ``async def``. For sync tools, the
    actual work is offloaded to anyio's thread pool via
    :func:`audit_mcp.async_runtime.run_tool`, which also applies the
    per-tool semaphore, in-flight dedup, and wall-clock timeout. For
    async tools, the runtime awaits the coroutine directly under the
    same protections.
    """

    async def handler(payload: dict[str, Any] | None = Body(default=None)) -> Any:
        params = payload if payload is not None else {}
        if not isinstance(params, dict):
            return {
                "status": "error",
                "error": (
                    f"Tool {tool_name} expects a JSON object body; "
                    f"got {type(params).__name__}"
                ),
            }
        if is_async:
            # Async tool: the underlying coroutine is fast (we hope),
            # and we still want the dedup + cap + timeout. Wrap it as
            # a tiny sync facade that drives the coroutine on a fresh
            # thread-local event loop. Async-native execution lives in
            # _make_async_runner so the dedup key shape stays identical
            # to sync tools.
            return await _run_async_tool(fn, params, tool_name)
        return await run_tool(tool_name, fn, params)

    handler.__name__ = f"call_{tool_name}"
    return handler


async def _run_async_tool(
    coro_fn: Callable[..., Any],
    kwargs: dict[str, Any],
    tool_name: str,
) -> Any:
    """Drive a native-async MCP tool under the same semaphore + dedup +
    timeout discipline that :func:`run_tool` applies to sync tools.

    Implementation note: ``run_tool`` is built around
    ``anyio.to_thread.run_sync``, which insists on a sync callable.
    For native-async tools we bypass the thread offload and await the
    coroutine directly inside the dedup wrapper, still inside the
    semaphore + timeout.
    """
    import asyncio
    import time

    from audit_mcp.async_runtime import (  # noqa: PLC0415 — avoid circulars
        _ensure_runtime,
        _timeout_for,
    )

    deduper, semaphores = _ensure_runtime()
    key = deduper.key_for(tool_name, kwargs)
    timeout_s = _timeout_for(tool_name)

    async def _do_work() -> Any:
        sem = semaphores.for_tool(tool_name)
        async with sem:
            t0 = time.time()
            try:
                return await asyncio.wait_for(
                    coro_fn(**kwargs), timeout=timeout_s,
                )
            except TimeoutError:
                elapsed = time.time() - t0
                _log.warning(
                    "async tool %s TIMED OUT after %.1fs (cap=%.1fs)",
                    tool_name, elapsed, timeout_s,
                )
                return {
                    "status": "error",
                    "error": (
                        f"tool {tool_name!r} exceeded its {timeout_s:.0f}s "
                        f"wall-clock timeout."
                    ),
                    "timeout_s": timeout_s,
                    "elapsed_s": round(elapsed, 1),
                }
            except _TOOL_EXCEPTIONS as exc:
                return {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }

    return await deduper.get_or_create(key, _do_work)


def create_app() -> FastAPI:
    """Build a FastAPI app with one async POST route per MCP tool."""
    app = FastAPI(
        title="Trailmark MCP — HTTP API (async-first)",
        description="HTTP transport mirroring the MCP stdio tool surface.",
        version="0.2.0",
    )

    @app.on_event("startup")
    async def _resize_threadpool() -> None:
        # Has to run inside the event loop — anyio's default limiter
        # is a per-loop singleton, so we can't touch it from
        # create_app() (which uvicorn calls BEFORE booting the loop
        # in single-worker mode). Startup event guarantees we're
        # already on the running loop.
        applied_limit = configure_thread_pool()
        _log.info("async runtime: thread pool limit set to %d", applied_limit)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.2.0",
            "tools": len(_tool_index()),
            "indexes": len(index_manager.list_indexes()),
        }

    @app.get("/tools")
    async def list_tools() -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            }
            for tool in _tool_index().values()
        ]

    @app.get("/runtime")
    async def runtime() -> dict[str, Any]:
        """Snapshot of dedup hit-rate, per-tool semaphore availability,
        and threadpool size. Cheap; safe to poll for ops dashboards."""
        return runtime_stats()

    async_count = 0
    sync_count = 0
    for name, tool in _tool_index().items():
        is_async = bool(getattr(tool, "is_async", False))
        if is_async:
            async_count += 1
        else:
            sync_count += 1
        summary = (tool.description or name).strip().splitlines()[0]
        app.add_api_route(
            path=f"/tools/{name}",
            endpoint=_make_handler(tool.fn, name, is_async=is_async),
            methods=["POST"],
            name=name,
            summary=summary[:120],
            response_model=None,
        )
    _log.info(
        "async runtime: mounted %d tools (%d sync + %d async)",
        sync_count + async_count, sync_count, async_count,
    )

    return app


def run_http(
    host: str | None = None,
    port: int | None = None,
    workers: int | None = None,
) -> None:
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
    if workers is None:
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
