"""Async-first runtime primitives for the HTTP tool transport.

The HTTP layer in :mod:`audit_mcp.http_api` historically mounted every
MCP tool as a synchronous FastAPI handler. FastAPI delegated each call
to an anyio worker thread (default pool cap = 40). Under concurrent
load — common with multi-branch VR investigations firing parallel
``semantic_search`` / ``read_function`` calls — the pool either:

  (a) saturated, queuing the 41st request indefinitely at the TCP
      listener;
  (b) serialized on the GIL inside the running threads, since most
      audit_mcp tools are pure-Python CPU-bound work;
  (c) wasted compute by running the same expensive search N times
      for N sibling branches asking identical questions.

This module implements the small async-side runtime that addresses
all three:

  * :class:`InFlightDedup` — per-tool request-key cache. When N
    callers issue the same ``(tool_name, canonical_kwargs)`` while
    no result has been emitted yet, the first caller does the work
    and all N waiters await the same ``asyncio.Future``.
  * :class:`ToolSemaphores` — per-tool concurrency caps. GPU-touching
    tools (``semantic_search``, ``find_related``) cap lower than
    cheap graph queries.
  * :func:`run_tool` — wraps a sync tool callable, applies the
    semaphore + dedup, runs the actual work inside
    :func:`asyncio.to_thread`, enforces a per-tool timeout, and
    surfaces failures as a tool-shaped ``{"status": "error", ...}``
    dict so callers never see an exception escape.

All knobs (semaphore caps, timeouts, thread-pool size) are
overridable via env vars so an operator can tune per host without a
redeploy. Defaults target a single-worker Windows host with one
RTX-class GPU; safe for multi-worker too because state is per
process.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

import anyio.to_thread

__all__ = [
    "InFlightDedup",
    "ToolSemaphores",
    "configure_thread_pool",
    "run_tool",
    "DEFAULT_TOOL_CAPS",
    "DEFAULT_TOOL_TIMEOUTS_S",
]

_log = logging.getLogger(__name__)


# --- per-tool concurrency caps ------------------------------------------
# Numbers are deliberately conservative on the GPU-touching tools.
# `semantic_search` / `find_related` both hit semble's CSR + reranker;
# beyond ~4 concurrent calls the GPU memory + CSR build cache starts
# thrashing. Pure graph queries (`callers_of`, `complexity_hotspots`)
# scale further. `index_codebase` is gated at 1 — heavy enough that two
# concurrent index runs would peg the box.
DEFAULT_TOOL_CAPS: dict[str, int] = {
    "semantic_search":     4,
    "find_related":        4,
    "read_function":       8,
    "search_functions":   16,
    "search_constants":   16,
    "search_macros":      16,
    "search_bitfields":   16,
    "callers_of":         16,
    "callees_of":         16,
    "ancestors_of":       16,
    "reachable_from":     16,
    "paths_between":       8,
    "taint_paths_to":      8,
    "complexity_hotspots": 8,
    "attack_surface":      4,
    "dead_code":           2,   # expensive whole-graph walk
    "unreachable_from_entrypoints": 2,
    "index_codebase":      1,
    "clone_repo":          2,
    "deep_audit":          1,
    "run_scanner":         2,
    "scan_and_correlate":  2,
    # Default for any tool not listed below.
    "__default__":        16,
}


# --- per-tool wall-clock timeouts ---------------------------------------
# The default 120s is sized for the slowest "interactive" tool we ship.
# Heavy long-running tools get explicit overrides. A timeout fires from
# the perspective of the async caller — the underlying worker thread
# cannot be force-killed (Python has no thread kill primitive), so the
# work continues to completion in the background and its result is
# discarded. Repeated timeouts on the same tool indicate either (a) a
# truly stuck call deserving operator investigation, or (b) too-low a
# cap.
DEFAULT_TOOL_TIMEOUTS_S: dict[str, float] = {
    "semantic_search":     90.0,
    "find_related":        90.0,
    "read_function":       30.0,
    "search_functions":    30.0,
    "search_constants":    30.0,
    "search_macros":       30.0,
    "search_bitfields":    30.0,
    "callers_of":          30.0,
    "callees_of":          30.0,
    "complexity_hotspots": 60.0,
    "attack_surface":      60.0,
    "dead_code":          300.0,
    "unreachable_from_entrypoints": 300.0,
    "deep_audit":         600.0,
    "run_scanner":        900.0,
    "scan_and_correlate": 900.0,
    "clone_repo":         600.0,
    "index_codebase":    7200.0,  # 2h cap for monorepo cold index
    "__default__":        120.0,
}


def _canonical_kwargs(kwargs: dict[str, Any]) -> str:
    """JSON-canonical kwargs for dedup keying.

    Sorting keys + default repr means callers that pass the same
    logical arg set in different dict orderings still collide on the
    same dedup key.
    """
    try:
        return json.dumps(kwargs, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(sorted(kwargs.items()))


# ----------------------------------------------------------------------
# InFlightDedup
# ----------------------------------------------------------------------


class InFlightDedup:
    """Coalesce concurrent identical tool calls onto one in-flight future.

    Keyed by ``(tool_name, sha256(canonical_kwargs))``. Hits cap latency
    of waiters to the source-call's latency; misses degrade to a normal
    function call. The dedup is **strict equality on the kwargs JSON**
    — two callers with semantically-equivalent but lexically-different
    kwargs (e.g. ``filter_languages=None`` vs ``filter_languages=[]``)
    DO NOT collide and each pays their own cost. That's the right
    trade-off: false positives in the cache key are far worse than
    missing some dedup wins.

    Entries auto-evict the moment the source call resolves; this is
    a "while-in-flight only" cache, not a result memoizer. The MCP
    tool itself may already have a downstream cache (semble pickle,
    trailmark engine LRU); we don't try to replicate that here.
    """

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def key_for(tool_name: str, kwargs: dict[str, Any]) -> str:
        canonical = _canonical_kwargs(kwargs)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"{tool_name}:{digest}"

    async def get_or_create(
        self,
        key: str,
        producer: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Run ``producer()`` once for ``key``; wait on the same future
        for concurrent callers with the same key."""
        async with self._lock:
            existing = self._inflight.get(key)
            if existing is not None:
                self._hits += 1
                fut = existing
            else:
                self._misses += 1
                loop = asyncio.get_running_loop()
                fut = loop.create_future()
                self._inflight[key] = fut

        if existing is not None:
            return await fut

        try:
            result = await producer()
        except BaseException as exc:  # noqa: BLE001 — propagate to all waiters
            async with self._lock:
                self._inflight.pop(key, None)
            if not fut.done():
                fut.set_exception(exc)
            raise

        async with self._lock:
            self._inflight.pop(key, None)
        if not fut.done():
            fut.set_result(result)
        return result

    def stats(self) -> dict[str, int]:
        return {
            "inflight": len(self._inflight),
            "hits": self._hits,
            "misses": self._misses,
        }


# ----------------------------------------------------------------------
# ToolSemaphores
# ----------------------------------------------------------------------


class ToolSemaphores:
    """Per-tool concurrency limiter.

    Owns one :class:`asyncio.Semaphore` per tool name. Acquire the
    semaphore BEFORE submitting work to the thread pool; this caps
    the number of pool slots a single tool can consume and prevents
    one tool from starving the others.

    Caps come from :data:`DEFAULT_TOOL_CAPS`, overridable via env var
    ``AUDIT_MCP_TOOL_CAP_<TOOLNAME_UPPER>``. Unknown tools get the
    ``__default__`` cap.
    """

    def __init__(self, caps: dict[str, int] | None = None) -> None:
        merged = dict(DEFAULT_TOOL_CAPS)
        if caps:
            merged.update(caps)
        for tool_name, default_cap in list(merged.items()):
            env_key = f"AUDIT_MCP_TOOL_CAP_{tool_name.upper()}"
            override = os.environ.get(env_key)
            if override:
                try:
                    merged[tool_name] = max(1, int(override))
                except ValueError:
                    _log.warning(
                        "ignoring non-integer env override %s=%r",
                        env_key, override,
                    )
        self._caps = merged
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def for_tool(self, tool_name: str) -> asyncio.Semaphore:
        sem = self._semaphores.get(tool_name)
        if sem is None:
            cap = self._caps.get(tool_name, self._caps.get("__default__", 16))
            sem = asyncio.Semaphore(cap)
            self._semaphores[tool_name] = sem
        return sem

    def cap_for(self, tool_name: str) -> int:
        return self._caps.get(tool_name, self._caps.get("__default__", 16))

    def stats(self) -> dict[str, Any]:
        """Snapshot of {tool_name: {cap, available}}.

        ``available`` reflects how many slots are NOT currently held —
        a cheap proxy for "is this tool the bottleneck right now".
        """
        out: dict[str, Any] = {}
        for tool_name, sem in self._semaphores.items():
            cap = self._caps.get(tool_name, self._caps.get("__default__", 16))
            # asyncio.Semaphore._value is internal but stable — public
            # API has no introspection.
            available = getattr(sem, "_value", -1)
            out[tool_name] = {"cap": cap, "available": available}
        return out


# ----------------------------------------------------------------------
# Threadpool sizing
# ----------------------------------------------------------------------


def configure_thread_pool(limit: int | None = None) -> int:
    """Resize the anyio default thread limiter.

    FastAPI/Starlette dispatch sync handlers through anyio's
    ``current_default_thread_limiter()``. The default is 40 — fine for
    short I/O-bound work, too small for our mix where a single
    ``index_codebase`` call can occupy a slot for hours.

    Resolves order:
      1. Explicit ``limit`` argument.
      2. Env ``AUDIT_MCP_THREAD_POOL_LIMIT``.
      3. Fallback: 64.

    Returns the limit that was applied.
    """
    if limit is None:
        env = os.environ.get("AUDIT_MCP_THREAD_POOL_LIMIT")
        limit = int(env) if env else 64
    limit = max(8, limit)  # never go below 8 — risk of trivial starvation
    limiter = anyio.to_thread.current_default_thread_limiter()
    limiter.total_tokens = limit
    return limit


# ----------------------------------------------------------------------
# run_tool — the unified async entry point
# ----------------------------------------------------------------------


# Module-level singletons. Wire-up happens in http_api.create_app at
# startup so tests can substitute their own instances.
_DEDUP: InFlightDedup | None = None
_SEMS: ToolSemaphores | None = None


def reset_runtime() -> None:
    """Reset module-level dedup + semaphore state. For tests."""
    global _DEDUP, _SEMS
    _DEDUP = None
    _SEMS = None


def _ensure_runtime() -> tuple[InFlightDedup, ToolSemaphores]:
    global _DEDUP, _SEMS
    if _DEDUP is None:
        _DEDUP = InFlightDedup()
    if _SEMS is None:
        _SEMS = ToolSemaphores()
    return _DEDUP, _SEMS


def _timeout_for(tool_name: str) -> float:
    env_key = f"AUDIT_MCP_TIMEOUT_{tool_name.upper()}"
    override = os.environ.get(env_key)
    if override:
        try:
            return max(1.0, float(override))
        except ValueError:
            _log.warning(
                "ignoring non-numeric env override %s=%r",
                env_key, override,
            )
    if tool_name in DEFAULT_TOOL_TIMEOUTS_S:
        return DEFAULT_TOOL_TIMEOUTS_S[tool_name]
    return DEFAULT_TOOL_TIMEOUTS_S["__default__"]


async def run_tool(
    tool_name: str,
    fn: Callable[..., Any],
    kwargs: dict[str, Any],
    *,
    dedup: bool = True,
) -> Any:
    """Run a sync MCP tool function from the async HTTP layer.

    Pipeline:
      1. Build dedup key from ``(tool_name, canonical(kwargs))``.
      2. Acquire the tool's semaphore (waits in event loop, not in
         the thread pool).
      3. Schedule ``fn(**kwargs)`` on ``anyio.to_thread.run_sync``.
      4. Race the work against the tool's wall-clock timeout.
      5. Return the result dict (or a tool-shaped error dict on
         failure).

    Concurrent callers with matching dedup keys collapse onto a single
    in-flight execution. The semaphore is acquired once per unique
    work item, not per caller.

    All exceptions are caught and surfaced as
    ``{"status": "error", "error": ...}`` so the FastAPI handler can
    return a normal 200 + JSON envelope. This matches the existing
    behavior of the sync handler in ``http_api._make_handler``.
    """
    deduper, semaphores = _ensure_runtime()
    key = deduper.key_for(tool_name, kwargs)
    timeout_s = _timeout_for(tool_name)

    async def _do_work() -> Any:
        sem = semaphores.for_tool(tool_name)
        async with sem:
            t0 = time.time()
            try:
                # asyncio.to_thread is the modern wrapper around
                # loop.run_in_executor; anyio.to_thread.run_sync uses
                # the same limiter we resize at startup.
                result = await asyncio.wait_for(
                    anyio.to_thread.run_sync(
                        lambda: fn(**kwargs),
                        abandon_on_cancel=True,
                    ),
                    timeout=timeout_s,
                )
                elapsed = time.time() - t0
                if elapsed > timeout_s * 0.8:
                    _log.warning(
                        "tool %s near timeout: %.1fs / %.1fs cap (args=%s)",
                        tool_name, elapsed, timeout_s,
                        _canonical_kwargs(kwargs)[:200],
                    )
                return result
            except TimeoutError:
                elapsed = time.time() - t0
                _log.warning(
                    "tool %s TIMED OUT after %.1fs (cap=%.1fs, args=%s)",
                    tool_name, elapsed, timeout_s,
                    _canonical_kwargs(kwargs)[:200],
                )
                return {
                    "status": "error",
                    "error": (
                        f"tool {tool_name!r} exceeded its {timeout_s:.0f}s "
                        f"wall-clock timeout. The underlying work may still "
                        f"complete in the background; retry the same call "
                        f"to either dedup onto the now-running invocation "
                        f"or get a fresh attempt."
                    ),
                    "timeout_s": timeout_s,
                    "elapsed_s": round(elapsed, 1),
                }
            except Exception as exc:  # noqa: BLE001 — match handler shape
                _log.exception(
                    "tool %s raised %s", tool_name, type(exc).__name__,
                )
                return {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }

    if not dedup:
        return await _do_work()
    return await deduper.get_or_create(key, _do_work)


def runtime_stats() -> dict[str, Any]:
    """Aggregate runtime telemetry for the ``/runtime`` debug endpoint."""
    deduper, semaphores = _ensure_runtime()
    return {
        "dedup": deduper.stats(),
        "semaphores": semaphores.stats(),
        "thread_pool_limit": anyio.to_thread.current_default_thread_limiter().total_tokens,
    }
