"""Standalone semble-build worker — runs in a separate Python process.

Invoked as ``python -m audit_mcp._semble_build <root_path> <cache_path>``.
Loads the potion-code-16M model, builds a SembleIndex from ``root_path``,
pickles it to ``cache_path``. Exits 0 on success, non-zero on failure with
a one-line error on stderr.

Why a separate process: the parent audit_mcp's single uvicorn worker
serves HTTP traffic. The semble build is pure-Python CPU work that holds
the GIL for minutes (firefox-scale: ~85 min). Running it in the parent
process — even in a daemon thread — slows every other HTTP call because
the GIL gets passed back and forth. A separate process has its own GIL,
its own memory, and exits cleanly once done.

The parent's lightweight poller thread checks process.poll() periodically,
loads the resulting pickle into parent memory on success, and updates
the IndexEntry's semble_status field. No IPC channel needed — pickle on
disk is the protocol.
"""
from __future__ import annotations

import argparse
import logging
import os
import pickle
import sys
import time
from pathlib import Path

_log = logging.getLogger("audit_mcp.semble_build")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a semble index for one repo")
    parser.add_argument("root_path", help="Source repo root")
    parser.add_argument("cache_path", help="Output .pkl path")
    parser.add_argument(
        "--model-dir", default=None,
        help="Local potion-code-16M dir; defaults to ~/.semble-models/potion-code-16M",
    )
    args = parser.parse_args()

    root_path = args.root_path
    cache_path = Path(args.cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    model_dir = args.model_dir
    if model_dir is None:
        env_dir = os.environ.get("AUDIT_MCP_SEMBLE_MODEL_DIR", "")
        if env_dir:
            model_dir = env_dir
        else:
            default = Path.home() / ".semble-models" / "potion-code-16M"
            if default.is_dir():
                model_dir = str(default)

    try:
        from model2vec import StaticModel
    except ImportError as exc:
        print(f"model2vec import failed: {exc}", file=sys.stderr)
        return 2

    try:
        from semble import SembleIndex
    except ImportError as exc:
        print(f"semble import failed: {exc}", file=sys.stderr)
        return 2

    t0 = time.time()
    try:
        if model_dir and Path(model_dir).is_dir():
            model = StaticModel.from_pretrained(model_dir)
        else:
            model = StaticModel.from_pretrained("minishlab/potion-code-16M")
    except (OSError, RuntimeError) as exc:
        print(f"model load failed: {exc}", file=sys.stderr)
        return 3
    print(f"model loaded in {time.time() - t0:.1f}s", file=sys.stderr)

    t0 = time.time()
    try:
        sidx = SembleIndex.from_path(root_path, model=model)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"semble build failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    print(f"semble built in {time.time() - t0:.1f}s", file=sys.stderr)

    # Strip model before pickle (singleton Encoder may not pickle cleanly
    # across versions; parent re-attaches its own model on load).
    t0 = time.time()
    try:
        sidx.model = None  # type: ignore[assignment]
        with cache_path.open("wb") as f:
            pickle.dump(sidx, f, protocol=pickle.HIGHEST_PROTOCOL)
    except (pickle.PicklingError, OSError, RecursionError) as exc:
        print(f"pickle write failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 5
    print(f"pickle written in {time.time() - t0:.1f}s ({cache_path.stat().st_size / 1024 / 1024:.0f} MB)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
