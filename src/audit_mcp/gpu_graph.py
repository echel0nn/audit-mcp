"""GPU-accelerated graph engine with automatic CPU fallback.

Converts trailmark's CodeGraph (Python dicts + lists) into a CSR sparse
adjacency matrix and runs BFS / reachability / blast radius via sparse
matrix-vector multiplication (SpMV).

GPU path: ``cupyx.scipy.sparse`` on NVIDIA GPUs via CuPy.
CPU path: ``scipy.sparse`` — same API, same results, ~16-56x slower
          on large graphs (benchmarked on RTX 3080).

The engine is built once at index time and reused for all queries.
Transfer to GPU happens once; subsequent SpMV operations stay on-device.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np
import scipy.sparse as sp_sparse

__all__ = ["GpuGraphEngine", "from_trailmark"]

_log = logging.getLogger(__name__)

# Below this edge count, GPU transfer overhead exceeds the compute gain.
_GPU_THRESHOLD = 50_000


def _try_import_cupy() -> tuple[Any, Any, bool]:
    """Import CuPy + check CUDA availability. Returns (cp, gpu_sparse, ok)."""
    try:
        import cupy as cp
        import cupyx.scipy.sparse as gpu_sparse

        if not cp.cuda.is_available():
            return None, None, False
        # Quick sanity — can we actually create a sparse matrix?
        _test = gpu_sparse.csr_matrix(sp_sparse.eye(2, format="csr"))
        del _test
        return cp, gpu_sparse, True
    except (ImportError, RuntimeError, OSError):
        return None, None, False


class GpuGraphEngine:
    """Adaptive CPU/GPU graph traversal engine.

    All public methods accept and return node *names* (strings) so the
    caller never touches indices or sparse matrices. The conversion is
    internal.

    Parameters
    ----------
    adj_csr : scipy.sparse.csr_matrix
        Call-edge adjacency matrix (source → target). Shape ``(n, n)``.
    node_names : list[str]
        Ordered node names matching the matrix rows/columns.
    node_dicts : list[dict[str, Any]]
        Full trailmark node dicts (with location, complexity, etc.)
        in the same order as *node_names*. Returned in query results
        so callers get the same shape as ``engine.callers_of()``.
    force_cpu : bool
        If True, never use GPU even if available.
    """

    def __init__(
        self,
        adj_csr: sp_sparse.csr_matrix,
        node_names: list[str],
        node_dicts: list[dict[str, Any]],
        force_cpu: bool = False,
    ) -> None:
        self._adj_cpu = adj_csr.astype(np.float32)
        self._adj_t_cpu = adj_csr.T.tocsr().astype(np.float32)  # transpose for callers
        self._names = node_names
        self._dicts = node_dicts
        self._name_to_idx: dict[str, int] = {n: i for i, n in enumerate(node_names)}
        self._n = len(node_names)

        # In-degree (precomputed for hub detection)
        self._in_degree: np.ndarray = np.array(
            self._adj_cpu.T.sum(axis=1), dtype=np.int32,
        ).ravel()

        # GPU state
        self._gpu = False
        self._cp: Any = None
        self._adj_gpu: Any = None
        self._adj_t_gpu: Any = None

        if not force_cpu and self._adj_cpu.nnz >= _GPU_THRESHOLD:
            cp, gpu_sparse, ok = _try_import_cupy()
            if ok:
                try:
                    t0 = time.monotonic()
                    self._adj_gpu = gpu_sparse.csr_matrix(self._adj_cpu)
                    self._adj_t_gpu = gpu_sparse.csr_matrix(self._adj_t_cpu)
                    self._cp = cp
                    self._gpu = True
                    _log.info(
                        "GPU graph engine: %d nodes, %d edges on CUDA (%.1fms transfer)",
                        self._n, self._adj_cpu.nnz,
                        (time.monotonic() - t0) * 1000,
                    )
                except (RuntimeError, MemoryError, OSError) as exc:
                    _log.warning("GPU transfer failed, falling back to CPU: %s", exc)
                    self._gpu = False

        if not self._gpu:
            _log.info(
                "GPU graph engine: %d nodes, %d edges on CPU%s",
                self._n, self._adj_cpu.nnz,
                " (below GPU threshold)" if self._adj_cpu.nnz < _GPU_THRESHOLD else "",
            )

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def using_gpu(self) -> bool:
        return self._gpu

    @property
    def node_count(self) -> int:
        return self._n

    @property
    def edge_count(self) -> int:
        return int(self._adj_cpu.nnz)

    def info(self) -> dict[str, Any]:
        return {
            "backend": "gpu" if self._gpu else "cpu",
            "nodes": self._n,
            "edges": self.edge_count,
            "gpu_threshold": _GPU_THRESHOLD,
        }

    # ------------------------------------------------------------------
    # Single BFS (callees / callers / reachable / ancestors)
    # ------------------------------------------------------------------

    def _resolve(self, name: str) -> int | None:
        return self._name_to_idx.get(name)

    def _idx_to_dicts(self, indices: np.ndarray) -> list[dict[str, Any]]:
        """Map a boolean or index array back to trailmark-shaped dicts."""
        if indices.dtype == bool:
            indices = np.where(indices)[0]
        return [self._dicts[i] for i in indices if 0 <= i < self._n]

    def _spmv_bfs(
        self,
        start_idx: int,
        adj: Any,
        max_depth: int,
    ) -> np.ndarray:
        """Single-source BFS via iterated SpMV. Returns a boolean visited array."""
        if self._gpu:
            cp = self._cp
            frontier = cp.zeros(self._n, dtype=cp.float32)
            frontier[start_idx] = 1.0
            visited = frontier.copy()
            for _ in range(max_depth):
                frontier = adj @ frontier
                frontier = (frontier > 0).astype(cp.float32)
                frontier = frontier * (1.0 - visited)
                if float(frontier.sum()) == 0:
                    break
                visited = cp.clip(visited + frontier, 0, 1)
            return cp.asnumpy(visited).astype(bool)
        else:
            frontier = np.zeros(self._n, dtype=np.float32)
            frontier[start_idx] = 1.0
            visited = frontier.copy()
            for _ in range(max_depth):
                frontier = adj @ frontier
                frontier = (frontier > 0).astype(np.float32)
                frontier = frontier * (1.0 - visited)
                if frontier.sum() == 0:
                    break
                visited = np.clip(visited + frontier, 0, 1)
            return visited.astype(bool)

    def callees_of(self, name: str) -> list[dict[str, Any]]:
        """Direct callees (depth=1 forward BFS).

        Implementation: ``A @ v`` returns predecessors-of-v (rows where
        the matrix has a 1 in any column that v has set). The CSR was
        built with ``rows=src, cols=tgt`` so ``A.T @ v`` gives the true
        forward step (nodes v points TO = nodes v calls). Without the
        transpose, callees_of historically returned callers and vice
        versa across every indexed codebase (nginx, httpd, ollama,
        firefox, litellm verified).
        """
        idx = self._resolve(name)
        if idx is None:
            return []
        adj_t = self._adj_t_gpu if self._gpu else self._adj_t_cpu
        visited = self._spmv_bfs(idx, adj_t, max_depth=1)
        visited[idx] = False
        return self._idx_to_dicts(visited)

    def callers_of(self, name: str) -> list[dict[str, Any]]:
        """Direct callers (depth=1 backward BFS).

        Uses the original (non-transposed) adjacency: ``A @ v`` gives
        predecessors of v, which are callers when edges are stored as
        caller→callee."""
        idx = self._resolve(name)
        if idx is None:
            return []
        adj = self._adj_gpu if self._gpu else self._adj_cpu
        visited = self._spmv_bfs(idx, adj, max_depth=1)
        visited[idx] = False
        return self._idx_to_dicts(visited)

    def reachable_from(self, name: str, max_depth: int = 20) -> list[dict[str, Any]]:
        """All transitively reachable callees (forward direction)."""
        idx = self._resolve(name)
        if idx is None:
            return []
        adj_t = self._adj_t_gpu if self._gpu else self._adj_t_cpu
        visited = self._spmv_bfs(idx, adj_t, max_depth)
        visited[idx] = False
        return self._idx_to_dicts(visited)

    def ancestors_of(self, name: str, max_depth: int = 20) -> list[dict[str, Any]]:
        """All transitive callers (backward direction)."""
        idx = self._resolve(name)
        if idx is None:
            return []
        adj = self._adj_gpu if self._gpu else self._adj_cpu
        visited = self._spmv_bfs(idx, adj, max_depth)
        visited[idx] = False
        return self._idx_to_dicts(visited)

    # ------------------------------------------------------------------
    # Batched BFS (blast radius, unreachable from entrypoints)
    # ------------------------------------------------------------------

    def _batched_bfs(
        self,
        start_indices: list[int],
        adj: Any,
        max_depth: int,
    ) -> np.ndarray:
        """Batched BFS: run ``len(start_indices)`` BFS traversals in one
        sparse matrix multiply per depth level.

        Returns a ``(n, k)`` boolean matrix where column *j* is the visited
        set for ``start_indices[j]``.
        """
        k = len(start_indices)
        if k == 0:
            return np.zeros((self._n, 0), dtype=bool)

        if self._gpu:
            cp = self._cp
            frontier = cp.zeros((self._n, k), dtype=cp.float32)
            for j, idx in enumerate(start_indices):
                frontier[idx, j] = 1.0
            visited = frontier.copy()
            for _ in range(max_depth):
                frontier = adj @ frontier
                frontier = (frontier > 0).astype(cp.float32)
                frontier = frontier * (1.0 - visited)
                if float(frontier.sum()) == 0:
                    break
                visited = cp.clip(visited + frontier, 0, 1)
            return cp.asnumpy(visited).astype(bool)
        else:
            frontier = np.zeros((self._n, k), dtype=np.float32)
            for j, idx in enumerate(start_indices):
                frontier[idx, j] = 1.0
            visited = frontier.copy()
            for _ in range(max_depth):
                frontier = adj @ frontier
                frontier = (frontier > 0).astype(np.float32)
                frontier = frontier * (1.0 - visited)
                if frontier.sum() == 0:
                    break
                visited = np.clip(visited + frontier, 0, 1)
            return visited.astype(bool)

    def blast_radius_batch(
        self,
        names: list[str],
        max_depth: int = 20,
    ) -> dict[str, int]:
        """Compute blast radius for multiple functions simultaneously.

        Returns ``{name: count_of_reachable_nodes}``.
        """
        indices = []
        valid_names = []
        for n in names:
            idx = self._resolve(n)
            if idx is not None:
                indices.append(idx)
                valid_names.append(n)
        if not indices:
            return {}

        adj = self._adj_gpu if self._gpu else self._adj_cpu
        visited = self._batched_bfs(indices, adj, max_depth)

        result: dict[str, int] = {}
        for j, name in enumerate(valid_names):
            col = visited[:, j]
            col[indices[j]] = False  # exclude self
            result[name] = int(col.sum())
        return result

    def unreachable_from(
        self,
        entrypoint_names: list[str],
        max_depth: int = 50,
    ) -> list[dict[str, Any]]:
        """Find all nodes NOT reachable from any entrypoint.

        Runs batched BFS from all entrypoints simultaneously, then
        returns nodes with zero coverage.
        """
        indices = [
            self._resolve(n) for n in entrypoint_names
            if self._resolve(n) is not None
        ]
        if not indices:
            return list(self._dicts)  # no entrypoints = everything unreachable

        adj = self._adj_gpu if self._gpu else self._adj_cpu
        visited = self._batched_bfs(indices, adj, max_depth)

        # Union across all columns: a node is reachable if ANY column is True
        reachable = visited.any(axis=1)
        # Entrypoints themselves are reachable
        for idx in indices:
            reachable[idx] = True
        unreachable_mask = ~reachable
        return self._idx_to_dicts(unreachable_mask)

    # ------------------------------------------------------------------
    # Hub detection (precomputed in-degree)
    # ------------------------------------------------------------------

    def hub_names(self, threshold: int = 100) -> frozenset[str]:
        """Return names of nodes with in-degree > threshold. O(1) after init."""
        mask = self._in_degree > threshold
        return frozenset(self._names[i] for i in np.where(mask)[0])

    def in_degree_of(self, name: str) -> int:
        idx = self._resolve(name)
        return int(self._in_degree[idx]) if idx is not None else 0


# ----------------------------------------------------------------------
# Constructor from trailmark engine
# ----------------------------------------------------------------------


def from_trailmark(engine: Any) -> GpuGraphEngine | None:
    """Build a GpuGraphEngine from a trailmark QueryEngine.

    Extracts call edges from ``engine._store._graph``, maps node IDs to
    indices, builds a CSR adjacency matrix, and returns the engine.

    Returns None if the graph can't be accessed (incompatible trailmark
    version, empty graph, etc.).
    """
    try:
        graph = engine._store._graph
    except AttributeError:
        _log.warning("Cannot access trailmark graph — GPU engine unavailable")
        return None

    nodes = graph.nodes
    edges = graph.edges

    if not nodes:
        return None

    # Build index mapping: node_id → integer index.
    # Start with function/method nodes from the graph, then add phantom
    # nodes for call targets that don't exist as graph nodes (external
    # APIs, libc functions, etc.). Without phantoms we lose 80%+ of edges.
    func_kinds = {"function", "method"}
    ordered_ids: list[str] = []
    ordered_names: list[str] = []
    ordered_dicts: list[dict[str, Any]] = []
    id_to_idx: dict[str, int] = {}

    for nid, node in nodes.items():
        kind_val = getattr(node.kind, "value", str(node.kind))
        if kind_val not in func_kinds:
            continue
        idx = len(ordered_ids)
        ordered_ids.append(nid)
        ordered_names.append(getattr(node, "name", nid))
        id_to_idx[nid] = idx
        loc = getattr(node, "location", None)
        ordered_dicts.append({
            "id": nid,
            "name": getattr(node, "name", nid),
            "kind": kind_val,
            "location": {
                "file_path": getattr(loc, "file_path", "") if loc else "",
                "start_line": getattr(loc, "start_line", 0) if loc else 0,
                "end_line": getattr(loc, "end_line", 0) if loc else 0,
                "start_col": getattr(loc, "start_col", 0) if loc else 0,
                "end_col": getattr(loc, "end_col", 0) if loc else 0,
            },
            "parameters": getattr(node, "parameters", ()),
            "return_type": getattr(node, "return_type", None),
            "exception_types": getattr(node, "exception_types", ()),
            "cyclomatic_complexity": getattr(node, "cyclomatic_complexity", None),
            "branches": getattr(node, "branches", ()),
            "docstring": getattr(node, "docstring", None),
        })

    # Scan call edges and create phantom nodes for unknown targets/sources.
    for edge in edges:
        kind_val = getattr(edge.kind, "value", str(edge.kind))
        if kind_val != "calls":
            continue
        for nid_attr in ("source_id", "target_id"):
            nid = getattr(edge, nid_attr, "")
            if nid and nid not in id_to_idx:
                idx = len(ordered_ids)
                ordered_ids.append(nid)
                # Extract a short name from the qualified id (e.g. "nginx:ngx_getpid" → "ngx_getpid")
                short_name = nid.rsplit(":", 1)[-1] if ":" in nid else nid
                ordered_names.append(short_name)
                id_to_idx[nid] = idx
                ordered_dicts.append({
                    "id": nid,
                    "name": short_name,
                    "kind": "function",
                    "location": {"file_path": "", "start_line": 0, "end_line": 0, "start_col": 0, "end_col": 0},
                    "parameters": (),
                    "return_type": None,
                    "exception_types": (),
                    "cyclomatic_complexity": None,
                    "branches": (),
                    "docstring": None,
                })

    n = len(ordered_ids)
    if n == 0:
        return None

    # Build adjacency matrix from call edges
    rows: list[int] = []
    cols: list[int] = []
    for edge in edges:
        kind_val = getattr(edge.kind, "value", str(edge.kind))
        if kind_val != "calls":
            continue
        src = id_to_idx.get(getattr(edge, "source_id", ""))
        tgt = id_to_idx.get(getattr(edge, "target_id", ""))
        if src is not None and tgt is not None:
            rows.append(src)
            cols.append(tgt)

    data = np.ones(len(rows), dtype=np.float32)
    adj = sp_sparse.csr_matrix((data, (rows, cols)), shape=(n, n))

    _log.info(
        "from_trailmark: %d function nodes, %d call edges → CSR (%d nnz)",
        n, len(rows), adj.nnz,
    )

    return GpuGraphEngine(
        adj_csr=adj,
        node_names=ordered_names,
        node_dicts=ordered_dicts,
    )
