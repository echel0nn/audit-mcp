# audit-mcp Large Codebase Performance — Implementation Plan

Source: `docs/LARGE_CODEBASE_OPTIMIZATION.md` (5-researcher discussion).
Scope: the 5 key findings, prioritized by impact, with exact file changes.

---

## Current State (What Exists)

| File | Responsibility | Perf Problem |
|---|---|---|
| `fast_indexer.py` | Parallel parse + content-hash cache | Graph merge + preanalysis re-run from scratch every warm re-index |
| `indexer.py` | `IndexManager` — thread-per-index lifecycle | Calls `engine.preanalysis()` eagerly on every index; no memory budget |
| `store.py` | `DurableIndexStore` — filesystem persistence | Serializes graph as JSON (slow for large graphs); no LRU eviction |
| `server.py` | 35 MCP tools | All graph queries unbounded — no depth/limit/offset/hub-exclusion |
| `deep_audit.py` | Dead code, unreachable, taint, fuzzing targets | `find_dead_code` calls `engine.callers_of()` per function — O(V×avg_degree) |
| `partitioner.py` | Partition plan for large codebases | Partitions are independent — no cross-partition queries |

---

## Phase 1: Bounded Graph Queries (prevents OOM + timeout)

**Why first:** Without this, a single `ancestors_of("main")` on a 500K-node graph can OOM the process and crash every other loaded index. This is a production safety issue.

### 1.1 Add bounded query wrapper

**New file:** `src/audit_mcp/query_bounds.py` (~120 LOC)

```python
@dataclass(frozen=True, slots=True)
class QueryBounds:
    depth: int = 5          # max BFS/DFS depth (hard cap: 20)
    limit: int = 100        # max results returned (hard cap: 5000)
    offset: int = 0         # pagination offset
    exclude_hubs: bool = True
    hub_threshold: int = 100  # in-degree > this = hub

HARD_DEPTH_CAP = 20
HARD_LIMIT_CAP = 5000

def clamp_bounds(bounds: QueryBounds) -> QueryBounds: ...

@dataclass
class BoundedResult:
    results: list[dict[str, Any]]
    total: int
    returned: int
    truncated: bool
    truncation_hint: str = ""
```

Functions:
- `bounded_ancestors(engine, name, bounds) -> BoundedResult` — BFS with depth cap, hub exclusion, result limit
- `bounded_reachable(engine, name, bounds) -> BoundedResult` — same
- `bounded_callers(engine, name, bounds) -> BoundedResult` — depth=1, hub exclusion
- `bounded_callees(engine, name, bounds) -> BoundedResult` — depth=1
- `bounded_paths(engine, source, target, bounds, max_paths=5) -> BoundedResult` — BFS shortest-first, max_paths cap
- `bounded_search(engine, pattern, bounds) -> BoundedResult` — regex + pagination
- `hub_set(engine, threshold) -> frozenset[str]` — cached set of high-in-degree node names

Implementation details:
- BFS uses `collections.deque` with depth tracking
- Hub detection: one pass over the graph's adjacency list to count in-degrees, cache as `frozenset`
- Hub cache key: `(id(engine), threshold)` with a module-level `functools.lru_cache`

### 1.2 Update server.py tool signatures

**File:** `src/audit_mcp/server.py`

Every traversal tool gains optional parameters:

```python
# Before
@mcp.tool()
def ancestors_of(index_id: str, name: str) -> dict[str, Any]: ...

# After
@mcp.tool()
def ancestors_of(
    index_id: str,
    name: str,
    depth: int = 5,
    limit: int = 100,
    offset: int = 0,
    exclude_hubs: bool = True,
) -> dict[str, Any]: ...
```

Affected tools (8):
- `callers_of` — add `limit`, `offset`, `exclude_hubs`
- `callees_of` — add `limit`, `offset`
- `ancestors_of` — add `depth`, `limit`, `offset`, `exclude_hubs`
- `reachable_from` — add `depth`, `limit`, `offset`, `exclude_hubs`
- `paths_between` — add `depth`, `limit` (here `limit` = max_paths, default 5)
- `entrypoint_paths_to` — add `limit` (max_paths), already has `max_depth`
- `search_functions` — add `limit`, `offset`
- `complexity_hotspots` — add `limit`, `offset` (already has `threshold`)

Response envelope change for ALL of these:

```python
# Before
return {"callers": engine.callers_of(name)}

# After
result = bounded_callers(engine, name, QueryBounds(limit=limit, offset=offset, ...))
return {
    "callers": result.results,
    "total": result.total,
    "returned": result.returned,
    "truncated": result.truncated,
    "truncation_hint": result.truncation_hint,
}
```

### 1.3 Cap `export_graph`

```python
# Before
@mcp.tool()
def export_graph(index_id: str) -> dict[str, Any]:
    return engine.to_json()

# After
@mcp.tool()
def export_graph(index_id: str, max_nodes: int = 10000) -> dict[str, Any]:
    summary = engine.summary()
    node_count = summary.get("functions", 0) + summary.get("classes", 0)
    if node_count > max_nodes:
        return {
            "status": "error",
            "error": f"Graph has {node_count} nodes (cap: {max_nodes}). "
                     "Use plan_partitions to split, or export per-partition.",
            "node_count": node_count,
        }
    return engine.to_json()
```

### 1.4 Tests

**New file:** `tests/test_query_bounds.py` (~150 LOC)

- Test BFS depth enforcement (depth=2 returns only 2 hops)
- Test result limit (limit=10 on 500 ancestors)
- Test offset pagination (offset=10, limit=10 returns items 10-19)
- Test hub exclusion (node with 200 callers excluded when threshold=100)
- Test `export_graph` cap refusal
- Mock engine with a known graph (20 nodes, 50 edges, one hub)

---

## Phase 2: Graph Serialization Cache (eliminates re-merge on warm re-index)

**Why second:** This turns a 12-minute warm re-index into a <30-second graph deserialization. The single highest-impact perf change.

### 2.1 Add msgpack serialization to `store.py`

**File:** `src/audit_mcp/store.py`

Add `msgpack` to dependencies. Change `mark_ready` to serialize graph as msgpack instead of JSON:

```python
# In mark_ready():
# Before
graph_json = engine.to_json()
(ws / "graph.json").write_text(json.dumps(graph_json, default=str), encoding="utf-8")

# After
graph_data = engine.to_json()  # still get the dict from trailmark
packed = msgpack.packb(graph_data, use_bin_type=True, default=str)
(ws / "graph.msgpack").write_bytes(packed)
```

Change `_load_engine_from_disk` to try msgpack first, fall back to JSON:

```python
def _load_engine_from_disk(self, index_id: str) -> Any | None:
    ws = self.workspace(index_id)
    msgpack_file = ws / "graph.msgpack"
    json_file = ws / "graph.json"

    if msgpack_file.exists():
        data = msgpack.unpackb(msgpack_file.read_bytes(), raw=False)
    elif json_file.exists():
        data = json.loads(json_file.read_text(encoding="utf-8"))
    else:
        return None

    graph = CodeGraph.from_dict(data)
    engine = QueryEngine.from_graph(graph)
    return engine
```

### 2.2 Add composite content hash to `fast_indexer.py`

**File:** `src/audit_mcp/fast_indexer.py`

After file discovery, compute a composite hash of all file content hashes. If it matches the stored composite hash, skip merge + preanalysis entirely — load the serialized graph.

```python
def index(self, path, language, progress, skip_preanalysis):
    # ... discover files ...
    composite_hash = self._composite_hash(source_files)

    # Check if a cached graph exists with this exact composite hash
    cached_engine = self._load_cached_graph(composite_hash)
    if cached_engine is not None:
        _log.info("graph cache hit for %s (composite %s)", path, composite_hash[:12])
        return cached_engine

    # ... parallel parse, merge, preanalysis (existing code) ...

    # Save the merged graph keyed by composite hash
    self._save_cached_graph(composite_hash, engine)
    return engine
```

New methods on `FastIndexer`:
- `_composite_hash(files: list[tuple[str, str]]) -> str` — SHA256 of sorted `(relative_path, content_hash)` pairs
- `_load_cached_graph(composite_hash: str) -> QueryEngine | None` — load from `~/.cache/audit-mcp/graphs/<hash>.msgpack`
- `_save_cached_graph(composite_hash: str, engine: QueryEngine) -> None`

### 2.3 Update `pyproject.toml`

Add `msgpack` dependency:

```toml
dependencies = [
    "trailmark>=0.3.0",
    "fastmcp>=0.4.0",
    "fastapi>=0.115.0",
    "uvicorn>=0.30.0",
    "msgpack>=1.0.0",
]
```

### 2.4 Tests

**New file:** `tests/test_graph_cache.py` (~100 LOC)

- Test composite hash stability (same files = same hash)
- Test composite hash changes when one file changes
- Test msgpack round-trip (serialize engine → deserialize → same summary)
- Test JSON fallback when msgpack file absent
- Test cache invalidation on file change

---

## Phase 3: Lazy Preanalysis (eliminates O(V^2) eagerness)

**Why third:** On a 500K-function codebase, `run_preanalysis()` computing blast radius for every node is the dominant cost. Making it lazy eliminates minutes of compute.

### 3.1 Add `LazyPreanalysis` wrapper

**New file:** `src/audit_mcp/lazy_preanalysis.py` (~150 LOC)

```python
class LazyPreanalysis:
    """Wraps a QueryEngine with on-demand preanalysis computation."""

    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._blast_cache: dict[str, int] = {}
        self._taint_cache: dict[str, list] = {}
        self._eager_done = False
        self._entrypoints: list[dict] | None = None
        self._privilege_boundaries: list[dict] | None = None

    def entrypoints(self) -> list[dict]:
        """Eager — always computed. O(V) pattern match."""
        if self._entrypoints is None:
            self._entrypoints = self._engine.attack_surface()
        return self._entrypoints

    def privilege_boundaries(self) -> list[dict]:
        """Eager — always computed."""
        ...

    def blast_radius(self, name: str) -> int:
        """Lazy — computed per node, cached."""
        if name not in self._blast_cache:
            reachable = self._engine.reachable_from(name)
            self._blast_cache[name] = len(reachable)
        return self._blast_cache[name]

    def blast_radius_top_n(self, n: int = 50) -> list[dict]:
        """Deferred batch — compute for top-N by complexity, cache all."""
        ...

    def taint_paths(self, sink: str, max_depth: int = 20) -> list:
        """Lazy — computed per sink, cached."""
        ...

    def full_preanalysis(self) -> dict[str, Any]:
        """Deferred — compute everything, called by preanalysis() tool."""
        return {
            "entrypoints": self.entrypoints(),
            "blast_radius_top_50": self.blast_radius_top_n(50),
            "privilege_boundaries": self.privilege_boundaries(),
        }

    def invalidate(self) -> None:
        """Clear all caches. Called when graph changes (annotation, SARIF import)."""
        self._blast_cache.clear()
        self._taint_cache.clear()
        self._entrypoints = None
        self._privilege_boundaries = None
```

### 3.2 Wire into `IndexManager` and `server.py`

**File:** `src/audit_mcp/indexer.py`

`IndexEntry` gains a `lazy_preanalysis: LazyPreanalysis | None` field.

In `_index_worker`:
```python
# Before
preanalysis = engine.preanalysis()   # <-- expensive eager call

# After
lazy = LazyPreanalysis(engine)
eager_preanalysis = {
    "entrypoints": lazy.entrypoints(),
    "entrypoint_count": len(lazy.entrypoints()),
}
# Blast radius computed later on demand
```

**File:** `src/audit_mcp/server.py`

`preanalysis()` tool calls `lazy.full_preanalysis()` instead of `engine.preanalysis()`.

`complexity_hotspots()` computes blast radius only for functions passing the threshold filter — via `lazy.blast_radius(name)` per qualifying function.

### 3.3 Invalidation on annotation/SARIF

**File:** `src/audit_mcp/server.py`

After `annotate_function`, `augment_sarif`, `run_scanner`, `clear_annotations`:
```python
lazy = _get_lazy_preanalysis(index_id)
if lazy:
    lazy.invalidate()
```

### 3.4 Tests

**New file:** `tests/test_lazy_preanalysis.py` (~120 LOC)

- Test entrypoints computed once, cached
- Test blast_radius computed on demand, cached
- Test invalidate clears all caches
- Test `full_preanalysis` produces same structure as eager version
- Test `blast_radius_top_n` returns sorted top-N

---

## Phase 4: Async Batch Tools (unblocks parallel workflows)

**Why fourth:** `run_scanner` blocks for up to 600 seconds. `dead_code` and `unreachable_from_entrypoints` do full-graph scans that take minutes on large codebases. These must be async.

### 4.1 Add task runner

**New file:** `src/audit_mcp/tasks.py` (~100 LOC)

```python
@dataclass
class TaskRecord:
    task_id: str
    kind: str                          # "scan", "dead_code", "unreachable", etc.
    index_id: str
    status: str = "running"            # running | completed | error
    progress_pct: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: float = 0.0
    finished_at: float = 0.0

class TaskRunner:
    """Submit background tasks, poll for results."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, index_id: str, fn: Callable, **kwargs) -> str:
        task_id = uuid4().hex[:12]
        record = TaskRecord(task_id=task_id, kind=kind, index_id=index_id, started_at=time.time())
        with self._lock:
            self._tasks[task_id] = record
        thread = threading.Thread(target=self._run, args=(task_id, fn, kwargs), daemon=True)
        thread.start()
        return task_id

    def poll(self, task_id: str) -> dict[str, Any]: ...
    def _run(self, task_id, fn, kwargs) -> None: ...
```

### 4.2 Convert blocking tools to async

**File:** `src/audit_mcp/server.py`

Tools that become async:
- `run_scanner` → returns `{"task_id": ..., "status": "running"}`
- `scan_and_correlate` → same
- `dead_code` → same
- `unreachable_from_entrypoints` → same

New tool:
- `poll_task(task_id: str)` → returns status + result when done

```python
task_runner = TaskRunner()

@mcp.tool()
def dead_code(index_id: str) -> dict[str, Any]:
    engine, err = _require_engine(index_id)
    if err:
        return err
    task_id = task_runner.submit("dead_code", index_id, find_dead_code, engine=engine)
    return {"task_id": task_id, "status": "running"}

@mcp.tool()
def poll_task(task_id: str) -> dict[str, Any]:
    return task_runner.poll(task_id)
```

### 4.3 Tests

**New file:** `tests/test_tasks.py` (~80 LOC)

- Test submit + poll lifecycle
- Test error propagation
- Test concurrent tasks

---

## Phase 5: LRU Partition Eviction (enables Chromium-scale without OOM)

**Why fifth:** Depends on bounded queries (Phase 1) being in place so evicted partitions don't get re-loaded by unbounded queries.

### 5.1 Add memory tracking to `IndexManager`

**File:** `src/audit_mcp/indexer.py`

```python
import psutil  # add to deps

class IndexManager:
    def __init__(self, memory_budget_mb: int = 4096) -> None:
        ...
        self._memory_budget_bytes = memory_budget_mb * 1024 * 1024
        self._access_order: list[str] = []  # LRU tracking

    def _touch(self, index_id: str) -> None:
        """Move index_id to most-recently-used position."""
        if index_id in self._access_order:
            self._access_order.remove(index_id)
        self._access_order.append(index_id)

    def _maybe_evict(self) -> None:
        """Evict least-recently-used engines until under budget."""
        process = psutil.Process()
        while process.memory_info().rss > self._memory_budget_bytes and self._access_order:
            victim = self._access_order.pop(0)
            entry = self._indexes.get(victim)
            if entry and entry.engine is not None:
                _log.info("evicting engine %s to stay under memory budget", victim)
                entry.engine = None  # release, graph stays on disk
```

`get_engine` calls `_touch(index_id)` and `_maybe_evict()` after loading.

### 5.2 Add `memory_usage` tool

**File:** `src/audit_mcp/server.py`

```python
@mcp.tool()
def memory_usage() -> dict[str, Any]:
    process = psutil.Process()
    mem = process.memory_info()
    loaded = sum(1 for e in index_manager._indexes.values() if e.engine is not None)
    total = len(index_manager._indexes)
    return {
        "rss_mb": round(mem.rss / (1024 * 1024), 1),
        "vms_mb": round(mem.vms / (1024 * 1024), 1),
        "loaded_indexes": loaded,
        "total_indexes": total,
        "memory_budget_mb": index_manager._memory_budget_bytes // (1024 * 1024),
    }
```

### 5.3 Update `pyproject.toml`

Add `psutil` dependency.

### 5.4 Tests

Add to `tests/test_tasks.py` or new file `tests/test_memory.py` (~60 LOC):
- Test eviction triggers when budget exceeded
- Test LRU ordering (most recent access survives)
- Test evicted engine reloads from disk on next query

---

## Dependency + File Matrix

| Phase | New Files | Modified Files | New Deps | Depends On |
|---|---|---|---|---|
| 1 | `query_bounds.py`, `tests/test_query_bounds.py` | `server.py` | — | — |
| 2 | `tests/test_graph_cache.py` | `store.py`, `fast_indexer.py`, `pyproject.toml` | `msgpack` | — |
| 3 | `lazy_preanalysis.py`, `tests/test_lazy_preanalysis.py` | `indexer.py`, `server.py` | — | — |
| 4 | `tasks.py`, `tests/test_tasks.py` | `server.py`, `deep_audit.py` | — | — |
| 5 | `tests/test_memory.py` | `indexer.py`, `server.py`, `pyproject.toml` | `psutil` | Phase 1 |

Phases 1-4 are independent and can be built in parallel. Phase 5 depends on Phase 1.

---

## Verification

After each phase, run:

```bash
cd C:/Users/THEDEVIL/Documents/audit-mcp
python -m pytest tests/ -x -v
python -m ruff check src/audit_mcp/
python -m compileall -q src/audit_mcp/
```

After all phases, benchmark against a real codebase:
- Index `trailmark-upstream/` (medium: ~200 files)
- Verify `callers_of` returns in <500ms with truncation
- Verify warm re-index (no changes) completes in <5s
- Verify `dead_code` returns a `task_id` immediately
- Verify `memory_usage` tool works

---

## What Is NOT In This Plan

These are deferred per the discussion consensus:

| Item | Why Deferred | When |
|---|---|---|
| Cross-partition queries | Requires overlay graph design, multi-index query routing | After partitioner is battle-tested |
| `freeze_partition` | Quality-of-life, not blocking | After LRU eviction works |
| Disk-backed graph store (SQLite) | Trailmark upstream change needed | Long-term |
| `scan_batch` (multi-partition parallel scan) | Depends on async tasks + cross-partition | After Phase 4+6 |
| Bidirectional BFS for `paths_between` | Trailmark engine change or custom BFS | Optimization pass |
