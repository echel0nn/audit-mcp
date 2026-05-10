# GPU Acceleration for audit-mcp — Research Findings

**Question:** Can we run source code graph computations on the GPU with CPU fallback?

**Short answer:** Yes, but not all of them, and not the way you'd expect. The graph traversals are the clear win. Parsing is a waste. Regex is borderline.

---

## The Audit-MCP Compute Breakdown

Our benchmark showed where time actually goes:

| Operation | nginx (3K fn) | CPython (82K fn) | Chromium (29K fn) | Nature |
|---|---|---|---|---|
| **File discovery + hashing** | ~0.5s | ~5s | ~5s | I/O bound (disk) |
| **Parsing (tree-sitter)** | ~2s | ~30s | ~25s | CPU, native C code |
| **Graph merge** | ~1s | ~15s | ~12s | CPU, Python object creation |
| **Preanalysis (lazy)** | ~0.01s | ~2.8s | ~0.1s | Graph traversal |
| **Hub detection** | 7ms | 166ms | 104ms | Edge scan O(E) |
| **BFS (ancestors/reachable)** | <1ms | <1ms | <1ms | Graph traversal |
| **Search (regex over names)** | 3ms | 69ms | 24ms | String matching |

The bottleneck is parsing + merge (80% of time), not graph traversal (<1% of time). GPU-accelerating graph queries that already take <1ms is pointless. The question is: can we GPU-accelerate the *expensive* parts?

---

## What Maps to GPU (and what doesn't)

### 1. Graph Traversals (BFS, reachability, ancestors) — GPU WINS at scale

**The math:** BFS on a graph is equivalent to sparse matrix-vector multiplication (SpMV). The adjacency matrix in CSR format on the GPU, multiplied by a frontier vector, gives you the next BFS level. Each iteration is one SpMV — massively parallel on GPU.

**The literature:**
- NVIDIA's GPU BFS achieves 3.3 billion traversed edges/second on a single GPU ([NVIDIA Research, 2012](https://research.nvidia.com/sites/default/files/pubs/2011-08_High-Performance-and/BFS%20TR.pdf))
- cuGraph's PageRank traverses 8.7 billion edges/second on a V100 ([RAPIDS blog](https://medium.com/rapids-ai/tackling-large-graphs-with-rapids-cugraph-and-unified-virtual-memory-b5b69a065d4))
- 10-12x speedup over CPU for general graph algorithms ([TechLoy 2025](https://www.techloy.com/running-graph-algorithms-on-gpus-optimizing-traversals-and-query-performance/))

**Our situation:** On Chromium's 417K edges, CPU BFS finishes in <1ms. The GPU transfer overhead alone is >1ms. GPU BFS only wins when the graph has millions of edges. At CPython scale (564K edges), we're at the crossover point. At full Chromium scale (tens of millions of edges), GPU wins by 10-100x.

**Verdict:** Not worth it at current benchmark sizes. Worth it for full Chromium/kernel scale. The right design is an adaptive threshold: use CPU below 1M edges, GPU above.

**How to implement:**

Option A — **RAPIDS cuGraph + nx-cugraph** (zero code change):
```python
# Set environment variable and NetworkX dispatches to GPU automatically
# NX_CUGRAPH_AUTOCONFIG=True
import networkx as nx
# All nx.bfs_edges, nx.shortest_path, nx.pagerank calls go to GPU
```
- Supports: BFS, shortest path, PageRank, connected components, community detection
- Requires: NVIDIA GPU + CUDA + RAPIDS install (Linux only, ~2GB install)
- Limitation: Linux only. No Windows/macOS GPU support.

Option B — **CuPy sparse matrix SpMV** (manual, cross-platform-ish):
```python
import scipy.sparse as sp

# Build CSR adjacency matrix from graph edges
row_idx = [edge.source_idx for edge in edges]
col_idx = [edge.target_idx for edge in edges]
data = [1] * len(edges)
adj_cpu = sp.csr_matrix((data, (row_idx, col_idx)), shape=(n, n))

try:
    import cupy as cp
    import cupyx.scipy.sparse as gpu_sparse
    adj = gpu_sparse.csr_matrix(adj_cpu)  # transfer to GPU once
    USE_GPU = True
except ImportError:
    adj = adj_cpu
    USE_GPU = False

# BFS via SpMV: frontier(k+1) = adj @ frontier(k), masked by visited
frontier = np.zeros(n); frontier[start] = 1
visited = frontier.copy()
for _ in range(max_depth):
    frontier = (adj @ frontier > 0).astype(float) * (1 - visited)
    if frontier.sum() == 0: break
    visited += frontier
```
- Works on any CUDA GPU (Windows + Linux)
- CPU fallback via scipy.sparse (same API)
- Manual implementation but full control

Option C — **Gunrock** (highest performance, C++ only):
- 3.3B edges/second BFS
- No Python bindings
- Would need a C extension or subprocess call
- Overkill for our use case

**Recommendation: Option B (CuPy).** Same API for CPU and GPU. Works on Windows. No RAPIDS dependency. Fallback is automatic.

---

### 2. Parsing (tree-sitter) — GPU LOSES

**Why not:** Parsing is inherently sequential per-file. Tree-sitter builds a concrete syntax tree via an incremental LR-style parser — each token depends on the parser state from the previous token. You can't parallelize within a file.

GPU parsing research shows disappointing results:
- GPU PCFG parser: initially 200x *slower* than CPU, optimized to merely "competitive" ([Johnson, 2011](https://pdfs.semanticscholar.org/16d2/eb40afc58d0ab1b06c9f3e660027dad2d88c.pdf))
- GPU PCAP parsing: "For a small PCAP the GPU version took 1s while the multi-threaded CPU version took 10ms" ([Aneesh Durg, 2025](https://aneeshdurg.me/posts/2025/01/21-gpu-pcaps/))
- Pareas (GPU compiler): interesting research, but a custom language, not production-ready ([GitHub](https://github.com/Snektron/pareas))

Tree-sitter is already native C code running at ~10ms/file. You can't beat that with a GPU because:
1. GPU memory transfer (CPU → GPU → CPU) per file costs more than parsing
2. Parser state is sequential — no parallelism to exploit
3. Tree-sitter doesn't produce CSR/CSC output — you'd need a conversion step

**What DOES work for parallel parsing:** Multi-process parallelism (ProcessPoolExecutor). Parse N files on N CPU cores simultaneously. We already fixed the thread-safety bug (tree-sitter's Parser is !Send). ProcessPoolExecutor sidesteps it entirely because each process has its own parser.

**Verdict:** Don't GPU-accelerate parsing. Use ProcessPoolExecutor instead of ThreadPoolExecutor.

---

### 3. Graph Merge — GPU LOSES

**Why not:** Graph merge is Python object creation — `CodeGraph.merge(file_graph)` creates `CodeUnit` and `CodeEdge` Python objects and inserts them into dicts. This is Python interpreter work, not numeric computation. GPUs can't run the CPython interpreter.

The fix is not GPU — it's better data structures:
- Build the adjacency list as numpy arrays / CSR during parse (not Python dicts)
- Merge by array concatenation, not dict.update
- This is a trailmark upstream change

**Verdict:** Don't GPU-accelerate merge. Fix the data structure upstream.

---

### 4. Regex Search over Function Names — GPU BORDERLINE

**The opportunity:** `search_functions("parse_.*header")` scans 82K function names on CPython. That's string matching over an array — classically GPU-parallelizable.

**GPU regex options:**
- **RAPIDS cuDF** has GPU regex via `cudf.Series.str.contains(pattern)` — 2-10x faster than pandas on large string arrays
- **CUDA grep** achieves 2-10x over grep ([bkase, 2014](http://bkase.github.io/CUDA-grep/finalreport.html))
- **Hyperscan** (Intel) achieves massive speedups via SIMD on CPU — often faster than GPU for regex because regex is branch-heavy and GPUs hate branch divergence

**Our situation:** 69ms to search 82K names on CPython. That's already fast. GPU transfer overhead would eat most of the speedup. On a 500K-function codebase, it might be 400ms CPU — still not worth the GPU round-trip.

**Better CPU optimization:** Pre-build a sorted name index + prefix trie at index time. Prefix queries (`parse_*`) become O(log N) lookups instead of O(N) regex scans. This would reduce the 69ms to <1ms without any GPU.

**Verdict:** Don't GPU-accelerate regex. Build a prefix index instead.

---

### 5. Blast Radius / Transitive Closure — GPU WINS at scale

**The math:** Computing blast radius for the top-50 functions means running 50 BFS traversals. On CPython (564K edges), that's 50 × SpMV iterations. This is the same as #1 but batched — run all 50 BFS from different start nodes simultaneously on the GPU.

**GPU batched BFS:**
```python
# All 50 BFS runs simultaneously as one sparse matrix multiply
# frontier_matrix is (n_vertices × 50), one column per start node
frontier_matrix = sparse.csc_matrix(...)  # 50 columns
for depth in range(max_depth):
    frontier_matrix = adj @ frontier_matrix  # one batched SpMV
    # mask visited...
```

This is where GPU truly excels — batched SpMV on a single adjacency matrix. The adjacency matrix is transferred to GPU once, then reused across all 50 traversals.

**Estimated speedup:** 50 × serial BFS at ~60ms each = 3 seconds CPU. Batched GPU SpMV: ~50ms total (adjacency already on GPU). 60x speedup.

**Verdict:** Worth it for blast_radius_top_n on large graphs. Use CuPy batched SpMV.

---

### 6. Dead Code / Unreachable Analysis — GPU WINS

**The math:** `unreachable_from_entrypoints` runs BFS from every entrypoint and unions the reachable sets. With 300 entrypoints (CPython), that's 300 BFS traversals. Same as #5 but with 300 start nodes instead of 50.

Batched GPU SpMV with 300 columns: one GPU operation computes reachability from all entrypoints simultaneously.

**Verdict:** Strong GPU candidate. Same CuPy batched SpMV pattern.

---

## Architecture: The GPU Graph Engine

### Design

```python
class GraphEngine:
    """Adaptive CPU/GPU graph engine with automatic fallback."""

    def __init__(self, adj_csr: sp.csr_matrix, node_names: list[str]):
        self._adj_cpu = adj_csr
        self._node_names = node_names
        self._name_to_idx = {n: i for i, n in enumerate(node_names)}
        self._gpu_available = False
        self._adj_gpu = None

        try:
            import cupy as cp
            import cupyx.scipy.sparse as gpu_sparse
            if cp.cuda.is_available():
                self._adj_gpu = gpu_sparse.csr_matrix(adj_csr)
                self._gpu_available = True
        except ImportError:
            pass

    @property
    def adj(self):
        """Return GPU adjacency if available, CPU otherwise."""
        return self._adj_gpu if self._gpu_available else self._adj_cpu

    def bfs(self, start_name: str, max_depth: int = 10) -> set[str]: ...
    def batched_bfs(self, start_names: list[str], max_depth: int = 10) -> list[set[str]]: ...
    def blast_radius(self, name: str) -> int: ...
    def blast_radius_batch(self, names: list[str]) -> dict[str, int]: ...
    def unreachable_from(self, entrypoints: list[str]) -> set[str]: ...
```

### Conversion from trailmark

```python
def graph_to_csr(engine) -> tuple[sp.csr_matrix, list[str]]:
    """Convert trailmark's graph to CSR for GPU/CPU operations."""
    graph = engine._store._graph
    nodes = list(graph.nodes.values())
    name_to_idx = {getattr(n, "id", ""): i for i, n in enumerate(nodes)}
    names = [getattr(n, "name", "") for n in nodes]

    rows, cols = [], []
    for edge in graph.edges:
        src = name_to_idx.get(getattr(edge, "source_id", ""))
        tgt = name_to_idx.get(getattr(edge, "target_id", ""))
        if src is not None and tgt is not None:
            rows.append(src)
            cols.append(tgt)

    n = len(nodes)
    data = [1] * len(rows)
    adj = sp.csr_matrix((data, (rows, cols)), shape=(n, n))
    return adj, names
```

### Fallback strategy

```
GPU path (cupy installed + CUDA available):
  adj_gpu = cupyx.scipy.sparse.csr_matrix(adj_cpu)
  BFS via batched SpMV on GPU
  Results transferred back as numpy arrays

CPU path (no GPU or cupy not installed):
  adj_cpu = scipy.sparse.csr_matrix
  BFS via batched SpMV on CPU (scipy)
  Same API, same results, ~10-100x slower on large graphs

Threshold: use GPU only when edge_count > 1_000_000
  Below that, CPU SpMV is fast enough and GPU transfer overhead dominates
```

---

## Dependencies

| Package | Purpose | Required | Size |
|---|---|---|---|
| `scipy` | CPU sparse matrix operations (CSR, SpMV) | Yes | 30 MB |
| `numpy` | Array operations | Yes (already a transitive dep) | 20 MB |
| `cupy-cuda12x` | GPU sparse matrix operations | Optional | ~400 MB |

CuPy is the ONLY new dependency for GPU support. It's optional — CPU fallback uses scipy which is already a transitive dependency of trailmark.

No RAPIDS. No cuGraph. No Gunrock. No CUDA toolkit install. CuPy ships its own CUDA runtime.

---

## What NOT to GPU-accelerate

| Operation | Why not |
|---|---|
| **Parsing (tree-sitter)** | Sequential per-file, GPU transfer > parse time |
| **Graph merge** | Python object creation, not numeric |
| **Regex search** | Branch-heavy, GPU hates it. Build a prefix index instead |
| **Individual BFS** | <1ms on CPU, GPU transfer alone is >1ms |
| **Small graphs (<1M edges)** | GPU transfer overhead dominates |

---

## Implementation Priority

| # | What | Speedup | Effort | Dependencies |
|---|---|---|---|---|
| 1 | **ProcessPoolExecutor for parsing** | 4-12x on multi-core CPUs | 2 hours | None (stdlib) |
| 2 | **CSR adjacency matrix** (CPU-only first) | Foundation for GPU | 1 day | scipy |
| 3 | **Batched BFS via SpMV** (CPU scipy) | 5-10x for blast_radius/unreachable | 1 day | scipy |
| 4 | **CuPy GPU backend** (optional) | 10-100x on >1M edges | 1 day | cupy (optional) |
| 5 | **Prefix index for search** | 50-100x for name search | 3 hours | None |

Items 1-3 improve performance for EVERYONE. Item 4 is the GPU bonus for people with NVIDIA GPUs. Item 5 is a better solution than GPU for the regex problem.

---

## What Your GPU Actually Is

## Benchmarked on RTX 3080 (8704 CUDA cores, 10GB VRAM, CC 8.6)

Real SpMV numbers from this machine via CuPy 13.6 + CUDA 11.8:

| Scale | Nodes | Edges | CPU SpMV | GPU SpMV | Speedup | Batched 50 BFS CPU | Batched 50 BFS GPU | Speedup |
|---|---|---|---|---|---|---|---|---|
| Small | 10K | 100K | 0.10ms | 0.06ms | 1.7x | 1.6ms | 0.1ms | **10.9x** |
| Medium | 100K | 1M | 0.95ms | 0.06ms | **16.1x** | 30.7ms | 1.1ms | **28.7x** |
| Large | 500K | 5M | 5.84ms | 0.12ms | **48.7x** | 250ms | 36.7ms | **6.8x** |
| XL | 1M | 10M | 12.3ms | 0.22ms | **56.4x** | 560ms | 85ms | **6.6x** |

CPython's graph (82K functions, 564K edges) sits in the Medium tier — 16-29x speedup.
Full Chromium (~2M functions, ~10M+ edges) would be in the XL tier — 56x single SpMV.

The adaptive threshold should be ~50K edges. Below that, GPU transfer overhead dominates. Above it, the 3080 pulls away hard.


---

## Full Chromium Benchmark (715K functions, 7.4M edges)

Tested on full chromium/src checkout -- 163K files, 110K parsed C/C++.

| Metric | Value |
|---|---|
| Functions | 715,138 |
| Call edges | 7,385,537 |
| Entrypoints | 977 |
| GPU CSR nodes | 2,644,560 |
| GPU CSR edges | 3,461,773 |
| Cold index | 31.6 min |
| GPU engine build | 25.8s |
| Dead code (GPU) | 541,850 in 1.4s |
| Hub detection | 7,113 hubs in 6.3ms |
| Search | 50/6,330 in 600ms |
| Memory | ~4 GB RSS |

### Dead Code False Positive Problem

75.8% reported dead. Cross-validated: GPU and trailmark agree 500/500.
The measurement is correct. The interpretation is misleading.

Chromium uses 70%+ indirect dispatch (virtual methods, callbacks, macros,
templates, Mojo IPC). Tree-sitter AST analysis sees none of these call
paths. Every virtual override, every callback target, every macro-dispatched
handler shows zero static callers.

The tool works correctly on direct-call codebases (C, Go, Python, Rust).
On C++ with heavy polymorphism, the false positive rate for dead code
is catastrophic. A future fix: integrate with clangd or compile_commands.json
for compiler-resolved call graphs instead of AST-level analysis.

### Known Scaling Issues at 715K Functions

- Warm re-index: 1,231s (pickle load of 2.6M-node graph)
- Unreachable analysis: timed out (977 entrypoints x depth-50 batched BFS on 2.6M nodes)
