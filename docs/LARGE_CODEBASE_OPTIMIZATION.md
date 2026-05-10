# audit-mcp Large Codebase Optimization — 5 Researcher Discussion

## Personas

### R1: "Tavis" — Staff, Browser Security (Chrome/Firefox scale)
15 years auditing browser codebases. Has found bugs in every layer from the JS engine to the GPU process sandbox. Works with 35M LOC codebases daily. Thinks in terms of IPC boundaries, sandbox escapes, and renderer-to-browser privilege transitions. Won't use a tool that takes more than 60 seconds to give him an answer.

### R2: "Jann" — Staff, Linux Kernel Security
Finds kernel privilege escalation bugs. Works with 30M LOC across 60K files in 5 languages (C, assembly, Rust, DTS, Python scripts). His targets are syscall handlers, ioctl dispatch, and netfilter hooks. Cares about which paths cross the user/kernel boundary and which slab allocators are reachable from an unprivileged process.

### R3: "Natalie" — Principal, Android Platform Security
Audits the entire Android stack: Java framework, native libraries, HAL implementations, kernel drivers. Cross-language calls (JNI, AIDL, HIDL, Binder IPC) are her daily reality. A vulnerability in the Java layer that calls through JNI into a C library that makes a Binder call to a privileged service — she needs the tool to trace across all three layers. 40M+ LOC across 6 languages. Build system is a monster (Soong/Blueprint/Make/Bazel hybrid).

### R4: "Ben" — Staff, Supply Chain Security
Audits large monorepos with hundreds of transitive dependencies. Doesn't care about one binary — cares about "which of these 847 third-party packages has a tainted path from network input to `eval()`?" Works with npm/PyPI/Maven ecosystems. His codebases are 10K-100K files, but the INTERESTING files are scattered across 200 vendored packages.

### R5: "Sarah" — Principal, Cloud Infrastructure Security
Audits cloud-native Go/Rust/Python microservice monorepos. 50+ services, shared libraries, gRPC proto definitions tying everything together. Her codebases are 5M-15M LOC. She cares about which service can reach which other service's internals, and which RPC handlers parse untrusted input without validation.

---

## Topic 1: Initial Indexing — "I just pointed this at Chromium and it's been 20 minutes"

**Tavis:** The current `FastIndexer` uses `ThreadPoolExecutor` with content-hash caching per file. That's fine for a 5K-file project. Chromium has 350,000 source files. Even with 16 workers and tree-sitter (fast C parser), the initial `os.walk` + hash + parse takes 15-25 minutes. That's before `CodeGraph.merge()` or `run_preanalysis()` even starts. The problem isn't parse speed — tree-sitter parses a file in <10ms. The problem is:

1. **350K filesystem stats + SHA256 hashes** = ~90 seconds of I/O
2. **350K `parse_file` calls even from cache** — reading and deserializing 350K JSON files is 60+ seconds
3. **`CodeGraph.merge()` is O(n) and single-threaded** — merging 350K file graphs into one is minutes
4. **`run_preanalysis()` (blast radius, taint) is O(V×E)** on a graph with 2M+ nodes — unbounded

First-run taking 25 minutes is acceptable IF the second run is fast. But right now, the second run STILL calls `CodeGraph.merge()` and `run_preanalysis()` from scratch even though every file is cached. The cache saves the parse step but not the expensive graph construction step.

**Jann:** For the kernel, I hit the same wall but the shape is different. The kernel has 60K files but the CALL GRAPH is enormous — 500K functions, 2M call edges. The parse phase is 3 minutes (fast). The preanalysis phase — computing blast radius for 500K functions — is where it dies. Blast radius is a transitive closure operation. On a 500K-node graph, that's O(V²) in the naive case. Even with BFS per node and early termination, it's minutes.

The fix: **DON'T compute blast radius for all functions eagerly.** Compute it on demand. When someone asks `complexity_hotspots(threshold=15)`, compute blast radius for the 200 functions that pass the complexity filter, not for 500K functions.

**Natalie:** The Android problem is worse than both of yours combined because it's MULTI-LANGUAGE. The Java framework has 200K functions. The native layer has 300K functions. The JNI boundary connects them. Trailmark parses each language independently — but the cross-language edges (JNI, Binder) aren't in the parse output. They're in AIDL/HIDL interface definitions that trailmark doesn't parse. Without those edges, `paths_between(JavaHandler, NativeParser)` returns empty even when the path exists through JNI.

That's not a performance problem — it's a CORRECTNESS problem. But it becomes a performance problem when I work around it by manually annotating 500 JNI boundaries. Each annotation triggers... what? Does the graph get rebuilt? Is the preanalysis invalidated?

**Ben:** My problem isn't file count — it's DIRECTORY STRUCTURE. I have 200 vendored packages under `node_modules/` or `vendor/`. Each is a self-contained codebase. I don't want ONE graph for everything — I want 200 small graphs that I can query independently, PLUS a way to ask "which of these 200 packages has a function reachable from my app's entrypoints?"

The current partitioner (`_MAX_FILES_PER_PARTITION = 5000`) splits by directory size, but the partitions are independent — no cross-partition queries. That means I can't ask the most important question: "trace from my Express handler through three npm packages to the dangerous `child_process.exec()` call."

**Sarah:** The microservices problem is similar to Ben's. 50 services, each 2K-10K files. Each service is a partition-sized codebase. I want:
1. Per-service indexes (fast, independent)
2. A cross-service overlay that knows about gRPC/REST connections
3. `taint_paths_to(sink="exec")` that traces ACROSS service boundaries through the RPC definitions

Right now, indexing all 50 services as one monolith takes 12 minutes and produces a graph so large that `reachable_from("main")` takes 30 seconds.

### Consensus: Two-Tier Indexing

The index must have two tiers:

**Tier 1: Partition-level indexes (fast, independent, cacheable as a unit)**
- Each partition (directory, package, service) is indexed independently
- The merged `CodeGraph` is serialized to disk after construction (not just the parse cache)
- Second-run loads the serialized graph directly — skip parse, merge, and preanalysis entirely
- Invalidation: content-hash of the partition's file list + individual file hashes. If ANY file changed, re-index that partition only.
- Target: partition index in <10s for up to 5K files from warm cache

**Tier 2: Cross-partition overlay (optional, on demand)**
- A lightweight graph of inter-partition edges: imports, JNI, RPC, Binder IPC
- Built from interface definitions (AIDL, proto, OpenAPI, package.json exports)
- `paths_between` across partitions queries the overlay, then drills into partition indexes
- NOT built by default — built when the user asks a cross-partition question

| Operation | Current | Target (warm cache) |
|---|---|---|
| Index 5K-file project | 15-30s | <5s |
| Index Chromium (350K files) from scratch | 25 min | 8-12 min |
| Re-index Chromium (no changes) | 8-12 min | <30s (graph deserialization) |
| Re-index Chromium (100 files changed) | 8-12 min | <60s (re-parse 100 + merge delta) |
| `reachable_from` on 2M-node graph | 30s+ | <3s (lazy BFS with depth cap) |
| `complexity_hotspots` | 30s (preanalysis) | <1s (pre-indexed) |

---

## Topic 2: Preanalysis — Eager vs Lazy Computation

**Jann:** `run_preanalysis()` computes blast radius, taint propagation, and privilege boundary detection for EVERY node in the graph. On the kernel, that's 500K nodes. Blast radius alone is a BFS per node — 500K BFS traversals. Even with each BFS bounded to depth 10, that's 500K × (avg_fanout^10) operations. It's the dominant cost.

The fix is obvious: **lazy preanalysis**. Don't compute blast radius until someone asks for it. When `complexity_hotspots(threshold=15)` is called, filter to the ~200 qualifying functions, THEN compute blast radius for those 200 only. Cache the results per-node so repeated queries are instant.

**Tavis:** Lazy preanalysis breaks one thing: the `preanalysis()` tool that returns the full preanalysis report upfront. That's currently the "give me the executive summary" tool — entrypoints, top blast radius, privilege boundaries. If everything is lazy, that tool has nothing to return until individual queries populate the cache.

The fix: **tiered preanalysis**.
- **Eager (always computed):** entrypoint detection, privilege boundary detection — these are cheap (pattern match on known framework annotations + API names). O(V) with small constants.
- **Deferred (computed in batch when requested):** blast radius top-50, taint propagation from entrypoints. Computed ONCE when `preanalysis()` is called, cached, never recomputed unless the graph changes.
- **Lazy (per-query):** individual function blast radius, individual taint paths. Computed on demand, cached per-node.

**Natalie:** Entrypoint detection is cheap for SINGLE-LANGUAGE codebases. For Android, the entrypoints are: Java Activities/Services/BroadcastReceivers (annotation-detected), native JNI exports (`JNIEXPORT`), Binder service methods (AIDL-generated stubs), kernel syscall handlers (`SYSCALL_DEFINE`). Each has a different detection pattern. The `detect_entrypoints` call needs to run ALL of them, across ALL languages, and merge. That's O(V) but with a large constant.

**Sarah:** For microservices, entrypoint detection is trivial within one service (find the gRPC handler methods). The HARD part is "which of these entrypoints is exposed to the internet vs internal-only?" That requires reading the proto files + Kubernetes service definitions + ingress rules. Way out of scope for trailmark — but the MCP should accept user-supplied entrypoint annotations that override auto-detection.

**Ben:** For dependency audit, I need blast radius computed for a very specific subset: functions in MY code that call into VENDORED code. I don't care about blast radius within vendored code — that's the vendor's problem. The MCP should support scoped preanalysis: "compute blast radius for nodes matching `src/**` only, counting edges into `vendor/**` but not within it."

### Consensus: Tiered Preanalysis

```
EAGER (always, at index time):
  - Entrypoint detection (known frameworks, O(V))
  - Privilege boundary detection (pattern match, O(V))
  - Function count, edge count, language breakdown (trivial)

DEFERRED (on first preanalysis() call, cached):
  - Blast radius top-N (configurable N, default 50)
  - Taint propagation from entrypoints to known sinks
  - Unreachable-from-entrypoints set

LAZY (per individual query, cached per-node):
  - Individual function blast radius
  - Individual taint path
  - Individual reachability
```

Implementation: add `_lazy_cache: dict[str, Any]` to the engine. Each lazy property checks the cache first. Cache invalidates when the graph changes (annotation applied, SARIF imported, partition re-indexed).

---

## Topic 3: Graph Query Performance — "ancestors_of on a 2M-node graph"

**Tavis:** The graph queries in `server.py` are all unbounded. `ancestors_of("main")` on Chromium returns 50,000 functions. That's a 15MB JSON response that takes 20 seconds to compute and crashes the MCP client's context window. Every graph query needs:

1. **Depth limit** (default 5, hard cap 20)
2. **Result limit** (default 100, hard cap 5000)
3. **Truncation indicator** ("200 of 50,000 ancestors returned; refine with `search_functions` first")

**Jann:** Depth limit isn't enough for the kernel. The call graph has functions called from THOUSANDS of sites (`printk`, `kmalloc`, `copy_to_user`). `callers_of("copy_to_user")` returns 8,000 direct callers. Even depth=1 blows up. The fix: **exclude library/utility functions** from graph traversals by default. Any function with in-degree > N (configurable, default 100) is treated as a "hub" and excluded from BFS unless explicitly included. The user can override: `callers_of("copy_to_user", include_hubs=True)`.

**Natalie:** Hub detection is language-dependent. In Java, `Log.d()` has 50,000 callers — it's a hub. But `Binder.transact()` also has 5,000 callers, and THAT one is security-relevant (it crosses the IPC boundary). Hub exclusion by degree alone loses security-relevant functions. The fix: **annotated hub list** per language/framework. Hubs are functions that are known-safe-to-ignore in security context: logging, assertions, string formatting. Security-relevant high-in-degree functions (IPC, syscalls, serialization) are never auto-excluded.

**Ben:** For dependency audit, I need `paths_between(my_handler, eval)` to work fast. If it does full BFS on a 100K-node graph, it's slow. If it uses bidirectional BFS (start from both ends, meet in the middle), it's 10-100x faster for long paths. Does trailmark's `paths_between` use bidirectional BFS?

**Sarah:** More important than speed: `paths_between` currently returns ALL paths. Between two functions in a microservice monorepo, there can be 10,000 distinct paths. I need the TOP 5 SHORTEST paths, not all paths. The tool should default to `max_paths=5, shortest_first=True`.

**Tavis:** Also: pagination. `search_functions(pattern="parse_*")` on Chromium returns 3,000 matches. Return them 100 at a time. Every list-returning tool needs `offset` and `limit` parameters.

### Consensus: Bounded, Paginated Graph Queries

Every graph query tool gets:

```python
# Universal parameters added to all graph query tools
depth: int = 5            # max traversal depth (hard cap: 20)
limit: int = 100          # max results returned (hard cap: 5000)
offset: int = 0           # pagination offset
exclude_hubs: bool = True # exclude functions with in-degree > hub_threshold
hub_threshold: int = 100  # what counts as a hub
```

Response envelope gains:

```json
{
  "results": [...],
  "total": 50000,
  "returned": 100,
  "truncated": true,
  "truncation_hint": "Add depth=2 or use search_functions to narrow scope"
}
```

Specific fixes:
- `paths_between`: bidirectional BFS, `max_paths=5`, shortest first
- `ancestors_of` / `reachable_from`: BFS with depth cap + hub exclusion
- `search_functions`: regex compiled once, results paginated
- `callers_of` / `callees_of`: depth=1 default, hub exclusion
- `export_graph`: **NEVER return the full graph for >10K-node codebases**. Return a partition list and let the user export one partition at a time.

---

## Topic 4: The Cache Problem — "I changed one file and it re-indexed everything"

**Tavis:** The `FastIndexer` caches individual file parse results by content hash. That's correct and necessary. But the EXPENSIVE part — `CodeGraph.merge()` + `run_preanalysis()` — runs from scratch every time, even when 100% of files hit cache. The merge produces the same graph from the same inputs. Cache the merged graph.

The right cache hierarchy:

```
Layer 1: File parse cache (exists, works)
  Key: SHA256(file_content)
  Value: parse result (functions, calls)
  Invalidation: file content changes

Layer 2: Partition graph cache (MISSING — must add)
  Key: SHA256(sorted file_hashes of all files in partition)
  Value: serialized CodeGraph
  Invalidation: any file in partition changes
  Format: MessagePack or pickle (JSON is too slow for large graphs)

Layer 3: Preanalysis cache (MISSING — must add)
  Key: SHA256(partition_graph_hash + preanalysis_config)
  Value: preanalysis results (entrypoints, blast radius top-N, taint)
  Invalidation: graph changes OR preanalysis config changes

Layer 4: Query result cache (MISSING — add for expensive queries)
  Key: (graph_hash, query_name, query_params)
  Value: query result
  Invalidation: graph changes
  TTL: none (deterministic — same graph, same query, same result)
```

**Jann:** Layer 2 is the critical one. On the kernel, parse takes 3 minutes. Merge + preanalysis takes 8 minutes. If I change ONE file, I should re-parse ONE file (10ms), delta-merge it into the existing graph (not rebuild from scratch), and re-run preanalysis ONLY for affected nodes.

Delta-merge is the hard part. `CodeGraph.merge()` probably doesn't support "remove file X's contribution and add file X-prime's contribution." It's merge-only, not diff-merge. Until trailmark supports delta-merge, the pragmatic answer is: serialize the full graph, and on change, re-run merge for the affected partition only. If a partition has 5K files and 1 changed, re-parse 1 + re-merge 5K from cache is still 10-30 seconds. Acceptable.

**Natalie:** The REAL cache invalidation problem is annotations. When the LLM (or operator) annotates a function — sets its type, marks it as an entrypoint, adds a finding — does that invalidate the graph cache? The preanalysis cache? The query cache?

Annotations are metadata on the graph, not the graph structure itself. They should live in a separate layer that doesn't invalidate the structural graph cache. Adding an annotation invalidates preanalysis cache (because taint propagation changes) and query cache (because reachability from the new entrypoint changes), but NOT the parse cache or the graph structure cache.

**Ben:** For vendored dependencies that NEVER change (they're pinned versions), the cache should be PERMANENT. Don't re-hash, don't re-check. Mark a partition as "frozen" and skip it entirely on re-index. My `node_modules/` has 100K files — re-hashing them takes 30 seconds every time for zero benefit. A `freeze_partition(partition_id)` command that pins the cache until explicitly unfrozen.

**Sarah:** Cache storage format matters. JSON serialization of a 500K-node graph is 400MB and takes 20 seconds to write / 10 seconds to read. MessagePack is 3-5x smaller and 10x faster to deserialize. Pickle is fastest but not portable. For the graph cache (Layer 2), use MessagePack. For the parse cache (Layer 1), JSON is fine — individual files are small.

### Consensus: Three-Layer Cache with Delta Support

| Layer | Key | Value | Format | Invalidation |
|---|---|---|---|---|
| File parse | `SHA256(content)` | functions + calls | JSON | Content change |
| Partition graph | `SHA256(sorted_file_hashes)` | Serialized `CodeGraph` | MessagePack | Any file in partition changes |
| Preanalysis | `SHA256(graph_hash + config)` | Entrypoints, blast radius, taint | MessagePack | Graph or annotation changes |

New commands:
- `freeze_partition(partition_id)` — skip re-hash on re-index
- `unfreeze_partition(partition_id)` — resume normal invalidation

Implementation priority:
1. **Graph serialization** (Layer 2) — highest impact. Eliminates merge on warm re-index.
2. **Preanalysis caching** (Layer 3) — second highest. Eliminates BFS re-runs.
3. **Freeze** — quality-of-life for vendored deps.

---

## Topic 5: Memory — "It OOM'd on Chromium"

**Tavis:** A 35M LOC codebase produces a graph with 2M+ nodes and 8M+ edges. In-memory, with Python object overhead, that's 4-8 GB of RAM. `run_preanalysis()` adds blast radius per node (another dict per node), taint sets (another set per node). Total: 8-16 GB. A workstation with 32 GB runs out when the OS, IDA, and the MCP are all resident.

The MCP server should report its own memory usage: `cache_stats()` currently returns disk cache size. Add `memory_usage()` that returns resident set size + graph node/edge counts. The user needs to know "this graph is consuming 6 GB" before they ask for another index.

**Jann:** Two strategies for memory:

1. **Streaming graph construction.** Don't build the entire `CodeGraph` in memory. Build it into a disk-backed store (SQLite with in-memory page cache). Queries run against the database. Memory usage is bounded by the page cache, not the graph size.

2. **Graph compression.** Most edges are call edges. Most call edges are between functions in the same file or the same module. Run-length encode or adjacency-list compress. 8M edges stored as sorted adjacency lists with delta encoding is 10-50 MB, not 500 MB.

Strategy 1 is a trailmark change (big). Strategy 2 is an MCP-level optimization (medium). For v0.1, cap memory with a hard limit: refuse to index a codebase that would produce a graph > N nodes (configurable, default 1M). Return an error: "Codebase too large for monolithic indexing. Use `plan_partitions` to split."

**Natalie:** Partitioned indexing already exists — `Partitioner` — but the partitions are INDEPENDENT. You lose cross-partition edges. The fix for memory is not "refuse large codebases" — it's "partition them and provide cross-partition queries." See Topic 1.

**Ben:** For dependency audit, each vendored package is a small graph (1K-10K nodes). 200 packages = 200 small graphs = 200 × 50 MB = 10 GB if all loaded. But I only need 5-10 loaded at a time. The MCP should LRU-evict partition graphs from memory. Keep metadata (function names, entrypoints) for all partitions; load the full graph only when a query touches that partition.

**Sarah:** Same — 50 services, each a small graph. LRU-evict with a memory budget. The `IndexManager` already tracks multiple indexes — extend it with a memory budget and eviction.

### Consensus: Memory-Bounded Graph Management

1. **Hard cap on monolithic indexing:** refuse codebases with >500K estimated functions without partitioning. Return partition plan instead.
2. **LRU eviction for partition graphs:** keep all partition metadata in memory (~1 KB per partition), load full graph on demand, evict when memory budget exceeded.
3. **Memory budget configuration:** `AUDIT_MCP_MEMORY_MB` env var, default 4096 (4 GB).
4. **`memory_usage()` tool:** returns RSS, graph node/edge counts, loaded partition count, evicted partition count.
5. **Long-term: disk-backed graph store.** SQLite with FTS5 for function name search, adjacency list table for edges. Trailmark upstream contribution.

---

## Topic 6: What Tools MUST Be Fast (<1s) and Which CAN Be Slow (>10s)?

**Tavis:** As a researcher, I think in 3-second cycles: ask question, read answer, form next question. If ANY tool takes >3 seconds, it breaks my flow. The entire MCP value proposition collapses if `callers_of` takes 10 seconds. Here's my classification:

| Tier | Max latency | Tools |
|---|---|---|
| **Interactive** (<1s) | 500ms | `callers_of`, `callees_of`, `search_functions`, `complexity_hotspots`, `annotations_of`, `findings` |
| **Analytical** (<5s) | 3s | `ancestors_of`, `reachable_from`, `paths_between`, `entrypoint_paths_to`, `taint_paths_to`, `attack_surface` |
| **Batch** (<60s) | 30s | `preanalysis`, `dead_code`, `unreachable_from_entrypoints`, `diff_codebases`, `scan_and_correlate` |
| **Background** (async) | minutes | `index_codebase`, `run_scanner`, `export_graph` |

The MCP should enforce these budgets. If `callers_of` exceeds 1 second, it's a bug — the data structure is wrong.

**Jann:** Interactive-tier tools should be O(1) lookups from pre-computed indexes. `callers_of` is a reverse-adjacency-list lookup — O(degree). `search_functions` is a regex over a name index — O(V) but with tiny constants if the index is a sorted list with binary search for prefix queries.

Analytical-tier tools are BFS/DFS — bounded by depth and result limits from Topic 3. With depth=5 and limit=100, even on a 2M-node graph, BFS terminates in <1s.

Batch-tier tools are full-graph scans — acceptable to be slow but must show progress. `dead_code` scanning 500K functions should emit progress: "scanning... 50K / 500K functions checked."

**Sarah:** Background-tier tools MUST be async. `index_codebase` already returns immediately with an `index_id` and you `poll_index` for status. `run_scanner` should work the same way — return a `scan_id`, poll for results. Currently `run_scanner` blocks for up to 600 seconds. That's a transport timeout waiting to happen.

**Natalie:** `scan_and_correlate` is the most important tool for actual audit work, and it's in the batch tier. It runs a scanner + imports SARIF + correlates with graph. That's 3 operations chained. If the scanner takes 30 seconds, the correlation takes 5 seconds, and the SARIF import takes 2 seconds — total 37 seconds. The user is staring at a spinner for 37 seconds. Make it async like `index_codebase`: start, poll, get results.

**Ben:** For dependency audit, I'll call `scan_and_correlate` on 200 packages. Serially, that's 200 × 37s = 2 hours. The MCP needs a batch variant: `scan_batch(index_ids=[...], scanner="semgrep")` that runs all 200 in parallel (bounded by worker count) and returns a single aggregated result.

### Consensus: Latency Tiers + Async for Batch

1. **Pre-compute interactive-tier data at index time:** reverse adjacency lists, name index, complexity index. O(1) lookups.
2. **Bound analytical-tier queries** per Topic 3 — depth + result limits ensure <3s.
3. **Make batch/background tools async:** `run_scanner`, `scan_and_correlate`, `dead_code`, `unreachable_from_entrypoints` return a task_id + poll pattern. Same as `index_codebase`.
4. **Add `scan_batch`** for multi-partition scanning.
5. **Progress reporting** for all async tools via `poll_task(task_id)` → `{status, progress_pct, partial_results}`.

---

## Topic 7: Concrete Implementation Priorities

**All five agree on priority order:**

| # | Change | Effort | Impact | Blocks |
|---|---|---|---|---|
| 1 | **Graph serialization cache (Layer 2)** — serialize merged CodeGraph to MessagePack, load on warm re-index | 1 day | Critical — eliminates 80% of re-index time | Nothing |
| 2 | **Bounded graph queries** — add depth, limit, offset, exclude_hubs to all traversal tools | 1 day | Critical — prevents OOM and timeout on large graphs | Nothing |
| 3 | **Lazy preanalysis** — compute blast radius on demand, not eagerly for all nodes | 1 day | High — eliminates preanalysis bottleneck | Nothing |
| 4 | **Async batch tools** — `run_scanner`, `scan_and_correlate`, `dead_code` return task_id + poll | 2 days | High — unblocks parallel workflows | Nothing |
| 5 | **LRU partition eviction** — memory-bounded graph loading with eviction | 1 day | High — enables Chromium-scale without OOM | #2 |
| 6 | **Cross-partition queries** — overlay graph for inter-partition edges | 3 days | Medium — enables monorepo/Android audits | #5 |
| 7 | **Preanalysis caching (Layer 3)** — cache taint/blast results per graph hash | 0.5 days | Medium — speeds up repeated queries | #3 |
| 8 | **`freeze_partition`** — pin vendored deps, skip re-hash | 0.5 days | Low — quality of life | #5 |
| 9 | **Disk-backed graph store (SQLite)** — bounded memory for any graph size | 5 days | Long-term — removes all memory limits | Trailmark upstream |

**Tavis:** Items 1-3 are the difference between "demo toy" and "usable on real codebases." Ship those first.

**Jann:** Item 2 is the one that prevents production incidents. Without bounded queries, an LLM calling `ancestors_of("printk")` on the kernel will OOM the server and crash every other index in the process.

**Natalie:** Item 6 is what makes this tool relevant for Android/multi-language audits. Without it, we're a single-language tool pretending to handle polyglot codebases.

**Ben:** Item 4 is what makes dependency audit viable. Without async scanning, auditing 200 packages is a 2-hour blocking operation.

**Sarah:** Item 5 is what lets us run this on a normal workstation instead of a 64 GB machine. Without LRU eviction, you can only have a few large indexes loaded at once.
