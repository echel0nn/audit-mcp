# audit-mcp

This is the greatest source code audit tool of all time.

Every other security scanner on the planet does the same thing: it scans your code like a flat bag of text files, pukes out 200 findings, and then just leaves. Just absolutely dumps a mountain of alerts on your desk and walks away like it didn't just ruin your afternoon. "Good luck figuring out which of these actually matter, dipshit." That's literally every SAST tool in existence.

audit-mcp doesn't do that. It builds a full call graph of your entire codebase first — every function, every call, every entrypoint, every trust boundary — and THEN it scans. So when semgrep says "line 42 has a SQL injection," this thing actually checks: is line 42 reachable from the network? Or is it in a test helper that nobody calls? Because those are two magnificently different situations.

Built on [Trail of Bits Trailmark](https://github.com/trailofbits/trailmark). 21 languages. Optional GPU acceleration via NVIDIA CUDA. Not another semgrep wrapper. Not a vendor-locked cloud subscription that costs more than your rent.

## Install

```bash
pip install -e .
```

That's it. Python 3.12+. It pulls in `trailmark`, `fastmcp`, `fastapi`, `uvicorn`, `scipy`, and `numpy`. If you can install a pip package, you can install this. The bar is literally on the floor.

### GPU acceleration (optional)

If you have an NVIDIA GPU and want dead code analysis to run 1,474x faster instead of waiting 72 seconds like some kind of animal:

```bash
pip install -e ".[gpu]"
```

This installs CuPy with CUDA 11.x support. The GPU engine activates automatically when it detects a CUDA-capable GPU and the graph has more than 50K edges. If you don't have a GPU, everything still works on CPU via scipy. Same results, just slower on large graphs.

Requires: NVIDIA GPU (GTX 1060+), CUDA toolkit 11.x installed, ~400MB disk for CuPy.

## Run This Thing

### MCP mode (stdio — for Claude Desktop, Cursor, whatever)

```bash
audit-mcp
```

Just type that. It starts. It works. Incredible.

```bash
python -m audit_mcp
```

Same thing for people who don't trust console scripts. Both valid. Both work. Moving on.

### HTTP mode (for when you want to hit it with curl like a normal person)

```bash
audit-mcp --mode http --port 18822
```

API docs show up at `http://127.0.0.1:18822/docs`. FastAPI swagger and everything. Beautiful.

## Wire It Into Claude Desktop

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "audit-mcp",
      "args": []
    }
  }
}
```

If you didn't `pip install` it globally and you're one of those people:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "python",
      "args": ["-m", "audit_mcp"],
      "cwd": "/path/to/audit-mcp"
    }
  }
}
```

## Wire It Into Cursor

Drop this in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "audit-mcp",
      "args": []
    }
  }
}
```

## What It Actually Does

Let me walk you through the gameplay loop here because it's genuinely incredible.

### Step 1: Index the codebase

You point it at a directory. It parses everything. 21 languages. Builds the full call graph. If you have a GPU, it also builds a CSR sparse adjacency matrix and transfers it to VRAM for later queries. Returns immediately and does the work in the background like a responsible adult.

```
index_codebase(path="/path/to/project")
-> {index_id: "a1b2c3", status: "indexing"}

poll_index(index_id="a1b2c3")
-> {status: "ready", summary: {functions: 4812, call_edges: 18234, entrypoints: 47}}
```

4,812 functions. 18,234 call edges. 47 entrypoints. It just mapped your entire attack surface in seconds. That's pretty solid.

### Step 2: See where the danger is

```
attack_surface(index_id="a1b2c3")
-> entrypoints with trust levels, blast radius, framework detection

preanalysis(index_id="a1b2c3")
-> blast radius top-50, privilege boundaries, taint propagation
```

It tells you which functions are exposed to the internet. Which ones have the highest blast radius. Which ones cross privilege boundaries. This is the information that every other tool just doesn't give you. Absolutely magnificent.

### Step 3: Run scanners and correlate

Here's where the magic happens. You run semgrep or bandit or whatever scanner you want, and this thing takes the raw findings and overlays them on the graph. The result is findings ranked by actual exploitability, not alphabetical order.

```
scan_and_correlate(index_id="a1b2c3", scanner="semgrep")
-> {task_id: "d4e5f6", status: "running"}

poll_task(task_id="d4e5f6")
-> findings sorted by risk_score (tainted + reachable + high blast radius = highest priority)
```

"Semgrep found 47 SQL injections. Of those, 12 are tainted from entrypoints. Of those, 3 have blast radius over 50. Start there." That's the output. That's the value proposition. You're welcome.

### Step 4: Ask it security questions

This is the part that goes absolutely dummy hard.

```
taint_paths_to(index_id="a1b2c3", sink_name="eval")
-> all entrypoint-to-eval call paths

callers_of(index_id="a1b2c3", name="parse_input", exclude_hubs=true)
-> direct callers, minus the logging/utility noise

dead_code(index_id="a1b2c3")
-> {task_id: ..., status: "running"}  # runs async, 49ms on GPU, 72 seconds without

paths_between(index_id="a1b2c3", source="handle_request", target="execute_query")
-> top 5 shortest call paths between two functions
```

"Is `eval()` reachable from the network?" One call. Answer. Done. No grepping through 50,000 files like a caveman.

### Step 5: Diff versions

```
diff_codebases(index_id_a="v1", index_id_b="v2")
-> added/removed/changed functions, attack surface delta

attack_surface_diff(index_id_a="v1", index_id_b="v2")
-> new entrypoints, removed validation, blast radius changes
```

"This PR added 3 new entrypoints and removed a validation check. Attack surface grew by 8%." That's the kind of sentence that makes security reviews actually useful instead of just theater.

## The Full Arsenal (41 Tools)

| Category | Tools | What They Do |
|---|---|---|
| **Index lifecycle** | `index_codebase`, `poll_index`, `list_indexes` | Parse + analyze codebases |
| **Graph queries** | `callers_of`, `callees_of`, `ancestors_of`, `reachable_from`, `paths_between`, `search_functions` | Navigate the call graph (GPU-accelerated) |
| **Security analysis** | `attack_surface`, `preanalysis`, `complexity_hotspots`, `entrypoint_paths_to`, `taint_paths_to` | Map attack surface + taint |
| **Deep audit** | `dead_code`, `unreachable_from_entrypoints`, `fuzzing_targets` | Graph-aware security analysis (GPU-accelerated) |
| **Scanners** | `list_scanners`, `run_scanner`, `scan_and_correlate`, `augment_sarif` | Run SAST tools + correlate |
| **Annotations** | `annotate_function`, `annotations_of`, `findings`, `clear_annotations`, `nodes_with_annotation`, `functions_that_raise` | Tag + query findings |
| **Diffing** | `diff_codebases`, `attack_surface_diff` | Version comparison |
| **Scale** | `plan_partitions`, `export_graph`, `cache_stats`, `clear_cache`, `memory_usage` | Large codebase support |
| **Async** | `poll_task`, `list_tasks` | Background task management |
| **Utilities** | `supported_languages`, `detect_languages` | Language detection |

41 tools. Every single one returns structured JSON. No parsing stdout like it's 2003.

## GPU Acceleration

The graph engine converts trailmark's call graph into a CSR sparse adjacency matrix and runs BFS/reachability via sparse matrix-vector multiplication. On an NVIDIA GPU, this runs on CUDA via CuPy. Without a GPU, the exact same code runs on CPU via scipy. The API is identical either way — you never think about it.

### What runs on GPU

| Operation | CPU (trailmark) | GPU (RTX 3080) | Speedup | How |
|---|---|---|---|---|
| **dead_code** (Chromium, 35K nodes) | 72,148ms | 49ms | **1,474x** | Precomputed in-degree array vs callers_of per node |
| **hub detection** (Chromium, 455K edges) | 82,000ms | 0.3ms | **~270,000x** | In-degree from CSR vs callers_of per node |
| **SpMV single BFS** (1M edges) | 12.3ms | 0.22ms | **56x** | cuSPARSE vs scipy |
| **Batched 50 BFS** (1M edges) | 560ms | 85ms | **7x** | One batched SpMV vs 50 serial traversals |

### What stays on CPU (and why)

| Operation | Time | Why not GPU |
|---|---|---|
| **Parsing** (tree-sitter) | 91% of index time | Sequential per file. Native C code. GPU can't help. |
| **Graph merge** | 2.3% | Python dict operations. GPU can't run CPython. |
| **Entrypoint detection** | 2.7% | Pattern matching on annotations. Already fast. |
| **Regex search** | <100ms | Branch-heavy. GPU hates branch divergence. |

The GPU doesn't touch trailmark at all. Trailmark does the parsing and modeling (the part it's good at). Our `GpuGraphEngine` does the traversal and analysis (the part GPUs are good at). Clean boundary, no coupling.

### Activation

The GPU engine activates automatically when:
1. CuPy is installed (`pip install -e ".[gpu]"`)
2. A CUDA-capable GPU is detected
3. The graph has more than 50,000 edges

Below 50K edges, CPU is faster because GPU memory transfer overhead exceeds the compute gain. The threshold is adaptive — you never configure it.

### Benchmarked on RTX 3080

Raw SpMV numbers (CuPy 13.6, CUDA 11.8, 8704 CUDA cores, 10GB VRAM):

| Scale | Nodes | Edges | CPU SpMV | GPU SpMV | Speedup |
|---|---|---|---|---|---|
| Small | 10K | 100K | 0.10ms | 0.06ms | 1.7x |
| Medium | 100K | 1M | 0.95ms | 0.06ms | **16x** |
| Large | 500K | 5M | 5.84ms | 0.12ms | **49x** |
| XL | 1M | 10M | 12.3ms | 0.22ms | **56x** |

## Scanners

These are optional. Install whichever ones cover your stack. `list_scanners()` tells you what's available on your machine.

| Scanner | Languages | How to Get It |
|---|---|---|
| [semgrep](https://semgrep.dev) | 13 languages | `pip install semgrep` |
| [bandit](https://bandit.readthedocs.io) | Python | `pip install bandit` |
| [trivy](https://trivy.dev) | 10 languages | [install guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| [bearer](https://bearer.com) | 6 languages | [install guide](https://docs.bearer.com/reference/installation/) |
| [gosec](https://securego.io) | Go | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| [phpstan](https://phpstan.org) | PHP | `composer require --dev phpstan/phpstan` |

You don't need all of them. You don't need any of them. The graph analysis works standalone. The scanners are just extra firepower when you want to go absolutely nuclear on a codebase.

## Large Codebase Support

Tested against real codebases. These are actual benchmark numbers, not estimates:

| Project | Files | Functions | Call Edges | Cold Index | Warm Re-index | Search | Hub Detect | Memory |
|---|---|---|---|---|---|---|---|---|
| **nginx** | 405 | 3,183 | 22,820 | 4.1s | 290ms | 3ms | 7ms | 114 MB |
| **redis** | 570 | 10,350 | 75,981 | 8.1s | 640ms | 7ms | 21ms | 281 MB |
| **curl** | 495 | 5,151 | 40,487 | 7.5s | 580ms | 4ms | 12ms | 269 MB |
| **CPython** | 2,157 | 82,327 | 564,225 | 47s | 3.8s | 69ms | 166ms | 1.6 GB |
| **Chromium** (base+net+url+crypto) | 5,519 | 35,178 | 454,616 | 50s | 3.5s | 24ms | 0.3ms | 1.5 GB |

Cold index = first-ever parse. Warm re-index = no files changed, loads from graph cache. Search = `search_functions("parse")`. Hub detect = build in-degree index from all edges. Memory = RSS after full index + queries.

Where time actually goes on Chromium (20.5 seconds pipeline):

| Stage | Time | % | GPU-able? |
|---|---|---|---|
| parse (tree-sitter) | 18.7s | 91% | No — sequential per file |
| merge + entrypoints | 1.1s | 5% | No — Python objects |
| preanalysis | 0.5s | 2.4% | Replaced by GPU engine |
| GPU engine build | 1.3s | — | CSR construction + CUDA transfer |

What makes this work:

- **GPU graph engine** — converts the call graph to a CSR sparse matrix. BFS, reachability, blast radius, dead code all run via SpMV on the GPU. CPU fallback via scipy when no GPU is available. Dead code analysis: 49ms GPU vs 72 seconds CPU on Chromium.
- **Bounded queries** — every graph traversal has depth limits, result caps, pagination, and hub exclusion. `ancestors_of("main")` won't OOM your machine. It returns 100 results and says "49,900 more available, refine your query." Responsible behavior.
- **Graph cache** — the merged graph gets pickled to disk. Warm re-index with no file changes: 290ms for nginx, 3.5s for Chromium. Content-hash based — if nothing changed, nothing recomputes.
- **Lazy preanalysis** — blast radius is computed on demand via batched GPU SpMV, not eagerly for every function. Because computing transitive closure for your entire codebase on startup is psychotic behavior.
- **O(1) hub detection** — precomputed in-degree array from the CSR matrix. 0.3ms for 531 hubs on Chromium's 455K edges. The non-GPU version called `callers_of()` per function and took 82 seconds.
- **Async heavy tools** — scanners and full-codebase analysis return a task ID. Poll for results. Don't block the server waiting for semgrep to finish.
- **LRU eviction** — configurable engine budget. Load 8 codebases, evict the oldest when you load the 9th. Engines reload from disk when you need them again. Memory stays bounded.
- **Partitioned indexing** — `plan_partitions()` splits a big codebase into indexable chunks by directory. Each chunk indexes independently. Cross-partition queries are not yet wired.

**What hasn't been tested:** full Chromium checkout (350K files). The sparse checkout above covers base/, net/, url/, crypto/ — 5.5K files, 35K functions. The full tree is 60x larger. If it falls over at that scale, open an issue.

## Environment Variables

| Variable | Default | What It Controls |
|---|---|---|
| `AUDIT_MCP_INDEX_DIR` | `~/.cache/audit-mcp/indexes` | Where indexes live on disk |
| `AUDIT_MCP_MAX_ENGINES` | `8` | Max engines in memory before LRU eviction kicks in |
| `AUDIT_MCP_HTTP_HOST` | `127.0.0.1` | HTTP server bind address |
| `AUDIT_MCP_HTTP_PORT` | `18822` | HTTP server port |

## Architecture

```
Source code (21 languages)
    |
    v
[trailmark] -- tree-sitter parse --> CodeGraph (Python dicts)
    |                                     |
    |                                     v
    |                          [gpu_graph.py] -- CSR sparse matrix
    |                                     |
    |                              +------+------+
    |                              |             |
    |                           [CuPy]      [scipy]
    |                           GPU SpMV    CPU SpMV
    |                              |             |
    |                              +------+------+
    |                                     |
    v                                     v
[server.py] -- 41 MCP tools ------------->  results
    |
    +-- callers_of, ancestors_of, reachable_from  --> gpu_graph BFS
    +-- dead_code, unreachable_from_entrypoints   --> gpu_graph batched BFS
    +-- blast_radius_top_n                        --> gpu_graph batched SpMV
    +-- hub_names                                 --> gpu_graph in-degree array
    +-- scan_and_correlate, augment_sarif         --> trailmark engine
    +-- annotate_function, findings               --> trailmark engine
    +-- search_functions, paths_between           --> query_bounds (bounded)
```

Trailmark owns parsing and modeling. The GPU engine owns traversal. The server owns the MCP tool surface. Clean boundaries, no coupling.

## Development

```bash
pip install -e ".[dev]"          # dev deps (pytest, ruff)
pip install -e ".[gpu]"          # GPU support (cupy-cuda11x)
pip install -e ".[dev,gpu]"      # both

python -m pytest tests/ -v       # 28 tests, <1 second
python -m ruff check src/audit_mcp/
```

## License

AGPL-3.0-or-later. Because if you're going to build on a security tool, you should contribute back. That's the social contract.
