# Source Code Audit MCP — Competitive Analysis & Differentiation

## The Existing Landscape (May 2026)

### Tier 1: Vendor MCP Servers (single-tool wrappers)

| Server | What it does | Limitation |
|---|---|---|
| **Semgrep MCP** (`semgrep mcp`) | Run semgrep scans, write custom rules | One tool. No graph context. No correlation. |
| **Snyk MCP** | SCA + SAST via Snyk API | Cloud-dependent. Requires Snyk account. |
| **SonarQube MCP** | Quality + security issues | Cloud or self-hosted SonarQube. No attack surface context. |
| **Trivy MCP** | Container + IaC + SBOM | Focused on deps/config, not source-level bugs. |
| **Datadog Code Security MCP** | SAST + SCA + secrets + IaC | Requires Datadog subscription. Cloud-only. |

**Their problem:** Each wraps ONE vendor's tool. No cross-tool correlation. No understanding of what's reachable from attacker input vs what's dead code.

### Tier 2: Multi-tool Aggregators

| Server | What it does | Limitation |
|---|---|---|
| **sast-mcp** (GitHub) | 23+ tools bundled (Semgrep, Bandit, Gosec, Brakeman, TruffleHog, Checkov, tfsec, Nikto, Nmap) | Kitchen sink. No prioritization. No graph. Dumps raw findings without context. "Swiss Army knife" — everything and nothing. |

**Their problem:** More tools ≠ better results. 23 tools × 80% false positive rate = noise. No way to answer "which of these 200 findings are actually exploitable?"

### Tier 3: MCP Security Scanners (scan MCP servers themselves)

| Server | What it does | Limitation |
|---|---|---|
| **Cisco Skill Scanner** | Scan MCP tool descriptions for prompt injection | Scans MCP servers, not source code. YARA-based — 78% false positive rate. |
| **Snyk mcp-scan** | Audit MCP server security | Same — audits MCP infra, not application code. |

**Their problem:** They secure the MCP protocol, not the code being analyzed.

---

## What NONE of Them Do

1. **Code graph context.** Nobody builds a function-level call graph and uses it to prioritize findings. Semgrep says "line 42 has a SQL injection." But is line 42 reachable from a public HTTP handler? Or is it in a test helper nobody calls? No existing MCP answers this.

2. **Taint-aware prioritization.** "47 findings. 12 are in functions tainted by untrusted input. 3 of those have blast radius > 50. Start there." Zero competitors do this.

3. **Attack surface mapping FIRST, then scanning.** Every competitor scans first, triages second. We map the attack surface (entrypoints, trust boundaries, taint propagation) THEN scan, so findings arrive pre-prioritized.

4. **Structural diffing for patch review.** "What changed between v1.2 and v1.3? 4 new functions, 2 removed, 1 entrypoint added, attack surface grew by 8%." Nobody does this except us (via trailmark).

5. **Cross-scanner dedup.** Run semgrep + bandit on the same codebase. Same function gets flagged twice (semgrep calls it "injection", bandit calls it "B603"). Nobody deduplicates across scanners using graph identity.

---

## Our Differentiation: Graph-First Audit

**Name: Source Code Audit MCP** (or `audit-mcp`)

### What we are
A code graph intelligence server that understands your codebase STRUCTURALLY — functions, calls, entrypoints, trust boundaries, taint flows — and uses that understanding to run, correlate, and prioritize security findings from any SAST tool.

### What we are NOT
- Not another semgrep wrapper
- Not a vendor-locked cloud service
- Not a tool aggregator that dumps raw results

### The value proposition in one sentence
**"We tell you which 5 of the 200 SAST findings actually matter."**

---

## Feature Comparison

| Feature | Semgrep MCP | sast-mcp | Datadog MCP | **Us** |
|---|---|---|---|---|
| SAST scanning | Semgrep only | 23 tools | DD engine | Any SARIF-producing tool |
| Code graph | No | No | No | **Trailmark (21 languages)** |
| Entrypoint detection | No | No | No | **Auto (30+ frameworks)** |
| Taint propagation | No | No | No | **Graph-based** |
| Blast radius | No | No | No | **Per-function** |
| Privilege boundaries | No | No | No | **Detected** |
| Finding correlation | No | No | No | **Risk-scored** |
| Structural diff | No | No | No | **Version diffing** |
| Attack surface map | No | No | No | **Full map** |
| Cross-scanner dedup | No | No | No | **Graph-identity** |
| Custom rules | Semgrep rules | Per-tool | DD rules | **Any SARIF source** |
| Cloud required | Semgrep.dev | No | Datadog | **No** |
| Cost | Free/paid | Free | $$$ | **Free (AGPL)** |
| Languages | 30+ (semgrep) | Varies | Limited | **21 (trailmark)** |

---

## Tools to Add (Beyond Current 28)

### Already Built (28 tools)
Graph queries (12), scanner orchestration (4), annotations (6), indexing (3), utilities (3)

### Phase 2: Deep Audit Tools

| Tool | What it does | Why unique |
|---|---|---|
| `dependency_audit(index_id)` | Extract imports/requires, check against OSV/NVD for known CVEs | Graph-aware: only flags deps actually USED in tainted paths |
| `secrets_scan(index_id)` | Run TruffleHog/Gitleaks, correlate with graph | Only flags secrets in functions reachable from entrypoints |
| `dead_code(index_id)` | Functions with zero callers AND not entrypoints | Safe to remove — reduces attack surface |
| `unreachable_from_entrypoints(index_id)` | Functions no entrypoint can transitively reach | Not exploitable by external attackers |
| `taint_paths_to_sink(index_id, sink)` | All entrypoint→sink paths with edge confidence | Direct "is this SQL injection reachable from the network?" answer |
| `cross_scanner_dedup(index_id)` | After running multiple scanners, merge by graph node | "Semgrep and Bandit both flagged parse_input — one finding, not two" |
| `audit_report(index_id, format)` | Generate consolidated report (JSON/HTML/SARIF) | Pre-prioritized by taint + blast radius + entrypoint reachability |
| `suggest_fuzzing_targets(index_id)` | High-complexity entrypoints processing untrusted input | "These 5 functions are the highest-value fuzzing targets" |
| `diff_attack_surface(index_id_a, index_id_b)` | How did the attack surface change between versions? | "3 new entrypoints, 2 new tainted sinks, blast radius of parse_request grew from 50 to 89" |
| `compliance_check(index_id, standard)` | Map findings to CWE/OWASP Top 10 | "Which OWASP categories have confirmed tainted findings?" |

### Phase 3: AI-Enhanced

| Tool | What it does |
|---|---|
| `explain_finding(index_id, node_name)` | LLM-generated explanation of why a finding matters, with graph context |
| `suggest_fix(index_id, node_name)` | LLM-generated fix suggestion with call-site impact analysis |
| `review_pr(index_id_before, index_id_after)` | Security-focused PR review: new entrypoints, new tainted paths, removed validation |

---

## Architecture Advantage

```
Competitor architecture:
  Scanner → Raw findings → Dump to user → User triages manually

Our architecture:
  1. Parse → Code graph (trailmark, 21 languages)
  2. Analyze → Entrypoints, taint, blast radius, privilege boundaries
  3. Scan → Any SARIF tool (semgrep, bandit, trivy, bearer, gosec, phpstan)
  4. Correlate → Map findings to graph nodes
  5. Prioritize → Score by taint + reachability + blast radius
  6. Report → "These 5 of 200 findings are critical. Here's why."
```

The graph is the moat. Every tool on the market scans code as flat files. We scan code as a GRAPH with security semantics (trust, taint, blast radius). That's a fundamentally different approach that no competitor has.

---

## Naming Decision

**`audit-mcp`** — Source Code Audit MCP

- Short, memorable, descriptive
- Not tied to one tool or vendor
- "Audit" implies the graph + prioritization layer, not just scanning
- Scope: source code security audit (not MCP server audit — that's Cisco/Snyk's territory)
