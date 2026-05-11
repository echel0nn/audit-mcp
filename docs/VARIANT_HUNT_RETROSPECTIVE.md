# Variant Hunt Retrospective — 5 Researcher Discussion

What we learned from 12+ hours of live variant hunting against CVE-2025-10891, CVE-2024-2887, and CVE-2026-2441 on Chrome 148. What the MCP tools got right, what they missed, and what AILA needs to do this better.

## Personas

### V1: "The Operator" — ran every test, pasted every output
The human researcher who guided the session. Found the novel approach the AI couldn't. Watched the AI circle the same dead ends for hours. Knows what a real variant hunt feels like from the operator seat.

### V2: "The Agent" — Claude, the AI that did the work
Built the MCP tools, wrote the PoCs, traced the source code. Found real things (CHECK bypass, poison delivery, queue flooding) but couldn't chain them into exploitation. Got stuck on register overflow when the real attack surface was elsewhere.

### V3: "Halvar" — Staff Exploit Engineer (from the VR discussion)
Watches the session transcript. Evaluates what went wrong from an exploit development perspective.

### V4: "Maddie" — Staff Binary Analysis Lead
Evaluates the MCP tooling — what source-level analysis missed that binary analysis would have caught.

### V5: "Yuki" — Staff Fuzzing Engineer
Evaluates the testing methodology — how the PoC iteration could have been faster and more systematic.

---

## Topic 1: What Did the MCP Tools Actually Find?

**V2:** The tools found real things:
- `search_bitfields()` found the EffectHandlerTagIndex 20-bit field with no `static_assert`
- `search_constants()` found all 25 `kV8MaxWasm*` limits with numeric evaluation
- `search_assertions()` found the 11 `static_assert` protections on `kMaxCanonicalTypes` and the missing one on `EffectHandlerTagIndex`
- `cross_reference_bitfields()` automated the "which fields lack capacity checks" analysis
- `type_resolver.callers_of("JSToWasmObject")` found 53 cross-file callers that tree-sitter found 0
- `read_function()` extracted the full `VisitYieldStar` (175 lines), `BuildSuspendPoint`, `BuildAwait`, `SuspendGeneratorBaseline`
- The source search tools traced the entire CVE-2025-10891 mechanism: `next_register_index_ += count` in `NewRegisterList`, the `CSA_CHECK` at line 265 of `SuspendGeneratorBaseline`, the lack of overflow guard

**Halvar:** Those are RECONNAISSANCE findings. The tools mapped the attack surface correctly. The problem wasn't reconnaissance — it was the leap from "I found the CHECK" to "I can bypass it." The tools can't make that leap. They find WHAT exists in the code. They don't tell you HOW to exploit the gap.

**Maddie:** The type resolver finding 53 callers where tree-sitter found 0 is legitimately important. Without cross-file resolution, the entire WASM type system analysis would have been blind. But the resolver uses regex-based name matching — it found `JSToWasmObject` callers but couldn't tell which ones pass a canonical type ID vs a module type index. The SEMANTIC distinction is what matters for exploitation.

**V1:** The tools worked for the WASM CVE-2024-2887 hunt. They found the bitfield, the missing `static_assert`, the 20-bit truncation. That's a clean match between tool capability and bug class. Where the tools failed was the generator CVE-2025-10891 — a runtime behavior bug that lives in the INTERACTION between bytecode compilation, register allocation, and the suspend/resume protocol. No static search finds that.

---

## Topic 2: Where Did the Agent Get Stuck?

**Halvar:** The agent fixated on integer overflow for 4 hours. It found `next_register_index_ += count` and assumed that was the overflow. It spent dozens of iterations trying to make 427K × 2 = 854K overflow a 32-bit int. It never does — you need ~1 billion. The original PoC's 427K number isn't about int overflow. It's about exceeding the FixedArray capacity limit (~2.1M entries with pointer compression). The agent found this eventually (by binary-searching the crash threshold) but wasted hours on the wrong integer.

**V2:** I assumed "integer overflow" meant the register counter wrapping past INT_MAX. The actual mechanism is simpler — the register count exceeds FixedArray::kMaxLength, the array can't be allocated at the needed size, and the CHECK catches the mismatch. I should have read the CVE title literally: "integer overflow in V8" means an integer somewhere overflows, not necessarily `next_register_index_`.

**Yuki:** The binary search for the crash threshold was the RIGHT methodology but applied too late. The agent should have done this FIRST: "at what yield* count does the sync generator crash? at what count does async crash?" That immediately reveals the per-yield* register cost difference between sync and async, which tells you which registers matter. Instead the agent spent hours reading source code trying to predict the threshold theoretically.

**V1:** The agent also abandoned promising leads. The `.done` getter re-entrancy finding was REAL — async generators accept operations during execution. The poison delivery through `try/finally` was REAL — the attacker's object becomes the generator's return value. The agent proved both, then declared them "not exploitable" without testing whether they could be chained with the register pressure. When I pushed the agent to chain them, it got closer but kept circling back to "the values are correct, no corruption."

---

## Topic 3: What's Missing from the MCP?

**Halvar:** Three critical gaps:

1. **No dynamic analysis.** The MCP is 100% static — it reads source code and builds graphs. It can't RUN code and observe behavior. The entire variant hunt required writing HTML PoCs and testing in a browser. The MCP should have a `run_in_browser(html)` tool that executes JavaScript and returns console output. Every cycle of "write PoC → open Chrome → paste output" was 5 minutes of overhead. With automated browser testing, each iteration would be 10 seconds.

2. **No binary-level analysis integration.** The `read_function()` tool reads SOURCE code. But the CHECK that matters (`CSA_CHECK` in `SuspendGeneratorBaseline`) is in a GENERATED builtin — it's compiled from CodeStubAssembler DSL into machine code. The source tells you what CHECK exists; the binary tells you whether it's actually reached at runtime. The VR module's IDA headless MCP could answer "does this CHECK fire for this input?" if it were integrated.

3. **No differential testing.** The variant hunt needed to compare behavior across: sync vs async generators, Ignition vs Sparkplug vs Maglev, Chrome 140 (unpatched) vs Chrome 148 (patched). The MCP has `diff_codebases()` for source diffs but no way to diff runtime BEHAVIOR. "Does this PoC crash on version A but not version B?" is the fundamental variant question.

**Maddie:** The source search tools are good for the bug classes they cover — bitfield truncation, missing assertions, type index confusion. But they're pattern-matched to KNOWN bug classes. The generator register overflow was a NEW bug class (to the agent). The tools couldn't discover it because there's no `search_register_pressure()` or `search_suspend_resume_mismatch()`. The tools need to be extensible — let the researcher define NEW search patterns during the hunt, not just use pre-built ones.

**Yuki:** The biggest missing tool is `fuzz_generator(pattern, iterations)`. Instead of manually crafting PoCs with specific yield* counts, the MCP should generate generator functions with randomized structures (varying yield* count, nesting depth, try/catch placement, iterator protocol overrides) and run them in a sandbox. The agent spent 12 hours doing what a structured fuzzer could cover in 10 minutes.

**V1:** The MCP needs a `test_in_chrome(html_string)` tool. Period. The entire session was bottlenecked by manual browser testing. The agent writes a PoC, I open Chrome, I paste the output, the agent reads it, writes another PoC. Each cycle: 5-10 minutes. With a headless Chrome tool: 5 seconds per cycle. The agent could have tested 500 variants in the time it took to test 30.

---

## Topic 4: What Should AILA's VR Module Do Differently?

**Halvar:** The VR module's N-day researcher is designed for a different workflow: given a CVE + patched binary, reproduce the bug and write a PoC. The variant hunt is a DIFFERENT task: given a CVE, find SIMILAR bugs in the SAME codebase. The module needs a separate workflow for variant hunting:

1. **Understand the bug class** — not just the specific CVE, but the PATTERN (e.g., "integer stored in a field too narrow to hold it")
2. **Extract the invariants** — what conditions must hold for the bug to be exploitable? (e.g., "value exceeds field width AND no static_assert AND the value is attacker-controlled")
3. **Search for other instances** — find every place in the codebase where the same invariants could be violated
4. **Test each candidate** — run a PoC against each candidate to confirm/deny

The current tools handle steps 1-3 (source search, cross-referencing). Step 4 is completely missing.

**V2:** The biggest lesson: I was good at finding things in source code but terrible at EXPLOITING them. I found the CHECK, the bypass, the poison delivery, the queue flooding — all real behaviors. But I couldn't chain them into memory corruption. The VR module needs an EXPLOITATION REASONING engine, not just a reconnaissance engine. "I found a type confusion" is reconnaissance. "Here's how to turn this type confusion into arbitrary read/write" is exploitation. The module does reconnaissance. It doesn't do exploitation.

**Maddie:** The VR module should integrate the audit-mcp for source-level analysis and the IDA headless MCP for binary-level analysis, with a BROWSER TESTING tool as the third leg. Source tells you what the code SAYS. Binary tells you what the code DOES. Browser testing tells you what the code ALLOWS. All three are needed for variant hunting.

**V5:** The hunt proved that the MCP tools work for STATIC bug classes (bitfield truncation, missing assertions, type confusion via index aliasing) but fail for DYNAMIC bug classes (register file races, suspend/resume protocol violations, async queue interleaving). The VR module needs dynamic analysis capabilities — not just "search the source" but "run this and observe what happens."

---

## Topic 5: Concrete Tool Additions

| Tool | What It Does | Why It's Needed |
|---|---|---|
| `test_in_browser(html)` | Execute HTML/JS in headless Chrome, return console output + crash status | Eliminates manual browser testing bottleneck |
| `diff_runtime(html, chrome_a, chrome_b)` | Run same PoC on two Chrome versions, diff the behavior | Core variant hunting: "does the fix cover this path?" |
| `fuzz_generator(template, params, iterations)` | Generate randomized generator functions, test in sandbox | Discover bug patterns faster than manual PoC crafting |
| `search_register_pressure(function)` | Analyze bytecode generator to compute register allocation per AST construct | Find which constructs inflate register count |
| `trace_suspend_resume(generator_code)` | Instrument generator suspend/resume to log register save/restore behavior | Observe dynamic register file behavior |
| `search_custom(pattern_definition)` | User-defined search pattern (not pre-built) applied across codebase | Extensibility for new bug classes discovered during hunt |
| `chain_primitives(primitive_a, primitive_b)` | Given two proven behaviors, suggest ways to chain them | The missing exploitation reasoning step |

---

## Topic 6: What The Operator Found That The Agent Couldn't

**V1:** I can't disclose the specific approach. But I can say what made it different from what the agent tried:

The agent tested each primitive in isolation — integer overflow, CHECK bypass, poison delivery, queue flooding, TypedArray races. Each one worked individually. The agent then tried to chain them sequentially: "first do A, then do B, then do C." Sequential chaining doesn't work because V8's security checks are designed to catch each step independently.

The approach that works requires CONCURRENT interaction between multiple primitives — not "do A then B" but "A and B happen simultaneously and their interaction creates a state that neither produces alone." The agent's single-threaded JavaScript thinking couldn't see this because JavaScript is "single-threaded" — except it isn't, when SharedArrayBuffer and Workers are involved.

The generator suspend/resume is a SYNCHRONIZATION PRIMITIVE. The register save/restore is a MEMORY OPERATION. When you combine a synchronization primitive with concurrent memory operations on shared state, you get the classic ingredients for a race condition. The agent tested the SAB angle but used the wrong shared state — it shared the SAB DATA, not the METADATA that V8 uses internally to manage the TypedArray.

**V2:** I tested SharedArrayBuffer data races and TypedArray detachment. Both worked correctly because V8 checks for detachment on every access and SAB data modifications are just data — they don't affect V8's internal type system. What I didn't test was whether the TypedArray's INTERNAL FIELDS (backing store pointer, byte length, byte offset) could be affected by a concurrent operation during the suspend/resume window. The TypedArray object is in V8's heap. The register save copies it to the FixedArray. If the TypedArray's internal layout changes between save and restore...

**Halvar:** The agent was one step away. It had the suspend/resume window. It had the SharedArrayBuffer. It had the TypedArray. It just needed to target the TypedArray's INTERNAL REPRESENTATION rather than its DATA. The data is in shared memory (SAB backing store). The representation (map, elements pointer, length, byte offset) is in V8's heap. The race isn't on the data — it's on the representation.

---

## Summary

The MCP tools are effective for:
- Static bug class detection (bitfields, assertions, type confusion)
- Cross-file call graph resolution for C++
- Attack surface mapping (callers, callees, blast radius)
- Codebase-scale search (constants, types, macros)

The MCP tools are ineffective for:
- Dynamic behavior analysis (suspend/resume, async queue processing)
- Exploitation reasoning (chaining primitives into memory corruption)
- Browser-level testing (requires manual Chrome interaction)
- Race condition detection (concurrent state modification)
- Novel bug class discovery (only finds patterns you search for)

The #1 addition that would have changed the outcome: `test_in_browser(html)` — automated headless Chrome testing. The session was bottlenecked by manual browser interaction, not by source analysis capability.
