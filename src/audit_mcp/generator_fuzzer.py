"""Generator structure fuzzer — explores async/sync generator edge cases.

Generates randomized generator functions varying:
- yield* count, nesting depth, try/catch/finally placement
- iterator protocol overrides (.done getters, .return handlers)
- async/sync cross-delegation
- SharedArrayBuffer + TypedArray interactions
- Queue flooding (.next/.return/.throw during execution)

Uses test_in_browser for automated execution + crash detection.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Any

from audit_mcp.browser_test import BrowserTestRunner

__all__ = ["GeneratorFuzzer", "FuzzResult"]

_log = logging.getLogger(__name__)


class FuzzResult:
    """Aggregated result from a fuzzing campaign."""

    __slots__ = ("total", "passed", "crashed", "timed_out", "errors",
                 "interesting", "elapsed_seconds")

    def __init__(self) -> None:
        self.total: int = 0
        self.passed: int = 0
        self.crashed: list[dict[str, Any]] = []
        self.timed_out: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.interesting: list[dict[str, Any]] = []
        self.elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "crashed": len(self.crashed),
            "timed_out": len(self.timed_out),
            "errors": len(self.errors),
            "interesting": len(self.interesting),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "crash_details": self.crashed[:10],
            "interesting_details": self.interesting[:10],
        }


class GeneratorFuzzer:
    """Fuzz generator constructs via headless browser testing."""

    def __init__(self, browser: str = "auto", seed: int | None = None) -> None:
        self._runner = BrowserTestRunner(browser=browser)
        self._rng = random.Random(seed)

    def available(self) -> bool:
        return self._runner.available()

    def fuzz(
        self,
        iterations: int = 100,
        timeout_per_test: int = 15,
        strategies: list[str] | None = None,
    ) -> FuzzResult:
        """Run a fuzzing campaign.

        ``strategies`` controls which generator patterns to test.
        Default: all strategies. Options:
        - ``"yield_star_count"`` — vary yield* count near known thresholds
        - ``"async_sync_cross"`` — async gen yield* sync iterator and vice versa
        - ``"iterator_override"`` — override Array/Object iterator protocols
        - ``"done_getter"`` — .done getter with re-entrancy
        - ``"try_finally_yield"`` — yield inside finally blocks
        - ``"queue_flood"`` — flood .next/.return/.throw during execution
        - ``"typed_array"`` — TypedArray + detachment during suspend
        - ``"nested_generators"`` — generators delegating to generators
        """
        result = FuzzResult()
        if not self.available():
            result.errors.append({"error": "No browser available"})
            return result

        all_strategies = [
            self._gen_yield_star_count,
            self._gen_async_sync_cross,
            self._gen_iterator_override,
            self._gen_done_getter_reentry,
            self._gen_try_finally_yield,
            self._gen_queue_flood,
            self._gen_typed_array,
            self._gen_nested_generators,
        ]

        strategy_map = {
            "yield_star_count": self._gen_yield_star_count,
            "async_sync_cross": self._gen_async_sync_cross,
            "iterator_override": self._gen_iterator_override,
            "done_getter": self._gen_done_getter_reentry,
            "try_finally_yield": self._gen_try_finally_yield,
            "queue_flood": self._gen_queue_flood,
            "typed_array": self._gen_typed_array,
            "nested_generators": self._gen_nested_generators,
        }

        if strategies:
            selected = [strategy_map[s] for s in strategies if s in strategy_map]
        else:
            selected = all_strategies

        t0 = time.monotonic()

        for i in range(iterations):
            strategy = self._rng.choice(selected)
            name, html = strategy()

            test_result = self._runner.run(html, timeout_seconds=timeout_per_test)
            result.total += 1

            case = {
                "iteration": i,
                "strategy": name,
                "console": test_result.console[:20],
                "errors": test_result.errors[:5],
                "exit_code": test_result.exit_code,
                "elapsed": test_result.elapsed_seconds,
            }

            if test_result.crashed:
                case["crash_reason"] = test_result.crash_reason
                result.crashed.append(case)
                _log.warning("CRASH at iteration %d (%s): %s", i, name, test_result.crash_reason)
            elif test_result.timed_out:
                result.timed_out.append(case)
            elif test_result.errors:
                # Check for interesting errors (not just syntax errors)
                if any("UNEXPECTED" in e or "!!!" in e for e in test_result.errors):
                    result.interesting.append(case)
                else:
                    result.errors.append(case)
            else:
                # Check console for interesting output
                if any("[!!!]" in line for line in test_result.console):
                    result.interesting.append(case)
                else:
                    result.passed += 1

        result.elapsed_seconds = time.monotonic() - t0
        return result

    # ------------------------------------------------------------------
    # Strategy generators — each returns (name, html_string)
    # ------------------------------------------------------------------

    def _gen_yield_star_count(self) -> tuple[str, str]:
        """Vary yield* count near known thresholds."""
        # Thresholds discovered during the hunt:
        # async: CHECK fires ~432K-435K
        # sync: CHECK fires ~1.26M
        # Stay within compilable range
        count = self._rng.choice([
            self._rng.randint(1000, 10000),
            self._rng.randint(100000, 200000),
            self._rng.randint(400000, 435000),  # near async threshold
        ])
        is_async = self._rng.choice([True, False])
        ctor = ("Object.getPrototypeOf(async function*(){}).constructor"
                if is_async else "Object.getPrototypeOf(function*(){}).constructor")

        d_def = "var d={[Symbol.iterator](){return{next(){return{done:true}}}}}};"
        if is_async:
            next_call = (
                'g.next().then(function(r){console.log("value="+r.value+" done="+r.done)})'
                '.catch(function(e){console.log("REJECT:"+e.message)})'
            )
        else:
            next_call = 'var r=g.next();console.log("value="+r.value+" done="+r.done)'

        js = (
            d_def + "\n"
            + "var GenFunc=" + ctor + ";\n"
            + "var code='var x=0xDEADBEEF;'+'yield*d;'.repeat(" + str(count) + ")+'yield x;';\n"
            + "try{\n"
            + "  var gen=new GenFunc('d',code);var g=gen(d);\n"
            + "  " + next_call + ";\n"
            + "}catch(e){console.log('CATCH:'+e.name+':'+e.message)}\n"
        )
        label = "yield_star_" + str(count) + "_" + ("async" if is_async else "sync")
        return (label, _wrap_js(js))

    def _gen_async_sync_cross(self) -> tuple[str, str]:
        """Async generator yield* to sync iterable and vice versa."""
        count = self._rng.randint(1000, 50000)
        d_def = "var d={[Symbol.iterator](){return{next(){return{done:true}}}}}};"
        js = (
            d_def + "\n"
            + "var code='yield*d;'.repeat(" + str(count) + ")+'yield 0xBEEF;';\n"
            + "var AsyncGen=Object.getPrototypeOf(async function*(){}).constructor;\n"
            + "try{\n"
            + "  var gen=new AsyncGen('d',code);var g=gen(d);\n"
            + "  g.next().then(function(r){console.log('cross value='+r.value+' done='+r.done)})\n"
            + "  .catch(function(e){console.log('REJECT:'+e.message)});\n"
            + "}catch(e){console.log('CATCH:'+e.name+':'+e.message)}\n"
        )
        return ("async_sync_cross_" + str(count), _wrap_js(js))

    def _gen_iterator_override(self) -> tuple[str, str]:
        """Override Array.prototype[Symbol.iterator] during yield*."""
        count = self._rng.randint(10000, 100000)
        js = f"""
var GenFunc = Object.getPrototypeOf(function*(){{}}).constructor;
var code = 'var x=0xFACE;' + 'yield*[1];'.repeat({count}) + 'yield x;';
var gen = new GenFunc(code);
var orig = Array.prototype[Symbol.iterator];
Array.prototype[Symbol.iterator] = function(){{return{{next:function(){{return{{done:true}}}}}}}};
try {{
  var g = gen();
  var r = g.next();
  console.log("override value="+r.value+" done="+r.done);
  if(r.value!==0xFACE&&r.value!==1)console.log("[!!!] UNEXPECTED:0x"+r.value.toString(16));
}} catch(e) {{ console.log("CATCH:"+e.message); }}
Array.prototype[Symbol.iterator] = orig;
"""
        return (f"iterator_override_{count}", _wrap_js(js))

    def _gen_done_getter_reentry(self) -> tuple[str, str]:
        """Malicious .done getter that re-enters the generator."""
        ops = self._rng.randint(1, 20)
        flood = self._rng.randint(10, 500)
        js = f"""
var gen;
var attacked = false;
var mal = {{[Symbol.asyncIterator](){{var c=0;return{{next:function(){{
  c++;if(c>5)return Promise.resolve({{done:true}});
  var r={{}};Object.defineProperty(r,'done',{{get:function(){{
    if(c===2&&gen&&!attacked){{attacked=true;
      for(var i=0;i<{flood};i++)gen.next('z'+i);
      for(var i=0;i<{ops};i++){{gen.return('r'+i);gen.throw(new Error('t'+i));}}
    }}return false;
  }}}});r.value=c*10;return Promise.resolve(r);
}}}}}}}};
async function run(){{
  var agf=Object.getPrototypeOf(async function*(){{}}).constructor;
  var body='try{{yield*mal;}}finally{{for(var i=0;i<{flood+ops*2+10};i++){{';
  body+='var z=yield i;if(typeof z==="object"&&z!==null)';
  body+='console.log("[!!!]OBJ at i="+i)}}}}';
  var fn=new agf('mal',body);
  gen=fn(mal);
  for(var i=0;i<{flood+ops*2+20};i++){{
    var r=await gen.next('d'+i);
    if(r.done){{console.log("done at "+i);break}}
  }}
}}
run().catch(function(e){{console.log("FATAL:"+e.message)}});
"""
        return (f"done_getter_flood_{flood}_ops_{ops}", _wrap_js(js))

    def _gen_try_finally_yield(self) -> tuple[str, str]:
        """Yield inside nested try/finally blocks in a generator."""
        depth = self._rng.randint(2, 50)
        yields_per_level = self._rng.randint(1, 5)
        js_parts = ["var a=0;"]
        for i in range(depth):
            js_parts.append("try {")
        for _ in range(yields_per_level):
            js_parts.append("yield a++;")
        for i in range(depth):
            js_parts.append("} finally { yield a++; }")

        body = "\\n".join(js_parts)
        js = f"""
var GenFunc = Object.getPrototypeOf(function*(){{}}).constructor;
try {{
  var gen = new GenFunc('{body}');
  var g = gen();
  for(var i=0;i<{depth*2+yields_per_level+5};i++){{
    var r=g.next();
    if(r.done){{console.log("done at "+i+" val="+r.value);break}}
  }}
  console.log("try_finally ok depth={depth}");
}} catch(e) {{ console.log("CATCH:"+e.message); }}
"""
        return (f"try_finally_d{depth}_y{yields_per_level}", _wrap_js(js))

    def _gen_queue_flood(self) -> tuple[str, str]:
        """Flood async generator queue with interleaved operations."""
        queue_size = self._rng.randint(100, 5000)
        js = f"""
async function run(){{
  var gen=(async function*(){{yield 1;await new Promise(function(){{}});}})();
  await gen.next();
  gen.next();
  await new Promise(function(r){{setTimeout(r,50)}});
  var t0=performance.now();
  for(var i=0;i<{queue_size};i++)gen.next('q'+i);
  var elapsed=performance.now()-t0;
  console.log("queued {queue_size} in "+elapsed.toFixed(0)+"ms");
  if(performance.memory)console.log("heap="+Math.round(performance.memory.usedJSHeapSize/1024/1024)+"MB");
}}
run().catch(function(e){{console.log("FATAL:"+e.message)}});
"""
        return (f"queue_flood_{queue_size}", _wrap_js(js))

    def _gen_typed_array(self) -> tuple[str, str]:
        """TypedArray detachment during generator suspend."""
        js = """
var shared={buf:null};
var mal={[Symbol.iterator](){var c=0;return{next(){
  c++;if(c>3)return{done:true};
  var r={};Object.defineProperty(r,'done',{get:function(){
    if(c===2&&shared.buf){try{structuredClone(shared.buf,{transfer:[shared.buf]})}catch(e){}}
    return false;
  }});r.value=c;return r;
}}}};
var GenFunc=Object.getPrototypeOf(function*(){}).constructor;
var fn=new GenFunc('mal','shared',
  'var buf=new ArrayBuffer(1024);var ta=new Uint32Array(buf);'+
  'for(var i=0;i<256;i++)ta[i]=0x41414141;shared.buf=buf;'+
  'yield*mal;'+
  'console.log("after:byteLen="+buf.byteLength+" ta.len="+ta.length+" ta[0]="+ta[0]);'+
  'if(buf.byteLength===0)console.log("detached ok");'+
  'if(ta[0]!==undefined&&ta[0]!==0)console.log("[!!!] READ AFTER DETACH:0x"+ta[0].toString(16))'
);
var g=fn(mal,shared);
for(var i=0;i<10;i++){var r=g.next();if(r.done)break}
"""
        return ("typed_array_detach", _wrap_js(js))

    def _gen_nested_generators(self) -> tuple[str, str]:
        """Generator yield* to another generator with re-entrancy."""
        inner_yields = self._rng.randint(5, 100)
        js = f"""
var outerGen;
function* inner(){{for(var i=0;i<{inner_yields};i++){{
  if(i===3&&outerGen){{try{{outerGen.return('kill')}}catch(e){{}}}}
  yield i;
}}}}
function* outer(){{
  var secret=0xDEADBEEF;
  yield* inner();
  console.log("after yield* secret=0x"+secret.toString(16));
  yield secret;
}}
outerGen=outer();
for(var i=0;i<{inner_yields+5};i++){{
  var r=outerGen.next();
  if(r.done){{console.log("done at "+i);break}}
}}
console.log("nested ok yields={inner_yields}");
"""
        return (f"nested_gen_{inner_yields}", _wrap_js(js))


def _wrap_js(js: str) -> str:
    """Wrap JavaScript in minimal HTML."""
    return f"<script>{js}</script>"
