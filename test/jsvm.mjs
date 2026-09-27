// jsvm.mjs — prove the JS->bytecode compiler + JS-value VM run REAL JS correctly:
// for each function, compile+virtualize it and compare its output to the native function
// over many inputs. This is the "feed a JS function, run it through the custom VM" claim.

import assert from "node:assert/strict";
import { compileFunctionSource } from "../src/jsc/compile.js";
import { createVM } from "../src/jsvm/vm.js";

let pass = 0;
const ok = (n) => (console.log(`  ✓ ${n}`), pass++);

// host globals the VM may reference
const globals = { Math, JSON, Object, Array, String, Number, Boolean, parseInt, parseFloat, isNaN };

const eq = (a, b) => {
  if (typeof a === "object" && a !== null) return JSON.stringify(a) === JSON.stringify(b);
  return Object.is(a, b);
};

function check(name, src, cases) {
  const native = eval(`(${src})`);
  const mod = compileFunctionSource(src);
  const vm = createVM(mod, globals);
  for (const args of cases) {
    const want = native(...args);
    const got = vm(...args);
    assert.ok(eq(want, got), `${name}(${JSON.stringify(args)}): want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
  }
  ok(`${name}  (${cases.length} cases, ${mod.functions.length} fn, ${mod.functions.reduce((s, f) => s + f.code.length, 0)} words)`);
}

// 1. arithmetic + precedence + bitwise
check("arith", `function(a,b){ return (a*2 + b) % 7 ^ (a & b) | (b << 1); }`,
  [[3, 4], [10, 2], [0, 0], [255, 17], [-5, 9]]);

// 2. if / ternary / comparison / logical
check("branch", `function(x){ let s = x > 10 ? "big" : (x < 0 ? "neg" : "mid"); return s + ":" + (x >= 0 && x < 100); }`,
  [[-3], [5], [50], [200]]);

// 3. while loop + accumulation
check("whilesum", `function(n){ let i=0, s=0; while(i<=n){ s += i; i++; } return s; }`,
  [[0], [1], [5], [10], [100]]);

// 4. for loop with break/continue
check("forbc", `function(n){ let s=0; for(let i=0;i<n;i++){ if(i%2===0) continue; if(i>15) break; s+=i; } return s; }`,
  [[0], [10], [20], [50]]);

// 5. recursion (entry self-call): factorial + fibonacci
check("fact", `function fact(n){ return n<=1 ? 1 : n*fact(n-1); }`, [[0], [1], [5], [10]]);
check("fib", `function fib(n){ if(n<2) return n; return fib(n-1)+fib(n-2); }`, [[0], [1], [7], [12]]);

// 6. nested function declaration + mutual use + closure over param
check("closure", `function(base){
  function add(x){ return x + base; }
  function twice(x){ return add(add(x)); }
  return twice(10);
}`, [[1], [5], [-2]]);

// 7. counter factory (closure captures/mutates outer var)
check("counter", `function(start){
  let n = start;
  function inc(){ n = n + 1; return n; }
  inc(); inc();
  return inc();
}`, [[0], [40], [-3]]);

// 8. arrays + objects + method calls (host Math / Array)
check("data", `function(xs){
  let obj = { sum: 0, max: xs[0] };
  for (let i=0;i<xs.length;i++){ obj.sum += xs[i]; if (xs[i] > obj.max) obj.max = xs[i]; }
  return { total: obj.sum, biggest: obj.max, mean: obj.sum / xs.length, sqrtMax: Math.sqrt(obj.max) };
}`, [[[3, 1, 4, 1, 5, 9, 2, 6]], [[10]], [[-2, -9, -1]]]);

// 9. string ops + template literal + method call
check("strings", `function(name, n){ return \`hi \${name}!\`.toUpperCase() + " x" + (n+1) + " " + "ab".repeat(n); }`,
  [["void", 2], ["brittle", 0], ["x", 3]]);

// 10. a realistic "license check" style function (the kind you'd actually virtualize)
check("license", `function verify(seed, salt){
  let h = 2166136261;
  let s = String(seed) + ":" + String(salt);
  for (let i=0;i<s.length;i++){ h = h ^ s.charCodeAt(i); h = (h * 16777619) >>> 0; }
  let out = (h ^ (h >>> 13)) >>> 0;
  return out % 1000000;
}`, [[12345, "void"], [999, "abc"], [0, ""]]);

// 11. update expressions: ++/-- always coerce to Number (never string-concat), across
// prefix/postfix and identifier/member targets — the kind of edge the VM must match.
check("update", `function(){
  let s = "5"; let a = s++; let b = ++s;        // string operand -> numeric result
  let o = { n: 10 }; let c = o.n++; let d = --o.n; // member postfix + prefix
  return { a, b, s, c, d, n: o.n };
}`, [[]]);

console.log(`\n${pass} checks passed.`);
