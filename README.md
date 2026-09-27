# brittle

A self-protecting JS/WASM engine for the browser. It runs a protected program as
per-session **mutated bytecode** inside a custom interpreter, engineered to resist static
and dynamic analysis in a fully client-inspectable environment. Correctness is guaranteed
only for the guarded program; everything else serves opacity and short shelf life.

It has two execution engines that share one protection philosophy:
- an **integer-ARX proof engine** for the server-rotated challenge-response (the copy-resistance core), and
- a **JS-value engine + `acorn` compiler** (`src/jsvm`, `src/jsc`) that takes a real JS function
  and runs it as bytecode — the obfuscator.io-style "mark a function, virtualize it" path,
  verified bit-identical to native JS (recursion, closures, objects, strings, a license check).

The design is deliberately transparent — read **[docs/SPEC.md](docs/SPEC.md)** for why
each protection holds, what overcomes it, and how server rotation expires that. The
shipped artifacts (opcode maps, keys, blobs, handler core) are deliberately opaque to
reading; that is the product.

## The idea in one line

A server mints a fresh, environment-bound blob per session and validates a
challenge-response the engine computes. **A copied blob stops working at the next mint.**
The success condition is not "unbreakable" — it's that any recovery expires before it's useful.

## Load-bearing invariant

The per-session mutation pass is *semantics-preserving*, so the server validates a proof
by running the **canonical** program itself and comparing one 256-bit accumulator to the
client's — no blob diffing. One equality discharges the whole challenge-response.

## Run it

```bash
node --version        # needs >= 20 (developed on 24)

npm test              # headless: unit e2e + WASM parity + real-HTTP integration
npm run serve         # start the mint server -> http://localhost:8080
npm run wasm          # emit src/wasm/core.wasm for inspection (runtime doesn't need it)
```

Then open <http://localhost:8080> and click **Request & unlock**:

- each click mints a fresh blob (new opcode map, keys, structure), runs it in the
  WASM-backed engine, and redeems the proof → **GRANTED**;
- open devtools and click again → the debugger signal folds into the proof → **DENIED**;
- reload → the previous session's blob is already expired.

## What `npm test` proves (all headless, no browser needed — 27 checks)

- **jsvm** (`test/jsvm.mjs`): the JS→bytecode compiler + JS-value engine run real functions
  (recursion, closures, counters, arrays/objects, strings/templates, update expressions,
  a license check) **bit-identical to native JS**.
- **e2e** (`test/e2e.mjs`): honest client granted; denied on wrong origin / wrong
  fingerprint / debugger signal / patched-stub integrity / tampered blob (returns a decoy,
  never throws); rotation produces distinct blobs; consumed sessions can't replay.
- **wasm** (`test/wasm.mjs`): the WASM MIX core validates, matches the JS `arx` over 100k
  vectors, keeps its key schedule in linear memory and drives MIX from there (`mix_step`,
  the live client path) bit-identically to the explicit-key form, and runs the full loop.
- **integration** (`test/integration.mjs`): boots the real server and drives the actual
  client loader over HTTP — honest grant, cross-origin denial, rotation.

## Layout

- `src/common/` — primitives shared verbatim by server and client (ARX u32, KDF, env
  vector, stage keys, blob byte format). Both halves must compute identically.
- `src/jsvm/` — stack-based JS-value engine (numbers/strings/objects/arrays/closures).
- `src/jsc/` — `acorn` AST → JS-engine bytecode compiler ("mark a function, virtualize it").
- `src/ir/` — guarded source → canonical IR/bytecode (readable; opacity is added later).
- `src/mint/` — server: mutation pass, layered/staged encryption, reference oracle,
  session lifecycle, HTTP endpoint.
- `src/vm/` — client: blob decoder + interpreter, environment binding, fingerprint,
  instrumentation signal, integrity self-hash, WASM loader, protocol loader.
- `src/wasm/` — in-process WASM emitter for the MIX handler core.
- `src/guarded/proof.js` — the demo protected program (it *is* the challenge-response).
- `demo/` — the browser page. `docs/SPEC.md` — the design rationale.

## Scope

In: hiding the program, making every session a different target, detecting and responding
to tampering, binding execution to the real origin/session. Out: speed, spec compliance,
running untrusted JS, and any client-only "unbreakable" claim.
