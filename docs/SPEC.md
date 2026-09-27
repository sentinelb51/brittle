# brittle — design specification

This is the transparent counterpart to the deliberately opaque artifacts. A competent
engineer should be able to reason here about why each protection holds and what breaks it.
The rule for this document: **every protection names (a) what it requires of an analyst,
(b) what overcomes it, and (c) how rotation expires that.** If that line can't be written,
the protection isn't understood well enough to ship.

---

## 1. Model and assumptions

- The analyst has the shipped JS + WASM, devtools, a debugger, and unlimited runs on
  their own page. Nothing client-side is secret from them by inspection.
- Their goals, in order: (1) recover the guarded logic, (2) reuse the analysis across
  sessions, (3) modify the client without detection, (4) copy a blob and run it elsewhere/later.
- Non-goals: speed, spec compliance, running arbitrary JS. brittle runs **one** program.
- **Assumption:** static analysis of any single build eventually succeeds. The success
  condition is not "unbreakable" — it is that **any recovery expires before it is useful**,
  because the server rotates the client faster than one build can be generalized.

## 2. Architecture: server-rotated disposable client

The client is throwaway. The server mints a fresh blob per session — fresh opcode map,
keys, and structure — and validates a challenge-response the engine computes. A copied
blob stops working at the next mint.

```
guarded source ──▶ canonical IR/bytecode ──▶ per-session mutation (server) ──▶ encrypted blob
                                                                                   │
   browser: fingerprint ─┐                                                         ▼
   POST /session ────────┴───────────────────────────────────── mint + challenge (nonce)
   run blob in engine (WASM MIX core) ──▶ proof ──▶ POST /prove ──▶ server validates ──▶ grant/deny
```

Files: `src/mint/*` (server), `src/vm/*` (client), `src/wasm/*` (handler core),
`src/common/*` (primitives shared verbatim so both halves compute identically),
`src/guarded/proof.js` (the demo protected program).

## 3. The load-bearing invariant (build this first — it is built and tested)

**The mutation pass is semantics-preserving.** Therefore:

> running the *canonical* program over a session's environment yields exactly the proof
> that running the *mutated blob* over the same environment must yield.

The server never diffs blobs to validate. It runs the canonical program itself
(`src/mint/reference.js`) and compares one 256-bit accumulator to the client's
(`src/mint/mint.js::validate`). This single equality discharges the entire
challenge-response. It is cheap (one execution, one compare) and it is exactly what the
model needs: any deviation — wrong environment, tamper, wrong path — changes the
accumulator and is rejected, without the server needing to know *how* the client deviated.

- **Cost:** to produce a valid proof, the analyst must run the real program on the real
  environment for a *fresh* nonce — i.e. overcome everything below at once.
- **Overcome by:** faithfully reproducing the whole computation and environment.
- **Rotation:** the nonce/token/structure are per session, so a reproduction is valid only
  for a session that is already consumed or expired (`SESSION_TTL_MS`, one-shot validate).

The proof is the challenge-response: the guarded program folds the server nonce with all
bindings into the accumulator. There is no separate "unlock" secret to hide — producing
the proof for a fresh nonce *is* the service.

## 4. Environment binding (the KDF) — `src/common/kdf.js`

One master seed drives every key: the outer blob layer, the constant pool, the per-stage
keys, and the WASM key schedule.

```
master = SHA256( "brittle/v0" ‖ origin ‖ token ‖ nonce ‖ fpHash ‖ signal ‖ integrity )
```

Every input is server-reproducible at validation time: it minted token/nonce, it pins the
origin, the client registered fpHash at `/session`, and `signal`/`integrity` equal fixed
CLEAN/known values in an untampered run. So the server recomputes `master` and the whole
schedule exactly. Change any input and the blob decodes to noise **and** the proof
diverges — four bindings from one derivation.

- **Cost:** the decode key exists nowhere in the blob; it must be re-derived from a live
  environment the analyst has to fully reproduce.
- **Overcome by:** reproducing every KDF input on the analyst's machine/page.
- **Rotation:** token and nonce are fresh per session, so even a perfect environment
  clone only decodes a blob whose session has expired.

## 5. Per-session mutation — `src/mint/mutate.js`

Each mint reshuffles, and embeds the reshuffling **encrypted** in the blob:

- **Opcode bytes** — each canonical op gets a fresh distinct byte (`opTable`). A handler
  index leaks nothing across sessions.
- **Register renaming + decoys** — a full permutation over real+decoy registers. It is an
  identity relabeling (applied uniformly), so the engine runs mutated indices directly; the
  analyst cannot assume register roles persist.
- **Constant re-encryption** — the pool is XORed with a per-session key; `CONST` decrypts
  on use.
- **Junk / decoy instructions** — `JUNK` ops on dead register lanes, interleaved with real
  code. They execute for real (analysis overhead) but never feed `EMIT`, so the accumulator
  is untouched — which is why mutation stays semantics-preserving.

- **Cost:** the entire disassembly (opcodes, registers, constants) is session-specific;
  notes from one session don't transfer.
- **Overcome by:** re-deriving the map for a captured session (it's in the blob, gated
  behind the env key).
- **Rotation:** next mint = new map/keys/structure; the derived map is worthless.

## 6. Staged bytecode — `src/common/stage.js`

Stage *k+1*'s instruction bytes are encrypted under a key folded from the **live
accumulator after stage k**. The key is computed, never stored: a static dump holds
stage 0 in the clear (after the env layer) and every later stage as ciphertext with no
key anywhere in the blob. You must actually execute the earlier stages to reveal the rest.
In the demo, stage 1 (the environment/integrity bindings) only appears after stage 0 runs.

- **Cost:** purely static extraction yields an incomplete program; you must drive execution.
- **Overcome by:** dynamic execution to the boundary, then reading decrypted memory.
- **Rotation:** the stage key is a function of env-bound state, so the extraction is valid
  only for that session's environment and nonce.

## 7. Encryption layers — `src/mint/mutate.js`, `src/vm/vm.js`

- **Outer (env) layer:** the whole blob is XORed with a keystream from `master`. Wrong
  environment ⇒ the header magic fails ⇒ the engine returns a decoy proof.
- **Inner (stage) layer:** later stages additionally XORed with their live-derived key.

Stream ciphers here provide *opacity + binding*, not cryptographic confidentiality against
the server (the server authored the plaintext). Their strength is that the key is
environment-derived and rotated, per the model — not the XOR itself.

## 8. WASM handler core — `src/wasm/emit.js`, `src/vm/wasmcore.js`

The sensitive `MIX` round (ARX) and the key schedule move off the JS surface. The 8 key
words live in WASM **linear memory** (`set_key`); `mix_step` reads them there. The bytes
are emitted in-process, so the module can be regenerated per session as a further rotation
surface. `mix(a,b,k)` is proven bit-identical to the JS `arx` over 100k vectors
(`test/wasm.mjs`), so moving into WASM changes no results.

- **Cost:** the analyst faces WASM analysis (a higher bar than beautified JS) and must
  extract keys from linear memory at the right instant.
- **Overcome by:** reading WASM memory during execution; re-implementing the ARX round.
- **Rotation:** keys in memory are session-bound; a capture is a stale key next session. (A
  per-session-permuted module would raise the re-implementation cost too — hook is present,
  see the TODO in `emit.js`.)

## 9. Instrumentation signal — `src/vm/antianalysis.js`

Devtools/debugger presence is folded into one `signal` word that must be `0` in a clean
environment (the server predicts the proof assuming `0`). Signals combined: debugger-stall
timing, console getter trap, hooked-native `toString`, and (strict) window size delta. We
**never branch** on the signal — it is folded into the key schedule, so there is no
`if(devtools) throw` site to nop out; a set bit just makes the proof wrong.

- **Cost:** every enabled check must be satisfied *simultaneously* and the fold held at
  exactly 0; the failure is delocalized from the check.
- **Overcome by:** patching each check to report clean.
- **Rotation:** patches are per-build; the next mint reshuffles the surrounding engine and
  re-binds keys, so a patch set expires with the session. (Signals are conservative to
  avoid false positives; a real deployment tunes thresholds and adds signals.)

## 10. Integrity self-hashes — `src/vm/integrity.js`, blob checksum

Two integrity bindings, both **folded, never compared**:

- **Code integrity** (`integrity` word): the engine hashes its dependencies (WASM bytes; a
  real build also folds the fetched stub source) into a word the server also ships and
  feeds into the KDF. Patch the code ⇒ word changes ⇒ `master` changes ⇒ proof diverges.
- **Blob integrity** (`checksum`, `src/common/u32.js` + `src/vm/vm.js`): the engine checksums
  the *decoded* blob bytes (right after removing the outer layer, before peeling stages)
  and folds that into the proof via `sealProof`; the server folds the checksum it computed
  at mint. Flip **any** blob byte — even inside a junk instruction — and the checksums
  disagree, so the proof is wrong. This is what makes junk-region tampering detectable
  (an earlier version missed it; the tamper test now covers it deterministically).

- **Cost:** you cannot edit the shipped code *or* the blob without shifting the proof.
- **Overcome by:** recompute both words after patching *and* re-derive keys under them for
  the exact bytes.
- **Rotation:** these words are inputs among several rotating ones (origin/token/fp/nonce),
  so recomputed words alone still fail the next challenge.

## 11. Tamper response

No protection fails at its check site. Wrong environment, bad opcode byte, or a corrupt
blob all funnel to a single behavior in `src/vm/vm.js`: return a **decoy** proof (a
deterministic, env-derived value that never ran the guarded program) — never throw. The
server simply sees a non-match. The analyst gets no localized "trap tripped" signal to
bisect against.

## 11b. Protecting real JS: the JS engine + compiler — `src/jsvm/`, `src/jsc/`

This is the obfuscator.io-parity path: *feed a JS function, run it as bytecode in a custom
engine* ("the marked function stops existing as JavaScript"). It is separate from the
integer-ARX proof engine above — different job, shared protection philosophy.

- **`src/jsvm/vm.js`** — a stack-based engine over real JS *values* (numbers, strings, booleans,
  null/undefined, arrays, objects, closures). Closures use a runtime environment chain
  (`{slots, parent}`); a closure carries its defining frame, upvalues walk `parent`.
  Arithmetic/compare/logic use native operators, so output is identical to the original.
- **`src/jsc/compile.js`** — `acorn` AST → engine module `{consts, names, functions, entry}`.
  Supports numbers/strings/booleans/null/undefined, `let`/`const`/`var`, arithmetic,
  bitwise, comparison, logical (`&& || ??` short-circuit), ternary, unary, update (`++`/`--`),
  assignment (`=` and compound), `if`/`else`, `while`, `do/while`, `for`, `break`/`continue`,
  `return`, function decls/exprs/arrows, closures, calls + method calls, member access,
  arrays, objects, template literals, sequence. Proper hoisting/pre-declaration so closures
  capture later-declared outer vars; entry self-binding so the marked function can recurse.
- **Verified** (`test/jsvm.mjs`): recursion (factorial/fibonacci), closures, a counter
  factory, array/object aggregation with host `Math`, string/template ops, and a realistic
  FNV-style license check — each compiled, virtualized, and checked **bit-identical to
  native JS** over many inputs.

Not yet supported (thrown with a clear message): `this`, `new`/`class`, `try/catch`,
`for-in`/`for-of`, `async`/generators, spread/rest, destructuring, labeled break, computed
compound assignment, postfix `++/--` on members, getters/setters, `delete`, regex literals.

**Model, matching obfuscator.io:** you don't virtualize a whole app (10–100× slower); you
mark the most sensitive functions. The engine produces stable, readable canonical opcodes
here; the per-build opacity layer (permuted opcodes, encrypted constants, junk, and
replacing the marked function with an engine-loader stub + rotation binding) is the **next**
step — it reuses the proof-engine's mutation machinery (§5–§7). Until then the JS engine is
a correct execution engine, not yet a hardened artifact.

## 12. What is built vs. designed-not-built

Built and tested headlessly (`npm test`, 27 checks): the whole proof loop — canonical IR,
mutation, layered + staged encryption, env binding, WASM MIX core (with the round key
served from linear memory via `mix_step` on the live client path — see §8), challenge-
response, rotation, replay rejection, blob + code integrity, and the negative cases (wrong
origin/fp/signal/integrity, tampered blob); **plus the JS engine + JS→bytecode compiler**
(§11b) that runs real marked functions bit-identically to native.

Designed here, hooks present, not yet wired (each is a rotation surface or hardening step,
not a correctness gap):
- **Opacity + rotation for the JS engine** — apply the proof-engine's per-session mutation
  (permuted opcodes, encrypted constants, junk, staged decrypt) and server rotation to the
  JS-engine module, and a packager that replaces a marked function in a source file with an
  engine-loader stub. This turns the correct JS engine into a hardened, rotating artifact.
- **Worker split** — run the engine/watchdog in a Web Worker with a cross-thread heartbeat
  feeding integrity, so pausing the main thread doesn't expose everything.
- **Per-session WASM** — parameterize `emitWasm()` to permute locals / reorder funcs /
  inject junk per mint.
- **Outer JS transform** — run the stub through string-array rotation + CFF as the last
  build step (the last, cheap layer; not load-bearing).
- **Constant re-encode-after-use** — currently decrypt-on-use; re-encrypt the scratch to
  keep plaintext constants out of memory between uses.
- **Integrity over stub source** — currently folds WASM bytes; fold the fetched stub text
  too (see `src/vm/loader.js`).
- **`emitFold` in WASM** — MIX/JUNK now take their round key from WASM linear memory
  (`mix_step`) on the live path, but the `EMIT` accumulator fold still reads the key
  schedule in JS. Moving it into the core too would let the schedule drop out of JS
  entirely during execution.

## 13. Known limitations / honest caveats

- Binary operand fields are one byte, so real+decoy registers, constants, and env
  selectors must each stay < 256. Fine for small guarded programs; widen the encoding for
  larger ones.
- Instrumentation and fingerprint signals are inherently environment-sensitive; the
  CLEAN-==-0 requirement means a mis-tuned signal denies honest users. Tune per deployment.
- The demo transport is plain HTTP for local runs; production must be HTTPS (the origin
  binding assumes an authenticated origin).
- brittle raises analysis cost and shortens shelf life. It is not, and does not claim to
  be, a client-only "unbreakable" scheme — see the model's success condition.
