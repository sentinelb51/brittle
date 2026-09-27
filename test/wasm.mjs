// wasm.mjs — verify the WASM handler core validates, matches the JS arx bit-for-bit,
// keeps its key schedule in linear memory (mix_step), and can stand in as the VM's MIX
// handler with the full e2e loop still passing.

import assert from "node:assert/strict";
import { loadWasmCore } from "../src/vm/wasmcore.js";
import { arx } from "../src/common/u32.js";
import { MintService, SIGNAL_CLEAN } from "../src/mint/mint.js";
import { runBlob } from "../src/vm/vm.js";
import { guardedProof } from "../src/guarded/proof.js";

let pass = 0;
const ok = (n) => (console.log(`  ✓ ${n}`), pass++);

async function main() {
  const keys = Uint32Array.from([0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888]);
  const core = await loadWasmCore(keys);

  // parity: explicit-key mix vs JS arx over random vectors
  let seed = 123456789 >>> 0;
  const rnd = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  for (let i = 0; i < 100000; i++) {
    const a = rnd(), b = rnd(), k = rnd();
    if (core.mix(a, b, k) !== arx(a, b, k)) {
      assert.fail(`mismatch at a=${a} b=${b} k=${k}: wasm=${core.mix(a, b, k)} js=${arx(a, b, k)}`);
    }
  }
  ok("wasm mix() matches JS arx() over 100k random vectors");

  // linear-memory key schedule: mix_step(a,b,step) == mix(a,b,keys[step&7])
  for (let step = 0; step < 32; step++) {
    const a = rnd(), b = rnd();
    assert.equal(core.mixStep(a, b, step), core.mix(a, b, keys[step & 7]));
  }
  ok("wasm mix_step() reads the key schedule from linear memory");

  // full e2e with the WASM core as the VM's MIX handler
  const ORIGIN = "https://app.example.com", INT = 0xabcdef01, FP = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
  const svc = new MintService(guardedProof, { allowedOrigin: ORIGIN, integrity: INT });
  const s = await svc.createSession(FP);
  const env = { origin: ORIGIN, token: s.token, nonce: s.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INT };
  const wcore = await loadWasmCore(); // keyless: interp passes k explicitly
  const proof = await runBlob(s.blob, env, { mixFn: wcore.mix });
  assert.equal(svc.validate(s.id, proof).ok, true, "wasm-backed VM proof must validate");
  ok("full mint->decode->execute loop passes with the WASM MIX core");

  // memory-key path: same blob, MIX driven by mix_step reading the schedule from WASM
  // linear memory. Must be bit-for-bit identical to the explicit-key path AND validate.
  {
    const s2 = await svc.createSession(FP);
    const env2 = { origin: ORIGIN, token: s2.token, nonce: s2.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INT };
    const core = await loadWasmCore();
    const pExplicit = await runBlob(s2.blob, env2, { mixFn: core.mix });
    const pMemKey = await runBlob(s2.blob, env2, { core });
    assert.equal(pMemKey, pExplicit, "mix_step (memory-key) proof must equal the explicit-key proof");
    assert.equal(svc.validate(s2.id, pMemKey).ok, true, "mix_step proof must validate");
    ok("MIX driven from the WASM key schedule (mix_step) matches explicit-key and validates");
  }

  console.log(`\n${pass} checks passed.`);
}
main().catch((e) => (console.error("WASM TEST FAILED:", e), process.exit(1)));
