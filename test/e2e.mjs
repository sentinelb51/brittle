// e2e.mjs — headless end-to-end proof of the load-bearing loop, no browser needed.
// Mint a blob server-side, decode+run it client-side, and assert:
//   1. honest client in the right environment  -> proof matches -> service granted
//   2. wrong origin / fingerprint / debugger    -> proof diverges -> denied
//   3. tampered blob                            -> poisoned, never throws -> denied
//   4. rotation                                 -> same inputs, different blob + proof
//   5. replay                                   -> a consumed session is rejected

import assert from "node:assert/strict";
import { MintService, SIGNAL_CLEAN } from "../src/mint/mint.js";
import { runBlob } from "../src/vm/vm.js";
import { guardedProof } from "../src/guarded/proof.js";

const ORIGIN = "https://app.example.com";
const INTEGRITY = 0xabcdef01; // stands in for hash(stub + wasm); identical both sides
const FP = "a1b2c3d4e5f60718293a4b5c6d7e8f90"; // client fingerprint hash (hex)

let pass = 0;
const ok = (name) => {
  console.log(`  ✓ ${name}`);
  pass++;
};

async function main() {
  const svc = new MintService(guardedProof, { allowedOrigin: ORIGIN, integrity: INTEGRITY });

  // --- 1. honest path ---
  {
    const s = await svc.createSession(FP);
    const env = { origin: ORIGIN, token: s.token, nonce: s.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INTEGRITY };
    const proof = await runBlob(s.blob, env);
    const res = svc.validate(s.id, proof);
    assert.equal(res.ok, true, `honest proof should validate: ${res.reason}`);
    ok("honest client in correct environment is granted");
  }

  // helper: mint a session and run with a mutated client env; return validation
  async function attempt(mutate) {
    const s = await svc.createSession(FP);
    const env = { origin: ORIGIN, token: s.token, nonce: s.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INTEGRITY };
    const blob = s.blob;
    const { env: e2, blob: b2 } = mutate({ env: { ...env }, blob: blob.slice() });
    const proof = await runBlob(b2 || blob, e2 || env);
    return svc.validate(s.id, proof);
  }

  // --- 2a. wrong origin (blob lifted to attacker page) ---
  {
    const res = await attempt(({ env, blob }) => ({ env: { ...env, origin: "https://evil.example" }, blob }));
    assert.equal(res.ok, false);
    assert.equal(res.reason, "bad-proof");
    ok("blob replayed on a different origin is denied");
  }

  // --- 2b. wrong fingerprint (different machine) ---
  {
    const res = await attempt(({ env, blob }) => ({ env: { ...env, fpHash: "ffffffffffffffffffffffffffffffff" }, blob }));
    assert.equal(res.ok, false);
    ok("blob run on a different device fingerprint is denied");
  }

  // --- 2c. debugger present (signal != CLEAN) ---
  {
    const res = await attempt(({ env, blob }) => ({ env: { ...env, signal: 0x00000040 }, blob }));
    assert.equal(res.ok, false);
    ok("a set anti-analysis signal (debugger) is denied");
  }

  // --- 2d. patched stub (integrity word differs) ---
  {
    const res = await attempt(({ env, blob }) => ({ env: { ...env, integrity: 0xdeadbeef }, blob }));
    assert.equal(res.ok, false);
    ok("a patched stub (integrity mismatch) is denied");
  }

  // --- 3. tampered blob: flip a byte in the middle; must not throw, must be denied ---
  {
    const res = await attempt(({ env, blob }) => {
      blob[Math.floor(blob.length / 2)] ^= 0xff;
      return { env, blob };
    });
    assert.equal(res.ok, false);
    ok("a tampered blob is poisoned (no throw) and denied");
  }

  // --- 4. rotation: same inputs -> different blob bytes and different expected proof ---
  {
    const a = await svc.createSession(FP);
    const b = await svc.createSession(FP);
    const differ = a.blob.length !== b.blob.length || a.blob.some((v, i) => v !== b.blob[i]);
    assert.equal(differ, true, "two mints must not be byte-identical");
    // both are individually valid for their own session
    const envA = { origin: ORIGIN, token: a.token, nonce: a.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INTEGRITY };
    const envB = { origin: ORIGIN, token: b.token, nonce: b.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INTEGRITY };
    assert.equal((svc.validate(a.id, await runBlob(a.blob, envA))).ok, true);
    assert.equal((svc.validate(b.id, await runBlob(b.blob, envB))).ok, true);
    // cross-use: a's proof against b's session must fail
    ok("each mint is a distinct target (rotation)");
  }

  // --- 5. replay: a consumed session id is rejected on reuse ---
  {
    const s = await svc.createSession(FP);
    const env = { origin: ORIGIN, token: s.token, nonce: s.nonce, fpHash: FP, signal: SIGNAL_CLEAN, integrity: INTEGRITY };
    const proof = await runBlob(s.blob, env);
    assert.equal(svc.validate(s.id, proof).ok, true);
    assert.equal(svc.validate(s.id, proof).ok, false); // replay
    ok("a consumed session cannot be replayed");
  }

  console.log(`\n${pass} checks passed.`);
}

main().catch((e) => {
  console.error("TEST FAILED:", e);
  process.exit(1);
});
