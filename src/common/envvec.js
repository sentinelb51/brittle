// envvec.js — build the environment vector that LDENV reads from. Both the server
// (validating over canonical bytecode) and the client engine (running the mutated blob)
// construct this vector identically from the session env, so LDENV yields the same
// words on both sides. This is what lets the guarded program fold origin/token/fp/
// nonce/signal/integrity into its output in a program-defined way.
//
// Layout (indices are the E selector values the assembler emits):
//   0..3   ORIGIN0..3     hash words of location.origin
//   4..7   TOKEN0..3      hash words of the server session token
//   8..11  FP0..3         words of the client fingerprint hash
//   12     NONCE          the challenge nonce (folded by the program => challenge-resp)
//   13     SIGNAL         instrumentation signal (CLEAN in an untampered run)
//   14     INTEGRITY      stub+blob integrity word (server-known)
//   15..22 MASTER0..7     the derived master words (also the WASM key schedule)

import { splitmix32 } from "./u32.js";
import { masterWords } from "./kdf.js";

export const ENV = {
  ORIGIN0: 0,
  TOKEN0: 4,
  FP0: 8,
  NONCE: 12,
  SIGNAL: 13,
  INTEGRITY: 14,
  MASTER0: 15,
  SIZE: 23,
};

// Deterministic string -> n u32 words. Not a security hash; just a stable spreader so
// LDENV(ORIGIN0..3) reflects the whole origin string, not just its first chars.
export function hashWords(str, n) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h = (h ^ str.charCodeAt(i)) >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const rng = splitmix32(h);
  const out = new Uint32Array(n);
  for (let i = 0; i < n; i++) out[i] = rng();
  return out;
}

function hexWords(hex, n) {
  const out = new Uint32Array(n);
  for (let i = 0; i < n; i++) {
    const slice = hex.slice(i * 8, i * 8 + 8).padEnd(8, "0");
    out[i] = parseInt(slice, 16) >>> 0;
  }
  return out;
}

// env: { origin, token, nonce, fpHash(hex), signal, integrity }, master: Uint8Array(32)
export function buildEnvVector(env, master) {
  const v = new Uint32Array(ENV.SIZE);
  const o = hashWords(env.origin, 4);
  const t = hashWords(env.token, 4);
  const f = hexWords(env.fpHash, 4);
  v.set(o, ENV.ORIGIN0);
  v.set(t, ENV.TOKEN0);
  v.set(f, ENV.FP0);
  v[ENV.NONCE] = env.nonce >>> 0;
  v[ENV.SIGNAL] = env.signal >>> 0;
  v[ENV.INTEGRITY] = env.integrity >>> 0;
  v.set(masterWords(master), ENV.MASTER0);
  return v;
}
