// u32.js — 32-bit unsigned ARX primitives, shared verbatim by the server mint and
// the client engine. The whole system's correctness rests on both sides computing the
// *same* integer arithmetic, so this file is the single source of truth for it.
//
// Everything is add-rotate-xor over uint32 lanes: cheap, branch-free, and it maps
// 1:1 onto WASM i32 ops (see src/wasm/emit.js), so the sensitive MIX handler can be
// moved into WASM without changing a single result bit.

export const MASK = 0xffffffff;

export const u32 = (x) => x >>> 0;
export const add32 = (a, b) => (a + b) >>> 0;
export const xor32 = (a, b) => (a ^ b) >>> 0;
// TODO: sub32/and32 are unused (no canonical op needs them; ARX masks inline). Kept for
// primitive-set completeness — wire a consumer or drop if it stays dead.
export const sub32 = (a, b) => (a - b) >>> 0;
export const and32 = (a, b) => (a & b) >>> 0;

// 32-bit multiply keeping only the low 32 bits. Math.imul is the native single-op form of
// exactly this (and matches WASM i32.mul); it can't lose precision the way a naive a*b
// can once the true product exceeds 2^53. Verified bit-identical to the old hi/lo split.
export const mul32 = (a, b) => Math.imul(a, b) >>> 0;

export const rol32 = (x, r) => {
  r &= 31;
  return ((x << r) | (x >>> (32 - r))) >>> 0;
};
export const ror32 = (x, r) => {
  r &= 31;
  return ((x >>> r) | (x << (32 - r))) >>> 0;
};

// One ARX quarter-round. This is the nonlinear heart of MIX and of the key schedule.
// It is deliberately its own function so it can be mirrored exactly in WASM.
export const arx = (a, b, k) => {
  a = add32(a, b);
  a = xor32(a, k);
  a = rol32(a, (b ^ k) & 31 || 7);
  a = add32(a, mul32(b | 1, 0x9e3779b1)); // golden-ratio odd multiplier -> full-period-ish diffusion
  return a >>> 0;
};

// splitmix32: a fast, deterministic, well-distributed PRNG. Used by the mint to
// derive per-session permutations and keystreams; NOT used as a security primitive
// on its own (the security comes from server rotation, not from this PRNG's strength).
export function splitmix32(seed) {
  let s = seed >>> 0;
  return function next() {
    s = (s + 0x9e3779b9) >>> 0;
    let z = s;
    z = mul32(z ^ (z >>> 16), 0x21f0aaad);
    z = mul32(z ^ (z >>> 15), 0x735a2d97);
    return (z ^ (z >>> 15)) >>> 0;
  };
}

// Fisher–Yates over [0..n) driven by a splitmix stream. Returns the permutation.
export function permutation(n, rng) {
  const p = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    const t = p[i];
    p[i] = p[j];
    p[j] = t;
  }
  return p;
}

// Invert a permutation: inv[p[i]] = i.
// TODO: nothing imports invert — the client runs mutated register indices directly (no
// un-permutation). Wire it if a decode path ever needs the inverse map, or drop it.
export function invert(p) {
  const inv = new Array(p.length);
  for (let i = 0; i < p.length; i++) inv[p[i]] = i;
  return inv;
}

// A keystream of `len` u32 words from a seed. Used to encrypt constants and blob bytes.
export function keystream(seed, len) {
  const rng = splitmix32(seed);
  const out = new Uint32Array(len);
  for (let i = 0; i < len; i++) out[i] = rng();
  return out;
}

// A keystream of `nbytes` bytes from a seed. Used as the XOR stream over blob bytes.
// Deterministic and identical on server (mint) and client (decode).
export function keystreamBytes(seed, nbytes) {
  const rng = splitmix32(seed);
  const out = new Uint8Array(nbytes);
  let i = 0;
  while (i < nbytes) {
    let w = rng();
    for (let b = 0; b < 4 && i < nbytes; b++, i++) {
      out[i] = w & 0xff;
      w >>>= 8;
    }
  }
  return out;
}

// FNV-1a checksum over bytes -> u32. Used for blob self-integrity: the engine folds the
// checksum of its decoded blob into the proof, and the server folds the checksum it
// computed at mint. Any tamper (even to a junk byte) changes it and diverges the proof.
export function checksum(bytes) {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    h = (h ^ bytes[i]) >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

// XOR `bytes` in place with a keystream derived from `seed`. Returns `bytes`.
export function xorStream(bytes, seed) {
  const ks = keystreamBytes(seed, bytes.length);
  for (let i = 0; i < bytes.length; i++) bytes[i] ^= ks[i];
  return bytes;
}
