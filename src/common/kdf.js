// kdf.js — environment-bound key derivation, shared by mint (server) and engine (client).
//
// The decode key, the constant keystream, and the WASM key-schedule words are all
// expanded from ONE master seed. That seed is SHA-256 over the session environment:
//
//     master = SHA256( origin ‖ token ‖ nonce ‖ fpHash ‖ signal ‖ integrity )
//
// Every input is something the SERVER already knows at validation time (it minted the
// token/nonce, it pins the allowed origin, the client registered fpHash at /session,
// and `signal`/`integrity` equal fixed CLEAN constants in an untampered run). So the
// server can reproduce `master`, and therefore the whole key schedule, exactly.
//
// The binding property: change origin (blob lifted to another page), change fp
// (different machine), flip a debugger signal bit, or patch the stub, and `master`
// changes -> the blob decodes to garbage AND the proof diverges. One derivation, four
// bindings. Async only because crypto.subtle is; it runs once per load, then the hot
// path is pure sync integer math.

const enc = new TextEncoder();

function concatBytes(parts) {
  // parts: array of (string | Uint8Array). Length-prefixed so fields can't smear
  // into each other (origin="ab",token="c" must differ from origin="a",token="bc").
  const chunks = [];
  for (const p of parts) {
    const b = typeof p === "string" ? enc.encode(p) : p;
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length, false);
    chunks.push(len, b);
  }
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

// The canonical field order. Both sides MUST build `parts` in this order.
export function envParts(env) {
  return [
    "brittle/v0",
    env.origin,
    env.token,
    u32ToBytes(env.nonce),
    env.fpHash, // hex string of the client fingerprint hash
    u32ToBytes(env.signal >>> 0), // CLEAN in an untampered run
    u32ToBytes(env.integrity >>> 0), // stub+blob hash word, server-known
  ];
}

export function u32ToBytes(x) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x >>> 0, false);
  return b;
}

export async function deriveMaster(env) {
  const bytes = concatBytes(envParts(env));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest); // 32 bytes
}

// Fold the 32-byte master into 8 u32 words (big-endian). Word[0] seeds most PRNG
// streams; the full set is loaded into WASM linear memory as the key schedule.
export function masterWords(master) {
  const dv = new DataView(master.buffer, master.byteOffset, master.byteLength);
  const w = new Uint32Array(8);
  for (let i = 0; i < 8; i++) w[i] = dv.getUint32(i * 4, false);
  return w;
}

// A single 32-bit seed pinned to a domain string, for deriving one independent stream
// (e.g. "const", "blob", "junk") from the master without cross-correlation.
export function seedFor(words, domain) {
  let s = words[0] ^ 0x243f6a88;
  const d = enc.encode(domain);
  for (let i = 0; i < d.length; i++) s = ((s * 33) ^ d[i]) >>> 0;
  for (let i = 0; i < words.length; i++) s = (s ^ (words[i] + i * 0x9e3779b9)) >>> 0;
  return s >>> 0;
}
