// integrity.js — a runtime self-hash folded into the key schedule and proof.
//
// The VM hashes artifacts it depends on (the WASM bytes, and — in a real build — the
// fetched stub source) into one u32 word. The server ships the same word (it computed it
// over the same artifacts), so an untampered client reproduces it and the proof matches.
// Patch the stub or the wasm and the word changes -> master changes -> the proof diverges
// many ops later. We fold, never compare, so there is no "if(hash!=X) fail" site to nop.
//
// Cost to reverser: cannot edit the shipped code without shifting every downstream value.
// Defeated by: recomputing/forging the word after patching AND re-encrypting under it.
// Rotation: the word is only half the binding; keys also depend on origin/token/fp/nonce,
// which rotate per session, so a forged word alone still fails the next challenge.

const enc = new TextEncoder();

// parts: array of (Uint8Array | string). Returns a u32 (first 4 bytes of SHA-256, BE).
export async function integrityWord(parts) {
  let total = 0;
  const chunks = parts.map((p) => (typeof p === "string" ? enc.encode(p) : p));
  for (const c of chunks) total += c.length;
  const buf = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    buf.set(c, o);
    o += c.length;
  }
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
}
