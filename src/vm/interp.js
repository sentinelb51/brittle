// interp.js — the ONE interpreter core. It is run in two places that must agree bit
// for bit:
//   * server, over the canonical (unmutated) program  -> expected proof
//   * client, over the decoded per-stage blob          -> presented proof
// Because the mutation pass is semantics-preserving, these proofs are identical iff
// the environment matches and nothing was tampered. That single equality is the whole
// challenge-response check (see docs/SPEC.md, "Load-bearing invariant").
//
// The interpreter is resumable: it mutates a `state` object so the client engine can run
// one stage, derive the next stage's key from live state, decrypt it, and continue.
//
// `resolved` instructions have CONST literals already inlined (server: plaintext;
// client: decrypted). So this core needs no constant pool — it just executes.

import { add32, xor32, mul32, rol32, arx } from "../common/u32.js";

// Fixed accumulator IV. Public constant; secrecy lives in the env-derived key schedule.
export const ACC_IV = Uint32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
  0x5be0cd19,
]);

export function initState(regCount) {
  return {
    R: new Uint32Array(regCount),
    acc: ACC_IV.slice(),
    mixStep: 0,
    emitIdx: 0,
    halted: false,
  };
}

// Fold one word into the 256-bit proof accumulator. Deterministic; touches every lane
// over successive EMITs so order and value both matter.
function emitFold(state, x, keyWords) {
  const a = state.acc;
  const e = state.emitIdx & 7;
  a[e] = arx(a[e], x, keyWords[(x ^ e) & 7]);
  a[(e + 3) & 7] = xor32(a[(e + 3) & 7], rol32(add32(x, e), (e + 1) & 31));
  a[(e + 5) & 7] = add32(a[(e + 5) & 7], mul32(x | 1, 0x85ebca77));
  state.emitIdx = (state.emitIdx + 1) >>> 0;
}

// Run one resolved code slice (one stage), advancing `state`.
//  * `mixFn(a,b,k)` is the explicit-key MIX handler — a JS fallback or the WASM `mix`
//    export; both compute u32 arx(). Used by the server reference run.
//  * `mixStep(a,b,step)`, if provided, is the WASM `mix_step` export: it reads key word
//    `step&7` from WASM linear memory itself, so the round key never lands in a JS
//    variable during execution. When present it drives MIX (and JUNK, so a decoy round is
//    indistinguishable from a real one); it is bit-identical to mixFn(a,b,keyWords[step]).
//  * `keyWords` is the 8-word key schedule; emitFold still folds it in JS.
export function runSlice(state, code, { envVector, mixFn, keyWords, mixStep }) {
  const R = state.R;
  for (let pc = 0; pc < code.length; pc++) {
    if (state.halted) break;
    const { op, args } = code[pc];
    switch (op) {
      case "CONST":
        R[args[0]] = args[1] >>> 0; // literal already inlined
        break;
      case "LDENV":
        R[args[0]] = envVector[args[1]] >>> 0;
        break;
      case "MOV":
        R[args[0]] = R[args[1]];
        break;
      case "ADD":
        R[args[0]] = add32(R[args[1]], R[args[2]]);
        break;
      case "XOR":
        R[args[0]] = xor32(R[args[1]], R[args[2]]);
        break;
      case "MUL":
        R[args[0]] = mul32(R[args[1]], R[args[2]]);
        break;
      case "ROL":
        R[args[0]] = rol32(R[args[1]], args[2]);
        break;
      case "MIX": {
        const step = state.mixStep & 7;
        R[args[0]] = mixStep
          ? mixStep(R[args[1]], R[args[2]], step)
          : mixFn(R[args[1]], R[args[2]], keyWords[step]);
        state.mixStep = (state.mixStep + 1) >>> 0;
        break;
      }
      case "JUNK": {
        // Decoy work into a register the mutation reserved as dead. Executed for real (so
        // it adds analysis overhead) but never feeds EMIT, so acc is unmoved — the
        // exact value is irrelevant. Routed through the same handler as MIX so a decoy round
        // is indistinguishable from a real one (both a WASM mix_step call on the fast path).
        const step = state.mixStep & 7;
        R[args[0]] = mixStep
          ? mixStep(R[args[1]], R[args[2]], step)
          : mixFn(R[args[1]], R[args[2]], keyWords[step] ^ 0x5a5a5a5a);
        break;
      }
      case "EMIT":
        emitFold(state, R[args[0]], keyWords);
        break;
      case "STAGE":
        // Boundary marker. In a single-slice reference run this is a no-op; the client
        // engine never passes STAGE into a slice (it splits on it). Present for symmetry.
        break;
      case "HALT":
        state.halted = true;
        break;
      default:
        throw new Error(`bad op at pc=${pc}: ${op}`);
    }
  }
  return state;
}

export function proofHex(acc) {
  let s = "";
  for (let i = 0; i < acc.length; i++) s += acc[i].toString(16).padStart(8, "0");
  return s;
}

// Fold a blob-integrity checksum word into the accumulator, then serialize. Both the
// client (checksum of its decoded blob) and the server (checksum from mint) call this;
// a tampered blob yields a different word here and thus a non-matching proof.
export function sealProof(acc, word) {
  const a = acc.slice();
  for (let i = 0; i < a.length; i++) {
    a[i] = arx(a[i], (word ^ (i * 0x9e3779b9)) >>> 0, ACC_IV[i]);
  }
  return proofHex(a);
}
