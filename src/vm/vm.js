// vm.js — the client half. Decode the per-session blob against the live environment and
// execute it to produce the challenge proof. This is what ships (minus transformation and
// the WASM offload, which wrap but do not change it).
//
// Key facts that make this small:
//  * Register renaming is an identity relabeling applied uniformly, so the engine runs the
//    mutated register indices directly in a totalRegs-sized file. No un-permutation.
//  * Keys are never in the blob; they are re-derived here from the environment. Wrong
//    origin / token / fingerprint / debugger-signal / patched-stub => wrong master =>
//    the outer layer decrypts to noise and the proof is garbage.
//  * Tamper policy: we NEVER throw at a check. Any inconsistency yields a deterministic
//    decoy proof; the server simply sees a non-match and denies service.

import { deriveMaster, masterWords, seedFor } from "../common/kdf.js";
import { buildEnvVector } from "../common/envvec.js";
import { OP_NAMES, operandKinds } from "../common/opcodes.js";
import { splitmix32, keystream, xorStream, checksum } from "../common/u32.js";
import { stageSeed } from "../common/stage.js";
import { MAGIC, HDR, readU16, readU32 } from "../common/blobfmt.js";
import { initState, runSlice, sealProof } from "./interp.js";
import { mixJS } from "./mix.js";

function decoy(master) {
  // Deterministic, environment-derived, and guaranteed not to equal a real proof
  // (it never runs the guarded program). Looks like a normal proof to the wire.
  const w = masterWords(master);
  let s = "";
  for (let i = 0; i < 8; i++) s += (splitmix32(w[i] ^ 0xdeadbeef)() >>> 0).toString(16).padStart(8, "0");
  return s;
}

// env: { origin, token, nonce, fpHash, signal, integrity }
// opts: { core }  — a WASM handler core (loadWasmCore); its mix_step drives MIX with the
//   key schedule kept in WASM linear memory (preferred). Or { mixFn } for an explicit-key
//   handler (JS fallback / parity tests). Nothing given => the JS arx fallback.
export async function runBlob(blob, env, opts = {}) {
  const core = opts.core || null;
  const mixFn = opts.mixFn || (core && core.mix) || mixJS;
  const master = await deriveMaster(env);
  const mw = masterWords(master);
  const envVector = buildEnvVector(env, master);

  // Prefer the memory-key path: load the schedule into WASM linear memory once and let
  // mix_step read it there, so the MIX round key never lives in a JS variable during the
  // run. Bit-identical to mixFn(a,b,keyWords[step]); emitFold still folds keyWords in JS.
  let mixStep = null;
  if (core && core.setKey && core.mixStep) {
    for (let i = 0; i < 8; i++) core.setKey(i, mw[i]);
    mixStep = core.mixStep;
  }

  try {
    // outer env layer
    const buf = blob.slice();
    xorStream(buf, seedFor(mw, "blob"));

    if (!(buf[0] === MAGIC[0] && buf[1] === MAGIC[1] && buf[2] === MAGIC[2] && buf[3] === MAGIC[3])) {
      return decoy(master); // wrong environment: outer layer produced noise
    }
    // blob self-integrity: checksum the decoded (stored-under-outer) bytes now, before we
    // peel any inner stage layers. Folded into the proof at the end; a tampered blob (any
    // byte, including junk) changes this and diverges the proof. Fold, never compare.
    const blobChk = checksum(buf);
    const totalRegs = buf[HDR.TOTALREGS];
    const stageCount = buf[HDR.STAGECOUNT];
    const constCount = buf[HDR.CONSTCOUNT];
    const opTableLen = buf[HDR.OPTABLELEN];

    // inverse opcode map: mutatedByte -> canonical op name. Opcode bytes are a 0..255
    // permutation, so a flat array indexed by the byte beats a Map (no hashing).
    const inv = new Array(256);
    for (let i = 0; i < opTableLen; i++) inv[buf[HDR.OPTABLE + i]] = OP_NAMES[i];

    let off = HDR.OPTABLE + opTableLen;

    // const pool (decrypt)
    const constKS = keystream(seedFor(mw, "const"), constCount || 1);
    const consts = new Uint32Array(constCount);
    for (let i = 0; i < constCount; i++) {
      consts[i] = (readU32(buf, off + i * 4) ^ constKS[i]) >>> 0;
    }
    off += constCount * 4;

    // stage lengths
    const stageLens = [];
    for (let k = 0; k < stageCount; k++) {
      stageLens.push(readU16(buf, off));
      off += 2;
    }

    const decodeStage = (bytes) => {
      const code = [];
      let p = 0;
      while (p < bytes.length) {
        const name = inv[bytes[p++]];
        if (!name) throw new Error("bad opcode byte"); // caught -> decoy
        const kinds = operandKinds(name);
        const args = [];
        for (let i = 0; i < kinds.length; i++) {
          let v = bytes[p++];
          if (name === "CONST" && kinds[i] === "C") v = consts[v] >>> 0; // inline decrypted literal
          args.push(v);
        }
        code.push({ op: name, args });
      }
      return code;
    };

    const state = initState(totalRegs);
    for (let k = 0; k < stageCount; k++) {
      const block = buf.subarray(off, off + stageLens[k]);
      off += stageLens[k];
      if (k >= 1) xorStream(block, stageSeed(state.acc, mw[0], k)); // peel inner layer with live-derived key
      const code = decodeStage(block);
      // MIX/JUNK run via mix_step (key from WASM memory) when a core was supplied; otherwise
      // via the explicit-key mixFn. emitFold still folds keyWords (mw) in JS — moving that
      // into WASM too is the next hardening step, and would let mw drop out of JS entirely.
      runSlice(state, code, { envVector, mixFn, keyWords: mw, mixStep });
    }
    return sealProof(state.acc, blobChk);
  } catch {
    return decoy(master); // never throw at a check site
  }
}
