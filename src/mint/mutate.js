// mutate.js — the per-session mutation + serialization + layered encryption pass.
// Input: canonical program + session env + a session structural seed.
// Output: an encrypted Uint8Array blob that only the matching environment can decode.
//
// What varies every mint (structural; embedded encrypted in the blob):
//   * opcode byte for each canonical op   (opTable)
//   * register renaming + decoy registers (regPerm)
//   * junk/decoy instructions on dead lanes
//   * stage partitioning
// What varies every mint (keys; re-derived by the client from env, never shipped):
//   * const-pool key, outer env-layer key, per-stage keys
//
// The structural seed makes two mints of the same program on the same env still differ,
// so even a client that legitimately re-handshakes gets a fresh target.

import { OP_NAMES, CANON, operandKinds } from "../common/opcodes.js";
import { deriveMaster, masterWords, seedFor } from "../common/kdf.js";
import { splitmix32, permutation, keystream, xorStream, checksum } from "../common/u32.js";
import { stageSeed } from "../common/stage.js";
import { buildEnvVector } from "../common/envvec.js";
import { initState, runSlice } from "../vm/interp.js";
import { mixJS } from "../vm/mix.js";
import { MAGIC, VERSION, HDR, writeU16, writeU32 } from "../common/blobfmt.js";

// Split canonical code into stage slices, dropping STAGE markers and the trailing HALT
// grouping (HALT stays at the end of the final stage).
function splitStages(program) {
  const slices = [];
  let cur = [];
  for (const ins of program.code) {
    if (ins.op === "STAGE") {
      slices.push(cur);
      cur = [];
    } else {
      cur.push(ins);
    }
  }
  slices.push(cur);
  return slices;
}

// Inline constant literals (CONST cidx -> CONST literal) so a snapshot run matches what
// the client computes after decrypting its pool. Emission still uses the pool index.
function lowerConsts(slice, consts) {
  return slice.map((ins) =>
    ins.op === "CONST" ? { op: "CONST", args: [ins.args[0], consts[ins.args[1]] >>> 0] } : ins
  );
}

// Run canonical stages in order, capturing the accumulator after each stage so the mint
// can derive the same stage keys the client will. Returns [accAfter0, accAfter1, ...].
function stageAccSnapshots(slices, consts, regCount, envVector, keyWords) {
  const state = initState(regCount);
  const snaps = [];
  for (const slice of slices) {
    runSlice(state, lowerConsts(slice, consts), { envVector, mixFn: mixJS, keyWords });
    snaps.push(state.acc.slice());
  }
  return snaps;
}

export async function mintBlob(program, env, structuralSeed) {
  const master = await deriveMaster(env);
  const mw = masterWords(master);
  const envVector = buildEnvVector(env, master);
  const rng = splitmix32(structuralSeed >>> 0);

  // --- opcode byte assignment: distinct random bytes, one per canonical op ---
  const byteperm = permutation(256, rng);
  const opTable = new Uint8Array(OP_NAMES.length);
  for (let i = 0; i < OP_NAMES.length; i++) opTable[i] = byteperm[i];
  const opByte = (name) => opTable[CANON[name]];

  // --- register renaming + decoy registers ---
  const realRegs = program.regCount;
  const decoyCount = 2 + (rng() % 4);
  const totalRegs = realRegs + decoyCount;
  const regPerm = permutation(totalRegs, rng); // canonical reg r -> regPerm[r]
  const decoyRegs = [];
  for (let r = realRegs; r < totalRegs; r++) decoyRegs.push(regPerm[r]);
  const anyReg = () => regPerm[rng() % totalRegs];
  const pickDecoy = () => decoyRegs[rng() % decoyRegs.length];

  // --- stages + stage keys (from canonical accumulator snapshots) ---
  const slices = splitStages(program);
  const snaps = stageAccSnapshots(slices, program.consts, program.regCount, envVector, mw);

  // --- emit mutated instruction bytes per stage, with junk interleaved ---
  // Real instructions carry CANONICAL register indices and are remapped here exactly
  // once. Junk instructions are authored directly in MUTATED index space (dest is a
  // decoy register), so they are emitted raw — remapping them again would alias a real
  // register and corrupt the real computation.
  const remapArg = (kind, val) => (kind === "R" ? regPerm[val] : val);

  const stageBlocks = slices.map((slice) => {
    const bytes = [];
    const emitReal = (ins) => {
      bytes.push(opByte(ins.op));
      const kinds = operandKinds(ins.op);
      for (let i = 0; i < kinds.length; i++) bytes.push(remapArg(kinds[i], ins.args[i]) & 0xff);
    };
    const emitJunk = () => {
      // JUNK dst, src, src — dst is a decoy lane; never feeds EMIT, so acc is unmoved.
      bytes.push(opByte("JUNK"), pickDecoy() & 0xff, anyReg() & 0xff, anyReg() & 0xff);
    };
    for (const ins of slice) {
      if (rng() % 3 === 0) emitJunk(); // junk before
      emitReal(ins);
      if (rng() % 4 === 0) emitJunk(); // junk after
    }
    return Uint8Array.from(bytes);
  });

  // inner layer: stage-encrypt blocks k>=1 with a key derived from acc after stage k-1
  for (let k = 1; k < stageBlocks.length; k++) {
    const seed = stageSeed(snaps[k - 1], mw[0], k);
    xorStream(stageBlocks[k], seed);
  }

  // --- const pool, encrypted with the const key ---
  const constKS = keystream(seedFor(mw, "const"), program.consts.length || 1);
  const constBytes = new Uint8Array(program.consts.length * 4);
  for (let i = 0; i < program.consts.length; i++) {
    writeU32(constBytes, i * 4, (program.consts[i] ^ constKS[i]) >>> 0);
  }

  // --- assemble full plaintext byte array ---
  const headerLen = HDR.OPTABLE + opTable.length;
  const stageLensLen = stageBlocks.length * 2;
  const blocksLen = stageBlocks.reduce((s, b) => s + b.length, 0);
  const total = headerLen + constBytes.length + stageLensLen + blocksLen;
  const out = new Uint8Array(total);

  for (let i = 0; i < 4; i++) out[i] = MAGIC[i];
  out[HDR.VERSION] = VERSION;
  out[HDR.TOTALREGS] = totalRegs;
  out[HDR.STAGECOUNT] = stageBlocks.length;
  out[HDR.CONSTCOUNT] = program.consts.length;
  out[HDR.OPTABLELEN] = opTable.length;
  out.set(opTable, HDR.OPTABLE);

  let off = headerLen;
  out.set(constBytes, off);
  off += constBytes.length;
  for (const b of stageBlocks) {
    writeU16(out, off, b.length);
    off += 2;
  }
  for (const b of stageBlocks) {
    out.set(b, off);
    off += b.length;
  }

  // blob self-integrity: checksum of the assembled plaintext (stored-under-outer form,
  // later stages already inner-encrypted). The client recomputes this after removing the
  // outer layer; the server folds this same value into the expected proof. Computed
  // BEFORE the outer XOR so the client can reproduce it right after outer-decrypt.
  const blobChecksum = checksum(out);

  // --- outer layer: env-XOR over the whole array ---
  xorStream(out, seedFor(mw, "blob"));

  return { blob: out, master, checksum: blobChecksum };
}
