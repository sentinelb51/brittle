// blobfmt.js — the on-the-wire blob byte layout, shared so the mint encoder and the VM
// decoder cannot drift. The blob is a Uint8Array (the mission's "encoded typed array").
//
// After the outer env-XOR layer is removed, the plaintext structure is:
//   [0..3]   MAGIC 'BRT0'
//   [4]      version
//   [5]      totalRegs (real + decoy)
//   [6]      stageCount
//   [7]      constCount
//   [8]      opTableLen (N canonical ops)
//   [9..]    opTable: N bytes; opTable[canonIdx] = mutated opcode byte
//   next     constPool: constCount * 4 bytes, u32 LE, XOR-encrypted with the const key
//   next     stageLens: stageCount * 2 bytes, u16 LE = byte length of each stage block
//   next     stage blocks concatenated; block 0 is plaintext (within the env layer),
//            blocks k>=1 are additionally XOR-encrypted with a stage key derived from
//            the live accumulator after stage k-1 (see common/stage.js).
//
// Each instruction inside a stage block: [ opByte, operand, operand, ... ] where the
// operand count is the arity of the canonical op that opByte maps to.

export const MAGIC = [0x42, 0x52, 0x54, 0x30]; // 'BRT0'
export const VERSION = 0;

export const HDR = {
  VERSION: 4,
  TOTALREGS: 5,
  STAGECOUNT: 6,
  CONSTCOUNT: 7,
  OPTABLELEN: 8,
  OPTABLE: 9,
};

export const writeU16 = (arr, off, v) => {
  arr[off] = v & 0xff;
  arr[off + 1] = (v >>> 8) & 0xff;
};
export const readU16 = (arr, off) => arr[off] | (arr[off + 1] << 8);

export const writeU32 = (arr, off, v) => {
  arr[off] = v & 0xff;
  arr[off + 1] = (v >>> 8) & 0xff;
  arr[off + 2] = (v >>> 16) & 0xff;
  arr[off + 3] = (v >>> 24) & 0xff;
};
export const readU32 = (arr, off) => (arr[off] | (arr[off + 1] << 8) | (arr[off + 2] << 16) | (arr[off + 3] << 24)) >>> 0;
