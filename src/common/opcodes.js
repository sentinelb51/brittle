// opcodes.js — the CANONICAL opcode set (names + arity). These names are stable and
// human-facing (assembler, SPEC). The *numbers* a engine dispatches on are assigned fresh
// every mint by the mutation pass, so a handler-table index leaks nothing across
// sessions. Arity is (dst?, ...operands) described per-op below.
//
// Operand kinds in canonical instructions:
//   R  = register index         (renamed per session)
//   C  = constant-pool index    (pool is re-encrypted per session)
//   E  = env-vector selector    (see envvec.js)
//   I  = small immediate integer (e.g. rotate amount)
//
// The set is intentionally tiny: an ARX register machine. Anything the guarded program
// needs is expressible as add/xor/mul/rotate/mix over u32, which is also exactly what
// lifts cleanly into WASM.

export const OPS = {
  CONST: { operands: ["R", "C"] }, // R = decrypt(constant C)
  LDENV: { operands: ["R", "E"] }, // R = envVector[E]
  MOV: { operands: ["R", "R"] }, // Rd = Rs
  ADD: { operands: ["R", "R", "R"] }, // Rd = Ra + Rb
  XOR: { operands: ["R", "R", "R"] }, // Rd = Ra ^ Rb
  MUL: { operands: ["R", "R", "R"] }, // Rd = Ra * Rb (32-bit)
  ROL: { operands: ["R", "R", "I"] }, // Rd = rol(Ra, I)
  MIX: { operands: ["R", "R", "R"] }, // Rd = arx(Ra, Rb, keyword) — SENSITIVE, lives in WASM
  EMIT: { operands: ["R"] }, // proof accumulator ^= mix(acc, Ra)
  JUNK: { operands: ["R", "R", "R"] }, // decoy: semantics-preserving no-op on real path
  STAGE: { operands: [] }, // stage boundary: bytes after this were decrypted by prior stage
  HALT: { operands: [] },
};

export const OP_NAMES = Object.keys(OPS);

// Canonical name -> canonical index (used only as a stable identifier pre-mutation).
export const CANON = Object.fromEntries(OP_NAMES.map((n, i) => [n, i]));

export function operandKinds(name) {
  return OPS[name].operands;
}
