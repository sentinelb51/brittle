// assemble.js — guarded source -> canonical IR/bytecode.
//
// "Source" here is a list of instruction tuples (a tiny DSL authored in JS; see
// src/guarded/*.js). This step is deliberately readable — per the comprehensibility
// policy, the DESIGN is transparent. Hostility to reading is added later, by the
// mutation pass, and only to the shipped artifact.
//
// Output canonical program:
//   { regCount, consts: Uint32Array, code: Instr[], stages: number[] }
//   Instr = { op: name, args: int[] }  // args are already resolved to indices/imms
//   stages[i] = index into `code` where stage i begins (stage 0 starts at 0)
//
// Semantics are fixed by src/vm/interp.js and mirrored by the server's reference run.

import { OPS, operandKinds } from "../common/opcodes.js";
import { ENV } from "../common/envvec.js";

export function assemble(source) {
  const regIndex = new Map();
  const consts = [];
  const code = [];
  const stages = [0];

  const reg = (name) => {
    if (typeof name !== "string" || !/^r\d+$/.test(name)) {
      throw new Error(`bad register operand: ${JSON.stringify(name)}`);
    }
    if (!regIndex.has(name)) regIndex.set(name, regIndex.size);
    return regIndex.get(name);
  };
  const constIdx = (lit) => {
    const v = lit >>> 0;
    const found = consts.indexOf(v);
    if (found >= 0) return found;
    consts.push(v);
    return consts.length - 1;
  };
  const envSel = (name) => {
    if (typeof name === "number") return name;
    if (!(name in ENV) || name === "SIZE") throw new Error(`unknown env selector: ${name}`);
    return ENV[name];
  };

  for (const [op, ...rest] of source) {
    if (!(op in OPS)) throw new Error(`unknown op: ${op}`);
    if (op === "STAGE") {
      stages.push(code.length);
      code.push({ op, args: [] });
      continue;
    }
    const kinds = operandKinds(op);
    if (rest.length !== kinds.length) {
      throw new Error(`${op} expects ${kinds.length} operands, got ${rest.length}`);
    }
    const args = rest.map((operand, i) => {
      switch (kinds[i]) {
        case "R":
          return reg(operand);
        case "C":
          return constIdx(operand);
        case "E":
          return envSel(operand);
        case "I":
          return operand & 0x1f; // immediates are small (rotate amounts)
        default:
          throw new Error(`bad kind ${kinds[i]}`);
      }
    });
    code.push({ op, args });
  }

  // Ensure a terminating HALT so the interpreter has a clean stop.
  if (code.length === 0 || code[code.length - 1].op !== "HALT") {
    code.push({ op: "HALT", args: [] });
  }

  return {
    regCount: Math.max(regIndex.size, 1),
    consts: Uint32Array.from(consts),
    code,
    stages,
  };
}
