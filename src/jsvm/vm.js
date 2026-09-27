// jsvm/vm.js — a stack-based virtual machine that executes real JS *values* (numbers,
// strings, booleans, null/undefined, arrays, objects, closures). This is the execution
// engine a marked JS function is compiled down to (see src/jsc/compile.js), matching the
// obfuscator.io engine model: "the marked function stops existing as JavaScript" — it becomes
// bytecode only this interpreter understands.
//
// Design notes:
//  * Stack machine: every expression leaves exactly one value on the operand stack; every
//    statement is stack-neutral. This keeps the compiler simple and the invariant checkable.
//  * Closures: each call creates a frame { slots, parent }. A closure value carries the
//    frame it was defined in as `env`; upvalue access walks `parent` `hops` times. This is
//    the standard environment-chain model — correct over fast, which suits a protection engine.
//  * Arithmetic/compare/logic use native JS operators, so results are bit-for-bit identical
//    to running the original source for every construct v1 supports.
//
// The opcode NUMBERS here are canonical/stable for readability. The shipped artifact gets a
// per-build permuted opcode map + encrypted constants from the mutation layer (that reuse
// is the next step); this file stays the transparent reference.

export const OP = {
  PUSH_CONST: 0, // [idx]   push consts[idx]
  PUSH_UNDEF: 1,
  PUSH_NULL: 2,
  PUSH_TRUE: 3,
  PUSH_FALSE: 4,
  POP: 5,
  DUP: 6,
  LOAD: 7, // [slot]  push frame.slots[slot]
  STORE: 8, // [slot]  frame.slots[slot] = pop   (stack-neutral)
  LOAD_UP: 9, // [hops, slot]
  STORE_UP: 10, // [hops, slot]
  LOAD_GLOBAL: 11, // [nameIdx]  push globals[name]
  ADD: 12, SUB: 13, MUL: 14, DIV: 15, MOD: 16, POW: 17,
  LT: 18, LE: 19, GT: 20, GE: 21, EQ: 22, NE: 23, SEQ: 24, SNE: 25,
  BAND: 26, BOR: 27, BXOR: 28, SHL: 29, SHR: 30, USHR: 31,
  NEG: 32, NOT: 33, BNOT: 34, TYPEOF: 35, UPLUS: 36,
  JMP: 37, // [target]
  JMP_IF_FALSE: 38, // [target]  pops
  JMP_IF_TRUE: 39, // [target]  pops
  GET_PROP: 40, // pop key, pop obj, push obj[key]
  GET_PROP_C: 41, // [keyIdx] pop obj, push obj[const key]
  SET_PROP: 42, // pop val,key,obj ; push val
  SET_PROP_C: 43, // [keyIdx] pop val,obj ; push val
  NEW_ARRAY: 44, // [n] pop n -> array
  NEW_OBJECT: 45, // [n] pop n (key,val) pairs -> object
  MAKE_CLOSURE: 46, // [fnIdx] push closure over current frame
  CALL: 47, // [argc] pop args, pop fn ; push fn(...args)
  CALL_METHOD: 48, // [argc] pop args, pop fn, pop this ; push fn.apply(this,args)
  RET: 49, // pop -> return value
};

const OP_NAME = Object.fromEntries(Object.entries(OP).map(([k, v]) => [v, k]));

// A compiled module: { consts, names, functions: FnProto[], entry }
// FnProto: { name, numParams, numSlots, code: Int32Array }  // flat [op, ...operands, ...]
// The compiler (src/jsc) emits convenient variable-length tuples and then linearizes each
// proto to this flat form; jump operands hold word offsets into `code`.
// A closure value at runtime: { __brittleClosure: true, proto, env }

function makeClosure(proto, env) {
  return { __brittleClosure: true, proto, env };
}
const isClosure = (v) => v && typeof v === "object" && v.__brittleClosure === true;

export function createEngine(module, globals = {}) {
  const { consts, names, functions } = module;

  // Hoisted out of runProto so it isn't reallocated on every frame (matters under
  // recursion). It closes over runProto only, not over any per-frame state.
  function callValue(fn, callArgs, thisVal) {
    if (isClosure(fn)) return runProto(fn.proto, fn.env, callArgs, thisVal);
    if (typeof fn === "function") {
      // Crossing into a host function: any engine closure among the args (e.g. the callback
      // in arr.map(x => ...), filter, reduce, sort(cmp), forEach) is a plain object the
      // host can't invoke. Trampoline each one into a real JS function so the host can
      // call it back into the engine. Only marshalled on the way out — closures re-entered
      // by the engine itself never take this path.
      for (let i = 0; i < callArgs.length; i++) {
        const c = callArgs[i];
        if (isClosure(c)) callArgs[i] = (...xs) => runProto(c.proto, c.env, xs, undefined);
      }
      return fn.apply(thisVal, callArgs);
    }
    throw new TypeError("not a function");
  }

  function runProto(proto, thisEnv, args, thisVal) {
    const frame = { slots: new Array(proto.numSlots).fill(undefined), parent: thisEnv };
    for (let i = 0; i < proto.numParams; i++) frame.slots[i] = args[i];
    const code = proto.code; // flat Int32Array: [op, ...operands, op, ...]
    const n = code.length;
    const st = []; // operand stack
    let pc = 0;

    while (pc < n) {
      const op = code[pc++];
      switch (op) {
        case OP.PUSH_CONST: st.push(consts[code[pc++]]); break;
        case OP.PUSH_UNDEF: st.push(undefined); break;
        case OP.PUSH_NULL: st.push(null); break;
        case OP.PUSH_TRUE: st.push(true); break;
        case OP.PUSH_FALSE: st.push(false); break;
        case OP.POP: st.pop(); break;
        case OP.DUP: st.push(st[st.length - 1]); break;
        case OP.LOAD: st.push(frame.slots[code[pc++]]); break;
        case OP.STORE: frame.slots[code[pc++]] = st.pop(); break;
        case OP.LOAD_UP: { let f = frame, h = code[pc++]; const slot = code[pc++]; while (h-- > 0) f = f.parent; st.push(f.slots[slot]); break; }
        case OP.STORE_UP: { let f = frame, h = code[pc++]; const slot = code[pc++]; while (h-- > 0) f = f.parent; f.slots[slot] = st.pop(); break; }
        case OP.LOAD_GLOBAL: {
          const name = names[code[pc++]];
          if (!(name in globals)) throw new ReferenceError(name + " is not defined");
          st.push(globals[name]);
          break;
        }
        case OP.ADD: { const b = st.pop(), a = st.pop(); st.push(a + b); break; }
        case OP.SUB: { const b = st.pop(), a = st.pop(); st.push(a - b); break; }
        case OP.MUL: { const b = st.pop(), a = st.pop(); st.push(a * b); break; }
        case OP.DIV: { const b = st.pop(), a = st.pop(); st.push(a / b); break; }
        case OP.MOD: { const b = st.pop(), a = st.pop(); st.push(a % b); break; }
        case OP.POW: { const b = st.pop(), a = st.pop(); st.push(a ** b); break; }
        case OP.LT: { const b = st.pop(), a = st.pop(); st.push(a < b); break; }
        case OP.LE: { const b = st.pop(), a = st.pop(); st.push(a <= b); break; }
        case OP.GT: { const b = st.pop(), a = st.pop(); st.push(a > b); break; }
        case OP.GE: { const b = st.pop(), a = st.pop(); st.push(a >= b); break; }
        case OP.EQ: { const b = st.pop(), a = st.pop(); st.push(a == b); break; }
        case OP.NE: { const b = st.pop(), a = st.pop(); st.push(a != b); break; }
        case OP.SEQ: { const b = st.pop(), a = st.pop(); st.push(a === b); break; }
        case OP.SNE: { const b = st.pop(), a = st.pop(); st.push(a !== b); break; }
        case OP.BAND: { const b = st.pop(), a = st.pop(); st.push(a & b); break; }
        case OP.BOR: { const b = st.pop(), a = st.pop(); st.push(a | b); break; }
        case OP.BXOR: { const b = st.pop(), a = st.pop(); st.push(a ^ b); break; }
        case OP.SHL: { const b = st.pop(), a = st.pop(); st.push(a << b); break; }
        case OP.SHR: { const b = st.pop(), a = st.pop(); st.push(a >> b); break; }
        case OP.USHR: { const b = st.pop(), a = st.pop(); st.push(a >>> b); break; }
        case OP.NEG: st.push(-st.pop()); break;
        case OP.UPLUS: st.push(+st.pop()); break;
        case OP.NOT: st.push(!st.pop()); break;
        case OP.BNOT: st.push(~st.pop()); break;
        case OP.TYPEOF: st.push(typeof st.pop()); break;
        case OP.JMP: pc = code[pc]; break;
        case OP.JMP_IF_FALSE: { const t = code[pc++]; if (!st.pop()) pc = t; break; }
        case OP.JMP_IF_TRUE: { const t = code[pc++]; if (st.pop()) pc = t; break; }
        case OP.GET_PROP: { const k = st.pop(), o = st.pop(); st.push(o[k]); break; }
        case OP.GET_PROP_C: { const o = st.pop(); st.push(o[consts[code[pc++]]]); break; }
        case OP.SET_PROP: { const v = st.pop(), k = st.pop(), o = st.pop(); o[k] = v; st.push(v); break; }
        case OP.SET_PROP_C: { const v = st.pop(), o = st.pop(); o[consts[code[pc++]]] = v; st.push(v); break; }
        case OP.NEW_ARRAY: {
          // argc is almost always tiny, where a pop-loop beats Array#slice's fixed overhead.
          const nn = code[pc++]; const arr = new Array(nn);
          for (let i = nn - 1; i >= 0; i--) arr[i] = st.pop();
          st.push(arr); break;
        }
        case OP.NEW_OBJECT: {
          // key/value pairs sit at the top in source order — read them in place (preserving
          // insertion order) and truncate, avoiding the reverse-pop + temp-array shuffle.
          const base = st.length - 2 * code[pc++]; const obj = {};
          for (let i = base; i < st.length; i += 2) obj[st[i]] = st[i + 1];
          st.length = base;
          st.push(obj); break;
        }
        case OP.MAKE_CLOSURE: st.push(makeClosure(functions[code[pc++]], frame)); break;
        case OP.CALL: {
          const argc = code[pc++]; const a = new Array(argc);
          for (let i = argc - 1; i >= 0; i--) a[i] = st.pop();
          const fn = st.pop();
          st.push(callValue(fn, a, undefined));
          break;
        }
        case OP.CALL_METHOD: {
          const argc = code[pc++]; const a = new Array(argc);
          for (let i = argc - 1; i >= 0; i--) a[i] = st.pop();
          const fn = st.pop(); const self = st.pop();
          st.push(callValue(fn, a, self));
          break;
        }
        case OP.RET: return st.pop();
        default: throw new Error("bad jsvm op " + op + " (" + (OP_NAME[op] || "?") + ")");
      }
    }
    return undefined; // fell off end
  }

  // Public: call the module entry function with args.
  return function run(...args) {
    return runProto(functions[module.entry], null, args, undefined);
  };
}

export { OP_NAME };
