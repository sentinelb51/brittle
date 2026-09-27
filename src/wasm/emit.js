// emit.js — emit the WASM handler-core module as raw bytes (no toolchain needed).
//
// Why WASM: the sensitive MIX round and the key schedule move off the JS surface. The
// 8 key words live in WASM linear memory (set via set_key); mix_step reads them there,
// so the JS bridge never sees the key material in a variable and a reverser faces WASM
// reversing (a higher bar than beautified JS). Emitting the bytes ourselves also means
// the module can later be regenerated per session (permuted locals, reordered funcs,
// junk locals) as another rotation surface — the hook is here.
//
// Exports:
//   memory
//   set_key(i, val)          -> store key word i (0..7) in linear memory
//   mix(a, b, k) -> i32      -> one ARX round with an explicit key (matches u32.js arx)
//   mix_step(a, b, step)->i32-> ARX round using key[(step & 7)] from linear memory
//
// The arithmetic mirrors src/common/u32.js `arx` exactly; test/wasm.mjs asserts parity.

const GOLDEN = 0x9e3779b1;

// ---- LEB128 ----
function uleb(n) {
  const out = [];
  n >>>= 0;
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return out;
}
function sleb(value) {
  // signed LEB128 of a 32-bit pattern interpreted as signed int
  let n = value | 0;
  const out = [];
  while (true) {
    let b = n & 0x7f;
    n >>= 7;
    const signBit = b & 0x40;
    if ((n === 0 && !signBit) || (n === -1 && signBit)) {
      out.push(b);
      break;
    }
    out.push(b | 0x80);
  }
  return out;
}

// ---- instruction shorthands ----
const OP = {
  block_void: [0x02, 0x40],
  if_void: [0x04, 0x40],
  else: [0x05],
  end: [0x0b],
  call: (i) => [0x10, ...uleb(i)],
  localGet: (i) => [0x20, ...uleb(i)],
  localSet: (i) => [0x21, ...uleb(i)],
  i32const: (v) => [0x41, ...sleb(v)],
  i32add: [0x6a],
  i32mul: [0x6c],
  i32and: [0x71],
  i32or: [0x72],
  i32xor: [0x73],
  i32shl: [0x74],
  i32rotl: [0x77],
  i32eqz: [0x45],
  i32load: [0x28, 0x02, 0x00], // align=2, offset=0
  i32store: [0x36, 0x02, 0x00],
};

function section(id, payload) {
  return [id, ...uleb(payload.length), ...payload];
}
function vec(items) {
  return [...uleb(items.length), ...items.flat()];
}
function body(localDecls, code) {
  // localDecls: array of [count, valtype]; valtype i32 = 0x7f
  const locals = vec(localDecls.map(([c, t]) => [...uleb(c), t]));
  const inner = [...locals, ...code, ...OP.end];
  return [...uleb(inner.length), ...inner];
}

export function emitWasm() {
  const I32 = 0x7f;

  // Type section: type0 (i32,i32,i32)->i32 ; type1 (i32,i32)->()
  const type0 = [0x60, ...vec([[I32], [I32], [I32]]), 0x01, I32];
  const type1 = [0x60, ...vec([[I32], [I32]]), 0x00];
  const typeSec = section(1, vec([type0, type1]));

  // Function section: func0->type0(mix), func1->type1(set_key), func2->type0(mix_step)
  const funcSec = section(3, vec([[0x00], [0x01], [0x00]]));

  // Memory section: 1 page min, no max
  const memSec = section(5, vec([[0x00, ...uleb(1)]]));

  // Export section
  const exp = (name, kind, idx) => {
    const bytes = [...name].map((c) => c.charCodeAt(0));
    return [...uleb(bytes.length), ...bytes, kind, ...uleb(idx)];
  };
  const exportSec = section(
    7,
    vec([
      exp("memory", 0x02, 0),
      exp("mix", 0x00, 0),
      exp("set_key", 0x00, 1),
      exp("mix_step", 0x00, 2),
    ])
  );

  // --- code: mix(a=0,b=1,k=2), local r=3 ---
  const mixCode = [
    ...OP.localGet(0), ...OP.localGet(1), ...OP.i32add, ...OP.localSet(0), // a=a+b
    ...OP.localGet(0), ...OP.localGet(2), ...OP.i32xor, ...OP.localSet(0), // a=a^k
    ...OP.localGet(1), ...OP.localGet(2), ...OP.i32xor, ...OP.i32const(31), ...OP.i32and, ...OP.localSet(3), // r=(b^k)&31
    ...OP.localGet(3), ...OP.i32eqz, ...OP.if_void, ...OP.i32const(7), ...OP.localSet(3), ...OP.end, // if r==0 r=7
    ...OP.localGet(0), ...OP.localGet(3), ...OP.i32rotl, ...OP.localSet(0), // a=rotl(a,r)
    ...OP.localGet(0),
    ...OP.localGet(1), ...OP.i32const(1), ...OP.i32or, ...OP.i32const(GOLDEN), ...OP.i32mul, // (b|1)*GOLDEN
    ...OP.i32add, ...OP.localSet(0), // a=a+that
    ...OP.localGet(0), // return a
  ];
  const mixBody = body([[1, I32]], mixCode);

  // --- set_key(i=0, val=1): mem[(i<<2)] = val ---
  const setKeyCode = [
    ...OP.localGet(0), ...OP.i32const(2), ...OP.i32shl, // addr = i<<2
    ...OP.localGet(1), // value
    ...OP.i32store,
  ];
  const setKeyBody = body([], setKeyCode);

  // --- mix_step(a=0,b=1,step=2), local k=3: k=mem[(step&7)<<2]; return mix(a,b,k) ---
  const mixStepCode = [
    ...OP.localGet(2), ...OP.i32const(7), ...OP.i32and, ...OP.i32const(2), ...OP.i32shl, // (step&7)<<2
    ...OP.i32load, ...OP.localSet(3), // k = mem[...]
    ...OP.localGet(0), ...OP.localGet(1), ...OP.localGet(3), ...OP.call(0), // mix(a,b,k)
  ];
  const mixStepBody = body([[1, I32]], mixStepCode);

  const codeSec = section(10, vec([mixBody, setKeyBody, mixStepBody]));

  const bytes = [
    0x00, 0x61, 0x73, 0x6d, // \0asm
    0x01, 0x00, 0x00, 0x00, // version 1
    ...typeSec,
    ...funcSec,
    ...memSec,
    ...exportSec,
    ...codeSec,
  ];
  return Uint8Array.from(bytes);
}
