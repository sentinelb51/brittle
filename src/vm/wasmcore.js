// wasmcore.js — instantiate the WASM handler core and expose it to the VM.
//
// The key schedule is loaded into WASM linear memory via set_key; mix_step reads keys
// from there, so on the browser path the key words never live in a JS variable during
// execution. `mix(a,b,k)` is the explicit-key form used for parity testing and as the
// drop-in mixFn for the shared interpreter (bit-identical to the JS fallback).

import { emitWasm } from "../wasm/emit.js";

export async function loadWasmCore(keyWords) {
  const bytes = emitWasm();
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { mix, set_key, mix_step, memory } = instance.exports;
  if (keyWords) for (let i = 0; i < 8; i++) set_key(i, keyWords[i] | 0);
  return {
    // explicit-key round (used as interp mixFn; identical to u32.arx)
    mix: (a, b, k) => mix(a | 0, b | 0, k | 0) >>> 0,
    // memory-key round: key taken from WASM linear memory at index (step & 7)
    mixStep: (a, b, step) => mix_step(a | 0, b | 0, step | 0) >>> 0,
    setKey: (i, v) => set_key(i | 0, v | 0),
    memory,
    bytes,
  };
}
