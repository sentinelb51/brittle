// mix.js — JS fallback for the sensitive MIX handler. It computes exactly what the
// WASM core computes (src/wasm/emit.js): one ARX round keyed by a key-schedule word.
// The VM prefers the WASM export and falls back to this only if WASM is unavailable,
// so results are identical either way.
import { arx } from "../common/u32.js";

export const mixJS = (a, b, k) => arx(a >>> 0, b >>> 0, k >>> 0);
