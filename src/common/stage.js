// stage.js — staged-bytecode key derivation, shared by mint and engine.
//
// Stage k+1's instruction bytes are encrypted under a seed that only exists once stage
// k has executed: it is folded from the live proof accumulator at the stage boundary.
// A static dump therefore contains stage 0 in the clear (after the env layer) and every
// later stage as ciphertext with no key present anywhere in the blob. The key is
// *computed*, not stored — you must actually run the earlier stages, defeating a purely
// static lift of the full program.
//
// The accumulator is identical on server (canonical run) and client (mutated run), so
// both derive the same stage seed. It is independent of register renaming and junk,
// which only touch dead lanes.

import { splitmix32, mul32 } from "./u32.js";

export function stageSeed(accWords, masterWord0, k) {
  let s = (0x9e3779b9 ^ masterWord0 ^ (k * 0x85ebca6b)) >>> 0;
  for (let i = 0; i < accWords.length; i++) {
    s = mul32(s ^ accWords[i], 0x27d4eb2f) >>> 0;
    s = (s ^ (s >>> 15)) >>> 0;
  }
  // one more splitmix hop so adjacent stages' seeds are uncorrelated
  return splitmix32(s)();
}
