// proof.js — THE GUARDED PROGRAM (the secret). Authored in the readable DSL; it becomes
// opaque only after mint-time mutation. Its job: fold the challenge nonce together with
// every binding signal into a 256-bit proof the server can independently predict.
//
// This program IS the challenge-response. There is no separate "unlock" logic to hide:
// producing the correct proof for a fresh nonce is the service. A copied blob cannot
// produce it on another origin/machine (different env => different key => garbage), and
// cannot replay it (the server issues a fresh nonce per session).
//
// Stage 0 folds server-known bindings (nonce, token, origin). Stage 1 — which only
// decrypts after stage 0 runs — folds environment/integrity bindings (fingerprint,
// instrumentation signal, stub integrity) and the master word. Splitting this way means a
// static dump that hasn't executed stage 0 cannot even read the environment-binding
// half of the program.

export const guardedProof = [
  // --- stage 0: challenge + server-known bindings ---
  ["LDENV", "r0", "NONCE"], // the challenge
  ["LDENV", "r1", "TOKEN0"], // session token
  ["MIX", "r0", "r0", "r1"],
  ["LDENV", "r2", "ORIGIN0"], // origin binding
  ["MIX", "r0", "r0", "r2"],
  ["CONST", "r3", 0x1337beef], // program constant (encrypted in the blob)
  ["XOR", "r0", "r0", "r3"],
  ["EMIT", "r0"],
  ["STAGE"],

  // --- stage 1: environment + integrity bindings (decrypts only after stage 0) ---
  ["LDENV", "r4", "FP0"], // device fingerprint
  ["LDENV", "r5", "SIGNAL"], // instrumentation signal (CLEAN => 0)
  ["MIX", "r4", "r4", "r5"],
  ["LDENV", "r6", "INTEGRITY"], // stub+wasm self-hash
  ["MIX", "r4", "r4", "r6"],
  ["MIX", "r0", "r0", "r4"],
  ["ROL", "r0", "r0", 7],
  ["EMIT", "r0"],
  ["LDENV", "r7", "MASTER0"], // master schedule word
  ["MIX", "r7", "r0", "r7"],
  ["EMIT", "r7"],
  ["HALT"],
];
