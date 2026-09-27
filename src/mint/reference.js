// reference.js — the server's expected-proof oracle.
//
// The server never inspects the client's mutated blob to validate a proof. Instead it
// runs the CANONICAL program over the same session environment and gets the proof the
// client MUST produce if (a) it decoded the blob with the right env key, (b) nothing
// was tampered, and (c) it ran the real path. Semantics-preserving mutation guarantees
// canonical-proof == mutated-proof. This is the entire validation.

import { deriveMaster, masterWords } from "../common/kdf.js";
import { buildEnvVector } from "../common/envvec.js";
import { initState, runSlice, sealProof } from "../vm/interp.js";
import { mixJS } from "../vm/mix.js";

// Inline constant literals so the interpreter needs no pool (mirrors what the client
// does after decrypting its pool).
function lower(program) {
  return program.code.map((ins) => {
    if (ins.op === "CONST") return { op: "CONST", args: [ins.args[0], program.consts[ins.args[1]] >>> 0] };
    return ins;
  });
}

// env: { origin, token, nonce, fpHash, signal, integrity }
// blobChecksum: the mint's checksum of the shipped blob, folded in to bind the exact bytes.
export async function expectedProof(program, env, blobChecksum) {
  const master = await deriveMaster(env);
  const keyWords = masterWords(master);
  const envVector = buildEnvVector(env, master);
  const state = initState(program.regCount);
  runSlice(state, lower(program), { envVector, mixFn: mixJS, keyWords });
  return sealProof(state.acc, blobChecksum >>> 0);
}
