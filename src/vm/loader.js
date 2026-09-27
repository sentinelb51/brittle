// loader.js — the client half of the rotation protocol. Runs in the browser (and, since
// every dependency degrades safely off-DOM, in Node for integration testing).
//
// Flow:
//   1. compute fingerprint, POST /session  -> { id, token, nonce, blob }
//   2. gather live environment (origin, fp, anti-analysis signal, self-integrity)
//   3. decode+run the blob in the VM (WASM MIX core) -> proof
//   4. POST /prove { id, proof } -> granted / denied
//
// The client computes integrity/signal LOCALLY and never trusts the server's copy: if the
// shipped code was patched, the locally computed values diverge and the proof fails. The
// keys are re-derived from the environment inside runBlob; nothing secret is shipped.

import { runBlob } from "./vm.js";
import { loadWasmCore } from "./wasmcore.js";
import { fingerprintHash } from "./fingerprint.js";
import { computeSignal } from "./antianalysis.js";
import { integrityWord } from "./integrity.js";
import { emitWasm } from "../wasm/emit.js";

function b64ToBytes(b64) {
  if (typeof atob === "function") {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export async function unlock(opts = {}) {
  const base = opts.base ?? "";
  const origin = opts.origin ?? (typeof location !== "undefined" ? location.origin : "");
  const doFetch = opts.fetch ?? fetch;
  const strict = opts.strict ?? false;

  const fpHash = await fingerprintHash();

  const sess = await (
    await doFetch(base + "/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fpHash }),
    })
  ).json();

  const blob = b64ToBytes(sess.blob);
  const signal = computeSignal({ strict });
  const integrity = await integrityWord([emitWasm()]); // real build also folds stub source
  const env = { origin, token: sess.token, nonce: sess.nonce >>> 0, fpHash, signal, integrity };

  const core = await loadWasmCore();
  // Pass the whole core: runBlob loads the key schedule into WASM linear memory and drives
  // MIX via mix_step, so round keys never surface in a JS variable during execution.
  const proof = await runBlob(blob, env, { core });

  const res = await (
    await doFetch(base + "/prove", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: sess.id, proof }),
    })
  ).json();

  return { granted: !!res.ok, reason: res.reason, proof, signal };
}
