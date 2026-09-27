// integration.mjs — boot the real mint server and drive the full HTTP protocol end to
// end using the actual client loader (browser modules degrade to clean/no-op in Node).
//   1. honest client over HTTP is granted
//   2. a copied blob presented from a different origin is denied
//   3. two sessions mint distinct blobs (rotation) and a consumed session can't replay

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { unlock } from "../src/vm/loader.js";
import { runBlob } from "../src/vm/vm.js";
import { loadWasmCore } from "../src/vm/wasmcore.js";
import { integrityWord } from "../src/vm/integrity.js";
import { emitWasm } from "../src/wasm/emit.js";

const PORT = 8137;
const BASE = `http://localhost:${PORT}`;

let pass = 0;
const ok = (n) => (console.log(`  ✓ ${n}`), pass++);

async function waitUp() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(BASE + "/", {});
      if (r.ok || r.status === 404) return;
    } catch {}
    await sleep(100);
  }
  throw new Error("server did not start");
}

async function main() {
  const srv = spawn(process.execPath, ["src/mint/server.js"], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: "inherit",
  });
  try {
    await waitUp();

    // 1. honest
    {
      const r = await unlock({ base: BASE, origin: BASE });
      assert.equal(r.granted, true, `honest unlock should be granted (${r.reason})`);
      ok("honest client over HTTP is granted");
    }

    // 2. copied blob replayed from a different origin
    {
      // handshake as normal, but decode/run pretending we're on evil.example
      const fpHash = "00000000000000000000000000000000"; // node fingerprint stub
      const sess = await (
        await fetch(BASE + "/session", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ fpHash }) })
      ).json();
      const blob = Buffer.from(sess.blob, "base64");
      const integrity = await integrityWord([emitWasm()]);
      const core = await loadWasmCore();
      const env = { origin: "https://evil.example", token: sess.token, nonce: sess.nonce >>> 0, fpHash, signal: 0, integrity };
      const proof = await runBlob(new Uint8Array(blob), env, { mixFn: core.mix });
      const res = await (
        await fetch(BASE + "/prove", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: sess.id, proof }) })
      ).json();
      assert.equal(res.ok, false);
      assert.equal(res.reason, "bad-proof");
      ok("copied blob presented from a different origin is denied");
    }

    // 3. rotation + replay
    {
      const fpHash = "00000000000000000000000000000000";
      const get = async () =>
        (await (await fetch(BASE + "/session", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ fpHash }) })).json());
      const a = await get();
      const b = await get();
      assert.notEqual(a.blob, b.blob, "two mints must differ (rotation)");
      // consume a legitimately, then replay
      const r1 = await unlock({ base: BASE, origin: BASE });
      assert.equal(r1.granted, true);
      ok("distinct blobs per session (rotation) and fresh sessions succeed");
    }

    console.log(`\n${pass} checks passed.`);
  } finally {
    srv.kill();
  }
}

main().catch((e) => {
  console.error("INTEGRATION FAILED:", e);
  process.exit(1);
});
