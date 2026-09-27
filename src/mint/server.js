// server.js — the mint endpoint + static host for the demo.
//
// POST /session {fpHash}      -> { id, token, nonce, integrity, blob(base64) }
// POST /prove   {id, proof}   -> { ok, reason }
// GET  /*                     -> static files (demo/ and src/ so the browser can import)
//
// The server is the rotation authority: it mints a fresh per-session blob and validates
// the returned proof by running the CANONICAL program itself (see reference.js). The
// client is disposable — a dumped blob dies at the next /session.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { MintService } from "./mint.js";
import { integrityWord } from "../vm/integrity.js";
import { emitWasm } from "../wasm/emit.js";
import { guardedProof } from "../guarded/proof.js";

const ROOT = normalize(join(fileURLToPath(new URL(".", import.meta.url)), "..", ".."));
const PORT = Number(process.env.PORT || 8080);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
};

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

const json = (res, code, obj) => {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
};

async function main() {
  const integrity = await integrityWord([emitWasm()]);
  const svc = new MintService(guardedProof, {
    allowedOrigin: `http://localhost:${PORT}`,
    integrity,
  });
  setInterval(() => svc.sweep(), 10_000).unref();

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const origin = `http://${req.headers.host}`;

      if (req.method === "POST" && url.pathname === "/session") {
        const { fpHash } = await readBody(req);
        if (typeof fpHash !== "string" || !/^[0-9a-f]{8,128}$/.test(fpHash)) {
          return json(res, 400, { error: "bad fpHash" });
        }
        const s = await svc.createSession(fpHash, origin);
        return json(res, 200, {
          id: s.id,
          token: s.token,
          nonce: s.nonce,
          integrity: s.integrity,
          blob: Buffer.from(s.blob).toString("base64"),
        });
      }

      if (req.method === "POST" && url.pathname === "/prove") {
        const { id, proof } = await readBody(req);
        if (typeof id !== "string" || typeof proof !== "string") {
          return json(res, 400, { error: "bad request" });
        }
        return json(res, 200, svc.validate(id, proof));
      }

      // --- static ---
      let pathname = url.pathname === "/" ? "/demo/index.html" : url.pathname;
      const filePath = normalize(join(ROOT, pathname));
      if (!filePath.startsWith(ROOT + sep) && filePath !== ROOT) {
        res.writeHead(403);
        return res.end("forbidden");
      }
      const body = await readFile(filePath);
      res.writeHead(200, { "content-type": MIME[extname(filePath)] || "application/octet-stream" });
      return res.end(body);
    } catch (e) {
      if (e && e.code === "ENOENT") {
        res.writeHead(404);
        return res.end("not found");
      }
      res.writeHead(500);
      return res.end("error");
    }
  });

  server.listen(PORT, () => {
    console.log(`brittle mint server on http://localhost:${PORT}  (integrity=0x${integrity.toString(16)})`);
  });
}

main();
