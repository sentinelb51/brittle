// mint.js — server-side session lifecycle: mint a per-session blob + challenge, then
// validate the returned proof. This is the rotation authority: each session gets fresh
// keys (token, nonce) and a fresh structure (structuralSeed), and each proof is accepted
// at most once. A dumped blob dies when its session is consumed or expires.

import { randomBytes, randomInt } from "node:crypto";
import { assemble } from "../ir/assemble.js";
import { mintBlob } from "./mutate.js";
import { expectedProof } from "./reference.js";

export const SIGNAL_CLEAN = 0; // the anti-analysis signal in an untampered environment

const SESSION_TTL_MS = 60_000; // short shelf life; tune per deployment

export class MintService {
  // guardedSource: the DSL program (e.g. guardedProof). allowedOrigin: the only origin
  // blobs are bound to. integrity: word = hash(stub source + wasm) the server ships.
  constructor(guardedSource, { allowedOrigin, integrity }) {
    this.canonical = assemble(guardedSource);
    this.allowedOrigin = allowedOrigin;
    this.integrity = integrity >>> 0;
    this.sessions = new Map();
  }

  // Client registers its fingerprint hash; server mints a bound blob + challenge.
  // `origin` binds the blob; it defaults to the configured allowedOrigin but the server
  // may pass the request's own origin so the demo works on any host:port.
  async createSession(fpHash, origin = this.allowedOrigin) {
    const id = randomBytes(12).toString("hex");
    const token = randomBytes(16).toString("hex");
    const nonce = randomInt(0, 0x100000000) >>> 0;
    const structuralSeed = randomInt(0, 0x100000000) >>> 0;

    const env = {
      origin,
      token,
      nonce,
      fpHash,
      signal: SIGNAL_CLEAN,
      integrity: this.integrity,
    };

    const { blob, checksum } = await mintBlob(this.canonical, env, structuralSeed);
    const expected = await expectedProof(this.canonical, env, checksum);

    this.sessions.set(id, { expected, expires: Date.now() + SESSION_TTL_MS });
    return { id, token, nonce, integrity: this.integrity, blob };
  }

  // One-shot proof check. Consuming or expiring the session rotates it out.
  validate(id, proof) {
    const s = this.sessions.get(id);
    if (!s) return { ok: false, reason: "unknown-or-consumed" };
    this.sessions.delete(id); // one-shot: no replay
    if (Date.now() > s.expires) return { ok: false, reason: "expired" };
    if (proof !== s.expected) return { ok: false, reason: "bad-proof" };
    return { ok: true };
  }

  sweep(now = Date.now()) {
    for (const [id, s] of this.sessions) if (now > s.expires) this.sessions.delete(id);
  }
}
