// fingerprint.js — derive a stable-ish device fingerprint hash (hex) from environment
// signals, folded into the key schedule and the proof. Purpose is BINDING, not unique
// tracking: a blob minted for fingerprint X decodes to garbage on a machine with
// fingerprint Y. The server pins the fp hash the client registered at /session, so it
// can predict the proof; a copied blob on different hardware cannot reproduce it.
//
// Cost to the analyst: to run a copied blob they must reproduce the exact fingerprint of
// the target machine, or hook every signal source consistently.
// Overcome by: matching every signal to a known-good capture.
// Rotation: the next session mints against a fresh nonce/token, so a captured fp only
// helps for a session that has already expired.

const enc = new TextEncoder();

async function sha256hex(str) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function canvasSignal() {
  try {
    const c = document.createElement("canvas");
    c.width = 200;
    c.height = 40;
    const g = c.getContext("2d");
    g.textBaseline = "top";
    g.font = "14px 'Arial'";
    g.fillStyle = "#f60";
    g.fillRect(2, 2, 120, 20);
    g.fillStyle = "#069";
    g.fillText("brittle:☃🔒", 4, 4);
    return c.toDataURL();
  } catch {
    return "canvas:na";
  }
}

function webglSignal() {
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return "webgl:na";
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
    const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    return `${vendor}|${renderer}`;
  } catch {
    return "webgl:na";
  }
}

async function audioSignal() {
  try {
    const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!Ctx) return "audio:na";
    const ctx = new Ctx(1, 4410, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    let acc = 0;
    const data = buf.getChannelData(0);
    for (let i = 0; i < data.length; i += 100) acc += Math.abs(data[i]);
    return acc.toString();
  } catch {
    return "audio:na";
  }
}

// Returns a hex string (SHA-256). In non-browser contexts returns a stable stub so the
// module is import-safe on the server and in tests.
export async function fingerprintHash() {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return "00000000000000000000000000000000";
  }
  const parts = [
    location.origin,
    navigator.userAgent,
    navigator.language,
    (navigator.languages || []).join(","),
    String(navigator.hardwareConcurrency || 0),
    String(navigator.deviceMemory || 0),
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    String(new Date().getTimezoneOffset()),
    Intl.DateTimeFormat().resolvedOptions().timeZone || "tz:na",
    canvasSignal(),
    webglSignal(),
    await audioSignal(),
  ];
  return sha256hex(parts.join("␟"));
}
