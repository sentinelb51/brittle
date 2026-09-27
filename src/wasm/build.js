// build.js — emit the handler-core WASM to disk (src/wasm/core.wasm) for inspection or
// static serving. The runtime does NOT need this file; the engine emits the bytes in-process
// (src/wasm/emit.js), which is what allows per-session WASM regeneration later.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { emitWasm } from "./emit.js";

const out = join(fileURLToPath(new URL(".", import.meta.url)), "core.wasm");
const bytes = emitWasm();
await writeFile(out, bytes);
console.log(`wrote ${out} (${bytes.length} bytes)`);
// sanity: it must instantiate
await WebAssembly.instantiate(bytes, {});
console.log("instantiated OK");
