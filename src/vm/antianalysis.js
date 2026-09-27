// antianalysis.js — fold devtools/debugger presence into a single u32 "signal" word.
// In an untampered environment this MUST be 0 (SIGNAL_CLEAN), because the server predicts
// the proof assuming 0. Any set bit perturbs the key schedule and the proof -> the server
// denies service. Crucially we never branch on the signal ("if(devtools) throw"): it is
// data folded into the computation, so the trap is delocalized (see docs/SPEC.md).
//
// No single check is reliable after timer coarsening, so signals are combined. Each bit:
//   bit0  debugger-statement stall (a paused debugger makes the block slow)
//   bit1  console getter trap fired (devtools rendered a logged object)
//   bit2  a hooked native (Function.prototype.toString no longer "[native code]")
//   bit3  large outer/inner window delta (docked devtools) -- STRICT only (noisy)
//
// Cost to reverser: must defeat every enabled signal simultaneously and keep the fold at
// exactly 0. Defeated by: patching each check to report clean. Rotation: patches are
// per-build; the next mint reshuffles the surrounding VM and re-binds keys, so a patch
// set expires with the session.

const DEBUGGER_STALL_MS = 100;

function debuggerStall() {
  try {
    const t0 = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    return performance.now() - t0 > DEBUGGER_STALL_MS ? 1 : 0;
  } catch {
    return 0;
  }
}

function consoleTrap() {
  try {
    let fired = 0;
    const bait = {};
    Object.defineProperty(bait, "id", {
      get() {
        fired = 1;
        return "brittle";
      },
    });
    // Only an open console that renders the object will access the getter.
    console.debug(bait);
    // eslint-disable-next-line no-console
    console.clear?.();
    return fired;
  } catch {
    return 0;
  }
}

function hookedNatives() {
  try {
    const suspects = [Function.prototype.toString, performance.now, console.debug];
    for (const fn of suspects) {
      if (!/\[native code\]/.test(Function.prototype.toString.call(fn))) return 1;
    }
    return 0;
  } catch {
    return 1; // toString itself throwing is itself suspicious
  }
}

function windowDelta() {
  try {
    const dw = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
    const dh = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
    return dw > 160 || dh > 160 ? 1 : 0;
  } catch {
    return 0;
  }
}

// Returns a u32 signal. 0 == clean. `strict` enables the noisy size-delta bit.
export function computeSignal({ strict = false } = {}) {
  if (typeof window === "undefined") return 0; // server/tests: clean
  let s = 0;
  s |= debuggerStall() << 0;
  s |= consoleTrap() << 1;
  s |= hookedNatives() << 2;
  if (strict) s |= windowDelta() << 3;
  return s >>> 0;
}
