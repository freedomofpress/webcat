// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with data and injected into scripts
// by response.ts

import { eventHook } from "./events";
import { wasmHook } from "./wasm";
import { serviceWorkerHook, sharedWorkerHook, workerHook } from "./workers";

console.log("[WEBCAT] Installing content script hook");
const data = "__DATA_PLACEHOLDER__";

// Find the first ancestor that is same-origin with the current window
// and is navigated to an HTTP(S) URL. That is, the first ancestor that
// receives hash updates from the network layer.
let ancestor = window;
while (
  !ancestor.location.protocol.startsWith("http") &&
  ancestor.parent !== ancestor
) {
  try {
    Object.hasOwn(ancestor.parent, "name");
  } catch {
    // not same-origin
    break;
  }
  ancestor = ancestor.parent as Window & typeof globalThis;
}

if (ancestor !== window) {
  // There is a same-origin ancestor that has already been
  // hooked; use it instead of attempting to re-hook here
  window.wrappedJSObject.WebAssembly = ancestor.wrappedJSObject.WebAssembly;
} else {
  wasmHook(window, data);
}

sharedWorkerHook(window, data);
serviceWorkerHook(window, data);
workerHook(window, data);
eventHook(window, data);
