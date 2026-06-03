import { serviceWorkerHook, sharedWorkerHook, wasmHook } from "./core";

console.log("[WEBCAT] Installing content script hook");

const hookInputs = {
  scope: window,
  unwrappedScope: window.wrappedJSObject,
  exportFunction: exportFunction,
  localScope: window,
};

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
  wasmHook(hookInputs);
}

sharedWorkerHook(hookInputs);
serviceWorkerHook(hookInputs);
