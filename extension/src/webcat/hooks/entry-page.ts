import {
  serviceWorkerHook,
  sharedWorkerHook,
  wasmHook,
  workerLocationHook,
} from "./core";

console.log("[WEBCAT] Installing page hook");

const hookInputs = {
  scope: globalThis,
  unwrappedScope: globalThis,
  exportFunction: (func, targetScope, options) => {
    if (options?.defineAs) {
      Object.defineProperty(targetScope, options.defineAs, { value: func });
    }
    return func;
  },
  localScope: {},
};

wasmHook(hookInputs);
sharedWorkerHook(hookInputs);
serviceWorkerHook(hookInputs);

if (
  "SharedWorkerGlobalScope" in globalThis ||
  "ServiceWorkerGlobalScope" in globalThis
) {
  workerLocationHook();
}
