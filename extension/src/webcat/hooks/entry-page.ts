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
  exportFunction: (func, targetScope, { defineAs }) => {
    Object.defineProperty(targetScope, defineAs, { value: func });
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
