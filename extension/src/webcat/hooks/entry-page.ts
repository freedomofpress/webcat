import {
  eventHook,
  serviceWorkerHook,
  sharedWorkerHook,
  wasmHook,
  workerHook,
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
workerHook(hookInputs);
eventHook(hookInputs);
