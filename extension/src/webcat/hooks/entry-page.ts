import { wasmHook } from "./core";

console.log("[WEBCAT] Installing page hook");

wasmHook(globalThis, globalThis, (func, targetScope, { defineAs }) => {
  Object.defineProperty(targetScope, defineAs, { value: func });
  return func;
});
