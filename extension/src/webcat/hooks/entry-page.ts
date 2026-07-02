import {
  eventHook,
  serviceWorkerHook,
  sharedWorkerHook,
  wasmHook,
  workerHook,
} from "./core";

console.log("[WEBCAT] Installing page hook");

const scope = {};

wasmHook(scope);
sharedWorkerHook(scope);
serviceWorkerHook(scope);
workerHook(scope);
eventHook(scope);
