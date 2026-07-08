// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with data and injected into scripts
// by response.ts

import { eventHook, eventTargetHook } from "./events";
import { wasmHook } from "./wasm";
import { serviceWorkerHook, sharedWorkerHook, workerHook } from "./workers";

console.log("[WEBCAT] Installing page hook");
const data = "__DATA_PLACEHOLDER__";
const scope = {};

wasmHook(scope, data);
sharedWorkerHook(scope, data);
serviceWorkerHook(scope, data);
workerHook(scope, data);
eventTargetHook(scope, data);
eventHook(scope, data);
