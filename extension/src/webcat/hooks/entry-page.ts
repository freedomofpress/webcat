// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with data and injected into scripts
// by response.ts

import { wasmHook } from "./wasm";

console.log("[WEBCAT] Installing page hook");
const data = "__DATA_PLACEHOLDER__";
const scope = {};

wasmHook(scope, data);
