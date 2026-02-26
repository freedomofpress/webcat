import { servieWorkersChecker, wasmHook } from "./core";

console.log("[WEBCAT] Installing page hook");

wasmHook();
servieWorkersChecker();
