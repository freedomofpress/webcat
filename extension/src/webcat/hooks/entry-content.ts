import { wasmHook } from "./core";

console.log("[WEBCAT] Installing content script hook");

wasmHook(window, window.wrappedJSObject, document.baseURI, exportFunction);
