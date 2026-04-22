import { WebcatErrorFile } from "../interfaces/errors";
import { wasmHook } from "./core";

console.log("[WEBCAT] Installing content script hook");

wasmHook(window, window.wrappedJSObject, exportFunction, () => {
  browser.runtime.sendMessage({ error: WebcatErrorFile.MISMATCH });
});
