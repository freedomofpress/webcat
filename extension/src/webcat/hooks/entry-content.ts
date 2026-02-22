import { installHook } from "./core";

console.log("[WEBCAT] Installing content script hook");

(function () {
  if (typeof window === "undefined") return;

  if (
    typeof window.wrappedJSObject !== "undefined" &&
    typeof window.exportFunction === "function"
  ) {
    const pageWindow = window.wrappedJSObject as typeof globalThis;

    const exported = window.exportFunction(installHook, pageWindow);
    exported(pageWindow);
  }
})();
