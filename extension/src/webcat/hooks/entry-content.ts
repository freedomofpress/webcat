console.log("[WEBCAT] Installing content script hook");

const pageWin = window.wrappedJSObject;
const wasm = pageWin.WebAssembly;

function getWebAssemblyPtr(pwd: string) {
  const key = "__KEY_PLACEHOLDER__";
  if (pwd === key) {
    return wasm;
  }
}

exportFunction(getWebAssemblyPtr, pageWin, { defineAs: "getWebAssemblyPtr" });

delete pageWin.WebAssembly;
