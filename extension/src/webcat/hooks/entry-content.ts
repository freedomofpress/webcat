console.log("[WEBCAT] Installing content script hook");
const wabt = window.wrappedJSObject.WebAssembly;

wabt.compile = exportFunction(function () {
  console.log("[WEBCAT] Blocked execution of WebAssembly.compile");
  throw new Error("WebAssembly.compile blocked");
}, window);

wabt.instantiate = exportFunction(function () {
  console.log("[WEBCAT] Blocked execution of WebAssembly.instantiate");
  throw new Error("WebAssembly.instantiate blocked");
}, window);

wabt.Module = exportFunction(function () {
  console.log("[WEBCAT] Blocked execution of WebAssembly.Module");
  throw new Error("WebAssembly.Module blocked");
}, window);
