console.log("[WEBCAT] Installing worker hook");

const wasm = globalThis.WebAssembly;

function block(name, returnPromise = true) {
  return function () {
    console.log(`[WEBCAT] Blocked execution of WebAssembly.${name}`);
    if (returnPromise) {
      return new Promise(() => {});
    }
    throw new Error(`WebAssembly.${name} blocked`);
  };
}

// Use defineProperty so it works even if properties are non-writable
Object.defineProperty(wasm, "compile", {
  value: block("compile"),
});

Object.defineProperty(wasm, "instantiate", {
  value: block("instantiate"),
});

Object.defineProperty(wasm, "Module", {
  value: block("Module", false),
});
