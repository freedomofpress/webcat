(function () {
  const originalModule = WebAssembly.Module;

  WebAssembly.Module = function (binarySource) {
    const module = Reflect.construct(
      originalModule,
      [binarySource],
      WebAssembly.Module,
    );

    Object.defineProperty(module, "__originalBytes__", {
      value: binarySource,
      writable: false,
      enumerable: false,
      configurable: false,
    });
    return module;
  };

  WebAssembly.Module.prototype = originalModule.prototype;
  delete originalModule;

  const originalCompile = WebAssembly.compile;
  WebAssembly.compile = async function (bufferSource) {
    const module = await originalCompile.apply(this, arguments);
    module.__originalBytes__ = bufferSource;
    return module;
  };

  delete originalCompile;

  const originalCompileStreaming = WebAssembly.compileStreaming;
  WebAssembly.compileStreaming = async function (response) {
    const awaitedResponse = await response;
    const clonedResponse = awaitedResponse.clone();
    const arrayBuffer = await clonedResponse.arrayBuffer();
    const module = await originalCompileStreaming.apply(this, [
      awaitedResponse,
    ]);
    module.__originalBytes__ = arrayBuffer;
    return module;
  };

  delete originalCompileStreaming;

  const originalInstantiate = WebAssembly.instantiate;

  WebAssembly.instantiate = async function (source, _importObject) {
    let hash;
    if (source instanceof WebAssembly.Module) {
      const originalBytes = source.__originalBytes__;
      if (originalBytes) {
        hash = await crypto.subtle.digest("SHA-256", originalBytes);
        console.log("Hash of WebAssembly.Module bytecode:", hash);
      } else {
        throw new Error(
          "If we have a module object, we must have the source too.",
        );
      }
    } else if (source instanceof ArrayBuffer || source instanceof Uint8Array) {
      hash = await crypto.subtle.digest("SHA-256", source);
      console.log("Hash of ArrayBuffer:", hash);
    } else {
      throw new Error("Unknown object passed to WebAssembly.instantiate.");
    }

    // Send hash to be validated
    window.postMessage({ type: "WASM_HASH", payload: hash });

    // Wait for validation response and stop execution if not valid
    const validationResult = await waitForValidation();
    if (!validationResult) {
      throw new Error("Error validating WASM.");
    }

    // Continue execution if validation passes
    return originalInstantiate.apply(this, arguments);
  };

  delete originalInstantiate;

  const originalInstantiateStreaming = WebAssembly.instantiateStreaming;

  WebAssembly.instantiateStreaming = async function (response, _importObject) {
    const awaitedResponse = await response;
    const clonedResponse = awaitedResponse.clone();
    const arrayBuffer = await clonedResponse.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", arrayBuffer);
    console.log("Hash of streamed ArrayBuffer:", hash);

    window.postMessage({ type: "WASM_HASH", payload: hash });

    const validationResult = await waitForValidation();
    if (!validationResult) {
      throw new Error("Error validating WASM.");
    }

    return originalInstantiateStreaming.apply(this, arguments);
  };

  delete originalInstantiateStreaming;

  function waitForValidation() {
    return new Promise((resolve) => {
      const validationListener = (event) => {
        if (event.source !== window) return;
        if (event.data.type === "WASM_RESPONSE") {
          window.removeEventListener("message", validationListener);
          resolve(event.data.response);
        }
      };
      window.addEventListener("message", validationListener, false);
    });
  }

  Object.freeze(WebAssembly.Module);
  Object.freeze(WebAssembly.compile);
  Object.freeze(WebAssembly.compileStreaming);
  Object.freeze(WebAssembly.instantiate);
  Object.freeze(WebAssembly.instantiateStreaming);
})();
