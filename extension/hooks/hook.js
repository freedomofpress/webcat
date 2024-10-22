(function () {
  const originalModule = WebAssembly.Module;

  WebAssembly.Module = function (binarySource) {
    const module = new originalModule(binarySource);
    Object.defineProperty(module, "__originalBytes__", {
      value: binarySource,
      writable: false,
      enumerable: false,
      configurable: false,
    });
    return module;
  };

  delete originalModule;

  const originalInstantiate = WebAssembly.instantiate;

  WebAssembly.instantiate = async function (source, importObject) {
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

  WebAssembly.instantiateStreaming = async function (response, importObject) {
    const awaitedResponse = await response;
    const clonedResponse = awaitedResponse.clone();
    const arrayBuffer = await clonedResponse.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", arrayBuffer);
    console.log("Hash of streamed ArrayBuffer:", hash);

    // Send hash to be validated
    window.postMessage({ type: "WASM_HASH", payload: hash });

    // Wait for validation response and stop execution if not valid
    const validationResult = await waitForValidation();
    if (!validationResult) {
      throw new Error("Error validating WASM.");
    }

    // Continue execution if validation passes
    return originalInstantiateStreaming.apply(this, arguments);
  };

  delete originalInstantiateStreaming;

  // Function to wait for validation response asynchronously
  function waitForValidation() {
    return new Promise((resolve) => {
      const validationListener = (event) => {
        if (event.source !== window) return;
        if (event.data.type === "WASM_RESPONSE") {
          window.removeEventListener("message", validationListener); // Clean up the listener
          resolve(event.data.response); // Resolve based on the response
        }
      };
      window.addEventListener("message", validationListener, false);
    });
  }

  Object.freeze(WebAssembly.Module);
  Object.freeze(WebAssembly.instantiate);
  Object.freeze(WebAssembly.instantiateStreaming);
})();
