(function() {
    const originalModule = WebAssembly.Module;
  
    WebAssembly.Module = function(binarySource) {
      const module = new originalModule(binarySource);
      Object.defineProperty(module, '__originalBytes__', {
        value: binarySource,
        writable: false,
        enumerable: false,
        configurable: false
      });
      return module;
    };
  
    const originalInstantiate = WebAssembly.instantiate;
  
    WebAssembly.instantiate = async function(source, importObject) {
      if (source instanceof WebAssembly.Module) {
        const originalBytes = source.__originalBytes__;
        if (originalBytes) {
          const hash = await crypto.subtle.digest('SHA-256', originalBytes);
          console.log('Hash of WebAssembly.Module bytecode:', hash);
        } else {
          throw new Error("If we have a module object, we must have the source too.");
        }
      } else if (source instanceof ArrayBuffer || source instanceof Uint8Array) {
        const hash = await crypto.subtle.digest('SHA-256', source);
        console.log('Hash of ArrayBuffer:', hash);
      } else {
        throw new Error("Unknown object passwd to WebAssembly.instantiate.");
      }
      return originalInstantiate.apply(this, arguments);
    };
  
    const originalInstantiateStreaming = WebAssembly.instantiateStreaming;

    WebAssembly.instantiateStreaming = async function(response, importObject) {
      const awaitedResponse = await response;
      const clonedResponse = awaitedResponse.clone();
      const arrayBuffer = await clonedResponse.arrayBuffer();
      const hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
      console.log('Hash of streamed ArrayBuffer:', hash);
      return originalInstantiateStreaming.apply(this, arguments);
    };
  })();