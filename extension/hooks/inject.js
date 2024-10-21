/* This script hooks methods that allow difficult-to-track, yet widely used, loading of JS:
    - WASM can only be loaded as a string. The CSP only has 'wasm-unsafe-eval'. Even instantiateStreaming
      would take a response object from a fetch, but not do the fetch itself.
    - To my knowledge, all types of workers are loaded via a URL and then bound to an ORIGIN, not a TAB.
    
    Two different kinds of problems:
    - Any kind of WASM is essentially an eval.
    - Service workers are not tab-scoped, while our sandbox is mostly tab-scoped.
*/
(function injectHookScript() {
  const script = document.createElement("script");
  script.textContent = `
      (function() {
        // Function to send messages to the extension
        function sendMessage(hookType, details) {
          window.postMessage({
            type: 'FROM_HOOK',
            hookType: hookType,
            details: details
          }, '*');
        }
  
        // WASM instantiate takes input from an ArrayBuffer, so we need to verify the content
        const originalInstantiate = WebAssembly.instantiate;
        Object.defineProperty(WebAssembly, 'instantiate', {
          value: function(...args) {
            //sendMessage('WebAssembly.instantiate', { arguments: args });
            sendMessage('WebAssembly.instantiate');
            return originalInstantiate.apply(this, args);
          },
          writable: false,
          configurable: false
        });
  
        // Wasm instantiateStreaming can take a URL, so we need to map the fetch and verify the request
        const originalInstantiateStreaming = WebAssembly.instantiateStreaming;
        Object.defineProperty(WebAssembly, 'instantiateStreaming', {
          value: function(...args) {
            //sendMessage('WebAssembly.instantiateStreaming', { arguments: args });
            sendMessage('WebAssembly.instantiateStreaming');
            return originalInstantiateStreaming.apply(this, args);
          },
          writable: false,
          configurable: false
        });
  
        // A Worker is instantiated from a URL
        const originalWorker = window.Worker;
        Object.defineProperty(window, 'Worker', {
          value: function(...args) {
            sendMessage('Worker', { arguments: args });
            return new originalWorker(...args);
          },
          writable: false,
          configurable: false
        });
  
        // SharedWorker also instantiated from a URL
        const originalSharedWorker = window.SharedWorker;
        Object.defineProperty(window, 'SharedWorker', {
          value: function(...args) {
            sendMessage('SharedWorker', { arguments: args });
            return new originalSharedWorker(...args);
          },
          writable: false,
          configurable: false
        });
  
        // ServiceWorker registration, also uses URLs
        const originalRegister = navigator.serviceWorker.register;
        Object.defineProperty(navigator.serviceWorker, 'register', {
          value: function(...args) {
            sendMessage('ServiceWorker.register', { arguments: args });
            return originalRegister.apply(this, args);
          },
          writable: false,
          configurable: false
        });
  
        // Freeze objects to prevent further tampering
        Object.freeze(WebAssembly);
        Object.freeze(window.Worker);
        Object.freeze(window.SharedWorker);
        Object.freeze(navigator.serviceWorker);
  
      })();
    `;
  document.documentElement.appendChild(script);
  script.remove();
})();
