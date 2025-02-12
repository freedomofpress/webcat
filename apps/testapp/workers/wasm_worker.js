self.addEventListener('message', (event) => {
  if (event.data === 'Check connection') {
    WebAssembly.instantiateStreaming(fetch("/wasm/reverseSub.wasm"), {})
      .then(result => {
        const reverseSub = result.instance.exports.reverseSub;

        const num1 = Math.floor(Math.random() * 100) + 1;
        const num2 = Math.floor(Math.random() * 100) + 1;

        console.log("wasm_worker.js: ", reverseSub(num1, num2) == (num2 - num1));
        postMessage('wasm_worker: active');
      })
      .catch(err => {
        console.error("Error loading WASM:", err);
      });
  }
});

