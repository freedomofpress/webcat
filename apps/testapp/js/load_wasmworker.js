if (window.Worker) {
    const wasm_worker = new Worker('/workers/wasm_worker.js');

    wasm_worker.onmessage = (event) => {
      if (event.data === 'wasm_worker: active') {
        console.log('load_wasmworker.js:', true);
      } else {
        throw event.data;
      }
    };

    wasm_worker.postMessage('Check connection');
}
