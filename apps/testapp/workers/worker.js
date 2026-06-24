importScripts("/workers/worker_import.js");
const worker = new Worker("/workers/worker_in_worker.js");
self.addEventListener('message', (event) => {
    if (event.data === 'Check connection') {
      postMessage('worker: active');
    }
});