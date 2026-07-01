importScripts("/workers/sharedworker_import.js");
const worker = new Worker("/workers/worker_in_sharedworker.js");
self.addEventListener('connect', async (event) => {
    const port = event.ports[0];
    await fetch("/console_log.png");
    port.postMessage('sharedworker: active');
    port.start();
});

throw new Error("error in sharedworker");