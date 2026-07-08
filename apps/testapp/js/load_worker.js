if (window.Worker) {
  const worker = new Worker('/workers/worker.js');

  worker.onmessage = (event) => {
    if (event.data === 'worker: active') {
      console.log('load_worker.js:', true);
    }
  };

  worker.postMessage('Check connection');

  worker.onerror = function (event) {
    console.log(event.message, event.target === this, "onerror");
    event.preventDefault();
  };
  worker.addEventListener("error", function (event) {
    console.log(event.message, event.target === this, "callback");
  });
  const handler = {};
  worker.addEventListener("error", handler);
  handler.handleEvent = function (event) {
    console.log(event.message, event.target === this, "handler");
  };
  const removedCallback = function (event) {
    console.log(event.message, event.target === this, "removed callback");
  };
  worker.addEventListener("error", removedCallback);
  worker.removeEventListener("error", removedCallback);
}
