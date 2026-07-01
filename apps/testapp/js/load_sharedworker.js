if (window.SharedWorker) {
    const sharedWorker = new SharedWorker('/workers/sharedworker.js');
  
    sharedWorker.port.onmessage = (event) => {
      if (event.data === 'sharedworker: active') {
        console.log('load_sharedworker.js:', true);
      }
    };
  
    sharedWorker.port.postMessage('Check connection');

    sharedWorker.onerror = function (event) {
      console.log(event.message, event.target === this, "onerror");
    };
    sharedWorker.addEventListener("error", function (event) {
      console.log(event.message, event.target === this, "callback");
    });
    const handler = {};
    sharedWorker.addEventListener("error", handler);
    handler.handleEvent = function (event) {
      console.log(event.message, event.target === this, "handler");
    };
  }
  