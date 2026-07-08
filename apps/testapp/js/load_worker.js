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
  }
