if (window.SharedWorker) {
    const sharedWorker = new SharedWorker('/workers/sharedworker.js');
  
    sharedWorker.port.onmessage = (event) => {
      if (event.data === 'sharedworker: active') {
        console.log('load_sharedworker.js:', true);
      }
    };
  
    sharedWorker.port.postMessage('Check connection');
  }
  