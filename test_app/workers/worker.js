self.addEventListener('message', (event) => {
    if (event.data === 'Check connection') {
      postMessage('worker: active');
    }
});