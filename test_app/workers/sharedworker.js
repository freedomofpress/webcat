self.addEventListener('connect', (event) => {
    const port = event.ports[0];
    port.postMessage('sharedworker: active');
    port.start();
});
  