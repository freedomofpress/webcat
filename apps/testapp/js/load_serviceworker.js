if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/workers/serviceworker.js')
    .then((registration) => {

      // Listen for messages from the Service Worker
      navigator.serviceWorker.addEventListener('message', (event) => {
	      console.log(event.data);
        if (event.data === 'serviceworker: active') {
          console.log('load_serviceworker.js:', true);
        }
      });
    })
    .catch((error) => {
      console.error('Service Worker registration failed:', error);
    });
}
