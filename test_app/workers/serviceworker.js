self.addEventListener('install', (event) => {
  console.log('Service Worker installed');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('Service Worker activated');
  clients.claim().then(() => {
    self.clients.matchAll().then(clients => {
      clients.forEach(client => {
        client.postMessage('serviceworker: active');
      });
    });
  });
});