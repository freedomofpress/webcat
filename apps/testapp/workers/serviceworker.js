self.addEventListener('install', (event) => {
  console.log('Service Worker installed');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('Service Worker activated');
  clients.claim().then(() => {
    self.clients.matchAll().then(clients => {
      console.log(`Found ${clients.length} client(s)`); // Log the number of clients matched
      if (clients.length === 0) {
        console.log('No clients controlled by the service worker yet.');
      }
      clients.forEach(client => {
        console.log("sending message to client:", client.id); // Log the client id
        client.postMessage('serviceworker: active');
      });
    }).catch(error => {
      console.error('Error matching clients:', error); // Catch any errors during matchAll
    });
  }).catch(error => {
    console.error('Error claiming clients:', error); // Catch any errors during claim
  });
});
