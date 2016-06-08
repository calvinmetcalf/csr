this.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open('v1').then(function(cache) {
      return cache.addAll([
        '/csr/',
        '/csr/index.html',
        '/csr/bootstrap.min.css',
        '/csr/worker.js',
        '/csr/zip-worker.js'
      ]);
    })
  );
});
