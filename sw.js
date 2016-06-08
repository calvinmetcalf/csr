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
this.addEventListener('fetch', function(event) {
  var response;
  event.respondWith(caches.match(event.request).catch(function() {
    return fetch(event.request);
  }).then(function(r) {
    response = r;
    caches.open('v1').then(function(cache) {
      cache.put(event.request, response);
    });
    return response.clone();
  });
});
