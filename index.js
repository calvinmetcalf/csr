var makeCsr = require('./create');

self.addEventListener('message', function (e) {
  makeCsr(e.data[0], e.data[1]).then(function (resp) {
    self.postMessage(resp);
  }).catch(function (e) {
    process.nextTick(function () {
      throw e;
    });
  });
});
