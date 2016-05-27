var JSZip = require('jszip');
self.addEventListener('message', function (e) {
  var zip = new JSZip();
  zip.file('key.pem', e.data.key);
  zip.file('csr.pem', e.data.csr);
  zip.generateAsync({type : 'uint8array'}).then(function (resp) {
    self.postMessage(resp, [resp.buffer])
  }).catch(function (e) {
    process.nextTick(function () {
      throw e;
    });
  })
});
