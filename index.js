var makeCsr = require('./create');

var form = global.document.getElementById('main-form');
var certTag = global.document.getElementById('cert');
var keyTag = global.document.getElementById('key');
form.addEventListener('submit', function (event) {
  event.preventDefault();
  var formData = new FormData(form);

  var obj = {};
  var keytype;
  for (let [key, value] of formData) {
    if (key === 'keytype') {
      keytype = value;
      continue;
    }
    obj[key] = value;
  }
  makeCsr(keytype, obj).then(function (resp) {
    setCert(resp[0]);
    setKey(resp[1]);
  }).catch(function (e) {
    console.log(e);
  })
});
function setCert(cert) {
  var tag = document.createElement('pre');
  tag.textContent=cert;
  certTag.replaceChild(tag, certTag.firstChild);
}
function setKey(key) {
  var tag = document.createElement('pre');
  tag.textContent=key;
  keyTag.replaceChild(tag, keyTag.firstChild);
}
