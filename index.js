var makeCsr = require('./create');

var form = global.document.getElementById('main-form');

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
    console.log(resp);
  }).catch(function (e) {
    console.log(e);
  })
});
