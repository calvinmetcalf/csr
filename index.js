'use strict';
var csr = require('./csr');
function createSignable(info, key, algo) {
  var out = csr.CertificationRequestInfo.encode('der', {
    info: createInfo(info),
    version: 0,
    publicKey: publicKey(key, algo)
  });
  return out;
}
var attrIds = {
  commonName: '',
  countryName: '',
  stateOrProvinceName: '',
  localityName: '',
  organizationName: '',
  organizationalUnitName: '',
  subjectAltName: ''
}
function createInfo(info) {
  return csr.RelativeDistinguishedName.encode('der', Object.keys(info).map(function (name) {
    if (attrIds[name]) {
      return {
        type: attrIds[name],
        value: info[name]
      }
    }
  }).filter(function (item) {
    return item;
  }))
}
function publicKey() {

}
