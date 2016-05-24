'use strict';
var csr = require('./csr');
var exp = new Uint8Array([1,0,1]);
function createSignable(info, key, algo) {
  var out = csr.CertificationRequestInfo.encode('der', {
    info: createInfo(info),
    version: 0,
    publicKey: publicKey(key, algo)
  });
  return out;
}
function generateEcdsa(curve) {
  return global.crypto.subtle.generateKey(
    {
        name: "ECDSA",
        namedCurve: curve,
    },
    true,
    ["sign", "verify"]
  ).then(function (pair) {
    return global.crypto.subtle.exportKey("jwk", pair.privateKey);
  });
}
function generateRsa(len) {
    return global.crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: len,
        publicExponent: exp,
        hash: {name: "SHA-256"},
    },
    true,
    ["sign", "verify"]
  ).then(function (pair) {
    return global.crypto.subtle.exportKey("jwk", pair.privateKey);
  }).then(function (a){console.log(a)});
}
var attrIds = {
  commonName: '2.5.4.3'.split('.'),
  countryName: '2.5.4.6'.split('.'),
  stateOrProvinceName: '2.5.4.8'.split('.'),
  localityName: '2.5.4.7'.split('.'),
  organizationName: '2.5.4.10'.split('.'),
  organizationalUnitName: '2.5.4.11'.split('.'),
  subjectAltName: '2.5.29.17'.split('.')
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
