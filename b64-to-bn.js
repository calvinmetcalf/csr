// from https://github.com/Brightspace/node-jwk-to-pem/blob/master/src/b64-to-bn.js
var BN = require('asn1.js').bignum;

module.exports = function base64ToBigNum(val, zero) {
  var buf = new Buffer(val, 'base64');
  var bn = val = new BN(buf, 10, 'be').iabs();
  if (zero) {
    buf.fill(0);
  }
  return bn;
};
