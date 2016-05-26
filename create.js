'use strict';
var csr = require('./csr');
var asn1 = require('asn1.js');
var EC = require('elliptic').ec;
var b64ToBn = require('./b64-to-bn');
var exp = new Uint8Array([1,0,1]);
var jwkToPem = require('jwk-to-pem');
var ECParameters = asn1.define('ECParameters', /* @this */ function() {
  this.choice({
    namedCurve: this.objid()
  });
});
var RSAPublicKey = asn1.define('RSAPublicKey', /* @this */ function() {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  );
});
var params = {
  'P-256': csr.AttributeType.encode([1, 2, 840, 10045, 3, 1, 7], 'pem', {
    label: 'EC PARAMETERS'
  }),
  'P-384': csr.AttributeType.encode([1, 3, 132, 0, 34], 'pem', {
    label: 'EC PARAMETERS'
  }),
  'P-521': csr.AttributeType.encode([1, 3, 132, 0, 35], 'pem', {
    label: 'EC PARAMETERS'
  })
}
var ecoids = {
  'P-256': [1, 2, 840, 10045, 3, 1, 7],
  'P-384': [1, 3, 132, 0, 34],
  'P-521': [1, 3, 132, 0, 35]
};
var curves = {
  'P-256': 'p256',
  'P-384': 'p384',
  'P-521': 'p521'
};
var hash = {
  'P-256': 'SHA-256',
  'P-384': 'SHA-384',
  'P-521': 'SHA-512'
}
function createSignable(info, key, algo) {
  var obj = {
    info: createInfo(info),
    version: 0,
    publicKey: publicKey(key, algo)
  };
  var der = csr.CertificationRequestInfo.encode(obj, 'der');
  return {
    json: obj,
    der: der
  };
}
function generateEcdsa(curve) {
  return global.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: curve
    },
    true,
    ['sign', 'verify']
  ).then(function (pair) {
    return global.crypto.subtle.exportKey('jwk', pair.privateKey).then(function (jwk) {
      return {
        pair: pair,
        jwk: jwk
      }
    });
  });
}
function generateRsa(len) {
  return global.crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: len,
    publicExponent: exp,
    hash: {name: 'SHA-256'}
  },
  true,
    ['sign', 'verify']
  ).then(function (pair) {
    return global.crypto.subtle.exportKey('jwk', pair.privateKey).then(function (jwk) {
      return {
        pair: pair,
        jwk: jwk
      }
    });
  });
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
  return Object.keys(info).map(function (name) {
    if (attrIds[name]) {
      var val = info[name].trim();
      if (name === 'subjectAltName' && !val) {
        return;
      }
      return [{
        type: attrIds[name],
        value: val
      }]
    }
  }).filter(function (item) {
    return item;
  });
}
function publicKey(key, algo) {
  if (algo === 'rsa') {
    return {
      subjectPublicKey: {
        unused: 0,
        data: RSAPublicKey.encode({
          modulus: b64ToBn(key.jwk.n, false),
          publicExponent: b64ToBn(key.jwk.e, false)
        }, 'der')
      },
      algorithm: {
        algorithm: '1.2.840.113549.1.1.1'.split('.')
      }
    }
  } else if (algo === 'ec') {
    var curveName = curves[key.jwk.crv];
    var curve = new EC(curveName);
    var k =  curve.keyPair({
      pub: {
        x: b64ToBn(key.jwk.x, false),
        y: b64ToBn(key.jwk.y, false)
      }
    });
    var subjectPublicKey = k.getPublic(false, 'hex');
    subjectPublicKey = new Buffer(subjectPublicKey, 'hex');
    subjectPublicKey = {
      unused: 0,
      data: subjectPublicKey
    };
    var parameters = ECParameters.encode({
      type: 'namedCurve',
      value: ecoids[key.jwk.crv]
    }, 'der');
    return {
      algorithm: {
        algorithm: [1, 2, 840, 10045, 2, 1],
        parameters: parameters
      },
      subjectPublicKey: subjectPublicKey
    }
  }
}
function createKey(id) {
  switch (id) {
  case '1':
    return generateEcdsa('P-256');
  case '4':
    return generateEcdsa('P-384');
  case '5':
    return generateEcdsa('P-521');
  case '2':
    return generateRsa(2048);
  case '3':
    return generateRsa(4096);
  }
}
function makeId(keyType) {
  switch (keyType) {
  case '2':
  case '3':
    return {
      parameters: null,
      algorithm: '1.2.840.113549.1.1.11'.split('.')
    };
  case '1':
    return {
      algorithm: '1.2.840.10045.4.3.2'.split('.')
    };
  case '4':
    return {
      algorithm: '1.2.840.10045.4.3.3'.split('.')
    };
  case '5':
    return {
      algorithm: '1.2.840.10045.4.3.4'.split('.')
    };
  }
}
module.exports = function (keyType, info) {
  return createKey(keyType).then(function (key) {
    var algo = 'ec';
    if (keyType === '2' || keyType === '3') {
      algo = 'rsa';
    }
    var signable = createSignable(info, key, algo);
    var signProm;
    if (algo === 'rsa') {
      signProm = global.crypto.subtle.sign({name: 'RSASSA-PKCS1-v1_5'}, key.pair.privateKey, signable.der)
    } else {
      signProm = global.crypto.subtle.sign({name: 'ECDSA', hash: {name: hash[key.jwk.crv]}}, key.pair.privateKey, signable.der);
    }
    return Promise.all([signProm.then(function (sig) {
      var method = algo === 'rsa' ? 'CertificationRequestRSA' : 'CertificationRequest';
      return csr[method].encode({
        certificationRequestInfo: signable.json,
        signature: {
          unused: 0,
          data: new Buffer(sig)
        },
        signatureAlgorithm: makeId(keyType)
      }, 'pem', {
        label: 'CERTIFICATE REQUEST'
      })
    }),
    Promise.resolve(jwkToPem(key.jwk, {
      private: true
    })).then(function (keyPem) {
      if (algo === 'rsa') {
        return keyPem
      }
      var param = params[key.jwk.crv];
      return param + '\n' + keyPem;
    })
  ]);
  });
}
