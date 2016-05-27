(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (Buffer){
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

}).call(this,require("buffer").Buffer)

},{"asn1.js":6,"buffer":23}],2:[function(require,module,exports){
(function (global,Buffer){
'use strict';
var csr = require('./csr');
var asn1 = require('asn1.js');
var EC = require('elliptic').ec;
var b64ToBn = require('./b64-to-bn');
var exp = new Uint8Array([1,0,1]);
var jwkToPem = require('jwk-to-pem');
var der = require('./der');

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
    publicKey: publicKey(key, algo),
    attributes: []
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
        type: 'AlgorithmIdentifierRSA',
        value: {
          algorithm: '1.2.840.113549.1.1.1'.split('.'),
          parameters: null
        }
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
        type: 'AlgorithmIdentifier',
        value: {
          algorithm: [1, 2, 840, 10045, 2, 1],
          parameters: parameters
        }
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
      if (algo !== 'rsa') {
        sig = der.toDER(new Buffer(sig));
      } else {
        sig = new Buffer(sig);
      }
      return csr[method].encode({
        certificationRequestInfo: signable.json,
        signature: {
          unused: 0,
          data: sig
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

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {},require("buffer").Buffer)

},{"./b64-to-bn":1,"./csr":3,"./der":4,"asn1.js":6,"buffer":23,"elliptic":24,"jwk-to-pem":53}],3:[function(require,module,exports){
var asn1 = require('asn1.js');

var AlgorithmIdentifierRSA = exports.AlgorithmIdentifierRSA = asn1.define('AlgorithmIdentifierRSA', function() {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters').optional().null_()
  );
});
var AlgorithmIdentifier = exports.AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function() {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters').optional().any()
  );
});
var AlgoChoice =  asn1.define('AlgoChoice', function() {
  this.choice({
    AlgorithmIdentifier: this.use(AlgorithmIdentifier),
    AlgorithmIdentifierRSA: this.use(AlgorithmIdentifierRSA)
  });
});
var Version = exports.Version = asn1.define('Version', function() {
  this.int({
    0: 'v1',
    1: 'v2',
    2: 'v3'
  });
});
var Int = asn1.define('Int', function() {
  this.int();
});
var SubjectPublicKeyInfo = exports.SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function() {
  this.seq().obj(
    this.key('algorithm').use(AlgoChoice),
    this.key('subjectPublicKey').bitstr()
  );
});

var AttributeValue = asn1.define('AttributeValue', function() {
  this.utf8str();
});
var AttributeType = exports.AttributeType = asn1.define('AttributeType', function() {
  this.objid();
});
var AttributeTypeAndValue = asn1.define('AttributeTypeAndValue', function () {
  this.seq().obj(
    this.key('type').use(AttributeType),
    this.key('value').use(AttributeValue)
  );
})

var RelativeDistinguishedName = exports.RelativeDistinguishedName = asn1.define('RelativeDistinguishedName',function() {
  this.setof(AttributeTypeAndValue);
});
var SeqOfRelativeDistinguishedName = asn1.define('SeqOfRelativeDistinguishedName',function() {
  this.seqof(RelativeDistinguishedName);
});
var CertificationRequestInfo = exports.CertificationRequestInfo = asn1.define('CertificationRequestInfo', function() {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('info').use(SeqOfRelativeDistinguishedName),
    this.key('publicKey').use(SubjectPublicKeyInfo),
    this.key('attributes').seqof(Int).implicit(0).optional()
  );
});
exports.CertificationRequest = asn1.define('CertificationRequest', function() {
  this.seq().obj(
    this.key('certificationRequestInfo').use(CertificationRequestInfo),
    this.key('signatureAlgorithm').use(AlgorithmIdentifier),
    this.key('signature').bitstr()
  );
});
exports.CertificationRequestRSA = asn1.define('CertificationRequestRSA', function() {
  this.seq().obj(
    this.key('certificationRequestInfo').use(CertificationRequestInfo),
    this.key('signatureAlgorithm').use(AlgorithmIdentifierRSA),
    this.key('signature').bitstr()
  );
});

},{"asn1.js":6}],4:[function(require,module,exports){
(function (Buffer){
'use strict';
var assert = require('minimalistic-assert');

exports.fromDer = fromDer;
exports.toDER = toDER;

function toDER (input) {
  if (input.length % 2) {
    input = Buffer.concat([new Buffer([0]), input]);
  }
  var sliceLen = Math.floor(input.length / 2);
  var r = input.slice(0, sliceLen);
  var s = input.slice(sliceLen);

  // Pad values

  if (r[0] & 0x80) {
    r = Buffer.concat([new Buffer([0]), r]);
  }
  // Pad values
  if (s[0] & 0x80) {
    s = Buffer.concat([new Buffer([0]), s]);
  }
  if (!r[0] && !(r[1] & 0x80)) {
    r = r.slice(1);
  }
  if (!s[0] && !(s[1] & 0x80)) {
    s = s.slice(1);
  }
  var rarr = [0x02];
  constructLength(rarr, r.length);
  var sarr = [0x02];
  constructLength(sarr, s.length);
  var backHalf = Buffer.concat([new Buffer(rarr), r, new Buffer(sarr), s]);
  var head = [0x30];
  constructLength(head, backHalf.length);
  return Buffer.concat([new Buffer(head), backHalf]);
}
function constructLength(arr, len) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  var octets = 1 + (Math.log2(len) >> 3);
  arr.push(octets ^ 0x80);
  while (true) {
    if (octets === 1) {
      arr.push(len & 0xff);
      return;
    }
    octets--;
    arr.push(len >> (octets << 3));
  }
}
function fromDer(input, len) {
  var p = {};
  p.place = 0;
  assert.equal(input[p.place++], 0x30);
  getLength(input, p);
  assert.equal(input[p.place++], 0x02);
  var rlen = getLength(input, p);
  var r = input.slice(p.place, rlen + p.place);
  p.place += rlen;
  assert.equal(input[p.place++], 0x02);
  var slen = getLength(input, p);
  assert.equal(input.length, slen + p.place);
  var s = input.slice(p.place, slen + p.place);
  if (!r[0] && (r[1] & 0x80)) {
    r = r.slice(1);
  }
  if (!s[0] && (s[1] & 0x80)) {
    s = s.slice(1);
  }
  while (r.length < len) {
    r = Buffer.concat([new Buffer([0]), r]);
  }
  while (s.length < len) {
    s = Buffer.concat([new Buffer([0]), s]);
  }
  return Buffer.concat([r, s]);
}
function getLength(buf, p) {
  var initial = buf[p.place++];
  if (!(initial & 0x80)) {
    return initial;
  }
  var octetLen = initial & 0xf;
  var data = buf.readUIntBE(p.place, octetLen);
  p.place += octetLen;
  return data;
}

}).call(this,require("buffer").Buffer)

},{"buffer":23,"minimalistic-assert":55}],5:[function(require,module,exports){
(function (global){
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
  clearAll();
  makeCsr(keytype, obj).then(function (resp) {
    setCert(resp[0]);
    setKey(resp[1]);
  }).catch(function (e) {
    console.log(e);
  })
});
function clearAll() {
  var tag = document.createElement('span');
  var tag2 = document.createElement('span');
  certTag.replaceChild(tag, certTag.firstChild);
  keyTag.replaceChild(tag2, keyTag.firstChild);
}
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

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./create":2}],6:[function(require,module,exports){
var asn1 = exports;

asn1.bignum = require('bn.js');

asn1.define = require('./asn1/api').define;
asn1.base = require('./asn1/base');
asn1.constants = require('./asn1/constants');
asn1.decoders = require('./asn1/decoders');
asn1.encoders = require('./asn1/encoders');

},{"./asn1/api":7,"./asn1/base":9,"./asn1/constants":13,"./asn1/decoders":15,"./asn1/encoders":18,"bn.js":21}],7:[function(require,module,exports){
var asn1 = require('../asn1');
var inherits = require('inherits');

var api = exports;

api.define = function define(name, body) {
  return new Entity(name, body);
};

function Entity(name, body) {
  this.name = name;
  this.body = body;

  this.decoders = {};
  this.encoders = {};
};

Entity.prototype._createNamed = function createNamed(base) {
  var named;
  try {
    named = require('vm').runInThisContext(
      '(function ' + this.name + '(entity) {\n' +
      '  this._initNamed(entity);\n' +
      '})'
    );
  } catch (e) {
    named = function (entity) {
      this._initNamed(entity);
    };
  }
  inherits(named, base);
  named.prototype._initNamed = function initnamed(entity) {
    base.call(this, entity);
  };

  return new named(this);
};

Entity.prototype._getDecoder = function _getDecoder(enc) {
  enc = enc || 'der';
  // Lazily create decoder
  if (!this.decoders.hasOwnProperty(enc))
    this.decoders[enc] = this._createNamed(asn1.decoders[enc]);
  return this.decoders[enc];
};

Entity.prototype.decode = function decode(data, enc, options) {
  return this._getDecoder(enc).decode(data, options);
};

Entity.prototype._getEncoder = function _getEncoder(enc) {
  enc = enc || 'der';
  // Lazily create encoder
  if (!this.encoders.hasOwnProperty(enc))
    this.encoders[enc] = this._createNamed(asn1.encoders[enc]);
  return this.encoders[enc];
};

Entity.prototype.encode = function encode(data, enc, /* internal */ reporter) {
  return this._getEncoder(enc).encode(data, reporter);
};

},{"../asn1":6,"inherits":49,"vm":56}],8:[function(require,module,exports){
var inherits = require('inherits');
var Reporter = require('../base').Reporter;
var Buffer = require('buffer').Buffer;

function DecoderBuffer(base, options) {
  Reporter.call(this, options);
  if (!Buffer.isBuffer(base)) {
    this.error('Input not Buffer');
    return;
  }

  this.base = base;
  this.offset = 0;
  this.length = base.length;
}
inherits(DecoderBuffer, Reporter);
exports.DecoderBuffer = DecoderBuffer;

DecoderBuffer.prototype.save = function save() {
  return { offset: this.offset, reporter: Reporter.prototype.save.call(this) };
};

DecoderBuffer.prototype.restore = function restore(save) {
  // Return skipped data
  var res = new DecoderBuffer(this.base);
  res.offset = save.offset;
  res.length = this.offset;

  this.offset = save.offset;
  Reporter.prototype.restore.call(this, save.reporter);

  return res;
};

DecoderBuffer.prototype.isEmpty = function isEmpty() {
  return this.offset === this.length;
};

DecoderBuffer.prototype.readUInt8 = function readUInt8(fail) {
  if (this.offset + 1 <= this.length)
    return this.base.readUInt8(this.offset++, true);
  else
    return this.error(fail || 'DecoderBuffer overrun');
}

DecoderBuffer.prototype.skip = function skip(bytes, fail) {
  if (!(this.offset + bytes <= this.length))
    return this.error(fail || 'DecoderBuffer overrun');

  var res = new DecoderBuffer(this.base);

  // Share reporter state
  res._reporterState = this._reporterState;

  res.offset = this.offset;
  res.length = this.offset + bytes;
  this.offset += bytes;
  return res;
}

DecoderBuffer.prototype.raw = function raw(save) {
  return this.base.slice(save ? save.offset : this.offset, this.length);
}

function EncoderBuffer(value, reporter) {
  if (Array.isArray(value)) {
    this.length = 0;
    this.value = value.map(function(item) {
      if (!(item instanceof EncoderBuffer))
        item = new EncoderBuffer(item, reporter);
      this.length += item.length;
      return item;
    }, this);
  } else if (typeof value === 'number') {
    if (!(0 <= value && value <= 0xff))
      return reporter.error('non-byte EncoderBuffer value');
    this.value = value;
    this.length = 1;
  } else if (typeof value === 'string') {
    this.value = value;
    this.length = Buffer.byteLength(value);
  } else if (Buffer.isBuffer(value)) {
    this.value = value;
    this.length = value.length;
  } else {
    return reporter.error('Unsupported type: ' + typeof value);
  }
}
exports.EncoderBuffer = EncoderBuffer;

EncoderBuffer.prototype.join = function join(out, offset) {
  if (!out)
    out = new Buffer(this.length);
  if (!offset)
    offset = 0;

  if (this.length === 0)
    return out;

  if (Array.isArray(this.value)) {
    this.value.forEach(function(item) {
      item.join(out, offset);
      offset += item.length;
    });
  } else {
    if (typeof this.value === 'number')
      out[offset] = this.value;
    else if (typeof this.value === 'string')
      out.write(this.value, offset);
    else if (Buffer.isBuffer(this.value))
      this.value.copy(out, offset);
    offset += this.length;
  }

  return out;
};

},{"../base":9,"buffer":23,"inherits":49}],9:[function(require,module,exports){
var base = exports;

base.Reporter = require('./reporter').Reporter;
base.DecoderBuffer = require('./buffer').DecoderBuffer;
base.EncoderBuffer = require('./buffer').EncoderBuffer;
base.Node = require('./node');

},{"./buffer":8,"./node":10,"./reporter":11}],10:[function(require,module,exports){
var Reporter = require('../base').Reporter;
var EncoderBuffer = require('../base').EncoderBuffer;
var DecoderBuffer = require('../base').DecoderBuffer;
var assert = require('minimalistic-assert');

// Supported tags
var tags = [
  'seq', 'seqof', 'set', 'setof', 'objid', 'bool',
  'gentime', 'utctime', 'null_', 'enum', 'int',
  'bitstr', 'bmpstr', 'charstr', 'genstr', 'graphstr', 'ia5str', 'iso646str',
  'numstr', 'octstr', 'printstr', 't61str', 'unistr', 'utf8str', 'videostr'
];

// Public methods list
var methods = [
  'key', 'obj', 'use', 'optional', 'explicit', 'implicit', 'def', 'choice',
  'any', 'contains'
].concat(tags);

// Overrided methods list
var overrided = [
  '_peekTag', '_decodeTag', '_use',
  '_decodeStr', '_decodeObjid', '_decodeTime',
  '_decodeNull', '_decodeInt', '_decodeBool', '_decodeList',

  '_encodeComposite', '_encodeStr', '_encodeObjid', '_encodeTime',
  '_encodeNull', '_encodeInt', '_encodeBool'
];

function Node(enc, parent) {
  var state = {};
  this._baseState = state;

  state.enc = enc;

  state.parent = parent || null;
  state.children = null;

  // State
  state.tag = null;
  state.args = null;
  state.reverseArgs = null;
  state.choice = null;
  state.optional = false;
  state.any = false;
  state.obj = false;
  state.use = null;
  state.useDecoder = null;
  state.key = null;
  state['default'] = null;
  state.explicit = null;
  state.implicit = null;
  state.contains = null;

  // Should create new instance on each method
  if (!state.parent) {
    state.children = [];
    this._wrap();
  }
}
module.exports = Node;

var stateProps = [
  'enc', 'parent', 'children', 'tag', 'args', 'reverseArgs', 'choice',
  'optional', 'any', 'obj', 'use', 'alteredUse', 'key', 'default', 'explicit',
  'implicit'
];

Node.prototype.clone = function clone() {
  var state = this._baseState;
  var cstate = {};
  stateProps.forEach(function(prop) {
    cstate[prop] = state[prop];
  });
  var res = new this.constructor(cstate.parent);
  res._baseState = cstate;
  return res;
};

Node.prototype._wrap = function wrap() {
  var state = this._baseState;
  methods.forEach(function(method) {
    this[method] = function _wrappedMethod() {
      var clone = new this.constructor(this);
      state.children.push(clone);
      return clone[method].apply(clone, arguments);
    };
  }, this);
};

Node.prototype._init = function init(body) {
  var state = this._baseState;

  assert(state.parent === null);
  body.call(this);

  // Filter children
  state.children = state.children.filter(function(child) {
    return child._baseState.parent === this;
  }, this);
  assert.equal(state.children.length, 1, 'Root node can have only one child');
};

Node.prototype._useArgs = function useArgs(args) {
  var state = this._baseState;

  // Filter children and args
  var children = args.filter(function(arg) {
    return arg instanceof this.constructor;
  }, this);
  args = args.filter(function(arg) {
    return !(arg instanceof this.constructor);
  }, this);

  if (children.length !== 0) {
    assert(state.children === null);
    state.children = children;

    // Replace parent to maintain backward link
    children.forEach(function(child) {
      child._baseState.parent = this;
    }, this);
  }
  if (args.length !== 0) {
    assert(state.args === null);
    state.args = args;
    state.reverseArgs = args.map(function(arg) {
      if (typeof arg !== 'object' || arg.constructor !== Object)
        return arg;

      var res = {};
      Object.keys(arg).forEach(function(key) {
        if (key == (key | 0))
          key |= 0;
        var value = arg[key];
        res[value] = key;
      });
      return res;
    });
  }
};

//
// Overrided methods
//

overrided.forEach(function(method) {
  Node.prototype[method] = function _overrided() {
    var state = this._baseState;
    throw new Error(method + ' not implemented for encoding: ' + state.enc);
  };
});

//
// Public methods
//

tags.forEach(function(tag) {
  Node.prototype[tag] = function _tagMethod() {
    var state = this._baseState;
    var args = Array.prototype.slice.call(arguments);

    assert(state.tag === null);
    state.tag = tag;

    this._useArgs(args);

    return this;
  };
});

Node.prototype.use = function use(item) {
  var state = this._baseState;

  assert(state.use === null);
  state.use = item;

  return this;
};

Node.prototype.optional = function optional() {
  var state = this._baseState;

  state.optional = true;

  return this;
};

Node.prototype.def = function def(val) {
  var state = this._baseState;

  assert(state['default'] === null);
  state['default'] = val;
  state.optional = true;

  return this;
};

Node.prototype.explicit = function explicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.explicit = num;

  return this;
};

Node.prototype.implicit = function implicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.implicit = num;

  return this;
};

Node.prototype.obj = function obj() {
  var state = this._baseState;
  var args = Array.prototype.slice.call(arguments);

  state.obj = true;

  if (args.length !== 0)
    this._useArgs(args);

  return this;
};

Node.prototype.key = function key(newKey) {
  var state = this._baseState;

  assert(state.key === null);
  state.key = newKey;

  return this;
};

Node.prototype.any = function any() {
  var state = this._baseState;

  state.any = true;

  return this;
};

Node.prototype.choice = function choice(obj) {
  var state = this._baseState;

  assert(state.choice === null);
  state.choice = obj;
  this._useArgs(Object.keys(obj).map(function(key) {
    return obj[key];
  }));

  return this;
};

Node.prototype.contains = function contains(item) {
  var state = this._baseState;

  assert(state.use === null);
  state.contains = item;

  return this;
};

//
// Decoding
//

Node.prototype._decode = function decode(input) {
  var state = this._baseState;

  // Decode root node
  if (state.parent === null)
    return input.wrapResult(state.children[0]._decode(input));

  var result = state['default'];
  var present = true;

  var prevKey;
  if (state.key !== null)
    prevKey = input.enterKey(state.key);

  // Check if tag is there
  if (state.optional) {
    var tag = null;
    if (state.explicit !== null)
      tag = state.explicit;
    else if (state.implicit !== null)
      tag = state.implicit;
    else if (state.tag !== null)
      tag = state.tag;

    if (tag === null && !state.any) {
      // Trial and Error
      var save = input.save();
      try {
        if (state.choice === null)
          this._decodeGeneric(state.tag, input);
        else
          this._decodeChoice(input);
        present = true;
      } catch (e) {
        present = false;
      }
      input.restore(save);
    } else {
      present = this._peekTag(input, tag, state.any);

      if (input.isError(present))
        return present;
    }
  }

  // Push object on stack
  var prevObj;
  if (state.obj && present)
    prevObj = input.enterObject();

  if (present) {
    // Unwrap explicit values
    if (state.explicit !== null) {
      var explicit = this._decodeTag(input, state.explicit);
      if (input.isError(explicit))
        return explicit;
      input = explicit;
    }

    // Unwrap implicit and normal values
    if (state.use === null && state.choice === null) {
      if (state.any)
        var save = input.save();
      var body = this._decodeTag(
        input,
        state.implicit !== null ? state.implicit : state.tag,
        state.any
      );
      if (input.isError(body))
        return body;

      if (state.any)
        result = input.raw(save);
      else
        input = body;
    }

    // Select proper method for tag
    if (state.any)
      result = result;
    else if (state.choice === null)
      result = this._decodeGeneric(state.tag, input);
    else
      result = this._decodeChoice(input);

    if (input.isError(result))
      return result;

    // Decode children
    if (!state.any && state.choice === null && state.children !== null) {
      state.children.forEach(function decodeChildren(child) {
        // NOTE: We are ignoring errors here, to let parser continue with other
        // parts of encoded data
        child._decode(input);
      });
    }

    // Decode contained/encoded by schema, only in bit or octet strings
    if (state.contains && (state.tag === 'octstr' || state.tag === 'bitstr')) {
      var data = new DecoderBuffer(result);
      result = this._getUse(state.contains, input._reporterState.obj)._decode(data);
    }
  }

  // Pop object
  if (state.obj && present)
    result = input.leaveObject(prevObj);

  // Set key
  if (state.key !== null && (result !== null || present === true))
    input.leaveKey(prevKey, state.key, result);

  return result;
};

Node.prototype._decodeGeneric = function decodeGeneric(tag, input) {
  var state = this._baseState;

  if (tag === 'seq' || tag === 'set')
    return null;
  if (tag === 'seqof' || tag === 'setof')
    return this._decodeList(input, tag, state.args[0]);
  else if (/str$/.test(tag))
    return this._decodeStr(input, tag);
  else if (tag === 'objid' && state.args)
    return this._decodeObjid(input, state.args[0], state.args[1]);
  else if (tag === 'objid')
    return this._decodeObjid(input, null, null);
  else if (tag === 'gentime' || tag === 'utctime')
    return this._decodeTime(input, tag);
  else if (tag === 'null_')
    return this._decodeNull(input);
  else if (tag === 'bool')
    return this._decodeBool(input);
  else if (tag === 'int' || tag === 'enum')
    return this._decodeInt(input, state.args && state.args[0]);
  else if (state.use !== null)
    return this._getUse(state.use, input._reporterState.obj)._decode(input);
  else
    return input.error('unknown tag: ' + tag);
};

Node.prototype._getUse = function _getUse(entity, obj) {

  var state = this._baseState;
  // Create altered use decoder if implicit is set
  state.useDecoder = this._use(entity, obj);
  assert(state.useDecoder._baseState.parent === null);
  state.useDecoder = state.useDecoder._baseState.children[0];
  if (state.implicit !== state.useDecoder._baseState.implicit) {
    state.useDecoder = state.useDecoder.clone();
    state.useDecoder._baseState.implicit = state.implicit;
  }
  return state.useDecoder;
};

Node.prototype._decodeChoice = function decodeChoice(input) {
  var state = this._baseState;
  var result = null;
  var match = false;

  Object.keys(state.choice).some(function(key) {
    var save = input.save();
    var node = state.choice[key];
    try {
      var value = node._decode(input);
      if (input.isError(value))
        return false;

      result = { type: key, value: value };
      match = true;
    } catch (e) {
      input.restore(save);
      return false;
    }
    return true;
  }, this);

  if (!match)
    return input.error('Choice not matched');

  return result;
};

//
// Encoding
//

Node.prototype._createEncoderBuffer = function createEncoderBuffer(data) {
  return new EncoderBuffer(data, this.reporter);
};

Node.prototype._encode = function encode(data, reporter, parent) {
  var state = this._baseState;
  if (state['default'] !== null && state['default'] === data)
    return;

  var result = this._encodeValue(data, reporter, parent);
  if (result === undefined)
    return;

  if (this._skipDefault(result, reporter, parent))
    return;

  return result;
};

Node.prototype._encodeValue = function encode(data, reporter, parent) {
  var state = this._baseState;

  // Decode root node
  if (state.parent === null)
    return state.children[0]._encode(data, reporter || new Reporter());

  var result = null;

  // Set reporter to share it with a child class
  this.reporter = reporter;

  // Check if data is there
  if (state.optional && data === undefined) {
    if (state['default'] !== null)
      data = state['default']
    else
      return;
  }

  // Encode children first
  var content = null;
  var primitive = false;
  if (state.any) {
    // Anything that was given is translated to buffer
    result = this._createEncoderBuffer(data);
  } else if (state.choice) {
    result = this._encodeChoice(data, reporter);
  } else if (state.contains) {
    content = this._getUse(state.contains, parent)._encode(data, reporter);
    primitive = true;
  } else if (state.children) {
    content = state.children.map(function(child) {
      if (child._baseState.tag === 'null_')
        return child._encode(null, reporter, data);

      if (child._baseState.key === null)
        return reporter.error('Child should have a key');
      var prevKey = reporter.enterKey(child._baseState.key);

      if (typeof data !== 'object')
        return reporter.error('Child expected, but input is not object');

      var res = child._encode(data[child._baseState.key], reporter, data);
      reporter.leaveKey(prevKey);

      return res;
    }, this).filter(function(child) {
      return child;
    });
    content = this._createEncoderBuffer(content);
  } else {
    if (state.tag === 'seqof' || state.tag === 'setof') {
      // TODO(indutny): this should be thrown on DSL level
      if (!(state.args && state.args.length === 1))
        return reporter.error('Too many args for : ' + state.tag);

      if (!Array.isArray(data))
        return reporter.error('seqof/setof, but data is not Array');

      var child = this.clone();
      child._baseState.implicit = null;
      content = this._createEncoderBuffer(data.map(function(item) {
        var state = this._baseState;

        return this._getUse(state.args[0], data)._encode(item, reporter);
      }, child));
    } else if (state.use !== null) {
      result = this._getUse(state.use, parent)._encode(data, reporter);
    } else {
      content = this._encodePrimitive(state.tag, data);
      primitive = true;
    }
  }

  // Encode data itself
  var result;
  if (!state.any && state.choice === null) {
    var tag = state.implicit !== null ? state.implicit : state.tag;
    var cls = state.implicit === null ? 'universal' : 'context';

    if (tag === null) {
      if (state.use === null)
        reporter.error('Tag could be ommited only for .use()');
    } else {
      if (state.use === null)
        result = this._encodeComposite(tag, primitive, cls, content);
    }
  }

  // Wrap in explicit
  if (state.explicit !== null)
    result = this._encodeComposite(state.explicit, false, 'context', result);

  return result;
};

Node.prototype._encodeChoice = function encodeChoice(data, reporter) {
  var state = this._baseState;

  var node = state.choice[data.type];
  if (!node) {
    assert(
        false,
        data.type + ' not found in ' +
            JSON.stringify(Object.keys(state.choice)));
  }
  return node._encode(data.value, reporter);
};

Node.prototype._encodePrimitive = function encodePrimitive(tag, data) {
  var state = this._baseState;

  if (/str$/.test(tag))
    return this._encodeStr(data, tag);
  else if (tag === 'objid' && state.args)
    return this._encodeObjid(data, state.reverseArgs[0], state.args[1]);
  else if (tag === 'objid')
    return this._encodeObjid(data, null, null);
  else if (tag === 'gentime' || tag === 'utctime')
    return this._encodeTime(data, tag);
  else if (tag === 'null_')
    return this._encodeNull();
  else if (tag === 'int' || tag === 'enum')
    return this._encodeInt(data, state.args && state.reverseArgs[0]);
  else if (tag === 'bool')
    return this._encodeBool(data);
  else
    throw new Error('Unsupported tag: ' + tag);
};

Node.prototype._isNumstr = function isNumstr(str) {
  return /^[0-9 ]*$/.test(str);
};

Node.prototype._isPrintstr = function isPrintstr(str) {
  return /^[A-Za-z0-9 '\(\)\+,\-\.\/:=\?]*$/.test(str);
};

},{"../base":9,"minimalistic-assert":55}],11:[function(require,module,exports){
var inherits = require('inherits');

function Reporter(options) {
  this._reporterState = {
    obj: null,
    path: [],
    options: options || {},
    errors: []
  };
}
exports.Reporter = Reporter;

Reporter.prototype.isError = function isError(obj) {
  return obj instanceof ReporterError;
};

Reporter.prototype.save = function save() {
  var state = this._reporterState;

  return { obj: state.obj, pathLen: state.path.length };
};

Reporter.prototype.restore = function restore(data) {
  var state = this._reporterState;

  state.obj = data.obj;
  state.path = state.path.slice(0, data.pathLen);
};

Reporter.prototype.enterKey = function enterKey(key) {
  return this._reporterState.path.push(key);
};

Reporter.prototype.leaveKey = function leaveKey(index, key, value) {
  var state = this._reporterState;

  state.path = state.path.slice(0, index - 1);
  if (state.obj !== null)
    state.obj[key] = value;
};

Reporter.prototype.enterObject = function enterObject() {
  var state = this._reporterState;

  var prev = state.obj;
  state.obj = {};
  return prev;
};

Reporter.prototype.leaveObject = function leaveObject(prev) {
  var state = this._reporterState;

  var now = state.obj;
  state.obj = prev;
  return now;
};

Reporter.prototype.error = function error(msg) {
  var err;
  var state = this._reporterState;

  var inherited = msg instanceof ReporterError;
  if (inherited) {
    err = msg;
  } else {
    err = new ReporterError(state.path.map(function(elem) {
      return '[' + JSON.stringify(elem) + ']';
    }).join(''), msg.message || msg, msg.stack);
  }

  if (!state.options.partial)
    throw err;

  if (!inherited)
    state.errors.push(err);

  return err;
};

Reporter.prototype.wrapResult = function wrapResult(result) {
  var state = this._reporterState;
  if (!state.options.partial)
    return result;

  return {
    result: this.isError(result) ? null : result,
    errors: state.errors
  };
};

function ReporterError(path, msg) {
  this.path = path;
  this.rethrow(msg);
};
inherits(ReporterError, Error);

ReporterError.prototype.rethrow = function rethrow(msg) {
  this.message = msg + ' at: ' + (this.path || '(shallow)');
  Error.captureStackTrace(this, ReporterError);

  return this;
};

},{"inherits":49}],12:[function(require,module,exports){
var constants = require('../constants');

exports.tagClass = {
  0: 'universal',
  1: 'application',
  2: 'context',
  3: 'private'
};
exports.tagClassByName = constants._reverse(exports.tagClass);

exports.tag = {
  0x00: 'end',
  0x01: 'bool',
  0x02: 'int',
  0x03: 'bitstr',
  0x04: 'octstr',
  0x05: 'null_',
  0x06: 'objid',
  0x07: 'objDesc',
  0x08: 'external',
  0x09: 'real',
  0x0a: 'enum',
  0x0b: 'embed',
  0x0c: 'utf8str',
  0x0d: 'relativeOid',
  0x10: 'seq',
  0x11: 'set',
  0x12: 'numstr',
  0x13: 'printstr',
  0x14: 't61str',
  0x15: 'videostr',
  0x16: 'ia5str',
  0x17: 'utctime',
  0x18: 'gentime',
  0x19: 'graphstr',
  0x1a: 'iso646str',
  0x1b: 'genstr',
  0x1c: 'unistr',
  0x1d: 'charstr',
  0x1e: 'bmpstr'
};
exports.tagByName = constants._reverse(exports.tag);

},{"../constants":13}],13:[function(require,module,exports){
var constants = exports;

// Helper
constants._reverse = function reverse(map) {
  var res = {};

  Object.keys(map).forEach(function(key) {
    // Convert key to integer if it is stringified
    if ((key | 0) == key)
      key = key | 0;

    var value = map[key];
    res[value] = key;
  });

  return res;
};

constants.der = require('./der');

},{"./der":12}],14:[function(require,module,exports){
var inherits = require('inherits');

var asn1 = require('../../asn1');
var base = asn1.base;
var bignum = asn1.bignum;

// Import DER constants
var der = asn1.constants.der;

function DERDecoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new DERNode();
  this.tree._init(entity.body);
};
module.exports = DERDecoder;

DERDecoder.prototype.decode = function decode(data, options) {
  if (!(data instanceof base.DecoderBuffer))
    data = new base.DecoderBuffer(data, options);

  return this.tree._decode(data, options);
};

// Tree methods

function DERNode(parent) {
  base.Node.call(this, 'der', parent);
}
inherits(DERNode, base.Node);

DERNode.prototype._peekTag = function peekTag(buffer, tag, any) {
  if (buffer.isEmpty())
    return false;

  var state = buffer.save();
  var decodedTag = derDecodeTag(buffer, 'Failed to peek tag: "' + tag + '"');
  if (buffer.isError(decodedTag))
    return decodedTag;

  buffer.restore(state);

  return decodedTag.tag === tag || decodedTag.tagStr === tag ||
    (decodedTag.tagStr + 'of') === tag || any;
};

DERNode.prototype._decodeTag = function decodeTag(buffer, tag, any) {
  var decodedTag = derDecodeTag(buffer,
                                'Failed to decode tag of "' + tag + '"');
  if (buffer.isError(decodedTag))
    return decodedTag;

  var len = derDecodeLen(buffer,
                         decodedTag.primitive,
                         'Failed to get length of "' + tag + '"');

  // Failure
  if (buffer.isError(len))
    return len;

  if (!any &&
      decodedTag.tag !== tag &&
      decodedTag.tagStr !== tag &&
      decodedTag.tagStr + 'of' !== tag) {
    return buffer.error('Failed to match tag: "' + tag + '"');
  }

  if (decodedTag.primitive || len !== null)
    return buffer.skip(len, 'Failed to match body of: "' + tag + '"');

  // Indefinite length... find END tag
  var state = buffer.save();
  var res = this._skipUntilEnd(
      buffer,
      'Failed to skip indefinite length body: "' + this.tag + '"');
  if (buffer.isError(res))
    return res;

  len = buffer.offset - state.offset;
  buffer.restore(state);
  return buffer.skip(len, 'Failed to match body of: "' + tag + '"');
};

DERNode.prototype._skipUntilEnd = function skipUntilEnd(buffer, fail) {
  while (true) {
    var tag = derDecodeTag(buffer, fail);
    if (buffer.isError(tag))
      return tag;
    var len = derDecodeLen(buffer, tag.primitive, fail);
    if (buffer.isError(len))
      return len;

    var res;
    if (tag.primitive || len !== null)
      res = buffer.skip(len)
    else
      res = this._skipUntilEnd(buffer, fail);

    // Failure
    if (buffer.isError(res))
      return res;

    if (tag.tagStr === 'end')
      break;
  }
};

DERNode.prototype._decodeList = function decodeList(buffer, tag, decoder) {
  var result = [];
  while (!buffer.isEmpty()) {
    var possibleEnd = this._peekTag(buffer, 'end');
    if (buffer.isError(possibleEnd))
      return possibleEnd;

    var res = decoder.decode(buffer, 'der');
    if (buffer.isError(res) && possibleEnd)
      break;
    result.push(res);
  }
  return result;
};

DERNode.prototype._decodeStr = function decodeStr(buffer, tag) {
  if (tag === 'bitstr') {
    var unused = buffer.readUInt8();
    if (buffer.isError(unused))
      return unused;
    return { unused: unused, data: buffer.raw() };
  } else if (tag === 'bmpstr') {
    var raw = buffer.raw();
    if (raw.length % 2 === 1)
      return buffer.error('Decoding of string type: bmpstr length mismatch');

    var str = '';
    for (var i = 0; i < raw.length / 2; i++) {
      str += String.fromCharCode(raw.readUInt16BE(i * 2));
    }
    return str;
  } else if (tag === 'numstr') {
    var numstr = buffer.raw().toString('ascii');
    if (!this._isNumstr(numstr)) {
      return buffer.error('Decoding of string type: ' +
                          'numstr unsupported characters');
    }
    return numstr;
  } else if (tag === 'octstr') {
    return buffer.raw();
  } else if (tag === 'printstr') {
    var printstr = buffer.raw().toString('ascii');
    if (!this._isPrintstr(printstr)) {
      return buffer.error('Decoding of string type: ' +
                          'printstr unsupported characters');
    }
    return printstr;
  } else if (/str$/.test(tag)) {
    return buffer.raw().toString();
  } else {
    return buffer.error('Decoding of string type: ' + tag + ' unsupported');
  }
};

DERNode.prototype._decodeObjid = function decodeObjid(buffer, values, relative) {
  var result;
  var identifiers = [];
  var ident = 0;
  while (!buffer.isEmpty()) {
    var subident = buffer.readUInt8();
    ident <<= 7;
    ident |= subident & 0x7f;
    if ((subident & 0x80) === 0) {
      identifiers.push(ident);
      ident = 0;
    }
  }
  if (subident & 0x80)
    identifiers.push(ident);

  var first = (identifiers[0] / 40) | 0;
  var second = identifiers[0] % 40;

  if (relative)
    result = identifiers;
  else
    result = [first, second].concat(identifiers.slice(1));

  if (values) {
    var tmp = values[result.join(' ')];
    if (tmp === undefined)
      tmp = values[result.join('.')];
    if (tmp !== undefined)
      result = tmp;
  }

  return result;
};

DERNode.prototype._decodeTime = function decodeTime(buffer, tag) {
  var str = buffer.raw().toString();
  if (tag === 'gentime') {
    var year = str.slice(0, 4) | 0;
    var mon = str.slice(4, 6) | 0;
    var day = str.slice(6, 8) | 0;
    var hour = str.slice(8, 10) | 0;
    var min = str.slice(10, 12) | 0;
    var sec = str.slice(12, 14) | 0;
  } else if (tag === 'utctime') {
    var year = str.slice(0, 2) | 0;
    var mon = str.slice(2, 4) | 0;
    var day = str.slice(4, 6) | 0;
    var hour = str.slice(6, 8) | 0;
    var min = str.slice(8, 10) | 0;
    var sec = str.slice(10, 12) | 0;
    if (year < 70)
      year = 2000 + year;
    else
      year = 1900 + year;
  } else {
    return buffer.error('Decoding ' + tag + ' time is not supported yet');
  }

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0);
};

DERNode.prototype._decodeNull = function decodeNull(buffer) {
  return null;
};

DERNode.prototype._decodeBool = function decodeBool(buffer) {
  var res = buffer.readUInt8();
  if (buffer.isError(res))
    return res;
  else
    return res !== 0;
};

DERNode.prototype._decodeInt = function decodeInt(buffer, values) {
  // Bigint, return as it is (assume big endian)
  var raw = buffer.raw();
  var res = new bignum(raw);

  if (values)
    res = values[res.toString(10)] || res;

  return res;
};

DERNode.prototype._use = function use(entity, obj) {
  if (typeof entity === 'function')
    entity = entity(obj);
  return entity._getDecoder('der').tree;
};

// Utility methods

function derDecodeTag(buf, fail) {
  var tag = buf.readUInt8(fail);
  if (buf.isError(tag))
    return tag;

  var cls = der.tagClass[tag >> 6];
  var primitive = (tag & 0x20) === 0;

  // Multi-octet tag - load
  if ((tag & 0x1f) === 0x1f) {
    var oct = tag;
    tag = 0;
    while ((oct & 0x80) === 0x80) {
      oct = buf.readUInt8(fail);
      if (buf.isError(oct))
        return oct;

      tag <<= 7;
      tag |= oct & 0x7f;
    }
  } else {
    tag &= 0x1f;
  }
  var tagStr = der.tag[tag];

  return {
    cls: cls,
    primitive: primitive,
    tag: tag,
    tagStr: tagStr
  };
}

function derDecodeLen(buf, primitive, fail) {
  var len = buf.readUInt8(fail);
  if (buf.isError(len))
    return len;

  // Indefinite form
  if (!primitive && len === 0x80)
    return null;

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len;
  }

  // Long form
  var num = len & 0x7f;
  if (num >= 4)
    return buf.error('length octect is too long');

  len = 0;
  for (var i = 0; i < num; i++) {
    len <<= 8;
    var j = buf.readUInt8(fail);
    if (buf.isError(j))
      return j;
    len |= j;
  }

  return len;
}

},{"../../asn1":6,"inherits":49}],15:[function(require,module,exports){
var decoders = exports;

decoders.der = require('./der');
decoders.pem = require('./pem');

},{"./der":14,"./pem":16}],16:[function(require,module,exports){
var inherits = require('inherits');
var Buffer = require('buffer').Buffer;

var DERDecoder = require('./der');

function PEMDecoder(entity) {
  DERDecoder.call(this, entity);
  this.enc = 'pem';
};
inherits(PEMDecoder, DERDecoder);
module.exports = PEMDecoder;

PEMDecoder.prototype.decode = function decode(data, options) {
  var lines = data.toString().split(/[\r\n]+/g);

  var label = options.label.toUpperCase();

  var re = /^-----(BEGIN|END) ([^-]+)-----$/;
  var start = -1;
  var end = -1;
  for (var i = 0; i < lines.length; i++) {
    var match = lines[i].match(re);
    if (match === null)
      continue;

    if (match[2] !== label)
      continue;

    if (start === -1) {
      if (match[1] !== 'BEGIN')
        break;
      start = i;
    } else {
      if (match[1] !== 'END')
        break;
      end = i;
      break;
    }
  }
  if (start === -1 || end === -1)
    throw new Error('PEM section not found for: ' + label);

  var base64 = lines.slice(start + 1, end).join('');
  // Remove excessive symbols
  base64.replace(/[^a-z0-9\+\/=]+/gi, '');

  var input = new Buffer(base64, 'base64');
  return DERDecoder.prototype.decode.call(this, input, options);
};

},{"./der":14,"buffer":23,"inherits":49}],17:[function(require,module,exports){
var inherits = require('inherits');
var Buffer = require('buffer').Buffer;

var asn1 = require('../../asn1');
var base = asn1.base;

// Import DER constants
var der = asn1.constants.der;

function DEREncoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new DERNode();
  this.tree._init(entity.body);
};
module.exports = DEREncoder;

DEREncoder.prototype.encode = function encode(data, reporter) {
  return this.tree._encode(data, reporter).join();
};

// Tree methods

function DERNode(parent) {
  base.Node.call(this, 'der', parent);
}
inherits(DERNode, base.Node);

DERNode.prototype._encodeComposite = function encodeComposite(tag,
                                                              primitive,
                                                              cls,
                                                              content) {
  var encodedTag = encodeTag(tag, primitive, cls, this.reporter);

  // Short form
  if (content.length < 0x80) {
    var header = new Buffer(2);
    header[0] = encodedTag;
    header[1] = content.length;
    return this._createEncoderBuffer([ header, content ]);
  }

  // Long form
  // Count octets required to store length
  var lenOctets = 1;
  for (var i = content.length; i >= 0x100; i >>= 8)
    lenOctets++;

  var header = new Buffer(1 + 1 + lenOctets);
  header[0] = encodedTag;
  header[1] = 0x80 | lenOctets;

  for (var i = 1 + lenOctets, j = content.length; j > 0; i--, j >>= 8)
    header[i] = j & 0xff;

  return this._createEncoderBuffer([ header, content ]);
};

DERNode.prototype._encodeStr = function encodeStr(str, tag) {
  if (tag === 'bitstr') {
    return this._createEncoderBuffer([ str.unused | 0, str.data ]);
  } else if (tag === 'bmpstr') {
    var buf = new Buffer(str.length * 2);
    for (var i = 0; i < str.length; i++) {
      buf.writeUInt16BE(str.charCodeAt(i), i * 2);
    }
    return this._createEncoderBuffer(buf);
  } else if (tag === 'numstr') {
    if (!this._isNumstr(str)) {
      return this.reporter.error('Encoding of string type: numstr supports ' +
                                 'only digits and space');
    }
    return this._createEncoderBuffer(str);
  } else if (tag === 'printstr') {
    if (!this._isPrintstr(str)) {
      return this.reporter.error('Encoding of string type: printstr supports ' +
                                 'only latin upper and lower case letters, ' +
                                 'digits, space, apostrophe, left and rigth ' +
                                 'parenthesis, plus sign, comma, hyphen, ' +
                                 'dot, slash, colon, equal sign, ' +
                                 'question mark');
    }
    return this._createEncoderBuffer(str);
  } else if (/str$/.test(tag)) {
    return this._createEncoderBuffer(str);
  } else {
    return this.reporter.error('Encoding of string type: ' + tag +
                               ' unsupported');
  }
};

DERNode.prototype._encodeObjid = function encodeObjid(id, values, relative) {
  if (typeof id === 'string') {
    if (!values)
      return this.reporter.error('string objid given, but no values map found');
    if (!values.hasOwnProperty(id))
      return this.reporter.error('objid not found in values map');
    id = values[id].split(/[\s\.]+/g);
    for (var i = 0; i < id.length; i++)
      id[i] |= 0;
  } else if (Array.isArray(id)) {
    id = id.slice();
    for (var i = 0; i < id.length; i++)
      id[i] |= 0;
  }

  if (!Array.isArray(id)) {
    return this.reporter.error('objid() should be either array or string, ' +
                               'got: ' + JSON.stringify(id));
  }

  if (!relative) {
    if (id[1] >= 40)
      return this.reporter.error('Second objid identifier OOB');
    id.splice(0, 2, id[0] * 40 + id[1]);
  }

  // Count number of octets
  var size = 0;
  for (var i = 0; i < id.length; i++) {
    var ident = id[i];
    for (size++; ident >= 0x80; ident >>= 7)
      size++;
  }

  var objid = new Buffer(size);
  var offset = objid.length - 1;
  for (var i = id.length - 1; i >= 0; i--) {
    var ident = id[i];
    objid[offset--] = ident & 0x7f;
    while ((ident >>= 7) > 0)
      objid[offset--] = 0x80 | (ident & 0x7f);
  }

  return this._createEncoderBuffer(objid);
};

function two(num) {
  if (num < 10)
    return '0' + num;
  else
    return num;
}

DERNode.prototype._encodeTime = function encodeTime(time, tag) {
  var str;
  var date = new Date(time);

  if (tag === 'gentime') {
    str = [
      two(date.getFullYear()),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('');
  } else if (tag === 'utctime') {
    str = [
      two(date.getFullYear() % 100),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('');
  } else {
    this.reporter.error('Encoding ' + tag + ' time is not supported yet');
  }

  return this._encodeStr(str, 'octstr');
};

DERNode.prototype._encodeNull = function encodeNull() {
  return this._createEncoderBuffer('');
};

DERNode.prototype._encodeInt = function encodeInt(num, values) {
  if (typeof num === 'string') {
    if (!values)
      return this.reporter.error('String int or enum given, but no values map');
    if (!values.hasOwnProperty(num)) {
      return this.reporter.error('Values map doesn\'t contain: ' +
                                 JSON.stringify(num));
    }
    num = values[num];
  }

  // Bignum, assume big endian
  if (typeof num !== 'number' && !Buffer.isBuffer(num)) {
    var numArray = num.toArray();
    if (!num.sign && numArray[0] & 0x80) {
      numArray.unshift(0);
    }
    num = new Buffer(numArray);
  }

  if (Buffer.isBuffer(num)) {
    var size = num.length;
    if (num.length === 0)
      size++;

    var out = new Buffer(size);
    num.copy(out);
    if (num.length === 0)
      out[0] = 0
    return this._createEncoderBuffer(out);
  }

  if (num < 0x80)
    return this._createEncoderBuffer(num);

  if (num < 0x100)
    return this._createEncoderBuffer([0, num]);

  var size = 1;
  for (var i = num; i >= 0x100; i >>= 8)
    size++;

  var out = new Array(size);
  for (var i = out.length - 1; i >= 0; i--) {
    out[i] = num & 0xff;
    num >>= 8;
  }
  if(out[0] & 0x80) {
    out.unshift(0);
  }

  return this._createEncoderBuffer(new Buffer(out));
};

DERNode.prototype._encodeBool = function encodeBool(value) {
  return this._createEncoderBuffer(value ? 0xff : 0);
};

DERNode.prototype._use = function use(entity, obj) {
  if (typeof entity === 'function')
    entity = entity(obj);
  return entity._getEncoder('der').tree;
};

DERNode.prototype._skipDefault = function skipDefault(dataBuffer, reporter, parent) {
  var state = this._baseState;
  var i;
  if (state['default'] === null)
    return false;

  var data = dataBuffer.join();
  if (state.defaultBuffer === undefined)
    state.defaultBuffer = this._encodeValue(state['default'], reporter, parent).join();

  if (data.length !== state.defaultBuffer.length)
    return false;

  for (i=0; i < data.length; i++)
    if (data[i] !== state.defaultBuffer[i])
      return false;

  return true;
};

// Utility methods

function encodeTag(tag, primitive, cls, reporter) {
  var res;

  if (tag === 'seqof')
    tag = 'seq';
  else if (tag === 'setof')
    tag = 'set';

  if (der.tagByName.hasOwnProperty(tag))
    res = der.tagByName[tag];
  else if (typeof tag === 'number' && (tag | 0) === tag)
    res = tag;
  else
    return reporter.error('Unknown tag: ' + tag);

  if (res >= 0x1f)
    return reporter.error('Multi-octet tag encoding unsupported');

  if (!primitive)
    res |= 0x20;

  res |= (der.tagClassByName[cls || 'universal'] << 6);

  return res;
}

},{"../../asn1":6,"buffer":23,"inherits":49}],18:[function(require,module,exports){
var encoders = exports;

encoders.der = require('./der');
encoders.pem = require('./pem');

},{"./der":17,"./pem":19}],19:[function(require,module,exports){
var inherits = require('inherits');

var DEREncoder = require('./der');

function PEMEncoder(entity) {
  DEREncoder.call(this, entity);
  this.enc = 'pem';
};
inherits(PEMEncoder, DEREncoder);
module.exports = PEMEncoder;

PEMEncoder.prototype.encode = function encode(data, options) {
  var buf = DEREncoder.prototype.encode.call(this, data);

  var p = buf.toString('base64');
  var out = [ '-----BEGIN ' + options.label + '-----' ];
  for (var i = 0; i < p.length; i += 64)
    out.push(p.slice(i, i + 64));
  out.push('-----END ' + options.label + '-----');
  return out.join('\n');
};

},{"./der":17,"inherits":49}],20:[function(require,module,exports){
'use strict'

exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

function init () {
  var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  for (var i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i]
    revLookup[code.charCodeAt(i)] = i
  }

  revLookup['-'.charCodeAt(0)] = 62
  revLookup['_'.charCodeAt(0)] = 63
}

init()

function toByteArray (b64) {
  var i, j, l, tmp, placeHolders, arr
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  placeHolders = b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0

  // base64 is 4/3 + up to two characters of the original data
  arr = new Arr(len * 3 / 4 - placeHolders)

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len

  var L = 0

  for (i = 0, j = 0; i < l; i += 4, j += 3) {
    tmp = (revLookup[b64.charCodeAt(i)] << 18) | (revLookup[b64.charCodeAt(i + 1)] << 12) | (revLookup[b64.charCodeAt(i + 2)] << 6) | revLookup[b64.charCodeAt(i + 3)]
    arr[L++] = (tmp >> 16) & 0xFF
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  if (placeHolders === 2) {
    tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[L++] = tmp & 0xFF
  } else if (placeHolders === 1) {
    tmp = (revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var output = ''
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    output += lookup[tmp >> 2]
    output += lookup[(tmp << 4) & 0x3F]
    output += '=='
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + (uint8[len - 1])
    output += lookup[tmp >> 10]
    output += lookup[(tmp >> 4) & 0x3F]
    output += lookup[(tmp << 2) & 0x3F]
    output += '='
  }

  parts.push(output)

  return parts.join('')
}

},{}],21:[function(require,module,exports){
(function (module, exports) {
  'use strict';

  // Utils
  function assert (val, msg) {
    if (!val) throw new Error(msg || 'Assertion failed');
  }

  // Could use `inherits` module, but don't want to move from single file
  // architecture yet.
  function inherits (ctor, superCtor) {
    ctor.super_ = superCtor;
    var TempCtor = function () {};
    TempCtor.prototype = superCtor.prototype;
    ctor.prototype = new TempCtor();
    ctor.prototype.constructor = ctor;
  }

  // BN

  function BN (number, base, endian) {
    if (BN.isBN(number)) {
      return number;
    }

    this.negative = 0;
    this.words = null;
    this.length = 0;

    // Reduction context
    this.red = null;

    if (number !== null) {
      if (base === 'le' || base === 'be') {
        endian = base;
        base = 10;
      }

      this._init(number || 0, base || 10, endian || 'be');
    }
  }
  if (typeof module === 'object') {
    module.exports = BN;
  } else {
    exports.BN = BN;
  }

  BN.BN = BN;
  BN.wordSize = 26;

  var Buffer;
  try {
    Buffer = require('buf' + 'fer').Buffer;
  } catch (e) {
  }

  BN.isBN = function isBN (num) {
    return num !== null && typeof num === 'object' &&
      num.constructor.name === 'BN' && Array.isArray(num.words);
  };

  BN.max = function max (left, right) {
    if (left.cmp(right) > 0) return left;
    return right;
  };

  BN.min = function min (left, right) {
    if (left.cmp(right) < 0) return left;
    return right;
  };

  BN.prototype._init = function init (number, base, endian) {
    if (typeof number === 'number') {
      return this._initNumber(number, base, endian);
    }

    if (typeof number === 'object') {
      return this._initArray(number, base, endian);
    }

    if (base === 'hex') {
      base = 16;
    }
    assert(base === (base | 0) && base >= 2 && base <= 36);

    number = number.toString().replace(/\s+/g, '');
    var start = 0;
    if (number[0] === '-') {
      start++;
    }

    if (base === 16) {
      this._parseHex(number, start);
    } else {
      this._parseBase(number, base, start);
    }

    if (number[0] === '-') {
      this.negative = 1;
    }

    this.strip();

    if (endian !== 'le') return;

    this._initArray(this.toArray(), base, endian);
  };

  BN.prototype._initNumber = function _initNumber (number, base, endian) {
    if (number < 0) {
      this.negative = 1;
      number = -number;
    }
    if (number < 0x4000000) {
      this.words = [ number & 0x3ffffff ];
      this.length = 1;
    } else if (number < 0x10000000000000) {
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      assert(number < 0x20000000000000); // 2 ^ 53 (unsafe)
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    if (endian !== 'le') return;

    // Reverse the bytes
    this._initArray(this.toArray(), base, endian);
  };

  BN.prototype._initArray = function _initArray (number, base, endian) {
    // Perhaps a Uint8Array
    assert(typeof number.length === 'number');
    if (number.length <= 0) {
      this.words = [ 0 ];
      this.length = 1;
      return this;
    }

    this.length = Math.ceil(number.length / 3);
    this.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      this.words[i] = 0;
    }

    var j, w;
    var off = 0;
    if (endian === 'be') {
      for (i = number.length - 1, j = 0; i >= 0; i -= 3) {
        w = number[i] | (number[i - 1] << 8) | (number[i - 2] << 16);
        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
        off += 24;
        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    } else if (endian === 'le') {
      for (i = 0, j = 0; i < number.length; i += 3) {
        w = number[i] | (number[i + 1] << 8) | (number[i + 2] << 16);
        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
        off += 24;
        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    }
    return this.strip();
  };

  function parseHex (str, start, end) {
    var r = 0;
    var len = Math.min(str.length, end);
    for (var i = start; i < len; i++) {
      var c = str.charCodeAt(i) - 48;

      r <<= 4;

      // 'a' - 'f'
      if (c >= 49 && c <= 54) {
        r |= c - 49 + 0xa;

      // 'A' - 'F'
      } else if (c >= 17 && c <= 22) {
        r |= c - 17 + 0xa;

      // '0' - '9'
      } else {
        r |= c & 0xf;
      }
    }
    return r;
  }

  BN.prototype._parseHex = function _parseHex (number, start) {
    // Create possibly bigger array to ensure that it fits the number
    this.length = Math.ceil((number.length - start) / 6);
    this.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      this.words[i] = 0;
    }

    var j, w;
    // Scan 24-bit chunks and add them to the number
    var off = 0;
    for (i = number.length - 6, j = 0; i >= start; i -= 6) {
      w = parseHex(number, i, i + 6);
      this.words[j] |= (w << off) & 0x3ffffff;
      // NOTE: `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
      off += 24;
      if (off >= 26) {
        off -= 26;
        j++;
      }
    }
    if (i + 6 !== start) {
      w = parseHex(number, start, i + 6);
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
    }
    this.strip();
  };

  function parseBase (str, start, end, mul) {
    var r = 0;
    var len = Math.min(str.length, end);
    for (var i = start; i < len; i++) {
      var c = str.charCodeAt(i) - 48;

      r *= mul;

      // 'a'
      if (c >= 49) {
        r += c - 49 + 0xa;

      // 'A'
      } else if (c >= 17) {
        r += c - 17 + 0xa;

      // '0' - '9'
      } else {
        r += c;
      }
    }
    return r;
  }

  BN.prototype._parseBase = function _parseBase (number, base, start) {
    // Initialize as zero
    this.words = [ 0 ];
    this.length = 1;

    // Find length of limb in base
    for (var limbLen = 0, limbPow = 1; limbPow <= 0x3ffffff; limbPow *= base) {
      limbLen++;
    }
    limbLen--;
    limbPow = (limbPow / base) | 0;

    var total = number.length - start;
    var mod = total % limbLen;
    var end = Math.min(total, total - mod) + start;

    var word = 0;
    for (var i = start; i < end; i += limbLen) {
      word = parseBase(number, i, i + limbLen, base);

      this.imuln(limbPow);
      if (this.words[0] + word < 0x4000000) {
        this.words[0] += word;
      } else {
        this._iaddn(word);
      }
    }

    if (mod !== 0) {
      var pow = 1;
      word = parseBase(number, i, number.length, base);

      for (i = 0; i < mod; i++) {
        pow *= base;
      }

      this.imuln(pow);
      if (this.words[0] + word < 0x4000000) {
        this.words[0] += word;
      } else {
        this._iaddn(word);
      }
    }
  };

  BN.prototype.copy = function copy (dest) {
    dest.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      dest.words[i] = this.words[i];
    }
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
  };

  BN.prototype.clone = function clone () {
    var r = new BN(null);
    this.copy(r);
    return r;
  };

  BN.prototype._expand = function _expand (size) {
    while (this.length < size) {
      this.words[this.length++] = 0;
    }
    return this;
  };

  // Remove leading `0` from `this`
  BN.prototype.strip = function strip () {
    while (this.length > 1 && this.words[this.length - 1] === 0) {
      this.length--;
    }
    return this._normSign();
  };

  BN.prototype._normSign = function _normSign () {
    // -0 = 0
    if (this.length === 1 && this.words[0] === 0) {
      this.negative = 0;
    }
    return this;
  };

  BN.prototype.inspect = function inspect () {
    return (this.red ? '<BN-R: ' : '<BN: ') + this.toString(16) + '>';
  };

  /*

  var zeros = [];
  var groupSizes = [];
  var groupBases = [];

  var s = '';
  var i = -1;
  while (++i < BN.wordSize) {
    zeros[i] = s;
    s += '0';
  }
  groupSizes[0] = 0;
  groupSizes[1] = 0;
  groupBases[0] = 0;
  groupBases[1] = 0;
  var base = 2 - 1;
  while (++base < 36 + 1) {
    var groupSize = 0;
    var groupBase = 1;
    while (groupBase < (1 << BN.wordSize) / base) {
      groupBase *= base;
      groupSize += 1;
    }
    groupSizes[base] = groupSize;
    groupBases[base] = groupBase;
  }

  */

  var zeros = [
    '',
    '0',
    '00',
    '000',
    '0000',
    '00000',
    '000000',
    '0000000',
    '00000000',
    '000000000',
    '0000000000',
    '00000000000',
    '000000000000',
    '0000000000000',
    '00000000000000',
    '000000000000000',
    '0000000000000000',
    '00000000000000000',
    '000000000000000000',
    '0000000000000000000',
    '00000000000000000000',
    '000000000000000000000',
    '0000000000000000000000',
    '00000000000000000000000',
    '000000000000000000000000',
    '0000000000000000000000000'
  ];

  var groupSizes = [
    0, 0,
    25, 16, 12, 11, 10, 9, 8,
    8, 7, 7, 7, 7, 6, 6,
    6, 6, 6, 6, 6, 5, 5,
    5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5
  ];

  var groupBases = [
    0, 0,
    33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
    43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
    16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
    6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
    24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
  ];

  BN.prototype.toString = function toString (base, padding) {
    base = base || 10;
    padding = padding | 0 || 1;

    var out;
    if (base === 16 || base === 'hex') {
      out = '';
      var off = 0;
      var carry = 0;
      for (var i = 0; i < this.length; i++) {
        var w = this.words[i];
        var word = (((w << off) | carry) & 0xffffff).toString(16);
        carry = (w >>> (24 - off)) & 0xffffff;
        if (carry !== 0 || i !== this.length - 1) {
          out = zeros[6 - word.length] + word + out;
        } else {
          out = word + out;
        }
        off += 2;
        if (off >= 26) {
          off -= 26;
          i--;
        }
      }
      if (carry !== 0) {
        out = carry.toString(16) + out;
      }
      while (out.length % padding !== 0) {
        out = '0' + out;
      }
      if (this.negative !== 0) {
        out = '-' + out;
      }
      return out;
    }

    if (base === (base | 0) && base >= 2 && base <= 36) {
      // var groupSize = Math.floor(BN.wordSize * Math.LN2 / Math.log(base));
      var groupSize = groupSizes[base];
      // var groupBase = Math.pow(base, groupSize);
      var groupBase = groupBases[base];
      out = '';
      var c = this.clone();
      c.negative = 0;
      while (!c.isZero()) {
        var r = c.modn(groupBase).toString(base);
        c = c.idivn(groupBase);

        if (!c.isZero()) {
          out = zeros[groupSize - r.length] + r + out;
        } else {
          out = r + out;
        }
      }
      if (this.isZero()) {
        out = '0' + out;
      }
      while (out.length % padding !== 0) {
        out = '0' + out;
      }
      if (this.negative !== 0) {
        out = '-' + out;
      }
      return out;
    }

    assert(false, 'Base should be between 2 and 36');
  };

  BN.prototype.toNumber = function toNumber () {
    var ret = this.words[0];
    if (this.length === 2) {
      ret += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // NOTE: at this stage it is known that the top bit is set
      ret += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      assert(false, 'Number can only safely store up to 53 bits');
    }
    return (this.negative !== 0) ? -ret : ret;
  };

  BN.prototype.toJSON = function toJSON () {
    return this.toString(16);
  };

  BN.prototype.toBuffer = function toBuffer (endian, length) {
    assert(typeof Buffer !== 'undefined');
    return this.toArrayLike(Buffer, endian, length);
  };

  BN.prototype.toArray = function toArray (endian, length) {
    return this.toArrayLike(Array, endian, length);
  };

  BN.prototype.toArrayLike = function toArrayLike (ArrayType, endian, length) {
    var byteLength = this.byteLength();
    var reqLength = length || Math.max(1, byteLength);
    assert(byteLength <= reqLength, 'byte array longer than desired length');
    assert(reqLength > 0, 'Requested array length <= 0');

    this.strip();
    var littleEndian = endian === 'le';
    var res = new ArrayType(reqLength);

    var b, i;
    var q = this.clone();
    if (!littleEndian) {
      // Assume big-endian
      for (i = 0; i < reqLength - byteLength; i++) {
        res[i] = 0;
      }

      for (i = 0; !q.isZero(); i++) {
        b = q.andln(0xff);
        q.iushrn(8);

        res[reqLength - i - 1] = b;
      }
    } else {
      for (i = 0; !q.isZero(); i++) {
        b = q.andln(0xff);
        q.iushrn(8);

        res[i] = b;
      }

      for (; i < reqLength; i++) {
        res[i] = 0;
      }
    }

    return res;
  };

  if (Math.clz32) {
    BN.prototype._countBits = function _countBits (w) {
      return 32 - Math.clz32(w);
    };
  } else {
    BN.prototype._countBits = function _countBits (w) {
      var t = w;
      var r = 0;
      if (t >= 0x1000) {
        r += 13;
        t >>>= 13;
      }
      if (t >= 0x40) {
        r += 7;
        t >>>= 7;
      }
      if (t >= 0x8) {
        r += 4;
        t >>>= 4;
      }
      if (t >= 0x02) {
        r += 2;
        t >>>= 2;
      }
      return r + t;
    };
  }

  BN.prototype._zeroBits = function _zeroBits (w) {
    // Short-cut
    if (w === 0) return 26;

    var t = w;
    var r = 0;
    if ((t & 0x1fff) === 0) {
      r += 13;
      t >>>= 13;
    }
    if ((t & 0x7f) === 0) {
      r += 7;
      t >>>= 7;
    }
    if ((t & 0xf) === 0) {
      r += 4;
      t >>>= 4;
    }
    if ((t & 0x3) === 0) {
      r += 2;
      t >>>= 2;
    }
    if ((t & 0x1) === 0) {
      r++;
    }
    return r;
  };

  // Return number of used bits in a BN
  BN.prototype.bitLength = function bitLength () {
    var w = this.words[this.length - 1];
    var hi = this._countBits(w);
    return (this.length - 1) * 26 + hi;
  };

  function toBitArray (num) {
    var w = new Array(num.bitLength());

    for (var bit = 0; bit < w.length; bit++) {
      var off = (bit / 26) | 0;
      var wbit = bit % 26;

      w[bit] = (num.words[off] & (1 << wbit)) >>> wbit;
    }

    return w;
  }

  // Number of trailing zero bits
  BN.prototype.zeroBits = function zeroBits () {
    if (this.isZero()) return 0;

    var r = 0;
    for (var i = 0; i < this.length; i++) {
      var b = this._zeroBits(this.words[i]);
      r += b;
      if (b !== 26) break;
    }
    return r;
  };

  BN.prototype.byteLength = function byteLength () {
    return Math.ceil(this.bitLength() / 8);
  };

  BN.prototype.toTwos = function toTwos (width) {
    if (this.negative !== 0) {
      return this.abs().inotn(width).iaddn(1);
    }
    return this.clone();
  };

  BN.prototype.fromTwos = function fromTwos (width) {
    if (this.testn(width - 1)) {
      return this.notn(width).iaddn(1).ineg();
    }
    return this.clone();
  };

  BN.prototype.isNeg = function isNeg () {
    return this.negative !== 0;
  };

  // Return negative clone of `this`
  BN.prototype.neg = function neg () {
    return this.clone().ineg();
  };

  BN.prototype.ineg = function ineg () {
    if (!this.isZero()) {
      this.negative ^= 1;
    }

    return this;
  };

  // Or `num` with `this` in-place
  BN.prototype.iuor = function iuor (num) {
    while (this.length < num.length) {
      this.words[this.length++] = 0;
    }

    for (var i = 0; i < num.length; i++) {
      this.words[i] = this.words[i] | num.words[i];
    }

    return this.strip();
  };

  BN.prototype.ior = function ior (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuor(num);
  };

  // Or `num` with `this`
  BN.prototype.or = function or (num) {
    if (this.length > num.length) return this.clone().ior(num);
    return num.clone().ior(this);
  };

  BN.prototype.uor = function uor (num) {
    if (this.length > num.length) return this.clone().iuor(num);
    return num.clone().iuor(this);
  };

  // And `num` with `this` in-place
  BN.prototype.iuand = function iuand (num) {
    // b = min-length(num, this)
    var b;
    if (this.length > num.length) {
      b = num;
    } else {
      b = this;
    }

    for (var i = 0; i < b.length; i++) {
      this.words[i] = this.words[i] & num.words[i];
    }

    this.length = b.length;

    return this.strip();
  };

  BN.prototype.iand = function iand (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuand(num);
  };

  // And `num` with `this`
  BN.prototype.and = function and (num) {
    if (this.length > num.length) return this.clone().iand(num);
    return num.clone().iand(this);
  };

  BN.prototype.uand = function uand (num) {
    if (this.length > num.length) return this.clone().iuand(num);
    return num.clone().iuand(this);
  };

  // Xor `num` with `this` in-place
  BN.prototype.iuxor = function iuxor (num) {
    // a.length > b.length
    var a;
    var b;
    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    for (var i = 0; i < b.length; i++) {
      this.words[i] = a.words[i] ^ b.words[i];
    }

    if (this !== a) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    this.length = a.length;

    return this.strip();
  };

  BN.prototype.ixor = function ixor (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuxor(num);
  };

  // Xor `num` with `this`
  BN.prototype.xor = function xor (num) {
    if (this.length > num.length) return this.clone().ixor(num);
    return num.clone().ixor(this);
  };

  BN.prototype.uxor = function uxor (num) {
    if (this.length > num.length) return this.clone().iuxor(num);
    return num.clone().iuxor(this);
  };

  // Not ``this`` with ``width`` bitwidth
  BN.prototype.inotn = function inotn (width) {
    assert(typeof width === 'number' && width >= 0);

    var bytesNeeded = Math.ceil(width / 26) | 0;
    var bitsLeft = width % 26;

    // Extend the buffer with leading zeroes
    this._expand(bytesNeeded);

    if (bitsLeft > 0) {
      bytesNeeded--;
    }

    // Handle complete words
    for (var i = 0; i < bytesNeeded; i++) {
      this.words[i] = ~this.words[i] & 0x3ffffff;
    }

    // Handle the residue
    if (bitsLeft > 0) {
      this.words[i] = ~this.words[i] & (0x3ffffff >> (26 - bitsLeft));
    }

    // And remove leading zeroes
    return this.strip();
  };

  BN.prototype.notn = function notn (width) {
    return this.clone().inotn(width);
  };

  // Set `bit` of `this`
  BN.prototype.setn = function setn (bit, val) {
    assert(typeof bit === 'number' && bit >= 0);

    var off = (bit / 26) | 0;
    var wbit = bit % 26;

    this._expand(off + 1);

    if (val) {
      this.words[off] = this.words[off] | (1 << wbit);
    } else {
      this.words[off] = this.words[off] & ~(1 << wbit);
    }

    return this.strip();
  };

  // Add `num` to `this` in-place
  BN.prototype.iadd = function iadd (num) {
    var r;

    // negative + positive
    if (this.negative !== 0 && num.negative === 0) {
      this.negative = 0;
      r = this.isub(num);
      this.negative ^= 1;
      return this._normSign();

    // positive + negative
    } else if (this.negative === 0 && num.negative !== 0) {
      num.negative = 0;
      r = this.isub(num);
      num.negative = 1;
      return r._normSign();
    }

    // a.length > b.length
    var a, b;
    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    var carry = 0;
    for (var i = 0; i < b.length; i++) {
      r = (a.words[i] | 0) + (b.words[i] | 0) + carry;
      this.words[i] = r & 0x3ffffff;
      carry = r >>> 26;
    }
    for (; carry !== 0 && i < a.length; i++) {
      r = (a.words[i] | 0) + carry;
      this.words[i] = r & 0x3ffffff;
      carry = r >>> 26;
    }

    this.length = a.length;
    if (carry !== 0) {
      this.words[this.length] = carry;
      this.length++;
    // Copy the rest of the words
    } else if (a !== this) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    return this;
  };

  // Add `num` to `this`
  BN.prototype.add = function add (num) {
    var res;
    if (num.negative !== 0 && this.negative === 0) {
      num.negative = 0;
      res = this.sub(num);
      num.negative ^= 1;
      return res;
    } else if (num.negative === 0 && this.negative !== 0) {
      this.negative = 0;
      res = num.sub(this);
      this.negative = 1;
      return res;
    }

    if (this.length > num.length) return this.clone().iadd(num);

    return num.clone().iadd(this);
  };

  // Subtract `num` from `this` in-place
  BN.prototype.isub = function isub (num) {
    // this - (-num) = this + num
    if (num.negative !== 0) {
      num.negative = 0;
      var r = this.iadd(num);
      num.negative = 1;
      return r._normSign();

    // -this - num = -(this + num)
    } else if (this.negative !== 0) {
      this.negative = 0;
      this.iadd(num);
      this.negative = 1;
      return this._normSign();
    }

    // At this point both numbers are positive
    var cmp = this.cmp(num);

    // Optimization - zeroify
    if (cmp === 0) {
      this.negative = 0;
      this.length = 1;
      this.words[0] = 0;
      return this;
    }

    // a > b
    var a, b;
    if (cmp > 0) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    var carry = 0;
    for (var i = 0; i < b.length; i++) {
      r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }
    for (; carry !== 0 && i < a.length; i++) {
      r = (a.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    // Copy rest of the words
    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    this.length = Math.max(this.length, i);

    if (a !== this) {
      this.negative = 1;
    }

    return this.strip();
  };

  // Subtract `num` from `this`
  BN.prototype.sub = function sub (num) {
    return this.clone().isub(num);
  };

  function smallMulTo (self, num, out) {
    out.negative = num.negative ^ self.negative;
    var len = (self.length + num.length) | 0;
    out.length = len;
    len = (len - 1) | 0;

    // Peel one iteration (compiler can't do it, because of code complexity)
    var a = self.words[0] | 0;
    var b = num.words[0] | 0;
    var r = a * b;

    var lo = r & 0x3ffffff;
    var carry = (r / 0x4000000) | 0;
    out.words[0] = lo;

    for (var k = 1; k < len; k++) {
      // Sum all words with the same `i + j = k` and accumulate `ncarry`,
      // note that ncarry could be >= 0x3ffffff
      var ncarry = carry >>> 26;
      var rword = carry & 0x3ffffff;
      var maxJ = Math.min(k, num.length - 1);
      for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
        var i = (k - j) | 0;
        a = self.words[i] | 0;
        b = num.words[j] | 0;
        r = a * b + rword;
        ncarry += (r / 0x4000000) | 0;
        rword = r & 0x3ffffff;
      }
      out.words[k] = rword | 0;
      carry = ncarry | 0;
    }
    if (carry !== 0) {
      out.words[k] = carry | 0;
    } else {
      out.length--;
    }

    return out.strip();
  }

  // TODO(indutny): it may be reasonable to omit it for users who don't need
  // to work with 256-bit numbers, otherwise it gives 20% improvement for 256-bit
  // multiplication (like elliptic secp256k1).
  var comb10MulTo = function comb10MulTo (self, num, out) {
    var a = self.words;
    var b = num.words;
    var o = out.words;
    var c = 0;
    var lo;
    var mid;
    var hi;
    var a0 = a[0] | 0;
    var al0 = a0 & 0x1fff;
    var ah0 = a0 >>> 13;
    var a1 = a[1] | 0;
    var al1 = a1 & 0x1fff;
    var ah1 = a1 >>> 13;
    var a2 = a[2] | 0;
    var al2 = a2 & 0x1fff;
    var ah2 = a2 >>> 13;
    var a3 = a[3] | 0;
    var al3 = a3 & 0x1fff;
    var ah3 = a3 >>> 13;
    var a4 = a[4] | 0;
    var al4 = a4 & 0x1fff;
    var ah4 = a4 >>> 13;
    var a5 = a[5] | 0;
    var al5 = a5 & 0x1fff;
    var ah5 = a5 >>> 13;
    var a6 = a[6] | 0;
    var al6 = a6 & 0x1fff;
    var ah6 = a6 >>> 13;
    var a7 = a[7] | 0;
    var al7 = a7 & 0x1fff;
    var ah7 = a7 >>> 13;
    var a8 = a[8] | 0;
    var al8 = a8 & 0x1fff;
    var ah8 = a8 >>> 13;
    var a9 = a[9] | 0;
    var al9 = a9 & 0x1fff;
    var ah9 = a9 >>> 13;
    var b0 = b[0] | 0;
    var bl0 = b0 & 0x1fff;
    var bh0 = b0 >>> 13;
    var b1 = b[1] | 0;
    var bl1 = b1 & 0x1fff;
    var bh1 = b1 >>> 13;
    var b2 = b[2] | 0;
    var bl2 = b2 & 0x1fff;
    var bh2 = b2 >>> 13;
    var b3 = b[3] | 0;
    var bl3 = b3 & 0x1fff;
    var bh3 = b3 >>> 13;
    var b4 = b[4] | 0;
    var bl4 = b4 & 0x1fff;
    var bh4 = b4 >>> 13;
    var b5 = b[5] | 0;
    var bl5 = b5 & 0x1fff;
    var bh5 = b5 >>> 13;
    var b6 = b[6] | 0;
    var bl6 = b6 & 0x1fff;
    var bh6 = b6 >>> 13;
    var b7 = b[7] | 0;
    var bl7 = b7 & 0x1fff;
    var bh7 = b7 >>> 13;
    var b8 = b[8] | 0;
    var bl8 = b8 & 0x1fff;
    var bh8 = b8 >>> 13;
    var b9 = b[9] | 0;
    var bl9 = b9 & 0x1fff;
    var bh9 = b9 >>> 13;

    out.negative = self.negative ^ num.negative;
    out.length = 19;
    /* k = 0 */
    lo = Math.imul(al0, bl0);
    mid = Math.imul(al0, bh0);
    mid += Math.imul(ah0, bl0);
    hi = Math.imul(ah0, bh0);
    var w0 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w0 >>> 26);
    w0 &= 0x3ffffff;
    /* k = 1 */
    lo = Math.imul(al1, bl0);
    mid = Math.imul(al1, bh0);
    mid += Math.imul(ah1, bl0);
    hi = Math.imul(ah1, bh0);
    lo += Math.imul(al0, bl1);
    mid += Math.imul(al0, bh1);
    mid += Math.imul(ah0, bl1);
    hi += Math.imul(ah0, bh1);
    var w1 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w1 >>> 26);
    w1 &= 0x3ffffff;
    /* k = 2 */
    lo = Math.imul(al2, bl0);
    mid = Math.imul(al2, bh0);
    mid += Math.imul(ah2, bl0);
    hi = Math.imul(ah2, bh0);
    lo += Math.imul(al1, bl1);
    mid += Math.imul(al1, bh1);
    mid += Math.imul(ah1, bl1);
    hi += Math.imul(ah1, bh1);
    lo += Math.imul(al0, bl2);
    mid += Math.imul(al0, bh2);
    mid += Math.imul(ah0, bl2);
    hi += Math.imul(ah0, bh2);
    var w2 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w2 >>> 26);
    w2 &= 0x3ffffff;
    /* k = 3 */
    lo = Math.imul(al3, bl0);
    mid = Math.imul(al3, bh0);
    mid += Math.imul(ah3, bl0);
    hi = Math.imul(ah3, bh0);
    lo += Math.imul(al2, bl1);
    mid += Math.imul(al2, bh1);
    mid += Math.imul(ah2, bl1);
    hi += Math.imul(ah2, bh1);
    lo += Math.imul(al1, bl2);
    mid += Math.imul(al1, bh2);
    mid += Math.imul(ah1, bl2);
    hi += Math.imul(ah1, bh2);
    lo += Math.imul(al0, bl3);
    mid += Math.imul(al0, bh3);
    mid += Math.imul(ah0, bl3);
    hi += Math.imul(ah0, bh3);
    var w3 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w3 >>> 26);
    w3 &= 0x3ffffff;
    /* k = 4 */
    lo = Math.imul(al4, bl0);
    mid = Math.imul(al4, bh0);
    mid += Math.imul(ah4, bl0);
    hi = Math.imul(ah4, bh0);
    lo += Math.imul(al3, bl1);
    mid += Math.imul(al3, bh1);
    mid += Math.imul(ah3, bl1);
    hi += Math.imul(ah3, bh1);
    lo += Math.imul(al2, bl2);
    mid += Math.imul(al2, bh2);
    mid += Math.imul(ah2, bl2);
    hi += Math.imul(ah2, bh2);
    lo += Math.imul(al1, bl3);
    mid += Math.imul(al1, bh3);
    mid += Math.imul(ah1, bl3);
    hi += Math.imul(ah1, bh3);
    lo += Math.imul(al0, bl4);
    mid += Math.imul(al0, bh4);
    mid += Math.imul(ah0, bl4);
    hi += Math.imul(ah0, bh4);
    var w4 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w4 >>> 26);
    w4 &= 0x3ffffff;
    /* k = 5 */
    lo = Math.imul(al5, bl0);
    mid = Math.imul(al5, bh0);
    mid += Math.imul(ah5, bl0);
    hi = Math.imul(ah5, bh0);
    lo += Math.imul(al4, bl1);
    mid += Math.imul(al4, bh1);
    mid += Math.imul(ah4, bl1);
    hi += Math.imul(ah4, bh1);
    lo += Math.imul(al3, bl2);
    mid += Math.imul(al3, bh2);
    mid += Math.imul(ah3, bl2);
    hi += Math.imul(ah3, bh2);
    lo += Math.imul(al2, bl3);
    mid += Math.imul(al2, bh3);
    mid += Math.imul(ah2, bl3);
    hi += Math.imul(ah2, bh3);
    lo += Math.imul(al1, bl4);
    mid += Math.imul(al1, bh4);
    mid += Math.imul(ah1, bl4);
    hi += Math.imul(ah1, bh4);
    lo += Math.imul(al0, bl5);
    mid += Math.imul(al0, bh5);
    mid += Math.imul(ah0, bl5);
    hi += Math.imul(ah0, bh5);
    var w5 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w5 >>> 26);
    w5 &= 0x3ffffff;
    /* k = 6 */
    lo = Math.imul(al6, bl0);
    mid = Math.imul(al6, bh0);
    mid += Math.imul(ah6, bl0);
    hi = Math.imul(ah6, bh0);
    lo += Math.imul(al5, bl1);
    mid += Math.imul(al5, bh1);
    mid += Math.imul(ah5, bl1);
    hi += Math.imul(ah5, bh1);
    lo += Math.imul(al4, bl2);
    mid += Math.imul(al4, bh2);
    mid += Math.imul(ah4, bl2);
    hi += Math.imul(ah4, bh2);
    lo += Math.imul(al3, bl3);
    mid += Math.imul(al3, bh3);
    mid += Math.imul(ah3, bl3);
    hi += Math.imul(ah3, bh3);
    lo += Math.imul(al2, bl4);
    mid += Math.imul(al2, bh4);
    mid += Math.imul(ah2, bl4);
    hi += Math.imul(ah2, bh4);
    lo += Math.imul(al1, bl5);
    mid += Math.imul(al1, bh5);
    mid += Math.imul(ah1, bl5);
    hi += Math.imul(ah1, bh5);
    lo += Math.imul(al0, bl6);
    mid += Math.imul(al0, bh6);
    mid += Math.imul(ah0, bl6);
    hi += Math.imul(ah0, bh6);
    var w6 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w6 >>> 26);
    w6 &= 0x3ffffff;
    /* k = 7 */
    lo = Math.imul(al7, bl0);
    mid = Math.imul(al7, bh0);
    mid += Math.imul(ah7, bl0);
    hi = Math.imul(ah7, bh0);
    lo += Math.imul(al6, bl1);
    mid += Math.imul(al6, bh1);
    mid += Math.imul(ah6, bl1);
    hi += Math.imul(ah6, bh1);
    lo += Math.imul(al5, bl2);
    mid += Math.imul(al5, bh2);
    mid += Math.imul(ah5, bl2);
    hi += Math.imul(ah5, bh2);
    lo += Math.imul(al4, bl3);
    mid += Math.imul(al4, bh3);
    mid += Math.imul(ah4, bl3);
    hi += Math.imul(ah4, bh3);
    lo += Math.imul(al3, bl4);
    mid += Math.imul(al3, bh4);
    mid += Math.imul(ah3, bl4);
    hi += Math.imul(ah3, bh4);
    lo += Math.imul(al2, bl5);
    mid += Math.imul(al2, bh5);
    mid += Math.imul(ah2, bl5);
    hi += Math.imul(ah2, bh5);
    lo += Math.imul(al1, bl6);
    mid += Math.imul(al1, bh6);
    mid += Math.imul(ah1, bl6);
    hi += Math.imul(ah1, bh6);
    lo += Math.imul(al0, bl7);
    mid += Math.imul(al0, bh7);
    mid += Math.imul(ah0, bl7);
    hi += Math.imul(ah0, bh7);
    var w7 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w7 >>> 26);
    w7 &= 0x3ffffff;
    /* k = 8 */
    lo = Math.imul(al8, bl0);
    mid = Math.imul(al8, bh0);
    mid += Math.imul(ah8, bl0);
    hi = Math.imul(ah8, bh0);
    lo += Math.imul(al7, bl1);
    mid += Math.imul(al7, bh1);
    mid += Math.imul(ah7, bl1);
    hi += Math.imul(ah7, bh1);
    lo += Math.imul(al6, bl2);
    mid += Math.imul(al6, bh2);
    mid += Math.imul(ah6, bl2);
    hi += Math.imul(ah6, bh2);
    lo += Math.imul(al5, bl3);
    mid += Math.imul(al5, bh3);
    mid += Math.imul(ah5, bl3);
    hi += Math.imul(ah5, bh3);
    lo += Math.imul(al4, bl4);
    mid += Math.imul(al4, bh4);
    mid += Math.imul(ah4, bl4);
    hi += Math.imul(ah4, bh4);
    lo += Math.imul(al3, bl5);
    mid += Math.imul(al3, bh5);
    mid += Math.imul(ah3, bl5);
    hi += Math.imul(ah3, bh5);
    lo += Math.imul(al2, bl6);
    mid += Math.imul(al2, bh6);
    mid += Math.imul(ah2, bl6);
    hi += Math.imul(ah2, bh6);
    lo += Math.imul(al1, bl7);
    mid += Math.imul(al1, bh7);
    mid += Math.imul(ah1, bl7);
    hi += Math.imul(ah1, bh7);
    lo += Math.imul(al0, bl8);
    mid += Math.imul(al0, bh8);
    mid += Math.imul(ah0, bl8);
    hi += Math.imul(ah0, bh8);
    var w8 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w8 >>> 26);
    w8 &= 0x3ffffff;
    /* k = 9 */
    lo = Math.imul(al9, bl0);
    mid = Math.imul(al9, bh0);
    mid += Math.imul(ah9, bl0);
    hi = Math.imul(ah9, bh0);
    lo += Math.imul(al8, bl1);
    mid += Math.imul(al8, bh1);
    mid += Math.imul(ah8, bl1);
    hi += Math.imul(ah8, bh1);
    lo += Math.imul(al7, bl2);
    mid += Math.imul(al7, bh2);
    mid += Math.imul(ah7, bl2);
    hi += Math.imul(ah7, bh2);
    lo += Math.imul(al6, bl3);
    mid += Math.imul(al6, bh3);
    mid += Math.imul(ah6, bl3);
    hi += Math.imul(ah6, bh3);
    lo += Math.imul(al5, bl4);
    mid += Math.imul(al5, bh4);
    mid += Math.imul(ah5, bl4);
    hi += Math.imul(ah5, bh4);
    lo += Math.imul(al4, bl5);
    mid += Math.imul(al4, bh5);
    mid += Math.imul(ah4, bl5);
    hi += Math.imul(ah4, bh5);
    lo += Math.imul(al3, bl6);
    mid += Math.imul(al3, bh6);
    mid += Math.imul(ah3, bl6);
    hi += Math.imul(ah3, bh6);
    lo += Math.imul(al2, bl7);
    mid += Math.imul(al2, bh7);
    mid += Math.imul(ah2, bl7);
    hi += Math.imul(ah2, bh7);
    lo += Math.imul(al1, bl8);
    mid += Math.imul(al1, bh8);
    mid += Math.imul(ah1, bl8);
    hi += Math.imul(ah1, bh8);
    lo += Math.imul(al0, bl9);
    mid += Math.imul(al0, bh9);
    mid += Math.imul(ah0, bl9);
    hi += Math.imul(ah0, bh9);
    var w9 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w9 >>> 26);
    w9 &= 0x3ffffff;
    /* k = 10 */
    lo = Math.imul(al9, bl1);
    mid = Math.imul(al9, bh1);
    mid += Math.imul(ah9, bl1);
    hi = Math.imul(ah9, bh1);
    lo += Math.imul(al8, bl2);
    mid += Math.imul(al8, bh2);
    mid += Math.imul(ah8, bl2);
    hi += Math.imul(ah8, bh2);
    lo += Math.imul(al7, bl3);
    mid += Math.imul(al7, bh3);
    mid += Math.imul(ah7, bl3);
    hi += Math.imul(ah7, bh3);
    lo += Math.imul(al6, bl4);
    mid += Math.imul(al6, bh4);
    mid += Math.imul(ah6, bl4);
    hi += Math.imul(ah6, bh4);
    lo += Math.imul(al5, bl5);
    mid += Math.imul(al5, bh5);
    mid += Math.imul(ah5, bl5);
    hi += Math.imul(ah5, bh5);
    lo += Math.imul(al4, bl6);
    mid += Math.imul(al4, bh6);
    mid += Math.imul(ah4, bl6);
    hi += Math.imul(ah4, bh6);
    lo += Math.imul(al3, bl7);
    mid += Math.imul(al3, bh7);
    mid += Math.imul(ah3, bl7);
    hi += Math.imul(ah3, bh7);
    lo += Math.imul(al2, bl8);
    mid += Math.imul(al2, bh8);
    mid += Math.imul(ah2, bl8);
    hi += Math.imul(ah2, bh8);
    lo += Math.imul(al1, bl9);
    mid += Math.imul(al1, bh9);
    mid += Math.imul(ah1, bl9);
    hi += Math.imul(ah1, bh9);
    var w10 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w10 >>> 26);
    w10 &= 0x3ffffff;
    /* k = 11 */
    lo = Math.imul(al9, bl2);
    mid = Math.imul(al9, bh2);
    mid += Math.imul(ah9, bl2);
    hi = Math.imul(ah9, bh2);
    lo += Math.imul(al8, bl3);
    mid += Math.imul(al8, bh3);
    mid += Math.imul(ah8, bl3);
    hi += Math.imul(ah8, bh3);
    lo += Math.imul(al7, bl4);
    mid += Math.imul(al7, bh4);
    mid += Math.imul(ah7, bl4);
    hi += Math.imul(ah7, bh4);
    lo += Math.imul(al6, bl5);
    mid += Math.imul(al6, bh5);
    mid += Math.imul(ah6, bl5);
    hi += Math.imul(ah6, bh5);
    lo += Math.imul(al5, bl6);
    mid += Math.imul(al5, bh6);
    mid += Math.imul(ah5, bl6);
    hi += Math.imul(ah5, bh6);
    lo += Math.imul(al4, bl7);
    mid += Math.imul(al4, bh7);
    mid += Math.imul(ah4, bl7);
    hi += Math.imul(ah4, bh7);
    lo += Math.imul(al3, bl8);
    mid += Math.imul(al3, bh8);
    mid += Math.imul(ah3, bl8);
    hi += Math.imul(ah3, bh8);
    lo += Math.imul(al2, bl9);
    mid += Math.imul(al2, bh9);
    mid += Math.imul(ah2, bl9);
    hi += Math.imul(ah2, bh9);
    var w11 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w11 >>> 26);
    w11 &= 0x3ffffff;
    /* k = 12 */
    lo = Math.imul(al9, bl3);
    mid = Math.imul(al9, bh3);
    mid += Math.imul(ah9, bl3);
    hi = Math.imul(ah9, bh3);
    lo += Math.imul(al8, bl4);
    mid += Math.imul(al8, bh4);
    mid += Math.imul(ah8, bl4);
    hi += Math.imul(ah8, bh4);
    lo += Math.imul(al7, bl5);
    mid += Math.imul(al7, bh5);
    mid += Math.imul(ah7, bl5);
    hi += Math.imul(ah7, bh5);
    lo += Math.imul(al6, bl6);
    mid += Math.imul(al6, bh6);
    mid += Math.imul(ah6, bl6);
    hi += Math.imul(ah6, bh6);
    lo += Math.imul(al5, bl7);
    mid += Math.imul(al5, bh7);
    mid += Math.imul(ah5, bl7);
    hi += Math.imul(ah5, bh7);
    lo += Math.imul(al4, bl8);
    mid += Math.imul(al4, bh8);
    mid += Math.imul(ah4, bl8);
    hi += Math.imul(ah4, bh8);
    lo += Math.imul(al3, bl9);
    mid += Math.imul(al3, bh9);
    mid += Math.imul(ah3, bl9);
    hi += Math.imul(ah3, bh9);
    var w12 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w12 >>> 26);
    w12 &= 0x3ffffff;
    /* k = 13 */
    lo = Math.imul(al9, bl4);
    mid = Math.imul(al9, bh4);
    mid += Math.imul(ah9, bl4);
    hi = Math.imul(ah9, bh4);
    lo += Math.imul(al8, bl5);
    mid += Math.imul(al8, bh5);
    mid += Math.imul(ah8, bl5);
    hi += Math.imul(ah8, bh5);
    lo += Math.imul(al7, bl6);
    mid += Math.imul(al7, bh6);
    mid += Math.imul(ah7, bl6);
    hi += Math.imul(ah7, bh6);
    lo += Math.imul(al6, bl7);
    mid += Math.imul(al6, bh7);
    mid += Math.imul(ah6, bl7);
    hi += Math.imul(ah6, bh7);
    lo += Math.imul(al5, bl8);
    mid += Math.imul(al5, bh8);
    mid += Math.imul(ah5, bl8);
    hi += Math.imul(ah5, bh8);
    lo += Math.imul(al4, bl9);
    mid += Math.imul(al4, bh9);
    mid += Math.imul(ah4, bl9);
    hi += Math.imul(ah4, bh9);
    var w13 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w13 >>> 26);
    w13 &= 0x3ffffff;
    /* k = 14 */
    lo = Math.imul(al9, bl5);
    mid = Math.imul(al9, bh5);
    mid += Math.imul(ah9, bl5);
    hi = Math.imul(ah9, bh5);
    lo += Math.imul(al8, bl6);
    mid += Math.imul(al8, bh6);
    mid += Math.imul(ah8, bl6);
    hi += Math.imul(ah8, bh6);
    lo += Math.imul(al7, bl7);
    mid += Math.imul(al7, bh7);
    mid += Math.imul(ah7, bl7);
    hi += Math.imul(ah7, bh7);
    lo += Math.imul(al6, bl8);
    mid += Math.imul(al6, bh8);
    mid += Math.imul(ah6, bl8);
    hi += Math.imul(ah6, bh8);
    lo += Math.imul(al5, bl9);
    mid += Math.imul(al5, bh9);
    mid += Math.imul(ah5, bl9);
    hi += Math.imul(ah5, bh9);
    var w14 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w14 >>> 26);
    w14 &= 0x3ffffff;
    /* k = 15 */
    lo = Math.imul(al9, bl6);
    mid = Math.imul(al9, bh6);
    mid += Math.imul(ah9, bl6);
    hi = Math.imul(ah9, bh6);
    lo += Math.imul(al8, bl7);
    mid += Math.imul(al8, bh7);
    mid += Math.imul(ah8, bl7);
    hi += Math.imul(ah8, bh7);
    lo += Math.imul(al7, bl8);
    mid += Math.imul(al7, bh8);
    mid += Math.imul(ah7, bl8);
    hi += Math.imul(ah7, bh8);
    lo += Math.imul(al6, bl9);
    mid += Math.imul(al6, bh9);
    mid += Math.imul(ah6, bl9);
    hi += Math.imul(ah6, bh9);
    var w15 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w15 >>> 26);
    w15 &= 0x3ffffff;
    /* k = 16 */
    lo = Math.imul(al9, bl7);
    mid = Math.imul(al9, bh7);
    mid += Math.imul(ah9, bl7);
    hi = Math.imul(ah9, bh7);
    lo += Math.imul(al8, bl8);
    mid += Math.imul(al8, bh8);
    mid += Math.imul(ah8, bl8);
    hi += Math.imul(ah8, bh8);
    lo += Math.imul(al7, bl9);
    mid += Math.imul(al7, bh9);
    mid += Math.imul(ah7, bl9);
    hi += Math.imul(ah7, bh9);
    var w16 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w16 >>> 26);
    w16 &= 0x3ffffff;
    /* k = 17 */
    lo = Math.imul(al9, bl8);
    mid = Math.imul(al9, bh8);
    mid += Math.imul(ah9, bl8);
    hi = Math.imul(ah9, bh8);
    lo += Math.imul(al8, bl9);
    mid += Math.imul(al8, bh9);
    mid += Math.imul(ah8, bl9);
    hi += Math.imul(ah8, bh9);
    var w17 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w17 >>> 26);
    w17 &= 0x3ffffff;
    /* k = 18 */
    lo = Math.imul(al9, bl9);
    mid = Math.imul(al9, bh9);
    mid += Math.imul(ah9, bl9);
    hi = Math.imul(ah9, bh9);
    var w18 = c + lo + ((mid & 0x1fff) << 13);
    c = hi + (mid >>> 13) + (w18 >>> 26);
    w18 &= 0x3ffffff;
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
    o[4] = w4;
    o[5] = w5;
    o[6] = w6;
    o[7] = w7;
    o[8] = w8;
    o[9] = w9;
    o[10] = w10;
    o[11] = w11;
    o[12] = w12;
    o[13] = w13;
    o[14] = w14;
    o[15] = w15;
    o[16] = w16;
    o[17] = w17;
    o[18] = w18;
    if (c !== 0) {
      o[19] = c;
      out.length++;
    }
    return out;
  };

  // Polyfill comb
  if (!Math.imul) {
    comb10MulTo = smallMulTo;
  }

  function bigMulTo (self, num, out) {
    out.negative = num.negative ^ self.negative;
    out.length = self.length + num.length;

    var carry = 0;
    var hncarry = 0;
    for (var k = 0; k < out.length - 1; k++) {
      // Sum all words with the same `i + j = k` and accumulate `ncarry`,
      // note that ncarry could be >= 0x3ffffff
      var ncarry = hncarry;
      hncarry = 0;
      var rword = carry & 0x3ffffff;
      var maxJ = Math.min(k, num.length - 1);
      for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
        var i = k - j;
        var a = self.words[i] | 0;
        var b = num.words[j] | 0;
        var r = a * b;

        var lo = r & 0x3ffffff;
        ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
        lo = (lo + rword) | 0;
        rword = lo & 0x3ffffff;
        ncarry = (ncarry + (lo >>> 26)) | 0;

        hncarry += ncarry >>> 26;
        ncarry &= 0x3ffffff;
      }
      out.words[k] = rword;
      carry = ncarry;
      ncarry = hncarry;
    }
    if (carry !== 0) {
      out.words[k] = carry;
    } else {
      out.length--;
    }

    return out.strip();
  }

  function jumboMulTo (self, num, out) {
    var fftm = new FFTM();
    return fftm.mulp(self, num, out);
  }

  BN.prototype.mulTo = function mulTo (num, out) {
    var res;
    var len = this.length + num.length;
    if (this.length === 10 && num.length === 10) {
      res = comb10MulTo(this, num, out);
    } else if (len < 63) {
      res = smallMulTo(this, num, out);
    } else if (len < 1024) {
      res = bigMulTo(this, num, out);
    } else {
      res = jumboMulTo(this, num, out);
    }

    return res;
  };

  // Cooley-Tukey algorithm for FFT
  // slightly revisited to rely on looping instead of recursion

  function FFTM (x, y) {
    this.x = x;
    this.y = y;
  }

  FFTM.prototype.makeRBT = function makeRBT (N) {
    var t = new Array(N);
    var l = BN.prototype._countBits(N) - 1;
    for (var i = 0; i < N; i++) {
      t[i] = this.revBin(i, l, N);
    }

    return t;
  };

  // Returns binary-reversed representation of `x`
  FFTM.prototype.revBin = function revBin (x, l, N) {
    if (x === 0 || x === N - 1) return x;

    var rb = 0;
    for (var i = 0; i < l; i++) {
      rb |= (x & 1) << (l - i - 1);
      x >>= 1;
    }

    return rb;
  };

  // Performs "tweedling" phase, therefore 'emulating'
  // behaviour of the recursive algorithm
  FFTM.prototype.permute = function permute (rbt, rws, iws, rtws, itws, N) {
    for (var i = 0; i < N; i++) {
      rtws[i] = rws[rbt[i]];
      itws[i] = iws[rbt[i]];
    }
  };

  FFTM.prototype.transform = function transform (rws, iws, rtws, itws, N, rbt) {
    this.permute(rbt, rws, iws, rtws, itws, N);

    for (var s = 1; s < N; s <<= 1) {
      var l = s << 1;

      var rtwdf = Math.cos(2 * Math.PI / l);
      var itwdf = Math.sin(2 * Math.PI / l);

      for (var p = 0; p < N; p += l) {
        var rtwdf_ = rtwdf;
        var itwdf_ = itwdf;

        for (var j = 0; j < s; j++) {
          var re = rtws[p + j];
          var ie = itws[p + j];

          var ro = rtws[p + j + s];
          var io = itws[p + j + s];

          var rx = rtwdf_ * ro - itwdf_ * io;

          io = rtwdf_ * io + itwdf_ * ro;
          ro = rx;

          rtws[p + j] = re + ro;
          itws[p + j] = ie + io;

          rtws[p + j + s] = re - ro;
          itws[p + j + s] = ie - io;

          /* jshint maxdepth : false */
          if (j !== l) {
            rx = rtwdf * rtwdf_ - itwdf * itwdf_;

            itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
            rtwdf_ = rx;
          }
        }
      }
    }
  };

  FFTM.prototype.guessLen13b = function guessLen13b (n, m) {
    var N = Math.max(m, n) | 1;
    var odd = N & 1;
    var i = 0;
    for (N = N / 2 | 0; N; N = N >>> 1) {
      i++;
    }

    return 1 << i + 1 + odd;
  };

  FFTM.prototype.conjugate = function conjugate (rws, iws, N) {
    if (N <= 1) return;

    for (var i = 0; i < N / 2; i++) {
      var t = rws[i];

      rws[i] = rws[N - i - 1];
      rws[N - i - 1] = t;

      t = iws[i];

      iws[i] = -iws[N - i - 1];
      iws[N - i - 1] = -t;
    }
  };

  FFTM.prototype.normalize13b = function normalize13b (ws, N) {
    var carry = 0;
    for (var i = 0; i < N / 2; i++) {
      var w = Math.round(ws[2 * i + 1] / N) * 0x2000 +
        Math.round(ws[2 * i] / N) +
        carry;

      ws[i] = w & 0x3ffffff;

      if (w < 0x4000000) {
        carry = 0;
      } else {
        carry = w / 0x4000000 | 0;
      }
    }

    return ws;
  };

  FFTM.prototype.convert13b = function convert13b (ws, len, rws, N) {
    var carry = 0;
    for (var i = 0; i < len; i++) {
      carry = carry + (ws[i] | 0);

      rws[2 * i] = carry & 0x1fff; carry = carry >>> 13;
      rws[2 * i + 1] = carry & 0x1fff; carry = carry >>> 13;
    }

    // Pad with zeroes
    for (i = 2 * len; i < N; ++i) {
      rws[i] = 0;
    }

    assert(carry === 0);
    assert((carry & ~0x1fff) === 0);
  };

  FFTM.prototype.stub = function stub (N) {
    var ph = new Array(N);
    for (var i = 0; i < N; i++) {
      ph[i] = 0;
    }

    return ph;
  };

  FFTM.prototype.mulp = function mulp (x, y, out) {
    var N = 2 * this.guessLen13b(x.length, y.length);

    var rbt = this.makeRBT(N);

    var _ = this.stub(N);

    var rws = new Array(N);
    var rwst = new Array(N);
    var iwst = new Array(N);

    var nrws = new Array(N);
    var nrwst = new Array(N);
    var niwst = new Array(N);

    var rmws = out.words;
    rmws.length = N;

    this.convert13b(x.words, x.length, rws, N);
    this.convert13b(y.words, y.length, nrws, N);

    this.transform(rws, _, rwst, iwst, N, rbt);
    this.transform(nrws, _, nrwst, niwst, N, rbt);

    for (var i = 0; i < N; i++) {
      var rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
      iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
      rwst[i] = rx;
    }

    this.conjugate(rwst, iwst, N);
    this.transform(rwst, iwst, rmws, _, N, rbt);
    this.conjugate(rmws, _, N);
    this.normalize13b(rmws, N);

    out.negative = x.negative ^ y.negative;
    out.length = x.length + y.length;
    return out.strip();
  };

  // Multiply `this` by `num`
  BN.prototype.mul = function mul (num) {
    var out = new BN(null);
    out.words = new Array(this.length + num.length);
    return this.mulTo(num, out);
  };

  // Multiply employing FFT
  BN.prototype.mulf = function mulf (num) {
    var out = new BN(null);
    out.words = new Array(this.length + num.length);
    return jumboMulTo(this, num, out);
  };

  // In-place Multiplication
  BN.prototype.imul = function imul (num) {
    return this.clone().mulTo(num, this);
  };

  BN.prototype.imuln = function imuln (num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);

    // Carry
    var carry = 0;
    for (var i = 0; i < this.length; i++) {
      var w = (this.words[i] | 0) * num;
      var lo = (w & 0x3ffffff) + (carry & 0x3ffffff);
      carry >>= 26;
      carry += (w / 0x4000000) | 0;
      // NOTE: lo is 27bit maximum
      carry += lo >>> 26;
      this.words[i] = lo & 0x3ffffff;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }

    return this;
  };

  BN.prototype.muln = function muln (num) {
    return this.clone().imuln(num);
  };

  // `this` * `this`
  BN.prototype.sqr = function sqr () {
    return this.mul(this);
  };

  // `this` * `this` in-place
  BN.prototype.isqr = function isqr () {
    return this.imul(this.clone());
  };

  // Math.pow(`this`, `num`)
  BN.prototype.pow = function pow (num) {
    var w = toBitArray(num);
    if (w.length === 0) return new BN(1);

    // Skip leading zeroes
    var res = this;
    for (var i = 0; i < w.length; i++, res = res.sqr()) {
      if (w[i] !== 0) break;
    }

    if (++i < w.length) {
      for (var q = res.sqr(); i < w.length; i++, q = q.sqr()) {
        if (w[i] === 0) continue;

        res = res.mul(q);
      }
    }

    return res;
  };

  // Shift-left in-place
  BN.prototype.iushln = function iushln (bits) {
    assert(typeof bits === 'number' && bits >= 0);
    var r = bits % 26;
    var s = (bits - r) / 26;
    var carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);
    var i;

    if (r !== 0) {
      var carry = 0;

      for (i = 0; i < this.length; i++) {
        var newCarry = this.words[i] & carryMask;
        var c = ((this.words[i] | 0) - newCarry) << r;
        this.words[i] = c | carry;
        carry = newCarry >>> (26 - r);
      }

      if (carry) {
        this.words[i] = carry;
        this.length++;
      }
    }

    if (s !== 0) {
      for (i = this.length - 1; i >= 0; i--) {
        this.words[i + s] = this.words[i];
      }

      for (i = 0; i < s; i++) {
        this.words[i] = 0;
      }

      this.length += s;
    }

    return this.strip();
  };

  BN.prototype.ishln = function ishln (bits) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushln(bits);
  };

  // Shift-right in-place
  // NOTE: `hint` is a lowest bit before trailing zeroes
  // NOTE: if `extended` is present - it will be filled with destroyed bits
  BN.prototype.iushrn = function iushrn (bits, hint, extended) {
    assert(typeof bits === 'number' && bits >= 0);
    var h;
    if (hint) {
      h = (hint - (hint % 26)) / 26;
    } else {
      h = 0;
    }

    var r = bits % 26;
    var s = Math.min((bits - r) / 26, this.length);
    var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
    var maskedWords = extended;

    h -= s;
    h = Math.max(0, h);

    // Extended mode, copy masked part
    if (maskedWords) {
      for (var i = 0; i < s; i++) {
        maskedWords.words[i] = this.words[i];
      }
      maskedWords.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all
    } else if (this.length > s) {
      this.length -= s;
      for (i = 0; i < this.length; i++) {
        this.words[i] = this.words[i + s];
      }
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    var carry = 0;
    for (i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
      var word = this.words[i] | 0;
      this.words[i] = (carry << (26 - r)) | (word >>> r);
      carry = word & mask;
    }

    // Push carried bits as a mask
    if (maskedWords && carry !== 0) {
      maskedWords.words[maskedWords.length++] = carry;
    }

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this.strip();
  };

  BN.prototype.ishrn = function ishrn (bits, hint, extended) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushrn(bits, hint, extended);
  };

  // Shift-left
  BN.prototype.shln = function shln (bits) {
    return this.clone().ishln(bits);
  };

  BN.prototype.ushln = function ushln (bits) {
    return this.clone().iushln(bits);
  };

  // Shift-right
  BN.prototype.shrn = function shrn (bits) {
    return this.clone().ishrn(bits);
  };

  BN.prototype.ushrn = function ushrn (bits) {
    return this.clone().iushrn(bits);
  };

  // Test if n bit is set
  BN.prototype.testn = function testn (bit) {
    assert(typeof bit === 'number' && bit >= 0);
    var r = bit % 26;
    var s = (bit - r) / 26;
    var q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s) return false;

    // Check bit and return
    var w = this.words[s];

    return !!(w & q);
  };

  // Return only lowers bits of number (in-place)
  BN.prototype.imaskn = function imaskn (bits) {
    assert(typeof bits === 'number' && bits >= 0);
    var r = bits % 26;
    var s = (bits - r) / 26;

    assert(this.negative === 0, 'imaskn works only with positive numbers');

    if (r !== 0) {
      s++;
    }
    this.length = Math.min(s, this.length);

    if (r !== 0) {
      var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
      this.words[this.length - 1] &= mask;
    }

    return this.strip();
  };

  // Return only lowers bits of number
  BN.prototype.maskn = function maskn (bits) {
    return this.clone().imaskn(bits);
  };

  // Add plain number `num` to `this`
  BN.prototype.iaddn = function iaddn (num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);
    if (num < 0) return this.isubn(-num);

    // Possible sign change
    if (this.negative !== 0) {
      if (this.length === 1 && (this.words[0] | 0) < num) {
        this.words[0] = num - (this.words[0] | 0);
        this.negative = 0;
        return this;
      }

      this.negative = 0;
      this.isubn(num);
      this.negative = 1;
      return this;
    }

    // Add without checks
    return this._iaddn(num);
  };

  BN.prototype._iaddn = function _iaddn (num) {
    this.words[0] += num;

    // Carry
    for (var i = 0; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;
      if (i === this.length - 1) {
        this.words[i + 1] = 1;
      } else {
        this.words[i + 1]++;
      }
    }
    this.length = Math.max(this.length, i + 1);

    return this;
  };

  // Subtract plain number `num` from `this`
  BN.prototype.isubn = function isubn (num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);
    if (num < 0) return this.iaddn(-num);

    if (this.negative !== 0) {
      this.negative = 0;
      this.iaddn(num);
      this.negative = 1;
      return this;
    }

    this.words[0] -= num;

    if (this.length === 1 && this.words[0] < 0) {
      this.words[0] = -this.words[0];
      this.negative = 1;
    } else {
      // Carry
      for (var i = 0; i < this.length && this.words[i] < 0; i++) {
        this.words[i] += 0x4000000;
        this.words[i + 1] -= 1;
      }
    }

    return this.strip();
  };

  BN.prototype.addn = function addn (num) {
    return this.clone().iaddn(num);
  };

  BN.prototype.subn = function subn (num) {
    return this.clone().isubn(num);
  };

  BN.prototype.iabs = function iabs () {
    this.negative = 0;

    return this;
  };

  BN.prototype.abs = function abs () {
    return this.clone().iabs();
  };

  BN.prototype._ishlnsubmul = function _ishlnsubmul (num, mul, shift) {
    var len = num.length + shift;
    var i;

    this._expand(len);

    var w;
    var carry = 0;
    for (i = 0; i < num.length; i++) {
      w = (this.words[i + shift] | 0) + carry;
      var right = (num.words[i] | 0) * mul;
      w -= right & 0x3ffffff;
      carry = (w >> 26) - ((right / 0x4000000) | 0);
      this.words[i + shift] = w & 0x3ffffff;
    }
    for (; i < this.length - shift; i++) {
      w = (this.words[i + shift] | 0) + carry;
      carry = w >> 26;
      this.words[i + shift] = w & 0x3ffffff;
    }

    if (carry === 0) return this.strip();

    // Subtraction overflow
    assert(carry === -1);
    carry = 0;
    for (i = 0; i < this.length; i++) {
      w = -(this.words[i] | 0) + carry;
      carry = w >> 26;
      this.words[i] = w & 0x3ffffff;
    }
    this.negative = 1;

    return this.strip();
  };

  BN.prototype._wordDiv = function _wordDiv (num, mode) {
    var shift = this.length - num.length;

    var a = this.clone();
    var b = num;

    // Normalize
    var bhi = b.words[b.length - 1] | 0;
    var bhiBits = this._countBits(bhi);
    shift = 26 - bhiBits;
    if (shift !== 0) {
      b = b.ushln(shift);
      a.iushln(shift);
      bhi = b.words[b.length - 1] | 0;
    }

    // Initialize quotient
    var m = a.length - b.length;
    var q;

    if (mode !== 'mod') {
      q = new BN(null);
      q.length = m + 1;
      q.words = new Array(q.length);
      for (var i = 0; i < q.length; i++) {
        q.words[i] = 0;
      }
    }

    var diff = a.clone()._ishlnsubmul(b, 1, m);
    if (diff.negative === 0) {
      a = diff;
      if (q) {
        q.words[m] = 1;
      }
    }

    for (var j = m - 1; j >= 0; j--) {
      var qj = (a.words[b.length + j] | 0) * 0x4000000 +
        (a.words[b.length + j - 1] | 0);

      // NOTE: (qj / bhi) is (0x3ffffff * 0x4000000 + 0x3ffffff) / 0x2000000 max
      // (0x7ffffff)
      qj = Math.min((qj / bhi) | 0, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);
      while (a.negative !== 0) {
        qj--;
        a.negative = 0;
        a._ishlnsubmul(b, 1, j);
        if (!a.isZero()) {
          a.negative ^= 1;
        }
      }
      if (q) {
        q.words[j] = qj;
      }
    }
    if (q) {
      q.strip();
    }
    a.strip();

    // Denormalize
    if (mode !== 'div' && shift !== 0) {
      a.iushrn(shift);
    }

    return {
      div: q || null,
      mod: a
    };
  };

  // NOTE: 1) `mode` can be set to `mod` to request mod only,
  //       to `div` to request div only, or be absent to
  //       request both div & mod
  //       2) `positive` is true if unsigned mod is requested
  BN.prototype.divmod = function divmod (num, mode, positive) {
    assert(!num.isZero());

    if (this.isZero()) {
      return {
        div: new BN(0),
        mod: new BN(0)
      };
    }

    var div, mod, res;
    if (this.negative !== 0 && num.negative === 0) {
      res = this.neg().divmod(num, mode);

      if (mode !== 'mod') {
        div = res.div.neg();
      }

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.iadd(num);
        }
      }

      return {
        div: div,
        mod: mod
      };
    }

    if (this.negative === 0 && num.negative !== 0) {
      res = this.divmod(num.neg(), mode);

      if (mode !== 'mod') {
        div = res.div.neg();
      }

      return {
        div: div,
        mod: res.mod
      };
    }

    if ((this.negative & num.negative) !== 0) {
      res = this.neg().divmod(num.neg(), mode);

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.isub(num);
        }
      }

      return {
        div: res.div,
        mod: mod
      };
    }

    // Both numbers are positive at this point

    // Strip both numbers to approximate shift value
    if (num.length > this.length || this.cmp(num) < 0) {
      return {
        div: new BN(0),
        mod: this
      };
    }

    // Very short reduction
    if (num.length === 1) {
      if (mode === 'div') {
        return {
          div: this.divn(num.words[0]),
          mod: null
        };
      }

      if (mode === 'mod') {
        return {
          div: null,
          mod: new BN(this.modn(num.words[0]))
        };
      }

      return {
        div: this.divn(num.words[0]),
        mod: new BN(this.modn(num.words[0]))
      };
    }

    return this._wordDiv(num, mode);
  };

  // Find `this` / `num`
  BN.prototype.div = function div (num) {
    return this.divmod(num, 'div', false).div;
  };

  // Find `this` % `num`
  BN.prototype.mod = function mod (num) {
    return this.divmod(num, 'mod', false).mod;
  };

  BN.prototype.umod = function umod (num) {
    return this.divmod(num, 'mod', true).mod;
  };

  // Find Round(`this` / `num`)
  BN.prototype.divRound = function divRound (num) {
    var dm = this.divmod(num);

    // Fast case - exact division
    if (dm.mod.isZero()) return dm.div;

    var mod = dm.div.negative !== 0 ? dm.mod.isub(num) : dm.mod;

    var half = num.ushrn(1);
    var r2 = num.andln(1);
    var cmp = mod.cmp(half);

    // Round down
    if (cmp < 0 || r2 === 1 && cmp === 0) return dm.div;

    // Round up
    return dm.div.negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
  };

  BN.prototype.modn = function modn (num) {
    assert(num <= 0x3ffffff);
    var p = (1 << 26) % num;

    var acc = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      acc = (p * acc + (this.words[i] | 0)) % num;
    }

    return acc;
  };

  // In-place division by number
  BN.prototype.idivn = function idivn (num) {
    assert(num <= 0x3ffffff);

    var carry = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      var w = (this.words[i] | 0) + carry * 0x4000000;
      this.words[i] = (w / num) | 0;
      carry = w % num;
    }

    return this.strip();
  };

  BN.prototype.divn = function divn (num) {
    return this.clone().idivn(num);
  };

  BN.prototype.egcd = function egcd (p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    var x = this;
    var y = p.clone();

    if (x.negative !== 0) {
      x = x.umod(p);
    } else {
      x = x.clone();
    }

    // A * x + B * y = x
    var A = new BN(1);
    var B = new BN(0);

    // C * x + D * y = y
    var C = new BN(0);
    var D = new BN(1);

    var g = 0;

    while (x.isEven() && y.isEven()) {
      x.iushrn(1);
      y.iushrn(1);
      ++g;
    }

    var yp = y.clone();
    var xp = x.clone();

    while (!x.isZero()) {
      for (var i = 0, im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        x.iushrn(i);
        while (i-- > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp);
            B.isub(xp);
          }

          A.iushrn(1);
          B.iushrn(1);
        }
      }

      for (var j = 0, jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        y.iushrn(j);
        while (j-- > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp);
            D.isub(xp);
          }

          C.iushrn(1);
          D.iushrn(1);
        }
      }

      if (x.cmp(y) >= 0) {
        x.isub(y);
        A.isub(C);
        B.isub(D);
      } else {
        y.isub(x);
        C.isub(A);
        D.isub(B);
      }
    }

    return {
      a: C,
      b: D,
      gcd: y.iushln(g)
    };
  };

  // This is reduced incarnation of the binary EEA
  // above, designated to invert members of the
  // _prime_ fields F(p) at a maximal speed
  BN.prototype._invmp = function _invmp (p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    var a = this;
    var b = p.clone();

    if (a.negative !== 0) {
      a = a.umod(p);
    } else {
      a = a.clone();
    }

    var x1 = new BN(1);
    var x2 = new BN(0);

    var delta = b.clone();

    while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
      for (var i = 0, im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        a.iushrn(i);
        while (i-- > 0) {
          if (x1.isOdd()) {
            x1.iadd(delta);
          }

          x1.iushrn(1);
        }
      }

      for (var j = 0, jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        b.iushrn(j);
        while (j-- > 0) {
          if (x2.isOdd()) {
            x2.iadd(delta);
          }

          x2.iushrn(1);
        }
      }

      if (a.cmp(b) >= 0) {
        a.isub(b);
        x1.isub(x2);
      } else {
        b.isub(a);
        x2.isub(x1);
      }
    }

    var res;
    if (a.cmpn(1) === 0) {
      res = x1;
    } else {
      res = x2;
    }

    if (res.cmpn(0) < 0) {
      res.iadd(p);
    }

    return res;
  };

  BN.prototype.gcd = function gcd (num) {
    if (this.isZero()) return num.abs();
    if (num.isZero()) return this.abs();

    var a = this.clone();
    var b = num.clone();
    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two
    for (var shift = 0; a.isEven() && b.isEven(); shift++) {
      a.iushrn(1);
      b.iushrn(1);
    }

    do {
      while (a.isEven()) {
        a.iushrn(1);
      }
      while (b.isEven()) {
        b.iushrn(1);
      }

      var r = a.cmp(b);
      if (r < 0) {
        // Swap `a` and `b` to make `a` always bigger than `b`
        var t = a;
        a = b;
        b = t;
      } else if (r === 0 || b.cmpn(1) === 0) {
        break;
      }

      a.isub(b);
    } while (true);

    return b.iushln(shift);
  };

  // Invert number in the field F(num)
  BN.prototype.invm = function invm (num) {
    return this.egcd(num).a.umod(num);
  };

  BN.prototype.isEven = function isEven () {
    return (this.words[0] & 1) === 0;
  };

  BN.prototype.isOdd = function isOdd () {
    return (this.words[0] & 1) === 1;
  };

  // And first word and num
  BN.prototype.andln = function andln (num) {
    return this.words[0] & num;
  };

  // Increment at the bit position in-line
  BN.prototype.bincn = function bincn (bit) {
    assert(typeof bit === 'number');
    var r = bit % 26;
    var s = (bit - r) / 26;
    var q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s) {
      this._expand(s + 1);
      this.words[s] |= q;
      return this;
    }

    // Add bit and propagate, if needed
    var carry = q;
    for (var i = s; carry !== 0 && i < this.length; i++) {
      var w = this.words[i] | 0;
      w += carry;
      carry = w >>> 26;
      w &= 0x3ffffff;
      this.words[i] = w;
    }
    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }
    return this;
  };

  BN.prototype.isZero = function isZero () {
    return this.length === 1 && this.words[0] === 0;
  };

  BN.prototype.cmpn = function cmpn (num) {
    var negative = num < 0;

    if (this.negative !== 0 && !negative) return -1;
    if (this.negative === 0 && negative) return 1;

    this.strip();

    var res;
    if (this.length > 1) {
      res = 1;
    } else {
      if (negative) {
        num = -num;
      }

      assert(num <= 0x3ffffff, 'Number is too big');

      var w = this.words[0] | 0;
      res = w === num ? 0 : w < num ? -1 : 1;
    }
    if (this.negative !== 0) return -res | 0;
    return res;
  };

  // Compare two numbers and return:
  // 1 - if `this` > `num`
  // 0 - if `this` == `num`
  // -1 - if `this` < `num`
  BN.prototype.cmp = function cmp (num) {
    if (this.negative !== 0 && num.negative === 0) return -1;
    if (this.negative === 0 && num.negative !== 0) return 1;

    var res = this.ucmp(num);
    if (this.negative !== 0) return -res | 0;
    return res;
  };

  // Unsigned comparison
  BN.prototype.ucmp = function ucmp (num) {
    // At this point both numbers have the same sign
    if (this.length > num.length) return 1;
    if (this.length < num.length) return -1;

    var res = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      var a = this.words[i] | 0;
      var b = num.words[i] | 0;

      if (a === b) continue;
      if (a < b) {
        res = -1;
      } else if (a > b) {
        res = 1;
      }
      break;
    }
    return res;
  };

  BN.prototype.gtn = function gtn (num) {
    return this.cmpn(num) === 1;
  };

  BN.prototype.gt = function gt (num) {
    return this.cmp(num) === 1;
  };

  BN.prototype.gten = function gten (num) {
    return this.cmpn(num) >= 0;
  };

  BN.prototype.gte = function gte (num) {
    return this.cmp(num) >= 0;
  };

  BN.prototype.ltn = function ltn (num) {
    return this.cmpn(num) === -1;
  };

  BN.prototype.lt = function lt (num) {
    return this.cmp(num) === -1;
  };

  BN.prototype.lten = function lten (num) {
    return this.cmpn(num) <= 0;
  };

  BN.prototype.lte = function lte (num) {
    return this.cmp(num) <= 0;
  };

  BN.prototype.eqn = function eqn (num) {
    return this.cmpn(num) === 0;
  };

  BN.prototype.eq = function eq (num) {
    return this.cmp(num) === 0;
  };

  //
  // A reduce context, could be using montgomery or something better, depending
  // on the `m` itself.
  //
  BN.red = function red (num) {
    return new Red(num);
  };

  BN.prototype.toRed = function toRed (ctx) {
    assert(!this.red, 'Already a number in reduction context');
    assert(this.negative === 0, 'red works only with positives');
    return ctx.convertTo(this)._forceRed(ctx);
  };

  BN.prototype.fromRed = function fromRed () {
    assert(this.red, 'fromRed works only with numbers in reduction context');
    return this.red.convertFrom(this);
  };

  BN.prototype._forceRed = function _forceRed (ctx) {
    this.red = ctx;
    return this;
  };

  BN.prototype.forceRed = function forceRed (ctx) {
    assert(!this.red, 'Already a number in reduction context');
    return this._forceRed(ctx);
  };

  BN.prototype.redAdd = function redAdd (num) {
    assert(this.red, 'redAdd works only with red numbers');
    return this.red.add(this, num);
  };

  BN.prototype.redIAdd = function redIAdd (num) {
    assert(this.red, 'redIAdd works only with red numbers');
    return this.red.iadd(this, num);
  };

  BN.prototype.redSub = function redSub (num) {
    assert(this.red, 'redSub works only with red numbers');
    return this.red.sub(this, num);
  };

  BN.prototype.redISub = function redISub (num) {
    assert(this.red, 'redISub works only with red numbers');
    return this.red.isub(this, num);
  };

  BN.prototype.redShl = function redShl (num) {
    assert(this.red, 'redShl works only with red numbers');
    return this.red.shl(this, num);
  };

  BN.prototype.redMul = function redMul (num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.mul(this, num);
  };

  BN.prototype.redIMul = function redIMul (num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.imul(this, num);
  };

  BN.prototype.redSqr = function redSqr () {
    assert(this.red, 'redSqr works only with red numbers');
    this.red._verify1(this);
    return this.red.sqr(this);
  };

  BN.prototype.redISqr = function redISqr () {
    assert(this.red, 'redISqr works only with red numbers');
    this.red._verify1(this);
    return this.red.isqr(this);
  };

  // Square root over p
  BN.prototype.redSqrt = function redSqrt () {
    assert(this.red, 'redSqrt works only with red numbers');
    this.red._verify1(this);
    return this.red.sqrt(this);
  };

  BN.prototype.redInvm = function redInvm () {
    assert(this.red, 'redInvm works only with red numbers');
    this.red._verify1(this);
    return this.red.invm(this);
  };

  // Return negative clone of `this` % `red modulo`
  BN.prototype.redNeg = function redNeg () {
    assert(this.red, 'redNeg works only with red numbers');
    this.red._verify1(this);
    return this.red.neg(this);
  };

  BN.prototype.redPow = function redPow (num) {
    assert(this.red && !num.red, 'redPow(normalNum)');
    this.red._verify1(this);
    return this.red.pow(this, num);
  };

  // Prime numbers with efficient reduction
  var primes = {
    k256: null,
    p224: null,
    p192: null,
    p25519: null
  };

  // Pseudo-Mersenne prime
  function MPrime (name, p) {
    // P = 2 ^ N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.k = new BN(1).iushln(this.n).isub(this.p);

    this.tmp = this._tmp();
  }

  MPrime.prototype._tmp = function _tmp () {
    var tmp = new BN(null);
    tmp.words = new Array(Math.ceil(this.n / 13));
    return tmp;
  };

  MPrime.prototype.ireduce = function ireduce (num) {
    // Assumes that `num` is less than `P^2`
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    var r = num;
    var rlen;

    do {
      this.split(r, this.tmp);
      r = this.imulK(r);
      r = r.iadd(this.tmp);
      rlen = r.bitLength();
    } while (rlen > this.n);

    var cmp = rlen < this.n ? -1 : r.ucmp(this.p);
    if (cmp === 0) {
      r.words[0] = 0;
      r.length = 1;
    } else if (cmp > 0) {
      r.isub(this.p);
    } else {
      r.strip();
    }

    return r;
  };

  MPrime.prototype.split = function split (input, out) {
    input.iushrn(this.n, 0, out);
  };

  MPrime.prototype.imulK = function imulK (num) {
    return num.imul(this.k);
  };

  function K256 () {
    MPrime.call(
      this,
      'k256',
      'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f');
  }
  inherits(K256, MPrime);

  K256.prototype.split = function split (input, output) {
    // 256 = 9 * 26 + 22
    var mask = 0x3fffff;

    var outLen = Math.min(input.length, 9);
    for (var i = 0; i < outLen; i++) {
      output.words[i] = input.words[i];
    }
    output.length = outLen;

    if (input.length <= 9) {
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs
    var prev = input.words[9];
    output.words[output.length++] = prev & mask;

    for (i = 10; i < input.length; i++) {
      var next = input.words[i] | 0;
      input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
      prev = next;
    }
    prev >>>= 22;
    input.words[i - 10] = prev;
    if (prev === 0 && input.length > 10) {
      input.length -= 10;
    } else {
      input.length -= 9;
    }
  };

  K256.prototype.imulK = function imulK (num) {
    // K = 0x1000003d1 = [ 0x40, 0x3d1 ]
    num.words[num.length] = 0;
    num.words[num.length + 1] = 0;
    num.length += 2;

    // bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    var lo = 0;
    for (var i = 0; i < num.length; i++) {
      var w = num.words[i] | 0;
      lo += w * 0x3d1;
      num.words[i] = lo & 0x3ffffff;
      lo = w * 0x40 + ((lo / 0x4000000) | 0);
    }

    // Fast length reduction
    if (num.words[num.length - 1] === 0) {
      num.length--;
      if (num.words[num.length - 1] === 0) {
        num.length--;
      }
    }
    return num;
  };

  function P224 () {
    MPrime.call(
      this,
      'p224',
      'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001');
  }
  inherits(P224, MPrime);

  function P192 () {
    MPrime.call(
      this,
      'p192',
      'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff');
  }
  inherits(P192, MPrime);

  function P25519 () {
    // 2 ^ 255 - 19
    MPrime.call(
      this,
      '25519',
      '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed');
  }
  inherits(P25519, MPrime);

  P25519.prototype.imulK = function imulK (num) {
    // K = 0x13
    var carry = 0;
    for (var i = 0; i < num.length; i++) {
      var hi = (num.words[i] | 0) * 0x13 + carry;
      var lo = hi & 0x3ffffff;
      hi >>>= 26;

      num.words[i] = lo;
      carry = hi;
    }
    if (carry !== 0) {
      num.words[num.length++] = carry;
    }
    return num;
  };

  // Exported mostly for testing purposes, use plain name instead
  BN._prime = function prime (name) {
    // Cached version of prime
    if (primes[name]) return primes[name];

    var prime;
    if (name === 'k256') {
      prime = new K256();
    } else if (name === 'p224') {
      prime = new P224();
    } else if (name === 'p192') {
      prime = new P192();
    } else if (name === 'p25519') {
      prime = new P25519();
    } else {
      throw new Error('Unknown prime ' + name);
    }
    primes[name] = prime;

    return prime;
  };

  //
  // Base reduction engine
  //
  function Red (m) {
    if (typeof m === 'string') {
      var prime = BN._prime(m);
      this.m = prime.p;
      this.prime = prime;
    } else {
      assert(m.gtn(1), 'modulus must be greater than 1');
      this.m = m;
      this.prime = null;
    }
  }

  Red.prototype._verify1 = function _verify1 (a) {
    assert(a.negative === 0, 'red works only with positives');
    assert(a.red, 'red works only with red numbers');
  };

  Red.prototype._verify2 = function _verify2 (a, b) {
    assert((a.negative | b.negative) === 0, 'red works only with positives');
    assert(a.red && a.red === b.red,
      'red works only with red numbers');
  };

  Red.prototype.imod = function imod (a) {
    if (this.prime) return this.prime.ireduce(a)._forceRed(this);
    return a.umod(this.m)._forceRed(this);
  };

  Red.prototype.neg = function neg (a) {
    if (a.isZero()) {
      return a.clone();
    }

    return this.m.sub(a)._forceRed(this);
  };

  Red.prototype.add = function add (a, b) {
    this._verify2(a, b);

    var res = a.add(b);
    if (res.cmp(this.m) >= 0) {
      res.isub(this.m);
    }
    return res._forceRed(this);
  };

  Red.prototype.iadd = function iadd (a, b) {
    this._verify2(a, b);

    var res = a.iadd(b);
    if (res.cmp(this.m) >= 0) {
      res.isub(this.m);
    }
    return res;
  };

  Red.prototype.sub = function sub (a, b) {
    this._verify2(a, b);

    var res = a.sub(b);
    if (res.cmpn(0) < 0) {
      res.iadd(this.m);
    }
    return res._forceRed(this);
  };

  Red.prototype.isub = function isub (a, b) {
    this._verify2(a, b);

    var res = a.isub(b);
    if (res.cmpn(0) < 0) {
      res.iadd(this.m);
    }
    return res;
  };

  Red.prototype.shl = function shl (a, num) {
    this._verify1(a);
    return this.imod(a.ushln(num));
  };

  Red.prototype.imul = function imul (a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  };

  Red.prototype.mul = function mul (a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  };

  Red.prototype.isqr = function isqr (a) {
    return this.imul(a, a.clone());
  };

  Red.prototype.sqr = function sqr (a) {
    return this.mul(a, a);
  };

  Red.prototype.sqrt = function sqrt (a) {
    if (a.isZero()) return a.clone();

    var mod3 = this.m.andln(3);
    assert(mod3 % 2 === 1);

    // Fast case
    if (mod3 === 3) {
      var pow = this.m.add(new BN(1)).iushrn(2);
      return this.pow(a, pow);
    }

    // Tonelli-Shanks algorithm (Totally unoptimized and slow)
    //
    // Find Q and S, that Q * 2 ^ S = (P - 1)
    var q = this.m.subn(1);
    var s = 0;
    while (!q.isZero() && q.andln(1) === 0) {
      s++;
      q.iushrn(1);
    }
    assert(!q.isZero());

    var one = new BN(1).toRed(this);
    var nOne = one.redNeg();

    // Find quadratic non-residue
    // NOTE: Max is such because of generalized Riemann hypothesis.
    var lpow = this.m.subn(1).iushrn(1);
    var z = this.m.bitLength();
    z = new BN(2 * z * z).toRed(this);

    while (this.pow(z, lpow).cmp(nOne) !== 0) {
      z.redIAdd(nOne);
    }

    var c = this.pow(z, q);
    var r = this.pow(a, q.addn(1).iushrn(1));
    var t = this.pow(a, q);
    var m = s;
    while (t.cmp(one) !== 0) {
      var tmp = t;
      for (var i = 0; tmp.cmp(one) !== 0; i++) {
        tmp = tmp.redSqr();
      }
      assert(i < m);
      var b = this.pow(c, new BN(1).iushln(m - i - 1));

      r = r.redMul(b);
      c = b.redSqr();
      t = t.redMul(c);
      m = i;
    }

    return r;
  };

  Red.prototype.invm = function invm (a) {
    var inv = a._invmp(this.m);
    if (inv.negative !== 0) {
      inv.negative = 0;
      return this.imod(inv).redNeg();
    } else {
      return this.imod(inv);
    }
  };

  Red.prototype.pow = function pow (a, num) {
    if (num.isZero()) return new BN(1);
    if (num.cmpn(1) === 0) return a.clone();

    var windowSize = 4;
    var wnd = new Array(1 << windowSize);
    wnd[0] = new BN(1).toRed(this);
    wnd[1] = a;
    for (var i = 2; i < wnd.length; i++) {
      wnd[i] = this.mul(wnd[i - 1], a);
    }

    var res = wnd[0];
    var current = 0;
    var currentLen = 0;
    var start = num.bitLength() % 26;
    if (start === 0) {
      start = 26;
    }

    for (i = num.length - 1; i >= 0; i--) {
      var word = num.words[i];
      for (var j = start - 1; j >= 0; j--) {
        var bit = (word >> j) & 1;
        if (res !== wnd[0]) {
          res = this.sqr(res);
        }

        if (bit === 0 && current === 0) {
          currentLen = 0;
          continue;
        }

        current <<= 1;
        current |= bit;
        currentLen++;
        if (currentLen !== windowSize && (i !== 0 || j !== 0)) continue;

        res = this.mul(res, wnd[current]);
        currentLen = 0;
        current = 0;
      }
      start = 26;
    }

    return res;
  };

  Red.prototype.convertTo = function convertTo (num) {
    var r = num.umod(this.m);

    return r === num ? r.clone() : r;
  };

  Red.prototype.convertFrom = function convertFrom (num) {
    var res = num.clone();
    res.red = null;
    return res;
  };

  //
  // Montgomery method engine
  //

  BN.mont = function mont (num) {
    return new Mont(num);
  };

  function Mont (m) {
    Red.call(this, m);

    this.shift = this.m.bitLength();
    if (this.shift % 26 !== 0) {
      this.shift += 26 - (this.shift % 26);
    }

    this.r = new BN(1).iushln(this.shift);
    this.r2 = this.imod(this.r.sqr());
    this.rinv = this.r._invmp(this.m);

    this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
    this.minv = this.minv.umod(this.r);
    this.minv = this.r.sub(this.minv);
  }
  inherits(Mont, Red);

  Mont.prototype.convertTo = function convertTo (num) {
    return this.imod(num.ushln(this.shift));
  };

  Mont.prototype.convertFrom = function convertFrom (num) {
    var r = this.imod(num.mul(this.rinv));
    r.red = null;
    return r;
  };

  Mont.prototype.imul = function imul (a, b) {
    if (a.isZero() || b.isZero()) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    var t = a.imul(b);
    var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    var u = t.isub(c).iushrn(this.shift);
    var res = u;

    if (u.cmp(this.m) >= 0) {
      res = u.isub(this.m);
    } else if (u.cmpn(0) < 0) {
      res = u.iadd(this.m);
    }

    return res._forceRed(this);
  };

  Mont.prototype.mul = function mul (a, b) {
    if (a.isZero() || b.isZero()) return new BN(0)._forceRed(this);

    var t = a.mul(b);
    var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    var u = t.isub(c).iushrn(this.shift);
    var res = u;
    if (u.cmp(this.m) >= 0) {
      res = u.isub(this.m);
    } else if (u.cmpn(0) < 0) {
      res = u.iadd(this.m);
    }

    return res._forceRed(this);
  };

  Mont.prototype.invm = function invm (a) {
    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    var res = this.imod(a._invmp(this.m).mul(this.r2));
    return res._forceRed(this);
  };
})(typeof module === 'undefined' || module, this);

},{}],22:[function(require,module,exports){
var r;

module.exports = function rand(len) {
  if (!r)
    r = new Rand(null);

  return r.generate(len);
};

function Rand(rand) {
  this.rand = rand;
}
module.exports.Rand = Rand;

Rand.prototype.generate = function generate(len) {
  return this._rand(len);
};

if (typeof window === 'object') {
  if (window.crypto && window.crypto.getRandomValues) {
    // Modern browsers
    Rand.prototype._rand = function _rand(n) {
      var arr = new Uint8Array(n);
      window.crypto.getRandomValues(arr);
      return arr;
    };
  } else if (window.msCrypto && window.msCrypto.getRandomValues) {
    // IE
    Rand.prototype._rand = function _rand(n) {
      var arr = new Uint8Array(n);
      window.msCrypto.getRandomValues(arr);
      return arr;
    };
  } else {
    // Old junk
    Rand.prototype._rand = function() {
      throw new Error('Not implemented yet');
    };
  }
} else {
  // Node.js or Web worker
  try {
    var crypto = require('cry' + 'pto');

    Rand.prototype._rand = function _rand(n) {
      return crypto.randomBytes(n);
    };
  } catch (e) {
    // Emulate crypto API using randy
    Rand.prototype._rand = function _rand(n) {
      var res = new Uint8Array(n);
      for (var i = 0; i < res.length; i++)
        res[i] = this.rand.getByte();
      return res;
    };
  }
}

},{}],23:[function(require,module,exports){
(function (global){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')
var isArray = require('isarray')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * Due to various browser bugs, sometimes the Object implementation will be used even
 * when the browser supports typed arrays.
 *
 * Note:
 *
 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
 *
 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
 *
 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
 *     incorrect length in some situations.

 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
 * get the Object implementation, which is slower but behaves correctly.
 */
Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
  ? global.TYPED_ARRAY_SUPPORT
  : typedArraySupport()

/*
 * Export kMaxLength after typed array support is determined.
 */
exports.kMaxLength = kMaxLength()

function typedArraySupport () {
  try {
    var arr = new Uint8Array(1)
    arr.foo = function () { return 42 }
    return arr.foo() === 42 && // typed array instances can be augmented
        typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
        arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
  } catch (e) {
    return false
  }
}

function kMaxLength () {
  return Buffer.TYPED_ARRAY_SUPPORT
    ? 0x7fffffff
    : 0x3fffffff
}

function createBuffer (that, length) {
  if (kMaxLength() < length) {
    throw new RangeError('Invalid typed array length')
  }
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = new Uint8Array(length)
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    if (that === null) {
      that = new Buffer(length)
    }
    that.length = length
  }

  return that
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
    return new Buffer(arg, encodingOrOffset, length)
  }

  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(this, arg)
  }
  return from(this, arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

// TODO: Legacy, not needed anymore. Remove in next major version.
Buffer._augment = function (arr) {
  arr.__proto__ = Buffer.prototype
  return arr
}

function from (that, value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return fromArrayBuffer(that, value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(that, value, encodingOrOffset)
  }

  return fromObject(that, value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(null, value, encodingOrOffset, length)
}

if (Buffer.TYPED_ARRAY_SUPPORT) {
  Buffer.prototype.__proto__ = Uint8Array.prototype
  Buffer.__proto__ = Uint8Array
  if (typeof Symbol !== 'undefined' && Symbol.species &&
      Buffer[Symbol.species] === Buffer) {
    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true
    })
  }
}

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  }
}

function alloc (that, size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(that, size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(that, size).fill(fill, encoding)
      : createBuffer(that, size).fill(fill)
  }
  return createBuffer(that, size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(null, size, fill, encoding)
}

function allocUnsafe (that, size) {
  assertSize(size)
  that = createBuffer(that, size < 0 ? 0 : checked(size) | 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) {
    for (var i = 0; i < size; i++) {
      that[i] = 0
    }
  }
  return that
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(null, size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(null, size)
}

function fromString (that, string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  that = createBuffer(that, length)

  that.write(string, encoding)
  return that
}

function fromArrayLike (that, array) {
  var length = checked(array.length) | 0
  that = createBuffer(that, length)
  for (var i = 0; i < length; i += 1) {
    that[i] = array[i] & 255
  }
  return that
}

function fromArrayBuffer (that, array, byteOffset, length) {
  array.byteLength // this throws if `array` is not a valid ArrayBuffer

  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  if (length === undefined) {
    array = new Uint8Array(array, byteOffset)
  } else {
    array = new Uint8Array(array, byteOffset, length)
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = array
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    that = fromArrayLike(that, array)
  }
  return that
}

function fromObject (that, obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    that = createBuffer(that, len)

    if (that.length === 0) {
      return that
    }

    obj.copy(that, 0, 0, len)
    return that
  }

  if (obj) {
    if ((typeof ArrayBuffer !== 'undefined' &&
        obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
      if (typeof obj.length !== 'number' || isnan(obj.length)) {
        return createBuffer(that, 0)
      }
      return fromArrayLike(that, obj)
    }

    if (obj.type === 'Buffer' && isArray(obj.data)) {
      return fromArrayLike(that, obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < kMaxLength` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= kMaxLength()) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + kMaxLength().toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return !!(b != null && b._isBuffer)
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'raw':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; i++) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; i++) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
      (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'binary':
      // Deprecated
      case 'raw':
      case 'raws':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'binary':
        return binarySlice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
// Buffer instances.
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length | 0
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

function arrayIndexOf (arr, val, byteOffset, encoding) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var foundIndex = -1
  for (var i = 0; byteOffset + i < arrLength; i++) {
    if (read(arr, byteOffset + i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
      if (foundIndex === -1) foundIndex = i
      if (i - foundIndex + 1 === valLength) return (byteOffset + foundIndex) * indexSize
    } else {
      if (foundIndex !== -1) i -= i - foundIndex
      foundIndex = -1
    }
  }
  return -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset >>= 0

  if (this.length === 0) return -1
  if (byteOffset >= this.length) return -1

  // Negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = Math.max(this.length + byteOffset, 0)

  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  if (Buffer.isBuffer(val)) {
    // special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(this, val, byteOffset, encoding)
  }
  if (typeof val === 'number') {
    if (Buffer.TYPED_ARRAY_SUPPORT && Uint8Array.prototype.indexOf === 'function') {
      return Uint8Array.prototype.indexOf.call(this, val, byteOffset)
    }
    return arrayIndexOf(this, [ val ], byteOffset, encoding)
  }

  throw new TypeError('val must be string, number or Buffer')
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new Error('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; i++) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (isNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function binaryWrite (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset | 0
    if (isFinite(length)) {
      length = length | 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  // legacy write(string, encoding, offset, length) - remove in v0.13
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'binary':
        return binaryWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function binarySlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; i++) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    newBuf = this.subarray(start, end)
    newBuf.__proto__ = Buffer.prototype
  } else {
    var sliceLen = end - start
    newBuf = new Buffer(sliceLen, undefined)
    for (var i = 0; i < sliceLen; i++) {
      newBuf[i] = this[i + start]
    }
  }

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  this[offset] = (value & 0xff)
  return offset + 1
}

function objectWriteUInt16 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; i++) {
    buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
      (littleEndian ? i : 1 - i) * 8
  }
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

function objectWriteUInt32 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffffffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; i++) {
    buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
  }
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset + 3] = (value >>> 24)
    this[offset + 2] = (value >>> 16)
    this[offset + 1] = (value >>> 8)
    this[offset] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
    this[offset + 2] = (value >>> 16)
    this[offset + 3] = (value >>> 24)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; i--) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
    // ascending copy from start
    for (i = 0; i < len; i++) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; i++) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : utf8ToBytes(new Buffer(val, encoding).toString())
    var len = bytes.length
    for (i = 0; i < end - start; i++) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = stringtrim(str).replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function stringtrim (str) {
  if (str.trim) return str.trim()
  return str.replace(/^\s+|\s+$/g, '')
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; i++) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; i++) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

function isnan (val) {
  return val !== val // eslint-disable-line no-self-compare
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"base64-js":20,"ieee754":47,"isarray":50}],24:[function(require,module,exports){
'use strict';

var elliptic = exports;

elliptic.version = require('../package.json').version;
elliptic.utils = require('./elliptic/utils');
elliptic.rand = require('brorand');
elliptic.hmacDRBG = require('./elliptic/hmac-drbg');
elliptic.curve = require('./elliptic/curve');
elliptic.curves = require('./elliptic/curves');

// Protocols
elliptic.ec = require('./elliptic/ec');
elliptic.eddsa = require('./elliptic/eddsa');

},{"../package.json":40,"./elliptic/curve":27,"./elliptic/curves":30,"./elliptic/ec":31,"./elliptic/eddsa":34,"./elliptic/hmac-drbg":37,"./elliptic/utils":39,"brorand":22}],25:[function(require,module,exports){
'use strict';

var BN = require('bn.js');
var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var getNAF = utils.getNAF;
var getJSF = utils.getJSF;
var assert = utils.assert;

function BaseCurve(type, conf) {
  this.type = type;
  this.p = new BN(conf.p, 16);

  // Use Montgomery, when there is no fast reduction for the prime
  this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);

  // Useful for many curves
  this.zero = new BN(0).toRed(this.red);
  this.one = new BN(1).toRed(this.red);
  this.two = new BN(2).toRed(this.red);

  // Curve configuration, optional
  this.n = conf.n && new BN(conf.n, 16);
  this.g = conf.g && this.pointFromJSON(conf.g, conf.gRed);

  // Temporary arrays
  this._wnafT1 = new Array(4);
  this._wnafT2 = new Array(4);
  this._wnafT3 = new Array(4);
  this._wnafT4 = new Array(4);
}
module.exports = BaseCurve;

BaseCurve.prototype.point = function point() {
  throw new Error('Not implemented');
};

BaseCurve.prototype.validate = function validate() {
  throw new Error('Not implemented');
};

BaseCurve.prototype._fixedNafMul = function _fixedNafMul(p, k) {
  assert(p.precomputed);
  var doubles = p._getDoubles();

  var naf = getNAF(k, 1);
  var I = (1 << (doubles.step + 1)) - (doubles.step % 2 === 0 ? 2 : 1);
  I /= 3;

  // Translate into more windowed form
  var repr = [];
  for (var j = 0; j < naf.length; j += doubles.step) {
    var nafW = 0;
    for (var k = j + doubles.step - 1; k >= j; k--)
      nafW = (nafW << 1) + naf[k];
    repr.push(nafW);
  }

  var a = this.jpoint(null, null, null);
  var b = this.jpoint(null, null, null);
  for (var i = I; i > 0; i--) {
    for (var j = 0; j < repr.length; j++) {
      var nafW = repr[j];
      if (nafW === i)
        b = b.mixedAdd(doubles.points[j]);
      else if (nafW === -i)
        b = b.mixedAdd(doubles.points[j].neg());
    }
    a = a.add(b);
  }
  return a.toP();
};

BaseCurve.prototype._wnafMul = function _wnafMul(p, k) {
  var w = 4;

  // Precompute window
  var nafPoints = p._getNAFPoints(w);
  w = nafPoints.wnd;
  var wnd = nafPoints.points;

  // Get NAF form
  var naf = getNAF(k, w);

  // Add `this`*(N+1) for every w-NAF index
  var acc = this.jpoint(null, null, null);
  for (var i = naf.length - 1; i >= 0; i--) {
    // Count zeroes
    for (var k = 0; i >= 0 && naf[i] === 0; i--)
      k++;
    if (i >= 0)
      k++;
    acc = acc.dblp(k);

    if (i < 0)
      break;
    var z = naf[i];
    assert(z !== 0);
    if (p.type === 'affine') {
      // J +- P
      if (z > 0)
        acc = acc.mixedAdd(wnd[(z - 1) >> 1]);
      else
        acc = acc.mixedAdd(wnd[(-z - 1) >> 1].neg());
    } else {
      // J +- J
      if (z > 0)
        acc = acc.add(wnd[(z - 1) >> 1]);
      else
        acc = acc.add(wnd[(-z - 1) >> 1].neg());
    }
  }
  return p.type === 'affine' ? acc.toP() : acc;
};

BaseCurve.prototype._wnafMulAdd = function _wnafMulAdd(defW,
                                                       points,
                                                       coeffs,
                                                       len) {
  var wndWidth = this._wnafT1;
  var wnd = this._wnafT2;
  var naf = this._wnafT3;

  // Fill all arrays
  var max = 0;
  for (var i = 0; i < len; i++) {
    var p = points[i];
    var nafPoints = p._getNAFPoints(defW);
    wndWidth[i] = nafPoints.wnd;
    wnd[i] = nafPoints.points;
  }

  // Comb small window NAFs
  for (var i = len - 1; i >= 1; i -= 2) {
    var a = i - 1;
    var b = i;
    if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
      naf[a] = getNAF(coeffs[a], wndWidth[a]);
      naf[b] = getNAF(coeffs[b], wndWidth[b]);
      max = Math.max(naf[a].length, max);
      max = Math.max(naf[b].length, max);
      continue;
    }

    var comb = [
      points[a], /* 1 */
      null, /* 3 */
      null, /* 5 */
      points[b] /* 7 */
    ];

    // Try to avoid Projective points, if possible
    if (points[a].y.cmp(points[b].y) === 0) {
      comb[1] = points[a].add(points[b]);
      comb[2] = points[a].toJ().mixedAdd(points[b].neg());
    } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
      comb[1] = points[a].toJ().mixedAdd(points[b]);
      comb[2] = points[a].add(points[b].neg());
    } else {
      comb[1] = points[a].toJ().mixedAdd(points[b]);
      comb[2] = points[a].toJ().mixedAdd(points[b].neg());
    }

    var index = [
      -3, /* -1 -1 */
      -1, /* -1 0 */
      -5, /* -1 1 */
      -7, /* 0 -1 */
      0, /* 0 0 */
      7, /* 0 1 */
      5, /* 1 -1 */
      1, /* 1 0 */
      3  /* 1 1 */
    ];

    var jsf = getJSF(coeffs[a], coeffs[b]);
    max = Math.max(jsf[0].length, max);
    naf[a] = new Array(max);
    naf[b] = new Array(max);
    for (var j = 0; j < max; j++) {
      var ja = jsf[0][j] | 0;
      var jb = jsf[1][j] | 0;

      naf[a][j] = index[(ja + 1) * 3 + (jb + 1)];
      naf[b][j] = 0;
      wnd[a] = comb;
    }
  }

  var acc = this.jpoint(null, null, null);
  var tmp = this._wnafT4;
  for (var i = max; i >= 0; i--) {
    var k = 0;

    while (i >= 0) {
      var zero = true;
      for (var j = 0; j < len; j++) {
        tmp[j] = naf[j][i] | 0;
        if (tmp[j] !== 0)
          zero = false;
      }
      if (!zero)
        break;
      k++;
      i--;
    }
    if (i >= 0)
      k++;
    acc = acc.dblp(k);
    if (i < 0)
      break;

    for (var j = 0; j < len; j++) {
      var z = tmp[j];
      var p;
      if (z === 0)
        continue;
      else if (z > 0)
        p = wnd[j][(z - 1) >> 1];
      else if (z < 0)
        p = wnd[j][(-z - 1) >> 1].neg();

      if (p.type === 'affine')
        acc = acc.mixedAdd(p);
      else
        acc = acc.add(p);
    }
  }
  // Zeroify references
  for (var i = 0; i < len; i++)
    wnd[i] = null;
  return acc.toP();
};

function BasePoint(curve, type) {
  this.curve = curve;
  this.type = type;
  this.precomputed = null;
}
BaseCurve.BasePoint = BasePoint;

BasePoint.prototype.eq = function eq(/*other*/) {
  throw new Error('Not implemented');
};

BasePoint.prototype.validate = function validate() {
  return this.curve.validate(this);
};

BaseCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
  bytes = utils.toArray(bytes, enc);

  var len = this.p.byteLength();
  if (bytes[0] === 0x04 && bytes.length - 1 === 2 * len) {
    return this.point(bytes.slice(1, 1 + len),
                      bytes.slice(1 + len, 1 + 2 * len));
  } else if ((bytes[0] === 0x02 || bytes[0] === 0x03) &&
              bytes.length - 1 === len) {
    return this.pointFromX(bytes.slice(1, 1 + len), bytes[0] === 0x03);
  }
  throw new Error('Unknown point format');
};

BasePoint.prototype.encodeCompressed = function encodeCompressed(enc) {
  return this.encode(enc, true);
};

BasePoint.prototype._encode = function _encode(compact) {
  var len = this.curve.p.byteLength();
  var x = this.getX().toArray('be', len);

  if (compact)
    return [ this.getY().isEven() ? 0x02 : 0x03 ].concat(x);

  return [ 0x04 ].concat(x, this.getY().toArray('be', len)) ;
};

BasePoint.prototype.encode = function encode(enc, compact) {
  return utils.encode(this._encode(compact), enc);
};

BasePoint.prototype.precompute = function precompute(power) {
  if (this.precomputed)
    return this;

  var precomputed = {
    doubles: null,
    naf: null,
    beta: null
  };
  precomputed.naf = this._getNAFPoints(8);
  precomputed.doubles = this._getDoubles(4, power);
  precomputed.beta = this._getBeta();
  this.precomputed = precomputed;

  return this;
};

BasePoint.prototype._hasDoubles = function _hasDoubles(k) {
  if (!this.precomputed)
    return false;

  var doubles = this.precomputed.doubles;
  if (!doubles)
    return false;

  return doubles.points.length >= Math.ceil((k.bitLength() + 1) / doubles.step);
};

BasePoint.prototype._getDoubles = function _getDoubles(step, power) {
  if (this.precomputed && this.precomputed.doubles)
    return this.precomputed.doubles;

  var doubles = [ this ];
  var acc = this;
  for (var i = 0; i < power; i += step) {
    for (var j = 0; j < step; j++)
      acc = acc.dbl();
    doubles.push(acc);
  }
  return {
    step: step,
    points: doubles
  };
};

BasePoint.prototype._getNAFPoints = function _getNAFPoints(wnd) {
  if (this.precomputed && this.precomputed.naf)
    return this.precomputed.naf;

  var res = [ this ];
  var max = (1 << wnd) - 1;
  var dbl = max === 1 ? null : this.dbl();
  for (var i = 1; i < max; i++)
    res[i] = res[i - 1].add(dbl);
  return {
    wnd: wnd,
    points: res
  };
};

BasePoint.prototype._getBeta = function _getBeta() {
  return null;
};

BasePoint.prototype.dblp = function dblp(k) {
  var r = this;
  for (var i = 0; i < k; i++)
    r = r.dbl();
  return r;
};

},{"../../elliptic":24,"bn.js":21}],26:[function(require,module,exports){
'use strict';

var curve = require('../curve');
var elliptic = require('../../elliptic');
var BN = require('bn.js');
var inherits = require('inherits');
var Base = curve.base;

var assert = elliptic.utils.assert;

function EdwardsCurve(conf) {
  // NOTE: Important as we are creating point in Base.call()
  this.twisted = (conf.a | 0) !== 1;
  this.mOneA = this.twisted && (conf.a | 0) === -1;
  this.extended = this.mOneA;

  Base.call(this, 'edwards', conf);

  this.a = new BN(conf.a, 16).umod(this.red.m);
  this.a = this.a.toRed(this.red);
  this.c = new BN(conf.c, 16).toRed(this.red);
  this.c2 = this.c.redSqr();
  this.d = new BN(conf.d, 16).toRed(this.red);
  this.dd = this.d.redAdd(this.d);

  assert(!this.twisted || this.c.fromRed().cmpn(1) === 0);
  this.oneC = (conf.c | 0) === 1;
}
inherits(EdwardsCurve, Base);
module.exports = EdwardsCurve;

EdwardsCurve.prototype._mulA = function _mulA(num) {
  if (this.mOneA)
    return num.redNeg();
  else
    return this.a.redMul(num);
};

EdwardsCurve.prototype._mulC = function _mulC(num) {
  if (this.oneC)
    return num;
  else
    return this.c.redMul(num);
};

// Just for compatibility with Short curve
EdwardsCurve.prototype.jpoint = function jpoint(x, y, z, t) {
  return this.point(x, y, z, t);
};

EdwardsCurve.prototype.pointFromX = function pointFromX(x, odd) {
  x = new BN(x, 16);
  if (!x.red)
    x = x.toRed(this.red);

  var x2 = x.redSqr();
  var rhs = this.c2.redSub(this.a.redMul(x2));
  var lhs = this.one.redSub(this.c2.redMul(this.d).redMul(x2));

  var y2 = rhs.redMul(lhs.redInvm());
  var y = y2.redSqrt();
  if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
    throw new Error('invalid point');

  var isOdd = y.fromRed().isOdd();
  if (odd && !isOdd || !odd && isOdd)
    y = y.redNeg();

  return this.point(x, y);
};

EdwardsCurve.prototype.pointFromY = function pointFromY(y, odd) {
  y = new BN(y, 16);
  if (!y.red)
    y = y.toRed(this.red);

  // x^2 = (y^2 - 1) / (d y^2 + 1)
  var y2 = y.redSqr();
  var lhs = y2.redSub(this.one);
  var rhs = y2.redMul(this.d).redAdd(this.one);
  var x2 = lhs.redMul(rhs.redInvm());

  if (x2.cmp(this.zero) === 0) {
    if (odd)
      throw new Error('invalid point');
    else
      return this.point(this.zero, y);
  }

  var x = x2.redSqrt();
  if (x.redSqr().redSub(x2).cmp(this.zero) !== 0)
    throw new Error('invalid point');

  if (x.isOdd() !== odd)
    x = x.redNeg();

  return this.point(x, y);
};

EdwardsCurve.prototype.validate = function validate(point) {
  if (point.isInfinity())
    return true;

  // Curve: A * X^2 + Y^2 = C^2 * (1 + D * X^2 * Y^2)
  point.normalize();

  var x2 = point.x.redSqr();
  var y2 = point.y.redSqr();
  var lhs = x2.redMul(this.a).redAdd(y2);
  var rhs = this.c2.redMul(this.one.redAdd(this.d.redMul(x2).redMul(y2)));

  return lhs.cmp(rhs) === 0;
};

function Point(curve, x, y, z, t) {
  Base.BasePoint.call(this, curve, 'projective');
  if (x === null && y === null && z === null) {
    this.x = this.curve.zero;
    this.y = this.curve.one;
    this.z = this.curve.one;
    this.t = this.curve.zero;
    this.zOne = true;
  } else {
    this.x = new BN(x, 16);
    this.y = new BN(y, 16);
    this.z = z ? new BN(z, 16) : this.curve.one;
    this.t = t && new BN(t, 16);
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);
    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);
    this.zOne = this.z === this.curve.one;

    // Use extended coordinates
    if (this.curve.extended && !this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redMul(this.z.redInvm());
    }
  }
}
inherits(Point, Base.BasePoint);

EdwardsCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
  return Point.fromJSON(this, obj);
};

EdwardsCurve.prototype.point = function point(x, y, z, t) {
  return new Point(this, x, y, z, t);
};

Point.fromJSON = function fromJSON(curve, obj) {
  return new Point(curve, obj[0], obj[1], obj[2]);
};

Point.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC Point Infinity>';
  return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
      ' y: ' + this.y.fromRed().toString(16, 2) +
      ' z: ' + this.z.fromRed().toString(16, 2) + '>';
};

Point.prototype.isInfinity = function isInfinity() {
  // XXX This code assumes that zero is always zero in red
  return this.x.cmpn(0) === 0 &&
         this.y.cmp(this.z) === 0;
};

Point.prototype._extDbl = function _extDbl() {
  // hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
  //     #doubling-dbl-2008-hwcd
  // 4M + 4S

  // A = X1^2
  var a = this.x.redSqr();
  // B = Y1^2
  var b = this.y.redSqr();
  // C = 2 * Z1^2
  var c = this.z.redSqr();
  c = c.redIAdd(c);
  // D = a * A
  var d = this.curve._mulA(a);
  // E = (X1 + Y1)^2 - A - B
  var e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);
  // G = D + B
  var g = d.redAdd(b);
  // F = G - C
  var f = g.redSub(c);
  // H = D - B
  var h = d.redSub(b);
  // X3 = E * F
  var nx = e.redMul(f);
  // Y3 = G * H
  var ny = g.redMul(h);
  // T3 = E * H
  var nt = e.redMul(h);
  // Z3 = F * G
  var nz = f.redMul(g);
  return this.curve.point(nx, ny, nz, nt);
};

Point.prototype._projDbl = function _projDbl() {
  // hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
  //     #doubling-dbl-2008-bbjlp
  //     #doubling-dbl-2007-bl
  // and others
  // Generally 3M + 4S or 2M + 4S

  // B = (X1 + Y1)^2
  var b = this.x.redAdd(this.y).redSqr();
  // C = X1^2
  var c = this.x.redSqr();
  // D = Y1^2
  var d = this.y.redSqr();

  var nx;
  var ny;
  var nz;
  if (this.curve.twisted) {
    // E = a * C
    var e = this.curve._mulA(c);
    // F = E + D
    var f = e.redAdd(d);
    if (this.zOne) {
      // X3 = (B - C - D) * (F - 2)
      nx = b.redSub(c).redSub(d).redMul(f.redSub(this.curve.two));
      // Y3 = F * (E - D)
      ny = f.redMul(e.redSub(d));
      // Z3 = F^2 - 2 * F
      nz = f.redSqr().redSub(f).redSub(f);
    } else {
      // H = Z1^2
      var h = this.z.redSqr();
      // J = F - 2 * H
      var j = f.redSub(h).redISub(h);
      // X3 = (B-C-D)*J
      nx = b.redSub(c).redISub(d).redMul(j);
      // Y3 = F * (E - D)
      ny = f.redMul(e.redSub(d));
      // Z3 = F * J
      nz = f.redMul(j);
    }
  } else {
    // E = C + D
    var e = c.redAdd(d);
    // H = (c * Z1)^2
    var h = this.curve._mulC(this.c.redMul(this.z)).redSqr();
    // J = E - 2 * H
    var j = e.redSub(h).redSub(h);
    // X3 = c * (B - E) * J
    nx = this.curve._mulC(b.redISub(e)).redMul(j);
    // Y3 = c * E * (C - D)
    ny = this.curve._mulC(e).redMul(c.redISub(d));
    // Z3 = E * J
    nz = e.redMul(j);
  }
  return this.curve.point(nx, ny, nz);
};

Point.prototype.dbl = function dbl() {
  if (this.isInfinity())
    return this;

  // Double in extended coordinates
  if (this.curve.extended)
    return this._extDbl();
  else
    return this._projDbl();
};

Point.prototype._extAdd = function _extAdd(p) {
  // hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
  //     #addition-add-2008-hwcd-3
  // 8M

  // A = (Y1 - X1) * (Y2 - X2)
  var a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));
  // B = (Y1 + X1) * (Y2 + X2)
  var b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));
  // C = T1 * k * T2
  var c = this.t.redMul(this.curve.dd).redMul(p.t);
  // D = Z1 * 2 * Z2
  var d = this.z.redMul(p.z.redAdd(p.z));
  // E = B - A
  var e = b.redSub(a);
  // F = D - C
  var f = d.redSub(c);
  // G = D + C
  var g = d.redAdd(c);
  // H = B + A
  var h = b.redAdd(a);
  // X3 = E * F
  var nx = e.redMul(f);
  // Y3 = G * H
  var ny = g.redMul(h);
  // T3 = E * H
  var nt = e.redMul(h);
  // Z3 = F * G
  var nz = f.redMul(g);
  return this.curve.point(nx, ny, nz, nt);
};

Point.prototype._projAdd = function _projAdd(p) {
  // hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
  //     #addition-add-2008-bbjlp
  //     #addition-add-2007-bl
  // 10M + 1S

  // A = Z1 * Z2
  var a = this.z.redMul(p.z);
  // B = A^2
  var b = a.redSqr();
  // C = X1 * X2
  var c = this.x.redMul(p.x);
  // D = Y1 * Y2
  var d = this.y.redMul(p.y);
  // E = d * C * D
  var e = this.curve.d.redMul(c).redMul(d);
  // F = B - E
  var f = b.redSub(e);
  // G = B + E
  var g = b.redAdd(e);
  // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
  var tmp = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y)).redISub(c).redISub(d);
  var nx = a.redMul(f).redMul(tmp);
  var ny;
  var nz;
  if (this.curve.twisted) {
    // Y3 = A * G * (D - a * C)
    ny = a.redMul(g).redMul(d.redSub(this.curve._mulA(c)));
    // Z3 = F * G
    nz = f.redMul(g);
  } else {
    // Y3 = A * G * (D - C)
    ny = a.redMul(g).redMul(d.redSub(c));
    // Z3 = c * F * G
    nz = this.curve._mulC(f).redMul(g);
  }
  return this.curve.point(nx, ny, nz);
};

Point.prototype.add = function add(p) {
  if (this.isInfinity())
    return p;
  if (p.isInfinity())
    return this;

  if (this.curve.extended)
    return this._extAdd(p);
  else
    return this._projAdd(p);
};

Point.prototype.mul = function mul(k) {
  if (this._hasDoubles(k))
    return this.curve._fixedNafMul(this, k);
  else
    return this.curve._wnafMul(this, k);
};

Point.prototype.mulAdd = function mulAdd(k1, p, k2) {
  return this.curve._wnafMulAdd(1, [ this, p ], [ k1, k2 ], 2);
};

Point.prototype.normalize = function normalize() {
  if (this.zOne)
    return this;

  // Normalize coordinates
  var zi = this.z.redInvm();
  this.x = this.x.redMul(zi);
  this.y = this.y.redMul(zi);
  if (this.t)
    this.t = this.t.redMul(zi);
  this.z = this.curve.one;
  this.zOne = true;
  return this;
};

Point.prototype.neg = function neg() {
  return this.curve.point(this.x.redNeg(),
                          this.y,
                          this.z,
                          this.t && this.t.redNeg());
};

Point.prototype.getX = function getX() {
  this.normalize();
  return this.x.fromRed();
};

Point.prototype.getY = function getY() {
  this.normalize();
  return this.y.fromRed();
};

Point.prototype.eq = function eq(other) {
  return this === other ||
         this.getX().cmp(other.getX()) === 0 &&
         this.getY().cmp(other.getY()) === 0;
};

// Compatibility with BaseCurve
Point.prototype.toP = Point.prototype.normalize;
Point.prototype.mixedAdd = Point.prototype.add;

},{"../../elliptic":24,"../curve":27,"bn.js":21,"inherits":49}],27:[function(require,module,exports){
'use strict';

var curve = exports;

curve.base = require('./base');
curve.short = require('./short');
curve.mont = require('./mont');
curve.edwards = require('./edwards');

},{"./base":25,"./edwards":26,"./mont":28,"./short":29}],28:[function(require,module,exports){
'use strict';

var curve = require('../curve');
var BN = require('bn.js');
var inherits = require('inherits');
var Base = curve.base;

var elliptic = require('../../elliptic');
var utils = elliptic.utils;

function MontCurve(conf) {
  Base.call(this, 'mont', conf);

  this.a = new BN(conf.a, 16).toRed(this.red);
  this.b = new BN(conf.b, 16).toRed(this.red);
  this.i4 = new BN(4).toRed(this.red).redInvm();
  this.two = new BN(2).toRed(this.red);
  this.a24 = this.i4.redMul(this.a.redAdd(this.two));
}
inherits(MontCurve, Base);
module.exports = MontCurve;

MontCurve.prototype.validate = function validate(point) {
  var x = point.normalize().x;
  var x2 = x.redSqr();
  var rhs = x2.redMul(x).redAdd(x2.redMul(this.a)).redAdd(x);
  var y = rhs.redSqrt();

  return y.redSqr().cmp(rhs) === 0;
};

function Point(curve, x, z) {
  Base.BasePoint.call(this, curve, 'projective');
  if (x === null && z === null) {
    this.x = this.curve.one;
    this.z = this.curve.zero;
  } else {
    this.x = new BN(x, 16);
    this.z = new BN(z, 16);
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }
}
inherits(Point, Base.BasePoint);

MontCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
  return this.point(utils.toArray(bytes, enc), 1);
};

MontCurve.prototype.point = function point(x, z) {
  return new Point(this, x, z);
};

MontCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
  return Point.fromJSON(this, obj);
};

Point.prototype.precompute = function precompute() {
  // No-op
};

Point.prototype._encode = function _encode() {
  return this.getX().toArray('be', this.curve.p.byteLength());
};

Point.fromJSON = function fromJSON(curve, obj) {
  return new Point(curve, obj[0], obj[1] || curve.one);
};

Point.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC Point Infinity>';
  return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
      ' z: ' + this.z.fromRed().toString(16, 2) + '>';
};

Point.prototype.isInfinity = function isInfinity() {
  // XXX This code assumes that zero is always zero in red
  return this.z.cmpn(0) === 0;
};

Point.prototype.dbl = function dbl() {
  // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
  // 2M + 2S + 4A

  // A = X1 + Z1
  var a = this.x.redAdd(this.z);
  // AA = A^2
  var aa = a.redSqr();
  // B = X1 - Z1
  var b = this.x.redSub(this.z);
  // BB = B^2
  var bb = b.redSqr();
  // C = AA - BB
  var c = aa.redSub(bb);
  // X3 = AA * BB
  var nx = aa.redMul(bb);
  // Z3 = C * (BB + A24 * C)
  var nz = c.redMul(bb.redAdd(this.curve.a24.redMul(c)));
  return this.curve.point(nx, nz);
};

Point.prototype.add = function add() {
  throw new Error('Not supported on Montgomery curve');
};

Point.prototype.diffAdd = function diffAdd(p, diff) {
  // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
  // 4M + 2S + 6A

  // A = X2 + Z2
  var a = this.x.redAdd(this.z);
  // B = X2 - Z2
  var b = this.x.redSub(this.z);
  // C = X3 + Z3
  var c = p.x.redAdd(p.z);
  // D = X3 - Z3
  var d = p.x.redSub(p.z);
  // DA = D * A
  var da = d.redMul(a);
  // CB = C * B
  var cb = c.redMul(b);
  // X5 = Z1 * (DA + CB)^2
  var nx = diff.z.redMul(da.redAdd(cb).redSqr());
  // Z5 = X1 * (DA - CB)^2
  var nz = diff.x.redMul(da.redISub(cb).redSqr());
  return this.curve.point(nx, nz);
};

Point.prototype.mul = function mul(k) {
  var t = k.clone();
  var a = this; // (N / 2) * Q + Q
  var b = this.curve.point(null, null); // (N / 2) * Q
  var c = this; // Q

  for (var bits = []; t.cmpn(0) !== 0; t.iushrn(1))
    bits.push(t.andln(1));

  for (var i = bits.length - 1; i >= 0; i--) {
    if (bits[i] === 0) {
      // N * Q + Q = ((N / 2) * Q + Q)) + (N / 2) * Q
      a = a.diffAdd(b, c);
      // N * Q = 2 * ((N / 2) * Q + Q))
      b = b.dbl();
    } else {
      // N * Q = ((N / 2) * Q + Q) + ((N / 2) * Q)
      b = a.diffAdd(b, c);
      // N * Q + Q = 2 * ((N / 2) * Q + Q)
      a = a.dbl();
    }
  }
  return b;
};

Point.prototype.mulAdd = function mulAdd() {
  throw new Error('Not supported on Montgomery curve');
};

Point.prototype.eq = function eq(other) {
  return this.getX().cmp(other.getX()) === 0;
};

Point.prototype.normalize = function normalize() {
  this.x = this.x.redMul(this.z.redInvm());
  this.z = this.curve.one;
  return this;
};

Point.prototype.getX = function getX() {
  // Normalize coordinates
  this.normalize();

  return this.x.fromRed();
};

},{"../../elliptic":24,"../curve":27,"bn.js":21,"inherits":49}],29:[function(require,module,exports){
'use strict';

var curve = require('../curve');
var elliptic = require('../../elliptic');
var BN = require('bn.js');
var inherits = require('inherits');
var Base = curve.base;

var assert = elliptic.utils.assert;

function ShortCurve(conf) {
  Base.call(this, 'short', conf);

  this.a = new BN(conf.a, 16).toRed(this.red);
  this.b = new BN(conf.b, 16).toRed(this.red);
  this.tinv = this.two.redInvm();

  this.zeroA = this.a.fromRed().cmpn(0) === 0;
  this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0;

  // If the curve is endomorphic, precalculate beta and lambda
  this.endo = this._getEndomorphism(conf);
  this._endoWnafT1 = new Array(4);
  this._endoWnafT2 = new Array(4);
}
inherits(ShortCurve, Base);
module.exports = ShortCurve;

ShortCurve.prototype._getEndomorphism = function _getEndomorphism(conf) {
  // No efficient endomorphism
  if (!this.zeroA || !this.g || !this.n || this.p.modn(3) !== 1)
    return;

  // Compute beta and lambda, that lambda * P = (beta * Px; Py)
  var beta;
  var lambda;
  if (conf.beta) {
    beta = new BN(conf.beta, 16).toRed(this.red);
  } else {
    var betas = this._getEndoRoots(this.p);
    // Choose the smallest beta
    beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
    beta = beta.toRed(this.red);
  }
  if (conf.lambda) {
    lambda = new BN(conf.lambda, 16);
  } else {
    // Choose the lambda that is matching selected beta
    var lambdas = this._getEndoRoots(this.n);
    if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
      lambda = lambdas[0];
    } else {
      lambda = lambdas[1];
      assert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
    }
  }

  // Get basis vectors, used for balanced length-two representation
  var basis;
  if (conf.basis) {
    basis = conf.basis.map(function(vec) {
      return {
        a: new BN(vec.a, 16),
        b: new BN(vec.b, 16)
      };
    });
  } else {
    basis = this._getEndoBasis(lambda);
  }

  return {
    beta: beta,
    lambda: lambda,
    basis: basis
  };
};

ShortCurve.prototype._getEndoRoots = function _getEndoRoots(num) {
  // Find roots of for x^2 + x + 1 in F
  // Root = (-1 +- Sqrt(-3)) / 2
  //
  var red = num === this.p ? this.red : BN.mont(num);
  var tinv = new BN(2).toRed(red).redInvm();
  var ntinv = tinv.redNeg();

  var s = new BN(3).toRed(red).redNeg().redSqrt().redMul(tinv);

  var l1 = ntinv.redAdd(s).fromRed();
  var l2 = ntinv.redSub(s).fromRed();
  return [ l1, l2 ];
};

ShortCurve.prototype._getEndoBasis = function _getEndoBasis(lambda) {
  // aprxSqrt >= sqrt(this.n)
  var aprxSqrt = this.n.ushrn(Math.floor(this.n.bitLength() / 2));

  // 3.74
  // Run EGCD, until r(L + 1) < aprxSqrt
  var u = lambda;
  var v = this.n.clone();
  var x1 = new BN(1);
  var y1 = new BN(0);
  var x2 = new BN(0);
  var y2 = new BN(1);

  // NOTE: all vectors are roots of: a + b * lambda = 0 (mod n)
  var a0;
  var b0;
  // First vector
  var a1;
  var b1;
  // Second vector
  var a2;
  var b2;

  var prevR;
  var i = 0;
  var r;
  var x;
  while (u.cmpn(0) !== 0) {
    var q = v.div(u);
    r = v.sub(q.mul(u));
    x = x2.sub(q.mul(x1));
    var y = y2.sub(q.mul(y1));

    if (!a1 && r.cmp(aprxSqrt) < 0) {
      a0 = prevR.neg();
      b0 = x1;
      a1 = r.neg();
      b1 = x;
    } else if (a1 && ++i === 2) {
      break;
    }
    prevR = r;

    v = u;
    u = r;
    x2 = x1;
    x1 = x;
    y2 = y1;
    y1 = y;
  }
  a2 = r.neg();
  b2 = x;

  var len1 = a1.sqr().add(b1.sqr());
  var len2 = a2.sqr().add(b2.sqr());
  if (len2.cmp(len1) >= 0) {
    a2 = a0;
    b2 = b0;
  }

  // Normalize signs
  if (a1.negative) {
    a1 = a1.neg();
    b1 = b1.neg();
  }
  if (a2.negative) {
    a2 = a2.neg();
    b2 = b2.neg();
  }

  return [
    { a: a1, b: b1 },
    { a: a2, b: b2 }
  ];
};

ShortCurve.prototype._endoSplit = function _endoSplit(k) {
  var basis = this.endo.basis;
  var v1 = basis[0];
  var v2 = basis[1];

  var c1 = v2.b.mul(k).divRound(this.n);
  var c2 = v1.b.neg().mul(k).divRound(this.n);

  var p1 = c1.mul(v1.a);
  var p2 = c2.mul(v2.a);
  var q1 = c1.mul(v1.b);
  var q2 = c2.mul(v2.b);

  // Calculate answer
  var k1 = k.sub(p1).sub(p2);
  var k2 = q1.add(q2).neg();
  return { k1: k1, k2: k2 };
};

ShortCurve.prototype.pointFromX = function pointFromX(x, odd) {
  x = new BN(x, 16);
  if (!x.red)
    x = x.toRed(this.red);

  var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(this.a)).redIAdd(this.b);
  var y = y2.redSqrt();
  if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
    throw new Error('invalid point');

  // XXX Is there any way to tell if the number is odd without converting it
  // to non-red form?
  var isOdd = y.fromRed().isOdd();
  if (odd && !isOdd || !odd && isOdd)
    y = y.redNeg();

  return this.point(x, y);
};

ShortCurve.prototype.validate = function validate(point) {
  if (point.inf)
    return true;

  var x = point.x;
  var y = point.y;

  var ax = this.a.redMul(x);
  var rhs = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
  return y.redSqr().redISub(rhs).cmpn(0) === 0;
};

ShortCurve.prototype._endoWnafMulAdd =
    function _endoWnafMulAdd(points, coeffs) {
  var npoints = this._endoWnafT1;
  var ncoeffs = this._endoWnafT2;
  for (var i = 0; i < points.length; i++) {
    var split = this._endoSplit(coeffs[i]);
    var p = points[i];
    var beta = p._getBeta();

    if (split.k1.negative) {
      split.k1.ineg();
      p = p.neg(true);
    }
    if (split.k2.negative) {
      split.k2.ineg();
      beta = beta.neg(true);
    }

    npoints[i * 2] = p;
    npoints[i * 2 + 1] = beta;
    ncoeffs[i * 2] = split.k1;
    ncoeffs[i * 2 + 1] = split.k2;
  }
  var res = this._wnafMulAdd(1, npoints, ncoeffs, i * 2);

  // Clean-up references to points and coefficients
  for (var j = 0; j < i * 2; j++) {
    npoints[j] = null;
    ncoeffs[j] = null;
  }
  return res;
};

function Point(curve, x, y, isRed) {
  Base.BasePoint.call(this, curve, 'affine');
  if (x === null && y === null) {
    this.x = null;
    this.y = null;
    this.inf = true;
  } else {
    this.x = new BN(x, 16);
    this.y = new BN(y, 16);
    // Force redgomery representation when loading from JSON
    if (isRed) {
      this.x.forceRed(this.curve.red);
      this.y.forceRed(this.curve.red);
    }
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);
    this.inf = false;
  }
}
inherits(Point, Base.BasePoint);

ShortCurve.prototype.point = function point(x, y, isRed) {
  return new Point(this, x, y, isRed);
};

ShortCurve.prototype.pointFromJSON = function pointFromJSON(obj, red) {
  return Point.fromJSON(this, obj, red);
};

Point.prototype._getBeta = function _getBeta() {
  if (!this.curve.endo)
    return;

  var pre = this.precomputed;
  if (pre && pre.beta)
    return pre.beta;

  var beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
  if (pre) {
    var curve = this.curve;
    var endoMul = function(p) {
      return curve.point(p.x.redMul(curve.endo.beta), p.y);
    };
    pre.beta = beta;
    beta.precomputed = {
      beta: null,
      naf: pre.naf && {
        wnd: pre.naf.wnd,
        points: pre.naf.points.map(endoMul)
      },
      doubles: pre.doubles && {
        step: pre.doubles.step,
        points: pre.doubles.points.map(endoMul)
      }
    };
  }
  return beta;
};

Point.prototype.toJSON = function toJSON() {
  if (!this.precomputed)
    return [ this.x, this.y ];

  return [ this.x, this.y, this.precomputed && {
    doubles: this.precomputed.doubles && {
      step: this.precomputed.doubles.step,
      points: this.precomputed.doubles.points.slice(1)
    },
    naf: this.precomputed.naf && {
      wnd: this.precomputed.naf.wnd,
      points: this.precomputed.naf.points.slice(1)
    }
  } ];
};

Point.fromJSON = function fromJSON(curve, obj, red) {
  if (typeof obj === 'string')
    obj = JSON.parse(obj);
  var res = curve.point(obj[0], obj[1], red);
  if (!obj[2])
    return res;

  function obj2point(obj) {
    return curve.point(obj[0], obj[1], red);
  }

  var pre = obj[2];
  res.precomputed = {
    beta: null,
    doubles: pre.doubles && {
      step: pre.doubles.step,
      points: [ res ].concat(pre.doubles.points.map(obj2point))
    },
    naf: pre.naf && {
      wnd: pre.naf.wnd,
      points: [ res ].concat(pre.naf.points.map(obj2point))
    }
  };
  return res;
};

Point.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC Point Infinity>';
  return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
      ' y: ' + this.y.fromRed().toString(16, 2) + '>';
};

Point.prototype.isInfinity = function isInfinity() {
  return this.inf;
};

Point.prototype.add = function add(p) {
  // O + P = P
  if (this.inf)
    return p;

  // P + O = P
  if (p.inf)
    return this;

  // P + P = 2P
  if (this.eq(p))
    return this.dbl();

  // P + (-P) = O
  if (this.neg().eq(p))
    return this.curve.point(null, null);

  // P + Q = O
  if (this.x.cmp(p.x) === 0)
    return this.curve.point(null, null);

  var c = this.y.redSub(p.y);
  if (c.cmpn(0) !== 0)
    c = c.redMul(this.x.redSub(p.x).redInvm());
  var nx = c.redSqr().redISub(this.x).redISub(p.x);
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
  return this.curve.point(nx, ny);
};

Point.prototype.dbl = function dbl() {
  if (this.inf)
    return this;

  // 2P = O
  var ys1 = this.y.redAdd(this.y);
  if (ys1.cmpn(0) === 0)
    return this.curve.point(null, null);

  var a = this.curve.a;

  var x2 = this.x.redSqr();
  var dyinv = ys1.redInvm();
  var c = x2.redAdd(x2).redIAdd(x2).redIAdd(a).redMul(dyinv);

  var nx = c.redSqr().redISub(this.x.redAdd(this.x));
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
  return this.curve.point(nx, ny);
};

Point.prototype.getX = function getX() {
  return this.x.fromRed();
};

Point.prototype.getY = function getY() {
  return this.y.fromRed();
};

Point.prototype.mul = function mul(k) {
  k = new BN(k, 16);

  if (this._hasDoubles(k))
    return this.curve._fixedNafMul(this, k);
  else if (this.curve.endo)
    return this.curve._endoWnafMulAdd([ this ], [ k ]);
  else
    return this.curve._wnafMul(this, k);
};

Point.prototype.mulAdd = function mulAdd(k1, p2, k2) {
  var points = [ this, p2 ];
  var coeffs = [ k1, k2 ];
  if (this.curve.endo)
    return this.curve._endoWnafMulAdd(points, coeffs);
  else
    return this.curve._wnafMulAdd(1, points, coeffs, 2);
};

Point.prototype.eq = function eq(p) {
  return this === p ||
         this.inf === p.inf &&
             (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0);
};

Point.prototype.neg = function neg(_precompute) {
  if (this.inf)
    return this;

  var res = this.curve.point(this.x, this.y.redNeg());
  if (_precompute && this.precomputed) {
    var pre = this.precomputed;
    var negate = function(p) {
      return p.neg();
    };
    res.precomputed = {
      naf: pre.naf && {
        wnd: pre.naf.wnd,
        points: pre.naf.points.map(negate)
      },
      doubles: pre.doubles && {
        step: pre.doubles.step,
        points: pre.doubles.points.map(negate)
      }
    };
  }
  return res;
};

Point.prototype.toJ = function toJ() {
  if (this.inf)
    return this.curve.jpoint(null, null, null);

  var res = this.curve.jpoint(this.x, this.y, this.curve.one);
  return res;
};

function JPoint(curve, x, y, z) {
  Base.BasePoint.call(this, curve, 'jacobian');
  if (x === null && y === null && z === null) {
    this.x = this.curve.one;
    this.y = this.curve.one;
    this.z = new BN(0);
  } else {
    this.x = new BN(x, 16);
    this.y = new BN(y, 16);
    this.z = new BN(z, 16);
  }
  if (!this.x.red)
    this.x = this.x.toRed(this.curve.red);
  if (!this.y.red)
    this.y = this.y.toRed(this.curve.red);
  if (!this.z.red)
    this.z = this.z.toRed(this.curve.red);

  this.zOne = this.z === this.curve.one;
}
inherits(JPoint, Base.BasePoint);

ShortCurve.prototype.jpoint = function jpoint(x, y, z) {
  return new JPoint(this, x, y, z);
};

JPoint.prototype.toP = function toP() {
  if (this.isInfinity())
    return this.curve.point(null, null);

  var zinv = this.z.redInvm();
  var zinv2 = zinv.redSqr();
  var ax = this.x.redMul(zinv2);
  var ay = this.y.redMul(zinv2).redMul(zinv);

  return this.curve.point(ax, ay);
};

JPoint.prototype.neg = function neg() {
  return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
};

JPoint.prototype.add = function add(p) {
  // O + P = P
  if (this.isInfinity())
    return p;

  // P + O = P
  if (p.isInfinity())
    return this;

  // 12M + 4S + 7A
  var pz2 = p.z.redSqr();
  var z2 = this.z.redSqr();
  var u1 = this.x.redMul(pz2);
  var u2 = p.x.redMul(z2);
  var s1 = this.y.redMul(pz2.redMul(p.z));
  var s2 = p.y.redMul(z2.redMul(this.z));

  var h = u1.redSub(u2);
  var r = s1.redSub(s2);
  if (h.cmpn(0) === 0) {
    if (r.cmpn(0) !== 0)
      return this.curve.jpoint(null, null, null);
    else
      return this.dbl();
  }

  var h2 = h.redSqr();
  var h3 = h2.redMul(h);
  var v = u1.redMul(h2);

  var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
  var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
  var nz = this.z.redMul(p.z).redMul(h);

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype.mixedAdd = function mixedAdd(p) {
  // O + P = P
  if (this.isInfinity())
    return p.toJ();

  // P + O = P
  if (p.isInfinity())
    return this;

  // 8M + 3S + 7A
  var z2 = this.z.redSqr();
  var u1 = this.x;
  var u2 = p.x.redMul(z2);
  var s1 = this.y;
  var s2 = p.y.redMul(z2).redMul(this.z);

  var h = u1.redSub(u2);
  var r = s1.redSub(s2);
  if (h.cmpn(0) === 0) {
    if (r.cmpn(0) !== 0)
      return this.curve.jpoint(null, null, null);
    else
      return this.dbl();
  }

  var h2 = h.redSqr();
  var h3 = h2.redMul(h);
  var v = u1.redMul(h2);

  var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
  var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
  var nz = this.z.redMul(h);

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype.dblp = function dblp(pow) {
  if (pow === 0)
    return this;
  if (this.isInfinity())
    return this;
  if (!pow)
    return this.dbl();

  if (this.curve.zeroA || this.curve.threeA) {
    var r = this;
    for (var i = 0; i < pow; i++)
      r = r.dbl();
    return r;
  }

  // 1M + 2S + 1A + N * (4S + 5M + 8A)
  // N = 1 => 6M + 6S + 9A
  var a = this.curve.a;
  var tinv = this.curve.tinv;

  var jx = this.x;
  var jy = this.y;
  var jz = this.z;
  var jz4 = jz.redSqr().redSqr();

  // Reuse results
  var jyd = jy.redAdd(jy);
  for (var i = 0; i < pow; i++) {
    var jx2 = jx.redSqr();
    var jyd2 = jyd.redSqr();
    var jyd4 = jyd2.redSqr();
    var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

    var t1 = jx.redMul(jyd2);
    var nx = c.redSqr().redISub(t1.redAdd(t1));
    var t2 = t1.redISub(nx);
    var dny = c.redMul(t2);
    dny = dny.redIAdd(dny).redISub(jyd4);
    var nz = jyd.redMul(jz);
    if (i + 1 < pow)
      jz4 = jz4.redMul(jyd4);

    jx = nx;
    jz = nz;
    jyd = dny;
  }

  return this.curve.jpoint(jx, jyd.redMul(tinv), jz);
};

JPoint.prototype.dbl = function dbl() {
  if (this.isInfinity())
    return this;

  if (this.curve.zeroA)
    return this._zeroDbl();
  else if (this.curve.threeA)
    return this._threeDbl();
  else
    return this._dbl();
};

JPoint.prototype._zeroDbl = function _zeroDbl() {
  var nx;
  var ny;
  var nz;
  // Z = 1
  if (this.zOne) {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    //     #doubling-mdbl-2007-bl
    // 1M + 5S + 14A

    // XX = X1^2
    var xx = this.x.redSqr();
    // YY = Y1^2
    var yy = this.y.redSqr();
    // YYYY = YY^2
    var yyyy = yy.redSqr();
    // S = 2 * ((X1 + YY)^2 - XX - YYYY)
    var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
    s = s.redIAdd(s);
    // M = 3 * XX + a; a = 0
    var m = xx.redAdd(xx).redIAdd(xx);
    // T = M ^ 2 - 2*S
    var t = m.redSqr().redISub(s).redISub(s);

    // 8 * YYYY
    var yyyy8 = yyyy.redIAdd(yyyy);
    yyyy8 = yyyy8.redIAdd(yyyy8);
    yyyy8 = yyyy8.redIAdd(yyyy8);

    // X3 = T
    nx = t;
    // Y3 = M * (S - T) - 8 * YYYY
    ny = m.redMul(s.redISub(t)).redISub(yyyy8);
    // Z3 = 2*Y1
    nz = this.y.redAdd(this.y);
  } else {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    //     #doubling-dbl-2009-l
    // 2M + 5S + 13A

    // A = X1^2
    var a = this.x.redSqr();
    // B = Y1^2
    var b = this.y.redSqr();
    // C = B^2
    var c = b.redSqr();
    // D = 2 * ((X1 + B)^2 - A - C)
    var d = this.x.redAdd(b).redSqr().redISub(a).redISub(c);
    d = d.redIAdd(d);
    // E = 3 * A
    var e = a.redAdd(a).redIAdd(a);
    // F = E^2
    var f = e.redSqr();

    // 8 * C
    var c8 = c.redIAdd(c);
    c8 = c8.redIAdd(c8);
    c8 = c8.redIAdd(c8);

    // X3 = F - 2 * D
    nx = f.redISub(d).redISub(d);
    // Y3 = E * (D - X3) - 8 * C
    ny = e.redMul(d.redISub(nx)).redISub(c8);
    // Z3 = 2 * Y1 * Z1
    nz = this.y.redMul(this.z);
    nz = nz.redIAdd(nz);
  }

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype._threeDbl = function _threeDbl() {
  var nx;
  var ny;
  var nz;
  // Z = 1
  if (this.zOne) {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
    //     #doubling-mdbl-2007-bl
    // 1M + 5S + 15A

    // XX = X1^2
    var xx = this.x.redSqr();
    // YY = Y1^2
    var yy = this.y.redSqr();
    // YYYY = YY^2
    var yyyy = yy.redSqr();
    // S = 2 * ((X1 + YY)^2 - XX - YYYY)
    var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
    s = s.redIAdd(s);
    // M = 3 * XX + a
    var m = xx.redAdd(xx).redIAdd(xx).redIAdd(this.curve.a);
    // T = M^2 - 2 * S
    var t = m.redSqr().redISub(s).redISub(s);
    // X3 = T
    nx = t;
    // Y3 = M * (S - T) - 8 * YYYY
    var yyyy8 = yyyy.redIAdd(yyyy);
    yyyy8 = yyyy8.redIAdd(yyyy8);
    yyyy8 = yyyy8.redIAdd(yyyy8);
    ny = m.redMul(s.redISub(t)).redISub(yyyy8);
    // Z3 = 2 * Y1
    nz = this.y.redAdd(this.y);
  } else {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // 3M + 5S

    // delta = Z1^2
    var delta = this.z.redSqr();
    // gamma = Y1^2
    var gamma = this.y.redSqr();
    // beta = X1 * gamma
    var beta = this.x.redMul(gamma);
    // alpha = 3 * (X1 - delta) * (X1 + delta)
    var alpha = this.x.redSub(delta).redMul(this.x.redAdd(delta));
    alpha = alpha.redAdd(alpha).redIAdd(alpha);
    // X3 = alpha^2 - 8 * beta
    var beta4 = beta.redIAdd(beta);
    beta4 = beta4.redIAdd(beta4);
    var beta8 = beta4.redAdd(beta4);
    nx = alpha.redSqr().redISub(beta8);
    // Z3 = (Y1 + Z1)^2 - gamma - delta
    nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);
    // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    var ggamma8 = gamma.redSqr();
    ggamma8 = ggamma8.redIAdd(ggamma8);
    ggamma8 = ggamma8.redIAdd(ggamma8);
    ggamma8 = ggamma8.redIAdd(ggamma8);
    ny = alpha.redMul(beta4.redISub(nx)).redISub(ggamma8);
  }

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype._dbl = function _dbl() {
  var a = this.curve.a;

  // 4M + 6S + 10A
  var jx = this.x;
  var jy = this.y;
  var jz = this.z;
  var jz4 = jz.redSqr().redSqr();

  var jx2 = jx.redSqr();
  var jy2 = jy.redSqr();

  var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

  var jxd4 = jx.redAdd(jx);
  jxd4 = jxd4.redIAdd(jxd4);
  var t1 = jxd4.redMul(jy2);
  var nx = c.redSqr().redISub(t1.redAdd(t1));
  var t2 = t1.redISub(nx);

  var jyd8 = jy2.redSqr();
  jyd8 = jyd8.redIAdd(jyd8);
  jyd8 = jyd8.redIAdd(jyd8);
  jyd8 = jyd8.redIAdd(jyd8);
  var ny = c.redMul(t2).redISub(jyd8);
  var nz = jy.redAdd(jy).redMul(jz);

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype.trpl = function trpl() {
  if (!this.curve.zeroA)
    return this.dbl().add(this);

  // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#tripling-tpl-2007-bl
  // 5M + 10S + ...

  // XX = X1^2
  var xx = this.x.redSqr();
  // YY = Y1^2
  var yy = this.y.redSqr();
  // ZZ = Z1^2
  var zz = this.z.redSqr();
  // YYYY = YY^2
  var yyyy = yy.redSqr();
  // M = 3 * XX + a * ZZ2; a = 0
  var m = xx.redAdd(xx).redIAdd(xx);
  // MM = M^2
  var mm = m.redSqr();
  // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
  var e = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
  e = e.redIAdd(e);
  e = e.redAdd(e).redIAdd(e);
  e = e.redISub(mm);
  // EE = E^2
  var ee = e.redSqr();
  // T = 16*YYYY
  var t = yyyy.redIAdd(yyyy);
  t = t.redIAdd(t);
  t = t.redIAdd(t);
  t = t.redIAdd(t);
  // U = (M + E)^2 - MM - EE - T
  var u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);
  // X3 = 4 * (X1 * EE - 4 * YY * U)
  var yyu4 = yy.redMul(u);
  yyu4 = yyu4.redIAdd(yyu4);
  yyu4 = yyu4.redIAdd(yyu4);
  var nx = this.x.redMul(ee).redISub(yyu4);
  nx = nx.redIAdd(nx);
  nx = nx.redIAdd(nx);
  // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
  var ny = this.y.redMul(u.redMul(t.redISub(u)).redISub(e.redMul(ee)));
  ny = ny.redIAdd(ny);
  ny = ny.redIAdd(ny);
  ny = ny.redIAdd(ny);
  // Z3 = (Z1 + E)^2 - ZZ - EE
  var nz = this.z.redAdd(e).redSqr().redISub(zz).redISub(ee);

  return this.curve.jpoint(nx, ny, nz);
};

JPoint.prototype.mul = function mul(k, kbase) {
  k = new BN(k, kbase);

  return this.curve._wnafMul(this, k);
};

JPoint.prototype.eq = function eq(p) {
  if (p.type === 'affine')
    return this.eq(p.toJ());

  if (this === p)
    return true;

  // x1 * z2^2 == x2 * z1^2
  var z2 = this.z.redSqr();
  var pz2 = p.z.redSqr();
  if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0)
    return false;

  // y1 * z2^3 == y2 * z1^3
  var z3 = z2.redMul(this.z);
  var pz3 = pz2.redMul(p.z);
  return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0;
};

JPoint.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC JPoint Infinity>';
  return '<EC JPoint x: ' + this.x.toString(16, 2) +
      ' y: ' + this.y.toString(16, 2) +
      ' z: ' + this.z.toString(16, 2) + '>';
};

JPoint.prototype.isInfinity = function isInfinity() {
  // XXX This code assumes that zero is always zero in red
  return this.z.cmpn(0) === 0;
};

},{"../../elliptic":24,"../curve":27,"bn.js":21,"inherits":49}],30:[function(require,module,exports){
'use strict';

var curves = exports;

var hash = require('hash.js');
var elliptic = require('../elliptic');

var assert = elliptic.utils.assert;

function PresetCurve(options) {
  if (options.type === 'short')
    this.curve = new elliptic.curve.short(options);
  else if (options.type === 'edwards')
    this.curve = new elliptic.curve.edwards(options);
  else
    this.curve = new elliptic.curve.mont(options);
  this.g = this.curve.g;
  this.n = this.curve.n;
  this.hash = options.hash;

  assert(this.g.validate(), 'Invalid curve');
  assert(this.g.mul(this.n).isInfinity(), 'Invalid curve, G*N != O');
}
curves.PresetCurve = PresetCurve;

function defineCurve(name, options) {
  Object.defineProperty(curves, name, {
    configurable: true,
    enumerable: true,
    get: function() {
      var curve = new PresetCurve(options);
      Object.defineProperty(curves, name, {
        configurable: true,
        enumerable: true,
        value: curve
      });
      return curve;
    }
  });
}

defineCurve('p192', {
  type: 'short',
  prime: 'p192',
  p: 'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff',
  a: 'ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc',
  b: '64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1',
  n: 'ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831',
  hash: hash.sha256,
  gRed: false,
  g: [
    '188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012',
    '07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811'
  ]
});

defineCurve('p224', {
  type: 'short',
  prime: 'p224',
  p: 'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001',
  a: 'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe',
  b: 'b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4',
  n: 'ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d',
  hash: hash.sha256,
  gRed: false,
  g: [
    'b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21',
    'bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34'
  ]
});

defineCurve('p256', {
  type: 'short',
  prime: null,
  p: 'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff',
  a: 'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc',
  b: '5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b',
  n: 'ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551',
  hash: hash.sha256,
  gRed: false,
  g: [
    '6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296',
    '4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5'
  ]
});

defineCurve('p384', {
  type: 'short',
  prime: null,
  p: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'fffffffe ffffffff 00000000 00000000 ffffffff',
  a: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'fffffffe ffffffff 00000000 00000000 fffffffc',
  b: 'b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f ' +
     '5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef',
  n: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 ' +
     'f4372ddf 581a0db2 48b0a77a ecec196a ccc52973',
  hash: hash.sha384,
  gRed: false,
  g: [
    'aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 ' +
    '5502f25d bf55296c 3a545e38 72760ab7',
    '3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 ' +
    '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f'
  ]
});

defineCurve('p521', {
  type: 'short',
  prime: null,
  p: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'ffffffff ffffffff ffffffff ffffffff ffffffff',
  a: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'ffffffff ffffffff ffffffff ffffffff fffffffc',
  b: '00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b ' +
     '99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd ' +
     '3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00',
  n: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
     'ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 ' +
     'f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409',
  hash: hash.sha512,
  gRed: false,
  g: [
    '000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 ' +
    '053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 ' +
    'a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66',
    '00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 ' +
    '579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 ' +
    '3fad0761 353c7086 a272c240 88be9476 9fd16650'
  ]
});

defineCurve('curve25519', {
  type: 'mont',
  prime: 'p25519',
  p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
  a: '76d06',
  b: '0',
  n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
  hash: hash.sha256,
  gRed: false,
  g: [
    '9'
  ]
});

defineCurve('ed25519', {
  type: 'edwards',
  prime: 'p25519',
  p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
  a: '-1',
  c: '1',
  // -121665 * (121666^(-1)) (mod P)
  d: '52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3',
  n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
  hash: hash.sha256,
  gRed: false,
  g: [
    '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',

    // 4/5
    '6666666666666666666666666666666666666666666666666666666666666658'
  ]
});

var pre;
try {
  pre = require('./precomputed/secp256k1');
} catch (e) {
  pre = undefined;
}

defineCurve('secp256k1', {
  type: 'short',
  prime: 'k256',
  p: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f',
  a: '0',
  b: '7',
  n: 'ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141',
  h: '1',
  hash: hash.sha256,

  // Precomputed endomorphism
  beta: '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee',
  lambda: '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72',
  basis: [
    {
      a: '3086d221a7d46bcde86c90e49284eb15',
      b: '-e4437ed6010e88286f547fa90abfe4c3'
    },
    {
      a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
      b: '3086d221a7d46bcde86c90e49284eb15'
    }
  ],

  gRed: false,
  g: [
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    pre
  ]
});

},{"../elliptic":24,"./precomputed/secp256k1":38,"hash.js":41}],31:[function(require,module,exports){
'use strict';

var BN = require('bn.js');
var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;

var KeyPair = require('./key');
var Signature = require('./signature');

function EC(options) {
  if (!(this instanceof EC))
    return new EC(options);

  // Shortcut `elliptic.ec(curve-name)`
  if (typeof options === 'string') {
    assert(elliptic.curves.hasOwnProperty(options), 'Unknown curve ' + options);

    options = elliptic.curves[options];
  }

  // Shortcut for `elliptic.ec(elliptic.curves.curveName)`
  if (options instanceof elliptic.curves.PresetCurve)
    options = { curve: options };

  this.curve = options.curve.curve;
  this.n = this.curve.n;
  this.nh = this.n.ushrn(1);
  this.g = this.curve.g;

  // Point on curve
  this.g = options.curve.g;
  this.g.precompute(options.curve.n.bitLength() + 1);

  // Hash for function for DRBG
  this.hash = options.hash || options.curve.hash;
}
module.exports = EC;

EC.prototype.keyPair = function keyPair(options) {
  return new KeyPair(this, options);
};

EC.prototype.keyFromPrivate = function keyFromPrivate(priv, enc) {
  return KeyPair.fromPrivate(this, priv, enc);
};

EC.prototype.keyFromPublic = function keyFromPublic(pub, enc) {
  return KeyPair.fromPublic(this, pub, enc);
};

EC.prototype.genKeyPair = function genKeyPair(options) {
  if (!options)
    options = {};

  // Instantiate Hmac_DRBG
  var drbg = new elliptic.hmacDRBG({
    hash: this.hash,
    pers: options.pers,
    entropy: options.entropy || elliptic.rand(this.hash.hmacStrength),
    nonce: this.n.toArray()
  });

  var bytes = this.n.byteLength();
  var ns2 = this.n.sub(new BN(2));
  do {
    var priv = new BN(drbg.generate(bytes));
    if (priv.cmp(ns2) > 0)
      continue;

    priv.iaddn(1);
    return this.keyFromPrivate(priv);
  } while (true);
};

EC.prototype._truncateToN = function truncateToN(msg, truncOnly) {
  var delta = msg.byteLength() * 8 - this.n.bitLength();
  if (delta > 0)
    msg = msg.ushrn(delta);
  if (!truncOnly && msg.cmp(this.n) >= 0)
    return msg.sub(this.n);
  else
    return msg;
};

EC.prototype.sign = function sign(msg, key, enc, options) {
  if (typeof enc === 'object') {
    options = enc;
    enc = null;
  }
  if (!options)
    options = {};

  key = this.keyFromPrivate(key, enc);
  msg = this._truncateToN(new BN(msg, 16));

  // Zero-extend key to provide enough entropy
  var bytes = this.n.byteLength();
  var bkey = key.getPrivate().toArray('be', bytes);

  // Zero-extend nonce to have the same byte size as N
  var nonce = msg.toArray('be', bytes);

  // Instantiate Hmac_DRBG
  var drbg = new elliptic.hmacDRBG({
    hash: this.hash,
    entropy: bkey,
    nonce: nonce,
    pers: options.pers,
    persEnc: options.persEnc
  });

  // Number of bytes to generate
  var ns1 = this.n.sub(new BN(1));

  for (var iter = 0; true; iter++) {
    var k = options.k ?
        options.k(iter) :
        new BN(drbg.generate(this.n.byteLength()));
    k = this._truncateToN(k, true);
    if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0)
      continue;

    var kp = this.g.mul(k);
    if (kp.isInfinity())
      continue;

    var kpX = kp.getX();
    var r = kpX.umod(this.n);
    if (r.cmpn(0) === 0)
      continue;

    var s = k.invm(this.n).mul(r.mul(key.getPrivate()).iadd(msg));
    s = s.umod(this.n);
    if (s.cmpn(0) === 0)
      continue;

    var recoveryParam = (kp.getY().isOdd() ? 1 : 0) |
                        (kpX.cmp(r) !== 0 ? 2 : 0);

    // Use complement of `s`, if it is > `n / 2`
    if (options.canonical && s.cmp(this.nh) > 0) {
      s = this.n.sub(s);
      recoveryParam ^= 1;
    }

    return new Signature({ r: r, s: s, recoveryParam: recoveryParam });
  }
};

EC.prototype.verify = function verify(msg, signature, key, enc) {
  msg = this._truncateToN(new BN(msg, 16));
  key = this.keyFromPublic(key, enc);
  signature = new Signature(signature, 'hex');

  // Perform primitive values validation
  var r = signature.r;
  var s = signature.s;
  if (r.cmpn(1) < 0 || r.cmp(this.n) >= 0)
    return false;
  if (s.cmpn(1) < 0 || s.cmp(this.n) >= 0)
    return false;

  // Validate signature
  var sinv = s.invm(this.n);
  var u1 = sinv.mul(msg).umod(this.n);
  var u2 = sinv.mul(r).umod(this.n);

  var p = this.g.mulAdd(u1, key.getPublic(), u2);
  if (p.isInfinity())
    return false;

  return p.getX().umod(this.n).cmp(r) === 0;
};

EC.prototype.recoverPubKey = function(msg, signature, j, enc) {
  assert((3 & j) === j, 'The recovery param is more than two bits');
  signature = new Signature(signature, enc);

  var n = this.n;
  var e = new BN(msg);
  var r = signature.r;
  var s = signature.s;

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = j & 1;
  var isSecondKey = j >> 1;
  if (r.cmp(this.curve.p.umod(this.curve.n)) >= 0 && isSecondKey)
    throw new Error('Unable to find sencond key candinate');

  // 1.1. Let x = r + jn.
  if (isSecondKey)
    r = this.curve.pointFromX(r.add(this.curve.n), isYOdd);
  else
    r = this.curve.pointFromX(r, isYOdd);

  var eNeg = n.sub(e);

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  var rInv = signature.r.invm(n);
  return this.g.mulAdd(eNeg, r, s).mul(rInv);
};

EC.prototype.getKeyRecoveryParam = function(e, signature, Q, enc) {
  signature = new Signature(signature, enc);
  if (signature.recoveryParam !== null)
    return signature.recoveryParam;

  for (var i = 0; i < 4; i++) {
    var Qprime;
    try {
      Qprime = this.recoverPubKey(e, signature, i);
    } catch (e) {
      continue;
    }

    if (Qprime.eq(Q))
      return i;
  }
  throw new Error('Unable to find valid recovery factor');
};

},{"../../elliptic":24,"./key":32,"./signature":33,"bn.js":21}],32:[function(require,module,exports){
'use strict';

var BN = require('bn.js');

function KeyPair(ec, options) {
  this.ec = ec;
  this.priv = null;
  this.pub = null;

  // KeyPair(ec, { priv: ..., pub: ... })
  if (options.priv)
    this._importPrivate(options.priv, options.privEnc);
  if (options.pub)
    this._importPublic(options.pub, options.pubEnc);
}
module.exports = KeyPair;

KeyPair.fromPublic = function fromPublic(ec, pub, enc) {
  if (pub instanceof KeyPair)
    return pub;

  return new KeyPair(ec, {
    pub: pub,
    pubEnc: enc
  });
};

KeyPair.fromPrivate = function fromPrivate(ec, priv, enc) {
  if (priv instanceof KeyPair)
    return priv;

  return new KeyPair(ec, {
    priv: priv,
    privEnc: enc
  });
};

KeyPair.prototype.validate = function validate() {
  var pub = this.getPublic();

  if (pub.isInfinity())
    return { result: false, reason: 'Invalid public key' };
  if (!pub.validate())
    return { result: false, reason: 'Public key is not a point' };
  if (!pub.mul(this.ec.curve.n).isInfinity())
    return { result: false, reason: 'Public key * N != O' };

  return { result: true, reason: null };
};

KeyPair.prototype.getPublic = function getPublic(compact, enc) {
  // compact is optional argument
  if (typeof compact === 'string') {
    enc = compact;
    compact = null;
  }

  if (!this.pub)
    this.pub = this.ec.g.mul(this.priv);

  if (!enc)
    return this.pub;

  return this.pub.encode(enc, compact);
};

KeyPair.prototype.getPrivate = function getPrivate(enc) {
  if (enc === 'hex')
    return this.priv.toString(16, 2);
  else
    return this.priv;
};

KeyPair.prototype._importPrivate = function _importPrivate(key, enc) {
  this.priv = new BN(key, enc || 16);

  // Ensure that the priv won't be bigger than n, otherwise we may fail
  // in fixed multiplication method
  this.priv = this.priv.umod(this.ec.curve.n);
};

KeyPair.prototype._importPublic = function _importPublic(key, enc) {
  if (key.x || key.y) {
    this.pub = this.ec.curve.point(key.x, key.y);
    return;
  }
  this.pub = this.ec.curve.decodePoint(key, enc);
};

// ECDH
KeyPair.prototype.derive = function derive(pub) {
  return pub.mul(this.priv).getX();
};

// ECDSA
KeyPair.prototype.sign = function sign(msg, enc, options) {
  return this.ec.sign(msg, this, enc, options);
};

KeyPair.prototype.verify = function verify(msg, signature) {
  return this.ec.verify(msg, signature, this);
};

KeyPair.prototype.inspect = function inspect() {
  return '<Key priv: ' + (this.priv && this.priv.toString(16, 2)) +
         ' pub: ' + (this.pub && this.pub.inspect()) + ' >';
};

},{"bn.js":21}],33:[function(require,module,exports){
'use strict';

var BN = require('bn.js');

var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;

function Signature(options, enc) {
  if (options instanceof Signature)
    return options;

  if (this._importDER(options, enc))
    return;

  assert(options.r && options.s, 'Signature without r or s');
  this.r = new BN(options.r, 16);
  this.s = new BN(options.s, 16);
  if (options.recoveryParam === undefined)
    this.recoveryParam = null;
  else
    this.recoveryParam = options.recoveryParam;
}
module.exports = Signature;

function Position() {
  this.place = 0;
}

function getLength(buf, p) {
  var initial = buf[p.place++];
  if (!(initial & 0x80)) {
    return initial;
  }
  var octetLen = initial & 0xf;
  var val = 0;
  for (var i = 0, off = p.place; i < octetLen; i++, off++) {
    val <<= 8;
    val |= buf[off];
  }
  p.place = off;
  return val;
}

function rmPadding(buf) {
  var i = 0;
  var len = buf.length - 1;
  while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
    i++;
  }
  if (i === 0) {
    return buf;
  }
  return buf.slice(i);
}

Signature.prototype._importDER = function _importDER(data, enc) {
  data = utils.toArray(data, enc);
  var p = new Position();
  if (data[p.place++] !== 0x30) {
    return false;
  }
  var len = getLength(data, p);
  if ((len + p.place) !== data.length) {
    return false;
  }
  if (data[p.place++] !== 0x02) {
    return false;
  }
  var rlen = getLength(data, p);
  var r = data.slice(p.place, rlen + p.place);
  p.place += rlen;
  if (data[p.place++] !== 0x02) {
    return false;
  }
  var slen = getLength(data, p);
  if (data.length !== slen + p.place) {
    return false;
  }
  var s = data.slice(p.place, slen + p.place);
  if (r[0] === 0 && (r[1] & 0x80)) {
    r = r.slice(1);
  }
  if (s[0] === 0 && (s[1] & 0x80)) {
    s = s.slice(1);
  }

  this.r = new BN(r);
  this.s = new BN(s);
  this.recoveryParam = null;

  return true;
};

function constructLength(arr, len) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  var octets = 1 + (Math.log(len) / Math.LN2 >>> 3);
  arr.push(octets | 0x80);
  while (--octets) {
    arr.push((len >>> (octets << 3)) & 0xff);
  }
  arr.push(len);
}

Signature.prototype.toDER = function toDER(enc) {
  var r = this.r.toArray();
  var s = this.s.toArray();

  // Pad values
  if (r[0] & 0x80)
    r = [ 0 ].concat(r);
  // Pad values
  if (s[0] & 0x80)
    s = [ 0 ].concat(s);

  r = rmPadding(r);
  s = rmPadding(s);

  while (!s[0] && !(s[1] & 0x80)) {
    s = s.slice(1);
  }
  var arr = [ 0x02 ];
  constructLength(arr, r.length);
  arr = arr.concat(r);
  arr.push(0x02);
  constructLength(arr, s.length);
  var backHalf = arr.concat(s);
  var res = [ 0x30 ];
  constructLength(res, backHalf.length);
  res = res.concat(backHalf);
  return utils.encode(res, enc);
};

},{"../../elliptic":24,"bn.js":21}],34:[function(require,module,exports){
'use strict';

var hash = require('hash.js');
var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;
var parseBytes = utils.parseBytes;
var KeyPair = require('./key');
var Signature = require('./signature');

function EDDSA(curve) {
  assert(curve === 'ed25519', 'only tested with ed25519 so far');

  if (!(this instanceof EDDSA))
    return new EDDSA(curve);

  var curve = elliptic.curves[curve].curve;
  this.curve = curve;
  this.g = curve.g;
  this.g.precompute(curve.n.bitLength() + 1);

  this.pointClass = curve.point().constructor;
  this.encodingLength = Math.ceil(curve.n.bitLength() / 8);
  this.hash = hash.sha512;
}

module.exports = EDDSA;

/**
* @param {Array|String} message - message bytes
* @param {Array|String|KeyPair} secret - secret bytes or a keypair
* @returns {Signature} - signature
*/
EDDSA.prototype.sign = function sign(message, secret) {
  message = parseBytes(message);
  var key = this.keyFromSecret(secret);
  var r = this.hashInt(key.messagePrefix(), message);
  var R = this.g.mul(r);
  var Rencoded = this.encodePoint(R);
  var s_ = this.hashInt(Rencoded, key.pubBytes(), message)
               .mul(key.priv());
  var S = r.add(s_).umod(this.curve.n);
  return this.makeSignature({ R: R, S: S, Rencoded: Rencoded });
};

/**
* @param {Array} message - message bytes
* @param {Array|String|Signature} sig - sig bytes
* @param {Array|String|Point|KeyPair} pub - public key
* @returns {Boolean} - true if public key matches sig of message
*/
EDDSA.prototype.verify = function verify(message, sig, pub) {
  message = parseBytes(message);
  sig = this.makeSignature(sig);
  var key = this.keyFromPublic(pub);
  var h = this.hashInt(sig.Rencoded(), key.pubBytes(), message);
  var SG = this.g.mul(sig.S());
  var RplusAh = sig.R().add(key.pub().mul(h));
  return RplusAh.eq(SG);
};

EDDSA.prototype.hashInt = function hashInt() {
  var hash = this.hash();
  for (var i = 0; i < arguments.length; i++)
    hash.update(arguments[i]);
  return utils.intFromLE(hash.digest()).umod(this.curve.n);
};

EDDSA.prototype.keyFromPublic = function keyFromPublic(pub) {
  return KeyPair.fromPublic(this, pub);
};

EDDSA.prototype.keyFromSecret = function keyFromSecret(secret) {
  return KeyPair.fromSecret(this, secret);
};

EDDSA.prototype.makeSignature = function makeSignature(sig) {
  if (sig instanceof Signature)
    return sig;
  return new Signature(this, sig);
};

/**
* * https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03#section-5.2
*
* EDDSA defines methods for encoding and decoding points and integers. These are
* helper convenience methods, that pass along to utility functions implied
* parameters.
*
*/
EDDSA.prototype.encodePoint = function encodePoint(point) {
  var enc = point.getY().toArray('le', this.encodingLength);
  enc[this.encodingLength - 1] |= point.getX().isOdd() ? 0x80 : 0;
  return enc;
};

EDDSA.prototype.decodePoint = function decodePoint(bytes) {
  bytes = utils.parseBytes(bytes);

  var lastIx = bytes.length - 1;
  var normed = bytes.slice(0, lastIx).concat(bytes[lastIx] & ~0x80);
  var xIsOdd = (bytes[lastIx] & 0x80) !== 0;

  var y = utils.intFromLE(normed);
  return this.curve.pointFromY(y, xIsOdd);
};

EDDSA.prototype.encodeInt = function encodeInt(num) {
  return num.toArray('le', this.encodingLength);
};

EDDSA.prototype.decodeInt = function decodeInt(bytes) {
  return utils.intFromLE(bytes);
};

EDDSA.prototype.isPoint = function isPoint(val) {
  return val instanceof this.pointClass;
};

},{"../../elliptic":24,"./key":35,"./signature":36,"hash.js":41}],35:[function(require,module,exports){
'use strict';

var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;
var parseBytes = utils.parseBytes;
var cachedProperty = utils.cachedProperty;

/**
* @param {EDDSA} eddsa - instance
* @param {Object} params - public/private key parameters
*
* @param {Array<Byte>} [params.secret] - secret seed bytes
* @param {Point} [params.pub] - public key point (aka `A` in eddsa terms)
* @param {Array<Byte>} [params.pub] - public key point encoded as bytes
*
*/
function KeyPair(eddsa, params) {
  this.eddsa = eddsa;
  this._secret = parseBytes(params.secret);
  if (eddsa.isPoint(params.pub))
    this._pub = params.pub;
  else
    this._pubBytes = parseBytes(params.pub);
}

KeyPair.fromPublic = function fromPublic(eddsa, pub) {
  if (pub instanceof KeyPair)
    return pub;
  return new KeyPair(eddsa, { pub: pub });
};

KeyPair.fromSecret = function fromSecret(eddsa, secret) {
  if (secret instanceof KeyPair)
    return secret;
  return new KeyPair(eddsa, { secret: secret });
};

KeyPair.prototype.secret = function secret() {
  return this._secret;
};

cachedProperty(KeyPair, 'pubBytes', function pubBytes() {
  return this.eddsa.encodePoint(this.pub());
});

cachedProperty(KeyPair, 'pub', function pub() {
  if (this._pubBytes)
    return this.eddsa.decodePoint(this._pubBytes);
  return this.eddsa.g.mul(this.priv());
});

cachedProperty(KeyPair, 'privBytes', function privBytes() {
  var eddsa = this.eddsa;
  var hash = this.hash();
  var lastIx = eddsa.encodingLength - 1;

  var a = hash.slice(0, eddsa.encodingLength);
  a[0] &= 248;
  a[lastIx] &= 127;
  a[lastIx] |= 64;

  return a;
});

cachedProperty(KeyPair, 'priv', function priv() {
  return this.eddsa.decodeInt(this.privBytes());
});

cachedProperty(KeyPair, 'hash', function hash() {
  return this.eddsa.hash().update(this.secret()).digest();
});

cachedProperty(KeyPair, 'messagePrefix', function messagePrefix() {
  return this.hash().slice(this.eddsa.encodingLength);
});

KeyPair.prototype.sign = function sign(message) {
  assert(this._secret, 'KeyPair can only verify');
  return this.eddsa.sign(message, this);
};

KeyPair.prototype.verify = function verify(message, sig) {
  return this.eddsa.verify(message, sig, this);
};

KeyPair.prototype.getSecret = function getSecret(enc) {
  assert(this._secret, 'KeyPair is public only');
  return utils.encode(this.secret(), enc);
};

KeyPair.prototype.getPublic = function getPublic(enc) {
  return utils.encode(this.pubBytes(), enc);
};

module.exports = KeyPair;

},{"../../elliptic":24}],36:[function(require,module,exports){
'use strict';

var BN = require('bn.js');
var elliptic = require('../../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;
var cachedProperty = utils.cachedProperty;
var parseBytes = utils.parseBytes;

/**
* @param {EDDSA} eddsa - eddsa instance
* @param {Array<Bytes>|Object} sig -
* @param {Array<Bytes>|Point} [sig.R] - R point as Point or bytes
* @param {Array<Bytes>|bn} [sig.S] - S scalar as bn or bytes
* @param {Array<Bytes>} [sig.Rencoded] - R point encoded
* @param {Array<Bytes>} [sig.Sencoded] - S scalar encoded
*/
function Signature(eddsa, sig) {
  this.eddsa = eddsa;

  if (typeof sig !== 'object')
    sig = parseBytes(sig);

  if (Array.isArray(sig)) {
    sig = {
      R: sig.slice(0, eddsa.encodingLength),
      S: sig.slice(eddsa.encodingLength)
    };
  }

  assert(sig.R && sig.S, 'Signature without R or S');

  if (eddsa.isPoint(sig.R))
    this._R = sig.R;
  if (sig.S instanceof BN)
    this._S = sig.S;

  this._Rencoded = Array.isArray(sig.R) ? sig.R : sig.Rencoded;
  this._Sencoded = Array.isArray(sig.S) ? sig.S : sig.Sencoded;
}

cachedProperty(Signature, 'S', function S() {
  return this.eddsa.decodeInt(this.Sencoded());
});

cachedProperty(Signature, 'R', function R() {
  return this.eddsa.decodePoint(this.Rencoded());
});

cachedProperty(Signature, 'Rencoded', function Rencoded() {
  return this.eddsa.encodePoint(this.R());
});

cachedProperty(Signature, 'Sencoded', function Sencoded() {
  return this.eddsa.encodeInt(this.S());
});

Signature.prototype.toBytes = function toBytes() {
  return this.Rencoded().concat(this.Sencoded());
};

Signature.prototype.toHex = function toHex() {
  return utils.encode(this.toBytes(), 'hex').toUpperCase();
};

module.exports = Signature;

},{"../../elliptic":24,"bn.js":21}],37:[function(require,module,exports){
'use strict';

var hash = require('hash.js');
var elliptic = require('../elliptic');
var utils = elliptic.utils;
var assert = utils.assert;

function HmacDRBG(options) {
  if (!(this instanceof HmacDRBG))
    return new HmacDRBG(options);
  this.hash = options.hash;
  this.predResist = !!options.predResist;

  this.outLen = this.hash.outSize;
  this.minEntropy = options.minEntropy || this.hash.hmacStrength;

  this.reseed = null;
  this.reseedInterval = null;
  this.K = null;
  this.V = null;

  var entropy = utils.toArray(options.entropy, options.entropyEnc);
  var nonce = utils.toArray(options.nonce, options.nonceEnc);
  var pers = utils.toArray(options.pers, options.persEnc);
  assert(entropy.length >= (this.minEntropy / 8),
         'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');
  this._init(entropy, nonce, pers);
}
module.exports = HmacDRBG;

HmacDRBG.prototype._init = function init(entropy, nonce, pers) {
  var seed = entropy.concat(nonce).concat(pers);

  this.K = new Array(this.outLen / 8);
  this.V = new Array(this.outLen / 8);
  for (var i = 0; i < this.V.length; i++) {
    this.K[i] = 0x00;
    this.V[i] = 0x01;
  }

  this._update(seed);
  this.reseed = 1;
  this.reseedInterval = 0x1000000000000;  // 2^48
};

HmacDRBG.prototype._hmac = function hmac() {
  return new hash.hmac(this.hash, this.K);
};

HmacDRBG.prototype._update = function update(seed) {
  var kmac = this._hmac()
                 .update(this.V)
                 .update([ 0x00 ]);
  if (seed)
    kmac = kmac.update(seed);
  this.K = kmac.digest();
  this.V = this._hmac().update(this.V).digest();
  if (!seed)
    return;

  this.K = this._hmac()
               .update(this.V)
               .update([ 0x01 ])
               .update(seed)
               .digest();
  this.V = this._hmac().update(this.V).digest();
};

HmacDRBG.prototype.reseed = function reseed(entropy, entropyEnc, add, addEnc) {
  // Optional entropy enc
  if (typeof entropyEnc !== 'string') {
    addEnc = add;
    add = entropyEnc;
    entropyEnc = null;
  }

  entropy = utils.toBuffer(entropy, entropyEnc);
  add = utils.toBuffer(add, addEnc);

  assert(entropy.length >= (this.minEntropy / 8),
         'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');

  this._update(entropy.concat(add || []));
  this.reseed = 1;
};

HmacDRBG.prototype.generate = function generate(len, enc, add, addEnc) {
  if (this.reseed > this.reseedInterval)
    throw new Error('Reseed is required');

  // Optional encoding
  if (typeof enc !== 'string') {
    addEnc = add;
    add = enc;
    enc = null;
  }

  // Optional additional data
  if (add) {
    add = utils.toArray(add, addEnc);
    this._update(add);
  }

  var temp = [];
  while (temp.length < len) {
    this.V = this._hmac().update(this.V).digest();
    temp = temp.concat(this.V);
  }

  var res = temp.slice(0, len);
  this._update(add);
  this.reseed++;
  return utils.encode(res, enc);
};

},{"../elliptic":24,"hash.js":41}],38:[function(require,module,exports){
module.exports = {
  doubles: {
    step: 4,
    points: [
      [
        'e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a',
        'f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821'
      ],
      [
        '8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508',
        '11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf'
      ],
      [
        '175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739',
        'd3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695'
      ],
      [
        '363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640',
        '4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9'
      ],
      [
        '8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c',
        '4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36'
      ],
      [
        '723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda',
        '96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f'
      ],
      [
        'eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa',
        '5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999'
      ],
      [
        '100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0',
        'cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09'
      ],
      [
        'e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d',
        '9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d'
      ],
      [
        'feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d',
        'e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088'
      ],
      [
        'da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1',
        '9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d'
      ],
      [
        '53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0',
        '5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8'
      ],
      [
        '8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047',
        '10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a'
      ],
      [
        '385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862',
        '283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453'
      ],
      [
        '6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7',
        '7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160'
      ],
      [
        '3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd',
        '56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0'
      ],
      [
        '85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83',
        '7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6'
      ],
      [
        '948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a',
        '53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589'
      ],
      [
        '6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8',
        'bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17'
      ],
      [
        'e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d',
        '4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda'
      ],
      [
        'e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725',
        '7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd'
      ],
      [
        '213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754',
        '4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2'
      ],
      [
        '4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c',
        '17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6'
      ],
      [
        'fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6',
        '6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f'
      ],
      [
        '76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39',
        'c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01'
      ],
      [
        'c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891',
        '893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3'
      ],
      [
        'd895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b',
        'febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f'
      ],
      [
        'b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03',
        '2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7'
      ],
      [
        'e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d',
        'eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78'
      ],
      [
        'a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070',
        '7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1'
      ],
      [
        '90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4',
        'e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150'
      ],
      [
        '8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da',
        '662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82'
      ],
      [
        'e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11',
        '1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc'
      ],
      [
        '8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e',
        'efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b'
      ],
      [
        'e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41',
        '2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51'
      ],
      [
        'b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef',
        '67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45'
      ],
      [
        'd68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8',
        'db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120'
      ],
      [
        '324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d',
        '648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84'
      ],
      [
        '4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96',
        '35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d'
      ],
      [
        '9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd',
        'ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d'
      ],
      [
        '6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5',
        '9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8'
      ],
      [
        'a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266',
        '40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8'
      ],
      [
        '7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71',
        '34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac'
      ],
      [
        '928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac',
        'c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f'
      ],
      [
        '85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751',
        '1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962'
      ],
      [
        'ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e',
        '493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907'
      ],
      [
        '827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241',
        'c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec'
      ],
      [
        'eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3',
        'be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d'
      ],
      [
        'e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f',
        '4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414'
      ],
      [
        '1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19',
        'aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd'
      ],
      [
        '146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be',
        'b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0'
      ],
      [
        'fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9',
        '6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811'
      ],
      [
        'da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2',
        '8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1'
      ],
      [
        'a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13',
        '7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c'
      ],
      [
        '174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c',
        'ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73'
      ],
      [
        '959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba',
        '2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd'
      ],
      [
        'd2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151',
        'e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405'
      ],
      [
        '64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073',
        'd99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589'
      ],
      [
        '8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458',
        '38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e'
      ],
      [
        '13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b',
        '69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27'
      ],
      [
        'bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366',
        'd3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1'
      ],
      [
        '8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa',
        '40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482'
      ],
      [
        '8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0',
        '620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945'
      ],
      [
        'dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787',
        '7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573'
      ],
      [
        'f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e',
        'ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82'
      ]
    ]
  },
  naf: {
    wnd: 7,
    points: [
      [
        'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
        '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'
      ],
      [
        '2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4',
        'd8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6'
      ],
      [
        '5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
        '6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da'
      ],
      [
        'acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe',
        'cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37'
      ],
      [
        '774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb',
        'd984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b'
      ],
      [
        'f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8',
        'ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81'
      ],
      [
        'd7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e',
        '581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58'
      ],
      [
        'defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34',
        '4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77'
      ],
      [
        '2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c',
        '85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a'
      ],
      [
        '352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5',
        '321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c'
      ],
      [
        '2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f',
        '2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67'
      ],
      [
        '9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714',
        '73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402'
      ],
      [
        'daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729',
        'a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55'
      ],
      [
        'c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db',
        '2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482'
      ],
      [
        '6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4',
        'e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82'
      ],
      [
        '1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5',
        'b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396'
      ],
      [
        '605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479',
        '2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49'
      ],
      [
        '62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d',
        '80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf'
      ],
      [
        '80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f',
        '1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a'
      ],
      [
        '7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb',
        'd0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7'
      ],
      [
        'd528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9',
        'eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933'
      ],
      [
        '49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963',
        '758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a'
      ],
      [
        '77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74',
        '958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6'
      ],
      [
        'f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530',
        'e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37'
      ],
      [
        '463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b',
        '5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e'
      ],
      [
        'f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247',
        'cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6'
      ],
      [
        'caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1',
        'cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476'
      ],
      [
        '2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120',
        '4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40'
      ],
      [
        '7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435',
        '91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61'
      ],
      [
        '754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18',
        '673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683'
      ],
      [
        'e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8',
        '59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5'
      ],
      [
        '186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb',
        '3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b'
      ],
      [
        'df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f',
        '55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417'
      ],
      [
        '5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143',
        'efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868'
      ],
      [
        '290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba',
        'e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a'
      ],
      [
        'af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45',
        'f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6'
      ],
      [
        '766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a',
        '744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996'
      ],
      [
        '59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e',
        'c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e'
      ],
      [
        'f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8',
        'e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d'
      ],
      [
        '7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c',
        '30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2'
      ],
      [
        '948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519',
        'e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e'
      ],
      [
        '7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab',
        '100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437'
      ],
      [
        '3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca',
        'ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311'
      ],
      [
        'd3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf',
        '8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4'
      ],
      [
        '1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610',
        '68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575'
      ],
      [
        '733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4',
        'f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d'
      ],
      [
        '15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c',
        'd56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d'
      ],
      [
        'a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940',
        'edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629'
      ],
      [
        'e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980',
        'a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06'
      ],
      [
        '311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3',
        '66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374'
      ],
      [
        '34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf',
        '9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee'
      ],
      [
        'f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63',
        '4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1'
      ],
      [
        'd7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448',
        'fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b'
      ],
      [
        '32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf',
        '5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661'
      ],
      [
        '7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5',
        '8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6'
      ],
      [
        'ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6',
        '8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e'
      ],
      [
        '16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5',
        '5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d'
      ],
      [
        'eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99',
        'f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc'
      ],
      [
        '78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51',
        'f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4'
      ],
      [
        '494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5',
        '42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c'
      ],
      [
        'a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
        '204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b'
      ],
      [
        'c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997',
        '4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913'
      ],
      [
        '841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881',
        '73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154'
      ],
      [
        '5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5',
        '39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865'
      ],
      [
        '36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66',
        'd2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc'
      ],
      [
        '336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726',
        'ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224'
      ],
      [
        '8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede',
        '6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e'
      ],
      [
        '1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94',
        '60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6'
      ],
      [
        '85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31',
        '3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511'
      ],
      [
        '29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51',
        'b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b'
      ],
      [
        'a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252',
        'ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2'
      ],
      [
        '4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5',
        'cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c'
      ],
      [
        'd24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b',
        '6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3'
      ],
      [
        'ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4',
        '322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d'
      ],
      [
        'af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f',
        '6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700'
      ],
      [
        'e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889',
        '2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4'
      ],
      [
        '591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246',
        'b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196'
      ],
      [
        '11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984',
        '998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4'
      ],
      [
        '3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a',
        'b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257'
      ],
      [
        'cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030',
        'bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13'
      ],
      [
        'c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197',
        '6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096'
      ],
      [
        'c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593',
        'c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38'
      ],
      [
        'a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef',
        '21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f'
      ],
      [
        '347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38',
        '60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448'
      ],
      [
        'da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a',
        '49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a'
      ],
      [
        'c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111',
        '5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4'
      ],
      [
        '4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502',
        '7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437'
      ],
      [
        '3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea',
        'be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7'
      ],
      [
        'cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26',
        '8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d'
      ],
      [
        'b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986',
        '39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a'
      ],
      [
        'd4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e',
        '62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54'
      ],
      [
        '48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4',
        '25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77'
      ],
      [
        'dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda',
        'ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517'
      ],
      [
        '6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859',
        'cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10'
      ],
      [
        'e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f',
        'f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125'
      ],
      [
        'eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c',
        '6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e'
      ],
      [
        '13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942',
        'fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1'
      ],
      [
        'ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a',
        '1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2'
      ],
      [
        'b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80',
        '5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423'
      ],
      [
        'ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d',
        '438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8'
      ],
      [
        '8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1',
        'cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758'
      ],
      [
        '52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63',
        'c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375'
      ],
      [
        'e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352',
        '6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d'
      ],
      [
        '7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193',
        'ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec'
      ],
      [
        '5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00',
        '9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0'
      ],
      [
        '32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58',
        'ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c'
      ],
      [
        'e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7',
        'd3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4'
      ],
      [
        '8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8',
        'c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f'
      ],
      [
        '4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e',
        '67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649'
      ],
      [
        '3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d',
        'cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826'
      ],
      [
        '674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b',
        '299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5'
      ],
      [
        'd32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f',
        'f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87'
      ],
      [
        '30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6',
        '462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b'
      ],
      [
        'be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297',
        '62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc'
      ],
      [
        '93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a',
        '7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c'
      ],
      [
        'b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c',
        'ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f'
      ],
      [
        'd5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52',
        '4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a'
      ],
      [
        'd3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb',
        'bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46'
      ],
      [
        '463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065',
        'bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f'
      ],
      [
        '7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917',
        '603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03'
      ],
      [
        '74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9',
        'cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08'
      ],
      [
        '30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3',
        '553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8'
      ],
      [
        '9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57',
        '712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373'
      ],
      [
        '176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66',
        'ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3'
      ],
      [
        '75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8',
        '9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8'
      ],
      [
        '809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721',
        '9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1'
      ],
      [
        '1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180',
        '4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9'
      ]
    ]
  }
};

},{}],39:[function(require,module,exports){
'use strict';

var utils = exports;
var BN = require('bn.js');

utils.assert = function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
};

function toArray(msg, enc) {
  if (Array.isArray(msg))
    return msg.slice();
  if (!msg)
    return [];
  var res = [];
  if (typeof msg !== 'string') {
    for (var i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
    return res;
  }
  if (!enc) {
    for (var i = 0; i < msg.length; i++) {
      var c = msg.charCodeAt(i);
      var hi = c >> 8;
      var lo = c & 0xff;
      if (hi)
        res.push(hi, lo);
      else
        res.push(lo);
    }
  } else if (enc === 'hex') {
    msg = msg.replace(/[^a-z0-9]+/ig, '');
    if (msg.length % 2 !== 0)
      msg = '0' + msg;
    for (var i = 0; i < msg.length; i += 2)
      res.push(parseInt(msg[i] + msg[i + 1], 16));
  }
  return res;
}
utils.toArray = toArray;

function zero2(word) {
  if (word.length === 1)
    return '0' + word;
  else
    return word;
}
utils.zero2 = zero2;

function toHex(msg) {
  var res = '';
  for (var i = 0; i < msg.length; i++)
    res += zero2(msg[i].toString(16));
  return res;
}
utils.toHex = toHex;

utils.encode = function encode(arr, enc) {
  if (enc === 'hex')
    return toHex(arr);
  else
    return arr;
};

// Represent num in a w-NAF form
function getNAF(num, w) {
  var naf = [];
  var ws = 1 << (w + 1);
  var k = num.clone();
  while (k.cmpn(1) >= 0) {
    var z;
    if (k.isOdd()) {
      var mod = k.andln(ws - 1);
      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;
      k.isubn(z);
    } else {
      z = 0;
    }
    naf.push(z);

    // Optimization, shift by word if possible
    var shift = (k.cmpn(0) !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;
    for (var i = 1; i < shift; i++)
      naf.push(0);
    k.iushrn(shift);
  }

  return naf;
}
utils.getNAF = getNAF;

// Represent k1, k2 in a Joint Sparse Form
function getJSF(k1, k2) {
  var jsf = [
    [],
    []
  ];

  k1 = k1.clone();
  k2 = k2.clone();
  var d1 = 0;
  var d2 = 0;
  while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {

    // First phase
    var m14 = (k1.andln(3) + d1) & 3;
    var m24 = (k2.andln(3) + d2) & 3;
    if (m14 === 3)
      m14 = -1;
    if (m24 === 3)
      m24 = -1;
    var u1;
    if ((m14 & 1) === 0) {
      u1 = 0;
    } else {
      var m8 = (k1.andln(7) + d1) & 7;
      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }
    jsf[0].push(u1);

    var u2;
    if ((m24 & 1) === 0) {
      u2 = 0;
    } else {
      var m8 = (k2.andln(7) + d2) & 7;
      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }
    jsf[1].push(u2);

    // Second phase
    if (2 * d1 === u1 + 1)
      d1 = 1 - d1;
    if (2 * d2 === u2 + 1)
      d2 = 1 - d2;
    k1.iushrn(1);
    k2.iushrn(1);
  }

  return jsf;
}
utils.getJSF = getJSF;

function cachedProperty(obj, name, computer) {
  var key = '_' + name;
  obj.prototype[name] = function cachedProperty() {
    return this[key] !== undefined ? this[key] :
           this[key] = computer.call(this);
  };
}
utils.cachedProperty = cachedProperty;

function parseBytes(bytes) {
  return typeof bytes === 'string' ? utils.toArray(bytes, 'hex') :
                                     bytes;
}
utils.parseBytes = parseBytes;

function intFromLE(bytes) {
  return new BN(bytes, 'hex', 'le');
}
utils.intFromLE = intFromLE;


},{"bn.js":21}],40:[function(require,module,exports){
module.exports={
  "_args": [
    [
      "elliptic@^6.0.0",
      "/Users/cmetcalf/projects/gen-csr/node_modules/browserify-sign"
    ]
  ],
  "_from": "elliptic@>=6.0.0 <7.0.0",
  "_id": "elliptic@6.2.7",
  "_inCache": true,
  "_installable": true,
  "_location": "/elliptic",
  "_nodeVersion": "6.0.0",
  "_npmOperationalInternal": {
    "host": "packages-12-west.internal.npmjs.com",
    "tmp": "tmp/elliptic-6.2.7.tgz_1464201793202_0.12479878286831081"
  },
  "_npmUser": {
    "email": "fedor@indutny.com",
    "name": "indutny"
  },
  "_npmVersion": "3.8.6",
  "_phantomChildren": {},
  "_requested": {
    "name": "elliptic",
    "raw": "elliptic@^6.0.0",
    "rawSpec": "^6.0.0",
    "scope": null,
    "spec": ">=6.0.0 <7.0.0",
    "type": "range"
  },
  "_requiredBy": [
    "/browserify-sign",
    "/create-ecdh"
  ],
  "_resolved": "https://registry.npmjs.org/elliptic/-/elliptic-6.2.7.tgz",
  "_shasum": "dce82efbf176eefa7495d4be3e8b9f5b5694b295",
  "_shrinkwrap": null,
  "_spec": "elliptic@^6.0.0",
  "_where": "/Users/cmetcalf/projects/gen-csr/node_modules/browserify-sign",
  "author": {
    "email": "fedor@indutny.com",
    "name": "Fedor Indutny"
  },
  "bugs": {
    "url": "https://github.com/indutny/elliptic/issues"
  },
  "dependencies": {
    "bn.js": "^4.0.0",
    "brorand": "^1.0.1",
    "hash.js": "^1.0.0",
    "inherits": "^2.0.1"
  },
  "description": "EC cryptography",
  "devDependencies": {
    "brfs": "^1.4.3",
    "coveralls": "^2.11.3",
    "grunt": "^0.4.5",
    "grunt-browserify": "^5.0.0",
    "grunt-contrib-connect": "^1.0.0",
    "grunt-contrib-copy": "^1.0.0",
    "grunt-contrib-uglify": "^1.0.1",
    "grunt-mocha-istanbul": "^3.0.1",
    "grunt-saucelabs": "^8.6.2",
    "istanbul": "^0.4.2",
    "jscs": "^2.9.0",
    "jshint": "^2.6.0",
    "mocha": "^2.1.0"
  },
  "directories": {},
  "dist": {
    "shasum": "dce82efbf176eefa7495d4be3e8b9f5b5694b295",
    "tarball": "https://registry.npmjs.org/elliptic/-/elliptic-6.2.7.tgz"
  },
  "files": [
    "lib"
  ],
  "gitHead": "6a8ef1457bb8f45102d6678fc1095165f77d55d3",
  "homepage": "https://github.com/indutny/elliptic",
  "keywords": [
    "EC",
    "Elliptic",
    "curve",
    "Cryptography"
  ],
  "license": "MIT",
  "main": "lib/elliptic.js",
  "maintainers": [
    {
      "email": "fedor@indutny.com",
      "name": "indutny"
    }
  ],
  "name": "elliptic",
  "optionalDependencies": {},
  "readme": "ERROR: No README data found!",
  "repository": {
    "type": "git",
    "url": "git+ssh://git@github.com/indutny/elliptic.git"
  },
  "scripts": {
    "jscs": "jscs benchmarks/*.js lib/*.js lib/**/*.js lib/**/**/*.js test/index.js",
    "jshint": "jscs benchmarks/*.js lib/*.js lib/**/*.js lib/**/**/*.js test/index.js",
    "lint": "npm run jscs && npm run jshint",
    "test": "npm run lint && npm run unit",
    "unit": "istanbul test _mocha --reporter=spec test/index.js",
    "version": "grunt dist && git add dist/"
  },
  "version": "6.2.7"
}

},{}],41:[function(require,module,exports){
var hash = exports;

hash.utils = require('./hash/utils');
hash.common = require('./hash/common');
hash.sha = require('./hash/sha');
hash.ripemd = require('./hash/ripemd');
hash.hmac = require('./hash/hmac');

// Proxy hash functions to the main object
hash.sha1 = hash.sha.sha1;
hash.sha256 = hash.sha.sha256;
hash.sha224 = hash.sha.sha224;
hash.sha384 = hash.sha.sha384;
hash.sha512 = hash.sha.sha512;
hash.ripemd160 = hash.ripemd.ripemd160;

},{"./hash/common":42,"./hash/hmac":43,"./hash/ripemd":44,"./hash/sha":45,"./hash/utils":46}],42:[function(require,module,exports){
var hash = require('../hash');
var utils = hash.utils;
var assert = utils.assert;

function BlockHash() {
  this.pending = null;
  this.pendingTotal = 0;
  this.blockSize = this.constructor.blockSize;
  this.outSize = this.constructor.outSize;
  this.hmacStrength = this.constructor.hmacStrength;
  this.padLength = this.constructor.padLength / 8;
  this.endian = 'big';

  this._delta8 = this.blockSize / 8;
  this._delta32 = this.blockSize / 32;
}
exports.BlockHash = BlockHash;

BlockHash.prototype.update = function update(msg, enc) {
  // Convert message to array, pad it, and join into 32bit blocks
  msg = utils.toArray(msg, enc);
  if (!this.pending)
    this.pending = msg;
  else
    this.pending = this.pending.concat(msg);
  this.pendingTotal += msg.length;

  // Enough data, try updating
  if (this.pending.length >= this._delta8) {
    msg = this.pending;

    // Process pending data in blocks
    var r = msg.length % this._delta8;
    this.pending = msg.slice(msg.length - r, msg.length);
    if (this.pending.length === 0)
      this.pending = null;

    msg = utils.join32(msg, 0, msg.length - r, this.endian);
    for (var i = 0; i < msg.length; i += this._delta32)
      this._update(msg, i, i + this._delta32);
  }

  return this;
};

BlockHash.prototype.digest = function digest(enc) {
  this.update(this._pad());
  assert(this.pending === null);

  return this._digest(enc);
};

BlockHash.prototype._pad = function pad() {
  var len = this.pendingTotal;
  var bytes = this._delta8;
  var k = bytes - ((len + this.padLength) % bytes);
  var res = new Array(k + this.padLength);
  res[0] = 0x80;
  for (var i = 1; i < k; i++)
    res[i] = 0;

  // Append length
  len <<= 3;
  if (this.endian === 'big') {
    for (var t = 8; t < this.padLength; t++)
      res[i++] = 0;

    res[i++] = 0;
    res[i++] = 0;
    res[i++] = 0;
    res[i++] = 0;
    res[i++] = (len >>> 24) & 0xff;
    res[i++] = (len >>> 16) & 0xff;
    res[i++] = (len >>> 8) & 0xff;
    res[i++] = len & 0xff;
  } else {
    res[i++] = len & 0xff;
    res[i++] = (len >>> 8) & 0xff;
    res[i++] = (len >>> 16) & 0xff;
    res[i++] = (len >>> 24) & 0xff;
    res[i++] = 0;
    res[i++] = 0;
    res[i++] = 0;
    res[i++] = 0;

    for (var t = 8; t < this.padLength; t++)
      res[i++] = 0;
  }

  return res;
};

},{"../hash":41}],43:[function(require,module,exports){
var hmac = exports;

var hash = require('../hash');
var utils = hash.utils;
var assert = utils.assert;

function Hmac(hash, key, enc) {
  if (!(this instanceof Hmac))
    return new Hmac(hash, key, enc);
  this.Hash = hash;
  this.blockSize = hash.blockSize / 8;
  this.outSize = hash.outSize / 8;
  this.inner = null;
  this.outer = null;

  this._init(utils.toArray(key, enc));
}
module.exports = Hmac;

Hmac.prototype._init = function init(key) {
  // Shorten key, if needed
  if (key.length > this.blockSize)
    key = new this.Hash().update(key).digest();
  assert(key.length <= this.blockSize);

  // Add padding to key
  for (var i = key.length; i < this.blockSize; i++)
    key.push(0);

  for (var i = 0; i < key.length; i++)
    key[i] ^= 0x36;
  this.inner = new this.Hash().update(key);

  // 0x36 ^ 0x5c = 0x6a
  for (var i = 0; i < key.length; i++)
    key[i] ^= 0x6a;
  this.outer = new this.Hash().update(key);
};

Hmac.prototype.update = function update(msg, enc) {
  this.inner.update(msg, enc);
  return this;
};

Hmac.prototype.digest = function digest(enc) {
  this.outer.update(this.inner.digest());
  return this.outer.digest(enc);
};

},{"../hash":41}],44:[function(require,module,exports){
var hash = require('../hash');
var utils = hash.utils;

var rotl32 = utils.rotl32;
var sum32 = utils.sum32;
var sum32_3 = utils.sum32_3;
var sum32_4 = utils.sum32_4;
var BlockHash = hash.common.BlockHash;

function RIPEMD160() {
  if (!(this instanceof RIPEMD160))
    return new RIPEMD160();

  BlockHash.call(this);

  this.h = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ];
  this.endian = 'little';
}
utils.inherits(RIPEMD160, BlockHash);
exports.ripemd160 = RIPEMD160;

RIPEMD160.blockSize = 512;
RIPEMD160.outSize = 160;
RIPEMD160.hmacStrength = 192;
RIPEMD160.padLength = 64;

RIPEMD160.prototype._update = function update(msg, start) {
  var A = this.h[0];
  var B = this.h[1];
  var C = this.h[2];
  var D = this.h[3];
  var E = this.h[4];
  var Ah = A;
  var Bh = B;
  var Ch = C;
  var Dh = D;
  var Eh = E;
  for (var j = 0; j < 80; j++) {
    var T = sum32(
      rotl32(
        sum32_4(A, f(j, B, C, D), msg[r[j] + start], K(j)),
        s[j]),
      E);
    A = E;
    E = D;
    D = rotl32(C, 10);
    C = B;
    B = T;
    T = sum32(
      rotl32(
        sum32_4(Ah, f(79 - j, Bh, Ch, Dh), msg[rh[j] + start], Kh(j)),
        sh[j]),
      Eh);
    Ah = Eh;
    Eh = Dh;
    Dh = rotl32(Ch, 10);
    Ch = Bh;
    Bh = T;
  }
  T = sum32_3(this.h[1], C, Dh);
  this.h[1] = sum32_3(this.h[2], D, Eh);
  this.h[2] = sum32_3(this.h[3], E, Ah);
  this.h[3] = sum32_3(this.h[4], A, Bh);
  this.h[4] = sum32_3(this.h[0], B, Ch);
  this.h[0] = T;
};

RIPEMD160.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h, 'little');
  else
    return utils.split32(this.h, 'little');
};

function f(j, x, y, z) {
  if (j <= 15)
    return x ^ y ^ z;
  else if (j <= 31)
    return (x & y) | ((~x) & z);
  else if (j <= 47)
    return (x | (~y)) ^ z;
  else if (j <= 63)
    return (x & z) | (y & (~z));
  else
    return x ^ (y | (~z));
}

function K(j) {
  if (j <= 15)
    return 0x00000000;
  else if (j <= 31)
    return 0x5a827999;
  else if (j <= 47)
    return 0x6ed9eba1;
  else if (j <= 63)
    return 0x8f1bbcdc;
  else
    return 0xa953fd4e;
}

function Kh(j) {
  if (j <= 15)
    return 0x50a28be6;
  else if (j <= 31)
    return 0x5c4dd124;
  else if (j <= 47)
    return 0x6d703ef3;
  else if (j <= 63)
    return 0x7a6d76e9;
  else
    return 0x00000000;
}

var r = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];

var rh = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];

var s = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];

var sh = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];

},{"../hash":41}],45:[function(require,module,exports){
var hash = require('../hash');
var utils = hash.utils;
var assert = utils.assert;

var rotr32 = utils.rotr32;
var rotl32 = utils.rotl32;
var sum32 = utils.sum32;
var sum32_4 = utils.sum32_4;
var sum32_5 = utils.sum32_5;
var rotr64_hi = utils.rotr64_hi;
var rotr64_lo = utils.rotr64_lo;
var shr64_hi = utils.shr64_hi;
var shr64_lo = utils.shr64_lo;
var sum64 = utils.sum64;
var sum64_hi = utils.sum64_hi;
var sum64_lo = utils.sum64_lo;
var sum64_4_hi = utils.sum64_4_hi;
var sum64_4_lo = utils.sum64_4_lo;
var sum64_5_hi = utils.sum64_5_hi;
var sum64_5_lo = utils.sum64_5_lo;
var BlockHash = hash.common.BlockHash;

var sha256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

var sha512_K = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

var sha1_K = [
  0x5A827999, 0x6ED9EBA1,
  0x8F1BBCDC, 0xCA62C1D6
];

function SHA256() {
  if (!(this instanceof SHA256))
    return new SHA256();

  BlockHash.call(this);
  this.h = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ];
  this.k = sha256_K;
  this.W = new Array(64);
}
utils.inherits(SHA256, BlockHash);
exports.sha256 = SHA256;

SHA256.blockSize = 512;
SHA256.outSize = 256;
SHA256.hmacStrength = 192;
SHA256.padLength = 64;

SHA256.prototype._update = function _update(msg, start) {
  var W = this.W;

  for (var i = 0; i < 16; i++)
    W[i] = msg[start + i];
  for (; i < W.length; i++)
    W[i] = sum32_4(g1_256(W[i - 2]), W[i - 7], g0_256(W[i - 15]), W[i - 16]);

  var a = this.h[0];
  var b = this.h[1];
  var c = this.h[2];
  var d = this.h[3];
  var e = this.h[4];
  var f = this.h[5];
  var g = this.h[6];
  var h = this.h[7];

  assert(this.k.length === W.length);
  for (var i = 0; i < W.length; i++) {
    var T1 = sum32_5(h, s1_256(e), ch32(e, f, g), this.k[i], W[i]);
    var T2 = sum32(s0_256(a), maj32(a, b, c));
    h = g;
    g = f;
    f = e;
    e = sum32(d, T1);
    d = c;
    c = b;
    b = a;
    a = sum32(T1, T2);
  }

  this.h[0] = sum32(this.h[0], a);
  this.h[1] = sum32(this.h[1], b);
  this.h[2] = sum32(this.h[2], c);
  this.h[3] = sum32(this.h[3], d);
  this.h[4] = sum32(this.h[4], e);
  this.h[5] = sum32(this.h[5], f);
  this.h[6] = sum32(this.h[6], g);
  this.h[7] = sum32(this.h[7], h);
};

SHA256.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h, 'big');
  else
    return utils.split32(this.h, 'big');
};

function SHA224() {
  if (!(this instanceof SHA224))
    return new SHA224();

  SHA256.call(this);
  this.h = [ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
             0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 ];
}
utils.inherits(SHA224, SHA256);
exports.sha224 = SHA224;

SHA224.blockSize = 512;
SHA224.outSize = 224;
SHA224.hmacStrength = 192;
SHA224.padLength = 64;

SHA224.prototype._digest = function digest(enc) {
  // Just truncate output
  if (enc === 'hex')
    return utils.toHex32(this.h.slice(0, 7), 'big');
  else
    return utils.split32(this.h.slice(0, 7), 'big');
};

function SHA512() {
  if (!(this instanceof SHA512))
    return new SHA512();

  BlockHash.call(this);
  this.h = [ 0x6a09e667, 0xf3bcc908,
             0xbb67ae85, 0x84caa73b,
             0x3c6ef372, 0xfe94f82b,
             0xa54ff53a, 0x5f1d36f1,
             0x510e527f, 0xade682d1,
             0x9b05688c, 0x2b3e6c1f,
             0x1f83d9ab, 0xfb41bd6b,
             0x5be0cd19, 0x137e2179 ];
  this.k = sha512_K;
  this.W = new Array(160);
}
utils.inherits(SHA512, BlockHash);
exports.sha512 = SHA512;

SHA512.blockSize = 1024;
SHA512.outSize = 512;
SHA512.hmacStrength = 192;
SHA512.padLength = 128;

SHA512.prototype._prepareBlock = function _prepareBlock(msg, start) {
  var W = this.W;

  // 32 x 32bit words
  for (var i = 0; i < 32; i++)
    W[i] = msg[start + i];
  for (; i < W.length; i += 2) {
    var c0_hi = g1_512_hi(W[i - 4], W[i - 3]);  // i - 2
    var c0_lo = g1_512_lo(W[i - 4], W[i - 3]);
    var c1_hi = W[i - 14];  // i - 7
    var c1_lo = W[i - 13];
    var c2_hi = g0_512_hi(W[i - 30], W[i - 29]);  // i - 15
    var c2_lo = g0_512_lo(W[i - 30], W[i - 29]);
    var c3_hi = W[i - 32];  // i - 16
    var c3_lo = W[i - 31];

    W[i] = sum64_4_hi(c0_hi, c0_lo,
                      c1_hi, c1_lo,
                      c2_hi, c2_lo,
                      c3_hi, c3_lo);
    W[i + 1] = sum64_4_lo(c0_hi, c0_lo,
                          c1_hi, c1_lo,
                          c2_hi, c2_lo,
                          c3_hi, c3_lo);
  }
};

SHA512.prototype._update = function _update(msg, start) {
  this._prepareBlock(msg, start);

  var W = this.W;

  var ah = this.h[0];
  var al = this.h[1];
  var bh = this.h[2];
  var bl = this.h[3];
  var ch = this.h[4];
  var cl = this.h[5];
  var dh = this.h[6];
  var dl = this.h[7];
  var eh = this.h[8];
  var el = this.h[9];
  var fh = this.h[10];
  var fl = this.h[11];
  var gh = this.h[12];
  var gl = this.h[13];
  var hh = this.h[14];
  var hl = this.h[15];

  assert(this.k.length === W.length);
  for (var i = 0; i < W.length; i += 2) {
    var c0_hi = hh;
    var c0_lo = hl;
    var c1_hi = s1_512_hi(eh, el);
    var c1_lo = s1_512_lo(eh, el);
    var c2_hi = ch64_hi(eh, el, fh, fl, gh, gl);
    var c2_lo = ch64_lo(eh, el, fh, fl, gh, gl);
    var c3_hi = this.k[i];
    var c3_lo = this.k[i + 1];
    var c4_hi = W[i];
    var c4_lo = W[i + 1];

    var T1_hi = sum64_5_hi(c0_hi, c0_lo,
                           c1_hi, c1_lo,
                           c2_hi, c2_lo,
                           c3_hi, c3_lo,
                           c4_hi, c4_lo);
    var T1_lo = sum64_5_lo(c0_hi, c0_lo,
                           c1_hi, c1_lo,
                           c2_hi, c2_lo,
                           c3_hi, c3_lo,
                           c4_hi, c4_lo);

    var c0_hi = s0_512_hi(ah, al);
    var c0_lo = s0_512_lo(ah, al);
    var c1_hi = maj64_hi(ah, al, bh, bl, ch, cl);
    var c1_lo = maj64_lo(ah, al, bh, bl, ch, cl);

    var T2_hi = sum64_hi(c0_hi, c0_lo, c1_hi, c1_lo);
    var T2_lo = sum64_lo(c0_hi, c0_lo, c1_hi, c1_lo);

    hh = gh;
    hl = gl;

    gh = fh;
    gl = fl;

    fh = eh;
    fl = el;

    eh = sum64_hi(dh, dl, T1_hi, T1_lo);
    el = sum64_lo(dl, dl, T1_hi, T1_lo);

    dh = ch;
    dl = cl;

    ch = bh;
    cl = bl;

    bh = ah;
    bl = al;

    ah = sum64_hi(T1_hi, T1_lo, T2_hi, T2_lo);
    al = sum64_lo(T1_hi, T1_lo, T2_hi, T2_lo);
  }

  sum64(this.h, 0, ah, al);
  sum64(this.h, 2, bh, bl);
  sum64(this.h, 4, ch, cl);
  sum64(this.h, 6, dh, dl);
  sum64(this.h, 8, eh, el);
  sum64(this.h, 10, fh, fl);
  sum64(this.h, 12, gh, gl);
  sum64(this.h, 14, hh, hl);
};

SHA512.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h, 'big');
  else
    return utils.split32(this.h, 'big');
};

function SHA384() {
  if (!(this instanceof SHA384))
    return new SHA384();

  SHA512.call(this);
  this.h = [ 0xcbbb9d5d, 0xc1059ed8,
             0x629a292a, 0x367cd507,
             0x9159015a, 0x3070dd17,
             0x152fecd8, 0xf70e5939,
             0x67332667, 0xffc00b31,
             0x8eb44a87, 0x68581511,
             0xdb0c2e0d, 0x64f98fa7,
             0x47b5481d, 0xbefa4fa4 ];
}
utils.inherits(SHA384, SHA512);
exports.sha384 = SHA384;

SHA384.blockSize = 1024;
SHA384.outSize = 384;
SHA384.hmacStrength = 192;
SHA384.padLength = 128;

SHA384.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h.slice(0, 12), 'big');
  else
    return utils.split32(this.h.slice(0, 12), 'big');
};

function SHA1() {
  if (!(this instanceof SHA1))
    return new SHA1();

  BlockHash.call(this);
  this.h = [ 0x67452301, 0xefcdab89, 0x98badcfe,
             0x10325476, 0xc3d2e1f0 ];
  this.W = new Array(80);
}

utils.inherits(SHA1, BlockHash);
exports.sha1 = SHA1;

SHA1.blockSize = 512;
SHA1.outSize = 160;
SHA1.hmacStrength = 80;
SHA1.padLength = 64;

SHA1.prototype._update = function _update(msg, start) {
  var W = this.W;

  for (var i = 0; i < 16; i++)
    W[i] = msg[start + i];

  for(; i < W.length; i++)
    W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

  var a = this.h[0];
  var b = this.h[1];
  var c = this.h[2];
  var d = this.h[3];
  var e = this.h[4];

  for (var i = 0; i < W.length; i++) {
    var s = ~~(i / 20);
    var t = sum32_5(rotl32(a, 5), ft_1(s, b, c, d), e, W[i], sha1_K[s]);
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = t;
  }

  this.h[0] = sum32(this.h[0], a);
  this.h[1] = sum32(this.h[1], b);
  this.h[2] = sum32(this.h[2], c);
  this.h[3] = sum32(this.h[3], d);
  this.h[4] = sum32(this.h[4], e);
};

SHA1.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h, 'big');
  else
    return utils.split32(this.h, 'big');
};

function ch32(x, y, z) {
  return (x & y) ^ ((~x) & z);
}

function maj32(x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

function p32(x, y, z) {
  return x ^ y ^ z;
}

function s0_256(x) {
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

function s1_256(x) {
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

function g0_256(x) {
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3);
}

function g1_256(x) {
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10);
}

function ft_1(s, x, y, z) {
  if (s === 0)
    return ch32(x, y, z);
  if (s === 1 || s === 3)
    return p32(x, y, z);
  if (s === 2)
    return maj32(x, y, z);
}

function ch64_hi(xh, xl, yh, yl, zh, zl) {
  var r = (xh & yh) ^ ((~xh) & zh);
  if (r < 0)
    r += 0x100000000;
  return r;
}

function ch64_lo(xh, xl, yh, yl, zh, zl) {
  var r = (xl & yl) ^ ((~xl) & zl);
  if (r < 0)
    r += 0x100000000;
  return r;
}

function maj64_hi(xh, xl, yh, yl, zh, zl) {
  var r = (xh & yh) ^ (xh & zh) ^ (yh & zh);
  if (r < 0)
    r += 0x100000000;
  return r;
}

function maj64_lo(xh, xl, yh, yl, zh, zl) {
  var r = (xl & yl) ^ (xl & zl) ^ (yl & zl);
  if (r < 0)
    r += 0x100000000;
  return r;
}

function s0_512_hi(xh, xl) {
  var c0_hi = rotr64_hi(xh, xl, 28);
  var c1_hi = rotr64_hi(xl, xh, 2);  // 34
  var c2_hi = rotr64_hi(xl, xh, 7);  // 39

  var r = c0_hi ^ c1_hi ^ c2_hi;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function s0_512_lo(xh, xl) {
  var c0_lo = rotr64_lo(xh, xl, 28);
  var c1_lo = rotr64_lo(xl, xh, 2);  // 34
  var c2_lo = rotr64_lo(xl, xh, 7);  // 39

  var r = c0_lo ^ c1_lo ^ c2_lo;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function s1_512_hi(xh, xl) {
  var c0_hi = rotr64_hi(xh, xl, 14);
  var c1_hi = rotr64_hi(xh, xl, 18);
  var c2_hi = rotr64_hi(xl, xh, 9);  // 41

  var r = c0_hi ^ c1_hi ^ c2_hi;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function s1_512_lo(xh, xl) {
  var c0_lo = rotr64_lo(xh, xl, 14);
  var c1_lo = rotr64_lo(xh, xl, 18);
  var c2_lo = rotr64_lo(xl, xh, 9);  // 41

  var r = c0_lo ^ c1_lo ^ c2_lo;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function g0_512_hi(xh, xl) {
  var c0_hi = rotr64_hi(xh, xl, 1);
  var c1_hi = rotr64_hi(xh, xl, 8);
  var c2_hi = shr64_hi(xh, xl, 7);

  var r = c0_hi ^ c1_hi ^ c2_hi;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function g0_512_lo(xh, xl) {
  var c0_lo = rotr64_lo(xh, xl, 1);
  var c1_lo = rotr64_lo(xh, xl, 8);
  var c2_lo = shr64_lo(xh, xl, 7);

  var r = c0_lo ^ c1_lo ^ c2_lo;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function g1_512_hi(xh, xl) {
  var c0_hi = rotr64_hi(xh, xl, 19);
  var c1_hi = rotr64_hi(xl, xh, 29);  // 61
  var c2_hi = shr64_hi(xh, xl, 6);

  var r = c0_hi ^ c1_hi ^ c2_hi;
  if (r < 0)
    r += 0x100000000;
  return r;
}

function g1_512_lo(xh, xl) {
  var c0_lo = rotr64_lo(xh, xl, 19);
  var c1_lo = rotr64_lo(xl, xh, 29);  // 61
  var c2_lo = shr64_lo(xh, xl, 6);

  var r = c0_lo ^ c1_lo ^ c2_lo;
  if (r < 0)
    r += 0x100000000;
  return r;
}

},{"../hash":41}],46:[function(require,module,exports){
var utils = exports;
var inherits = require('inherits');

function toArray(msg, enc) {
  if (Array.isArray(msg))
    return msg.slice();
  if (!msg)
    return [];
  var res = [];
  if (typeof msg === 'string') {
    if (!enc) {
      for (var i = 0; i < msg.length; i++) {
        var c = msg.charCodeAt(i);
        var hi = c >> 8;
        var lo = c & 0xff;
        if (hi)
          res.push(hi, lo);
        else
          res.push(lo);
      }
    } else if (enc === 'hex') {
      msg = msg.replace(/[^a-z0-9]+/ig, '');
      if (msg.length % 2 !== 0)
        msg = '0' + msg;
      for (var i = 0; i < msg.length; i += 2)
        res.push(parseInt(msg[i] + msg[i + 1], 16));
    }
  } else {
    for (var i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
  }
  return res;
}
utils.toArray = toArray;

function toHex(msg) {
  var res = '';
  for (var i = 0; i < msg.length; i++)
    res += zero2(msg[i].toString(16));
  return res;
}
utils.toHex = toHex;

function htonl(w) {
  var res = (w >>> 24) |
            ((w >>> 8) & 0xff00) |
            ((w << 8) & 0xff0000) |
            ((w & 0xff) << 24);
  return res >>> 0;
}
utils.htonl = htonl;

function toHex32(msg, endian) {
  var res = '';
  for (var i = 0; i < msg.length; i++) {
    var w = msg[i];
    if (endian === 'little')
      w = htonl(w);
    res += zero8(w.toString(16));
  }
  return res;
}
utils.toHex32 = toHex32;

function zero2(word) {
  if (word.length === 1)
    return '0' + word;
  else
    return word;
}
utils.zero2 = zero2;

function zero8(word) {
  if (word.length === 7)
    return '0' + word;
  else if (word.length === 6)
    return '00' + word;
  else if (word.length === 5)
    return '000' + word;
  else if (word.length === 4)
    return '0000' + word;
  else if (word.length === 3)
    return '00000' + word;
  else if (word.length === 2)
    return '000000' + word;
  else if (word.length === 1)
    return '0000000' + word;
  else
    return word;
}
utils.zero8 = zero8;

function join32(msg, start, end, endian) {
  var len = end - start;
  assert(len % 4 === 0);
  var res = new Array(len / 4);
  for (var i = 0, k = start; i < res.length; i++, k += 4) {
    var w;
    if (endian === 'big')
      w = (msg[k] << 24) | (msg[k + 1] << 16) | (msg[k + 2] << 8) | msg[k + 3];
    else
      w = (msg[k + 3] << 24) | (msg[k + 2] << 16) | (msg[k + 1] << 8) | msg[k];
    res[i] = w >>> 0;
  }
  return res;
}
utils.join32 = join32;

function split32(msg, endian) {
  var res = new Array(msg.length * 4);
  for (var i = 0, k = 0; i < msg.length; i++, k += 4) {
    var m = msg[i];
    if (endian === 'big') {
      res[k] = m >>> 24;
      res[k + 1] = (m >>> 16) & 0xff;
      res[k + 2] = (m >>> 8) & 0xff;
      res[k + 3] = m & 0xff;
    } else {
      res[k + 3] = m >>> 24;
      res[k + 2] = (m >>> 16) & 0xff;
      res[k + 1] = (m >>> 8) & 0xff;
      res[k] = m & 0xff;
    }
  }
  return res;
}
utils.split32 = split32;

function rotr32(w, b) {
  return (w >>> b) | (w << (32 - b));
}
utils.rotr32 = rotr32;

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}
utils.rotl32 = rotl32;

function sum32(a, b) {
  return (a + b) >>> 0;
}
utils.sum32 = sum32;

function sum32_3(a, b, c) {
  return (a + b + c) >>> 0;
}
utils.sum32_3 = sum32_3;

function sum32_4(a, b, c, d) {
  return (a + b + c + d) >>> 0;
}
utils.sum32_4 = sum32_4;

function sum32_5(a, b, c, d, e) {
  return (a + b + c + d + e) >>> 0;
}
utils.sum32_5 = sum32_5;

function assert(cond, msg) {
  if (!cond)
    throw new Error(msg || 'Assertion failed');
}
utils.assert = assert;

utils.inherits = inherits;

function sum64(buf, pos, ah, al) {
  var bh = buf[pos];
  var bl = buf[pos + 1];

  var lo = (al + bl) >>> 0;
  var hi = (lo < al ? 1 : 0) + ah + bh;
  buf[pos] = hi >>> 0;
  buf[pos + 1] = lo;
}
exports.sum64 = sum64;

function sum64_hi(ah, al, bh, bl) {
  var lo = (al + bl) >>> 0;
  var hi = (lo < al ? 1 : 0) + ah + bh;
  return hi >>> 0;
};
exports.sum64_hi = sum64_hi;

function sum64_lo(ah, al, bh, bl) {
  var lo = al + bl;
  return lo >>> 0;
};
exports.sum64_lo = sum64_lo;

function sum64_4_hi(ah, al, bh, bl, ch, cl, dh, dl) {
  var carry = 0;
  var lo = al;
  lo = (lo + bl) >>> 0;
  carry += lo < al ? 1 : 0;
  lo = (lo + cl) >>> 0;
  carry += lo < cl ? 1 : 0;
  lo = (lo + dl) >>> 0;
  carry += lo < dl ? 1 : 0;

  var hi = ah + bh + ch + dh + carry;
  return hi >>> 0;
};
exports.sum64_4_hi = sum64_4_hi;

function sum64_4_lo(ah, al, bh, bl, ch, cl, dh, dl) {
  var lo = al + bl + cl + dl;
  return lo >>> 0;
};
exports.sum64_4_lo = sum64_4_lo;

function sum64_5_hi(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
  var carry = 0;
  var lo = al;
  lo = (lo + bl) >>> 0;
  carry += lo < al ? 1 : 0;
  lo = (lo + cl) >>> 0;
  carry += lo < cl ? 1 : 0;
  lo = (lo + dl) >>> 0;
  carry += lo < dl ? 1 : 0;
  lo = (lo + el) >>> 0;
  carry += lo < el ? 1 : 0;

  var hi = ah + bh + ch + dh + eh + carry;
  return hi >>> 0;
};
exports.sum64_5_hi = sum64_5_hi;

function sum64_5_lo(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
  var lo = al + bl + cl + dl + el;

  return lo >>> 0;
};
exports.sum64_5_lo = sum64_5_lo;

function rotr64_hi(ah, al, num) {
  var r = (al << (32 - num)) | (ah >>> num);
  return r >>> 0;
};
exports.rotr64_hi = rotr64_hi;

function rotr64_lo(ah, al, num) {
  var r = (ah << (32 - num)) | (al >>> num);
  return r >>> 0;
};
exports.rotr64_lo = rotr64_lo;

function shr64_hi(ah, al, num) {
  return ah >>> num;
};
exports.shr64_hi = shr64_hi;

function shr64_lo(ah, al, num) {
  var r = (ah << (32 - num)) | (al >>> num);
  return r >>> 0;
};
exports.shr64_lo = shr64_lo;

},{"inherits":49}],47:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],48:[function(require,module,exports){

var indexOf = [].indexOf;

module.exports = function(arr, obj){
  if (indexOf) return arr.indexOf(obj);
  for (var i = 0; i < arr.length; ++i) {
    if (arr[i] === obj) return i;
  }
  return -1;
};
},{}],49:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],50:[function(require,module,exports){
var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};

},{}],51:[function(require,module,exports){
(function (Buffer){
'use strict';

var BN = require('asn1.js').bignum;

module.exports = function base64ToBigNum(val, zero) {
	var buf = new Buffer(val, 'base64');
	var bn = val = new BN(buf, 10, 'be').iabs();
	if (zero) {
		buf.fill(0);
	}
	return bn;
};

}).call(this,require("buffer").Buffer)

},{"asn1.js":6,"buffer":23}],52:[function(require,module,exports){
(function (Buffer){
'use strict';

var asn1 = require('asn1.js'),
	EC = require('elliptic').ec;

var b64ToBn = require('./b64-to-bn');

var curves = {
		'P-256': 'p256',
		'P-384': 'p384',
		'P-521': 'p521'
	},
	oids = {
		'P-256': [1, 2, 840, 10045, 3, 1, 7],
		'P-384': [1, 3, 132, 0, 34],
		'P-521': [1, 3, 132, 0, 35]
	};

function ecJwkToBuffer(jwk, opts) {
	if ('string' !== typeof jwk.crv) {
		throw new TypeError('Expected "jwk.crv" to be a String');
	}

	var hasD = 'string' === typeof jwk.d;
	var xyTypes = hasD
		? ['undefined', 'string']
		: ['string'];

	if (-1 === xyTypes.indexOf(typeof jwk.x)) {
		throw new TypeError('Expected "jwk.x" to be a String');
	}

	if (-1 === xyTypes.indexOf(typeof jwk.y)) {
		throw new TypeError('Expected "jwk.y" to be a String');
	}

	if (opts.private && !hasD) {
		throw new TypeError('Expected "jwk.d" to be a String');
	}

	var curveName = curves[jwk.crv];
	if (!curveName) {
		throw new Error('Unsupported curve "' + jwk.crv + '"');
	}

	var curve = new EC(curveName);

	var key = {};

	var hasPub = jwk.x && jwk.y;
	if (hasPub) {
		key.pub = {
			x: b64ToBn(jwk.x, false),
			y: b64ToBn(jwk.y, false)
		};
	}

	if (opts.private || !hasPub) {
		key.priv = b64ToBn(jwk.d, true);
	}

	key = curve.keyPair(key);

	var keyValidation = key.validate();
	if (!keyValidation.result) {
		throw new Error('Invalid key for curve: "' + keyValidation.reason + '"');
	}

	var result = keyToPem(jwk.crv, key, opts);

	return result;
}

function keyToPem(crv, key, opts) {
	var compact = false;
	var subjectPublicKey = key.getPublic(compact, 'hex');
	subjectPublicKey = new Buffer(subjectPublicKey, 'hex');
	subjectPublicKey = {
		unused: 0,
		data: subjectPublicKey
	};

	var parameters = ECParameters.encode({
		type: 'namedCurve',
		value: oids[crv]
	}, 'der');

	var result;
	if (opts.private) {
		var privateKey = key.getPrivate('hex');
		privateKey = new Buffer(privateKey, 'hex');

		result = ECPrivateKey.encode({
			version: ecPrivkeyVer1,
			privateKey: privateKey,
			parameters: parameters,
			publicKey: subjectPublicKey
		}, 'pem', {
			label: 'EC PRIVATE KEY'
		});

		privateKey.fill(0);
	} else {
		result = SubjectPublicKeyInfo.encode({
			algorithm: {
				algorithm: [1, 2, 840, 10045, 2, 1],
				parameters: parameters
			},
			subjectPublicKey: subjectPublicKey
		}, 'pem', {
			label: 'PUBLIC KEY'
		});
	}

	// This is in an if incase asn1.js adds a trailing \n
	// istanbul ignore else
	if ('\n' !== result.slice(-1)) {
		result += '\n';
	}

	return result;
}

var ECParameters = asn1.define('ECParameters', /* @this */ function() {
	this.choice({
		namedCurve: this.objid()
	});
});

var ecPrivkeyVer1 = 1;

var ECPrivateKey = asn1.define('ECPrivateKey', /* @this */ function() {
	this.seq().obj(
		this.key('version').int(),
		this.key('privateKey').octstr(),
		this.key('parameters').explicit(0).optional().any(),
		this.key('publicKey').explicit(1).optional().bitstr()
	);
});

var AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', /* @this */ function() {
	this.seq().obj(
		this.key('algorithm').objid(),
		this.key('parameters').optional().any()
	);
});

var SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', /* @this */ function() {
	this.seq().obj(
		this.key('algorithm').use(AlgorithmIdentifier),
		this.key('subjectPublicKey').bitstr()
	);
});

module.exports = ecJwkToBuffer;

}).call(this,require("buffer").Buffer)

},{"./b64-to-bn":51,"asn1.js":6,"buffer":23,"elliptic":24}],53:[function(require,module,exports){
'use strict';

var ec = require('./ec'),
	rsa = require('./rsa');

function jwkToBuffer(jwk, opts) {
	if ('object' !== typeof jwk || null === jwk) {
		throw new TypeError('Expected "jwk" to be an Object');
	}

	var kty = jwk.kty;
	if ('string' !== typeof kty) {
		throw new TypeError('Expected "jwk.kty" to be a String');
	}

	opts = opts || {};
	opts.private = opts.private === true;

	switch (kty) {
		case 'EC': {
			return ec(jwk, opts);
		}
		case 'RSA': {
			return rsa(jwk, opts);
		}
		default: {
			throw new Error('Unsupported key type "' + kty + '"');
		}
	}
}

module.exports = jwkToBuffer;

},{"./ec":52,"./rsa":54}],54:[function(require,module,exports){
'use strict';

var asn1 = require('asn1.js');

var b64ToBn = require('./b64-to-bn');

var Version = asn1.define('Version', /* @this */ function() {
	this.int();
});

var RSAPrivateKey = asn1.define('RSAPrivateKey', /* @this */ function() {
	this.seq().obj(
		this.key('version').use(Version),
		this.key('modulus').int(),
		this.key('publicExponent').int(),
		this.key('privateExponent').int(),
		this.key('prime1').int(),
		this.key('prime2').int(),
		this.key('exponent1').int(),
		this.key('exponent2').int(),
		this.key('coefficient').int()
	);
});

var RSAPublicKey = asn1.define('RSAPublicKey', /* @this */ function() {
	this.seq().obj(
		this.key('modulus').int(),
		this.key('publicExponent').int()
	);
});

function rsaJwkToBuffer(jwk, opts) {
	if ('string' !== typeof jwk.e) {
		throw new TypeError('Expected "jwk.e" to be a String');
	}

	if ('string' !== typeof jwk.n) {
		throw new TypeError('Expected "jwk.n" to be a String');
	}

	if (opts.private) {
		if ('string' !== typeof jwk.d) {
			throw new TypeError('Expected "jwk.d" to be a String');
		}

		if ('string' !== typeof jwk.p) {
			throw new TypeError('Expected "jwk.p" to be a String');
		}

		if ('string' !== typeof jwk.q) {
			throw new TypeError('Expected "jwk.q" to be a String');
		}

		if ('string' !== typeof jwk.dp) {
			throw new TypeError('Expected "jwk.dp" to be a String');
		}

		if ('string' !== typeof jwk.dq) {
			throw new TypeError('Expected "jwk.dq" to be a String');
		}

		if ('string' !== typeof jwk.qi) {
			throw new TypeError('Expected "jwk.qi" to be a String');
		}
	}

	var pem;
	if (opts.private) {
		pem = RSAPrivateKey.encode({
			version: 0,
			modulus: b64ToBn(jwk.n, false),
			publicExponent: b64ToBn(jwk.e, false),
			privateExponent: b64ToBn(jwk.d, true),
			prime1: b64ToBn(jwk.p, true),
			prime2: b64ToBn(jwk.q, true),
			exponent1: b64ToBn(jwk.dp, true),
			exponent2: b64ToBn(jwk.dq, true),
			coefficient: b64ToBn(jwk.qi, true)
		}, 'pem', {
			label: 'RSA PRIVATE KEY'
		});
	} else {
		pem = RSAPublicKey.encode({
			modulus: b64ToBn(jwk.n, false),
			publicExponent: b64ToBn(jwk.e, false)
		}, 'pem', {
			label: 'RSA PUBLIC KEY'
		});
	}

	// This is in an if incase asn1.js adds a trailing \n
	// istanbul ignore else
	if ('\n' !== pem.slice(-1)) {
		pem += '\n';
	}

	return pem;
}

module.exports = rsaJwkToBuffer;

},{"./b64-to-bn":51,"asn1.js":6}],55:[function(require,module,exports){
module.exports = assert;

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

assert.equal = function assertEqual(l, r, msg) {
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};

},{}],56:[function(require,module,exports){
var indexOf = require('indexof');

var Object_keys = function (obj) {
    if (Object.keys) return Object.keys(obj)
    else {
        var res = [];
        for (var key in obj) res.push(key)
        return res;
    }
};

var forEach = function (xs, fn) {
    if (xs.forEach) return xs.forEach(fn)
    else for (var i = 0; i < xs.length; i++) {
        fn(xs[i], i, xs);
    }
};

var defineProp = (function() {
    try {
        Object.defineProperty({}, '_', {});
        return function(obj, name, value) {
            Object.defineProperty(obj, name, {
                writable: true,
                enumerable: false,
                configurable: true,
                value: value
            })
        };
    } catch(e) {
        return function(obj, name, value) {
            obj[name] = value;
        };
    }
}());

var globals = ['Array', 'Boolean', 'Date', 'Error', 'EvalError', 'Function',
'Infinity', 'JSON', 'Math', 'NaN', 'Number', 'Object', 'RangeError',
'ReferenceError', 'RegExp', 'String', 'SyntaxError', 'TypeError', 'URIError',
'decodeURI', 'decodeURIComponent', 'encodeURI', 'encodeURIComponent', 'escape',
'eval', 'isFinite', 'isNaN', 'parseFloat', 'parseInt', 'undefined', 'unescape'];

function Context() {}
Context.prototype = {};

var Script = exports.Script = function NodeScript (code) {
    if (!(this instanceof Script)) return new Script(code);
    this.code = code;
};

Script.prototype.runInContext = function (context) {
    if (!(context instanceof Context)) {
        throw new TypeError("needs a 'context' argument.");
    }
    
    var iframe = document.createElement('iframe');
    if (!iframe.style) iframe.style = {};
    iframe.style.display = 'none';
    
    document.body.appendChild(iframe);
    
    var win = iframe.contentWindow;
    var wEval = win.eval, wExecScript = win.execScript;

    if (!wEval && wExecScript) {
        // win.eval() magically appears when this is called in IE:
        wExecScript.call(win, 'null');
        wEval = win.eval;
    }
    
    forEach(Object_keys(context), function (key) {
        win[key] = context[key];
    });
    forEach(globals, function (key) {
        if (context[key]) {
            win[key] = context[key];
        }
    });
    
    var winKeys = Object_keys(win);

    var res = wEval.call(win, this.code);
    
    forEach(Object_keys(win), function (key) {
        // Avoid copying circular objects like `top` and `window` by only
        // updating existing context properties or new properties in the `win`
        // that was only introduced after the eval.
        if (key in context || indexOf(winKeys, key) === -1) {
            context[key] = win[key];
        }
    });

    forEach(globals, function (key) {
        if (!(key in context)) {
            defineProp(context, key, win[key]);
        }
    });
    
    document.body.removeChild(iframe);
    
    return res;
};

Script.prototype.runInThisContext = function () {
    return eval(this.code); // maybe...
};

Script.prototype.runInNewContext = function (context) {
    var ctx = Script.createContext(context);
    var res = this.runInContext(ctx);

    forEach(Object_keys(ctx), function (key) {
        context[key] = ctx[key];
    });

    return res;
};

forEach(Object_keys(Script.prototype), function (name) {
    exports[name] = Script[name] = function (code) {
        var s = Script(code);
        return s[name].apply(s, [].slice.call(arguments, 1));
    };
});

exports.createScript = function (code) {
    return exports.Script(code);
};

exports.createContext = Script.createContext = function (context) {
    var copy = new Context();
    if(typeof context === 'object') {
        forEach(Object_keys(context), function (key) {
            copy[key] = context[key];
        });
    }
    return copy;
};

},{"indexof":48}]},{},[5])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJiNjQtdG8tYm4uanMiLCJjcmVhdGUuanMiLCJjc3IuanMiLCJkZXIuanMiLCJpbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYXBpLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9idWZmZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9iYXNlL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9ub2RlLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9yZXBvcnRlci5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2NvbnN0YW50cy9kZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9jb25zdGFudHMvaW5kZXguanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9kZWNvZGVycy9kZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9kZWNvZGVycy9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2RlY29kZXJzL3BlbS5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2VuY29kZXJzL2Rlci5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2VuY29kZXJzL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvZW5jb2RlcnMvcGVtLmpzIiwibm9kZV9tb2R1bGVzL2Jhc2U2NC1qcy9saWIvYjY0LmpzIiwibm9kZV9tb2R1bGVzL2JuLmpzL2xpYi9ibi5qcyIsIm5vZGVfbW9kdWxlcy9icm9yYW5kL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2J1ZmZlci9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2Jhc2UuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2Vkd2FyZHMuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9jdXJ2ZS9tb250LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9jdXJ2ZS9zaG9ydC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvY3VydmVzLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lYy9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvZWMva2V5LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lYy9zaWduYXR1cmUuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2VkZHNhL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lZGRzYS9rZXkuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2VkZHNhL3NpZ25hdHVyZS5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvaG1hYy1kcmJnLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9wcmVjb21wdXRlZC9zZWNwMjU2azEuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL3V0aWxzLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL3BhY2thZ2UuanNvbiIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoLmpzIiwibm9kZV9tb2R1bGVzL2hhc2guanMvbGliL2hhc2gvY29tbW9uLmpzIiwibm9kZV9tb2R1bGVzL2hhc2guanMvbGliL2hhc2gvaG1hYy5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3JpcGVtZC5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3NoYS5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3V0aWxzLmpzIiwibm9kZV9tb2R1bGVzL2llZWU3NTQvaW5kZXguanMiLCJub2RlX21vZHVsZXMvaW5kZXhvZi9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9pbmhlcml0cy9pbmhlcml0c19icm93c2VyLmpzIiwibm9kZV9tb2R1bGVzL2lzYXJyYXkvaW5kZXguanMiLCJub2RlX21vZHVsZXMvandrLXRvLXBlbS9zcmMvYjY0LXRvLWJuLmpzIiwibm9kZV9tb2R1bGVzL2p3ay10by1wZW0vc3JjL2VjLmpzIiwibm9kZV9tb2R1bGVzL2p3ay10by1wZW0vc3JjL2p3ay10by1wZW0uanMiLCJub2RlX21vZHVsZXMvandrLXRvLXBlbS9zcmMvcnNhLmpzIiwibm9kZV9tb2R1bGVzL21pbmltYWxpc3RpYy1hc3NlcnQvaW5kZXguanMiLCJub2RlX21vZHVsZXMvdm0tYnJvd3NlcmlmeS9pbmRleC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7O0FDWEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ3ZQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDOUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7O0FDM0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7O0FDMUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDN0RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdm1CQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN0R0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2pVQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakRBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNyU0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNyQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM3R0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzMxR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQ3pEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7O0FDL3FEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDZEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDL1ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMxWkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDNzRCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzdNQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5TkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzNHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN2SUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN0SEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2xFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDNXdCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzVLQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcGpCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDalFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3BGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNUQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7O0FDWkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7O0FDM0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gZSh0LG4scil7ZnVuY3Rpb24gcyhvLHUpe2lmKCFuW29dKXtpZighdFtvXSl7dmFyIGE9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtpZighdSYmYSlyZXR1cm4gYShvLCEwKTtpZihpKXJldHVybiBpKG8sITApO3ZhciBmPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIrbytcIidcIik7dGhyb3cgZi5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGZ9dmFyIGw9bltvXT17ZXhwb3J0czp7fX07dFtvXVswXS5jYWxsKGwuZXhwb3J0cyxmdW5jdGlvbihlKXt2YXIgbj10W29dWzFdW2VdO3JldHVybiBzKG4/bjplKX0sbCxsLmV4cG9ydHMsZSx0LG4scil9cmV0dXJuIG5bb10uZXhwb3J0c312YXIgaT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2Zvcih2YXIgbz0wO288ci5sZW5ndGg7bysrKXMocltvXSk7cmV0dXJuIHN9KSIsIi8vIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL0JyaWdodHNwYWNlL25vZGUtandrLXRvLXBlbS9ibG9iL21hc3Rlci9zcmMvYjY0LXRvLWJuLmpzXG52YXIgQk4gPSByZXF1aXJlKCdhc24xLmpzJykuYmlnbnVtO1xuXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGJhc2U2NFRvQmlnTnVtKHZhbCwgemVybykge1xuICB2YXIgYnVmID0gbmV3IEJ1ZmZlcih2YWwsICdiYXNlNjQnKTtcbiAgdmFyIGJuID0gdmFsID0gbmV3IEJOKGJ1ZiwgMTAsICdiZScpLmlhYnMoKTtcbiAgaWYgKHplcm8pIHtcbiAgICBidWYuZmlsbCgwKTtcbiAgfVxuICByZXR1cm4gYm47XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xudmFyIGNzciA9IHJlcXVpcmUoJy4vY3NyJyk7XG52YXIgYXNuMSA9IHJlcXVpcmUoJ2FzbjEuanMnKTtcbnZhciBFQyA9IHJlcXVpcmUoJ2VsbGlwdGljJykuZWM7XG52YXIgYjY0VG9CbiA9IHJlcXVpcmUoJy4vYjY0LXRvLWJuJyk7XG52YXIgZXhwID0gbmV3IFVpbnQ4QXJyYXkoWzEsMCwxXSk7XG52YXIgandrVG9QZW0gPSByZXF1aXJlKCdqd2stdG8tcGVtJyk7XG52YXIgZGVyID0gcmVxdWlyZSgnLi9kZXInKTtcblxudmFyIEVDUGFyYW1ldGVycyA9IGFzbjEuZGVmaW5lKCdFQ1BhcmFtZXRlcnMnLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcbiAgdGhpcy5jaG9pY2Uoe1xuICAgIG5hbWVkQ3VydmU6IHRoaXMub2JqaWQoKVxuICB9KTtcbn0pO1xudmFyIFJTQVB1YmxpY0tleSA9IGFzbjEuZGVmaW5lKCdSU0FQdWJsaWNLZXknLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ21vZHVsdXMnKS5pbnQoKSxcbiAgICB0aGlzLmtleSgncHVibGljRXhwb25lbnQnKS5pbnQoKVxuICApO1xufSk7XG52YXIgcGFyYW1zID0ge1xuICAnUC0yNTYnOiBjc3IuQXR0cmlidXRlVHlwZS5lbmNvZGUoWzEsIDIsIDg0MCwgMTAwNDUsIDMsIDEsIDddLCAncGVtJywge1xuICAgIGxhYmVsOiAnRUMgUEFSQU1FVEVSUydcbiAgfSksXG4gICdQLTM4NCc6IGNzci5BdHRyaWJ1dGVUeXBlLmVuY29kZShbMSwgMywgMTMyLCAwLCAzNF0sICdwZW0nLCB7XG4gICAgbGFiZWw6ICdFQyBQQVJBTUVURVJTJ1xuICB9KSxcbiAgJ1AtNTIxJzogY3NyLkF0dHJpYnV0ZVR5cGUuZW5jb2RlKFsxLCAzLCAxMzIsIDAsIDM1XSwgJ3BlbScsIHtcbiAgICBsYWJlbDogJ0VDIFBBUkFNRVRFUlMnXG4gIH0pXG59XG52YXIgZWNvaWRzID0ge1xuICAnUC0yNTYnOiBbMSwgMiwgODQwLCAxMDA0NSwgMywgMSwgN10sXG4gICdQLTM4NCc6IFsxLCAzLCAxMzIsIDAsIDM0XSxcbiAgJ1AtNTIxJzogWzEsIDMsIDEzMiwgMCwgMzVdXG59O1xudmFyIGN1cnZlcyA9IHtcbiAgJ1AtMjU2JzogJ3AyNTYnLFxuICAnUC0zODQnOiAncDM4NCcsXG4gICdQLTUyMSc6ICdwNTIxJ1xufTtcbnZhciBoYXNoID0ge1xuICAnUC0yNTYnOiAnU0hBLTI1NicsXG4gICdQLTM4NCc6ICdTSEEtMzg0JyxcbiAgJ1AtNTIxJzogJ1NIQS01MTInXG59XG5mdW5jdGlvbiBjcmVhdGVTaWduYWJsZShpbmZvLCBrZXksIGFsZ28pIHtcbiAgdmFyIG9iaiA9IHtcbiAgICBpbmZvOiBjcmVhdGVJbmZvKGluZm8pLFxuICAgIHZlcnNpb246IDAsXG4gICAgcHVibGljS2V5OiBwdWJsaWNLZXkoa2V5LCBhbGdvKSxcbiAgICBhdHRyaWJ1dGVzOiBbXVxuICB9O1xuICB2YXIgZGVyID0gY3NyLkNlcnRpZmljYXRpb25SZXF1ZXN0SW5mby5lbmNvZGUob2JqLCAnZGVyJyk7XG4gIHJldHVybiB7XG4gICAganNvbjogb2JqLFxuICAgIGRlcjogZGVyXG4gIH07XG59XG5mdW5jdGlvbiBnZW5lcmF0ZUVjZHNhKGN1cnZlKSB7XG4gIHJldHVybiBnbG9iYWwuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShcbiAgICB7XG4gICAgICBuYW1lOiAnRUNEU0EnLFxuICAgICAgbmFtZWRDdXJ2ZTogY3VydmVcbiAgICB9LFxuICAgIHRydWUsXG4gICAgWydzaWduJywgJ3ZlcmlmeSddXG4gICkudGhlbihmdW5jdGlvbiAocGFpcikge1xuICAgIHJldHVybiBnbG9iYWwuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIHBhaXIucHJpdmF0ZUtleSkudGhlbihmdW5jdGlvbiAoandrKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBwYWlyOiBwYWlyLFxuICAgICAgICBqd2s6IGp3a1xuICAgICAgfVxuICAgIH0pO1xuICB9KTtcbn1cbmZ1bmN0aW9uIGdlbmVyYXRlUnNhKGxlbikge1xuICByZXR1cm4gZ2xvYmFsLmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoe1xuICAgIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsXG4gICAgbW9kdWx1c0xlbmd0aDogbGVuLFxuICAgIHB1YmxpY0V4cG9uZW50OiBleHAsXG4gICAgaGFzaDoge25hbWU6ICdTSEEtMjU2J31cbiAgfSxcbiAgdHJ1ZSxcbiAgICBbJ3NpZ24nLCAndmVyaWZ5J11cbiAgKS50aGVuKGZ1bmN0aW9uIChwYWlyKSB7XG4gICAgcmV0dXJuIGdsb2JhbC5jcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywgcGFpci5wcml2YXRlS2V5KS50aGVuKGZ1bmN0aW9uIChqd2spIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHBhaXI6IHBhaXIsXG4gICAgICAgIGp3azogandrXG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xufVxudmFyIGF0dHJJZHMgPSB7XG4gIGNvbW1vbk5hbWU6ICcyLjUuNC4zJy5zcGxpdCgnLicpLFxuICBjb3VudHJ5TmFtZTogJzIuNS40LjYnLnNwbGl0KCcuJyksXG4gIHN0YXRlT3JQcm92aW5jZU5hbWU6ICcyLjUuNC44Jy5zcGxpdCgnLicpLFxuICBsb2NhbGl0eU5hbWU6ICcyLjUuNC43Jy5zcGxpdCgnLicpLFxuICBvcmdhbml6YXRpb25OYW1lOiAnMi41LjQuMTAnLnNwbGl0KCcuJyksXG4gIG9yZ2FuaXphdGlvbmFsVW5pdE5hbWU6ICcyLjUuNC4xMScuc3BsaXQoJy4nKSxcbiAgc3ViamVjdEFsdE5hbWU6ICcyLjUuMjkuMTcnLnNwbGl0KCcuJylcbn1cbmZ1bmN0aW9uIGNyZWF0ZUluZm8oaW5mbykge1xuICByZXR1cm4gT2JqZWN0LmtleXMoaW5mbykubWFwKGZ1bmN0aW9uIChuYW1lKSB7XG4gICAgaWYgKGF0dHJJZHNbbmFtZV0pIHtcbiAgICAgIHZhciB2YWwgPSBpbmZvW25hbWVdLnRyaW0oKTtcbiAgICAgIGlmIChuYW1lID09PSAnc3ViamVjdEFsdE5hbWUnICYmICF2YWwpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgcmV0dXJuIFt7XG4gICAgICAgIHR5cGU6IGF0dHJJZHNbbmFtZV0sXG4gICAgICAgIHZhbHVlOiB2YWxcbiAgICAgIH1dXG4gICAgfVxuICB9KS5maWx0ZXIoZnVuY3Rpb24gKGl0ZW0pIHtcbiAgICByZXR1cm4gaXRlbTtcbiAgfSk7XG59XG5mdW5jdGlvbiBwdWJsaWNLZXkoa2V5LCBhbGdvKSB7XG4gIGlmIChhbGdvID09PSAncnNhJykge1xuICAgIHJldHVybiB7XG4gICAgICBzdWJqZWN0UHVibGljS2V5OiB7XG4gICAgICAgIHVudXNlZDogMCxcbiAgICAgICAgZGF0YTogUlNBUHVibGljS2V5LmVuY29kZSh7XG4gICAgICAgICAgbW9kdWx1czogYjY0VG9CbihrZXkuandrLm4sIGZhbHNlKSxcbiAgICAgICAgICBwdWJsaWNFeHBvbmVudDogYjY0VG9CbihrZXkuandrLmUsIGZhbHNlKVxuICAgICAgICB9LCAnZGVyJylcbiAgICAgIH0sXG4gICAgICBhbGdvcml0aG06IHtcbiAgICAgICAgdHlwZTogJ0FsZ29yaXRobUlkZW50aWZpZXJSU0EnLFxuICAgICAgICB2YWx1ZToge1xuICAgICAgICAgIGFsZ29yaXRobTogJzEuMi44NDAuMTEzNTQ5LjEuMS4xJy5zcGxpdCgnLicpLFxuICAgICAgICAgIHBhcmFtZXRlcnM6IG51bGxcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfSBlbHNlIGlmIChhbGdvID09PSAnZWMnKSB7XG4gICAgdmFyIGN1cnZlTmFtZSA9IGN1cnZlc1trZXkuandrLmNydl07XG4gICAgdmFyIGN1cnZlID0gbmV3IEVDKGN1cnZlTmFtZSk7XG4gICAgdmFyIGsgPSAgY3VydmUua2V5UGFpcih7XG4gICAgICBwdWI6IHtcbiAgICAgICAgeDogYjY0VG9CbihrZXkuandrLngsIGZhbHNlKSxcbiAgICAgICAgeTogYjY0VG9CbihrZXkuandrLnksIGZhbHNlKVxuICAgICAgfVxuICAgIH0pO1xuICAgIHZhciBzdWJqZWN0UHVibGljS2V5ID0gay5nZXRQdWJsaWMoZmFsc2UsICdoZXgnKTtcbiAgICBzdWJqZWN0UHVibGljS2V5ID0gbmV3IEJ1ZmZlcihzdWJqZWN0UHVibGljS2V5LCAnaGV4Jyk7XG4gICAgc3ViamVjdFB1YmxpY0tleSA9IHtcbiAgICAgIHVudXNlZDogMCxcbiAgICAgIGRhdGE6IHN1YmplY3RQdWJsaWNLZXlcbiAgICB9O1xuICAgIHZhciBwYXJhbWV0ZXJzID0gRUNQYXJhbWV0ZXJzLmVuY29kZSh7XG4gICAgICB0eXBlOiAnbmFtZWRDdXJ2ZScsXG4gICAgICB2YWx1ZTogZWNvaWRzW2tleS5qd2suY3J2XVxuICAgIH0sICdkZXInKTtcbiAgICByZXR1cm4ge1xuICAgICAgYWxnb3JpdGhtOiB7XG4gICAgICAgIHR5cGU6ICdBbGdvcml0aG1JZGVudGlmaWVyJyxcbiAgICAgICAgdmFsdWU6IHtcbiAgICAgICAgICBhbGdvcml0aG06IFsxLCAyLCA4NDAsIDEwMDQ1LCAyLCAxXSxcbiAgICAgICAgICBwYXJhbWV0ZXJzOiBwYXJhbWV0ZXJzXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBzdWJqZWN0UHVibGljS2V5OiBzdWJqZWN0UHVibGljS2V5XG4gICAgfVxuICB9XG59XG5mdW5jdGlvbiBjcmVhdGVLZXkoaWQpIHtcbiAgc3dpdGNoIChpZCkge1xuICBjYXNlICcxJzpcbiAgICByZXR1cm4gZ2VuZXJhdGVFY2RzYSgnUC0yNTYnKTtcbiAgY2FzZSAnNCc6XG4gICAgcmV0dXJuIGdlbmVyYXRlRWNkc2EoJ1AtMzg0Jyk7XG4gIGNhc2UgJzUnOlxuICAgIHJldHVybiBnZW5lcmF0ZUVjZHNhKCdQLTUyMScpO1xuICBjYXNlICcyJzpcbiAgICByZXR1cm4gZ2VuZXJhdGVSc2EoMjA0OCk7XG4gIGNhc2UgJzMnOlxuICAgIHJldHVybiBnZW5lcmF0ZVJzYSg0MDk2KTtcbiAgfVxufVxuZnVuY3Rpb24gbWFrZUlkKGtleVR5cGUpIHtcbiAgc3dpdGNoIChrZXlUeXBlKSB7XG4gIGNhc2UgJzInOlxuICBjYXNlICczJzpcbiAgICByZXR1cm4ge1xuICAgICAgcGFyYW1ldGVyczogbnVsbCxcbiAgICAgIGFsZ29yaXRobTogJzEuMi44NDAuMTEzNTQ5LjEuMS4xMScuc3BsaXQoJy4nKVxuICAgIH07XG4gIGNhc2UgJzEnOlxuICAgIHJldHVybiB7XG4gICAgICBhbGdvcml0aG06ICcxLjIuODQwLjEwMDQ1LjQuMy4yJy5zcGxpdCgnLicpXG4gICAgfTtcbiAgY2FzZSAnNCc6XG4gICAgcmV0dXJuIHtcbiAgICAgIGFsZ29yaXRobTogJzEuMi44NDAuMTAwNDUuNC4zLjMnLnNwbGl0KCcuJylcbiAgICB9O1xuICBjYXNlICc1JzpcbiAgICByZXR1cm4ge1xuICAgICAgYWxnb3JpdGhtOiAnMS4yLjg0MC4xMDA0NS40LjMuNCcuc3BsaXQoJy4nKVxuICAgIH07XG4gIH1cbn1cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gKGtleVR5cGUsIGluZm8pIHtcbiAgcmV0dXJuIGNyZWF0ZUtleShrZXlUeXBlKS50aGVuKGZ1bmN0aW9uIChrZXkpIHtcbiAgICB2YXIgYWxnbyA9ICdlYyc7XG4gICAgaWYgKGtleVR5cGUgPT09ICcyJyB8fCBrZXlUeXBlID09PSAnMycpIHtcbiAgICAgIGFsZ28gPSAncnNhJztcbiAgICB9XG4gICAgdmFyIHNpZ25hYmxlID0gY3JlYXRlU2lnbmFibGUoaW5mbywga2V5LCBhbGdvKTtcbiAgICB2YXIgc2lnblByb207XG4gICAgaWYgKGFsZ28gPT09ICdyc2EnKSB7XG4gICAgICBzaWduUHJvbSA9IGdsb2JhbC5jcnlwdG8uc3VidGxlLnNpZ24oe25hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNSd9LCBrZXkucGFpci5wcml2YXRlS2V5LCBzaWduYWJsZS5kZXIpXG4gICAgfSBlbHNlIHtcbiAgICAgIHNpZ25Qcm9tID0gZ2xvYmFsLmNyeXB0by5zdWJ0bGUuc2lnbih7bmFtZTogJ0VDRFNBJywgaGFzaDoge25hbWU6IGhhc2hba2V5Lmp3ay5jcnZdfX0sIGtleS5wYWlyLnByaXZhdGVLZXksIHNpZ25hYmxlLmRlcik7XG4gICAgfVxuICAgIHJldHVybiBQcm9taXNlLmFsbChbc2lnblByb20udGhlbihmdW5jdGlvbiAoc2lnKSB7XG4gICAgICB2YXIgbWV0aG9kID0gYWxnbyA9PT0gJ3JzYScgPyAnQ2VydGlmaWNhdGlvblJlcXVlc3RSU0EnIDogJ0NlcnRpZmljYXRpb25SZXF1ZXN0JztcbiAgICAgIGlmIChhbGdvICE9PSAncnNhJykge1xuICAgICAgICBzaWcgPSBkZXIudG9ERVIobmV3IEJ1ZmZlcihzaWcpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHNpZyA9IG5ldyBCdWZmZXIoc2lnKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBjc3JbbWV0aG9kXS5lbmNvZGUoe1xuICAgICAgICBjZXJ0aWZpY2F0aW9uUmVxdWVzdEluZm86IHNpZ25hYmxlLmpzb24sXG4gICAgICAgIHNpZ25hdHVyZToge1xuICAgICAgICAgIHVudXNlZDogMCxcbiAgICAgICAgICBkYXRhOiBzaWdcbiAgICAgICAgfSxcbiAgICAgICAgc2lnbmF0dXJlQWxnb3JpdGhtOiBtYWtlSWQoa2V5VHlwZSlcbiAgICAgIH0sICdwZW0nLCB7XG4gICAgICAgIGxhYmVsOiAnQ0VSVElGSUNBVEUgUkVRVUVTVCdcbiAgICAgIH0pXG4gICAgfSksXG4gICAgUHJvbWlzZS5yZXNvbHZlKGp3a1RvUGVtKGtleS5qd2ssIHtcbiAgICAgIHByaXZhdGU6IHRydWVcbiAgICB9KSkudGhlbihmdW5jdGlvbiAoa2V5UGVtKSB7XG4gICAgICBpZiAoYWxnbyA9PT0gJ3JzYScpIHtcbiAgICAgICAgcmV0dXJuIGtleVBlbVxuICAgICAgfVxuICAgICAgdmFyIHBhcmFtID0gcGFyYW1zW2tleS5qd2suY3J2XTtcbiAgICAgIHJldHVybiBwYXJhbSArICdcXG4nICsga2V5UGVtO1xuICAgIH0pXG4gIF0pO1xuICB9KTtcbn1cbiIsInZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpO1xuXG52YXIgQWxnb3JpdGhtSWRlbnRpZmllclJTQSA9IGV4cG9ydHMuQWxnb3JpdGhtSWRlbnRpZmllclJTQSA9IGFzbjEuZGVmaW5lKCdBbGdvcml0aG1JZGVudGlmaWVyUlNBJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMuc2VxKCkub2JqKFxuICAgIHRoaXMua2V5KCdhbGdvcml0aG0nKS5vYmppZCgpLFxuICAgIHRoaXMua2V5KCdwYXJhbWV0ZXJzJykub3B0aW9uYWwoKS5udWxsXygpXG4gICk7XG59KTtcbnZhciBBbGdvcml0aG1JZGVudGlmaWVyID0gZXhwb3J0cy5BbGdvcml0aG1JZGVudGlmaWVyID0gYXNuMS5kZWZpbmUoJ0FsZ29yaXRobUlkZW50aWZpZXInLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ2FsZ29yaXRobScpLm9iamlkKCksXG4gICAgdGhpcy5rZXkoJ3BhcmFtZXRlcnMnKS5vcHRpb25hbCgpLmFueSgpXG4gICk7XG59KTtcbnZhciBBbGdvQ2hvaWNlID0gIGFzbjEuZGVmaW5lKCdBbGdvQ2hvaWNlJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMuY2hvaWNlKHtcbiAgICBBbGdvcml0aG1JZGVudGlmaWVyOiB0aGlzLnVzZShBbGdvcml0aG1JZGVudGlmaWVyKSxcbiAgICBBbGdvcml0aG1JZGVudGlmaWVyUlNBOiB0aGlzLnVzZShBbGdvcml0aG1JZGVudGlmaWVyUlNBKVxuICB9KTtcbn0pO1xudmFyIFZlcnNpb24gPSBleHBvcnRzLlZlcnNpb24gPSBhc24xLmRlZmluZSgnVmVyc2lvbicsIGZ1bmN0aW9uKCkge1xuICB0aGlzLmludCh7XG4gICAgMDogJ3YxJyxcbiAgICAxOiAndjInLFxuICAgIDI6ICd2MydcbiAgfSk7XG59KTtcbnZhciBJbnQgPSBhc24xLmRlZmluZSgnSW50JywgZnVuY3Rpb24oKSB7XG4gIHRoaXMuaW50KCk7XG59KTtcbnZhciBTdWJqZWN0UHVibGljS2V5SW5mbyA9IGV4cG9ydHMuU3ViamVjdFB1YmxpY0tleUluZm8gPSBhc24xLmRlZmluZSgnU3ViamVjdFB1YmxpY0tleUluZm8nLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ2FsZ29yaXRobScpLnVzZShBbGdvQ2hvaWNlKSxcbiAgICB0aGlzLmtleSgnc3ViamVjdFB1YmxpY0tleScpLmJpdHN0cigpXG4gICk7XG59KTtcblxudmFyIEF0dHJpYnV0ZVZhbHVlID0gYXNuMS5kZWZpbmUoJ0F0dHJpYnV0ZVZhbHVlJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMudXRmOHN0cigpO1xufSk7XG52YXIgQXR0cmlidXRlVHlwZSA9IGV4cG9ydHMuQXR0cmlidXRlVHlwZSA9IGFzbjEuZGVmaW5lKCdBdHRyaWJ1dGVUeXBlJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMub2JqaWQoKTtcbn0pO1xudmFyIEF0dHJpYnV0ZVR5cGVBbmRWYWx1ZSA9IGFzbjEuZGVmaW5lKCdBdHRyaWJ1dGVUeXBlQW5kVmFsdWUnLCBmdW5jdGlvbiAoKSB7XG4gIHRoaXMuc2VxKCkub2JqKFxuICAgIHRoaXMua2V5KCd0eXBlJykudXNlKEF0dHJpYnV0ZVR5cGUpLFxuICAgIHRoaXMua2V5KCd2YWx1ZScpLnVzZShBdHRyaWJ1dGVWYWx1ZSlcbiAgKTtcbn0pXG5cbnZhciBSZWxhdGl2ZURpc3Rpbmd1aXNoZWROYW1lID0gZXhwb3J0cy5SZWxhdGl2ZURpc3Rpbmd1aXNoZWROYW1lID0gYXNuMS5kZWZpbmUoJ1JlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUnLGZ1bmN0aW9uKCkge1xuICB0aGlzLnNldG9mKEF0dHJpYnV0ZVR5cGVBbmRWYWx1ZSk7XG59KTtcbnZhciBTZXFPZlJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUgPSBhc24xLmRlZmluZSgnU2VxT2ZSZWxhdGl2ZURpc3Rpbmd1aXNoZWROYW1lJyxmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXFvZihSZWxhdGl2ZURpc3Rpbmd1aXNoZWROYW1lKTtcbn0pO1xudmFyIENlcnRpZmljYXRpb25SZXF1ZXN0SW5mbyA9IGV4cG9ydHMuQ2VydGlmaWNhdGlvblJlcXVlc3RJbmZvID0gYXNuMS5kZWZpbmUoJ0NlcnRpZmljYXRpb25SZXF1ZXN0SW5mbycsIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgndmVyc2lvbicpLnVzZShWZXJzaW9uKSxcbiAgICB0aGlzLmtleSgnaW5mbycpLnVzZShTZXFPZlJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUpLFxuICAgIHRoaXMua2V5KCdwdWJsaWNLZXknKS51c2UoU3ViamVjdFB1YmxpY0tleUluZm8pLFxuICAgIHRoaXMua2V5KCdhdHRyaWJ1dGVzJykuc2Vxb2YoSW50KS5pbXBsaWNpdCgwKS5vcHRpb25hbCgpXG4gICk7XG59KTtcbmV4cG9ydHMuQ2VydGlmaWNhdGlvblJlcXVlc3QgPSBhc24xLmRlZmluZSgnQ2VydGlmaWNhdGlvblJlcXVlc3QnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ2NlcnRpZmljYXRpb25SZXF1ZXN0SW5mbycpLnVzZShDZXJ0aWZpY2F0aW9uUmVxdWVzdEluZm8pLFxuICAgIHRoaXMua2V5KCdzaWduYXR1cmVBbGdvcml0aG0nKS51c2UoQWxnb3JpdGhtSWRlbnRpZmllciksXG4gICAgdGhpcy5rZXkoJ3NpZ25hdHVyZScpLmJpdHN0cigpXG4gICk7XG59KTtcbmV4cG9ydHMuQ2VydGlmaWNhdGlvblJlcXVlc3RSU0EgPSBhc24xLmRlZmluZSgnQ2VydGlmaWNhdGlvblJlcXVlc3RSU0EnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ2NlcnRpZmljYXRpb25SZXF1ZXN0SW5mbycpLnVzZShDZXJ0aWZpY2F0aW9uUmVxdWVzdEluZm8pLFxuICAgIHRoaXMua2V5KCdzaWduYXR1cmVBbGdvcml0aG0nKS51c2UoQWxnb3JpdGhtSWRlbnRpZmllclJTQSksXG4gICAgdGhpcy5rZXkoJ3NpZ25hdHVyZScpLmJpdHN0cigpXG4gICk7XG59KTtcbiIsIid1c2Ugc3RyaWN0JztcbnZhciBhc3NlcnQgPSByZXF1aXJlKCdtaW5pbWFsaXN0aWMtYXNzZXJ0Jyk7XG5cbmV4cG9ydHMuZnJvbURlciA9IGZyb21EZXI7XG5leHBvcnRzLnRvREVSID0gdG9ERVI7XG5cbmZ1bmN0aW9uIHRvREVSIChpbnB1dCkge1xuICBpZiAoaW5wdXQubGVuZ3RoICUgMikge1xuICAgIGlucHV0ID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihbMF0pLCBpbnB1dF0pO1xuICB9XG4gIHZhciBzbGljZUxlbiA9IE1hdGguZmxvb3IoaW5wdXQubGVuZ3RoIC8gMik7XG4gIHZhciByID0gaW5wdXQuc2xpY2UoMCwgc2xpY2VMZW4pO1xuICB2YXIgcyA9IGlucHV0LnNsaWNlKHNsaWNlTGVuKTtcblxuICAvLyBQYWQgdmFsdWVzXG5cbiAgaWYgKHJbMF0gJiAweDgwKSB7XG4gICAgciA9IEJ1ZmZlci5jb25jYXQoW25ldyBCdWZmZXIoWzBdKSwgcl0pO1xuICB9XG4gIC8vIFBhZCB2YWx1ZXNcbiAgaWYgKHNbMF0gJiAweDgwKSB7XG4gICAgcyA9IEJ1ZmZlci5jb25jYXQoW25ldyBCdWZmZXIoWzBdKSwgc10pO1xuICB9XG4gIGlmICghclswXSAmJiAhKHJbMV0gJiAweDgwKSkge1xuICAgIHIgPSByLnNsaWNlKDEpO1xuICB9XG4gIGlmICghc1swXSAmJiAhKHNbMV0gJiAweDgwKSkge1xuICAgIHMgPSBzLnNsaWNlKDEpO1xuICB9XG4gIHZhciByYXJyID0gWzB4MDJdO1xuICBjb25zdHJ1Y3RMZW5ndGgocmFyciwgci5sZW5ndGgpO1xuICB2YXIgc2FyciA9IFsweDAyXTtcbiAgY29uc3RydWN0TGVuZ3RoKHNhcnIsIHMubGVuZ3RoKTtcbiAgdmFyIGJhY2tIYWxmID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihyYXJyKSwgciwgbmV3IEJ1ZmZlcihzYXJyKSwgc10pO1xuICB2YXIgaGVhZCA9IFsweDMwXTtcbiAgY29uc3RydWN0TGVuZ3RoKGhlYWQsIGJhY2tIYWxmLmxlbmd0aCk7XG4gIHJldHVybiBCdWZmZXIuY29uY2F0KFtuZXcgQnVmZmVyKGhlYWQpLCBiYWNrSGFsZl0pO1xufVxuZnVuY3Rpb24gY29uc3RydWN0TGVuZ3RoKGFyciwgbGVuKSB7XG4gIGlmIChsZW4gPCAweDgwKSB7XG4gICAgYXJyLnB1c2gobGVuKTtcbiAgICByZXR1cm47XG4gIH1cbiAgdmFyIG9jdGV0cyA9IDEgKyAoTWF0aC5sb2cyKGxlbikgPj4gMyk7XG4gIGFyci5wdXNoKG9jdGV0cyBeIDB4ODApO1xuICB3aGlsZSAodHJ1ZSkge1xuICAgIGlmIChvY3RldHMgPT09IDEpIHtcbiAgICAgIGFyci5wdXNoKGxlbiAmIDB4ZmYpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBvY3RldHMtLTtcbiAgICBhcnIucHVzaChsZW4gPj4gKG9jdGV0cyA8PCAzKSk7XG4gIH1cbn1cbmZ1bmN0aW9uIGZyb21EZXIoaW5wdXQsIGxlbikge1xuICB2YXIgcCA9IHt9O1xuICBwLnBsYWNlID0gMDtcbiAgYXNzZXJ0LmVxdWFsKGlucHV0W3AucGxhY2UrK10sIDB4MzApO1xuICBnZXRMZW5ndGgoaW5wdXQsIHApO1xuICBhc3NlcnQuZXF1YWwoaW5wdXRbcC5wbGFjZSsrXSwgMHgwMik7XG4gIHZhciBybGVuID0gZ2V0TGVuZ3RoKGlucHV0LCBwKTtcbiAgdmFyIHIgPSBpbnB1dC5zbGljZShwLnBsYWNlLCBybGVuICsgcC5wbGFjZSk7XG4gIHAucGxhY2UgKz0gcmxlbjtcbiAgYXNzZXJ0LmVxdWFsKGlucHV0W3AucGxhY2UrK10sIDB4MDIpO1xuICB2YXIgc2xlbiA9IGdldExlbmd0aChpbnB1dCwgcCk7XG4gIGFzc2VydC5lcXVhbChpbnB1dC5sZW5ndGgsIHNsZW4gKyBwLnBsYWNlKTtcbiAgdmFyIHMgPSBpbnB1dC5zbGljZShwLnBsYWNlLCBzbGVuICsgcC5wbGFjZSk7XG4gIGlmICghclswXSAmJiAoclsxXSAmIDB4ODApKSB7XG4gICAgciA9IHIuc2xpY2UoMSk7XG4gIH1cbiAgaWYgKCFzWzBdICYmIChzWzFdICYgMHg4MCkpIHtcbiAgICBzID0gcy5zbGljZSgxKTtcbiAgfVxuICB3aGlsZSAoci5sZW5ndGggPCBsZW4pIHtcbiAgICByID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihbMF0pLCByXSk7XG4gIH1cbiAgd2hpbGUgKHMubGVuZ3RoIDwgbGVuKSB7XG4gICAgcyA9IEJ1ZmZlci5jb25jYXQoW25ldyBCdWZmZXIoWzBdKSwgc10pO1xuICB9XG4gIHJldHVybiBCdWZmZXIuY29uY2F0KFtyLCBzXSk7XG59XG5mdW5jdGlvbiBnZXRMZW5ndGgoYnVmLCBwKSB7XG4gIHZhciBpbml0aWFsID0gYnVmW3AucGxhY2UrK107XG4gIGlmICghKGluaXRpYWwgJiAweDgwKSkge1xuICAgIHJldHVybiBpbml0aWFsO1xuICB9XG4gIHZhciBvY3RldExlbiA9IGluaXRpYWwgJiAweGY7XG4gIHZhciBkYXRhID0gYnVmLnJlYWRVSW50QkUocC5wbGFjZSwgb2N0ZXRMZW4pO1xuICBwLnBsYWNlICs9IG9jdGV0TGVuO1xuICByZXR1cm4gZGF0YTtcbn1cbiIsInZhciBtYWtlQ3NyID0gcmVxdWlyZSgnLi9jcmVhdGUnKTtcblxudmFyIGZvcm0gPSBnbG9iYWwuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21haW4tZm9ybScpO1xudmFyIGNlcnRUYWcgPSBnbG9iYWwuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NlcnQnKTtcbnZhciBrZXlUYWcgPSBnbG9iYWwuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2tleScpO1xuZm9ybS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcbiAgdmFyIGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKGZvcm0pO1xuXG4gIHZhciBvYmogPSB7fTtcbiAgdmFyIGtleXR5cGU7XG4gIGZvciAobGV0IFtrZXksIHZhbHVlXSBvZiBmb3JtRGF0YSkge1xuICAgIGlmIChrZXkgPT09ICdrZXl0eXBlJykge1xuICAgICAga2V5dHlwZSA9IHZhbHVlO1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIG9ialtrZXldID0gdmFsdWU7XG4gIH1cbiAgY2xlYXJBbGwoKTtcbiAgbWFrZUNzcihrZXl0eXBlLCBvYmopLnRoZW4oZnVuY3Rpb24gKHJlc3ApIHtcbiAgICBzZXRDZXJ0KHJlc3BbMF0pO1xuICAgIHNldEtleShyZXNwWzFdKTtcbiAgfSkuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICBjb25zb2xlLmxvZyhlKTtcbiAgfSlcbn0pO1xuZnVuY3Rpb24gY2xlYXJBbGwoKSB7XG4gIHZhciB0YWcgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyk7XG4gIHZhciB0YWcyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpO1xuICBjZXJ0VGFnLnJlcGxhY2VDaGlsZCh0YWcsIGNlcnRUYWcuZmlyc3RDaGlsZCk7XG4gIGtleVRhZy5yZXBsYWNlQ2hpbGQodGFnMiwga2V5VGFnLmZpcnN0Q2hpbGQpO1xufVxuZnVuY3Rpb24gc2V0Q2VydChjZXJ0KSB7XG4gIHZhciB0YWcgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdwcmUnKTtcbiAgdGFnLnRleHRDb250ZW50PWNlcnQ7XG4gIGNlcnRUYWcucmVwbGFjZUNoaWxkKHRhZywgY2VydFRhZy5maXJzdENoaWxkKTtcbn1cbmZ1bmN0aW9uIHNldEtleShrZXkpIHtcbiAgdmFyIHRhZyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3ByZScpO1xuICB0YWcudGV4dENvbnRlbnQ9a2V5O1xuICBrZXlUYWcucmVwbGFjZUNoaWxkKHRhZywga2V5VGFnLmZpcnN0Q2hpbGQpO1xufVxuIiwidmFyIGFzbjEgPSBleHBvcnRzO1xuXG5hc24xLmJpZ251bSA9IHJlcXVpcmUoJ2JuLmpzJyk7XG5cbmFzbjEuZGVmaW5lID0gcmVxdWlyZSgnLi9hc24xL2FwaScpLmRlZmluZTtcbmFzbjEuYmFzZSA9IHJlcXVpcmUoJy4vYXNuMS9iYXNlJyk7XG5hc24xLmNvbnN0YW50cyA9IHJlcXVpcmUoJy4vYXNuMS9jb25zdGFudHMnKTtcbmFzbjEuZGVjb2RlcnMgPSByZXF1aXJlKCcuL2FzbjEvZGVjb2RlcnMnKTtcbmFzbjEuZW5jb2RlcnMgPSByZXF1aXJlKCcuL2FzbjEvZW5jb2RlcnMnKTtcbiIsInZhciBhc24xID0gcmVxdWlyZSgnLi4vYXNuMScpO1xudmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcblxudmFyIGFwaSA9IGV4cG9ydHM7XG5cbmFwaS5kZWZpbmUgPSBmdW5jdGlvbiBkZWZpbmUobmFtZSwgYm9keSkge1xuICByZXR1cm4gbmV3IEVudGl0eShuYW1lLCBib2R5KTtcbn07XG5cbmZ1bmN0aW9uIEVudGl0eShuYW1lLCBib2R5KSB7XG4gIHRoaXMubmFtZSA9IG5hbWU7XG4gIHRoaXMuYm9keSA9IGJvZHk7XG5cbiAgdGhpcy5kZWNvZGVycyA9IHt9O1xuICB0aGlzLmVuY29kZXJzID0ge307XG59O1xuXG5FbnRpdHkucHJvdG90eXBlLl9jcmVhdGVOYW1lZCA9IGZ1bmN0aW9uIGNyZWF0ZU5hbWVkKGJhc2UpIHtcbiAgdmFyIG5hbWVkO1xuICB0cnkge1xuICAgIG5hbWVkID0gcmVxdWlyZSgndm0nKS5ydW5JblRoaXNDb250ZXh0KFxuICAgICAgJyhmdW5jdGlvbiAnICsgdGhpcy5uYW1lICsgJyhlbnRpdHkpIHtcXG4nICtcbiAgICAgICcgIHRoaXMuX2luaXROYW1lZChlbnRpdHkpO1xcbicgK1xuICAgICAgJ30pJ1xuICAgICk7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICBuYW1lZCA9IGZ1bmN0aW9uIChlbnRpdHkpIHtcbiAgICAgIHRoaXMuX2luaXROYW1lZChlbnRpdHkpO1xuICAgIH07XG4gIH1cbiAgaW5oZXJpdHMobmFtZWQsIGJhc2UpO1xuICBuYW1lZC5wcm90b3R5cGUuX2luaXROYW1lZCA9IGZ1bmN0aW9uIGluaXRuYW1lZChlbnRpdHkpIHtcbiAgICBiYXNlLmNhbGwodGhpcywgZW50aXR5KTtcbiAgfTtcblxuICByZXR1cm4gbmV3IG5hbWVkKHRoaXMpO1xufTtcblxuRW50aXR5LnByb3RvdHlwZS5fZ2V0RGVjb2RlciA9IGZ1bmN0aW9uIF9nZXREZWNvZGVyKGVuYykge1xuICBlbmMgPSBlbmMgfHwgJ2Rlcic7XG4gIC8vIExhemlseSBjcmVhdGUgZGVjb2RlclxuICBpZiAoIXRoaXMuZGVjb2RlcnMuaGFzT3duUHJvcGVydHkoZW5jKSlcbiAgICB0aGlzLmRlY29kZXJzW2VuY10gPSB0aGlzLl9jcmVhdGVOYW1lZChhc24xLmRlY29kZXJzW2VuY10pO1xuICByZXR1cm4gdGhpcy5kZWNvZGVyc1tlbmNdO1xufTtcblxuRW50aXR5LnByb3RvdHlwZS5kZWNvZGUgPSBmdW5jdGlvbiBkZWNvZGUoZGF0YSwgZW5jLCBvcHRpb25zKSB7XG4gIHJldHVybiB0aGlzLl9nZXREZWNvZGVyKGVuYykuZGVjb2RlKGRhdGEsIG9wdGlvbnMpO1xufTtcblxuRW50aXR5LnByb3RvdHlwZS5fZ2V0RW5jb2RlciA9IGZ1bmN0aW9uIF9nZXRFbmNvZGVyKGVuYykge1xuICBlbmMgPSBlbmMgfHwgJ2Rlcic7XG4gIC8vIExhemlseSBjcmVhdGUgZW5jb2RlclxuICBpZiAoIXRoaXMuZW5jb2RlcnMuaGFzT3duUHJvcGVydHkoZW5jKSlcbiAgICB0aGlzLmVuY29kZXJzW2VuY10gPSB0aGlzLl9jcmVhdGVOYW1lZChhc24xLmVuY29kZXJzW2VuY10pO1xuICByZXR1cm4gdGhpcy5lbmNvZGVyc1tlbmNdO1xufTtcblxuRW50aXR5LnByb3RvdHlwZS5lbmNvZGUgPSBmdW5jdGlvbiBlbmNvZGUoZGF0YSwgZW5jLCAvKiBpbnRlcm5hbCAqLyByZXBvcnRlcikge1xuICByZXR1cm4gdGhpcy5fZ2V0RW5jb2RlcihlbmMpLmVuY29kZShkYXRhLCByZXBvcnRlcik7XG59O1xuIiwidmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcbnZhciBSZXBvcnRlciA9IHJlcXVpcmUoJy4uL2Jhc2UnKS5SZXBvcnRlcjtcbnZhciBCdWZmZXIgPSByZXF1aXJlKCdidWZmZXInKS5CdWZmZXI7XG5cbmZ1bmN0aW9uIERlY29kZXJCdWZmZXIoYmFzZSwgb3B0aW9ucykge1xuICBSZXBvcnRlci5jYWxsKHRoaXMsIG9wdGlvbnMpO1xuICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcihiYXNlKSkge1xuICAgIHRoaXMuZXJyb3IoJ0lucHV0IG5vdCBCdWZmZXInKTtcbiAgICByZXR1cm47XG4gIH1cblxuICB0aGlzLmJhc2UgPSBiYXNlO1xuICB0aGlzLm9mZnNldCA9IDA7XG4gIHRoaXMubGVuZ3RoID0gYmFzZS5sZW5ndGg7XG59XG5pbmhlcml0cyhEZWNvZGVyQnVmZmVyLCBSZXBvcnRlcik7XG5leHBvcnRzLkRlY29kZXJCdWZmZXIgPSBEZWNvZGVyQnVmZmVyO1xuXG5EZWNvZGVyQnVmZmVyLnByb3RvdHlwZS5zYXZlID0gZnVuY3Rpb24gc2F2ZSgpIHtcbiAgcmV0dXJuIHsgb2Zmc2V0OiB0aGlzLm9mZnNldCwgcmVwb3J0ZXI6IFJlcG9ydGVyLnByb3RvdHlwZS5zYXZlLmNhbGwodGhpcykgfTtcbn07XG5cbkRlY29kZXJCdWZmZXIucHJvdG90eXBlLnJlc3RvcmUgPSBmdW5jdGlvbiByZXN0b3JlKHNhdmUpIHtcbiAgLy8gUmV0dXJuIHNraXBwZWQgZGF0YVxuICB2YXIgcmVzID0gbmV3IERlY29kZXJCdWZmZXIodGhpcy5iYXNlKTtcbiAgcmVzLm9mZnNldCA9IHNhdmUub2Zmc2V0O1xuICByZXMubGVuZ3RoID0gdGhpcy5vZmZzZXQ7XG5cbiAgdGhpcy5vZmZzZXQgPSBzYXZlLm9mZnNldDtcbiAgUmVwb3J0ZXIucHJvdG90eXBlLnJlc3RvcmUuY2FsbCh0aGlzLCBzYXZlLnJlcG9ydGVyKTtcblxuICByZXR1cm4gcmVzO1xufTtcblxuRGVjb2RlckJ1ZmZlci5wcm90b3R5cGUuaXNFbXB0eSA9IGZ1bmN0aW9uIGlzRW1wdHkoKSB7XG4gIHJldHVybiB0aGlzLm9mZnNldCA9PT0gdGhpcy5sZW5ndGg7XG59O1xuXG5EZWNvZGVyQnVmZmVyLnByb3RvdHlwZS5yZWFkVUludDggPSBmdW5jdGlvbiByZWFkVUludDgoZmFpbCkge1xuICBpZiAodGhpcy5vZmZzZXQgKyAxIDw9IHRoaXMubGVuZ3RoKVxuICAgIHJldHVybiB0aGlzLmJhc2UucmVhZFVJbnQ4KHRoaXMub2Zmc2V0KyssIHRydWUpO1xuICBlbHNlXG4gICAgcmV0dXJuIHRoaXMuZXJyb3IoZmFpbCB8fCAnRGVjb2RlckJ1ZmZlciBvdmVycnVuJyk7XG59XG5cbkRlY29kZXJCdWZmZXIucHJvdG90eXBlLnNraXAgPSBmdW5jdGlvbiBza2lwKGJ5dGVzLCBmYWlsKSB7XG4gIGlmICghKHRoaXMub2Zmc2V0ICsgYnl0ZXMgPD0gdGhpcy5sZW5ndGgpKVxuICAgIHJldHVybiB0aGlzLmVycm9yKGZhaWwgfHwgJ0RlY29kZXJCdWZmZXIgb3ZlcnJ1bicpO1xuXG4gIHZhciByZXMgPSBuZXcgRGVjb2RlckJ1ZmZlcih0aGlzLmJhc2UpO1xuXG4gIC8vIFNoYXJlIHJlcG9ydGVyIHN0YXRlXG4gIHJlcy5fcmVwb3J0ZXJTdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgcmVzLm9mZnNldCA9IHRoaXMub2Zmc2V0O1xuICByZXMubGVuZ3RoID0gdGhpcy5vZmZzZXQgKyBieXRlcztcbiAgdGhpcy5vZmZzZXQgKz0gYnl0ZXM7XG4gIHJldHVybiByZXM7XG59XG5cbkRlY29kZXJCdWZmZXIucHJvdG90eXBlLnJhdyA9IGZ1bmN0aW9uIHJhdyhzYXZlKSB7XG4gIHJldHVybiB0aGlzLmJhc2Uuc2xpY2Uoc2F2ZSA/IHNhdmUub2Zmc2V0IDogdGhpcy5vZmZzZXQsIHRoaXMubGVuZ3RoKTtcbn1cblxuZnVuY3Rpb24gRW5jb2RlckJ1ZmZlcih2YWx1ZSwgcmVwb3J0ZXIpIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgdGhpcy5sZW5ndGggPSAwO1xuICAgIHRoaXMudmFsdWUgPSB2YWx1ZS5tYXAoZnVuY3Rpb24oaXRlbSkge1xuICAgICAgaWYgKCEoaXRlbSBpbnN0YW5jZW9mIEVuY29kZXJCdWZmZXIpKVxuICAgICAgICBpdGVtID0gbmV3IEVuY29kZXJCdWZmZXIoaXRlbSwgcmVwb3J0ZXIpO1xuICAgICAgdGhpcy5sZW5ndGggKz0gaXRlbS5sZW5ndGg7XG4gICAgICByZXR1cm4gaXRlbTtcbiAgICB9LCB0aGlzKTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgdmFsdWUgPT09ICdudW1iZXInKSB7XG4gICAgaWYgKCEoMCA8PSB2YWx1ZSAmJiB2YWx1ZSA8PSAweGZmKSlcbiAgICAgIHJldHVybiByZXBvcnRlci5lcnJvcignbm9uLWJ5dGUgRW5jb2RlckJ1ZmZlciB2YWx1ZScpO1xuICAgIHRoaXMudmFsdWUgPSB2YWx1ZTtcbiAgICB0aGlzLmxlbmd0aCA9IDE7XG4gIH0gZWxzZSBpZiAodHlwZW9mIHZhbHVlID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMudmFsdWUgPSB2YWx1ZTtcbiAgICB0aGlzLmxlbmd0aCA9IEJ1ZmZlci5ieXRlTGVuZ3RoKHZhbHVlKTtcbiAgfSBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIodmFsdWUpKSB7XG4gICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgIHRoaXMubGVuZ3RoID0gdmFsdWUubGVuZ3RoO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiByZXBvcnRlci5lcnJvcignVW5zdXBwb3J0ZWQgdHlwZTogJyArIHR5cGVvZiB2YWx1ZSk7XG4gIH1cbn1cbmV4cG9ydHMuRW5jb2RlckJ1ZmZlciA9IEVuY29kZXJCdWZmZXI7XG5cbkVuY29kZXJCdWZmZXIucHJvdG90eXBlLmpvaW4gPSBmdW5jdGlvbiBqb2luKG91dCwgb2Zmc2V0KSB7XG4gIGlmICghb3V0KVxuICAgIG91dCA9IG5ldyBCdWZmZXIodGhpcy5sZW5ndGgpO1xuICBpZiAoIW9mZnNldClcbiAgICBvZmZzZXQgPSAwO1xuXG4gIGlmICh0aGlzLmxlbmd0aCA9PT0gMClcbiAgICByZXR1cm4gb3V0O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KHRoaXMudmFsdWUpKSB7XG4gICAgdGhpcy52YWx1ZS5mb3JFYWNoKGZ1bmN0aW9uKGl0ZW0pIHtcbiAgICAgIGl0ZW0uam9pbihvdXQsIG9mZnNldCk7XG4gICAgICBvZmZzZXQgKz0gaXRlbS5sZW5ndGg7XG4gICAgfSk7XG4gIH0gZWxzZSB7XG4gICAgaWYgKHR5cGVvZiB0aGlzLnZhbHVlID09PSAnbnVtYmVyJylcbiAgICAgIG91dFtvZmZzZXRdID0gdGhpcy52YWx1ZTtcbiAgICBlbHNlIGlmICh0eXBlb2YgdGhpcy52YWx1ZSA9PT0gJ3N0cmluZycpXG4gICAgICBvdXQud3JpdGUodGhpcy52YWx1ZSwgb2Zmc2V0KTtcbiAgICBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIodGhpcy52YWx1ZSkpXG4gICAgICB0aGlzLnZhbHVlLmNvcHkob3V0LCBvZmZzZXQpO1xuICAgIG9mZnNldCArPSB0aGlzLmxlbmd0aDtcbiAgfVxuXG4gIHJldHVybiBvdXQ7XG59O1xuIiwidmFyIGJhc2UgPSBleHBvcnRzO1xuXG5iYXNlLlJlcG9ydGVyID0gcmVxdWlyZSgnLi9yZXBvcnRlcicpLlJlcG9ydGVyO1xuYmFzZS5EZWNvZGVyQnVmZmVyID0gcmVxdWlyZSgnLi9idWZmZXInKS5EZWNvZGVyQnVmZmVyO1xuYmFzZS5FbmNvZGVyQnVmZmVyID0gcmVxdWlyZSgnLi9idWZmZXInKS5FbmNvZGVyQnVmZmVyO1xuYmFzZS5Ob2RlID0gcmVxdWlyZSgnLi9ub2RlJyk7XG4iLCJ2YXIgUmVwb3J0ZXIgPSByZXF1aXJlKCcuLi9iYXNlJykuUmVwb3J0ZXI7XG52YXIgRW5jb2RlckJ1ZmZlciA9IHJlcXVpcmUoJy4uL2Jhc2UnKS5FbmNvZGVyQnVmZmVyO1xudmFyIERlY29kZXJCdWZmZXIgPSByZXF1aXJlKCcuLi9iYXNlJykuRGVjb2RlckJ1ZmZlcjtcbnZhciBhc3NlcnQgPSByZXF1aXJlKCdtaW5pbWFsaXN0aWMtYXNzZXJ0Jyk7XG5cbi8vIFN1cHBvcnRlZCB0YWdzXG52YXIgdGFncyA9IFtcbiAgJ3NlcScsICdzZXFvZicsICdzZXQnLCAnc2V0b2YnLCAnb2JqaWQnLCAnYm9vbCcsXG4gICdnZW50aW1lJywgJ3V0Y3RpbWUnLCAnbnVsbF8nLCAnZW51bScsICdpbnQnLFxuICAnYml0c3RyJywgJ2JtcHN0cicsICdjaGFyc3RyJywgJ2dlbnN0cicsICdncmFwaHN0cicsICdpYTVzdHInLCAnaXNvNjQ2c3RyJyxcbiAgJ251bXN0cicsICdvY3RzdHInLCAncHJpbnRzdHInLCAndDYxc3RyJywgJ3VuaXN0cicsICd1dGY4c3RyJywgJ3ZpZGVvc3RyJ1xuXTtcblxuLy8gUHVibGljIG1ldGhvZHMgbGlzdFxudmFyIG1ldGhvZHMgPSBbXG4gICdrZXknLCAnb2JqJywgJ3VzZScsICdvcHRpb25hbCcsICdleHBsaWNpdCcsICdpbXBsaWNpdCcsICdkZWYnLCAnY2hvaWNlJyxcbiAgJ2FueScsICdjb250YWlucydcbl0uY29uY2F0KHRhZ3MpO1xuXG4vLyBPdmVycmlkZWQgbWV0aG9kcyBsaXN0XG52YXIgb3ZlcnJpZGVkID0gW1xuICAnX3BlZWtUYWcnLCAnX2RlY29kZVRhZycsICdfdXNlJyxcbiAgJ19kZWNvZGVTdHInLCAnX2RlY29kZU9iamlkJywgJ19kZWNvZGVUaW1lJyxcbiAgJ19kZWNvZGVOdWxsJywgJ19kZWNvZGVJbnQnLCAnX2RlY29kZUJvb2wnLCAnX2RlY29kZUxpc3QnLFxuXG4gICdfZW5jb2RlQ29tcG9zaXRlJywgJ19lbmNvZGVTdHInLCAnX2VuY29kZU9iamlkJywgJ19lbmNvZGVUaW1lJyxcbiAgJ19lbmNvZGVOdWxsJywgJ19lbmNvZGVJbnQnLCAnX2VuY29kZUJvb2wnXG5dO1xuXG5mdW5jdGlvbiBOb2RlKGVuYywgcGFyZW50KSB7XG4gIHZhciBzdGF0ZSA9IHt9O1xuICB0aGlzLl9iYXNlU3RhdGUgPSBzdGF0ZTtcblxuICBzdGF0ZS5lbmMgPSBlbmM7XG5cbiAgc3RhdGUucGFyZW50ID0gcGFyZW50IHx8IG51bGw7XG4gIHN0YXRlLmNoaWxkcmVuID0gbnVsbDtcblxuICAvLyBTdGF0ZVxuICBzdGF0ZS50YWcgPSBudWxsO1xuICBzdGF0ZS5hcmdzID0gbnVsbDtcbiAgc3RhdGUucmV2ZXJzZUFyZ3MgPSBudWxsO1xuICBzdGF0ZS5jaG9pY2UgPSBudWxsO1xuICBzdGF0ZS5vcHRpb25hbCA9IGZhbHNlO1xuICBzdGF0ZS5hbnkgPSBmYWxzZTtcbiAgc3RhdGUub2JqID0gZmFsc2U7XG4gIHN0YXRlLnVzZSA9IG51bGw7XG4gIHN0YXRlLnVzZURlY29kZXIgPSBudWxsO1xuICBzdGF0ZS5rZXkgPSBudWxsO1xuICBzdGF0ZVsnZGVmYXVsdCddID0gbnVsbDtcbiAgc3RhdGUuZXhwbGljaXQgPSBudWxsO1xuICBzdGF0ZS5pbXBsaWNpdCA9IG51bGw7XG4gIHN0YXRlLmNvbnRhaW5zID0gbnVsbDtcblxuICAvLyBTaG91bGQgY3JlYXRlIG5ldyBpbnN0YW5jZSBvbiBlYWNoIG1ldGhvZFxuICBpZiAoIXN0YXRlLnBhcmVudCkge1xuICAgIHN0YXRlLmNoaWxkcmVuID0gW107XG4gICAgdGhpcy5fd3JhcCgpO1xuICB9XG59XG5tb2R1bGUuZXhwb3J0cyA9IE5vZGU7XG5cbnZhciBzdGF0ZVByb3BzID0gW1xuICAnZW5jJywgJ3BhcmVudCcsICdjaGlsZHJlbicsICd0YWcnLCAnYXJncycsICdyZXZlcnNlQXJncycsICdjaG9pY2UnLFxuICAnb3B0aW9uYWwnLCAnYW55JywgJ29iaicsICd1c2UnLCAnYWx0ZXJlZFVzZScsICdrZXknLCAnZGVmYXVsdCcsICdleHBsaWNpdCcsXG4gICdpbXBsaWNpdCdcbl07XG5cbk5vZGUucHJvdG90eXBlLmNsb25lID0gZnVuY3Rpb24gY2xvbmUoKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgdmFyIGNzdGF0ZSA9IHt9O1xuICBzdGF0ZVByb3BzLmZvckVhY2goZnVuY3Rpb24ocHJvcCkge1xuICAgIGNzdGF0ZVtwcm9wXSA9IHN0YXRlW3Byb3BdO1xuICB9KTtcbiAgdmFyIHJlcyA9IG5ldyB0aGlzLmNvbnN0cnVjdG9yKGNzdGF0ZS5wYXJlbnQpO1xuICByZXMuX2Jhc2VTdGF0ZSA9IGNzdGF0ZTtcbiAgcmV0dXJuIHJlcztcbn07XG5cbk5vZGUucHJvdG90eXBlLl93cmFwID0gZnVuY3Rpb24gd3JhcCgpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICBtZXRob2RzLmZvckVhY2goZnVuY3Rpb24obWV0aG9kKSB7XG4gICAgdGhpc1ttZXRob2RdID0gZnVuY3Rpb24gX3dyYXBwZWRNZXRob2QoKSB7XG4gICAgICB2YXIgY2xvbmUgPSBuZXcgdGhpcy5jb25zdHJ1Y3Rvcih0aGlzKTtcbiAgICAgIHN0YXRlLmNoaWxkcmVuLnB1c2goY2xvbmUpO1xuICAgICAgcmV0dXJuIGNsb25lW21ldGhvZF0uYXBwbHkoY2xvbmUsIGFyZ3VtZW50cyk7XG4gICAgfTtcbiAgfSwgdGhpcyk7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5faW5pdCA9IGZ1bmN0aW9uIGluaXQoYm9keSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLnBhcmVudCA9PT0gbnVsbCk7XG4gIGJvZHkuY2FsbCh0aGlzKTtcblxuICAvLyBGaWx0ZXIgY2hpbGRyZW5cbiAgc3RhdGUuY2hpbGRyZW4gPSBzdGF0ZS5jaGlsZHJlbi5maWx0ZXIoZnVuY3Rpb24oY2hpbGQpIHtcbiAgICByZXR1cm4gY2hpbGQuX2Jhc2VTdGF0ZS5wYXJlbnQgPT09IHRoaXM7XG4gIH0sIHRoaXMpO1xuICBhc3NlcnQuZXF1YWwoc3RhdGUuY2hpbGRyZW4ubGVuZ3RoLCAxLCAnUm9vdCBub2RlIGNhbiBoYXZlIG9ubHkgb25lIGNoaWxkJyk7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fdXNlQXJncyA9IGZ1bmN0aW9uIHVzZUFyZ3MoYXJncykge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgLy8gRmlsdGVyIGNoaWxkcmVuIGFuZCBhcmdzXG4gIHZhciBjaGlsZHJlbiA9IGFyZ3MuZmlsdGVyKGZ1bmN0aW9uKGFyZykge1xuICAgIHJldHVybiBhcmcgaW5zdGFuY2VvZiB0aGlzLmNvbnN0cnVjdG9yO1xuICB9LCB0aGlzKTtcbiAgYXJncyA9IGFyZ3MuZmlsdGVyKGZ1bmN0aW9uKGFyZykge1xuICAgIHJldHVybiAhKGFyZyBpbnN0YW5jZW9mIHRoaXMuY29uc3RydWN0b3IpO1xuICB9LCB0aGlzKTtcblxuICBpZiAoY2hpbGRyZW4ubGVuZ3RoICE9PSAwKSB7XG4gICAgYXNzZXJ0KHN0YXRlLmNoaWxkcmVuID09PSBudWxsKTtcbiAgICBzdGF0ZS5jaGlsZHJlbiA9IGNoaWxkcmVuO1xuXG4gICAgLy8gUmVwbGFjZSBwYXJlbnQgdG8gbWFpbnRhaW4gYmFja3dhcmQgbGlua1xuICAgIGNoaWxkcmVuLmZvckVhY2goZnVuY3Rpb24oY2hpbGQpIHtcbiAgICAgIGNoaWxkLl9iYXNlU3RhdGUucGFyZW50ID0gdGhpcztcbiAgICB9LCB0aGlzKTtcbiAgfVxuICBpZiAoYXJncy5sZW5ndGggIT09IDApIHtcbiAgICBhc3NlcnQoc3RhdGUuYXJncyA9PT0gbnVsbCk7XG4gICAgc3RhdGUuYXJncyA9IGFyZ3M7XG4gICAgc3RhdGUucmV2ZXJzZUFyZ3MgPSBhcmdzLm1hcChmdW5jdGlvbihhcmcpIHtcbiAgICAgIGlmICh0eXBlb2YgYXJnICE9PSAnb2JqZWN0JyB8fCBhcmcuY29uc3RydWN0b3IgIT09IE9iamVjdClcbiAgICAgICAgcmV0dXJuIGFyZztcblxuICAgICAgdmFyIHJlcyA9IHt9O1xuICAgICAgT2JqZWN0LmtleXMoYXJnKS5mb3JFYWNoKGZ1bmN0aW9uKGtleSkge1xuICAgICAgICBpZiAoa2V5ID09IChrZXkgfCAwKSlcbiAgICAgICAgICBrZXkgfD0gMDtcbiAgICAgICAgdmFyIHZhbHVlID0gYXJnW2tleV07XG4gICAgICAgIHJlc1t2YWx1ZV0gPSBrZXk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybiByZXM7XG4gICAgfSk7XG4gIH1cbn07XG5cbi8vXG4vLyBPdmVycmlkZWQgbWV0aG9kc1xuLy9cblxub3ZlcnJpZGVkLmZvckVhY2goZnVuY3Rpb24obWV0aG9kKSB7XG4gIE5vZGUucHJvdG90eXBlW21ldGhvZF0gPSBmdW5jdGlvbiBfb3ZlcnJpZGVkKCkge1xuICAgIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgICB0aHJvdyBuZXcgRXJyb3IobWV0aG9kICsgJyBub3QgaW1wbGVtZW50ZWQgZm9yIGVuY29kaW5nOiAnICsgc3RhdGUuZW5jKTtcbiAgfTtcbn0pO1xuXG4vL1xuLy8gUHVibGljIG1ldGhvZHNcbi8vXG5cbnRhZ3MuZm9yRWFjaChmdW5jdGlvbih0YWcpIHtcbiAgTm9kZS5wcm90b3R5cGVbdGFnXSA9IGZ1bmN0aW9uIF90YWdNZXRob2QoKSB7XG4gICAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICAgIHZhciBhcmdzID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtcblxuICAgIGFzc2VydChzdGF0ZS50YWcgPT09IG51bGwpO1xuICAgIHN0YXRlLnRhZyA9IHRhZztcblxuICAgIHRoaXMuX3VzZUFyZ3MoYXJncyk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcbn0pO1xuXG5Ob2RlLnByb3RvdHlwZS51c2UgPSBmdW5jdGlvbiB1c2UoaXRlbSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLnVzZSA9PT0gbnVsbCk7XG4gIHN0YXRlLnVzZSA9IGl0ZW07XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5vcHRpb25hbCA9IGZ1bmN0aW9uIG9wdGlvbmFsKCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgc3RhdGUub3B0aW9uYWwgPSB0cnVlO1xuXG4gIHJldHVybiB0aGlzO1xufTtcblxuTm9kZS5wcm90b3R5cGUuZGVmID0gZnVuY3Rpb24gZGVmKHZhbCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlWydkZWZhdWx0J10gPT09IG51bGwpO1xuICBzdGF0ZVsnZGVmYXVsdCddID0gdmFsO1xuICBzdGF0ZS5vcHRpb25hbCA9IHRydWU7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5leHBsaWNpdCA9IGZ1bmN0aW9uIGV4cGxpY2l0KG51bSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLmV4cGxpY2l0ID09PSBudWxsICYmIHN0YXRlLmltcGxpY2l0ID09PSBudWxsKTtcbiAgc3RhdGUuZXhwbGljaXQgPSBudW07XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5pbXBsaWNpdCA9IGZ1bmN0aW9uIGltcGxpY2l0KG51bSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLmV4cGxpY2l0ID09PSBudWxsICYmIHN0YXRlLmltcGxpY2l0ID09PSBudWxsKTtcbiAgc3RhdGUuaW1wbGljaXQgPSBudW07XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5vYmogPSBmdW5jdGlvbiBvYmooKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgdmFyIGFyZ3MgPSBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChhcmd1bWVudHMpO1xuXG4gIHN0YXRlLm9iaiA9IHRydWU7XG5cbiAgaWYgKGFyZ3MubGVuZ3RoICE9PSAwKVxuICAgIHRoaXMuX3VzZUFyZ3MoYXJncyk7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5rZXkgPSBmdW5jdGlvbiBrZXkobmV3S2V5KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGUua2V5ID09PSBudWxsKTtcbiAgc3RhdGUua2V5ID0gbmV3S2V5O1xuXG4gIHJldHVybiB0aGlzO1xufTtcblxuTm9kZS5wcm90b3R5cGUuYW55ID0gZnVuY3Rpb24gYW55KCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgc3RhdGUuYW55ID0gdHJ1ZTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLmNob2ljZSA9IGZ1bmN0aW9uIGNob2ljZShvYmopIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIGFzc2VydChzdGF0ZS5jaG9pY2UgPT09IG51bGwpO1xuICBzdGF0ZS5jaG9pY2UgPSBvYmo7XG4gIHRoaXMuX3VzZUFyZ3MoT2JqZWN0LmtleXMob2JqKS5tYXAoZnVuY3Rpb24oa2V5KSB7XG4gICAgcmV0dXJuIG9ialtrZXldO1xuICB9KSk7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5jb250YWlucyA9IGZ1bmN0aW9uIGNvbnRhaW5zKGl0ZW0pIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIGFzc2VydChzdGF0ZS51c2UgPT09IG51bGwpO1xuICBzdGF0ZS5jb250YWlucyA9IGl0ZW07XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vL1xuLy8gRGVjb2Rpbmdcbi8vXG5cbk5vZGUucHJvdG90eXBlLl9kZWNvZGUgPSBmdW5jdGlvbiBkZWNvZGUoaW5wdXQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIC8vIERlY29kZSByb290IG5vZGVcbiAgaWYgKHN0YXRlLnBhcmVudCA9PT0gbnVsbClcbiAgICByZXR1cm4gaW5wdXQud3JhcFJlc3VsdChzdGF0ZS5jaGlsZHJlblswXS5fZGVjb2RlKGlucHV0KSk7XG5cbiAgdmFyIHJlc3VsdCA9IHN0YXRlWydkZWZhdWx0J107XG4gIHZhciBwcmVzZW50ID0gdHJ1ZTtcblxuICB2YXIgcHJldktleTtcbiAgaWYgKHN0YXRlLmtleSAhPT0gbnVsbClcbiAgICBwcmV2S2V5ID0gaW5wdXQuZW50ZXJLZXkoc3RhdGUua2V5KTtcblxuICAvLyBDaGVjayBpZiB0YWcgaXMgdGhlcmVcbiAgaWYgKHN0YXRlLm9wdGlvbmFsKSB7XG4gICAgdmFyIHRhZyA9IG51bGw7XG4gICAgaWYgKHN0YXRlLmV4cGxpY2l0ICE9PSBudWxsKVxuICAgICAgdGFnID0gc3RhdGUuZXhwbGljaXQ7XG4gICAgZWxzZSBpZiAoc3RhdGUuaW1wbGljaXQgIT09IG51bGwpXG4gICAgICB0YWcgPSBzdGF0ZS5pbXBsaWNpdDtcbiAgICBlbHNlIGlmIChzdGF0ZS50YWcgIT09IG51bGwpXG4gICAgICB0YWcgPSBzdGF0ZS50YWc7XG5cbiAgICBpZiAodGFnID09PSBudWxsICYmICFzdGF0ZS5hbnkpIHtcbiAgICAgIC8vIFRyaWFsIGFuZCBFcnJvclxuICAgICAgdmFyIHNhdmUgPSBpbnB1dC5zYXZlKCk7XG4gICAgICB0cnkge1xuICAgICAgICBpZiAoc3RhdGUuY2hvaWNlID09PSBudWxsKVxuICAgICAgICAgIHRoaXMuX2RlY29kZUdlbmVyaWMoc3RhdGUudGFnLCBpbnB1dCk7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aGlzLl9kZWNvZGVDaG9pY2UoaW5wdXQpO1xuICAgICAgICBwcmVzZW50ID0gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgcHJlc2VudCA9IGZhbHNlO1xuICAgICAgfVxuICAgICAgaW5wdXQucmVzdG9yZShzYXZlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcHJlc2VudCA9IHRoaXMuX3BlZWtUYWcoaW5wdXQsIHRhZywgc3RhdGUuYW55KTtcblxuICAgICAgaWYgKGlucHV0LmlzRXJyb3IocHJlc2VudCkpXG4gICAgICAgIHJldHVybiBwcmVzZW50O1xuICAgIH1cbiAgfVxuXG4gIC8vIFB1c2ggb2JqZWN0IG9uIHN0YWNrXG4gIHZhciBwcmV2T2JqO1xuICBpZiAoc3RhdGUub2JqICYmIHByZXNlbnQpXG4gICAgcHJldk9iaiA9IGlucHV0LmVudGVyT2JqZWN0KCk7XG5cbiAgaWYgKHByZXNlbnQpIHtcbiAgICAvLyBVbndyYXAgZXhwbGljaXQgdmFsdWVzXG4gICAgaWYgKHN0YXRlLmV4cGxpY2l0ICE9PSBudWxsKSB7XG4gICAgICB2YXIgZXhwbGljaXQgPSB0aGlzLl9kZWNvZGVUYWcoaW5wdXQsIHN0YXRlLmV4cGxpY2l0KTtcbiAgICAgIGlmIChpbnB1dC5pc0Vycm9yKGV4cGxpY2l0KSlcbiAgICAgICAgcmV0dXJuIGV4cGxpY2l0O1xuICAgICAgaW5wdXQgPSBleHBsaWNpdDtcbiAgICB9XG5cbiAgICAvLyBVbndyYXAgaW1wbGljaXQgYW5kIG5vcm1hbCB2YWx1ZXNcbiAgICBpZiAoc3RhdGUudXNlID09PSBudWxsICYmIHN0YXRlLmNob2ljZSA9PT0gbnVsbCkge1xuICAgICAgaWYgKHN0YXRlLmFueSlcbiAgICAgICAgdmFyIHNhdmUgPSBpbnB1dC5zYXZlKCk7XG4gICAgICB2YXIgYm9keSA9IHRoaXMuX2RlY29kZVRhZyhcbiAgICAgICAgaW5wdXQsXG4gICAgICAgIHN0YXRlLmltcGxpY2l0ICE9PSBudWxsID8gc3RhdGUuaW1wbGljaXQgOiBzdGF0ZS50YWcsXG4gICAgICAgIHN0YXRlLmFueVxuICAgICAgKTtcbiAgICAgIGlmIChpbnB1dC5pc0Vycm9yKGJvZHkpKVxuICAgICAgICByZXR1cm4gYm9keTtcblxuICAgICAgaWYgKHN0YXRlLmFueSlcbiAgICAgICAgcmVzdWx0ID0gaW5wdXQucmF3KHNhdmUpO1xuICAgICAgZWxzZVxuICAgICAgICBpbnB1dCA9IGJvZHk7XG4gICAgfVxuXG4gICAgLy8gU2VsZWN0IHByb3BlciBtZXRob2QgZm9yIHRhZ1xuICAgIGlmIChzdGF0ZS5hbnkpXG4gICAgICByZXN1bHQgPSByZXN1bHQ7XG4gICAgZWxzZSBpZiAoc3RhdGUuY2hvaWNlID09PSBudWxsKVxuICAgICAgcmVzdWx0ID0gdGhpcy5fZGVjb2RlR2VuZXJpYyhzdGF0ZS50YWcsIGlucHV0KTtcbiAgICBlbHNlXG4gICAgICByZXN1bHQgPSB0aGlzLl9kZWNvZGVDaG9pY2UoaW5wdXQpO1xuXG4gICAgaWYgKGlucHV0LmlzRXJyb3IocmVzdWx0KSlcbiAgICAgIHJldHVybiByZXN1bHQ7XG5cbiAgICAvLyBEZWNvZGUgY2hpbGRyZW5cbiAgICBpZiAoIXN0YXRlLmFueSAmJiBzdGF0ZS5jaG9pY2UgPT09IG51bGwgJiYgc3RhdGUuY2hpbGRyZW4gIT09IG51bGwpIHtcbiAgICAgIHN0YXRlLmNoaWxkcmVuLmZvckVhY2goZnVuY3Rpb24gZGVjb2RlQ2hpbGRyZW4oY2hpbGQpIHtcbiAgICAgICAgLy8gTk9URTogV2UgYXJlIGlnbm9yaW5nIGVycm9ycyBoZXJlLCB0byBsZXQgcGFyc2VyIGNvbnRpbnVlIHdpdGggb3RoZXJcbiAgICAgICAgLy8gcGFydHMgb2YgZW5jb2RlZCBkYXRhXG4gICAgICAgIGNoaWxkLl9kZWNvZGUoaW5wdXQpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gRGVjb2RlIGNvbnRhaW5lZC9lbmNvZGVkIGJ5IHNjaGVtYSwgb25seSBpbiBiaXQgb3Igb2N0ZXQgc3RyaW5nc1xuICAgIGlmIChzdGF0ZS5jb250YWlucyAmJiAoc3RhdGUudGFnID09PSAnb2N0c3RyJyB8fCBzdGF0ZS50YWcgPT09ICdiaXRzdHInKSkge1xuICAgICAgdmFyIGRhdGEgPSBuZXcgRGVjb2RlckJ1ZmZlcihyZXN1bHQpO1xuICAgICAgcmVzdWx0ID0gdGhpcy5fZ2V0VXNlKHN0YXRlLmNvbnRhaW5zLCBpbnB1dC5fcmVwb3J0ZXJTdGF0ZS5vYmopLl9kZWNvZGUoZGF0YSk7XG4gICAgfVxuICB9XG5cbiAgLy8gUG9wIG9iamVjdFxuICBpZiAoc3RhdGUub2JqICYmIHByZXNlbnQpXG4gICAgcmVzdWx0ID0gaW5wdXQubGVhdmVPYmplY3QocHJldk9iaik7XG5cbiAgLy8gU2V0IGtleVxuICBpZiAoc3RhdGUua2V5ICE9PSBudWxsICYmIChyZXN1bHQgIT09IG51bGwgfHwgcHJlc2VudCA9PT0gdHJ1ZSkpXG4gICAgaW5wdXQubGVhdmVLZXkocHJldktleSwgc3RhdGUua2V5LCByZXN1bHQpO1xuXG4gIHJldHVybiByZXN1bHQ7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fZGVjb2RlR2VuZXJpYyA9IGZ1bmN0aW9uIGRlY29kZUdlbmVyaWModGFnLCBpbnB1dCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgaWYgKHRhZyA9PT0gJ3NlcScgfHwgdGFnID09PSAnc2V0JylcbiAgICByZXR1cm4gbnVsbDtcbiAgaWYgKHRhZyA9PT0gJ3NlcW9mJyB8fCB0YWcgPT09ICdzZXRvZicpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZUxpc3QoaW5wdXQsIHRhZywgc3RhdGUuYXJnc1swXSk7XG4gIGVsc2UgaWYgKC9zdHIkLy50ZXN0KHRhZykpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZVN0cihpbnB1dCwgdGFnKTtcbiAgZWxzZSBpZiAodGFnID09PSAnb2JqaWQnICYmIHN0YXRlLmFyZ3MpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZU9iamlkKGlucHV0LCBzdGF0ZS5hcmdzWzBdLCBzdGF0ZS5hcmdzWzFdKTtcbiAgZWxzZSBpZiAodGFnID09PSAnb2JqaWQnKVxuICAgIHJldHVybiB0aGlzLl9kZWNvZGVPYmppZChpbnB1dCwgbnVsbCwgbnVsbCk7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ2dlbnRpbWUnIHx8IHRhZyA9PT0gJ3V0Y3RpbWUnKVxuICAgIHJldHVybiB0aGlzLl9kZWNvZGVUaW1lKGlucHV0LCB0YWcpO1xuICBlbHNlIGlmICh0YWcgPT09ICdudWxsXycpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZU51bGwoaW5wdXQpO1xuICBlbHNlIGlmICh0YWcgPT09ICdib29sJylcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlQm9vbChpbnB1dCk7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ2ludCcgfHwgdGFnID09PSAnZW51bScpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZUludChpbnB1dCwgc3RhdGUuYXJncyAmJiBzdGF0ZS5hcmdzWzBdKTtcbiAgZWxzZSBpZiAoc3RhdGUudXNlICE9PSBudWxsKVxuICAgIHJldHVybiB0aGlzLl9nZXRVc2Uoc3RhdGUudXNlLCBpbnB1dC5fcmVwb3J0ZXJTdGF0ZS5vYmopLl9kZWNvZGUoaW5wdXQpO1xuICBlbHNlXG4gICAgcmV0dXJuIGlucHV0LmVycm9yKCd1bmtub3duIHRhZzogJyArIHRhZyk7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fZ2V0VXNlID0gZnVuY3Rpb24gX2dldFVzZShlbnRpdHksIG9iaikge1xuXG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgLy8gQ3JlYXRlIGFsdGVyZWQgdXNlIGRlY29kZXIgaWYgaW1wbGljaXQgaXMgc2V0XG4gIHN0YXRlLnVzZURlY29kZXIgPSB0aGlzLl91c2UoZW50aXR5LCBvYmopO1xuICBhc3NlcnQoc3RhdGUudXNlRGVjb2Rlci5fYmFzZVN0YXRlLnBhcmVudCA9PT0gbnVsbCk7XG4gIHN0YXRlLnVzZURlY29kZXIgPSBzdGF0ZS51c2VEZWNvZGVyLl9iYXNlU3RhdGUuY2hpbGRyZW5bMF07XG4gIGlmIChzdGF0ZS5pbXBsaWNpdCAhPT0gc3RhdGUudXNlRGVjb2Rlci5fYmFzZVN0YXRlLmltcGxpY2l0KSB7XG4gICAgc3RhdGUudXNlRGVjb2RlciA9IHN0YXRlLnVzZURlY29kZXIuY2xvbmUoKTtcbiAgICBzdGF0ZS51c2VEZWNvZGVyLl9iYXNlU3RhdGUuaW1wbGljaXQgPSBzdGF0ZS5pbXBsaWNpdDtcbiAgfVxuICByZXR1cm4gc3RhdGUudXNlRGVjb2Rlcjtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9kZWNvZGVDaG9pY2UgPSBmdW5jdGlvbiBkZWNvZGVDaG9pY2UoaW5wdXQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICB2YXIgcmVzdWx0ID0gbnVsbDtcbiAgdmFyIG1hdGNoID0gZmFsc2U7XG5cbiAgT2JqZWN0LmtleXMoc3RhdGUuY2hvaWNlKS5zb21lKGZ1bmN0aW9uKGtleSkge1xuICAgIHZhciBzYXZlID0gaW5wdXQuc2F2ZSgpO1xuICAgIHZhciBub2RlID0gc3RhdGUuY2hvaWNlW2tleV07XG4gICAgdHJ5IHtcbiAgICAgIHZhciB2YWx1ZSA9IG5vZGUuX2RlY29kZShpbnB1dCk7XG4gICAgICBpZiAoaW5wdXQuaXNFcnJvcih2YWx1ZSkpXG4gICAgICAgIHJldHVybiBmYWxzZTtcblxuICAgICAgcmVzdWx0ID0geyB0eXBlOiBrZXksIHZhbHVlOiB2YWx1ZSB9O1xuICAgICAgbWF0Y2ggPSB0cnVlO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGlucHV0LnJlc3RvcmUoc2F2ZSk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9LCB0aGlzKTtcblxuICBpZiAoIW1hdGNoKVxuICAgIHJldHVybiBpbnB1dC5lcnJvcignQ2hvaWNlIG5vdCBtYXRjaGVkJyk7XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cbi8vXG4vLyBFbmNvZGluZ1xuLy9cblxuTm9kZS5wcm90b3R5cGUuX2NyZWF0ZUVuY29kZXJCdWZmZXIgPSBmdW5jdGlvbiBjcmVhdGVFbmNvZGVyQnVmZmVyKGRhdGEpIHtcbiAgcmV0dXJuIG5ldyBFbmNvZGVyQnVmZmVyKGRhdGEsIHRoaXMucmVwb3J0ZXIpO1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2VuY29kZSA9IGZ1bmN0aW9uIGVuY29kZShkYXRhLCByZXBvcnRlciwgcGFyZW50KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgaWYgKHN0YXRlWydkZWZhdWx0J10gIT09IG51bGwgJiYgc3RhdGVbJ2RlZmF1bHQnXSA9PT0gZGF0YSlcbiAgICByZXR1cm47XG5cbiAgdmFyIHJlc3VsdCA9IHRoaXMuX2VuY29kZVZhbHVlKGRhdGEsIHJlcG9ydGVyLCBwYXJlbnQpO1xuICBpZiAocmVzdWx0ID09PSB1bmRlZmluZWQpXG4gICAgcmV0dXJuO1xuXG4gIGlmICh0aGlzLl9za2lwRGVmYXVsdChyZXN1bHQsIHJlcG9ydGVyLCBwYXJlbnQpKVxuICAgIHJldHVybjtcblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2VuY29kZVZhbHVlID0gZnVuY3Rpb24gZW5jb2RlKGRhdGEsIHJlcG9ydGVyLCBwYXJlbnQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIC8vIERlY29kZSByb290IG5vZGVcbiAgaWYgKHN0YXRlLnBhcmVudCA9PT0gbnVsbClcbiAgICByZXR1cm4gc3RhdGUuY2hpbGRyZW5bMF0uX2VuY29kZShkYXRhLCByZXBvcnRlciB8fCBuZXcgUmVwb3J0ZXIoKSk7XG5cbiAgdmFyIHJlc3VsdCA9IG51bGw7XG5cbiAgLy8gU2V0IHJlcG9ydGVyIHRvIHNoYXJlIGl0IHdpdGggYSBjaGlsZCBjbGFzc1xuICB0aGlzLnJlcG9ydGVyID0gcmVwb3J0ZXI7XG5cbiAgLy8gQ2hlY2sgaWYgZGF0YSBpcyB0aGVyZVxuICBpZiAoc3RhdGUub3B0aW9uYWwgJiYgZGF0YSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgaWYgKHN0YXRlWydkZWZhdWx0J10gIT09IG51bGwpXG4gICAgICBkYXRhID0gc3RhdGVbJ2RlZmF1bHQnXVxuICAgIGVsc2VcbiAgICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIEVuY29kZSBjaGlsZHJlbiBmaXJzdFxuICB2YXIgY29udGVudCA9IG51bGw7XG4gIHZhciBwcmltaXRpdmUgPSBmYWxzZTtcbiAgaWYgKHN0YXRlLmFueSkge1xuICAgIC8vIEFueXRoaW5nIHRoYXQgd2FzIGdpdmVuIGlzIHRyYW5zbGF0ZWQgdG8gYnVmZmVyXG4gICAgcmVzdWx0ID0gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihkYXRhKTtcbiAgfSBlbHNlIGlmIChzdGF0ZS5jaG9pY2UpIHtcbiAgICByZXN1bHQgPSB0aGlzLl9lbmNvZGVDaG9pY2UoZGF0YSwgcmVwb3J0ZXIpO1xuICB9IGVsc2UgaWYgKHN0YXRlLmNvbnRhaW5zKSB7XG4gICAgY29udGVudCA9IHRoaXMuX2dldFVzZShzdGF0ZS5jb250YWlucywgcGFyZW50KS5fZW5jb2RlKGRhdGEsIHJlcG9ydGVyKTtcbiAgICBwcmltaXRpdmUgPSB0cnVlO1xuICB9IGVsc2UgaWYgKHN0YXRlLmNoaWxkcmVuKSB7XG4gICAgY29udGVudCA9IHN0YXRlLmNoaWxkcmVuLm1hcChmdW5jdGlvbihjaGlsZCkge1xuICAgICAgaWYgKGNoaWxkLl9iYXNlU3RhdGUudGFnID09PSAnbnVsbF8nKVxuICAgICAgICByZXR1cm4gY2hpbGQuX2VuY29kZShudWxsLCByZXBvcnRlciwgZGF0YSk7XG5cbiAgICAgIGlmIChjaGlsZC5fYmFzZVN0YXRlLmtleSA9PT0gbnVsbClcbiAgICAgICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdDaGlsZCBzaG91bGQgaGF2ZSBhIGtleScpO1xuICAgICAgdmFyIHByZXZLZXkgPSByZXBvcnRlci5lbnRlcktleShjaGlsZC5fYmFzZVN0YXRlLmtleSk7XG5cbiAgICAgIGlmICh0eXBlb2YgZGF0YSAhPT0gJ29iamVjdCcpXG4gICAgICAgIHJldHVybiByZXBvcnRlci5lcnJvcignQ2hpbGQgZXhwZWN0ZWQsIGJ1dCBpbnB1dCBpcyBub3Qgb2JqZWN0Jyk7XG5cbiAgICAgIHZhciByZXMgPSBjaGlsZC5fZW5jb2RlKGRhdGFbY2hpbGQuX2Jhc2VTdGF0ZS5rZXldLCByZXBvcnRlciwgZGF0YSk7XG4gICAgICByZXBvcnRlci5sZWF2ZUtleShwcmV2S2V5KTtcblxuICAgICAgcmV0dXJuIHJlcztcbiAgICB9LCB0aGlzKS5maWx0ZXIoZnVuY3Rpb24oY2hpbGQpIHtcbiAgICAgIHJldHVybiBjaGlsZDtcbiAgICB9KTtcbiAgICBjb250ZW50ID0gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihjb250ZW50KTtcbiAgfSBlbHNlIHtcbiAgICBpZiAoc3RhdGUudGFnID09PSAnc2Vxb2YnIHx8IHN0YXRlLnRhZyA9PT0gJ3NldG9mJykge1xuICAgICAgLy8gVE9ETyhpbmR1dG55KTogdGhpcyBzaG91bGQgYmUgdGhyb3duIG9uIERTTCBsZXZlbFxuICAgICAgaWYgKCEoc3RhdGUuYXJncyAmJiBzdGF0ZS5hcmdzLmxlbmd0aCA9PT0gMSkpXG4gICAgICAgIHJldHVybiByZXBvcnRlci5lcnJvcignVG9vIG1hbnkgYXJncyBmb3IgOiAnICsgc3RhdGUudGFnKTtcblxuICAgICAgaWYgKCFBcnJheS5pc0FycmF5KGRhdGEpKVxuICAgICAgICByZXR1cm4gcmVwb3J0ZXIuZXJyb3IoJ3NlcW9mL3NldG9mLCBidXQgZGF0YSBpcyBub3QgQXJyYXknKTtcblxuICAgICAgdmFyIGNoaWxkID0gdGhpcy5jbG9uZSgpO1xuICAgICAgY2hpbGQuX2Jhc2VTdGF0ZS5pbXBsaWNpdCA9IG51bGw7XG4gICAgICBjb250ZW50ID0gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihkYXRhLm1hcChmdW5jdGlvbihpdGVtKSB7XG4gICAgICAgIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICAgICAgICByZXR1cm4gdGhpcy5fZ2V0VXNlKHN0YXRlLmFyZ3NbMF0sIGRhdGEpLl9lbmNvZGUoaXRlbSwgcmVwb3J0ZXIpO1xuICAgICAgfSwgY2hpbGQpKTtcbiAgICB9IGVsc2UgaWYgKHN0YXRlLnVzZSAhPT0gbnVsbCkge1xuICAgICAgcmVzdWx0ID0gdGhpcy5fZ2V0VXNlKHN0YXRlLnVzZSwgcGFyZW50KS5fZW5jb2RlKGRhdGEsIHJlcG9ydGVyKTtcbiAgICB9IGVsc2Uge1xuICAgICAgY29udGVudCA9IHRoaXMuX2VuY29kZVByaW1pdGl2ZShzdGF0ZS50YWcsIGRhdGEpO1xuICAgICAgcHJpbWl0aXZlID0gdHJ1ZTtcbiAgICB9XG4gIH1cblxuICAvLyBFbmNvZGUgZGF0YSBpdHNlbGZcbiAgdmFyIHJlc3VsdDtcbiAgaWYgKCFzdGF0ZS5hbnkgJiYgc3RhdGUuY2hvaWNlID09PSBudWxsKSB7XG4gICAgdmFyIHRhZyA9IHN0YXRlLmltcGxpY2l0ICE9PSBudWxsID8gc3RhdGUuaW1wbGljaXQgOiBzdGF0ZS50YWc7XG4gICAgdmFyIGNscyA9IHN0YXRlLmltcGxpY2l0ID09PSBudWxsID8gJ3VuaXZlcnNhbCcgOiAnY29udGV4dCc7XG5cbiAgICBpZiAodGFnID09PSBudWxsKSB7XG4gICAgICBpZiAoc3RhdGUudXNlID09PSBudWxsKVxuICAgICAgICByZXBvcnRlci5lcnJvcignVGFnIGNvdWxkIGJlIG9tbWl0ZWQgb25seSBmb3IgLnVzZSgpJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChzdGF0ZS51c2UgPT09IG51bGwpXG4gICAgICAgIHJlc3VsdCA9IHRoaXMuX2VuY29kZUNvbXBvc2l0ZSh0YWcsIHByaW1pdGl2ZSwgY2xzLCBjb250ZW50KTtcbiAgICB9XG4gIH1cblxuICAvLyBXcmFwIGluIGV4cGxpY2l0XG4gIGlmIChzdGF0ZS5leHBsaWNpdCAhPT0gbnVsbClcbiAgICByZXN1bHQgPSB0aGlzLl9lbmNvZGVDb21wb3NpdGUoc3RhdGUuZXhwbGljaXQsIGZhbHNlLCAnY29udGV4dCcsIHJlc3VsdCk7XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9lbmNvZGVDaG9pY2UgPSBmdW5jdGlvbiBlbmNvZGVDaG9pY2UoZGF0YSwgcmVwb3J0ZXIpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIHZhciBub2RlID0gc3RhdGUuY2hvaWNlW2RhdGEudHlwZV07XG4gIGlmICghbm9kZSkge1xuICAgIGFzc2VydChcbiAgICAgICAgZmFsc2UsXG4gICAgICAgIGRhdGEudHlwZSArICcgbm90IGZvdW5kIGluICcgK1xuICAgICAgICAgICAgSlNPTi5zdHJpbmdpZnkoT2JqZWN0LmtleXMoc3RhdGUuY2hvaWNlKSkpO1xuICB9XG4gIHJldHVybiBub2RlLl9lbmNvZGUoZGF0YS52YWx1ZSwgcmVwb3J0ZXIpO1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2VuY29kZVByaW1pdGl2ZSA9IGZ1bmN0aW9uIGVuY29kZVByaW1pdGl2ZSh0YWcsIGRhdGEpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIGlmICgvc3RyJC8udGVzdCh0YWcpKVxuICAgIHJldHVybiB0aGlzLl9lbmNvZGVTdHIoZGF0YSwgdGFnKTtcbiAgZWxzZSBpZiAodGFnID09PSAnb2JqaWQnICYmIHN0YXRlLmFyZ3MpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZU9iamlkKGRhdGEsIHN0YXRlLnJldmVyc2VBcmdzWzBdLCBzdGF0ZS5hcmdzWzFdKTtcbiAgZWxzZSBpZiAodGFnID09PSAnb2JqaWQnKVxuICAgIHJldHVybiB0aGlzLl9lbmNvZGVPYmppZChkYXRhLCBudWxsLCBudWxsKTtcbiAgZWxzZSBpZiAodGFnID09PSAnZ2VudGltZScgfHwgdGFnID09PSAndXRjdGltZScpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZVRpbWUoZGF0YSwgdGFnKTtcbiAgZWxzZSBpZiAodGFnID09PSAnbnVsbF8nKVxuICAgIHJldHVybiB0aGlzLl9lbmNvZGVOdWxsKCk7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ2ludCcgfHwgdGFnID09PSAnZW51bScpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZUludChkYXRhLCBzdGF0ZS5hcmdzICYmIHN0YXRlLnJldmVyc2VBcmdzWzBdKTtcbiAgZWxzZSBpZiAodGFnID09PSAnYm9vbCcpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZUJvb2woZGF0YSk7XG4gIGVsc2VcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1Vuc3VwcG9ydGVkIHRhZzogJyArIHRhZyk7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5faXNOdW1zdHIgPSBmdW5jdGlvbiBpc051bXN0cihzdHIpIHtcbiAgcmV0dXJuIC9eWzAtOSBdKiQvLnRlc3Qoc3RyKTtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9pc1ByaW50c3RyID0gZnVuY3Rpb24gaXNQcmludHN0cihzdHIpIHtcbiAgcmV0dXJuIC9eW0EtWmEtejAtOSAnXFwoXFwpXFwrLFxcLVxcLlxcLzo9XFw/XSokLy50ZXN0KHN0cik7XG59O1xuIiwidmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcblxuZnVuY3Rpb24gUmVwb3J0ZXIob3B0aW9ucykge1xuICB0aGlzLl9yZXBvcnRlclN0YXRlID0ge1xuICAgIG9iajogbnVsbCxcbiAgICBwYXRoOiBbXSxcbiAgICBvcHRpb25zOiBvcHRpb25zIHx8IHt9LFxuICAgIGVycm9yczogW11cbiAgfTtcbn1cbmV4cG9ydHMuUmVwb3J0ZXIgPSBSZXBvcnRlcjtcblxuUmVwb3J0ZXIucHJvdG90eXBlLmlzRXJyb3IgPSBmdW5jdGlvbiBpc0Vycm9yKG9iaikge1xuICByZXR1cm4gb2JqIGluc3RhbmNlb2YgUmVwb3J0ZXJFcnJvcjtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5zYXZlID0gZnVuY3Rpb24gc2F2ZSgpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fcmVwb3J0ZXJTdGF0ZTtcblxuICByZXR1cm4geyBvYmo6IHN0YXRlLm9iaiwgcGF0aExlbjogc3RhdGUucGF0aC5sZW5ndGggfTtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5yZXN0b3JlID0gZnVuY3Rpb24gcmVzdG9yZShkYXRhKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgc3RhdGUub2JqID0gZGF0YS5vYmo7XG4gIHN0YXRlLnBhdGggPSBzdGF0ZS5wYXRoLnNsaWNlKDAsIGRhdGEucGF0aExlbik7XG59O1xuXG5SZXBvcnRlci5wcm90b3R5cGUuZW50ZXJLZXkgPSBmdW5jdGlvbiBlbnRlcktleShrZXkpIHtcbiAgcmV0dXJuIHRoaXMuX3JlcG9ydGVyU3RhdGUucGF0aC5wdXNoKGtleSk7XG59O1xuXG5SZXBvcnRlci5wcm90b3R5cGUubGVhdmVLZXkgPSBmdW5jdGlvbiBsZWF2ZUtleShpbmRleCwga2V5LCB2YWx1ZSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9yZXBvcnRlclN0YXRlO1xuXG4gIHN0YXRlLnBhdGggPSBzdGF0ZS5wYXRoLnNsaWNlKDAsIGluZGV4IC0gMSk7XG4gIGlmIChzdGF0ZS5vYmogIT09IG51bGwpXG4gICAgc3RhdGUub2JqW2tleV0gPSB2YWx1ZTtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5lbnRlck9iamVjdCA9IGZ1bmN0aW9uIGVudGVyT2JqZWN0KCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9yZXBvcnRlclN0YXRlO1xuXG4gIHZhciBwcmV2ID0gc3RhdGUub2JqO1xuICBzdGF0ZS5vYmogPSB7fTtcbiAgcmV0dXJuIHByZXY7XG59O1xuXG5SZXBvcnRlci5wcm90b3R5cGUubGVhdmVPYmplY3QgPSBmdW5jdGlvbiBsZWF2ZU9iamVjdChwcmV2KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgdmFyIG5vdyA9IHN0YXRlLm9iajtcbiAgc3RhdGUub2JqID0gcHJldjtcbiAgcmV0dXJuIG5vdztcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5lcnJvciA9IGZ1bmN0aW9uIGVycm9yKG1zZykge1xuICB2YXIgZXJyO1xuICB2YXIgc3RhdGUgPSB0aGlzLl9yZXBvcnRlclN0YXRlO1xuXG4gIHZhciBpbmhlcml0ZWQgPSBtc2cgaW5zdGFuY2VvZiBSZXBvcnRlckVycm9yO1xuICBpZiAoaW5oZXJpdGVkKSB7XG4gICAgZXJyID0gbXNnO1xuICB9IGVsc2Uge1xuICAgIGVyciA9IG5ldyBSZXBvcnRlckVycm9yKHN0YXRlLnBhdGgubWFwKGZ1bmN0aW9uKGVsZW0pIHtcbiAgICAgIHJldHVybiAnWycgKyBKU09OLnN0cmluZ2lmeShlbGVtKSArICddJztcbiAgICB9KS5qb2luKCcnKSwgbXNnLm1lc3NhZ2UgfHwgbXNnLCBtc2cuc3RhY2spO1xuICB9XG5cbiAgaWYgKCFzdGF0ZS5vcHRpb25zLnBhcnRpYWwpXG4gICAgdGhyb3cgZXJyO1xuXG4gIGlmICghaW5oZXJpdGVkKVxuICAgIHN0YXRlLmVycm9ycy5wdXNoKGVycik7XG5cbiAgcmV0dXJuIGVycjtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS53cmFwUmVzdWx0ID0gZnVuY3Rpb24gd3JhcFJlc3VsdChyZXN1bHQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fcmVwb3J0ZXJTdGF0ZTtcbiAgaWYgKCFzdGF0ZS5vcHRpb25zLnBhcnRpYWwpXG4gICAgcmV0dXJuIHJlc3VsdDtcblxuICByZXR1cm4ge1xuICAgIHJlc3VsdDogdGhpcy5pc0Vycm9yKHJlc3VsdCkgPyBudWxsIDogcmVzdWx0LFxuICAgIGVycm9yczogc3RhdGUuZXJyb3JzXG4gIH07XG59O1xuXG5mdW5jdGlvbiBSZXBvcnRlckVycm9yKHBhdGgsIG1zZykge1xuICB0aGlzLnBhdGggPSBwYXRoO1xuICB0aGlzLnJldGhyb3cobXNnKTtcbn07XG5pbmhlcml0cyhSZXBvcnRlckVycm9yLCBFcnJvcik7XG5cblJlcG9ydGVyRXJyb3IucHJvdG90eXBlLnJldGhyb3cgPSBmdW5jdGlvbiByZXRocm93KG1zZykge1xuICB0aGlzLm1lc3NhZ2UgPSBtc2cgKyAnIGF0OiAnICsgKHRoaXMucGF0aCB8fCAnKHNoYWxsb3cpJyk7XG4gIEVycm9yLmNhcHR1cmVTdGFja1RyYWNlKHRoaXMsIFJlcG9ydGVyRXJyb3IpO1xuXG4gIHJldHVybiB0aGlzO1xufTtcbiIsInZhciBjb25zdGFudHMgPSByZXF1aXJlKCcuLi9jb25zdGFudHMnKTtcblxuZXhwb3J0cy50YWdDbGFzcyA9IHtcbiAgMDogJ3VuaXZlcnNhbCcsXG4gIDE6ICdhcHBsaWNhdGlvbicsXG4gIDI6ICdjb250ZXh0JyxcbiAgMzogJ3ByaXZhdGUnXG59O1xuZXhwb3J0cy50YWdDbGFzc0J5TmFtZSA9IGNvbnN0YW50cy5fcmV2ZXJzZShleHBvcnRzLnRhZ0NsYXNzKTtcblxuZXhwb3J0cy50YWcgPSB7XG4gIDB4MDA6ICdlbmQnLFxuICAweDAxOiAnYm9vbCcsXG4gIDB4MDI6ICdpbnQnLFxuICAweDAzOiAnYml0c3RyJyxcbiAgMHgwNDogJ29jdHN0cicsXG4gIDB4MDU6ICdudWxsXycsXG4gIDB4MDY6ICdvYmppZCcsXG4gIDB4MDc6ICdvYmpEZXNjJyxcbiAgMHgwODogJ2V4dGVybmFsJyxcbiAgMHgwOTogJ3JlYWwnLFxuICAweDBhOiAnZW51bScsXG4gIDB4MGI6ICdlbWJlZCcsXG4gIDB4MGM6ICd1dGY4c3RyJyxcbiAgMHgwZDogJ3JlbGF0aXZlT2lkJyxcbiAgMHgxMDogJ3NlcScsXG4gIDB4MTE6ICdzZXQnLFxuICAweDEyOiAnbnVtc3RyJyxcbiAgMHgxMzogJ3ByaW50c3RyJyxcbiAgMHgxNDogJ3Q2MXN0cicsXG4gIDB4MTU6ICd2aWRlb3N0cicsXG4gIDB4MTY6ICdpYTVzdHInLFxuICAweDE3OiAndXRjdGltZScsXG4gIDB4MTg6ICdnZW50aW1lJyxcbiAgMHgxOTogJ2dyYXBoc3RyJyxcbiAgMHgxYTogJ2lzbzY0NnN0cicsXG4gIDB4MWI6ICdnZW5zdHInLFxuICAweDFjOiAndW5pc3RyJyxcbiAgMHgxZDogJ2NoYXJzdHInLFxuICAweDFlOiAnYm1wc3RyJ1xufTtcbmV4cG9ydHMudGFnQnlOYW1lID0gY29uc3RhbnRzLl9yZXZlcnNlKGV4cG9ydHMudGFnKTtcbiIsInZhciBjb25zdGFudHMgPSBleHBvcnRzO1xuXG4vLyBIZWxwZXJcbmNvbnN0YW50cy5fcmV2ZXJzZSA9IGZ1bmN0aW9uIHJldmVyc2UobWFwKSB7XG4gIHZhciByZXMgPSB7fTtcblxuICBPYmplY3Qua2V5cyhtYXApLmZvckVhY2goZnVuY3Rpb24oa2V5KSB7XG4gICAgLy8gQ29udmVydCBrZXkgdG8gaW50ZWdlciBpZiBpdCBpcyBzdHJpbmdpZmllZFxuICAgIGlmICgoa2V5IHwgMCkgPT0ga2V5KVxuICAgICAga2V5ID0ga2V5IHwgMDtcblxuICAgIHZhciB2YWx1ZSA9IG1hcFtrZXldO1xuICAgIHJlc1t2YWx1ZV0gPSBrZXk7XG4gIH0pO1xuXG4gIHJldHVybiByZXM7XG59O1xuXG5jb25zdGFudHMuZGVyID0gcmVxdWlyZSgnLi9kZXInKTtcbiIsInZhciBpbmhlcml0cyA9IHJlcXVpcmUoJ2luaGVyaXRzJyk7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnLi4vLi4vYXNuMScpO1xudmFyIGJhc2UgPSBhc24xLmJhc2U7XG52YXIgYmlnbnVtID0gYXNuMS5iaWdudW07XG5cbi8vIEltcG9ydCBERVIgY29uc3RhbnRzXG52YXIgZGVyID0gYXNuMS5jb25zdGFudHMuZGVyO1xuXG5mdW5jdGlvbiBERVJEZWNvZGVyKGVudGl0eSkge1xuICB0aGlzLmVuYyA9ICdkZXInO1xuICB0aGlzLm5hbWUgPSBlbnRpdHkubmFtZTtcbiAgdGhpcy5lbnRpdHkgPSBlbnRpdHk7XG5cbiAgLy8gQ29uc3RydWN0IGJhc2UgdHJlZVxuICB0aGlzLnRyZWUgPSBuZXcgREVSTm9kZSgpO1xuICB0aGlzLnRyZWUuX2luaXQoZW50aXR5LmJvZHkpO1xufTtcbm1vZHVsZS5leHBvcnRzID0gREVSRGVjb2RlcjtcblxuREVSRGVjb2Rlci5wcm90b3R5cGUuZGVjb2RlID0gZnVuY3Rpb24gZGVjb2RlKGRhdGEsIG9wdGlvbnMpIHtcbiAgaWYgKCEoZGF0YSBpbnN0YW5jZW9mIGJhc2UuRGVjb2RlckJ1ZmZlcikpXG4gICAgZGF0YSA9IG5ldyBiYXNlLkRlY29kZXJCdWZmZXIoZGF0YSwgb3B0aW9ucyk7XG5cbiAgcmV0dXJuIHRoaXMudHJlZS5fZGVjb2RlKGRhdGEsIG9wdGlvbnMpO1xufTtcblxuLy8gVHJlZSBtZXRob2RzXG5cbmZ1bmN0aW9uIERFUk5vZGUocGFyZW50KSB7XG4gIGJhc2UuTm9kZS5jYWxsKHRoaXMsICdkZXInLCBwYXJlbnQpO1xufVxuaW5oZXJpdHMoREVSTm9kZSwgYmFzZS5Ob2RlKTtcblxuREVSTm9kZS5wcm90b3R5cGUuX3BlZWtUYWcgPSBmdW5jdGlvbiBwZWVrVGFnKGJ1ZmZlciwgdGFnLCBhbnkpIHtcbiAgaWYgKGJ1ZmZlci5pc0VtcHR5KCkpXG4gICAgcmV0dXJuIGZhbHNlO1xuXG4gIHZhciBzdGF0ZSA9IGJ1ZmZlci5zYXZlKCk7XG4gIHZhciBkZWNvZGVkVGFnID0gZGVyRGVjb2RlVGFnKGJ1ZmZlciwgJ0ZhaWxlZCB0byBwZWVrIHRhZzogXCInICsgdGFnICsgJ1wiJyk7XG4gIGlmIChidWZmZXIuaXNFcnJvcihkZWNvZGVkVGFnKSlcbiAgICByZXR1cm4gZGVjb2RlZFRhZztcblxuICBidWZmZXIucmVzdG9yZShzdGF0ZSk7XG5cbiAgcmV0dXJuIGRlY29kZWRUYWcudGFnID09PSB0YWcgfHwgZGVjb2RlZFRhZy50YWdTdHIgPT09IHRhZyB8fFxuICAgIChkZWNvZGVkVGFnLnRhZ1N0ciArICdvZicpID09PSB0YWcgfHwgYW55O1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZVRhZyA9IGZ1bmN0aW9uIGRlY29kZVRhZyhidWZmZXIsIHRhZywgYW55KSB7XG4gIHZhciBkZWNvZGVkVGFnID0gZGVyRGVjb2RlVGFnKGJ1ZmZlcixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ0ZhaWxlZCB0byBkZWNvZGUgdGFnIG9mIFwiJyArIHRhZyArICdcIicpO1xuICBpZiAoYnVmZmVyLmlzRXJyb3IoZGVjb2RlZFRhZykpXG4gICAgcmV0dXJuIGRlY29kZWRUYWc7XG5cbiAgdmFyIGxlbiA9IGRlckRlY29kZUxlbihidWZmZXIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgZGVjb2RlZFRhZy5wcmltaXRpdmUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgJ0ZhaWxlZCB0byBnZXQgbGVuZ3RoIG9mIFwiJyArIHRhZyArICdcIicpO1xuXG4gIC8vIEZhaWx1cmVcbiAgaWYgKGJ1ZmZlci5pc0Vycm9yKGxlbikpXG4gICAgcmV0dXJuIGxlbjtcblxuICBpZiAoIWFueSAmJlxuICAgICAgZGVjb2RlZFRhZy50YWcgIT09IHRhZyAmJlxuICAgICAgZGVjb2RlZFRhZy50YWdTdHIgIT09IHRhZyAmJlxuICAgICAgZGVjb2RlZFRhZy50YWdTdHIgKyAnb2YnICE9PSB0YWcpIHtcbiAgICByZXR1cm4gYnVmZmVyLmVycm9yKCdGYWlsZWQgdG8gbWF0Y2ggdGFnOiBcIicgKyB0YWcgKyAnXCInKTtcbiAgfVxuXG4gIGlmIChkZWNvZGVkVGFnLnByaW1pdGl2ZSB8fCBsZW4gIT09IG51bGwpXG4gICAgcmV0dXJuIGJ1ZmZlci5za2lwKGxlbiwgJ0ZhaWxlZCB0byBtYXRjaCBib2R5IG9mOiBcIicgKyB0YWcgKyAnXCInKTtcblxuICAvLyBJbmRlZmluaXRlIGxlbmd0aC4uLiBmaW5kIEVORCB0YWdcbiAgdmFyIHN0YXRlID0gYnVmZmVyLnNhdmUoKTtcbiAgdmFyIHJlcyA9IHRoaXMuX3NraXBVbnRpbEVuZChcbiAgICAgIGJ1ZmZlcixcbiAgICAgICdGYWlsZWQgdG8gc2tpcCBpbmRlZmluaXRlIGxlbmd0aCBib2R5OiBcIicgKyB0aGlzLnRhZyArICdcIicpO1xuICBpZiAoYnVmZmVyLmlzRXJyb3IocmVzKSlcbiAgICByZXR1cm4gcmVzO1xuXG4gIGxlbiA9IGJ1ZmZlci5vZmZzZXQgLSBzdGF0ZS5vZmZzZXQ7XG4gIGJ1ZmZlci5yZXN0b3JlKHN0YXRlKTtcbiAgcmV0dXJuIGJ1ZmZlci5za2lwKGxlbiwgJ0ZhaWxlZCB0byBtYXRjaCBib2R5IG9mOiBcIicgKyB0YWcgKyAnXCInKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9za2lwVW50aWxFbmQgPSBmdW5jdGlvbiBza2lwVW50aWxFbmQoYnVmZmVyLCBmYWlsKSB7XG4gIHdoaWxlICh0cnVlKSB7XG4gICAgdmFyIHRhZyA9IGRlckRlY29kZVRhZyhidWZmZXIsIGZhaWwpO1xuICAgIGlmIChidWZmZXIuaXNFcnJvcih0YWcpKVxuICAgICAgcmV0dXJuIHRhZztcbiAgICB2YXIgbGVuID0gZGVyRGVjb2RlTGVuKGJ1ZmZlciwgdGFnLnByaW1pdGl2ZSwgZmFpbCk7XG4gICAgaWYgKGJ1ZmZlci5pc0Vycm9yKGxlbikpXG4gICAgICByZXR1cm4gbGVuO1xuXG4gICAgdmFyIHJlcztcbiAgICBpZiAodGFnLnByaW1pdGl2ZSB8fCBsZW4gIT09IG51bGwpXG4gICAgICByZXMgPSBidWZmZXIuc2tpcChsZW4pXG4gICAgZWxzZVxuICAgICAgcmVzID0gdGhpcy5fc2tpcFVudGlsRW5kKGJ1ZmZlciwgZmFpbCk7XG5cbiAgICAvLyBGYWlsdXJlXG4gICAgaWYgKGJ1ZmZlci5pc0Vycm9yKHJlcykpXG4gICAgICByZXR1cm4gcmVzO1xuXG4gICAgaWYgKHRhZy50YWdTdHIgPT09ICdlbmQnKVxuICAgICAgYnJlYWs7XG4gIH1cbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9kZWNvZGVMaXN0ID0gZnVuY3Rpb24gZGVjb2RlTGlzdChidWZmZXIsIHRhZywgZGVjb2Rlcikge1xuICB2YXIgcmVzdWx0ID0gW107XG4gIHdoaWxlICghYnVmZmVyLmlzRW1wdHkoKSkge1xuICAgIHZhciBwb3NzaWJsZUVuZCA9IHRoaXMuX3BlZWtUYWcoYnVmZmVyLCAnZW5kJyk7XG4gICAgaWYgKGJ1ZmZlci5pc0Vycm9yKHBvc3NpYmxlRW5kKSlcbiAgICAgIHJldHVybiBwb3NzaWJsZUVuZDtcblxuICAgIHZhciByZXMgPSBkZWNvZGVyLmRlY29kZShidWZmZXIsICdkZXInKTtcbiAgICBpZiAoYnVmZmVyLmlzRXJyb3IocmVzKSAmJiBwb3NzaWJsZUVuZClcbiAgICAgIGJyZWFrO1xuICAgIHJlc3VsdC5wdXNoKHJlcyk7XG4gIH1cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9kZWNvZGVTdHIgPSBmdW5jdGlvbiBkZWNvZGVTdHIoYnVmZmVyLCB0YWcpIHtcbiAgaWYgKHRhZyA9PT0gJ2JpdHN0cicpIHtcbiAgICB2YXIgdW51c2VkID0gYnVmZmVyLnJlYWRVSW50OCgpO1xuICAgIGlmIChidWZmZXIuaXNFcnJvcih1bnVzZWQpKVxuICAgICAgcmV0dXJuIHVudXNlZDtcbiAgICByZXR1cm4geyB1bnVzZWQ6IHVudXNlZCwgZGF0YTogYnVmZmVyLnJhdygpIH07XG4gIH0gZWxzZSBpZiAodGFnID09PSAnYm1wc3RyJykge1xuICAgIHZhciByYXcgPSBidWZmZXIucmF3KCk7XG4gICAgaWYgKHJhdy5sZW5ndGggJSAyID09PSAxKVxuICAgICAgcmV0dXJuIGJ1ZmZlci5lcnJvcignRGVjb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6IGJtcHN0ciBsZW5ndGggbWlzbWF0Y2gnKTtcblxuICAgIHZhciBzdHIgPSAnJztcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJhdy5sZW5ndGggLyAyOyBpKyspIHtcbiAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHJhdy5yZWFkVUludDE2QkUoaSAqIDIpKTtcbiAgICB9XG4gICAgcmV0dXJuIHN0cjtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdudW1zdHInKSB7XG4gICAgdmFyIG51bXN0ciA9IGJ1ZmZlci5yYXcoKS50b1N0cmluZygnYXNjaWknKTtcbiAgICBpZiAoIXRoaXMuX2lzTnVtc3RyKG51bXN0cikpIHtcbiAgICAgIHJldHVybiBidWZmZXIuZXJyb3IoJ0RlY29kaW5nIG9mIHN0cmluZyB0eXBlOiAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgJ251bXN0ciB1bnN1cHBvcnRlZCBjaGFyYWN0ZXJzJyk7XG4gICAgfVxuICAgIHJldHVybiBudW1zdHI7XG4gIH0gZWxzZSBpZiAodGFnID09PSAnb2N0c3RyJykge1xuICAgIHJldHVybiBidWZmZXIucmF3KCk7XG4gIH0gZWxzZSBpZiAodGFnID09PSAncHJpbnRzdHInKSB7XG4gICAgdmFyIHByaW50c3RyID0gYnVmZmVyLnJhdygpLnRvU3RyaW5nKCdhc2NpaScpO1xuICAgIGlmICghdGhpcy5faXNQcmludHN0cihwcmludHN0cikpIHtcbiAgICAgIHJldHVybiBidWZmZXIuZXJyb3IoJ0RlY29kaW5nIG9mIHN0cmluZyB0eXBlOiAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgJ3ByaW50c3RyIHVuc3VwcG9ydGVkIGNoYXJhY3RlcnMnKTtcbiAgICB9XG4gICAgcmV0dXJuIHByaW50c3RyO1xuICB9IGVsc2UgaWYgKC9zdHIkLy50ZXN0KHRhZykpIHtcbiAgICByZXR1cm4gYnVmZmVyLnJhdygpLnRvU3RyaW5nKCk7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIGJ1ZmZlci5lcnJvcignRGVjb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6ICcgKyB0YWcgKyAnIHVuc3VwcG9ydGVkJyk7XG4gIH1cbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9kZWNvZGVPYmppZCA9IGZ1bmN0aW9uIGRlY29kZU9iamlkKGJ1ZmZlciwgdmFsdWVzLCByZWxhdGl2ZSkge1xuICB2YXIgcmVzdWx0O1xuICB2YXIgaWRlbnRpZmllcnMgPSBbXTtcbiAgdmFyIGlkZW50ID0gMDtcbiAgd2hpbGUgKCFidWZmZXIuaXNFbXB0eSgpKSB7XG4gICAgdmFyIHN1YmlkZW50ID0gYnVmZmVyLnJlYWRVSW50OCgpO1xuICAgIGlkZW50IDw8PSA3O1xuICAgIGlkZW50IHw9IHN1YmlkZW50ICYgMHg3ZjtcbiAgICBpZiAoKHN1YmlkZW50ICYgMHg4MCkgPT09IDApIHtcbiAgICAgIGlkZW50aWZpZXJzLnB1c2goaWRlbnQpO1xuICAgICAgaWRlbnQgPSAwO1xuICAgIH1cbiAgfVxuICBpZiAoc3ViaWRlbnQgJiAweDgwKVxuICAgIGlkZW50aWZpZXJzLnB1c2goaWRlbnQpO1xuXG4gIHZhciBmaXJzdCA9IChpZGVudGlmaWVyc1swXSAvIDQwKSB8IDA7XG4gIHZhciBzZWNvbmQgPSBpZGVudGlmaWVyc1swXSAlIDQwO1xuXG4gIGlmIChyZWxhdGl2ZSlcbiAgICByZXN1bHQgPSBpZGVudGlmaWVycztcbiAgZWxzZVxuICAgIHJlc3VsdCA9IFtmaXJzdCwgc2Vjb25kXS5jb25jYXQoaWRlbnRpZmllcnMuc2xpY2UoMSkpO1xuXG4gIGlmICh2YWx1ZXMpIHtcbiAgICB2YXIgdG1wID0gdmFsdWVzW3Jlc3VsdC5qb2luKCcgJyldO1xuICAgIGlmICh0bXAgPT09IHVuZGVmaW5lZClcbiAgICAgIHRtcCA9IHZhbHVlc1tyZXN1bHQuam9pbignLicpXTtcbiAgICBpZiAodG1wICE9PSB1bmRlZmluZWQpXG4gICAgICByZXN1bHQgPSB0bXA7XG4gIH1cblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZVRpbWUgPSBmdW5jdGlvbiBkZWNvZGVUaW1lKGJ1ZmZlciwgdGFnKSB7XG4gIHZhciBzdHIgPSBidWZmZXIucmF3KCkudG9TdHJpbmcoKTtcbiAgaWYgKHRhZyA9PT0gJ2dlbnRpbWUnKSB7XG4gICAgdmFyIHllYXIgPSBzdHIuc2xpY2UoMCwgNCkgfCAwO1xuICAgIHZhciBtb24gPSBzdHIuc2xpY2UoNCwgNikgfCAwO1xuICAgIHZhciBkYXkgPSBzdHIuc2xpY2UoNiwgOCkgfCAwO1xuICAgIHZhciBob3VyID0gc3RyLnNsaWNlKDgsIDEwKSB8IDA7XG4gICAgdmFyIG1pbiA9IHN0ci5zbGljZSgxMCwgMTIpIHwgMDtcbiAgICB2YXIgc2VjID0gc3RyLnNsaWNlKDEyLCAxNCkgfCAwO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ3V0Y3RpbWUnKSB7XG4gICAgdmFyIHllYXIgPSBzdHIuc2xpY2UoMCwgMikgfCAwO1xuICAgIHZhciBtb24gPSBzdHIuc2xpY2UoMiwgNCkgfCAwO1xuICAgIHZhciBkYXkgPSBzdHIuc2xpY2UoNCwgNikgfCAwO1xuICAgIHZhciBob3VyID0gc3RyLnNsaWNlKDYsIDgpIHwgMDtcbiAgICB2YXIgbWluID0gc3RyLnNsaWNlKDgsIDEwKSB8IDA7XG4gICAgdmFyIHNlYyA9IHN0ci5zbGljZSgxMCwgMTIpIHwgMDtcbiAgICBpZiAoeWVhciA8IDcwKVxuICAgICAgeWVhciA9IDIwMDAgKyB5ZWFyO1xuICAgIGVsc2VcbiAgICAgIHllYXIgPSAxOTAwICsgeWVhcjtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gYnVmZmVyLmVycm9yKCdEZWNvZGluZyAnICsgdGFnICsgJyB0aW1lIGlzIG5vdCBzdXBwb3J0ZWQgeWV0Jyk7XG4gIH1cblxuICByZXR1cm4gRGF0ZS5VVEMoeWVhciwgbW9uIC0gMSwgZGF5LCBob3VyLCBtaW4sIHNlYywgMCk7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZGVjb2RlTnVsbCA9IGZ1bmN0aW9uIGRlY29kZU51bGwoYnVmZmVyKSB7XG4gIHJldHVybiBudWxsO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZUJvb2wgPSBmdW5jdGlvbiBkZWNvZGVCb29sKGJ1ZmZlcikge1xuICB2YXIgcmVzID0gYnVmZmVyLnJlYWRVSW50OCgpO1xuICBpZiAoYnVmZmVyLmlzRXJyb3IocmVzKSlcbiAgICByZXR1cm4gcmVzO1xuICBlbHNlXG4gICAgcmV0dXJuIHJlcyAhPT0gMDtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9kZWNvZGVJbnQgPSBmdW5jdGlvbiBkZWNvZGVJbnQoYnVmZmVyLCB2YWx1ZXMpIHtcbiAgLy8gQmlnaW50LCByZXR1cm4gYXMgaXQgaXMgKGFzc3VtZSBiaWcgZW5kaWFuKVxuICB2YXIgcmF3ID0gYnVmZmVyLnJhdygpO1xuICB2YXIgcmVzID0gbmV3IGJpZ251bShyYXcpO1xuXG4gIGlmICh2YWx1ZXMpXG4gICAgcmVzID0gdmFsdWVzW3Jlcy50b1N0cmluZygxMCldIHx8IHJlcztcblxuICByZXR1cm4gcmVzO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX3VzZSA9IGZ1bmN0aW9uIHVzZShlbnRpdHksIG9iaikge1xuICBpZiAodHlwZW9mIGVudGl0eSA9PT0gJ2Z1bmN0aW9uJylcbiAgICBlbnRpdHkgPSBlbnRpdHkob2JqKTtcbiAgcmV0dXJuIGVudGl0eS5fZ2V0RGVjb2RlcignZGVyJykudHJlZTtcbn07XG5cbi8vIFV0aWxpdHkgbWV0aG9kc1xuXG5mdW5jdGlvbiBkZXJEZWNvZGVUYWcoYnVmLCBmYWlsKSB7XG4gIHZhciB0YWcgPSBidWYucmVhZFVJbnQ4KGZhaWwpO1xuICBpZiAoYnVmLmlzRXJyb3IodGFnKSlcbiAgICByZXR1cm4gdGFnO1xuXG4gIHZhciBjbHMgPSBkZXIudGFnQ2xhc3NbdGFnID4+IDZdO1xuICB2YXIgcHJpbWl0aXZlID0gKHRhZyAmIDB4MjApID09PSAwO1xuXG4gIC8vIE11bHRpLW9jdGV0IHRhZyAtIGxvYWRcbiAgaWYgKCh0YWcgJiAweDFmKSA9PT0gMHgxZikge1xuICAgIHZhciBvY3QgPSB0YWc7XG4gICAgdGFnID0gMDtcbiAgICB3aGlsZSAoKG9jdCAmIDB4ODApID09PSAweDgwKSB7XG4gICAgICBvY3QgPSBidWYucmVhZFVJbnQ4KGZhaWwpO1xuICAgICAgaWYgKGJ1Zi5pc0Vycm9yKG9jdCkpXG4gICAgICAgIHJldHVybiBvY3Q7XG5cbiAgICAgIHRhZyA8PD0gNztcbiAgICAgIHRhZyB8PSBvY3QgJiAweDdmO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICB0YWcgJj0gMHgxZjtcbiAgfVxuICB2YXIgdGFnU3RyID0gZGVyLnRhZ1t0YWddO1xuXG4gIHJldHVybiB7XG4gICAgY2xzOiBjbHMsXG4gICAgcHJpbWl0aXZlOiBwcmltaXRpdmUsXG4gICAgdGFnOiB0YWcsXG4gICAgdGFnU3RyOiB0YWdTdHJcbiAgfTtcbn1cblxuZnVuY3Rpb24gZGVyRGVjb2RlTGVuKGJ1ZiwgcHJpbWl0aXZlLCBmYWlsKSB7XG4gIHZhciBsZW4gPSBidWYucmVhZFVJbnQ4KGZhaWwpO1xuICBpZiAoYnVmLmlzRXJyb3IobGVuKSlcbiAgICByZXR1cm4gbGVuO1xuXG4gIC8vIEluZGVmaW5pdGUgZm9ybVxuICBpZiAoIXByaW1pdGl2ZSAmJiBsZW4gPT09IDB4ODApXG4gICAgcmV0dXJuIG51bGw7XG5cbiAgLy8gRGVmaW5pdGUgZm9ybVxuICBpZiAoKGxlbiAmIDB4ODApID09PSAwKSB7XG4gICAgLy8gU2hvcnQgZm9ybVxuICAgIHJldHVybiBsZW47XG4gIH1cblxuICAvLyBMb25nIGZvcm1cbiAgdmFyIG51bSA9IGxlbiAmIDB4N2Y7XG4gIGlmIChudW0gPj0gNClcbiAgICByZXR1cm4gYnVmLmVycm9yKCdsZW5ndGggb2N0ZWN0IGlzIHRvbyBsb25nJyk7XG5cbiAgbGVuID0gMDtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBudW07IGkrKykge1xuICAgIGxlbiA8PD0gODtcbiAgICB2YXIgaiA9IGJ1Zi5yZWFkVUludDgoZmFpbCk7XG4gICAgaWYgKGJ1Zi5pc0Vycm9yKGopKVxuICAgICAgcmV0dXJuIGo7XG4gICAgbGVuIHw9IGo7XG4gIH1cblxuICByZXR1cm4gbGVuO1xufVxuIiwidmFyIGRlY29kZXJzID0gZXhwb3J0cztcblxuZGVjb2RlcnMuZGVyID0gcmVxdWlyZSgnLi9kZXInKTtcbmRlY29kZXJzLnBlbSA9IHJlcXVpcmUoJy4vcGVtJyk7XG4iLCJ2YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIEJ1ZmZlciA9IHJlcXVpcmUoJ2J1ZmZlcicpLkJ1ZmZlcjtcblxudmFyIERFUkRlY29kZXIgPSByZXF1aXJlKCcuL2RlcicpO1xuXG5mdW5jdGlvbiBQRU1EZWNvZGVyKGVudGl0eSkge1xuICBERVJEZWNvZGVyLmNhbGwodGhpcywgZW50aXR5KTtcbiAgdGhpcy5lbmMgPSAncGVtJztcbn07XG5pbmhlcml0cyhQRU1EZWNvZGVyLCBERVJEZWNvZGVyKTtcbm1vZHVsZS5leHBvcnRzID0gUEVNRGVjb2RlcjtcblxuUEVNRGVjb2Rlci5wcm90b3R5cGUuZGVjb2RlID0gZnVuY3Rpb24gZGVjb2RlKGRhdGEsIG9wdGlvbnMpIHtcbiAgdmFyIGxpbmVzID0gZGF0YS50b1N0cmluZygpLnNwbGl0KC9bXFxyXFxuXSsvZyk7XG5cbiAgdmFyIGxhYmVsID0gb3B0aW9ucy5sYWJlbC50b1VwcGVyQ2FzZSgpO1xuXG4gIHZhciByZSA9IC9eLS0tLS0oQkVHSU58RU5EKSAoW14tXSspLS0tLS0kLztcbiAgdmFyIHN0YXJ0ID0gLTE7XG4gIHZhciBlbmQgPSAtMTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgIHZhciBtYXRjaCA9IGxpbmVzW2ldLm1hdGNoKHJlKTtcbiAgICBpZiAobWF0Y2ggPT09IG51bGwpXG4gICAgICBjb250aW51ZTtcblxuICAgIGlmIChtYXRjaFsyXSAhPT0gbGFiZWwpXG4gICAgICBjb250aW51ZTtcblxuICAgIGlmIChzdGFydCA9PT0gLTEpIHtcbiAgICAgIGlmIChtYXRjaFsxXSAhPT0gJ0JFR0lOJylcbiAgICAgICAgYnJlYWs7XG4gICAgICBzdGFydCA9IGk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChtYXRjaFsxXSAhPT0gJ0VORCcpXG4gICAgICAgIGJyZWFrO1xuICAgICAgZW5kID0gaTtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxuICBpZiAoc3RhcnQgPT09IC0xIHx8IGVuZCA9PT0gLTEpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdQRU0gc2VjdGlvbiBub3QgZm91bmQgZm9yOiAnICsgbGFiZWwpO1xuXG4gIHZhciBiYXNlNjQgPSBsaW5lcy5zbGljZShzdGFydCArIDEsIGVuZCkuam9pbignJyk7XG4gIC8vIFJlbW92ZSBleGNlc3NpdmUgc3ltYm9sc1xuICBiYXNlNjQucmVwbGFjZSgvW15hLXowLTlcXCtcXC89XSsvZ2ksICcnKTtcblxuICB2YXIgaW5wdXQgPSBuZXcgQnVmZmVyKGJhc2U2NCwgJ2Jhc2U2NCcpO1xuICByZXR1cm4gREVSRGVjb2Rlci5wcm90b3R5cGUuZGVjb2RlLmNhbGwodGhpcywgaW5wdXQsIG9wdGlvbnMpO1xufTtcbiIsInZhciBpbmhlcml0cyA9IHJlcXVpcmUoJ2luaGVyaXRzJyk7XG52YXIgQnVmZmVyID0gcmVxdWlyZSgnYnVmZmVyJykuQnVmZmVyO1xuXG52YXIgYXNuMSA9IHJlcXVpcmUoJy4uLy4uL2FzbjEnKTtcbnZhciBiYXNlID0gYXNuMS5iYXNlO1xuXG4vLyBJbXBvcnQgREVSIGNvbnN0YW50c1xudmFyIGRlciA9IGFzbjEuY29uc3RhbnRzLmRlcjtcblxuZnVuY3Rpb24gREVSRW5jb2RlcihlbnRpdHkpIHtcbiAgdGhpcy5lbmMgPSAnZGVyJztcbiAgdGhpcy5uYW1lID0gZW50aXR5Lm5hbWU7XG4gIHRoaXMuZW50aXR5ID0gZW50aXR5O1xuXG4gIC8vIENvbnN0cnVjdCBiYXNlIHRyZWVcbiAgdGhpcy50cmVlID0gbmV3IERFUk5vZGUoKTtcbiAgdGhpcy50cmVlLl9pbml0KGVudGl0eS5ib2R5KTtcbn07XG5tb2R1bGUuZXhwb3J0cyA9IERFUkVuY29kZXI7XG5cbkRFUkVuY29kZXIucHJvdG90eXBlLmVuY29kZSA9IGZ1bmN0aW9uIGVuY29kZShkYXRhLCByZXBvcnRlcikge1xuICByZXR1cm4gdGhpcy50cmVlLl9lbmNvZGUoZGF0YSwgcmVwb3J0ZXIpLmpvaW4oKTtcbn07XG5cbi8vIFRyZWUgbWV0aG9kc1xuXG5mdW5jdGlvbiBERVJOb2RlKHBhcmVudCkge1xuICBiYXNlLk5vZGUuY2FsbCh0aGlzLCAnZGVyJywgcGFyZW50KTtcbn1cbmluaGVyaXRzKERFUk5vZGUsIGJhc2UuTm9kZSk7XG5cbkRFUk5vZGUucHJvdG90eXBlLl9lbmNvZGVDb21wb3NpdGUgPSBmdW5jdGlvbiBlbmNvZGVDb21wb3NpdGUodGFnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltaXRpdmUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNscyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGVudCkge1xuICB2YXIgZW5jb2RlZFRhZyA9IGVuY29kZVRhZyh0YWcsIHByaW1pdGl2ZSwgY2xzLCB0aGlzLnJlcG9ydGVyKTtcblxuICAvLyBTaG9ydCBmb3JtXG4gIGlmIChjb250ZW50Lmxlbmd0aCA8IDB4ODApIHtcbiAgICB2YXIgaGVhZGVyID0gbmV3IEJ1ZmZlcigyKTtcbiAgICBoZWFkZXJbMF0gPSBlbmNvZGVkVGFnO1xuICAgIGhlYWRlclsxXSA9IGNvbnRlbnQubGVuZ3RoO1xuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKFsgaGVhZGVyLCBjb250ZW50IF0pO1xuICB9XG5cbiAgLy8gTG9uZyBmb3JtXG4gIC8vIENvdW50IG9jdGV0cyByZXF1aXJlZCB0byBzdG9yZSBsZW5ndGhcbiAgdmFyIGxlbk9jdGV0cyA9IDE7XG4gIGZvciAodmFyIGkgPSBjb250ZW50Lmxlbmd0aDsgaSA+PSAweDEwMDsgaSA+Pj0gOClcbiAgICBsZW5PY3RldHMrKztcblxuICB2YXIgaGVhZGVyID0gbmV3IEJ1ZmZlcigxICsgMSArIGxlbk9jdGV0cyk7XG4gIGhlYWRlclswXSA9IGVuY29kZWRUYWc7XG4gIGhlYWRlclsxXSA9IDB4ODAgfCBsZW5PY3RldHM7XG5cbiAgZm9yICh2YXIgaSA9IDEgKyBsZW5PY3RldHMsIGogPSBjb250ZW50Lmxlbmd0aDsgaiA+IDA7IGktLSwgaiA+Pj0gOClcbiAgICBoZWFkZXJbaV0gPSBqICYgMHhmZjtcblxuICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihbIGhlYWRlciwgY29udGVudCBdKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9lbmNvZGVTdHIgPSBmdW5jdGlvbiBlbmNvZGVTdHIoc3RyLCB0YWcpIHtcbiAgaWYgKHRhZyA9PT0gJ2JpdHN0cicpIHtcbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihbIHN0ci51bnVzZWQgfCAwLCBzdHIuZGF0YSBdKTtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdibXBzdHInKSB7XG4gICAgdmFyIGJ1ZiA9IG5ldyBCdWZmZXIoc3RyLmxlbmd0aCAqIDIpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc3RyLmxlbmd0aDsgaSsrKSB7XG4gICAgICBidWYud3JpdGVVSW50MTZCRShzdHIuY2hhckNvZGVBdChpKSwgaSAqIDIpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihidWYpO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ251bXN0cicpIHtcbiAgICBpZiAoIXRoaXMuX2lzTnVtc3RyKHN0cikpIHtcbiAgICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdFbmNvZGluZyBvZiBzdHJpbmcgdHlwZTogbnVtc3RyIHN1cHBvcnRzICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ29ubHkgZGlnaXRzIGFuZCBzcGFjZScpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihzdHIpO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ3ByaW50c3RyJykge1xuICAgIGlmICghdGhpcy5faXNQcmludHN0cihzdHIpKSB7XG4gICAgICByZXR1cm4gdGhpcy5yZXBvcnRlci5lcnJvcignRW5jb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6IHByaW50c3RyIHN1cHBvcnRzICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ29ubHkgbGF0aW4gdXBwZXIgYW5kIGxvd2VyIGNhc2UgbGV0dGVycywgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZGlnaXRzLCBzcGFjZSwgYXBvc3Ryb3BoZSwgbGVmdCBhbmQgcmlndGggJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAncGFyZW50aGVzaXMsIHBsdXMgc2lnbiwgY29tbWEsIGh5cGhlbiwgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZG90LCBzbGFzaCwgY29sb24sIGVxdWFsIHNpZ24sICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3F1ZXN0aW9uIG1hcmsnKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIoc3RyKTtcbiAgfSBlbHNlIGlmICgvc3RyJC8udGVzdCh0YWcpKSB7XG4gICAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIoc3RyKTtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gdGhpcy5yZXBvcnRlci5lcnJvcignRW5jb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6ICcgKyB0YWcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICcgdW5zdXBwb3J0ZWQnKTtcbiAgfVxufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZU9iamlkID0gZnVuY3Rpb24gZW5jb2RlT2JqaWQoaWQsIHZhbHVlcywgcmVsYXRpdmUpIHtcbiAgaWYgKHR5cGVvZiBpZCA9PT0gJ3N0cmluZycpIHtcbiAgICBpZiAoIXZhbHVlcylcbiAgICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdzdHJpbmcgb2JqaWQgZ2l2ZW4sIGJ1dCBubyB2YWx1ZXMgbWFwIGZvdW5kJyk7XG4gICAgaWYgKCF2YWx1ZXMuaGFzT3duUHJvcGVydHkoaWQpKVxuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ29iamlkIG5vdCBmb3VuZCBpbiB2YWx1ZXMgbWFwJyk7XG4gICAgaWQgPSB2YWx1ZXNbaWRdLnNwbGl0KC9bXFxzXFwuXSsvZyk7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpZC5sZW5ndGg7IGkrKylcbiAgICAgIGlkW2ldIHw9IDA7XG4gIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheShpZCkpIHtcbiAgICBpZCA9IGlkLnNsaWNlKCk7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpZC5sZW5ndGg7IGkrKylcbiAgICAgIGlkW2ldIHw9IDA7XG4gIH1cblxuICBpZiAoIUFycmF5LmlzQXJyYXkoaWQpKSB7XG4gICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ29iamlkKCkgc2hvdWxkIGJlIGVpdGhlciBhcnJheSBvciBzdHJpbmcsICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdnb3Q6ICcgKyBKU09OLnN0cmluZ2lmeShpZCkpO1xuICB9XG5cbiAgaWYgKCFyZWxhdGl2ZSkge1xuICAgIGlmIChpZFsxXSA+PSA0MClcbiAgICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdTZWNvbmQgb2JqaWQgaWRlbnRpZmllciBPT0InKTtcbiAgICBpZC5zcGxpY2UoMCwgMiwgaWRbMF0gKiA0MCArIGlkWzFdKTtcbiAgfVxuXG4gIC8vIENvdW50IG51bWJlciBvZiBvY3RldHNcbiAgdmFyIHNpemUgPSAwO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGlkLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIGlkZW50ID0gaWRbaV07XG4gICAgZm9yIChzaXplKys7IGlkZW50ID49IDB4ODA7IGlkZW50ID4+PSA3KVxuICAgICAgc2l6ZSsrO1xuICB9XG5cbiAgdmFyIG9iamlkID0gbmV3IEJ1ZmZlcihzaXplKTtcbiAgdmFyIG9mZnNldCA9IG9iamlkLmxlbmd0aCAtIDE7XG4gIGZvciAodmFyIGkgPSBpZC5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgIHZhciBpZGVudCA9IGlkW2ldO1xuICAgIG9iamlkW29mZnNldC0tXSA9IGlkZW50ICYgMHg3ZjtcbiAgICB3aGlsZSAoKGlkZW50ID4+PSA3KSA+IDApXG4gICAgICBvYmppZFtvZmZzZXQtLV0gPSAweDgwIHwgKGlkZW50ICYgMHg3Zik7XG4gIH1cblxuICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihvYmppZCk7XG59O1xuXG5mdW5jdGlvbiB0d28obnVtKSB7XG4gIGlmIChudW0gPCAxMClcbiAgICByZXR1cm4gJzAnICsgbnVtO1xuICBlbHNlXG4gICAgcmV0dXJuIG51bTtcbn1cblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZVRpbWUgPSBmdW5jdGlvbiBlbmNvZGVUaW1lKHRpbWUsIHRhZykge1xuICB2YXIgc3RyO1xuICB2YXIgZGF0ZSA9IG5ldyBEYXRlKHRpbWUpO1xuXG4gIGlmICh0YWcgPT09ICdnZW50aW1lJykge1xuICAgIHN0ciA9IFtcbiAgICAgIHR3byhkYXRlLmdldEZ1bGxZZWFyKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDTW9udGgoKSArIDEpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDRGF0ZSgpKSxcbiAgICAgIHR3byhkYXRlLmdldFVUQ0hvdXJzKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDTWludXRlcygpKSxcbiAgICAgIHR3byhkYXRlLmdldFVUQ1NlY29uZHMoKSksXG4gICAgICAnWidcbiAgICBdLmpvaW4oJycpO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ3V0Y3RpbWUnKSB7XG4gICAgc3RyID0gW1xuICAgICAgdHdvKGRhdGUuZ2V0RnVsbFllYXIoKSAlIDEwMCksXG4gICAgICB0d28oZGF0ZS5nZXRVVENNb250aCgpICsgMSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENEYXRlKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDSG91cnMoKSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENNaW51dGVzKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDU2Vjb25kcygpKSxcbiAgICAgICdaJ1xuICAgIF0uam9pbignJyk7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5yZXBvcnRlci5lcnJvcignRW5jb2RpbmcgJyArIHRhZyArICcgdGltZSBpcyBub3Qgc3VwcG9ydGVkIHlldCcpO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2VuY29kZVN0cihzdHIsICdvY3RzdHInKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9lbmNvZGVOdWxsID0gZnVuY3Rpb24gZW5jb2RlTnVsbCgpIHtcbiAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIoJycpO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZUludCA9IGZ1bmN0aW9uIGVuY29kZUludChudW0sIHZhbHVlcykge1xuICBpZiAodHlwZW9mIG51bSA9PT0gJ3N0cmluZycpIHtcbiAgICBpZiAoIXZhbHVlcylcbiAgICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdTdHJpbmcgaW50IG9yIGVudW0gZ2l2ZW4sIGJ1dCBubyB2YWx1ZXMgbWFwJyk7XG4gICAgaWYgKCF2YWx1ZXMuaGFzT3duUHJvcGVydHkobnVtKSkge1xuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ1ZhbHVlcyBtYXAgZG9lc25cXCd0IGNvbnRhaW46ICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSlNPTi5zdHJpbmdpZnkobnVtKSk7XG4gICAgfVxuICAgIG51bSA9IHZhbHVlc1tudW1dO1xuICB9XG5cbiAgLy8gQmlnbnVtLCBhc3N1bWUgYmlnIGVuZGlhblxuICBpZiAodHlwZW9mIG51bSAhPT0gJ251bWJlcicgJiYgIUJ1ZmZlci5pc0J1ZmZlcihudW0pKSB7XG4gICAgdmFyIG51bUFycmF5ID0gbnVtLnRvQXJyYXkoKTtcbiAgICBpZiAoIW51bS5zaWduICYmIG51bUFycmF5WzBdICYgMHg4MCkge1xuICAgICAgbnVtQXJyYXkudW5zaGlmdCgwKTtcbiAgICB9XG4gICAgbnVtID0gbmV3IEJ1ZmZlcihudW1BcnJheSk7XG4gIH1cblxuICBpZiAoQnVmZmVyLmlzQnVmZmVyKG51bSkpIHtcbiAgICB2YXIgc2l6ZSA9IG51bS5sZW5ndGg7XG4gICAgaWYgKG51bS5sZW5ndGggPT09IDApXG4gICAgICBzaXplKys7XG5cbiAgICB2YXIgb3V0ID0gbmV3IEJ1ZmZlcihzaXplKTtcbiAgICBudW0uY29weShvdXQpO1xuICAgIGlmIChudW0ubGVuZ3RoID09PSAwKVxuICAgICAgb3V0WzBdID0gMFxuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKG91dCk7XG4gIH1cblxuICBpZiAobnVtIDwgMHg4MClcbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihudW0pO1xuXG4gIGlmIChudW0gPCAweDEwMClcbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihbMCwgbnVtXSk7XG5cbiAgdmFyIHNpemUgPSAxO1xuICBmb3IgKHZhciBpID0gbnVtOyBpID49IDB4MTAwOyBpID4+PSA4KVxuICAgIHNpemUrKztcblxuICB2YXIgb3V0ID0gbmV3IEFycmF5KHNpemUpO1xuICBmb3IgKHZhciBpID0gb3V0Lmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgb3V0W2ldID0gbnVtICYgMHhmZjtcbiAgICBudW0gPj49IDg7XG4gIH1cbiAgaWYob3V0WzBdICYgMHg4MCkge1xuICAgIG91dC51bnNoaWZ0KDApO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIobmV3IEJ1ZmZlcihvdXQpKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9lbmNvZGVCb29sID0gZnVuY3Rpb24gZW5jb2RlQm9vbCh2YWx1ZSkge1xuICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcih2YWx1ZSA/IDB4ZmYgOiAwKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl91c2UgPSBmdW5jdGlvbiB1c2UoZW50aXR5LCBvYmopIHtcbiAgaWYgKHR5cGVvZiBlbnRpdHkgPT09ICdmdW5jdGlvbicpXG4gICAgZW50aXR5ID0gZW50aXR5KG9iaik7XG4gIHJldHVybiBlbnRpdHkuX2dldEVuY29kZXIoJ2RlcicpLnRyZWU7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fc2tpcERlZmF1bHQgPSBmdW5jdGlvbiBza2lwRGVmYXVsdChkYXRhQnVmZmVyLCByZXBvcnRlciwgcGFyZW50KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcbiAgdmFyIGk7XG4gIGlmIChzdGF0ZVsnZGVmYXVsdCddID09PSBudWxsKVxuICAgIHJldHVybiBmYWxzZTtcblxuICB2YXIgZGF0YSA9IGRhdGFCdWZmZXIuam9pbigpO1xuICBpZiAoc3RhdGUuZGVmYXVsdEJ1ZmZlciA9PT0gdW5kZWZpbmVkKVxuICAgIHN0YXRlLmRlZmF1bHRCdWZmZXIgPSB0aGlzLl9lbmNvZGVWYWx1ZShzdGF0ZVsnZGVmYXVsdCddLCByZXBvcnRlciwgcGFyZW50KS5qb2luKCk7XG5cbiAgaWYgKGRhdGEubGVuZ3RoICE9PSBzdGF0ZS5kZWZhdWx0QnVmZmVyLmxlbmd0aClcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgZm9yIChpPTA7IGkgPCBkYXRhLmxlbmd0aDsgaSsrKVxuICAgIGlmIChkYXRhW2ldICE9PSBzdGF0ZS5kZWZhdWx0QnVmZmVyW2ldKVxuICAgICAgcmV0dXJuIGZhbHNlO1xuXG4gIHJldHVybiB0cnVlO1xufTtcblxuLy8gVXRpbGl0eSBtZXRob2RzXG5cbmZ1bmN0aW9uIGVuY29kZVRhZyh0YWcsIHByaW1pdGl2ZSwgY2xzLCByZXBvcnRlcikge1xuICB2YXIgcmVzO1xuXG4gIGlmICh0YWcgPT09ICdzZXFvZicpXG4gICAgdGFnID0gJ3NlcSc7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ3NldG9mJylcbiAgICB0YWcgPSAnc2V0JztcblxuICBpZiAoZGVyLnRhZ0J5TmFtZS5oYXNPd25Qcm9wZXJ0eSh0YWcpKVxuICAgIHJlcyA9IGRlci50YWdCeU5hbWVbdGFnXTtcbiAgZWxzZSBpZiAodHlwZW9mIHRhZyA9PT0gJ251bWJlcicgJiYgKHRhZyB8IDApID09PSB0YWcpXG4gICAgcmVzID0gdGFnO1xuICBlbHNlXG4gICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdVbmtub3duIHRhZzogJyArIHRhZyk7XG5cbiAgaWYgKHJlcyA+PSAweDFmKVxuICAgIHJldHVybiByZXBvcnRlci5lcnJvcignTXVsdGktb2N0ZXQgdGFnIGVuY29kaW5nIHVuc3VwcG9ydGVkJyk7XG5cbiAgaWYgKCFwcmltaXRpdmUpXG4gICAgcmVzIHw9IDB4MjA7XG5cbiAgcmVzIHw9IChkZXIudGFnQ2xhc3NCeU5hbWVbY2xzIHx8ICd1bml2ZXJzYWwnXSA8PCA2KTtcblxuICByZXR1cm4gcmVzO1xufVxuIiwidmFyIGVuY29kZXJzID0gZXhwb3J0cztcblxuZW5jb2RlcnMuZGVyID0gcmVxdWlyZSgnLi9kZXInKTtcbmVuY29kZXJzLnBlbSA9IHJlcXVpcmUoJy4vcGVtJyk7XG4iLCJ2YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG52YXIgREVSRW5jb2RlciA9IHJlcXVpcmUoJy4vZGVyJyk7XG5cbmZ1bmN0aW9uIFBFTUVuY29kZXIoZW50aXR5KSB7XG4gIERFUkVuY29kZXIuY2FsbCh0aGlzLCBlbnRpdHkpO1xuICB0aGlzLmVuYyA9ICdwZW0nO1xufTtcbmluaGVyaXRzKFBFTUVuY29kZXIsIERFUkVuY29kZXIpO1xubW9kdWxlLmV4cG9ydHMgPSBQRU1FbmNvZGVyO1xuXG5QRU1FbmNvZGVyLnByb3RvdHlwZS5lbmNvZGUgPSBmdW5jdGlvbiBlbmNvZGUoZGF0YSwgb3B0aW9ucykge1xuICB2YXIgYnVmID0gREVSRW5jb2Rlci5wcm90b3R5cGUuZW5jb2RlLmNhbGwodGhpcywgZGF0YSk7XG5cbiAgdmFyIHAgPSBidWYudG9TdHJpbmcoJ2Jhc2U2NCcpO1xuICB2YXIgb3V0ID0gWyAnLS0tLS1CRUdJTiAnICsgb3B0aW9ucy5sYWJlbCArICctLS0tLScgXTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwLmxlbmd0aDsgaSArPSA2NClcbiAgICBvdXQucHVzaChwLnNsaWNlKGksIGkgKyA2NCkpO1xuICBvdXQucHVzaCgnLS0tLS1FTkQgJyArIG9wdGlvbnMubGFiZWwgKyAnLS0tLS0nKTtcbiAgcmV0dXJuIG91dC5qb2luKCdcXG4nKTtcbn07XG4iLCIndXNlIHN0cmljdCdcblxuZXhwb3J0cy50b0J5dGVBcnJheSA9IHRvQnl0ZUFycmF5XG5leHBvcnRzLmZyb21CeXRlQXJyYXkgPSBmcm9tQnl0ZUFycmF5XG5cbnZhciBsb29rdXAgPSBbXVxudmFyIHJldkxvb2t1cCA9IFtdXG52YXIgQXJyID0gdHlwZW9mIFVpbnQ4QXJyYXkgIT09ICd1bmRlZmluZWQnID8gVWludDhBcnJheSA6IEFycmF5XG5cbmZ1bmN0aW9uIGluaXQgKCkge1xuICB2YXIgY29kZSA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJ1xuICBmb3IgKHZhciBpID0gMCwgbGVuID0gY29kZS5sZW5ndGg7IGkgPCBsZW47ICsraSkge1xuICAgIGxvb2t1cFtpXSA9IGNvZGVbaV1cbiAgICByZXZMb29rdXBbY29kZS5jaGFyQ29kZUF0KGkpXSA9IGlcbiAgfVxuXG4gIHJldkxvb2t1cFsnLScuY2hhckNvZGVBdCgwKV0gPSA2MlxuICByZXZMb29rdXBbJ18nLmNoYXJDb2RlQXQoMCldID0gNjNcbn1cblxuaW5pdCgpXG5cbmZ1bmN0aW9uIHRvQnl0ZUFycmF5IChiNjQpIHtcbiAgdmFyIGksIGosIGwsIHRtcCwgcGxhY2VIb2xkZXJzLCBhcnJcbiAgdmFyIGxlbiA9IGI2NC5sZW5ndGhcblxuICBpZiAobGVuICUgNCA+IDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKVxuICB9XG5cbiAgLy8gdGhlIG51bWJlciBvZiBlcXVhbCBzaWducyAocGxhY2UgaG9sZGVycylcbiAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAvLyByZXByZXNlbnQgb25lIGJ5dGVcbiAgLy8gaWYgdGhlcmUgaXMgb25seSBvbmUsIHRoZW4gdGhlIHRocmVlIGNoYXJhY3RlcnMgYmVmb3JlIGl0IHJlcHJlc2VudCAyIGJ5dGVzXG4gIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgcGxhY2VIb2xkZXJzID0gYjY0W2xlbiAtIDJdID09PSAnPScgPyAyIDogYjY0W2xlbiAtIDFdID09PSAnPScgPyAxIDogMFxuXG4gIC8vIGJhc2U2NCBpcyA0LzMgKyB1cCB0byB0d28gY2hhcmFjdGVycyBvZiB0aGUgb3JpZ2luYWwgZGF0YVxuICBhcnIgPSBuZXcgQXJyKGxlbiAqIDMgLyA0IC0gcGxhY2VIb2xkZXJzKVxuXG4gIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBsZW4gLSA0IDogbGVuXG5cbiAgdmFyIEwgPSAwXG5cbiAgZm9yIChpID0gMCwgaiA9IDA7IGkgPCBsOyBpICs9IDQsIGogKz0gMykge1xuICAgIHRtcCA9IChyZXZMb29rdXBbYjY0LmNoYXJDb2RlQXQoaSldIDw8IDE4KSB8IChyZXZMb29rdXBbYjY0LmNoYXJDb2RlQXQoaSArIDEpXSA8PCAxMikgfCAocmV2TG9va3VwW2I2NC5jaGFyQ29kZUF0KGkgKyAyKV0gPDwgNikgfCByZXZMb29rdXBbYjY0LmNoYXJDb2RlQXQoaSArIDMpXVxuICAgIGFycltMKytdID0gKHRtcCA+PiAxNikgJiAweEZGXG4gICAgYXJyW0wrK10gPSAodG1wID4+IDgpICYgMHhGRlxuICAgIGFycltMKytdID0gdG1wICYgMHhGRlxuICB9XG5cbiAgaWYgKHBsYWNlSG9sZGVycyA9PT0gMikge1xuICAgIHRtcCA9IChyZXZMb29rdXBbYjY0LmNoYXJDb2RlQXQoaSldIDw8IDIpIHwgKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpICsgMSldID4+IDQpXG4gICAgYXJyW0wrK10gPSB0bXAgJiAweEZGXG4gIH0gZWxzZSBpZiAocGxhY2VIb2xkZXJzID09PSAxKSB7XG4gICAgdG1wID0gKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpKV0gPDwgMTApIHwgKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpICsgMSldIDw8IDQpIHwgKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpICsgMildID4+IDIpXG4gICAgYXJyW0wrK10gPSAodG1wID4+IDgpICYgMHhGRlxuICAgIGFycltMKytdID0gdG1wICYgMHhGRlxuICB9XG5cbiAgcmV0dXJuIGFyclxufVxuXG5mdW5jdGlvbiB0cmlwbGV0VG9CYXNlNjQgKG51bSkge1xuICByZXR1cm4gbG9va3VwW251bSA+PiAxOCAmIDB4M0ZdICsgbG9va3VwW251bSA+PiAxMiAmIDB4M0ZdICsgbG9va3VwW251bSA+PiA2ICYgMHgzRl0gKyBsb29rdXBbbnVtICYgMHgzRl1cbn1cblxuZnVuY3Rpb24gZW5jb2RlQ2h1bmsgKHVpbnQ4LCBzdGFydCwgZW5kKSB7XG4gIHZhciB0bXBcbiAgdmFyIG91dHB1dCA9IFtdXG4gIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgaSArPSAzKSB7XG4gICAgdG1wID0gKHVpbnQ4W2ldIDw8IDE2KSArICh1aW50OFtpICsgMV0gPDwgOCkgKyAodWludDhbaSArIDJdKVxuICAgIG91dHB1dC5wdXNoKHRyaXBsZXRUb0Jhc2U2NCh0bXApKVxuICB9XG4gIHJldHVybiBvdXRwdXQuam9pbignJylcbn1cblxuZnVuY3Rpb24gZnJvbUJ5dGVBcnJheSAodWludDgpIHtcbiAgdmFyIHRtcFxuICB2YXIgbGVuID0gdWludDgubGVuZ3RoXG4gIHZhciBleHRyYUJ5dGVzID0gbGVuICUgMyAvLyBpZiB3ZSBoYXZlIDEgYnl0ZSBsZWZ0LCBwYWQgMiBieXRlc1xuICB2YXIgb3V0cHV0ID0gJydcbiAgdmFyIHBhcnRzID0gW11cbiAgdmFyIG1heENodW5rTGVuZ3RoID0gMTYzODMgLy8gbXVzdCBiZSBtdWx0aXBsZSBvZiAzXG5cbiAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICBmb3IgKHZhciBpID0gMCwgbGVuMiA9IGxlbiAtIGV4dHJhQnl0ZXM7IGkgPCBsZW4yOyBpICs9IG1heENodW5rTGVuZ3RoKSB7XG4gICAgcGFydHMucHVzaChlbmNvZGVDaHVuayh1aW50OCwgaSwgKGkgKyBtYXhDaHVua0xlbmd0aCkgPiBsZW4yID8gbGVuMiA6IChpICsgbWF4Q2h1bmtMZW5ndGgpKSlcbiAgfVxuXG4gIC8vIHBhZCB0aGUgZW5kIHdpdGggemVyb3MsIGJ1dCBtYWtlIHN1cmUgdG8gbm90IGZvcmdldCB0aGUgZXh0cmEgYnl0ZXNcbiAgaWYgKGV4dHJhQnl0ZXMgPT09IDEpIHtcbiAgICB0bXAgPSB1aW50OFtsZW4gLSAxXVxuICAgIG91dHB1dCArPSBsb29rdXBbdG1wID4+IDJdXG4gICAgb3V0cHV0ICs9IGxvb2t1cFsodG1wIDw8IDQpICYgMHgzRl1cbiAgICBvdXRwdXQgKz0gJz09J1xuICB9IGVsc2UgaWYgKGV4dHJhQnl0ZXMgPT09IDIpIHtcbiAgICB0bXAgPSAodWludDhbbGVuIC0gMl0gPDwgOCkgKyAodWludDhbbGVuIC0gMV0pXG4gICAgb3V0cHV0ICs9IGxvb2t1cFt0bXAgPj4gMTBdXG4gICAgb3V0cHV0ICs9IGxvb2t1cFsodG1wID4+IDQpICYgMHgzRl1cbiAgICBvdXRwdXQgKz0gbG9va3VwWyh0bXAgPDwgMikgJiAweDNGXVxuICAgIG91dHB1dCArPSAnPSdcbiAgfVxuXG4gIHBhcnRzLnB1c2gob3V0cHV0KVxuXG4gIHJldHVybiBwYXJ0cy5qb2luKCcnKVxufVxuIiwiKGZ1bmN0aW9uIChtb2R1bGUsIGV4cG9ydHMpIHtcbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIC8vIFV0aWxzXG4gIGZ1bmN0aW9uIGFzc2VydCAodmFsLCBtc2cpIHtcbiAgICBpZiAoIXZhbCkgdGhyb3cgbmV3IEVycm9yKG1zZyB8fCAnQXNzZXJ0aW9uIGZhaWxlZCcpO1xuICB9XG5cbiAgLy8gQ291bGQgdXNlIGBpbmhlcml0c2AgbW9kdWxlLCBidXQgZG9uJ3Qgd2FudCB0byBtb3ZlIGZyb20gc2luZ2xlIGZpbGVcbiAgLy8gYXJjaGl0ZWN0dXJlIHlldC5cbiAgZnVuY3Rpb24gaW5oZXJpdHMgKGN0b3IsIHN1cGVyQ3Rvcikge1xuICAgIGN0b3Iuc3VwZXJfID0gc3VwZXJDdG9yO1xuICAgIHZhciBUZW1wQ3RvciA9IGZ1bmN0aW9uICgpIHt9O1xuICAgIFRlbXBDdG9yLnByb3RvdHlwZSA9IHN1cGVyQ3Rvci5wcm90b3R5cGU7XG4gICAgY3Rvci5wcm90b3R5cGUgPSBuZXcgVGVtcEN0b3IoKTtcbiAgICBjdG9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IGN0b3I7XG4gIH1cblxuICAvLyBCTlxuXG4gIGZ1bmN0aW9uIEJOIChudW1iZXIsIGJhc2UsIGVuZGlhbikge1xuICAgIGlmIChCTi5pc0JOKG51bWJlcikpIHtcbiAgICAgIHJldHVybiBudW1iZXI7XG4gICAgfVxuXG4gICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgdGhpcy53b3JkcyA9IG51bGw7XG4gICAgdGhpcy5sZW5ndGggPSAwO1xuXG4gICAgLy8gUmVkdWN0aW9uIGNvbnRleHRcbiAgICB0aGlzLnJlZCA9IG51bGw7XG5cbiAgICBpZiAobnVtYmVyICE9PSBudWxsKSB7XG4gICAgICBpZiAoYmFzZSA9PT0gJ2xlJyB8fCBiYXNlID09PSAnYmUnKSB7XG4gICAgICAgIGVuZGlhbiA9IGJhc2U7XG4gICAgICAgIGJhc2UgPSAxMDtcbiAgICAgIH1cblxuICAgICAgdGhpcy5faW5pdChudW1iZXIgfHwgMCwgYmFzZSB8fCAxMCwgZW5kaWFuIHx8ICdiZScpO1xuICAgIH1cbiAgfVxuICBpZiAodHlwZW9mIG1vZHVsZSA9PT0gJ29iamVjdCcpIHtcbiAgICBtb2R1bGUuZXhwb3J0cyA9IEJOO1xuICB9IGVsc2Uge1xuICAgIGV4cG9ydHMuQk4gPSBCTjtcbiAgfVxuXG4gIEJOLkJOID0gQk47XG4gIEJOLndvcmRTaXplID0gMjY7XG5cbiAgdmFyIEJ1ZmZlcjtcbiAgdHJ5IHtcbiAgICBCdWZmZXIgPSByZXF1aXJlKCdidWYnICsgJ2ZlcicpLkJ1ZmZlcjtcbiAgfSBjYXRjaCAoZSkge1xuICB9XG5cbiAgQk4uaXNCTiA9IGZ1bmN0aW9uIGlzQk4gKG51bSkge1xuICAgIHJldHVybiBudW0gIT09IG51bGwgJiYgdHlwZW9mIG51bSA9PT0gJ29iamVjdCcgJiZcbiAgICAgIG51bS5jb25zdHJ1Y3Rvci5uYW1lID09PSAnQk4nICYmIEFycmF5LmlzQXJyYXkobnVtLndvcmRzKTtcbiAgfTtcblxuICBCTi5tYXggPSBmdW5jdGlvbiBtYXggKGxlZnQsIHJpZ2h0KSB7XG4gICAgaWYgKGxlZnQuY21wKHJpZ2h0KSA+IDApIHJldHVybiBsZWZ0O1xuICAgIHJldHVybiByaWdodDtcbiAgfTtcblxuICBCTi5taW4gPSBmdW5jdGlvbiBtaW4gKGxlZnQsIHJpZ2h0KSB7XG4gICAgaWYgKGxlZnQuY21wKHJpZ2h0KSA8IDApIHJldHVybiBsZWZ0O1xuICAgIHJldHVybiByaWdodDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2luaXQgPSBmdW5jdGlvbiBpbml0IChudW1iZXIsIGJhc2UsIGVuZGlhbikge1xuICAgIGlmICh0eXBlb2YgbnVtYmVyID09PSAnbnVtYmVyJykge1xuICAgICAgcmV0dXJuIHRoaXMuX2luaXROdW1iZXIobnVtYmVyLCBiYXNlLCBlbmRpYW4pO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgbnVtYmVyID09PSAnb2JqZWN0Jykge1xuICAgICAgcmV0dXJuIHRoaXMuX2luaXRBcnJheShudW1iZXIsIGJhc2UsIGVuZGlhbik7XG4gICAgfVxuXG4gICAgaWYgKGJhc2UgPT09ICdoZXgnKSB7XG4gICAgICBiYXNlID0gMTY7XG4gICAgfVxuICAgIGFzc2VydChiYXNlID09PSAoYmFzZSB8IDApICYmIGJhc2UgPj0gMiAmJiBiYXNlIDw9IDM2KTtcblxuICAgIG51bWJlciA9IG51bWJlci50b1N0cmluZygpLnJlcGxhY2UoL1xccysvZywgJycpO1xuICAgIHZhciBzdGFydCA9IDA7XG4gICAgaWYgKG51bWJlclswXSA9PT0gJy0nKSB7XG4gICAgICBzdGFydCsrO1xuICAgIH1cblxuICAgIGlmIChiYXNlID09PSAxNikge1xuICAgICAgdGhpcy5fcGFyc2VIZXgobnVtYmVyLCBzdGFydCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX3BhcnNlQmFzZShudW1iZXIsIGJhc2UsIHN0YXJ0KTtcbiAgICB9XG5cbiAgICBpZiAobnVtYmVyWzBdID09PSAnLScpIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAxO1xuICAgIH1cblxuICAgIHRoaXMuc3RyaXAoKTtcblxuICAgIGlmIChlbmRpYW4gIT09ICdsZScpIHJldHVybjtcblxuICAgIHRoaXMuX2luaXRBcnJheSh0aGlzLnRvQXJyYXkoKSwgYmFzZSwgZW5kaWFuKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2luaXROdW1iZXIgPSBmdW5jdGlvbiBfaW5pdE51bWJlciAobnVtYmVyLCBiYXNlLCBlbmRpYW4pIHtcbiAgICBpZiAobnVtYmVyIDwgMCkge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG4gICAgICBudW1iZXIgPSAtbnVtYmVyO1xuICAgIH1cbiAgICBpZiAobnVtYmVyIDwgMHg0MDAwMDAwKSB7XG4gICAgICB0aGlzLndvcmRzID0gWyBudW1iZXIgJiAweDNmZmZmZmYgXTtcbiAgICAgIHRoaXMubGVuZ3RoID0gMTtcbiAgICB9IGVsc2UgaWYgKG51bWJlciA8IDB4MTAwMDAwMDAwMDAwMDApIHtcbiAgICAgIHRoaXMud29yZHMgPSBbXG4gICAgICAgIG51bWJlciAmIDB4M2ZmZmZmZixcbiAgICAgICAgKG51bWJlciAvIDB4NDAwMDAwMCkgJiAweDNmZmZmZmZcbiAgICAgIF07XG4gICAgICB0aGlzLmxlbmd0aCA9IDI7XG4gICAgfSBlbHNlIHtcbiAgICAgIGFzc2VydChudW1iZXIgPCAweDIwMDAwMDAwMDAwMDAwKTsgLy8gMiBeIDUzICh1bnNhZmUpXG4gICAgICB0aGlzLndvcmRzID0gW1xuICAgICAgICBudW1iZXIgJiAweDNmZmZmZmYsXG4gICAgICAgIChudW1iZXIgLyAweDQwMDAwMDApICYgMHgzZmZmZmZmLFxuICAgICAgICAxXG4gICAgICBdO1xuICAgICAgdGhpcy5sZW5ndGggPSAzO1xuICAgIH1cblxuICAgIGlmIChlbmRpYW4gIT09ICdsZScpIHJldHVybjtcblxuICAgIC8vIFJldmVyc2UgdGhlIGJ5dGVzXG4gICAgdGhpcy5faW5pdEFycmF5KHRoaXMudG9BcnJheSgpLCBiYXNlLCBlbmRpYW4pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5faW5pdEFycmF5ID0gZnVuY3Rpb24gX2luaXRBcnJheSAobnVtYmVyLCBiYXNlLCBlbmRpYW4pIHtcbiAgICAvLyBQZXJoYXBzIGEgVWludDhBcnJheVxuICAgIGFzc2VydCh0eXBlb2YgbnVtYmVyLmxlbmd0aCA9PT0gJ251bWJlcicpO1xuICAgIGlmIChudW1iZXIubGVuZ3RoIDw9IDApIHtcbiAgICAgIHRoaXMud29yZHMgPSBbIDAgXTtcbiAgICAgIHRoaXMubGVuZ3RoID0gMTtcbiAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cblxuICAgIHRoaXMubGVuZ3RoID0gTWF0aC5jZWlsKG51bWJlci5sZW5ndGggLyAzKTtcbiAgICB0aGlzLndvcmRzID0gbmV3IEFycmF5KHRoaXMubGVuZ3RoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHRoaXMud29yZHNbaV0gPSAwO1xuICAgIH1cblxuICAgIHZhciBqLCB3O1xuICAgIHZhciBvZmYgPSAwO1xuICAgIGlmIChlbmRpYW4gPT09ICdiZScpIHtcbiAgICAgIGZvciAoaSA9IG51bWJlci5sZW5ndGggLSAxLCBqID0gMDsgaSA+PSAwOyBpIC09IDMpIHtcbiAgICAgICAgdyA9IG51bWJlcltpXSB8IChudW1iZXJbaSAtIDFdIDw8IDgpIHwgKG51bWJlcltpIC0gMl0gPDwgMTYpO1xuICAgICAgICB0aGlzLndvcmRzW2pdIHw9ICh3IDw8IG9mZikgJiAweDNmZmZmZmY7XG4gICAgICAgIHRoaXMud29yZHNbaiArIDFdID0gKHcgPj4+ICgyNiAtIG9mZikpICYgMHgzZmZmZmZmO1xuICAgICAgICBvZmYgKz0gMjQ7XG4gICAgICAgIGlmIChvZmYgPj0gMjYpIHtcbiAgICAgICAgICBvZmYgLT0gMjY7XG4gICAgICAgICAgaisrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIGlmIChlbmRpYW4gPT09ICdsZScpIHtcbiAgICAgIGZvciAoaSA9IDAsIGogPSAwOyBpIDwgbnVtYmVyLmxlbmd0aDsgaSArPSAzKSB7XG4gICAgICAgIHcgPSBudW1iZXJbaV0gfCAobnVtYmVyW2kgKyAxXSA8PCA4KSB8IChudW1iZXJbaSArIDJdIDw8IDE2KTtcbiAgICAgICAgdGhpcy53b3Jkc1tqXSB8PSAodyA8PCBvZmYpICYgMHgzZmZmZmZmO1xuICAgICAgICB0aGlzLndvcmRzW2ogKyAxXSA9ICh3ID4+PiAoMjYgLSBvZmYpKSAmIDB4M2ZmZmZmZjtcbiAgICAgICAgb2ZmICs9IDI0O1xuICAgICAgICBpZiAob2ZmID49IDI2KSB7XG4gICAgICAgICAgb2ZmIC09IDI2O1xuICAgICAgICAgIGorKztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIGZ1bmN0aW9uIHBhcnNlSGV4IChzdHIsIHN0YXJ0LCBlbmQpIHtcbiAgICB2YXIgciA9IDA7XG4gICAgdmFyIGxlbiA9IE1hdGgubWluKHN0ci5sZW5ndGgsIGVuZCk7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIHZhciBjID0gc3RyLmNoYXJDb2RlQXQoaSkgLSA0ODtcblxuICAgICAgciA8PD0gNDtcblxuICAgICAgLy8gJ2EnIC0gJ2YnXG4gICAgICBpZiAoYyA+PSA0OSAmJiBjIDw9IDU0KSB7XG4gICAgICAgIHIgfD0gYyAtIDQ5ICsgMHhhO1xuXG4gICAgICAvLyAnQScgLSAnRidcbiAgICAgIH0gZWxzZSBpZiAoYyA+PSAxNyAmJiBjIDw9IDIyKSB7XG4gICAgICAgIHIgfD0gYyAtIDE3ICsgMHhhO1xuXG4gICAgICAvLyAnMCcgLSAnOSdcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHIgfD0gYyAmIDB4ZjtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHI7XG4gIH1cblxuICBCTi5wcm90b3R5cGUuX3BhcnNlSGV4ID0gZnVuY3Rpb24gX3BhcnNlSGV4IChudW1iZXIsIHN0YXJ0KSB7XG4gICAgLy8gQ3JlYXRlIHBvc3NpYmx5IGJpZ2dlciBhcnJheSB0byBlbnN1cmUgdGhhdCBpdCBmaXRzIHRoZSBudW1iZXJcbiAgICB0aGlzLmxlbmd0aCA9IE1hdGguY2VpbCgobnVtYmVyLmxlbmd0aCAtIHN0YXJ0KSAvIDYpO1xuICAgIHRoaXMud29yZHMgPSBuZXcgQXJyYXkodGhpcy5sZW5ndGgpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IDA7XG4gICAgfVxuXG4gICAgdmFyIGosIHc7XG4gICAgLy8gU2NhbiAyNC1iaXQgY2h1bmtzIGFuZCBhZGQgdGhlbSB0byB0aGUgbnVtYmVyXG4gICAgdmFyIG9mZiA9IDA7XG4gICAgZm9yIChpID0gbnVtYmVyLmxlbmd0aCAtIDYsIGogPSAwOyBpID49IHN0YXJ0OyBpIC09IDYpIHtcbiAgICAgIHcgPSBwYXJzZUhleChudW1iZXIsIGksIGkgKyA2KTtcbiAgICAgIHRoaXMud29yZHNbal0gfD0gKHcgPDwgb2ZmKSAmIDB4M2ZmZmZmZjtcbiAgICAgIC8vIE5PVEU6IGAweDNmZmZmZmAgaXMgaW50ZW50aW9uYWwgaGVyZSwgMjZiaXRzIG1heCBzaGlmdCArIDI0Yml0IGhleCBsaW1iXG4gICAgICB0aGlzLndvcmRzW2ogKyAxXSB8PSB3ID4+PiAoMjYgLSBvZmYpICYgMHgzZmZmZmY7XG4gICAgICBvZmYgKz0gMjQ7XG4gICAgICBpZiAob2ZmID49IDI2KSB7XG4gICAgICAgIG9mZiAtPSAyNjtcbiAgICAgICAgaisrO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoaSArIDYgIT09IHN0YXJ0KSB7XG4gICAgICB3ID0gcGFyc2VIZXgobnVtYmVyLCBzdGFydCwgaSArIDYpO1xuICAgICAgdGhpcy53b3Jkc1tqXSB8PSAodyA8PCBvZmYpICYgMHgzZmZmZmZmO1xuICAgICAgdGhpcy53b3Jkc1tqICsgMV0gfD0gdyA+Pj4gKDI2IC0gb2ZmKSAmIDB4M2ZmZmZmO1xuICAgIH1cbiAgICB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgZnVuY3Rpb24gcGFyc2VCYXNlIChzdHIsIHN0YXJ0LCBlbmQsIG11bCkge1xuICAgIHZhciByID0gMDtcbiAgICB2YXIgbGVuID0gTWF0aC5taW4oc3RyLmxlbmd0aCwgZW5kKTtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBsZW47IGkrKykge1xuICAgICAgdmFyIGMgPSBzdHIuY2hhckNvZGVBdChpKSAtIDQ4O1xuXG4gICAgICByICo9IG11bDtcblxuICAgICAgLy8gJ2EnXG4gICAgICBpZiAoYyA+PSA0OSkge1xuICAgICAgICByICs9IGMgLSA0OSArIDB4YTtcblxuICAgICAgLy8gJ0EnXG4gICAgICB9IGVsc2UgaWYgKGMgPj0gMTcpIHtcbiAgICAgICAgciArPSBjIC0gMTcgKyAweGE7XG5cbiAgICAgIC8vICcwJyAtICc5J1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgciArPSBjO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcjtcbiAgfVxuXG4gIEJOLnByb3RvdHlwZS5fcGFyc2VCYXNlID0gZnVuY3Rpb24gX3BhcnNlQmFzZSAobnVtYmVyLCBiYXNlLCBzdGFydCkge1xuICAgIC8vIEluaXRpYWxpemUgYXMgemVyb1xuICAgIHRoaXMud29yZHMgPSBbIDAgXTtcbiAgICB0aGlzLmxlbmd0aCA9IDE7XG5cbiAgICAvLyBGaW5kIGxlbmd0aCBvZiBsaW1iIGluIGJhc2VcbiAgICBmb3IgKHZhciBsaW1iTGVuID0gMCwgbGltYlBvdyA9IDE7IGxpbWJQb3cgPD0gMHgzZmZmZmZmOyBsaW1iUG93ICo9IGJhc2UpIHtcbiAgICAgIGxpbWJMZW4rKztcbiAgICB9XG4gICAgbGltYkxlbi0tO1xuICAgIGxpbWJQb3cgPSAobGltYlBvdyAvIGJhc2UpIHwgMDtcblxuICAgIHZhciB0b3RhbCA9IG51bWJlci5sZW5ndGggLSBzdGFydDtcbiAgICB2YXIgbW9kID0gdG90YWwgJSBsaW1iTGVuO1xuICAgIHZhciBlbmQgPSBNYXRoLm1pbih0b3RhbCwgdG90YWwgLSBtb2QpICsgc3RhcnQ7XG5cbiAgICB2YXIgd29yZCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyBpICs9IGxpbWJMZW4pIHtcbiAgICAgIHdvcmQgPSBwYXJzZUJhc2UobnVtYmVyLCBpLCBpICsgbGltYkxlbiwgYmFzZSk7XG5cbiAgICAgIHRoaXMuaW11bG4obGltYlBvdyk7XG4gICAgICBpZiAodGhpcy53b3Jkc1swXSArIHdvcmQgPCAweDQwMDAwMDApIHtcbiAgICAgICAgdGhpcy53b3Jkc1swXSArPSB3b3JkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5faWFkZG4od29yZCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKG1vZCAhPT0gMCkge1xuICAgICAgdmFyIHBvdyA9IDE7XG4gICAgICB3b3JkID0gcGFyc2VCYXNlKG51bWJlciwgaSwgbnVtYmVyLmxlbmd0aCwgYmFzZSk7XG5cbiAgICAgIGZvciAoaSA9IDA7IGkgPCBtb2Q7IGkrKykge1xuICAgICAgICBwb3cgKj0gYmFzZTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5pbXVsbihwb3cpO1xuICAgICAgaWYgKHRoaXMud29yZHNbMF0gKyB3b3JkIDwgMHg0MDAwMDAwKSB7XG4gICAgICAgIHRoaXMud29yZHNbMF0gKz0gd29yZDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuX2lhZGRuKHdvcmQpO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICBCTi5wcm90b3R5cGUuY29weSA9IGZ1bmN0aW9uIGNvcHkgKGRlc3QpIHtcbiAgICBkZXN0LndvcmRzID0gbmV3IEFycmF5KHRoaXMubGVuZ3RoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGRlc3Qud29yZHNbaV0gPSB0aGlzLndvcmRzW2ldO1xuICAgIH1cbiAgICBkZXN0Lmxlbmd0aCA9IHRoaXMubGVuZ3RoO1xuICAgIGRlc3QubmVnYXRpdmUgPSB0aGlzLm5lZ2F0aXZlO1xuICAgIGRlc3QucmVkID0gdGhpcy5yZWQ7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmNsb25lID0gZnVuY3Rpb24gY2xvbmUgKCkge1xuICAgIHZhciByID0gbmV3IEJOKG51bGwpO1xuICAgIHRoaXMuY29weShyKTtcbiAgICByZXR1cm4gcjtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2V4cGFuZCA9IGZ1bmN0aW9uIF9leHBhbmQgKHNpemUpIHtcbiAgICB3aGlsZSAodGhpcy5sZW5ndGggPCBzaXplKSB7XG4gICAgICB0aGlzLndvcmRzW3RoaXMubGVuZ3RoKytdID0gMDtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgLy8gUmVtb3ZlIGxlYWRpbmcgYDBgIGZyb20gYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5zdHJpcCA9IGZ1bmN0aW9uIHN0cmlwICgpIHtcbiAgICB3aGlsZSAodGhpcy5sZW5ndGggPiAxICYmIHRoaXMud29yZHNbdGhpcy5sZW5ndGggLSAxXSA9PT0gMCkge1xuICAgICAgdGhpcy5sZW5ndGgtLTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX25vcm1TaWduKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLl9ub3JtU2lnbiA9IGZ1bmN0aW9uIF9ub3JtU2lnbiAoKSB7XG4gICAgLy8gLTAgPSAwXG4gICAgaWYgKHRoaXMubGVuZ3RoID09PSAxICYmIHRoaXMud29yZHNbMF0gPT09IDApIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAwO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaW5zcGVjdCA9IGZ1bmN0aW9uIGluc3BlY3QgKCkge1xuICAgIHJldHVybiAodGhpcy5yZWQgPyAnPEJOLVI6ICcgOiAnPEJOOiAnKSArIHRoaXMudG9TdHJpbmcoMTYpICsgJz4nO1xuICB9O1xuXG4gIC8qXG5cbiAgdmFyIHplcm9zID0gW107XG4gIHZhciBncm91cFNpemVzID0gW107XG4gIHZhciBncm91cEJhc2VzID0gW107XG5cbiAgdmFyIHMgPSAnJztcbiAgdmFyIGkgPSAtMTtcbiAgd2hpbGUgKCsraSA8IEJOLndvcmRTaXplKSB7XG4gICAgemVyb3NbaV0gPSBzO1xuICAgIHMgKz0gJzAnO1xuICB9XG4gIGdyb3VwU2l6ZXNbMF0gPSAwO1xuICBncm91cFNpemVzWzFdID0gMDtcbiAgZ3JvdXBCYXNlc1swXSA9IDA7XG4gIGdyb3VwQmFzZXNbMV0gPSAwO1xuICB2YXIgYmFzZSA9IDIgLSAxO1xuICB3aGlsZSAoKytiYXNlIDwgMzYgKyAxKSB7XG4gICAgdmFyIGdyb3VwU2l6ZSA9IDA7XG4gICAgdmFyIGdyb3VwQmFzZSA9IDE7XG4gICAgd2hpbGUgKGdyb3VwQmFzZSA8ICgxIDw8IEJOLndvcmRTaXplKSAvIGJhc2UpIHtcbiAgICAgIGdyb3VwQmFzZSAqPSBiYXNlO1xuICAgICAgZ3JvdXBTaXplICs9IDE7XG4gICAgfVxuICAgIGdyb3VwU2l6ZXNbYmFzZV0gPSBncm91cFNpemU7XG4gICAgZ3JvdXBCYXNlc1tiYXNlXSA9IGdyb3VwQmFzZTtcbiAgfVxuXG4gICovXG5cbiAgdmFyIHplcm9zID0gW1xuICAgICcnLFxuICAgICcwJyxcbiAgICAnMDAnLFxuICAgICcwMDAnLFxuICAgICcwMDAwJyxcbiAgICAnMDAwMDAnLFxuICAgICcwMDAwMDAnLFxuICAgICcwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwJyxcbiAgICAnMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwJ1xuICBdO1xuXG4gIHZhciBncm91cFNpemVzID0gW1xuICAgIDAsIDAsXG4gICAgMjUsIDE2LCAxMiwgMTEsIDEwLCA5LCA4LFxuICAgIDgsIDcsIDcsIDcsIDcsIDYsIDYsXG4gICAgNiwgNiwgNiwgNiwgNiwgNSwgNSxcbiAgICA1LCA1LCA1LCA1LCA1LCA1LCA1LFxuICAgIDUsIDUsIDUsIDUsIDUsIDUsIDVcbiAgXTtcblxuICB2YXIgZ3JvdXBCYXNlcyA9IFtcbiAgICAwLCAwLFxuICAgIDMzNTU0NDMyLCA0MzA0NjcyMSwgMTY3NzcyMTYsIDQ4ODI4MTI1LCA2MDQ2NjE3NiwgNDAzNTM2MDcsIDE2Nzc3MjE2LFxuICAgIDQzMDQ2NzIxLCAxMDAwMDAwMCwgMTk0ODcxNzEsIDM1ODMxODA4LCA2Mjc0ODUxNywgNzUyOTUzNiwgMTEzOTA2MjUsXG4gICAgMTY3NzcyMTYsIDI0MTM3NTY5LCAzNDAxMjIyNCwgNDcwNDU4ODEsIDY0MDAwMDAwLCA0MDg0MTAxLCA1MTUzNjMyLFxuICAgIDY0MzYzNDMsIDc5NjI2MjQsIDk3NjU2MjUsIDExODgxMzc2LCAxNDM0ODkwNywgMTcyMTAzNjgsIDIwNTExMTQ5LFxuICAgIDI0MzAwMDAwLCAyODYyOTE1MSwgMzM1NTQ0MzIsIDM5MTM1MzkzLCA0NTQzNTQyNCwgNTI1MjE4NzUsIDYwNDY2MTc2XG4gIF07XG5cbiAgQk4ucHJvdG90eXBlLnRvU3RyaW5nID0gZnVuY3Rpb24gdG9TdHJpbmcgKGJhc2UsIHBhZGRpbmcpIHtcbiAgICBiYXNlID0gYmFzZSB8fCAxMDtcbiAgICBwYWRkaW5nID0gcGFkZGluZyB8IDAgfHwgMTtcblxuICAgIHZhciBvdXQ7XG4gICAgaWYgKGJhc2UgPT09IDE2IHx8IGJhc2UgPT09ICdoZXgnKSB7XG4gICAgICBvdXQgPSAnJztcbiAgICAgIHZhciBvZmYgPSAwO1xuICAgICAgdmFyIGNhcnJ5ID0gMDtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgICB2YXIgdyA9IHRoaXMud29yZHNbaV07XG4gICAgICAgIHZhciB3b3JkID0gKCgodyA8PCBvZmYpIHwgY2FycnkpICYgMHhmZmZmZmYpLnRvU3RyaW5nKDE2KTtcbiAgICAgICAgY2FycnkgPSAodyA+Pj4gKDI0IC0gb2ZmKSkgJiAweGZmZmZmZjtcbiAgICAgICAgaWYgKGNhcnJ5ICE9PSAwIHx8IGkgIT09IHRoaXMubGVuZ3RoIC0gMSkge1xuICAgICAgICAgIG91dCA9IHplcm9zWzYgLSB3b3JkLmxlbmd0aF0gKyB3b3JkICsgb3V0O1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIG91dCA9IHdvcmQgKyBvdXQ7XG4gICAgICAgIH1cbiAgICAgICAgb2ZmICs9IDI7XG4gICAgICAgIGlmIChvZmYgPj0gMjYpIHtcbiAgICAgICAgICBvZmYgLT0gMjY7XG4gICAgICAgICAgaS0tO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAoY2FycnkgIT09IDApIHtcbiAgICAgICAgb3V0ID0gY2FycnkudG9TdHJpbmcoMTYpICsgb3V0O1xuICAgICAgfVxuICAgICAgd2hpbGUgKG91dC5sZW5ndGggJSBwYWRkaW5nICE9PSAwKSB7XG4gICAgICAgIG91dCA9ICcwJyArIG91dDtcbiAgICAgIH1cbiAgICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICAgIG91dCA9ICctJyArIG91dDtcbiAgICAgIH1cbiAgICAgIHJldHVybiBvdXQ7XG4gICAgfVxuXG4gICAgaWYgKGJhc2UgPT09IChiYXNlIHwgMCkgJiYgYmFzZSA+PSAyICYmIGJhc2UgPD0gMzYpIHtcbiAgICAgIC8vIHZhciBncm91cFNpemUgPSBNYXRoLmZsb29yKEJOLndvcmRTaXplICogTWF0aC5MTjIgLyBNYXRoLmxvZyhiYXNlKSk7XG4gICAgICB2YXIgZ3JvdXBTaXplID0gZ3JvdXBTaXplc1tiYXNlXTtcbiAgICAgIC8vIHZhciBncm91cEJhc2UgPSBNYXRoLnBvdyhiYXNlLCBncm91cFNpemUpO1xuICAgICAgdmFyIGdyb3VwQmFzZSA9IGdyb3VwQmFzZXNbYmFzZV07XG4gICAgICBvdXQgPSAnJztcbiAgICAgIHZhciBjID0gdGhpcy5jbG9uZSgpO1xuICAgICAgYy5uZWdhdGl2ZSA9IDA7XG4gICAgICB3aGlsZSAoIWMuaXNaZXJvKCkpIHtcbiAgICAgICAgdmFyIHIgPSBjLm1vZG4oZ3JvdXBCYXNlKS50b1N0cmluZyhiYXNlKTtcbiAgICAgICAgYyA9IGMuaWRpdm4oZ3JvdXBCYXNlKTtcblxuICAgICAgICBpZiAoIWMuaXNaZXJvKCkpIHtcbiAgICAgICAgICBvdXQgPSB6ZXJvc1tncm91cFNpemUgLSByLmxlbmd0aF0gKyByICsgb3V0O1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIG91dCA9IHIgKyBvdXQ7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmICh0aGlzLmlzWmVybygpKSB7XG4gICAgICAgIG91dCA9ICcwJyArIG91dDtcbiAgICAgIH1cbiAgICAgIHdoaWxlIChvdXQubGVuZ3RoICUgcGFkZGluZyAhPT0gMCkge1xuICAgICAgICBvdXQgPSAnMCcgKyBvdXQ7XG4gICAgICB9XG4gICAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgICBvdXQgPSAnLScgKyBvdXQ7XG4gICAgICB9XG4gICAgICByZXR1cm4gb3V0O1xuICAgIH1cblxuICAgIGFzc2VydChmYWxzZSwgJ0Jhc2Ugc2hvdWxkIGJlIGJldHdlZW4gMiBhbmQgMzYnKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudG9OdW1iZXIgPSBmdW5jdGlvbiB0b051bWJlciAoKSB7XG4gICAgdmFyIHJldCA9IHRoaXMud29yZHNbMF07XG4gICAgaWYgKHRoaXMubGVuZ3RoID09PSAyKSB7XG4gICAgICByZXQgKz0gdGhpcy53b3Jkc1sxXSAqIDB4NDAwMDAwMDtcbiAgICB9IGVsc2UgaWYgKHRoaXMubGVuZ3RoID09PSAzICYmIHRoaXMud29yZHNbMl0gPT09IDB4MDEpIHtcbiAgICAgIC8vIE5PVEU6IGF0IHRoaXMgc3RhZ2UgaXQgaXMga25vd24gdGhhdCB0aGUgdG9wIGJpdCBpcyBzZXRcbiAgICAgIHJldCArPSAweDEwMDAwMDAwMDAwMDAwICsgKHRoaXMud29yZHNbMV0gKiAweDQwMDAwMDApO1xuICAgIH0gZWxzZSBpZiAodGhpcy5sZW5ndGggPiAyKSB7XG4gICAgICBhc3NlcnQoZmFsc2UsICdOdW1iZXIgY2FuIG9ubHkgc2FmZWx5IHN0b3JlIHVwIHRvIDUzIGJpdHMnKTtcbiAgICB9XG4gICAgcmV0dXJuICh0aGlzLm5lZ2F0aXZlICE9PSAwKSA/IC1yZXQgOiByZXQ7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uIHRvSlNPTiAoKSB7XG4gICAgcmV0dXJuIHRoaXMudG9TdHJpbmcoMTYpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS50b0J1ZmZlciA9IGZ1bmN0aW9uIHRvQnVmZmVyIChlbmRpYW4sIGxlbmd0aCkge1xuICAgIGFzc2VydCh0eXBlb2YgQnVmZmVyICE9PSAndW5kZWZpbmVkJyk7XG4gICAgcmV0dXJuIHRoaXMudG9BcnJheUxpa2UoQnVmZmVyLCBlbmRpYW4sIGxlbmd0aCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnRvQXJyYXkgPSBmdW5jdGlvbiB0b0FycmF5IChlbmRpYW4sIGxlbmd0aCkge1xuICAgIHJldHVybiB0aGlzLnRvQXJyYXlMaWtlKEFycmF5LCBlbmRpYW4sIGxlbmd0aCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnRvQXJyYXlMaWtlID0gZnVuY3Rpb24gdG9BcnJheUxpa2UgKEFycmF5VHlwZSwgZW5kaWFuLCBsZW5ndGgpIHtcbiAgICB2YXIgYnl0ZUxlbmd0aCA9IHRoaXMuYnl0ZUxlbmd0aCgpO1xuICAgIHZhciByZXFMZW5ndGggPSBsZW5ndGggfHwgTWF0aC5tYXgoMSwgYnl0ZUxlbmd0aCk7XG4gICAgYXNzZXJ0KGJ5dGVMZW5ndGggPD0gcmVxTGVuZ3RoLCAnYnl0ZSBhcnJheSBsb25nZXIgdGhhbiBkZXNpcmVkIGxlbmd0aCcpO1xuICAgIGFzc2VydChyZXFMZW5ndGggPiAwLCAnUmVxdWVzdGVkIGFycmF5IGxlbmd0aCA8PSAwJyk7XG5cbiAgICB0aGlzLnN0cmlwKCk7XG4gICAgdmFyIGxpdHRsZUVuZGlhbiA9IGVuZGlhbiA9PT0gJ2xlJztcbiAgICB2YXIgcmVzID0gbmV3IEFycmF5VHlwZShyZXFMZW5ndGgpO1xuXG4gICAgdmFyIGIsIGk7XG4gICAgdmFyIHEgPSB0aGlzLmNsb25lKCk7XG4gICAgaWYgKCFsaXR0bGVFbmRpYW4pIHtcbiAgICAgIC8vIEFzc3VtZSBiaWctZW5kaWFuXG4gICAgICBmb3IgKGkgPSAwOyBpIDwgcmVxTGVuZ3RoIC0gYnl0ZUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHJlc1tpXSA9IDA7XG4gICAgICB9XG5cbiAgICAgIGZvciAoaSA9IDA7ICFxLmlzWmVybygpOyBpKyspIHtcbiAgICAgICAgYiA9IHEuYW5kbG4oMHhmZik7XG4gICAgICAgIHEuaXVzaHJuKDgpO1xuXG4gICAgICAgIHJlc1tyZXFMZW5ndGggLSBpIC0gMV0gPSBiO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGkgPSAwOyAhcS5pc1plcm8oKTsgaSsrKSB7XG4gICAgICAgIGIgPSBxLmFuZGxuKDB4ZmYpO1xuICAgICAgICBxLml1c2hybig4KTtcblxuICAgICAgICByZXNbaV0gPSBiO1xuICAgICAgfVxuXG4gICAgICBmb3IgKDsgaSA8IHJlcUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHJlc1tpXSA9IDA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICBpZiAoTWF0aC5jbHozMikge1xuICAgIEJOLnByb3RvdHlwZS5fY291bnRCaXRzID0gZnVuY3Rpb24gX2NvdW50Qml0cyAodykge1xuICAgICAgcmV0dXJuIDMyIC0gTWF0aC5jbHozMih3KTtcbiAgICB9O1xuICB9IGVsc2Uge1xuICAgIEJOLnByb3RvdHlwZS5fY291bnRCaXRzID0gZnVuY3Rpb24gX2NvdW50Qml0cyAodykge1xuICAgICAgdmFyIHQgPSB3O1xuICAgICAgdmFyIHIgPSAwO1xuICAgICAgaWYgKHQgPj0gMHgxMDAwKSB7XG4gICAgICAgIHIgKz0gMTM7XG4gICAgICAgIHQgPj4+PSAxMztcbiAgICAgIH1cbiAgICAgIGlmICh0ID49IDB4NDApIHtcbiAgICAgICAgciArPSA3O1xuICAgICAgICB0ID4+Pj0gNztcbiAgICAgIH1cbiAgICAgIGlmICh0ID49IDB4OCkge1xuICAgICAgICByICs9IDQ7XG4gICAgICAgIHQgPj4+PSA0O1xuICAgICAgfVxuICAgICAgaWYgKHQgPj0gMHgwMikge1xuICAgICAgICByICs9IDI7XG4gICAgICAgIHQgPj4+PSAyO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHIgKyB0O1xuICAgIH07XG4gIH1cblxuICBCTi5wcm90b3R5cGUuX3plcm9CaXRzID0gZnVuY3Rpb24gX3plcm9CaXRzICh3KSB7XG4gICAgLy8gU2hvcnQtY3V0XG4gICAgaWYgKHcgPT09IDApIHJldHVybiAyNjtcblxuICAgIHZhciB0ID0gdztcbiAgICB2YXIgciA9IDA7XG4gICAgaWYgKCh0ICYgMHgxZmZmKSA9PT0gMCkge1xuICAgICAgciArPSAxMztcbiAgICAgIHQgPj4+PSAxMztcbiAgICB9XG4gICAgaWYgKCh0ICYgMHg3ZikgPT09IDApIHtcbiAgICAgIHIgKz0gNztcbiAgICAgIHQgPj4+PSA3O1xuICAgIH1cbiAgICBpZiAoKHQgJiAweGYpID09PSAwKSB7XG4gICAgICByICs9IDQ7XG4gICAgICB0ID4+Pj0gNDtcbiAgICB9XG4gICAgaWYgKCh0ICYgMHgzKSA9PT0gMCkge1xuICAgICAgciArPSAyO1xuICAgICAgdCA+Pj49IDI7XG4gICAgfVxuICAgIGlmICgodCAmIDB4MSkgPT09IDApIHtcbiAgICAgIHIrKztcbiAgICB9XG4gICAgcmV0dXJuIHI7XG4gIH07XG5cbiAgLy8gUmV0dXJuIG51bWJlciBvZiB1c2VkIGJpdHMgaW4gYSBCTlxuICBCTi5wcm90b3R5cGUuYml0TGVuZ3RoID0gZnVuY3Rpb24gYml0TGVuZ3RoICgpIHtcbiAgICB2YXIgdyA9IHRoaXMud29yZHNbdGhpcy5sZW5ndGggLSAxXTtcbiAgICB2YXIgaGkgPSB0aGlzLl9jb3VudEJpdHModyk7XG4gICAgcmV0dXJuICh0aGlzLmxlbmd0aCAtIDEpICogMjYgKyBoaTtcbiAgfTtcblxuICBmdW5jdGlvbiB0b0JpdEFycmF5IChudW0pIHtcbiAgICB2YXIgdyA9IG5ldyBBcnJheShudW0uYml0TGVuZ3RoKCkpO1xuXG4gICAgZm9yICh2YXIgYml0ID0gMDsgYml0IDwgdy5sZW5ndGg7IGJpdCsrKSB7XG4gICAgICB2YXIgb2ZmID0gKGJpdCAvIDI2KSB8IDA7XG4gICAgICB2YXIgd2JpdCA9IGJpdCAlIDI2O1xuXG4gICAgICB3W2JpdF0gPSAobnVtLndvcmRzW29mZl0gJiAoMSA8PCB3Yml0KSkgPj4+IHdiaXQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIHc7XG4gIH1cblxuICAvLyBOdW1iZXIgb2YgdHJhaWxpbmcgemVybyBiaXRzXG4gIEJOLnByb3RvdHlwZS56ZXJvQml0cyA9IGZ1bmN0aW9uIHplcm9CaXRzICgpIHtcbiAgICBpZiAodGhpcy5pc1plcm8oKSkgcmV0dXJuIDA7XG5cbiAgICB2YXIgciA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgYiA9IHRoaXMuX3plcm9CaXRzKHRoaXMud29yZHNbaV0pO1xuICAgICAgciArPSBiO1xuICAgICAgaWYgKGIgIT09IDI2KSBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIHI7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmJ5dGVMZW5ndGggPSBmdW5jdGlvbiBieXRlTGVuZ3RoICgpIHtcbiAgICByZXR1cm4gTWF0aC5jZWlsKHRoaXMuYml0TGVuZ3RoKCkgLyA4KTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudG9Ud29zID0gZnVuY3Rpb24gdG9Ud29zICh3aWR0aCkge1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICByZXR1cm4gdGhpcy5hYnMoKS5pbm90bih3aWR0aCkuaWFkZG4oMSk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmNsb25lKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmZyb21Ud29zID0gZnVuY3Rpb24gZnJvbVR3b3MgKHdpZHRoKSB7XG4gICAgaWYgKHRoaXMudGVzdG4od2lkdGggLSAxKSkge1xuICAgICAgcmV0dXJuIHRoaXMubm90bih3aWR0aCkuaWFkZG4oMSkuaW5lZygpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pc05lZyA9IGZ1bmN0aW9uIGlzTmVnICgpIHtcbiAgICByZXR1cm4gdGhpcy5uZWdhdGl2ZSAhPT0gMDtcbiAgfTtcblxuICAvLyBSZXR1cm4gbmVnYXRpdmUgY2xvbmUgb2YgYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5uZWcgPSBmdW5jdGlvbiBuZWcgKCkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaW5lZygpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pbmVnID0gZnVuY3Rpb24gaW5lZyAoKSB7XG4gICAgaWYgKCF0aGlzLmlzWmVybygpKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlIF49IDE7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgLy8gT3IgYG51bWAgd2l0aCBgdGhpc2AgaW4tcGxhY2VcbiAgQk4ucHJvdG90eXBlLml1b3IgPSBmdW5jdGlvbiBpdW9yIChudW0pIHtcbiAgICB3aGlsZSAodGhpcy5sZW5ndGggPCBudW0ubGVuZ3RoKSB7XG4gICAgICB0aGlzLndvcmRzW3RoaXMubGVuZ3RoKytdID0gMDtcbiAgICB9XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG51bS5sZW5ndGg7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IHRoaXMud29yZHNbaV0gfCBudW0ud29yZHNbaV07XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaW9yID0gZnVuY3Rpb24gaW9yIChudW0pIHtcbiAgICBhc3NlcnQoKHRoaXMubmVnYXRpdmUgfCBudW0ubmVnYXRpdmUpID09PSAwKTtcbiAgICByZXR1cm4gdGhpcy5pdW9yKG51bSk7XG4gIH07XG5cbiAgLy8gT3IgYG51bWAgd2l0aCBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLm9yID0gZnVuY3Rpb24gb3IgKG51bSkge1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaW9yKG51bSk7XG4gICAgcmV0dXJuIG51bS5jbG9uZSgpLmlvcih0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudW9yID0gZnVuY3Rpb24gdW9yIChudW0pIHtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSByZXR1cm4gdGhpcy5jbG9uZSgpLml1b3IobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaXVvcih0aGlzKTtcbiAgfTtcblxuICAvLyBBbmQgYG51bWAgd2l0aCBgdGhpc2AgaW4tcGxhY2VcbiAgQk4ucHJvdG90eXBlLml1YW5kID0gZnVuY3Rpb24gaXVhbmQgKG51bSkge1xuICAgIC8vIGIgPSBtaW4tbGVuZ3RoKG51bSwgdGhpcylcbiAgICB2YXIgYjtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSB7XG4gICAgICBiID0gbnVtO1xuICAgIH0gZWxzZSB7XG4gICAgICBiID0gdGhpcztcbiAgICB9XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGIubGVuZ3RoOyBpKyspIHtcbiAgICAgIHRoaXMud29yZHNbaV0gPSB0aGlzLndvcmRzW2ldICYgbnVtLndvcmRzW2ldO1xuICAgIH1cblxuICAgIHRoaXMubGVuZ3RoID0gYi5sZW5ndGg7XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pYW5kID0gZnVuY3Rpb24gaWFuZCAobnVtKSB7XG4gICAgYXNzZXJ0KCh0aGlzLm5lZ2F0aXZlIHwgbnVtLm5lZ2F0aXZlKSA9PT0gMCk7XG4gICAgcmV0dXJuIHRoaXMuaXVhbmQobnVtKTtcbiAgfTtcblxuICAvLyBBbmQgYG51bWAgd2l0aCBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLmFuZCA9IGZ1bmN0aW9uIGFuZCAobnVtKSB7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkgcmV0dXJuIHRoaXMuY2xvbmUoKS5pYW5kKG51bSk7XG4gICAgcmV0dXJuIG51bS5jbG9uZSgpLmlhbmQodGhpcyk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnVhbmQgPSBmdW5jdGlvbiB1YW5kIChudW0pIHtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSByZXR1cm4gdGhpcy5jbG9uZSgpLml1YW5kKG51bSk7XG4gICAgcmV0dXJuIG51bS5jbG9uZSgpLml1YW5kKHRoaXMpO1xuICB9O1xuXG4gIC8vIFhvciBgbnVtYCB3aXRoIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXV4b3IgPSBmdW5jdGlvbiBpdXhvciAobnVtKSB7XG4gICAgLy8gYS5sZW5ndGggPiBiLmxlbmd0aFxuICAgIHZhciBhO1xuICAgIHZhciBiO1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHtcbiAgICAgIGEgPSB0aGlzO1xuICAgICAgYiA9IG51bTtcbiAgICB9IGVsc2Uge1xuICAgICAgYSA9IG51bTtcbiAgICAgIGIgPSB0aGlzO1xuICAgIH1cblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYi5sZW5ndGg7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IGEud29yZHNbaV0gXiBiLndvcmRzW2ldO1xuICAgIH1cblxuICAgIGlmICh0aGlzICE9PSBhKSB7XG4gICAgICBmb3IgKDsgaSA8IGEubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpXSA9IGEud29yZHNbaV07XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5sZW5ndGggPSBhLmxlbmd0aDtcblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLml4b3IgPSBmdW5jdGlvbiBpeG9yIChudW0pIHtcbiAgICBhc3NlcnQoKHRoaXMubmVnYXRpdmUgfCBudW0ubmVnYXRpdmUpID09PSAwKTtcbiAgICByZXR1cm4gdGhpcy5pdXhvcihudW0pO1xuICB9O1xuXG4gIC8vIFhvciBgbnVtYCB3aXRoIGB0aGlzYFxuICBCTi5wcm90b3R5cGUueG9yID0gZnVuY3Rpb24geG9yIChudW0pIHtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSByZXR1cm4gdGhpcy5jbG9uZSgpLml4b3IobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaXhvcih0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudXhvciA9IGZ1bmN0aW9uIHV4b3IgKG51bSkge1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaXV4b3IobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaXV4b3IodGhpcyk7XG4gIH07XG5cbiAgLy8gTm90IGBgdGhpc2BgIHdpdGggYGB3aWR0aGBgIGJpdHdpZHRoXG4gIEJOLnByb3RvdHlwZS5pbm90biA9IGZ1bmN0aW9uIGlub3RuICh3aWR0aCkge1xuICAgIGFzc2VydCh0eXBlb2Ygd2lkdGggPT09ICdudW1iZXInICYmIHdpZHRoID49IDApO1xuXG4gICAgdmFyIGJ5dGVzTmVlZGVkID0gTWF0aC5jZWlsKHdpZHRoIC8gMjYpIHwgMDtcbiAgICB2YXIgYml0c0xlZnQgPSB3aWR0aCAlIDI2O1xuXG4gICAgLy8gRXh0ZW5kIHRoZSBidWZmZXIgd2l0aCBsZWFkaW5nIHplcm9lc1xuICAgIHRoaXMuX2V4cGFuZChieXRlc05lZWRlZCk7XG5cbiAgICBpZiAoYml0c0xlZnQgPiAwKSB7XG4gICAgICBieXRlc05lZWRlZC0tO1xuICAgIH1cblxuICAgIC8vIEhhbmRsZSBjb21wbGV0ZSB3b3Jkc1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZXNOZWVkZWQ7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IH50aGlzLndvcmRzW2ldICYgMHgzZmZmZmZmO1xuICAgIH1cblxuICAgIC8vIEhhbmRsZSB0aGUgcmVzaWR1ZVxuICAgIGlmIChiaXRzTGVmdCA+IDApIHtcbiAgICAgIHRoaXMud29yZHNbaV0gPSB+dGhpcy53b3Jkc1tpXSAmICgweDNmZmZmZmYgPj4gKDI2IC0gYml0c0xlZnQpKTtcbiAgICB9XG5cbiAgICAvLyBBbmQgcmVtb3ZlIGxlYWRpbmcgemVyb2VzXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUubm90biA9IGZ1bmN0aW9uIG5vdG4gKHdpZHRoKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pbm90bih3aWR0aCk7XG4gIH07XG5cbiAgLy8gU2V0IGBiaXRgIG9mIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuc2V0biA9IGZ1bmN0aW9uIHNldG4gKGJpdCwgdmFsKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBiaXQgPT09ICdudW1iZXInICYmIGJpdCA+PSAwKTtcblxuICAgIHZhciBvZmYgPSAoYml0IC8gMjYpIHwgMDtcbiAgICB2YXIgd2JpdCA9IGJpdCAlIDI2O1xuXG4gICAgdGhpcy5fZXhwYW5kKG9mZiArIDEpO1xuXG4gICAgaWYgKHZhbCkge1xuICAgICAgdGhpcy53b3Jkc1tvZmZdID0gdGhpcy53b3Jkc1tvZmZdIHwgKDEgPDwgd2JpdCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMud29yZHNbb2ZmXSA9IHRoaXMud29yZHNbb2ZmXSAmIH4oMSA8PCB3Yml0KTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIC8vIEFkZCBgbnVtYCB0byBgdGhpc2AgaW4tcGxhY2VcbiAgQk4ucHJvdG90eXBlLmlhZGQgPSBmdW5jdGlvbiBpYWRkIChudW0pIHtcbiAgICB2YXIgcjtcblxuICAgIC8vIG5lZ2F0aXZlICsgcG9zaXRpdmVcbiAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCAmJiBudW0ubmVnYXRpdmUgPT09IDApIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAwO1xuICAgICAgciA9IHRoaXMuaXN1YihudW0pO1xuICAgICAgdGhpcy5uZWdhdGl2ZSBePSAxO1xuICAgICAgcmV0dXJuIHRoaXMuX25vcm1TaWduKCk7XG5cbiAgICAvLyBwb3NpdGl2ZSArIG5lZ2F0aXZlXG4gICAgfSBlbHNlIGlmICh0aGlzLm5lZ2F0aXZlID09PSAwICYmIG51bS5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgbnVtLm5lZ2F0aXZlID0gMDtcbiAgICAgIHIgPSB0aGlzLmlzdWIobnVtKTtcbiAgICAgIG51bS5uZWdhdGl2ZSA9IDE7XG4gICAgICByZXR1cm4gci5fbm9ybVNpZ24oKTtcbiAgICB9XG5cbiAgICAvLyBhLmxlbmd0aCA+IGIubGVuZ3RoXG4gICAgdmFyIGEsIGI7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkge1xuICAgICAgYSA9IHRoaXM7XG4gICAgICBiID0gbnVtO1xuICAgIH0gZWxzZSB7XG4gICAgICBhID0gbnVtO1xuICAgICAgYiA9IHRoaXM7XG4gICAgfVxuXG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGIubGVuZ3RoOyBpKyspIHtcbiAgICAgIHIgPSAoYS53b3Jkc1tpXSB8IDApICsgKGIud29yZHNbaV0gfCAwKSArIGNhcnJ5O1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IHIgJiAweDNmZmZmZmY7XG4gICAgICBjYXJyeSA9IHIgPj4+IDI2O1xuICAgIH1cbiAgICBmb3IgKDsgY2FycnkgIT09IDAgJiYgaSA8IGEubGVuZ3RoOyBpKyspIHtcbiAgICAgIHIgPSAoYS53b3Jkc1tpXSB8IDApICsgY2Fycnk7XG4gICAgICB0aGlzLndvcmRzW2ldID0gciAmIDB4M2ZmZmZmZjtcbiAgICAgIGNhcnJ5ID0gciA+Pj4gMjY7XG4gICAgfVxuXG4gICAgdGhpcy5sZW5ndGggPSBhLmxlbmd0aDtcbiAgICBpZiAoY2FycnkgIT09IDApIHtcbiAgICAgIHRoaXMud29yZHNbdGhpcy5sZW5ndGhdID0gY2Fycnk7XG4gICAgICB0aGlzLmxlbmd0aCsrO1xuICAgIC8vIENvcHkgdGhlIHJlc3Qgb2YgdGhlIHdvcmRzXG4gICAgfSBlbHNlIGlmIChhICE9PSB0aGlzKSB7XG4gICAgICBmb3IgKDsgaSA8IGEubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpXSA9IGEud29yZHNbaV07XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgLy8gQWRkIGBudW1gIHRvIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuYWRkID0gZnVuY3Rpb24gYWRkIChudW0pIHtcbiAgICB2YXIgcmVzO1xuICAgIGlmIChudW0ubmVnYXRpdmUgIT09IDAgJiYgdGhpcy5uZWdhdGl2ZSA9PT0gMCkge1xuICAgICAgbnVtLm5lZ2F0aXZlID0gMDtcbiAgICAgIHJlcyA9IHRoaXMuc3ViKG51bSk7XG4gICAgICBudW0ubmVnYXRpdmUgXj0gMTtcbiAgICAgIHJldHVybiByZXM7XG4gICAgfSBlbHNlIGlmIChudW0ubmVnYXRpdmUgPT09IDAgJiYgdGhpcy5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgICByZXMgPSBudW0uc3ViKHRoaXMpO1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG4gICAgICByZXR1cm4gcmVzO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaWFkZChudW0pO1xuXG4gICAgcmV0dXJuIG51bS5jbG9uZSgpLmlhZGQodGhpcyk7XG4gIH07XG5cbiAgLy8gU3VidHJhY3QgYG51bWAgZnJvbSBgdGhpc2AgaW4tcGxhY2VcbiAgQk4ucHJvdG90eXBlLmlzdWIgPSBmdW5jdGlvbiBpc3ViIChudW0pIHtcbiAgICAvLyB0aGlzIC0gKC1udW0pID0gdGhpcyArIG51bVxuICAgIGlmIChudW0ubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIG51bS5uZWdhdGl2ZSA9IDA7XG4gICAgICB2YXIgciA9IHRoaXMuaWFkZChudW0pO1xuICAgICAgbnVtLm5lZ2F0aXZlID0gMTtcbiAgICAgIHJldHVybiByLl9ub3JtU2lnbigpO1xuXG4gICAgLy8gLXRoaXMgLSBudW0gPSAtKHRoaXMgKyBudW0pXG4gICAgfSBlbHNlIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgIHRoaXMuaWFkZChudW0pO1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG4gICAgICByZXR1cm4gdGhpcy5fbm9ybVNpZ24oKTtcbiAgICB9XG5cbiAgICAvLyBBdCB0aGlzIHBvaW50IGJvdGggbnVtYmVycyBhcmUgcG9zaXRpdmVcbiAgICB2YXIgY21wID0gdGhpcy5jbXAobnVtKTtcblxuICAgIC8vIE9wdGltaXphdGlvbiAtIHplcm9pZnlcbiAgICBpZiAoY21wID09PSAwKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgIHRoaXMubGVuZ3RoID0gMTtcbiAgICAgIHRoaXMud29yZHNbMF0gPSAwO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgLy8gYSA+IGJcbiAgICB2YXIgYSwgYjtcbiAgICBpZiAoY21wID4gMCkge1xuICAgICAgYSA9IHRoaXM7XG4gICAgICBiID0gbnVtO1xuICAgIH0gZWxzZSB7XG4gICAgICBhID0gbnVtO1xuICAgICAgYiA9IHRoaXM7XG4gICAgfVxuXG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGIubGVuZ3RoOyBpKyspIHtcbiAgICAgIHIgPSAoYS53b3Jkc1tpXSB8IDApIC0gKGIud29yZHNbaV0gfCAwKSArIGNhcnJ5O1xuICAgICAgY2FycnkgPSByID4+IDI2O1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IHIgJiAweDNmZmZmZmY7XG4gICAgfVxuICAgIGZvciAoOyBjYXJyeSAhPT0gMCAmJiBpIDwgYS5sZW5ndGg7IGkrKykge1xuICAgICAgciA9IChhLndvcmRzW2ldIHwgMCkgKyBjYXJyeTtcbiAgICAgIGNhcnJ5ID0gciA+PiAyNjtcbiAgICAgIHRoaXMud29yZHNbaV0gPSByICYgMHgzZmZmZmZmO1xuICAgIH1cblxuICAgIC8vIENvcHkgcmVzdCBvZiB0aGUgd29yZHNcbiAgICBpZiAoY2FycnkgPT09IDAgJiYgaSA8IGEubGVuZ3RoICYmIGEgIT09IHRoaXMpIHtcbiAgICAgIGZvciAoOyBpIDwgYS5sZW5ndGg7IGkrKykge1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gYS53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aGlzLmxlbmd0aCA9IE1hdGgubWF4KHRoaXMubGVuZ3RoLCBpKTtcblxuICAgIGlmIChhICE9PSB0aGlzKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIC8vIFN1YnRyYWN0IGBudW1gIGZyb20gYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5zdWIgPSBmdW5jdGlvbiBzdWIgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaXN1YihudW0pO1xuICB9O1xuXG4gIGZ1bmN0aW9uIHNtYWxsTXVsVG8gKHNlbGYsIG51bSwgb3V0KSB7XG4gICAgb3V0Lm5lZ2F0aXZlID0gbnVtLm5lZ2F0aXZlIF4gc2VsZi5uZWdhdGl2ZTtcbiAgICB2YXIgbGVuID0gKHNlbGYubGVuZ3RoICsgbnVtLmxlbmd0aCkgfCAwO1xuICAgIG91dC5sZW5ndGggPSBsZW47XG4gICAgbGVuID0gKGxlbiAtIDEpIHwgMDtcblxuICAgIC8vIFBlZWwgb25lIGl0ZXJhdGlvbiAoY29tcGlsZXIgY2FuJ3QgZG8gaXQsIGJlY2F1c2Ugb2YgY29kZSBjb21wbGV4aXR5KVxuICAgIHZhciBhID0gc2VsZi53b3Jkc1swXSB8IDA7XG4gICAgdmFyIGIgPSBudW0ud29yZHNbMF0gfCAwO1xuICAgIHZhciByID0gYSAqIGI7XG5cbiAgICB2YXIgbG8gPSByICYgMHgzZmZmZmZmO1xuICAgIHZhciBjYXJyeSA9IChyIC8gMHg0MDAwMDAwKSB8IDA7XG4gICAgb3V0LndvcmRzWzBdID0gbG87XG5cbiAgICBmb3IgKHZhciBrID0gMTsgayA8IGxlbjsgaysrKSB7XG4gICAgICAvLyBTdW0gYWxsIHdvcmRzIHdpdGggdGhlIHNhbWUgYGkgKyBqID0ga2AgYW5kIGFjY3VtdWxhdGUgYG5jYXJyeWAsXG4gICAgICAvLyBub3RlIHRoYXQgbmNhcnJ5IGNvdWxkIGJlID49IDB4M2ZmZmZmZlxuICAgICAgdmFyIG5jYXJyeSA9IGNhcnJ5ID4+PiAyNjtcbiAgICAgIHZhciByd29yZCA9IGNhcnJ5ICYgMHgzZmZmZmZmO1xuICAgICAgdmFyIG1heEogPSBNYXRoLm1pbihrLCBudW0ubGVuZ3RoIC0gMSk7XG4gICAgICBmb3IgKHZhciBqID0gTWF0aC5tYXgoMCwgayAtIHNlbGYubGVuZ3RoICsgMSk7IGogPD0gbWF4SjsgaisrKSB7XG4gICAgICAgIHZhciBpID0gKGsgLSBqKSB8IDA7XG4gICAgICAgIGEgPSBzZWxmLndvcmRzW2ldIHwgMDtcbiAgICAgICAgYiA9IG51bS53b3Jkc1tqXSB8IDA7XG4gICAgICAgIHIgPSBhICogYiArIHJ3b3JkO1xuICAgICAgICBuY2FycnkgKz0gKHIgLyAweDQwMDAwMDApIHwgMDtcbiAgICAgICAgcndvcmQgPSByICYgMHgzZmZmZmZmO1xuICAgICAgfVxuICAgICAgb3V0LndvcmRzW2tdID0gcndvcmQgfCAwO1xuICAgICAgY2FycnkgPSBuY2FycnkgfCAwO1xuICAgIH1cbiAgICBpZiAoY2FycnkgIT09IDApIHtcbiAgICAgIG91dC53b3Jkc1trXSA9IGNhcnJ5IHwgMDtcbiAgICB9IGVsc2Uge1xuICAgICAgb3V0Lmxlbmd0aC0tO1xuICAgIH1cblxuICAgIHJldHVybiBvdXQuc3RyaXAoKTtcbiAgfVxuXG4gIC8vIFRPRE8oaW5kdXRueSk6IGl0IG1heSBiZSByZWFzb25hYmxlIHRvIG9taXQgaXQgZm9yIHVzZXJzIHdobyBkb24ndCBuZWVkXG4gIC8vIHRvIHdvcmsgd2l0aCAyNTYtYml0IG51bWJlcnMsIG90aGVyd2lzZSBpdCBnaXZlcyAyMCUgaW1wcm92ZW1lbnQgZm9yIDI1Ni1iaXRcbiAgLy8gbXVsdGlwbGljYXRpb24gKGxpa2UgZWxsaXB0aWMgc2VjcDI1NmsxKS5cbiAgdmFyIGNvbWIxME11bFRvID0gZnVuY3Rpb24gY29tYjEwTXVsVG8gKHNlbGYsIG51bSwgb3V0KSB7XG4gICAgdmFyIGEgPSBzZWxmLndvcmRzO1xuICAgIHZhciBiID0gbnVtLndvcmRzO1xuICAgIHZhciBvID0gb3V0LndvcmRzO1xuICAgIHZhciBjID0gMDtcbiAgICB2YXIgbG87XG4gICAgdmFyIG1pZDtcbiAgICB2YXIgaGk7XG4gICAgdmFyIGEwID0gYVswXSB8IDA7XG4gICAgdmFyIGFsMCA9IGEwICYgMHgxZmZmO1xuICAgIHZhciBhaDAgPSBhMCA+Pj4gMTM7XG4gICAgdmFyIGExID0gYVsxXSB8IDA7XG4gICAgdmFyIGFsMSA9IGExICYgMHgxZmZmO1xuICAgIHZhciBhaDEgPSBhMSA+Pj4gMTM7XG4gICAgdmFyIGEyID0gYVsyXSB8IDA7XG4gICAgdmFyIGFsMiA9IGEyICYgMHgxZmZmO1xuICAgIHZhciBhaDIgPSBhMiA+Pj4gMTM7XG4gICAgdmFyIGEzID0gYVszXSB8IDA7XG4gICAgdmFyIGFsMyA9IGEzICYgMHgxZmZmO1xuICAgIHZhciBhaDMgPSBhMyA+Pj4gMTM7XG4gICAgdmFyIGE0ID0gYVs0XSB8IDA7XG4gICAgdmFyIGFsNCA9IGE0ICYgMHgxZmZmO1xuICAgIHZhciBhaDQgPSBhNCA+Pj4gMTM7XG4gICAgdmFyIGE1ID0gYVs1XSB8IDA7XG4gICAgdmFyIGFsNSA9IGE1ICYgMHgxZmZmO1xuICAgIHZhciBhaDUgPSBhNSA+Pj4gMTM7XG4gICAgdmFyIGE2ID0gYVs2XSB8IDA7XG4gICAgdmFyIGFsNiA9IGE2ICYgMHgxZmZmO1xuICAgIHZhciBhaDYgPSBhNiA+Pj4gMTM7XG4gICAgdmFyIGE3ID0gYVs3XSB8IDA7XG4gICAgdmFyIGFsNyA9IGE3ICYgMHgxZmZmO1xuICAgIHZhciBhaDcgPSBhNyA+Pj4gMTM7XG4gICAgdmFyIGE4ID0gYVs4XSB8IDA7XG4gICAgdmFyIGFsOCA9IGE4ICYgMHgxZmZmO1xuICAgIHZhciBhaDggPSBhOCA+Pj4gMTM7XG4gICAgdmFyIGE5ID0gYVs5XSB8IDA7XG4gICAgdmFyIGFsOSA9IGE5ICYgMHgxZmZmO1xuICAgIHZhciBhaDkgPSBhOSA+Pj4gMTM7XG4gICAgdmFyIGIwID0gYlswXSB8IDA7XG4gICAgdmFyIGJsMCA9IGIwICYgMHgxZmZmO1xuICAgIHZhciBiaDAgPSBiMCA+Pj4gMTM7XG4gICAgdmFyIGIxID0gYlsxXSB8IDA7XG4gICAgdmFyIGJsMSA9IGIxICYgMHgxZmZmO1xuICAgIHZhciBiaDEgPSBiMSA+Pj4gMTM7XG4gICAgdmFyIGIyID0gYlsyXSB8IDA7XG4gICAgdmFyIGJsMiA9IGIyICYgMHgxZmZmO1xuICAgIHZhciBiaDIgPSBiMiA+Pj4gMTM7XG4gICAgdmFyIGIzID0gYlszXSB8IDA7XG4gICAgdmFyIGJsMyA9IGIzICYgMHgxZmZmO1xuICAgIHZhciBiaDMgPSBiMyA+Pj4gMTM7XG4gICAgdmFyIGI0ID0gYls0XSB8IDA7XG4gICAgdmFyIGJsNCA9IGI0ICYgMHgxZmZmO1xuICAgIHZhciBiaDQgPSBiNCA+Pj4gMTM7XG4gICAgdmFyIGI1ID0gYls1XSB8IDA7XG4gICAgdmFyIGJsNSA9IGI1ICYgMHgxZmZmO1xuICAgIHZhciBiaDUgPSBiNSA+Pj4gMTM7XG4gICAgdmFyIGI2ID0gYls2XSB8IDA7XG4gICAgdmFyIGJsNiA9IGI2ICYgMHgxZmZmO1xuICAgIHZhciBiaDYgPSBiNiA+Pj4gMTM7XG4gICAgdmFyIGI3ID0gYls3XSB8IDA7XG4gICAgdmFyIGJsNyA9IGI3ICYgMHgxZmZmO1xuICAgIHZhciBiaDcgPSBiNyA+Pj4gMTM7XG4gICAgdmFyIGI4ID0gYls4XSB8IDA7XG4gICAgdmFyIGJsOCA9IGI4ICYgMHgxZmZmO1xuICAgIHZhciBiaDggPSBiOCA+Pj4gMTM7XG4gICAgdmFyIGI5ID0gYls5XSB8IDA7XG4gICAgdmFyIGJsOSA9IGI5ICYgMHgxZmZmO1xuICAgIHZhciBiaDkgPSBiOSA+Pj4gMTM7XG5cbiAgICBvdXQubmVnYXRpdmUgPSBzZWxmLm5lZ2F0aXZlIF4gbnVtLm5lZ2F0aXZlO1xuICAgIG91dC5sZW5ndGggPSAxOTtcbiAgICAvKiBrID0gMCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsMCwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWwwLCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgwLCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoMCwgYmgwKTtcbiAgICB2YXIgdzAgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MCA+Pj4gMjYpO1xuICAgIHcwICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMSAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsMSwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWwxLCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoMSwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwwLCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwwLCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgwLCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDAsIGJoMSk7XG4gICAgdmFyIHcxID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzEgPj4+IDI2KTtcbiAgICB3MSAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDIgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDIsIGJsMCk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsMiwgYmgwKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMiwgYmwwKTtcbiAgICBoaSA9IE1hdGguaW11bChhaDIsIGJoMCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmwxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmgxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmwxKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDEpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsMik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmgyKTtcbiAgICB2YXIgdzIgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MiA+Pj4gMjYpO1xuICAgIHcyICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMyAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsMywgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWwzLCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgzLCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoMywgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmgzKTtcbiAgICB2YXIgdzMgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MyA+Pj4gMjYpO1xuICAgIHczICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gNCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsNCwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw0LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoNCwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwzLCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwzLCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgzLCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDMsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMiwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMiwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMiwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgyLCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDEsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDEsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDEsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMSwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwwLCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwwLCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgwLCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDAsIGJoNCk7XG4gICAgdmFyIHc0ID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzQgPj4+IDI2KTtcbiAgICB3NCAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDUgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDUsIGJsMCk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsNSwgYmgwKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmwwKTtcbiAgICBoaSA9IE1hdGguaW11bChhaDUsIGJoMCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmwxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmgxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmwxKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDEpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsMik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmgyKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDMpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoMyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw0KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDQpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsNSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg1KTtcbiAgICB2YXIgdzUgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3NSA+Pj4gMjYpO1xuICAgIHc1ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gNiAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsNiwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw2LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoNiwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg2KTtcbiAgICB2YXIgdzYgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3NiA+Pj4gMjYpO1xuICAgIHc2ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gNyAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsNywgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw3LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg3LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoNywgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw2LCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw2LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDYsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNSwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNSwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg1LCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDQsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDQsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDQsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNCwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwzLCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwzLCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgzLCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDMsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMiwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMiwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMiwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgyLCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDEsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDEsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDEsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMSwgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwwLCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwwLCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgwLCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDAsIGJoNyk7XG4gICAgdmFyIHc3ID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzcgPj4+IDI2KTtcbiAgICB3NyAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDggKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDgsIGJsMCk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOCwgYmgwKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmwwKTtcbiAgICBoaSA9IE1hdGguaW11bChhaDgsIGJoMCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmwxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmgxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmwxKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDEpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoMik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsMik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmgyKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDMpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoMyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw0KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDQpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsNSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg1KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDYpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoNik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw3KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDcpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsOCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg4KTtcbiAgICB2YXIgdzggPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3OCA+Pj4gMjYpO1xuICAgIHc4ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gOSAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg5KTtcbiAgICB2YXIgdzkgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3OSA+Pj4gMjYpO1xuICAgIHc5ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTAgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsMSk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmgxKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmwxKTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDcsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDcsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNywgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw2LCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw2LCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDYsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNSwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNSwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg1LCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDQsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDQsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDQsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNCwgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwzLCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwzLCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgzLCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDMsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMiwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMiwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMiwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgyLCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDEsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDEsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDEsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMSwgYmg5KTtcbiAgICB2YXIgdzEwID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzEwID4+PiAyNik7XG4gICAgdzEwICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTEgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsMik7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmwyKTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDcsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDcsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNywgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw2LCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw2LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDYsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNSwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNSwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg1LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDQsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDQsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDQsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNCwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwzLCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwzLCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgzLCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDMsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMiwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMiwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMiwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgyLCBiaDkpO1xuICAgIHZhciB3MTEgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTEgPj4+IDI2KTtcbiAgICB3MTEgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxMiAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmwzKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDMpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg5KTtcbiAgICB2YXIgdzEyID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzEyID4+PiAyNik7XG4gICAgdzEyICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTMgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsNCk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmg0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmw0KTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDcsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDcsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNywgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw2LCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw2LCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDYsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNSwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNSwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg1LCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDQsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDQsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDQsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNCwgYmg5KTtcbiAgICB2YXIgdzEzID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzEzID4+PiAyNik7XG4gICAgdzEzICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTQgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsNSk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmw1KTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDcsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDcsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNywgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw2LCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw2LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg2LCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDYsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNSwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNSwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNSwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg1LCBiaDkpO1xuICAgIHZhciB3MTQgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTQgPj4+IDI2KTtcbiAgICB3MTQgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxNSAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw2KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDYpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg5KTtcbiAgICB2YXIgdzE1ID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzE1ID4+PiAyNik7XG4gICAgdzE1ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTYgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsNyk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmg3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmw3KTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDgpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDcsIGJsOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDcsIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsOSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNywgYmg5KTtcbiAgICB2YXIgdzE2ID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzE2ID4+PiAyNik7XG4gICAgdzE2ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMTcgKi9cbiAgICBsbyA9IE1hdGguaW11bChhbDksIGJsOCk7XG4gICAgbWlkID0gTWF0aC5pbXVsKGFsOSwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOSwgYmw4KTtcbiAgICBoaSA9IE1hdGguaW11bChhaDksIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsOCwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsOCwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoOCwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg4LCBiaDkpO1xuICAgIHZhciB3MTcgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTcgPj4+IDI2KTtcbiAgICB3MTcgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxOCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw5KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDkpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg5KTtcbiAgICB2YXIgdzE4ID0gYyArIGxvICsgKChtaWQgJiAweDFmZmYpIDw8IDEzKTtcbiAgICBjID0gaGkgKyAobWlkID4+PiAxMykgKyAodzE4ID4+PiAyNik7XG4gICAgdzE4ICY9IDB4M2ZmZmZmZjtcbiAgICBvWzBdID0gdzA7XG4gICAgb1sxXSA9IHcxO1xuICAgIG9bMl0gPSB3MjtcbiAgICBvWzNdID0gdzM7XG4gICAgb1s0XSA9IHc0O1xuICAgIG9bNV0gPSB3NTtcbiAgICBvWzZdID0gdzY7XG4gICAgb1s3XSA9IHc3O1xuICAgIG9bOF0gPSB3ODtcbiAgICBvWzldID0gdzk7XG4gICAgb1sxMF0gPSB3MTA7XG4gICAgb1sxMV0gPSB3MTE7XG4gICAgb1sxMl0gPSB3MTI7XG4gICAgb1sxM10gPSB3MTM7XG4gICAgb1sxNF0gPSB3MTQ7XG4gICAgb1sxNV0gPSB3MTU7XG4gICAgb1sxNl0gPSB3MTY7XG4gICAgb1sxN10gPSB3MTc7XG4gICAgb1sxOF0gPSB3MTg7XG4gICAgaWYgKGMgIT09IDApIHtcbiAgICAgIG9bMTldID0gYztcbiAgICAgIG91dC5sZW5ndGgrKztcbiAgICB9XG4gICAgcmV0dXJuIG91dDtcbiAgfTtcblxuICAvLyBQb2x5ZmlsbCBjb21iXG4gIGlmICghTWF0aC5pbXVsKSB7XG4gICAgY29tYjEwTXVsVG8gPSBzbWFsbE11bFRvO1xuICB9XG5cbiAgZnVuY3Rpb24gYmlnTXVsVG8gKHNlbGYsIG51bSwgb3V0KSB7XG4gICAgb3V0Lm5lZ2F0aXZlID0gbnVtLm5lZ2F0aXZlIF4gc2VsZi5uZWdhdGl2ZTtcbiAgICBvdXQubGVuZ3RoID0gc2VsZi5sZW5ndGggKyBudW0ubGVuZ3RoO1xuXG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICB2YXIgaG5jYXJyeSA9IDA7XG4gICAgZm9yICh2YXIgayA9IDA7IGsgPCBvdXQubGVuZ3RoIC0gMTsgaysrKSB7XG4gICAgICAvLyBTdW0gYWxsIHdvcmRzIHdpdGggdGhlIHNhbWUgYGkgKyBqID0ga2AgYW5kIGFjY3VtdWxhdGUgYG5jYXJyeWAsXG4gICAgICAvLyBub3RlIHRoYXQgbmNhcnJ5IGNvdWxkIGJlID49IDB4M2ZmZmZmZlxuICAgICAgdmFyIG5jYXJyeSA9IGhuY2Fycnk7XG4gICAgICBobmNhcnJ5ID0gMDtcbiAgICAgIHZhciByd29yZCA9IGNhcnJ5ICYgMHgzZmZmZmZmO1xuICAgICAgdmFyIG1heEogPSBNYXRoLm1pbihrLCBudW0ubGVuZ3RoIC0gMSk7XG4gICAgICBmb3IgKHZhciBqID0gTWF0aC5tYXgoMCwgayAtIHNlbGYubGVuZ3RoICsgMSk7IGogPD0gbWF4SjsgaisrKSB7XG4gICAgICAgIHZhciBpID0gayAtIGo7XG4gICAgICAgIHZhciBhID0gc2VsZi53b3Jkc1tpXSB8IDA7XG4gICAgICAgIHZhciBiID0gbnVtLndvcmRzW2pdIHwgMDtcbiAgICAgICAgdmFyIHIgPSBhICogYjtcblxuICAgICAgICB2YXIgbG8gPSByICYgMHgzZmZmZmZmO1xuICAgICAgICBuY2FycnkgPSAobmNhcnJ5ICsgKChyIC8gMHg0MDAwMDAwKSB8IDApKSB8IDA7XG4gICAgICAgIGxvID0gKGxvICsgcndvcmQpIHwgMDtcbiAgICAgICAgcndvcmQgPSBsbyAmIDB4M2ZmZmZmZjtcbiAgICAgICAgbmNhcnJ5ID0gKG5jYXJyeSArIChsbyA+Pj4gMjYpKSB8IDA7XG5cbiAgICAgICAgaG5jYXJyeSArPSBuY2FycnkgPj4+IDI2O1xuICAgICAgICBuY2FycnkgJj0gMHgzZmZmZmZmO1xuICAgICAgfVxuICAgICAgb3V0LndvcmRzW2tdID0gcndvcmQ7XG4gICAgICBjYXJyeSA9IG5jYXJyeTtcbiAgICAgIG5jYXJyeSA9IGhuY2Fycnk7XG4gICAgfVxuICAgIGlmIChjYXJyeSAhPT0gMCkge1xuICAgICAgb3V0LndvcmRzW2tdID0gY2Fycnk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG91dC5sZW5ndGgtLTtcbiAgICB9XG5cbiAgICByZXR1cm4gb3V0LnN0cmlwKCk7XG4gIH1cblxuICBmdW5jdGlvbiBqdW1ib011bFRvIChzZWxmLCBudW0sIG91dCkge1xuICAgIHZhciBmZnRtID0gbmV3IEZGVE0oKTtcbiAgICByZXR1cm4gZmZ0bS5tdWxwKHNlbGYsIG51bSwgb3V0KTtcbiAgfVxuXG4gIEJOLnByb3RvdHlwZS5tdWxUbyA9IGZ1bmN0aW9uIG11bFRvIChudW0sIG91dCkge1xuICAgIHZhciByZXM7XG4gICAgdmFyIGxlbiA9IHRoaXMubGVuZ3RoICsgbnVtLmxlbmd0aDtcbiAgICBpZiAodGhpcy5sZW5ndGggPT09IDEwICYmIG51bS5sZW5ndGggPT09IDEwKSB7XG4gICAgICByZXMgPSBjb21iMTBNdWxUbyh0aGlzLCBudW0sIG91dCk7XG4gICAgfSBlbHNlIGlmIChsZW4gPCA2Mykge1xuICAgICAgcmVzID0gc21hbGxNdWxUbyh0aGlzLCBudW0sIG91dCk7XG4gICAgfSBlbHNlIGlmIChsZW4gPCAxMDI0KSB7XG4gICAgICByZXMgPSBiaWdNdWxUbyh0aGlzLCBudW0sIG91dCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcyA9IGp1bWJvTXVsVG8odGhpcywgbnVtLCBvdXQpO1xuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgLy8gQ29vbGV5LVR1a2V5IGFsZ29yaXRobSBmb3IgRkZUXG4gIC8vIHNsaWdodGx5IHJldmlzaXRlZCB0byByZWx5IG9uIGxvb3BpbmcgaW5zdGVhZCBvZiByZWN1cnNpb25cblxuICBmdW5jdGlvbiBGRlRNICh4LCB5KSB7XG4gICAgdGhpcy54ID0geDtcbiAgICB0aGlzLnkgPSB5O1xuICB9XG5cbiAgRkZUTS5wcm90b3R5cGUubWFrZVJCVCA9IGZ1bmN0aW9uIG1ha2VSQlQgKE4pIHtcbiAgICB2YXIgdCA9IG5ldyBBcnJheShOKTtcbiAgICB2YXIgbCA9IEJOLnByb3RvdHlwZS5fY291bnRCaXRzKE4pIC0gMTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IE47IGkrKykge1xuICAgICAgdFtpXSA9IHRoaXMucmV2QmluKGksIGwsIE4pO1xuICAgIH1cblxuICAgIHJldHVybiB0O1xuICB9O1xuXG4gIC8vIFJldHVybnMgYmluYXJ5LXJldmVyc2VkIHJlcHJlc2VudGF0aW9uIG9mIGB4YFxuICBGRlRNLnByb3RvdHlwZS5yZXZCaW4gPSBmdW5jdGlvbiByZXZCaW4gKHgsIGwsIE4pIHtcbiAgICBpZiAoeCA9PT0gMCB8fCB4ID09PSBOIC0gMSkgcmV0dXJuIHg7XG5cbiAgICB2YXIgcmIgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbDsgaSsrKSB7XG4gICAgICByYiB8PSAoeCAmIDEpIDw8IChsIC0gaSAtIDEpO1xuICAgICAgeCA+Pj0gMTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmI7XG4gIH07XG5cbiAgLy8gUGVyZm9ybXMgXCJ0d2VlZGxpbmdcIiBwaGFzZSwgdGhlcmVmb3JlICdlbXVsYXRpbmcnXG4gIC8vIGJlaGF2aW91ciBvZiB0aGUgcmVjdXJzaXZlIGFsZ29yaXRobVxuICBGRlRNLnByb3RvdHlwZS5wZXJtdXRlID0gZnVuY3Rpb24gcGVybXV0ZSAocmJ0LCByd3MsIGl3cywgcnR3cywgaXR3cywgTikge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgTjsgaSsrKSB7XG4gICAgICBydHdzW2ldID0gcndzW3JidFtpXV07XG4gICAgICBpdHdzW2ldID0gaXdzW3JidFtpXV07XG4gICAgfVxuICB9O1xuXG4gIEZGVE0ucHJvdG90eXBlLnRyYW5zZm9ybSA9IGZ1bmN0aW9uIHRyYW5zZm9ybSAocndzLCBpd3MsIHJ0d3MsIGl0d3MsIE4sIHJidCkge1xuICAgIHRoaXMucGVybXV0ZShyYnQsIHJ3cywgaXdzLCBydHdzLCBpdHdzLCBOKTtcblxuICAgIGZvciAodmFyIHMgPSAxOyBzIDwgTjsgcyA8PD0gMSkge1xuICAgICAgdmFyIGwgPSBzIDw8IDE7XG5cbiAgICAgIHZhciBydHdkZiA9IE1hdGguY29zKDIgKiBNYXRoLlBJIC8gbCk7XG4gICAgICB2YXIgaXR3ZGYgPSBNYXRoLnNpbigyICogTWF0aC5QSSAvIGwpO1xuXG4gICAgICBmb3IgKHZhciBwID0gMDsgcCA8IE47IHAgKz0gbCkge1xuICAgICAgICB2YXIgcnR3ZGZfID0gcnR3ZGY7XG4gICAgICAgIHZhciBpdHdkZl8gPSBpdHdkZjtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHM7IGorKykge1xuICAgICAgICAgIHZhciByZSA9IHJ0d3NbcCArIGpdO1xuICAgICAgICAgIHZhciBpZSA9IGl0d3NbcCArIGpdO1xuXG4gICAgICAgICAgdmFyIHJvID0gcnR3c1twICsgaiArIHNdO1xuICAgICAgICAgIHZhciBpbyA9IGl0d3NbcCArIGogKyBzXTtcblxuICAgICAgICAgIHZhciByeCA9IHJ0d2RmXyAqIHJvIC0gaXR3ZGZfICogaW87XG5cbiAgICAgICAgICBpbyA9IHJ0d2RmXyAqIGlvICsgaXR3ZGZfICogcm87XG4gICAgICAgICAgcm8gPSByeDtcblxuICAgICAgICAgIHJ0d3NbcCArIGpdID0gcmUgKyBybztcbiAgICAgICAgICBpdHdzW3AgKyBqXSA9IGllICsgaW87XG5cbiAgICAgICAgICBydHdzW3AgKyBqICsgc10gPSByZSAtIHJvO1xuICAgICAgICAgIGl0d3NbcCArIGogKyBzXSA9IGllIC0gaW87XG5cbiAgICAgICAgICAvKiBqc2hpbnQgbWF4ZGVwdGggOiBmYWxzZSAqL1xuICAgICAgICAgIGlmIChqICE9PSBsKSB7XG4gICAgICAgICAgICByeCA9IHJ0d2RmICogcnR3ZGZfIC0gaXR3ZGYgKiBpdHdkZl87XG5cbiAgICAgICAgICAgIGl0d2RmXyA9IHJ0d2RmICogaXR3ZGZfICsgaXR3ZGYgKiBydHdkZl87XG4gICAgICAgICAgICBydHdkZl8gPSByeDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUuZ3Vlc3NMZW4xM2IgPSBmdW5jdGlvbiBndWVzc0xlbjEzYiAobiwgbSkge1xuICAgIHZhciBOID0gTWF0aC5tYXgobSwgbikgfCAxO1xuICAgIHZhciBvZGQgPSBOICYgMTtcbiAgICB2YXIgaSA9IDA7XG4gICAgZm9yIChOID0gTiAvIDIgfCAwOyBOOyBOID0gTiA+Pj4gMSkge1xuICAgICAgaSsrO1xuICAgIH1cblxuICAgIHJldHVybiAxIDw8IGkgKyAxICsgb2RkO1xuICB9O1xuXG4gIEZGVE0ucHJvdG90eXBlLmNvbmp1Z2F0ZSA9IGZ1bmN0aW9uIGNvbmp1Z2F0ZSAocndzLCBpd3MsIE4pIHtcbiAgICBpZiAoTiA8PSAxKSByZXR1cm47XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IE4gLyAyOyBpKyspIHtcbiAgICAgIHZhciB0ID0gcndzW2ldO1xuXG4gICAgICByd3NbaV0gPSByd3NbTiAtIGkgLSAxXTtcbiAgICAgIHJ3c1tOIC0gaSAtIDFdID0gdDtcblxuICAgICAgdCA9IGl3c1tpXTtcblxuICAgICAgaXdzW2ldID0gLWl3c1tOIC0gaSAtIDFdO1xuICAgICAgaXdzW04gLSBpIC0gMV0gPSAtdDtcbiAgICB9XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUubm9ybWFsaXplMTNiID0gZnVuY3Rpb24gbm9ybWFsaXplMTNiICh3cywgTikge1xuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBOIC8gMjsgaSsrKSB7XG4gICAgICB2YXIgdyA9IE1hdGgucm91bmQod3NbMiAqIGkgKyAxXSAvIE4pICogMHgyMDAwICtcbiAgICAgICAgTWF0aC5yb3VuZCh3c1syICogaV0gLyBOKSArXG4gICAgICAgIGNhcnJ5O1xuXG4gICAgICB3c1tpXSA9IHcgJiAweDNmZmZmZmY7XG5cbiAgICAgIGlmICh3IDwgMHg0MDAwMDAwKSB7XG4gICAgICAgIGNhcnJ5ID0gMDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNhcnJ5ID0gdyAvIDB4NDAwMDAwMCB8IDA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHdzO1xuICB9O1xuXG4gIEZGVE0ucHJvdG90eXBlLmNvbnZlcnQxM2IgPSBmdW5jdGlvbiBjb252ZXJ0MTNiICh3cywgbGVuLCByd3MsIE4pIHtcbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIGNhcnJ5ID0gY2FycnkgKyAod3NbaV0gfCAwKTtcblxuICAgICAgcndzWzIgKiBpXSA9IGNhcnJ5ICYgMHgxZmZmOyBjYXJyeSA9IGNhcnJ5ID4+PiAxMztcbiAgICAgIHJ3c1syICogaSArIDFdID0gY2FycnkgJiAweDFmZmY7IGNhcnJ5ID0gY2FycnkgPj4+IDEzO1xuICAgIH1cblxuICAgIC8vIFBhZCB3aXRoIHplcm9lc1xuICAgIGZvciAoaSA9IDIgKiBsZW47IGkgPCBOOyArK2kpIHtcbiAgICAgIHJ3c1tpXSA9IDA7XG4gICAgfVxuXG4gICAgYXNzZXJ0KGNhcnJ5ID09PSAwKTtcbiAgICBhc3NlcnQoKGNhcnJ5ICYgfjB4MWZmZikgPT09IDApO1xuICB9O1xuXG4gIEZGVE0ucHJvdG90eXBlLnN0dWIgPSBmdW5jdGlvbiBzdHViIChOKSB7XG4gICAgdmFyIHBoID0gbmV3IEFycmF5KE4pO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgTjsgaSsrKSB7XG4gICAgICBwaFtpXSA9IDA7XG4gICAgfVxuXG4gICAgcmV0dXJuIHBoO1xuICB9O1xuXG4gIEZGVE0ucHJvdG90eXBlLm11bHAgPSBmdW5jdGlvbiBtdWxwICh4LCB5LCBvdXQpIHtcbiAgICB2YXIgTiA9IDIgKiB0aGlzLmd1ZXNzTGVuMTNiKHgubGVuZ3RoLCB5Lmxlbmd0aCk7XG5cbiAgICB2YXIgcmJ0ID0gdGhpcy5tYWtlUkJUKE4pO1xuXG4gICAgdmFyIF8gPSB0aGlzLnN0dWIoTik7XG5cbiAgICB2YXIgcndzID0gbmV3IEFycmF5KE4pO1xuICAgIHZhciByd3N0ID0gbmV3IEFycmF5KE4pO1xuICAgIHZhciBpd3N0ID0gbmV3IEFycmF5KE4pO1xuXG4gICAgdmFyIG5yd3MgPSBuZXcgQXJyYXkoTik7XG4gICAgdmFyIG5yd3N0ID0gbmV3IEFycmF5KE4pO1xuICAgIHZhciBuaXdzdCA9IG5ldyBBcnJheShOKTtcblxuICAgIHZhciBybXdzID0gb3V0LndvcmRzO1xuICAgIHJtd3MubGVuZ3RoID0gTjtcblxuICAgIHRoaXMuY29udmVydDEzYih4LndvcmRzLCB4Lmxlbmd0aCwgcndzLCBOKTtcbiAgICB0aGlzLmNvbnZlcnQxM2IoeS53b3JkcywgeS5sZW5ndGgsIG5yd3MsIE4pO1xuXG4gICAgdGhpcy50cmFuc2Zvcm0ocndzLCBfLCByd3N0LCBpd3N0LCBOLCByYnQpO1xuICAgIHRoaXMudHJhbnNmb3JtKG5yd3MsIF8sIG5yd3N0LCBuaXdzdCwgTiwgcmJ0KTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgTjsgaSsrKSB7XG4gICAgICB2YXIgcnggPSByd3N0W2ldICogbnJ3c3RbaV0gLSBpd3N0W2ldICogbml3c3RbaV07XG4gICAgICBpd3N0W2ldID0gcndzdFtpXSAqIG5pd3N0W2ldICsgaXdzdFtpXSAqIG5yd3N0W2ldO1xuICAgICAgcndzdFtpXSA9IHJ4O1xuICAgIH1cblxuICAgIHRoaXMuY29uanVnYXRlKHJ3c3QsIGl3c3QsIE4pO1xuICAgIHRoaXMudHJhbnNmb3JtKHJ3c3QsIGl3c3QsIHJtd3MsIF8sIE4sIHJidCk7XG4gICAgdGhpcy5jb25qdWdhdGUocm13cywgXywgTik7XG4gICAgdGhpcy5ub3JtYWxpemUxM2Iocm13cywgTik7XG5cbiAgICBvdXQubmVnYXRpdmUgPSB4Lm5lZ2F0aXZlIF4geS5uZWdhdGl2ZTtcbiAgICBvdXQubGVuZ3RoID0geC5sZW5ndGggKyB5Lmxlbmd0aDtcbiAgICByZXR1cm4gb3V0LnN0cmlwKCk7XG4gIH07XG5cbiAgLy8gTXVsdGlwbHkgYHRoaXNgIGJ5IGBudW1gXG4gIEJOLnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwgKG51bSkge1xuICAgIHZhciBvdXQgPSBuZXcgQk4obnVsbCk7XG4gICAgb3V0LndvcmRzID0gbmV3IEFycmF5KHRoaXMubGVuZ3RoICsgbnVtLmxlbmd0aCk7XG4gICAgcmV0dXJuIHRoaXMubXVsVG8obnVtLCBvdXQpO1xuICB9O1xuXG4gIC8vIE11bHRpcGx5IGVtcGxveWluZyBGRlRcbiAgQk4ucHJvdG90eXBlLm11bGYgPSBmdW5jdGlvbiBtdWxmIChudW0pIHtcbiAgICB2YXIgb3V0ID0gbmV3IEJOKG51bGwpO1xuICAgIG91dC53b3JkcyA9IG5ldyBBcnJheSh0aGlzLmxlbmd0aCArIG51bS5sZW5ndGgpO1xuICAgIHJldHVybiBqdW1ib011bFRvKHRoaXMsIG51bSwgb3V0KTtcbiAgfTtcblxuICAvLyBJbi1wbGFjZSBNdWx0aXBsaWNhdGlvblxuICBCTi5wcm90b3R5cGUuaW11bCA9IGZ1bmN0aW9uIGltdWwgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkubXVsVG8obnVtLCB0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaW11bG4gPSBmdW5jdGlvbiBpbXVsbiAobnVtKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBudW0gPT09ICdudW1iZXInKTtcbiAgICBhc3NlcnQobnVtIDwgMHg0MDAwMDAwKTtcblxuICAgIC8vIENhcnJ5XG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciB3ID0gKHRoaXMud29yZHNbaV0gfCAwKSAqIG51bTtcbiAgICAgIHZhciBsbyA9ICh3ICYgMHgzZmZmZmZmKSArIChjYXJyeSAmIDB4M2ZmZmZmZik7XG4gICAgICBjYXJyeSA+Pj0gMjY7XG4gICAgICBjYXJyeSArPSAodyAvIDB4NDAwMDAwMCkgfCAwO1xuICAgICAgLy8gTk9URTogbG8gaXMgMjdiaXQgbWF4aW11bVxuICAgICAgY2FycnkgKz0gbG8gPj4+IDI2O1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IGxvICYgMHgzZmZmZmZmO1xuICAgIH1cblxuICAgIGlmIChjYXJyeSAhPT0gMCkge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IGNhcnJ5O1xuICAgICAgdGhpcy5sZW5ndGgrKztcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUubXVsbiA9IGZ1bmN0aW9uIG11bG4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaW11bG4obnVtKTtcbiAgfTtcblxuICAvLyBgdGhpc2AgKiBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLnNxciA9IGZ1bmN0aW9uIHNxciAoKSB7XG4gICAgcmV0dXJuIHRoaXMubXVsKHRoaXMpO1xuICB9O1xuXG4gIC8vIGB0aGlzYCAqIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXNxciA9IGZ1bmN0aW9uIGlzcXIgKCkge1xuICAgIHJldHVybiB0aGlzLmltdWwodGhpcy5jbG9uZSgpKTtcbiAgfTtcblxuICAvLyBNYXRoLnBvdyhgdGhpc2AsIGBudW1gKVxuICBCTi5wcm90b3R5cGUucG93ID0gZnVuY3Rpb24gcG93IChudW0pIHtcbiAgICB2YXIgdyA9IHRvQml0QXJyYXkobnVtKTtcbiAgICBpZiAody5sZW5ndGggPT09IDApIHJldHVybiBuZXcgQk4oMSk7XG5cbiAgICAvLyBTa2lwIGxlYWRpbmcgemVyb2VzXG4gICAgdmFyIHJlcyA9IHRoaXM7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB3Lmxlbmd0aDsgaSsrLCByZXMgPSByZXMuc3FyKCkpIHtcbiAgICAgIGlmICh3W2ldICE9PSAwKSBicmVhaztcbiAgICB9XG5cbiAgICBpZiAoKytpIDwgdy5sZW5ndGgpIHtcbiAgICAgIGZvciAodmFyIHEgPSByZXMuc3FyKCk7IGkgPCB3Lmxlbmd0aDsgaSsrLCBxID0gcS5zcXIoKSkge1xuICAgICAgICBpZiAod1tpXSA9PT0gMCkgY29udGludWU7XG5cbiAgICAgICAgcmVzID0gcmVzLm11bChxKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIC8vIFNoaWZ0LWxlZnQgaW4tcGxhY2VcbiAgQk4ucHJvdG90eXBlLml1c2hsbiA9IGZ1bmN0aW9uIGl1c2hsbiAoYml0cykge1xuICAgIGFzc2VydCh0eXBlb2YgYml0cyA9PT0gJ251bWJlcicgJiYgYml0cyA+PSAwKTtcbiAgICB2YXIgciA9IGJpdHMgJSAyNjtcbiAgICB2YXIgcyA9IChiaXRzIC0gcikgLyAyNjtcbiAgICB2YXIgY2FycnlNYXNrID0gKDB4M2ZmZmZmZiA+Pj4gKDI2IC0gcikpIDw8ICgyNiAtIHIpO1xuICAgIHZhciBpO1xuXG4gICAgaWYgKHIgIT09IDApIHtcbiAgICAgIHZhciBjYXJyeSA9IDA7XG5cbiAgICAgIGZvciAoaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciBuZXdDYXJyeSA9IHRoaXMud29yZHNbaV0gJiBjYXJyeU1hc2s7XG4gICAgICAgIHZhciBjID0gKCh0aGlzLndvcmRzW2ldIHwgMCkgLSBuZXdDYXJyeSkgPDwgcjtcbiAgICAgICAgdGhpcy53b3Jkc1tpXSA9IGMgfCBjYXJyeTtcbiAgICAgICAgY2FycnkgPSBuZXdDYXJyeSA+Pj4gKDI2IC0gcik7XG4gICAgICB9XG5cbiAgICAgIGlmIChjYXJyeSkge1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gY2Fycnk7XG4gICAgICAgIHRoaXMubGVuZ3RoKys7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHMgIT09IDApIHtcbiAgICAgIGZvciAoaSA9IHRoaXMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpICsgc10gPSB0aGlzLndvcmRzW2ldO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGkgPSAwOyBpIDwgczsgaSsrKSB7XG4gICAgICAgIHRoaXMud29yZHNbaV0gPSAwO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmxlbmd0aCArPSBzO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmlzaGxuID0gZnVuY3Rpb24gaXNobG4gKGJpdHMpIHtcbiAgICAvLyBUT0RPKGluZHV0bnkpOiBpbXBsZW1lbnQgbWVcbiAgICBhc3NlcnQodGhpcy5uZWdhdGl2ZSA9PT0gMCk7XG4gICAgcmV0dXJuIHRoaXMuaXVzaGxuKGJpdHMpO1xuICB9O1xuXG4gIC8vIFNoaWZ0LXJpZ2h0IGluLXBsYWNlXG4gIC8vIE5PVEU6IGBoaW50YCBpcyBhIGxvd2VzdCBiaXQgYmVmb3JlIHRyYWlsaW5nIHplcm9lc1xuICAvLyBOT1RFOiBpZiBgZXh0ZW5kZWRgIGlzIHByZXNlbnQgLSBpdCB3aWxsIGJlIGZpbGxlZCB3aXRoIGRlc3Ryb3llZCBiaXRzXG4gIEJOLnByb3RvdHlwZS5pdXNocm4gPSBmdW5jdGlvbiBpdXNocm4gKGJpdHMsIGhpbnQsIGV4dGVuZGVkKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBiaXRzID09PSAnbnVtYmVyJyAmJiBiaXRzID49IDApO1xuICAgIHZhciBoO1xuICAgIGlmIChoaW50KSB7XG4gICAgICBoID0gKGhpbnQgLSAoaGludCAlIDI2KSkgLyAyNjtcbiAgICB9IGVsc2Uge1xuICAgICAgaCA9IDA7XG4gICAgfVxuXG4gICAgdmFyIHIgPSBiaXRzICUgMjY7XG4gICAgdmFyIHMgPSBNYXRoLm1pbigoYml0cyAtIHIpIC8gMjYsIHRoaXMubGVuZ3RoKTtcbiAgICB2YXIgbWFzayA9IDB4M2ZmZmZmZiBeICgoMHgzZmZmZmZmID4+PiByKSA8PCByKTtcbiAgICB2YXIgbWFza2VkV29yZHMgPSBleHRlbmRlZDtcblxuICAgIGggLT0gcztcbiAgICBoID0gTWF0aC5tYXgoMCwgaCk7XG5cbiAgICAvLyBFeHRlbmRlZCBtb2RlLCBjb3B5IG1hc2tlZCBwYXJ0XG4gICAgaWYgKG1hc2tlZFdvcmRzKSB7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHM7IGkrKykge1xuICAgICAgICBtYXNrZWRXb3Jkcy53b3Jkc1tpXSA9IHRoaXMud29yZHNbaV07XG4gICAgICB9XG4gICAgICBtYXNrZWRXb3Jkcy5sZW5ndGggPSBzO1xuICAgIH1cblxuICAgIGlmIChzID09PSAwKSB7XG4gICAgICAvLyBOby1vcCwgd2Ugc2hvdWxkIG5vdCBtb3ZlIGFueXRoaW5nIGF0IGFsbFxuICAgIH0gZWxzZSBpZiAodGhpcy5sZW5ndGggPiBzKSB7XG4gICAgICB0aGlzLmxlbmd0aCAtPSBzO1xuICAgICAgZm9yIChpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpXSA9IHRoaXMud29yZHNbaSArIHNdO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLndvcmRzWzBdID0gMDtcbiAgICAgIHRoaXMubGVuZ3RoID0gMTtcbiAgICB9XG5cbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAoaSA9IHRoaXMubGVuZ3RoIC0gMTsgaSA+PSAwICYmIChjYXJyeSAhPT0gMCB8fCBpID49IGgpOyBpLS0pIHtcbiAgICAgIHZhciB3b3JkID0gdGhpcy53b3Jkc1tpXSB8IDA7XG4gICAgICB0aGlzLndvcmRzW2ldID0gKGNhcnJ5IDw8ICgyNiAtIHIpKSB8ICh3b3JkID4+PiByKTtcbiAgICAgIGNhcnJ5ID0gd29yZCAmIG1hc2s7XG4gICAgfVxuXG4gICAgLy8gUHVzaCBjYXJyaWVkIGJpdHMgYXMgYSBtYXNrXG4gICAgaWYgKG1hc2tlZFdvcmRzICYmIGNhcnJ5ICE9PSAwKSB7XG4gICAgICBtYXNrZWRXb3Jkcy53b3Jkc1ttYXNrZWRXb3Jkcy5sZW5ndGgrK10gPSBjYXJyeTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMud29yZHNbMF0gPSAwO1xuICAgICAgdGhpcy5sZW5ndGggPSAxO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmlzaHJuID0gZnVuY3Rpb24gaXNocm4gKGJpdHMsIGhpbnQsIGV4dGVuZGVkKSB7XG4gICAgLy8gVE9ETyhpbmR1dG55KTogaW1wbGVtZW50IG1lXG4gICAgYXNzZXJ0KHRoaXMubmVnYXRpdmUgPT09IDApO1xuICAgIHJldHVybiB0aGlzLml1c2hybihiaXRzLCBoaW50LCBleHRlbmRlZCk7XG4gIH07XG5cbiAgLy8gU2hpZnQtbGVmdFxuICBCTi5wcm90b3R5cGUuc2hsbiA9IGZ1bmN0aW9uIHNobG4gKGJpdHMpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlzaGxuKGJpdHMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS51c2hsbiA9IGZ1bmN0aW9uIHVzaGxuIChiaXRzKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pdXNobG4oYml0cyk7XG4gIH07XG5cbiAgLy8gU2hpZnQtcmlnaHRcbiAgQk4ucHJvdG90eXBlLnNocm4gPSBmdW5jdGlvbiBzaHJuIChiaXRzKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pc2hybihiaXRzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudXNocm4gPSBmdW5jdGlvbiB1c2hybiAoYml0cykge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaXVzaHJuKGJpdHMpO1xuICB9O1xuXG4gIC8vIFRlc3QgaWYgbiBiaXQgaXMgc2V0XG4gIEJOLnByb3RvdHlwZS50ZXN0biA9IGZ1bmN0aW9uIHRlc3RuIChiaXQpIHtcbiAgICBhc3NlcnQodHlwZW9mIGJpdCA9PT0gJ251bWJlcicgJiYgYml0ID49IDApO1xuICAgIHZhciByID0gYml0ICUgMjY7XG4gICAgdmFyIHMgPSAoYml0IC0gcikgLyAyNjtcbiAgICB2YXIgcSA9IDEgPDwgcjtcblxuICAgIC8vIEZhc3QgY2FzZTogYml0IGlzIG11Y2ggaGlnaGVyIHRoYW4gYWxsIGV4aXN0aW5nIHdvcmRzXG4gICAgaWYgKHRoaXMubGVuZ3RoIDw9IHMpIHJldHVybiBmYWxzZTtcblxuICAgIC8vIENoZWNrIGJpdCBhbmQgcmV0dXJuXG4gICAgdmFyIHcgPSB0aGlzLndvcmRzW3NdO1xuXG4gICAgcmV0dXJuICEhKHcgJiBxKTtcbiAgfTtcblxuICAvLyBSZXR1cm4gb25seSBsb3dlcnMgYml0cyBvZiBudW1iZXIgKGluLXBsYWNlKVxuICBCTi5wcm90b3R5cGUuaW1hc2tuID0gZnVuY3Rpb24gaW1hc2tuIChiaXRzKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBiaXRzID09PSAnbnVtYmVyJyAmJiBiaXRzID49IDApO1xuICAgIHZhciByID0gYml0cyAlIDI2O1xuICAgIHZhciBzID0gKGJpdHMgLSByKSAvIDI2O1xuXG4gICAgYXNzZXJ0KHRoaXMubmVnYXRpdmUgPT09IDAsICdpbWFza24gd29ya3Mgb25seSB3aXRoIHBvc2l0aXZlIG51bWJlcnMnKTtcblxuICAgIGlmIChyICE9PSAwKSB7XG4gICAgICBzKys7XG4gICAgfVxuICAgIHRoaXMubGVuZ3RoID0gTWF0aC5taW4ocywgdGhpcy5sZW5ndGgpO1xuXG4gICAgaWYgKHIgIT09IDApIHtcbiAgICAgIHZhciBtYXNrID0gMHgzZmZmZmZmIF4gKCgweDNmZmZmZmYgPj4+IHIpIDw8IHIpO1xuICAgICAgdGhpcy53b3Jkc1t0aGlzLmxlbmd0aCAtIDFdICY9IG1hc2s7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICAvLyBSZXR1cm4gb25seSBsb3dlcnMgYml0cyBvZiBudW1iZXJcbiAgQk4ucHJvdG90eXBlLm1hc2tuID0gZnVuY3Rpb24gbWFza24gKGJpdHMpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmltYXNrbihiaXRzKTtcbiAgfTtcblxuICAvLyBBZGQgcGxhaW4gbnVtYmVyIGBudW1gIHRvIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuaWFkZG4gPSBmdW5jdGlvbiBpYWRkbiAobnVtKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBudW0gPT09ICdudW1iZXInKTtcbiAgICBhc3NlcnQobnVtIDwgMHg0MDAwMDAwKTtcbiAgICBpZiAobnVtIDwgMCkgcmV0dXJuIHRoaXMuaXN1Ym4oLW51bSk7XG5cbiAgICAvLyBQb3NzaWJsZSBzaWduIGNoYW5nZVxuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICBpZiAodGhpcy5sZW5ndGggPT09IDEgJiYgKHRoaXMud29yZHNbMF0gfCAwKSA8IG51bSkge1xuICAgICAgICB0aGlzLndvcmRzWzBdID0gbnVtIC0gKHRoaXMud29yZHNbMF0gfCAwKTtcbiAgICAgICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgfVxuXG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgIHRoaXMuaXN1Ym4obnVtKTtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAxO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgLy8gQWRkIHdpdGhvdXQgY2hlY2tzXG4gICAgcmV0dXJuIHRoaXMuX2lhZGRuKG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLl9pYWRkbiA9IGZ1bmN0aW9uIF9pYWRkbiAobnVtKSB7XG4gICAgdGhpcy53b3Jkc1swXSArPSBudW07XG5cbiAgICAvLyBDYXJyeVxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGggJiYgdGhpcy53b3Jkc1tpXSA+PSAweDQwMDAwMDA7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSAtPSAweDQwMDAwMDA7XG4gICAgICBpZiAoaSA9PT0gdGhpcy5sZW5ndGggLSAxKSB7XG4gICAgICAgIHRoaXMud29yZHNbaSArIDFdID0gMTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMud29yZHNbaSArIDFdKys7XG4gICAgICB9XG4gICAgfVxuICAgIHRoaXMubGVuZ3RoID0gTWF0aC5tYXgodGhpcy5sZW5ndGgsIGkgKyAxKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIC8vIFN1YnRyYWN0IHBsYWluIG51bWJlciBgbnVtYCBmcm9tIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuaXN1Ym4gPSBmdW5jdGlvbiBpc3VibiAobnVtKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBudW0gPT09ICdudW1iZXInKTtcbiAgICBhc3NlcnQobnVtIDwgMHg0MDAwMDAwKTtcbiAgICBpZiAobnVtIDwgMCkgcmV0dXJuIHRoaXMuaWFkZG4oLW51bSk7XG5cbiAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgICB0aGlzLmlhZGRuKG51bSk7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cblxuICAgIHRoaXMud29yZHNbMF0gLT0gbnVtO1xuXG4gICAgaWYgKHRoaXMubGVuZ3RoID09PSAxICYmIHRoaXMud29yZHNbMF0gPCAwKSB7XG4gICAgICB0aGlzLndvcmRzWzBdID0gLXRoaXMud29yZHNbMF07XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gQ2FycnlcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGggJiYgdGhpcy53b3Jkc1tpXSA8IDA7IGkrKykge1xuICAgICAgICB0aGlzLndvcmRzW2ldICs9IDB4NDAwMDAwMDtcbiAgICAgICAgdGhpcy53b3Jkc1tpICsgMV0gLT0gMTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5hZGRuID0gZnVuY3Rpb24gYWRkbiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pYWRkbihudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5zdWJuID0gZnVuY3Rpb24gc3VibiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pc3VibihudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pYWJzID0gZnVuY3Rpb24gaWFicyAoKSB7XG4gICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuYWJzID0gZnVuY3Rpb24gYWJzICgpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlhYnMoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2lzaGxuc3VibXVsID0gZnVuY3Rpb24gX2lzaGxuc3VibXVsIChudW0sIG11bCwgc2hpZnQpIHtcbiAgICB2YXIgbGVuID0gbnVtLmxlbmd0aCArIHNoaWZ0O1xuICAgIHZhciBpO1xuXG4gICAgdGhpcy5fZXhwYW5kKGxlbik7XG5cbiAgICB2YXIgdztcbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAoaSA9IDA7IGkgPCBudW0ubGVuZ3RoOyBpKyspIHtcbiAgICAgIHcgPSAodGhpcy53b3Jkc1tpICsgc2hpZnRdIHwgMCkgKyBjYXJyeTtcbiAgICAgIHZhciByaWdodCA9IChudW0ud29yZHNbaV0gfCAwKSAqIG11bDtcbiAgICAgIHcgLT0gcmlnaHQgJiAweDNmZmZmZmY7XG4gICAgICBjYXJyeSA9ICh3ID4+IDI2KSAtICgocmlnaHQgLyAweDQwMDAwMDApIHwgMCk7XG4gICAgICB0aGlzLndvcmRzW2kgKyBzaGlmdF0gPSB3ICYgMHgzZmZmZmZmO1xuICAgIH1cbiAgICBmb3IgKDsgaSA8IHRoaXMubGVuZ3RoIC0gc2hpZnQ7IGkrKykge1xuICAgICAgdyA9ICh0aGlzLndvcmRzW2kgKyBzaGlmdF0gfCAwKSArIGNhcnJ5O1xuICAgICAgY2FycnkgPSB3ID4+IDI2O1xuICAgICAgdGhpcy53b3Jkc1tpICsgc2hpZnRdID0gdyAmIDB4M2ZmZmZmZjtcbiAgICB9XG5cbiAgICBpZiAoY2FycnkgPT09IDApIHJldHVybiB0aGlzLnN0cmlwKCk7XG5cbiAgICAvLyBTdWJ0cmFjdGlvbiBvdmVyZmxvd1xuICAgIGFzc2VydChjYXJyeSA9PT0gLTEpO1xuICAgIGNhcnJ5ID0gMDtcbiAgICBmb3IgKGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgdyA9IC0odGhpcy53b3Jkc1tpXSB8IDApICsgY2Fycnk7XG4gICAgICBjYXJyeSA9IHcgPj4gMjY7XG4gICAgICB0aGlzLndvcmRzW2ldID0gdyAmIDB4M2ZmZmZmZjtcbiAgICB9XG4gICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5fd29yZERpdiA9IGZ1bmN0aW9uIF93b3JkRGl2IChudW0sIG1vZGUpIHtcbiAgICB2YXIgc2hpZnQgPSB0aGlzLmxlbmd0aCAtIG51bS5sZW5ndGg7XG5cbiAgICB2YXIgYSA9IHRoaXMuY2xvbmUoKTtcbiAgICB2YXIgYiA9IG51bTtcblxuICAgIC8vIE5vcm1hbGl6ZVxuICAgIHZhciBiaGkgPSBiLndvcmRzW2IubGVuZ3RoIC0gMV0gfCAwO1xuICAgIHZhciBiaGlCaXRzID0gdGhpcy5fY291bnRCaXRzKGJoaSk7XG4gICAgc2hpZnQgPSAyNiAtIGJoaUJpdHM7XG4gICAgaWYgKHNoaWZ0ICE9PSAwKSB7XG4gICAgICBiID0gYi51c2hsbihzaGlmdCk7XG4gICAgICBhLml1c2hsbihzaGlmdCk7XG4gICAgICBiaGkgPSBiLndvcmRzW2IubGVuZ3RoIC0gMV0gfCAwO1xuICAgIH1cblxuICAgIC8vIEluaXRpYWxpemUgcXVvdGllbnRcbiAgICB2YXIgbSA9IGEubGVuZ3RoIC0gYi5sZW5ndGg7XG4gICAgdmFyIHE7XG5cbiAgICBpZiAobW9kZSAhPT0gJ21vZCcpIHtcbiAgICAgIHEgPSBuZXcgQk4obnVsbCk7XG4gICAgICBxLmxlbmd0aCA9IG0gKyAxO1xuICAgICAgcS53b3JkcyA9IG5ldyBBcnJheShxLmxlbmd0aCk7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHEubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgcS53b3Jkc1tpXSA9IDA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdmFyIGRpZmYgPSBhLmNsb25lKCkuX2lzaGxuc3VibXVsKGIsIDEsIG0pO1xuICAgIGlmIChkaWZmLm5lZ2F0aXZlID09PSAwKSB7XG4gICAgICBhID0gZGlmZjtcbiAgICAgIGlmIChxKSB7XG4gICAgICAgIHEud29yZHNbbV0gPSAxO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZvciAodmFyIGogPSBtIC0gMTsgaiA+PSAwOyBqLS0pIHtcbiAgICAgIHZhciBxaiA9IChhLndvcmRzW2IubGVuZ3RoICsgal0gfCAwKSAqIDB4NDAwMDAwMCArXG4gICAgICAgIChhLndvcmRzW2IubGVuZ3RoICsgaiAtIDFdIHwgMCk7XG5cbiAgICAgIC8vIE5PVEU6IChxaiAvIGJoaSkgaXMgKDB4M2ZmZmZmZiAqIDB4NDAwMDAwMCArIDB4M2ZmZmZmZikgLyAweDIwMDAwMDAgbWF4XG4gICAgICAvLyAoMHg3ZmZmZmZmKVxuICAgICAgcWogPSBNYXRoLm1pbigocWogLyBiaGkpIHwgMCwgMHgzZmZmZmZmKTtcblxuICAgICAgYS5faXNobG5zdWJtdWwoYiwgcWosIGopO1xuICAgICAgd2hpbGUgKGEubmVnYXRpdmUgIT09IDApIHtcbiAgICAgICAgcWotLTtcbiAgICAgICAgYS5uZWdhdGl2ZSA9IDA7XG4gICAgICAgIGEuX2lzaGxuc3VibXVsKGIsIDEsIGopO1xuICAgICAgICBpZiAoIWEuaXNaZXJvKCkpIHtcbiAgICAgICAgICBhLm5lZ2F0aXZlIF49IDE7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChxKSB7XG4gICAgICAgIHEud29yZHNbal0gPSBxajtcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKHEpIHtcbiAgICAgIHEuc3RyaXAoKTtcbiAgICB9XG4gICAgYS5zdHJpcCgpO1xuXG4gICAgLy8gRGVub3JtYWxpemVcbiAgICBpZiAobW9kZSAhPT0gJ2RpdicgJiYgc2hpZnQgIT09IDApIHtcbiAgICAgIGEuaXVzaHJuKHNoaWZ0KTtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgZGl2OiBxIHx8IG51bGwsXG4gICAgICBtb2Q6IGFcbiAgICB9O1xuICB9O1xuXG4gIC8vIE5PVEU6IDEpIGBtb2RlYCBjYW4gYmUgc2V0IHRvIGBtb2RgIHRvIHJlcXVlc3QgbW9kIG9ubHksXG4gIC8vICAgICAgIHRvIGBkaXZgIHRvIHJlcXVlc3QgZGl2IG9ubHksIG9yIGJlIGFic2VudCB0b1xuICAvLyAgICAgICByZXF1ZXN0IGJvdGggZGl2ICYgbW9kXG4gIC8vICAgICAgIDIpIGBwb3NpdGl2ZWAgaXMgdHJ1ZSBpZiB1bnNpZ25lZCBtb2QgaXMgcmVxdWVzdGVkXG4gIEJOLnByb3RvdHlwZS5kaXZtb2QgPSBmdW5jdGlvbiBkaXZtb2QgKG51bSwgbW9kZSwgcG9zaXRpdmUpIHtcbiAgICBhc3NlcnQoIW51bS5pc1plcm8oKSk7XG5cbiAgICBpZiAodGhpcy5pc1plcm8oKSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZGl2OiBuZXcgQk4oMCksXG4gICAgICAgIG1vZDogbmV3IEJOKDApXG4gICAgICB9O1xuICAgIH1cblxuICAgIHZhciBkaXYsIG1vZCwgcmVzO1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwICYmIG51bS5uZWdhdGl2ZSA9PT0gMCkge1xuICAgICAgcmVzID0gdGhpcy5uZWcoKS5kaXZtb2QobnVtLCBtb2RlKTtcblxuICAgICAgaWYgKG1vZGUgIT09ICdtb2QnKSB7XG4gICAgICAgIGRpdiA9IHJlcy5kaXYubmVnKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChtb2RlICE9PSAnZGl2Jykge1xuICAgICAgICBtb2QgPSByZXMubW9kLm5lZygpO1xuICAgICAgICBpZiAocG9zaXRpdmUgJiYgbW9kLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICAgICAgbW9kLmlhZGQobnVtKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBkaXY6IGRpdixcbiAgICAgICAgbW9kOiBtb2RcbiAgICAgIH07XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubmVnYXRpdmUgPT09IDAgJiYgbnVtLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICByZXMgPSB0aGlzLmRpdm1vZChudW0ubmVnKCksIG1vZGUpO1xuXG4gICAgICBpZiAobW9kZSAhPT0gJ21vZCcpIHtcbiAgICAgICAgZGl2ID0gcmVzLmRpdi5uZWcoKTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZGl2OiBkaXYsXG4gICAgICAgIG1vZDogcmVzLm1vZFxuICAgICAgfTtcbiAgICB9XG5cbiAgICBpZiAoKHRoaXMubmVnYXRpdmUgJiBudW0ubmVnYXRpdmUpICE9PSAwKSB7XG4gICAgICByZXMgPSB0aGlzLm5lZygpLmRpdm1vZChudW0ubmVnKCksIG1vZGUpO1xuXG4gICAgICBpZiAobW9kZSAhPT0gJ2RpdicpIHtcbiAgICAgICAgbW9kID0gcmVzLm1vZC5uZWcoKTtcbiAgICAgICAgaWYgKHBvc2l0aXZlICYmIG1vZC5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgICAgIG1vZC5pc3ViKG51bSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZGl2OiByZXMuZGl2LFxuICAgICAgICBtb2Q6IG1vZFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBCb3RoIG51bWJlcnMgYXJlIHBvc2l0aXZlIGF0IHRoaXMgcG9pbnRcblxuICAgIC8vIFN0cmlwIGJvdGggbnVtYmVycyB0byBhcHByb3hpbWF0ZSBzaGlmdCB2YWx1ZVxuICAgIGlmIChudW0ubGVuZ3RoID4gdGhpcy5sZW5ndGggfHwgdGhpcy5jbXAobnVtKSA8IDApIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGRpdjogbmV3IEJOKDApLFxuICAgICAgICBtb2Q6IHRoaXNcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gVmVyeSBzaG9ydCByZWR1Y3Rpb25cbiAgICBpZiAobnVtLmxlbmd0aCA9PT0gMSkge1xuICAgICAgaWYgKG1vZGUgPT09ICdkaXYnKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgZGl2OiB0aGlzLmRpdm4obnVtLndvcmRzWzBdKSxcbiAgICAgICAgICBtb2Q6IG51bGxcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgaWYgKG1vZGUgPT09ICdtb2QnKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgZGl2OiBudWxsLFxuICAgICAgICAgIG1vZDogbmV3IEJOKHRoaXMubW9kbihudW0ud29yZHNbMF0pKVxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBkaXY6IHRoaXMuZGl2bihudW0ud29yZHNbMF0pLFxuICAgICAgICBtb2Q6IG5ldyBCTih0aGlzLm1vZG4obnVtLndvcmRzWzBdKSlcbiAgICAgIH07XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuX3dvcmREaXYobnVtLCBtb2RlKTtcbiAgfTtcblxuICAvLyBGaW5kIGB0aGlzYCAvIGBudW1gXG4gIEJOLnByb3RvdHlwZS5kaXYgPSBmdW5jdGlvbiBkaXYgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmRpdm1vZChudW0sICdkaXYnLCBmYWxzZSkuZGl2O1xuICB9O1xuXG4gIC8vIEZpbmQgYHRoaXNgICUgYG51bWBcbiAgQk4ucHJvdG90eXBlLm1vZCA9IGZ1bmN0aW9uIG1vZCAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuZGl2bW9kKG51bSwgJ21vZCcsIGZhbHNlKS5tb2Q7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnVtb2QgPSBmdW5jdGlvbiB1bW9kIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5kaXZtb2QobnVtLCAnbW9kJywgdHJ1ZSkubW9kO1xuICB9O1xuXG4gIC8vIEZpbmQgUm91bmQoYHRoaXNgIC8gYG51bWApXG4gIEJOLnByb3RvdHlwZS5kaXZSb3VuZCA9IGZ1bmN0aW9uIGRpdlJvdW5kIChudW0pIHtcbiAgICB2YXIgZG0gPSB0aGlzLmRpdm1vZChudW0pO1xuXG4gICAgLy8gRmFzdCBjYXNlIC0gZXhhY3QgZGl2aXNpb25cbiAgICBpZiAoZG0ubW9kLmlzWmVybygpKSByZXR1cm4gZG0uZGl2O1xuXG4gICAgdmFyIG1vZCA9IGRtLmRpdi5uZWdhdGl2ZSAhPT0gMCA/IGRtLm1vZC5pc3ViKG51bSkgOiBkbS5tb2Q7XG5cbiAgICB2YXIgaGFsZiA9IG51bS51c2hybigxKTtcbiAgICB2YXIgcjIgPSBudW0uYW5kbG4oMSk7XG4gICAgdmFyIGNtcCA9IG1vZC5jbXAoaGFsZik7XG5cbiAgICAvLyBSb3VuZCBkb3duXG4gICAgaWYgKGNtcCA8IDAgfHwgcjIgPT09IDEgJiYgY21wID09PSAwKSByZXR1cm4gZG0uZGl2O1xuXG4gICAgLy8gUm91bmQgdXBcbiAgICByZXR1cm4gZG0uZGl2Lm5lZ2F0aXZlICE9PSAwID8gZG0uZGl2LmlzdWJuKDEpIDogZG0uZGl2LmlhZGRuKDEpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5tb2RuID0gZnVuY3Rpb24gbW9kbiAobnVtKSB7XG4gICAgYXNzZXJ0KG51bSA8PSAweDNmZmZmZmYpO1xuICAgIHZhciBwID0gKDEgPDwgMjYpICUgbnVtO1xuXG4gICAgdmFyIGFjYyA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHRoaXMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICAgIGFjYyA9IChwICogYWNjICsgKHRoaXMud29yZHNbaV0gfCAwKSkgJSBudW07XG4gICAgfVxuXG4gICAgcmV0dXJuIGFjYztcbiAgfTtcblxuICAvLyBJbi1wbGFjZSBkaXZpc2lvbiBieSBudW1iZXJcbiAgQk4ucHJvdG90eXBlLmlkaXZuID0gZnVuY3Rpb24gaWRpdm4gKG51bSkge1xuICAgIGFzc2VydChudW0gPD0gMHgzZmZmZmZmKTtcblxuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHRoaXMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICAgIHZhciB3ID0gKHRoaXMud29yZHNbaV0gfCAwKSArIGNhcnJ5ICogMHg0MDAwMDAwO1xuICAgICAgdGhpcy53b3Jkc1tpXSA9ICh3IC8gbnVtKSB8IDA7XG4gICAgICBjYXJyeSA9IHcgJSBudW07XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZGl2biA9IGZ1bmN0aW9uIGRpdm4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaWRpdm4obnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZWdjZCA9IGZ1bmN0aW9uIGVnY2QgKHApIHtcbiAgICBhc3NlcnQocC5uZWdhdGl2ZSA9PT0gMCk7XG4gICAgYXNzZXJ0KCFwLmlzWmVybygpKTtcblxuICAgIHZhciB4ID0gdGhpcztcbiAgICB2YXIgeSA9IHAuY2xvbmUoKTtcblxuICAgIGlmICh4Lm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICB4ID0geC51bW9kKHApO1xuICAgIH0gZWxzZSB7XG4gICAgICB4ID0geC5jbG9uZSgpO1xuICAgIH1cblxuICAgIC8vIEEgKiB4ICsgQiAqIHkgPSB4XG4gICAgdmFyIEEgPSBuZXcgQk4oMSk7XG4gICAgdmFyIEIgPSBuZXcgQk4oMCk7XG5cbiAgICAvLyBDICogeCArIEQgKiB5ID0geVxuICAgIHZhciBDID0gbmV3IEJOKDApO1xuICAgIHZhciBEID0gbmV3IEJOKDEpO1xuXG4gICAgdmFyIGcgPSAwO1xuXG4gICAgd2hpbGUgKHguaXNFdmVuKCkgJiYgeS5pc0V2ZW4oKSkge1xuICAgICAgeC5pdXNocm4oMSk7XG4gICAgICB5Lml1c2hybigxKTtcbiAgICAgICsrZztcbiAgICB9XG5cbiAgICB2YXIgeXAgPSB5LmNsb25lKCk7XG4gICAgdmFyIHhwID0geC5jbG9uZSgpO1xuXG4gICAgd2hpbGUgKCF4LmlzWmVybygpKSB7XG4gICAgICBmb3IgKHZhciBpID0gMCwgaW0gPSAxOyAoeC53b3Jkc1swXSAmIGltKSA9PT0gMCAmJiBpIDwgMjY7ICsraSwgaW0gPDw9IDEpO1xuICAgICAgaWYgKGkgPiAwKSB7XG4gICAgICAgIHguaXVzaHJuKGkpO1xuICAgICAgICB3aGlsZSAoaS0tID4gMCkge1xuICAgICAgICAgIGlmIChBLmlzT2RkKCkgfHwgQi5pc09kZCgpKSB7XG4gICAgICAgICAgICBBLmlhZGQoeXApO1xuICAgICAgICAgICAgQi5pc3ViKHhwKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBBLml1c2hybigxKTtcbiAgICAgICAgICBCLml1c2hybigxKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBmb3IgKHZhciBqID0gMCwgam0gPSAxOyAoeS53b3Jkc1swXSAmIGptKSA9PT0gMCAmJiBqIDwgMjY7ICsraiwgam0gPDw9IDEpO1xuICAgICAgaWYgKGogPiAwKSB7XG4gICAgICAgIHkuaXVzaHJuKGopO1xuICAgICAgICB3aGlsZSAoai0tID4gMCkge1xuICAgICAgICAgIGlmIChDLmlzT2RkKCkgfHwgRC5pc09kZCgpKSB7XG4gICAgICAgICAgICBDLmlhZGQoeXApO1xuICAgICAgICAgICAgRC5pc3ViKHhwKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBDLml1c2hybigxKTtcbiAgICAgICAgICBELml1c2hybigxKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoeC5jbXAoeSkgPj0gMCkge1xuICAgICAgICB4LmlzdWIoeSk7XG4gICAgICAgIEEuaXN1YihDKTtcbiAgICAgICAgQi5pc3ViKEQpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgeS5pc3ViKHgpO1xuICAgICAgICBDLmlzdWIoQSk7XG4gICAgICAgIEQuaXN1YihCKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgYTogQyxcbiAgICAgIGI6IEQsXG4gICAgICBnY2Q6IHkuaXVzaGxuKGcpXG4gICAgfTtcbiAgfTtcblxuICAvLyBUaGlzIGlzIHJlZHVjZWQgaW5jYXJuYXRpb24gb2YgdGhlIGJpbmFyeSBFRUFcbiAgLy8gYWJvdmUsIGRlc2lnbmF0ZWQgdG8gaW52ZXJ0IG1lbWJlcnMgb2YgdGhlXG4gIC8vIF9wcmltZV8gZmllbGRzIEYocCkgYXQgYSBtYXhpbWFsIHNwZWVkXG4gIEJOLnByb3RvdHlwZS5faW52bXAgPSBmdW5jdGlvbiBfaW52bXAgKHApIHtcbiAgICBhc3NlcnQocC5uZWdhdGl2ZSA9PT0gMCk7XG4gICAgYXNzZXJ0KCFwLmlzWmVybygpKTtcblxuICAgIHZhciBhID0gdGhpcztcbiAgICB2YXIgYiA9IHAuY2xvbmUoKTtcblxuICAgIGlmIChhLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICBhID0gYS51bW9kKHApO1xuICAgIH0gZWxzZSB7XG4gICAgICBhID0gYS5jbG9uZSgpO1xuICAgIH1cblxuICAgIHZhciB4MSA9IG5ldyBCTigxKTtcbiAgICB2YXIgeDIgPSBuZXcgQk4oMCk7XG5cbiAgICB2YXIgZGVsdGEgPSBiLmNsb25lKCk7XG5cbiAgICB3aGlsZSAoYS5jbXBuKDEpID4gMCAmJiBiLmNtcG4oMSkgPiAwKSB7XG4gICAgICBmb3IgKHZhciBpID0gMCwgaW0gPSAxOyAoYS53b3Jkc1swXSAmIGltKSA9PT0gMCAmJiBpIDwgMjY7ICsraSwgaW0gPDw9IDEpO1xuICAgICAgaWYgKGkgPiAwKSB7XG4gICAgICAgIGEuaXVzaHJuKGkpO1xuICAgICAgICB3aGlsZSAoaS0tID4gMCkge1xuICAgICAgICAgIGlmICh4MS5pc09kZCgpKSB7XG4gICAgICAgICAgICB4MS5pYWRkKGRlbHRhKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB4MS5pdXNocm4oMSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgZm9yICh2YXIgaiA9IDAsIGptID0gMTsgKGIud29yZHNbMF0gJiBqbSkgPT09IDAgJiYgaiA8IDI2OyArK2osIGptIDw8PSAxKTtcbiAgICAgIGlmIChqID4gMCkge1xuICAgICAgICBiLml1c2hybihqKTtcbiAgICAgICAgd2hpbGUgKGotLSA+IDApIHtcbiAgICAgICAgICBpZiAoeDIuaXNPZGQoKSkge1xuICAgICAgICAgICAgeDIuaWFkZChkZWx0YSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgeDIuaXVzaHJuKDEpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChhLmNtcChiKSA+PSAwKSB7XG4gICAgICAgIGEuaXN1YihiKTtcbiAgICAgICAgeDEuaXN1Yih4Mik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBiLmlzdWIoYSk7XG4gICAgICAgIHgyLmlzdWIoeDEpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZhciByZXM7XG4gICAgaWYgKGEuY21wbigxKSA9PT0gMCkge1xuICAgICAgcmVzID0geDE7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcyA9IHgyO1xuICAgIH1cblxuICAgIGlmIChyZXMuY21wbigwKSA8IDApIHtcbiAgICAgIHJlcy5pYWRkKHApO1xuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmdjZCA9IGZ1bmN0aW9uIGdjZCAobnVtKSB7XG4gICAgaWYgKHRoaXMuaXNaZXJvKCkpIHJldHVybiBudW0uYWJzKCk7XG4gICAgaWYgKG51bS5pc1plcm8oKSkgcmV0dXJuIHRoaXMuYWJzKCk7XG5cbiAgICB2YXIgYSA9IHRoaXMuY2xvbmUoKTtcbiAgICB2YXIgYiA9IG51bS5jbG9uZSgpO1xuICAgIGEubmVnYXRpdmUgPSAwO1xuICAgIGIubmVnYXRpdmUgPSAwO1xuXG4gICAgLy8gUmVtb3ZlIGNvbW1vbiBmYWN0b3Igb2YgdHdvXG4gICAgZm9yICh2YXIgc2hpZnQgPSAwOyBhLmlzRXZlbigpICYmIGIuaXNFdmVuKCk7IHNoaWZ0KyspIHtcbiAgICAgIGEuaXVzaHJuKDEpO1xuICAgICAgYi5pdXNocm4oMSk7XG4gICAgfVxuXG4gICAgZG8ge1xuICAgICAgd2hpbGUgKGEuaXNFdmVuKCkpIHtcbiAgICAgICAgYS5pdXNocm4oMSk7XG4gICAgICB9XG4gICAgICB3aGlsZSAoYi5pc0V2ZW4oKSkge1xuICAgICAgICBiLml1c2hybigxKTtcbiAgICAgIH1cblxuICAgICAgdmFyIHIgPSBhLmNtcChiKTtcbiAgICAgIGlmIChyIDwgMCkge1xuICAgICAgICAvLyBTd2FwIGBhYCBhbmQgYGJgIHRvIG1ha2UgYGFgIGFsd2F5cyBiaWdnZXIgdGhhbiBgYmBcbiAgICAgICAgdmFyIHQgPSBhO1xuICAgICAgICBhID0gYjtcbiAgICAgICAgYiA9IHQ7XG4gICAgICB9IGVsc2UgaWYgKHIgPT09IDAgfHwgYi5jbXBuKDEpID09PSAwKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4gICAgICBhLmlzdWIoYik7XG4gICAgfSB3aGlsZSAodHJ1ZSk7XG5cbiAgICByZXR1cm4gYi5pdXNobG4oc2hpZnQpO1xuICB9O1xuXG4gIC8vIEludmVydCBudW1iZXIgaW4gdGhlIGZpZWxkIEYobnVtKVxuICBCTi5wcm90b3R5cGUuaW52bSA9IGZ1bmN0aW9uIGludm0gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmVnY2QobnVtKS5hLnVtb2QobnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXNFdmVuID0gZnVuY3Rpb24gaXNFdmVuICgpIHtcbiAgICByZXR1cm4gKHRoaXMud29yZHNbMF0gJiAxKSA9PT0gMDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXNPZGQgPSBmdW5jdGlvbiBpc09kZCAoKSB7XG4gICAgcmV0dXJuICh0aGlzLndvcmRzWzBdICYgMSkgPT09IDE7XG4gIH07XG5cbiAgLy8gQW5kIGZpcnN0IHdvcmQgYW5kIG51bVxuICBCTi5wcm90b3R5cGUuYW5kbG4gPSBmdW5jdGlvbiBhbmRsbiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMud29yZHNbMF0gJiBudW07XG4gIH07XG5cbiAgLy8gSW5jcmVtZW50IGF0IHRoZSBiaXQgcG9zaXRpb24gaW4tbGluZVxuICBCTi5wcm90b3R5cGUuYmluY24gPSBmdW5jdGlvbiBiaW5jbiAoYml0KSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBiaXQgPT09ICdudW1iZXInKTtcbiAgICB2YXIgciA9IGJpdCAlIDI2O1xuICAgIHZhciBzID0gKGJpdCAtIHIpIC8gMjY7XG4gICAgdmFyIHEgPSAxIDw8IHI7XG5cbiAgICAvLyBGYXN0IGNhc2U6IGJpdCBpcyBtdWNoIGhpZ2hlciB0aGFuIGFsbCBleGlzdGluZyB3b3Jkc1xuICAgIGlmICh0aGlzLmxlbmd0aCA8PSBzKSB7XG4gICAgICB0aGlzLl9leHBhbmQocyArIDEpO1xuICAgICAgdGhpcy53b3Jkc1tzXSB8PSBxO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgLy8gQWRkIGJpdCBhbmQgcHJvcGFnYXRlLCBpZiBuZWVkZWRcbiAgICB2YXIgY2FycnkgPSBxO1xuICAgIGZvciAodmFyIGkgPSBzOyBjYXJyeSAhPT0gMCAmJiBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIHcgPSB0aGlzLndvcmRzW2ldIHwgMDtcbiAgICAgIHcgKz0gY2Fycnk7XG4gICAgICBjYXJyeSA9IHcgPj4+IDI2O1xuICAgICAgdyAmPSAweDNmZmZmZmY7XG4gICAgICB0aGlzLndvcmRzW2ldID0gdztcbiAgICB9XG4gICAgaWYgKGNhcnJ5ICE9PSAwKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gY2Fycnk7XG4gICAgICB0aGlzLmxlbmd0aCsrO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXNaZXJvID0gZnVuY3Rpb24gaXNaZXJvICgpIHtcbiAgICByZXR1cm4gdGhpcy5sZW5ndGggPT09IDEgJiYgdGhpcy53b3Jkc1swXSA9PT0gMDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuY21wbiA9IGZ1bmN0aW9uIGNtcG4gKG51bSkge1xuICAgIHZhciBuZWdhdGl2ZSA9IG51bSA8IDA7XG5cbiAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCAmJiAhbmVnYXRpdmUpIHJldHVybiAtMTtcbiAgICBpZiAodGhpcy5uZWdhdGl2ZSA9PT0gMCAmJiBuZWdhdGl2ZSkgcmV0dXJuIDE7XG5cbiAgICB0aGlzLnN0cmlwKCk7XG5cbiAgICB2YXIgcmVzO1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IDEpIHtcbiAgICAgIHJlcyA9IDE7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChuZWdhdGl2ZSkge1xuICAgICAgICBudW0gPSAtbnVtO1xuICAgICAgfVxuXG4gICAgICBhc3NlcnQobnVtIDw9IDB4M2ZmZmZmZiwgJ051bWJlciBpcyB0b28gYmlnJyk7XG5cbiAgICAgIHZhciB3ID0gdGhpcy53b3Jkc1swXSB8IDA7XG4gICAgICByZXMgPSB3ID09PSBudW0gPyAwIDogdyA8IG51bSA/IC0xIDogMTtcbiAgICB9XG4gICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHJldHVybiAtcmVzIHwgMDtcbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIC8vIENvbXBhcmUgdHdvIG51bWJlcnMgYW5kIHJldHVybjpcbiAgLy8gMSAtIGlmIGB0aGlzYCA+IGBudW1gXG4gIC8vIDAgLSBpZiBgdGhpc2AgPT0gYG51bWBcbiAgLy8gLTEgLSBpZiBgdGhpc2AgPCBgbnVtYFxuICBCTi5wcm90b3R5cGUuY21wID0gZnVuY3Rpb24gY21wIChudW0pIHtcbiAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCAmJiBudW0ubmVnYXRpdmUgPT09IDApIHJldHVybiAtMTtcbiAgICBpZiAodGhpcy5uZWdhdGl2ZSA9PT0gMCAmJiBudW0ubmVnYXRpdmUgIT09IDApIHJldHVybiAxO1xuXG4gICAgdmFyIHJlcyA9IHRoaXMudWNtcChudW0pO1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSByZXR1cm4gLXJlcyB8IDA7XG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICAvLyBVbnNpZ25lZCBjb21wYXJpc29uXG4gIEJOLnByb3RvdHlwZS51Y21wID0gZnVuY3Rpb24gdWNtcCAobnVtKSB7XG4gICAgLy8gQXQgdGhpcyBwb2ludCBib3RoIG51bWJlcnMgaGF2ZSB0aGUgc2FtZSBzaWduXG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkgcmV0dXJuIDE7XG4gICAgaWYgKHRoaXMubGVuZ3RoIDwgbnVtLmxlbmd0aCkgcmV0dXJuIC0xO1xuXG4gICAgdmFyIHJlcyA9IDA7XG4gICAgZm9yICh2YXIgaSA9IHRoaXMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICAgIHZhciBhID0gdGhpcy53b3Jkc1tpXSB8IDA7XG4gICAgICB2YXIgYiA9IG51bS53b3Jkc1tpXSB8IDA7XG5cbiAgICAgIGlmIChhID09PSBiKSBjb250aW51ZTtcbiAgICAgIGlmIChhIDwgYikge1xuICAgICAgICByZXMgPSAtMTtcbiAgICAgIH0gZWxzZSBpZiAoYSA+IGIpIHtcbiAgICAgICAgcmVzID0gMTtcbiAgICAgIH1cbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5ndG4gPSBmdW5jdGlvbiBndG4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcG4obnVtKSA9PT0gMTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZ3QgPSBmdW5jdGlvbiBndCAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wKG51bSkgPT09IDE7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmd0ZW4gPSBmdW5jdGlvbiBndGVuIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbXBuKG51bSkgPj0gMDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZ3RlID0gZnVuY3Rpb24gZ3RlIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbXAobnVtKSA+PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5sdG4gPSBmdW5jdGlvbiBsdG4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcG4obnVtKSA9PT0gLTE7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmx0ID0gZnVuY3Rpb24gbHQgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcChudW0pID09PSAtMTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUubHRlbiA9IGZ1bmN0aW9uIGx0ZW4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcG4obnVtKSA8PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5sdGUgPSBmdW5jdGlvbiBsdGUgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcChudW0pIDw9IDA7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmVxbiA9IGZ1bmN0aW9uIGVxbiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wbihudW0pID09PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5lcSA9IGZ1bmN0aW9uIGVxIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbXAobnVtKSA9PT0gMDtcbiAgfTtcblxuICAvL1xuICAvLyBBIHJlZHVjZSBjb250ZXh0LCBjb3VsZCBiZSB1c2luZyBtb250Z29tZXJ5IG9yIHNvbWV0aGluZyBiZXR0ZXIsIGRlcGVuZGluZ1xuICAvLyBvbiB0aGUgYG1gIGl0c2VsZi5cbiAgLy9cbiAgQk4ucmVkID0gZnVuY3Rpb24gcmVkIChudW0pIHtcbiAgICByZXR1cm4gbmV3IFJlZChudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS50b1JlZCA9IGZ1bmN0aW9uIHRvUmVkIChjdHgpIHtcbiAgICBhc3NlcnQoIXRoaXMucmVkLCAnQWxyZWFkeSBhIG51bWJlciBpbiByZWR1Y3Rpb24gY29udGV4dCcpO1xuICAgIGFzc2VydCh0aGlzLm5lZ2F0aXZlID09PSAwLCAncmVkIHdvcmtzIG9ubHkgd2l0aCBwb3NpdGl2ZXMnKTtcbiAgICByZXR1cm4gY3R4LmNvbnZlcnRUbyh0aGlzKS5fZm9yY2VSZWQoY3R4KTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZnJvbVJlZCA9IGZ1bmN0aW9uIGZyb21SZWQgKCkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ2Zyb21SZWQgd29ya3Mgb25seSB3aXRoIG51bWJlcnMgaW4gcmVkdWN0aW9uIGNvbnRleHQnKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuY29udmVydEZyb20odGhpcyk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLl9mb3JjZVJlZCA9IGZ1bmN0aW9uIF9mb3JjZVJlZCAoY3R4KSB7XG4gICAgdGhpcy5yZWQgPSBjdHg7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmZvcmNlUmVkID0gZnVuY3Rpb24gZm9yY2VSZWQgKGN0eCkge1xuICAgIGFzc2VydCghdGhpcy5yZWQsICdBbHJlYWR5IGEgbnVtYmVyIGluIHJlZHVjdGlvbiBjb250ZXh0Jyk7XG4gICAgcmV0dXJuIHRoaXMuX2ZvcmNlUmVkKGN0eCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnJlZEFkZCA9IGZ1bmN0aW9uIHJlZEFkZCAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkQWRkIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHJldHVybiB0aGlzLnJlZC5hZGQodGhpcywgbnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkSUFkZCA9IGZ1bmN0aW9uIHJlZElBZGQgKG51bSkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZElBZGQgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLmlhZGQodGhpcywgbnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkU3ViID0gZnVuY3Rpb24gcmVkU3ViIChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRTdWIgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLnN1Yih0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRJU3ViID0gZnVuY3Rpb24gcmVkSVN1YiAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkSVN1YiB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuaXN1Yih0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRTaGwgPSBmdW5jdGlvbiByZWRTaGwgKG51bSkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZFNobCB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuc2hsKHRoaXMsIG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnJlZE11bCA9IGZ1bmN0aW9uIHJlZE11bCAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkTXVsIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHRoaXMucmVkLl92ZXJpZnkyKHRoaXMsIG51bSk7XG4gICAgcmV0dXJuIHRoaXMucmVkLm11bCh0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRJTXVsID0gZnVuY3Rpb24gcmVkSU11bCAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkTXVsIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHRoaXMucmVkLl92ZXJpZnkyKHRoaXMsIG51bSk7XG4gICAgcmV0dXJuIHRoaXMucmVkLmltdWwodGhpcywgbnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkU3FyID0gZnVuY3Rpb24gcmVkU3FyICgpIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRTcXIgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTEodGhpcyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLnNxcih0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkSVNxciA9IGZ1bmN0aW9uIHJlZElTcXIgKCkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZElTcXIgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTEodGhpcyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLmlzcXIodGhpcyk7XG4gIH07XG5cbiAgLy8gU3F1YXJlIHJvb3Qgb3ZlciBwXG4gIEJOLnByb3RvdHlwZS5yZWRTcXJ0ID0gZnVuY3Rpb24gcmVkU3FydCAoKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkU3FydCB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICB0aGlzLnJlZC5fdmVyaWZ5MSh0aGlzKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuc3FydCh0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkSW52bSA9IGZ1bmN0aW9uIHJlZEludm0gKCkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZEludm0gd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTEodGhpcyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLmludm0odGhpcyk7XG4gIH07XG5cbiAgLy8gUmV0dXJuIG5lZ2F0aXZlIGNsb25lIG9mIGB0aGlzYCAlIGByZWQgbW9kdWxvYFxuICBCTi5wcm90b3R5cGUucmVkTmVnID0gZnVuY3Rpb24gcmVkTmVnICgpIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWROZWcgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTEodGhpcyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLm5lZyh0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkUG93ID0gZnVuY3Rpb24gcmVkUG93IChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQgJiYgIW51bS5yZWQsICdyZWRQb3cobm9ybWFsTnVtKScpO1xuICAgIHRoaXMucmVkLl92ZXJpZnkxKHRoaXMpO1xuICAgIHJldHVybiB0aGlzLnJlZC5wb3codGhpcywgbnVtKTtcbiAgfTtcblxuICAvLyBQcmltZSBudW1iZXJzIHdpdGggZWZmaWNpZW50IHJlZHVjdGlvblxuICB2YXIgcHJpbWVzID0ge1xuICAgIGsyNTY6IG51bGwsXG4gICAgcDIyNDogbnVsbCxcbiAgICBwMTkyOiBudWxsLFxuICAgIHAyNTUxOTogbnVsbFxuICB9O1xuXG4gIC8vIFBzZXVkby1NZXJzZW5uZSBwcmltZVxuICBmdW5jdGlvbiBNUHJpbWUgKG5hbWUsIHApIHtcbiAgICAvLyBQID0gMiBeIE4gLSBLXG4gICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICB0aGlzLnAgPSBuZXcgQk4ocCwgMTYpO1xuICAgIHRoaXMubiA9IHRoaXMucC5iaXRMZW5ndGgoKTtcbiAgICB0aGlzLmsgPSBuZXcgQk4oMSkuaXVzaGxuKHRoaXMubikuaXN1Yih0aGlzLnApO1xuXG4gICAgdGhpcy50bXAgPSB0aGlzLl90bXAoKTtcbiAgfVxuXG4gIE1QcmltZS5wcm90b3R5cGUuX3RtcCA9IGZ1bmN0aW9uIF90bXAgKCkge1xuICAgIHZhciB0bXAgPSBuZXcgQk4obnVsbCk7XG4gICAgdG1wLndvcmRzID0gbmV3IEFycmF5KE1hdGguY2VpbCh0aGlzLm4gLyAxMykpO1xuICAgIHJldHVybiB0bXA7XG4gIH07XG5cbiAgTVByaW1lLnByb3RvdHlwZS5pcmVkdWNlID0gZnVuY3Rpb24gaXJlZHVjZSAobnVtKSB7XG4gICAgLy8gQXNzdW1lcyB0aGF0IGBudW1gIGlzIGxlc3MgdGhhbiBgUF4yYFxuICAgIC8vIG51bSA9IEhJICogKDIgXiBOIC0gSykgKyBISSAqIEsgKyBMTyA9IEhJICogSyArIExPIChtb2QgUClcbiAgICB2YXIgciA9IG51bTtcbiAgICB2YXIgcmxlbjtcblxuICAgIGRvIHtcbiAgICAgIHRoaXMuc3BsaXQociwgdGhpcy50bXApO1xuICAgICAgciA9IHRoaXMuaW11bEsocik7XG4gICAgICByID0gci5pYWRkKHRoaXMudG1wKTtcbiAgICAgIHJsZW4gPSByLmJpdExlbmd0aCgpO1xuICAgIH0gd2hpbGUgKHJsZW4gPiB0aGlzLm4pO1xuXG4gICAgdmFyIGNtcCA9IHJsZW4gPCB0aGlzLm4gPyAtMSA6IHIudWNtcCh0aGlzLnApO1xuICAgIGlmIChjbXAgPT09IDApIHtcbiAgICAgIHIud29yZHNbMF0gPSAwO1xuICAgICAgci5sZW5ndGggPSAxO1xuICAgIH0gZWxzZSBpZiAoY21wID4gMCkge1xuICAgICAgci5pc3ViKHRoaXMucCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHIuc3RyaXAoKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcjtcbiAgfTtcblxuICBNUHJpbWUucHJvdG90eXBlLnNwbGl0ID0gZnVuY3Rpb24gc3BsaXQgKGlucHV0LCBvdXQpIHtcbiAgICBpbnB1dC5pdXNocm4odGhpcy5uLCAwLCBvdXQpO1xuICB9O1xuXG4gIE1QcmltZS5wcm90b3R5cGUuaW11bEsgPSBmdW5jdGlvbiBpbXVsSyAobnVtKSB7XG4gICAgcmV0dXJuIG51bS5pbXVsKHRoaXMuayk7XG4gIH07XG5cbiAgZnVuY3Rpb24gSzI1NiAoKSB7XG4gICAgTVByaW1lLmNhbGwoXG4gICAgICB0aGlzLFxuICAgICAgJ2syNTYnLFxuICAgICAgJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZlIGZmZmZmYzJmJyk7XG4gIH1cbiAgaW5oZXJpdHMoSzI1NiwgTVByaW1lKTtcblxuICBLMjU2LnByb3RvdHlwZS5zcGxpdCA9IGZ1bmN0aW9uIHNwbGl0IChpbnB1dCwgb3V0cHV0KSB7XG4gICAgLy8gMjU2ID0gOSAqIDI2ICsgMjJcbiAgICB2YXIgbWFzayA9IDB4M2ZmZmZmO1xuXG4gICAgdmFyIG91dExlbiA9IE1hdGgubWluKGlucHV0Lmxlbmd0aCwgOSk7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBvdXRMZW47IGkrKykge1xuICAgICAgb3V0cHV0LndvcmRzW2ldID0gaW5wdXQud29yZHNbaV07XG4gICAgfVxuICAgIG91dHB1dC5sZW5ndGggPSBvdXRMZW47XG5cbiAgICBpZiAoaW5wdXQubGVuZ3RoIDw9IDkpIHtcbiAgICAgIGlucHV0LndvcmRzWzBdID0gMDtcbiAgICAgIGlucHV0Lmxlbmd0aCA9IDE7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gU2hpZnQgYnkgOSBsaW1ic1xuICAgIHZhciBwcmV2ID0gaW5wdXQud29yZHNbOV07XG4gICAgb3V0cHV0LndvcmRzW291dHB1dC5sZW5ndGgrK10gPSBwcmV2ICYgbWFzaztcblxuICAgIGZvciAoaSA9IDEwOyBpIDwgaW5wdXQubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBuZXh0ID0gaW5wdXQud29yZHNbaV0gfCAwO1xuICAgICAgaW5wdXQud29yZHNbaSAtIDEwXSA9ICgobmV4dCAmIG1hc2spIDw8IDQpIHwgKHByZXYgPj4+IDIyKTtcbiAgICAgIHByZXYgPSBuZXh0O1xuICAgIH1cbiAgICBwcmV2ID4+Pj0gMjI7XG4gICAgaW5wdXQud29yZHNbaSAtIDEwXSA9IHByZXY7XG4gICAgaWYgKHByZXYgPT09IDAgJiYgaW5wdXQubGVuZ3RoID4gMTApIHtcbiAgICAgIGlucHV0Lmxlbmd0aCAtPSAxMDtcbiAgICB9IGVsc2Uge1xuICAgICAgaW5wdXQubGVuZ3RoIC09IDk7XG4gICAgfVxuICB9O1xuXG4gIEsyNTYucHJvdG90eXBlLmltdWxLID0gZnVuY3Rpb24gaW11bEsgKG51bSkge1xuICAgIC8vIEsgPSAweDEwMDAwMDNkMSA9IFsgMHg0MCwgMHgzZDEgXVxuICAgIG51bS53b3Jkc1tudW0ubGVuZ3RoXSA9IDA7XG4gICAgbnVtLndvcmRzW251bS5sZW5ndGggKyAxXSA9IDA7XG4gICAgbnVtLmxlbmd0aCArPSAyO1xuXG4gICAgLy8gYm91bmRlZCBhdDogMHg0MCAqIDB4M2ZmZmZmZiArIDB4M2QwID0gMHgxMDAwMDAzOTBcbiAgICB2YXIgbG8gPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbnVtLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgdyA9IG51bS53b3Jkc1tpXSB8IDA7XG4gICAgICBsbyArPSB3ICogMHgzZDE7XG4gICAgICBudW0ud29yZHNbaV0gPSBsbyAmIDB4M2ZmZmZmZjtcbiAgICAgIGxvID0gdyAqIDB4NDAgKyAoKGxvIC8gMHg0MDAwMDAwKSB8IDApO1xuICAgIH1cblxuICAgIC8vIEZhc3QgbGVuZ3RoIHJlZHVjdGlvblxuICAgIGlmIChudW0ud29yZHNbbnVtLmxlbmd0aCAtIDFdID09PSAwKSB7XG4gICAgICBudW0ubGVuZ3RoLS07XG4gICAgICBpZiAobnVtLndvcmRzW251bS5sZW5ndGggLSAxXSA9PT0gMCkge1xuICAgICAgICBudW0ubGVuZ3RoLS07XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBudW07XG4gIH07XG5cbiAgZnVuY3Rpb24gUDIyNCAoKSB7XG4gICAgTVByaW1lLmNhbGwoXG4gICAgICB0aGlzLFxuICAgICAgJ3AyMjQnLFxuICAgICAgJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAxJyk7XG4gIH1cbiAgaW5oZXJpdHMoUDIyNCwgTVByaW1lKTtcblxuICBmdW5jdGlvbiBQMTkyICgpIHtcbiAgICBNUHJpbWUuY2FsbChcbiAgICAgIHRoaXMsXG4gICAgICAncDE5MicsXG4gICAgICAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmUgZmZmZmZmZmYgZmZmZmZmZmYnKTtcbiAgfVxuICBpbmhlcml0cyhQMTkyLCBNUHJpbWUpO1xuXG4gIGZ1bmN0aW9uIFAyNTUxOSAoKSB7XG4gICAgLy8gMiBeIDI1NSAtIDE5XG4gICAgTVByaW1lLmNhbGwoXG4gICAgICB0aGlzLFxuICAgICAgJzI1NTE5JyxcbiAgICAgICc3ZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmVkJyk7XG4gIH1cbiAgaW5oZXJpdHMoUDI1NTE5LCBNUHJpbWUpO1xuXG4gIFAyNTUxOS5wcm90b3R5cGUuaW11bEsgPSBmdW5jdGlvbiBpbXVsSyAobnVtKSB7XG4gICAgLy8gSyA9IDB4MTNcbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbnVtLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgaGkgPSAobnVtLndvcmRzW2ldIHwgMCkgKiAweDEzICsgY2Fycnk7XG4gICAgICB2YXIgbG8gPSBoaSAmIDB4M2ZmZmZmZjtcbiAgICAgIGhpID4+Pj0gMjY7XG5cbiAgICAgIG51bS53b3Jkc1tpXSA9IGxvO1xuICAgICAgY2FycnkgPSBoaTtcbiAgICB9XG4gICAgaWYgKGNhcnJ5ICE9PSAwKSB7XG4gICAgICBudW0ud29yZHNbbnVtLmxlbmd0aCsrXSA9IGNhcnJ5O1xuICAgIH1cbiAgICByZXR1cm4gbnVtO1xuICB9O1xuXG4gIC8vIEV4cG9ydGVkIG1vc3RseSBmb3IgdGVzdGluZyBwdXJwb3NlcywgdXNlIHBsYWluIG5hbWUgaW5zdGVhZFxuICBCTi5fcHJpbWUgPSBmdW5jdGlvbiBwcmltZSAobmFtZSkge1xuICAgIC8vIENhY2hlZCB2ZXJzaW9uIG9mIHByaW1lXG4gICAgaWYgKHByaW1lc1tuYW1lXSkgcmV0dXJuIHByaW1lc1tuYW1lXTtcblxuICAgIHZhciBwcmltZTtcbiAgICBpZiAobmFtZSA9PT0gJ2syNTYnKSB7XG4gICAgICBwcmltZSA9IG5ldyBLMjU2KCk7XG4gICAgfSBlbHNlIGlmIChuYW1lID09PSAncDIyNCcpIHtcbiAgICAgIHByaW1lID0gbmV3IFAyMjQoKTtcbiAgICB9IGVsc2UgaWYgKG5hbWUgPT09ICdwMTkyJykge1xuICAgICAgcHJpbWUgPSBuZXcgUDE5MigpO1xuICAgIH0gZWxzZSBpZiAobmFtZSA9PT0gJ3AyNTUxOScpIHtcbiAgICAgIHByaW1lID0gbmV3IFAyNTUxOSgpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1Vua25vd24gcHJpbWUgJyArIG5hbWUpO1xuICAgIH1cbiAgICBwcmltZXNbbmFtZV0gPSBwcmltZTtcblxuICAgIHJldHVybiBwcmltZTtcbiAgfTtcblxuICAvL1xuICAvLyBCYXNlIHJlZHVjdGlvbiBlbmdpbmVcbiAgLy9cbiAgZnVuY3Rpb24gUmVkIChtKSB7XG4gICAgaWYgKHR5cGVvZiBtID09PSAnc3RyaW5nJykge1xuICAgICAgdmFyIHByaW1lID0gQk4uX3ByaW1lKG0pO1xuICAgICAgdGhpcy5tID0gcHJpbWUucDtcbiAgICAgIHRoaXMucHJpbWUgPSBwcmltZTtcbiAgICB9IGVsc2Uge1xuICAgICAgYXNzZXJ0KG0uZ3RuKDEpLCAnbW9kdWx1cyBtdXN0IGJlIGdyZWF0ZXIgdGhhbiAxJyk7XG4gICAgICB0aGlzLm0gPSBtO1xuICAgICAgdGhpcy5wcmltZSA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgUmVkLnByb3RvdHlwZS5fdmVyaWZ5MSA9IGZ1bmN0aW9uIF92ZXJpZnkxIChhKSB7XG4gICAgYXNzZXJ0KGEubmVnYXRpdmUgPT09IDAsICdyZWQgd29ya3Mgb25seSB3aXRoIHBvc2l0aXZlcycpO1xuICAgIGFzc2VydChhLnJlZCwgJ3JlZCB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLl92ZXJpZnkyID0gZnVuY3Rpb24gX3ZlcmlmeTIgKGEsIGIpIHtcbiAgICBhc3NlcnQoKGEubmVnYXRpdmUgfCBiLm5lZ2F0aXZlKSA9PT0gMCwgJ3JlZCB3b3JrcyBvbmx5IHdpdGggcG9zaXRpdmVzJyk7XG4gICAgYXNzZXJ0KGEucmVkICYmIGEucmVkID09PSBiLnJlZCxcbiAgICAgICdyZWQgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5pbW9kID0gZnVuY3Rpb24gaW1vZCAoYSkge1xuICAgIGlmICh0aGlzLnByaW1lKSByZXR1cm4gdGhpcy5wcmltZS5pcmVkdWNlKGEpLl9mb3JjZVJlZCh0aGlzKTtcbiAgICByZXR1cm4gYS51bW9kKHRoaXMubSkuX2ZvcmNlUmVkKHRoaXMpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUubmVnID0gZnVuY3Rpb24gbmVnIChhKSB7XG4gICAgaWYgKGEuaXNaZXJvKCkpIHtcbiAgICAgIHJldHVybiBhLmNsb25lKCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMubS5zdWIoYSkuX2ZvcmNlUmVkKHRoaXMpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuYWRkID0gZnVuY3Rpb24gYWRkIChhLCBiKSB7XG4gICAgdGhpcy5fdmVyaWZ5MihhLCBiKTtcblxuICAgIHZhciByZXMgPSBhLmFkZChiKTtcbiAgICBpZiAocmVzLmNtcCh0aGlzLm0pID49IDApIHtcbiAgICAgIHJlcy5pc3ViKHRoaXMubSk7XG4gICAgfVxuICAgIHJldHVybiByZXMuX2ZvcmNlUmVkKHRoaXMpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuaWFkZCA9IGZ1bmN0aW9uIGlhZGQgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuXG4gICAgdmFyIHJlcyA9IGEuaWFkZChiKTtcbiAgICBpZiAocmVzLmNtcCh0aGlzLm0pID49IDApIHtcbiAgICAgIHJlcy5pc3ViKHRoaXMubSk7XG4gICAgfVxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5zdWIgPSBmdW5jdGlvbiBzdWIgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuXG4gICAgdmFyIHJlcyA9IGEuc3ViKGIpO1xuICAgIGlmIChyZXMuY21wbigwKSA8IDApIHtcbiAgICAgIHJlcy5pYWRkKHRoaXMubSk7XG4gICAgfVxuICAgIHJldHVybiByZXMuX2ZvcmNlUmVkKHRoaXMpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuaXN1YiA9IGZ1bmN0aW9uIGlzdWIgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuXG4gICAgdmFyIHJlcyA9IGEuaXN1YihiKTtcbiAgICBpZiAocmVzLmNtcG4oMCkgPCAwKSB7XG4gICAgICByZXMuaWFkZCh0aGlzLm0pO1xuICAgIH1cbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuc2hsID0gZnVuY3Rpb24gc2hsIChhLCBudW0pIHtcbiAgICB0aGlzLl92ZXJpZnkxKGEpO1xuICAgIHJldHVybiB0aGlzLmltb2QoYS51c2hsbihudW0pKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLmltdWwgPSBmdW5jdGlvbiBpbXVsIChhLCBiKSB7XG4gICAgdGhpcy5fdmVyaWZ5MihhLCBiKTtcbiAgICByZXR1cm4gdGhpcy5pbW9kKGEuaW11bChiKSk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuICAgIHJldHVybiB0aGlzLmltb2QoYS5tdWwoYikpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuaXNxciA9IGZ1bmN0aW9uIGlzcXIgKGEpIHtcbiAgICByZXR1cm4gdGhpcy5pbXVsKGEsIGEuY2xvbmUoKSk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5zcXIgPSBmdW5jdGlvbiBzcXIgKGEpIHtcbiAgICByZXR1cm4gdGhpcy5tdWwoYSwgYSk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5zcXJ0ID0gZnVuY3Rpb24gc3FydCAoYSkge1xuICAgIGlmIChhLmlzWmVybygpKSByZXR1cm4gYS5jbG9uZSgpO1xuXG4gICAgdmFyIG1vZDMgPSB0aGlzLm0uYW5kbG4oMyk7XG4gICAgYXNzZXJ0KG1vZDMgJSAyID09PSAxKTtcblxuICAgIC8vIEZhc3QgY2FzZVxuICAgIGlmIChtb2QzID09PSAzKSB7XG4gICAgICB2YXIgcG93ID0gdGhpcy5tLmFkZChuZXcgQk4oMSkpLml1c2hybigyKTtcbiAgICAgIHJldHVybiB0aGlzLnBvdyhhLCBwb3cpO1xuICAgIH1cblxuICAgIC8vIFRvbmVsbGktU2hhbmtzIGFsZ29yaXRobSAoVG90YWxseSB1bm9wdGltaXplZCBhbmQgc2xvdylcbiAgICAvL1xuICAgIC8vIEZpbmQgUSBhbmQgUywgdGhhdCBRICogMiBeIFMgPSAoUCAtIDEpXG4gICAgdmFyIHEgPSB0aGlzLm0uc3VibigxKTtcbiAgICB2YXIgcyA9IDA7XG4gICAgd2hpbGUgKCFxLmlzWmVybygpICYmIHEuYW5kbG4oMSkgPT09IDApIHtcbiAgICAgIHMrKztcbiAgICAgIHEuaXVzaHJuKDEpO1xuICAgIH1cbiAgICBhc3NlcnQoIXEuaXNaZXJvKCkpO1xuXG4gICAgdmFyIG9uZSA9IG5ldyBCTigxKS50b1JlZCh0aGlzKTtcbiAgICB2YXIgbk9uZSA9IG9uZS5yZWROZWcoKTtcblxuICAgIC8vIEZpbmQgcXVhZHJhdGljIG5vbi1yZXNpZHVlXG4gICAgLy8gTk9URTogTWF4IGlzIHN1Y2ggYmVjYXVzZSBvZiBnZW5lcmFsaXplZCBSaWVtYW5uIGh5cG90aGVzaXMuXG4gICAgdmFyIGxwb3cgPSB0aGlzLm0uc3VibigxKS5pdXNocm4oMSk7XG4gICAgdmFyIHogPSB0aGlzLm0uYml0TGVuZ3RoKCk7XG4gICAgeiA9IG5ldyBCTigyICogeiAqIHopLnRvUmVkKHRoaXMpO1xuXG4gICAgd2hpbGUgKHRoaXMucG93KHosIGxwb3cpLmNtcChuT25lKSAhPT0gMCkge1xuICAgICAgei5yZWRJQWRkKG5PbmUpO1xuICAgIH1cblxuICAgIHZhciBjID0gdGhpcy5wb3coeiwgcSk7XG4gICAgdmFyIHIgPSB0aGlzLnBvdyhhLCBxLmFkZG4oMSkuaXVzaHJuKDEpKTtcbiAgICB2YXIgdCA9IHRoaXMucG93KGEsIHEpO1xuICAgIHZhciBtID0gcztcbiAgICB3aGlsZSAodC5jbXAob25lKSAhPT0gMCkge1xuICAgICAgdmFyIHRtcCA9IHQ7XG4gICAgICBmb3IgKHZhciBpID0gMDsgdG1wLmNtcChvbmUpICE9PSAwOyBpKyspIHtcbiAgICAgICAgdG1wID0gdG1wLnJlZFNxcigpO1xuICAgICAgfVxuICAgICAgYXNzZXJ0KGkgPCBtKTtcbiAgICAgIHZhciBiID0gdGhpcy5wb3coYywgbmV3IEJOKDEpLml1c2hsbihtIC0gaSAtIDEpKTtcblxuICAgICAgciA9IHIucmVkTXVsKGIpO1xuICAgICAgYyA9IGIucmVkU3FyKCk7XG4gICAgICB0ID0gdC5yZWRNdWwoYyk7XG4gICAgICBtID0gaTtcbiAgICB9XG5cbiAgICByZXR1cm4gcjtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLmludm0gPSBmdW5jdGlvbiBpbnZtIChhKSB7XG4gICAgdmFyIGludiA9IGEuX2ludm1wKHRoaXMubSk7XG4gICAgaWYgKGludi5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgaW52Lm5lZ2F0aXZlID0gMDtcbiAgICAgIHJldHVybiB0aGlzLmltb2QoaW52KS5yZWROZWcoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMuaW1vZChpbnYpO1xuICAgIH1cbiAgfTtcblxuICBSZWQucHJvdG90eXBlLnBvdyA9IGZ1bmN0aW9uIHBvdyAoYSwgbnVtKSB7XG4gICAgaWYgKG51bS5pc1plcm8oKSkgcmV0dXJuIG5ldyBCTigxKTtcbiAgICBpZiAobnVtLmNtcG4oMSkgPT09IDApIHJldHVybiBhLmNsb25lKCk7XG5cbiAgICB2YXIgd2luZG93U2l6ZSA9IDQ7XG4gICAgdmFyIHduZCA9IG5ldyBBcnJheSgxIDw8IHdpbmRvd1NpemUpO1xuICAgIHduZFswXSA9IG5ldyBCTigxKS50b1JlZCh0aGlzKTtcbiAgICB3bmRbMV0gPSBhO1xuICAgIGZvciAodmFyIGkgPSAyOyBpIDwgd25kLmxlbmd0aDsgaSsrKSB7XG4gICAgICB3bmRbaV0gPSB0aGlzLm11bCh3bmRbaSAtIDFdLCBhKTtcbiAgICB9XG5cbiAgICB2YXIgcmVzID0gd25kWzBdO1xuICAgIHZhciBjdXJyZW50ID0gMDtcbiAgICB2YXIgY3VycmVudExlbiA9IDA7XG4gICAgdmFyIHN0YXJ0ID0gbnVtLmJpdExlbmd0aCgpICUgMjY7XG4gICAgaWYgKHN0YXJ0ID09PSAwKSB7XG4gICAgICBzdGFydCA9IDI2O1xuICAgIH1cblxuICAgIGZvciAoaSA9IG51bS5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgICAgdmFyIHdvcmQgPSBudW0ud29yZHNbaV07XG4gICAgICBmb3IgKHZhciBqID0gc3RhcnQgLSAxOyBqID49IDA7IGotLSkge1xuICAgICAgICB2YXIgYml0ID0gKHdvcmQgPj4gaikgJiAxO1xuICAgICAgICBpZiAocmVzICE9PSB3bmRbMF0pIHtcbiAgICAgICAgICByZXMgPSB0aGlzLnNxcihyZXMpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGJpdCA9PT0gMCAmJiBjdXJyZW50ID09PSAwKSB7XG4gICAgICAgICAgY3VycmVudExlbiA9IDA7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBjdXJyZW50IDw8PSAxO1xuICAgICAgICBjdXJyZW50IHw9IGJpdDtcbiAgICAgICAgY3VycmVudExlbisrO1xuICAgICAgICBpZiAoY3VycmVudExlbiAhPT0gd2luZG93U2l6ZSAmJiAoaSAhPT0gMCB8fCBqICE9PSAwKSkgY29udGludWU7XG5cbiAgICAgICAgcmVzID0gdGhpcy5tdWwocmVzLCB3bmRbY3VycmVudF0pO1xuICAgICAgICBjdXJyZW50TGVuID0gMDtcbiAgICAgICAgY3VycmVudCA9IDA7XG4gICAgICB9XG4gICAgICBzdGFydCA9IDI2O1xuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5jb252ZXJ0VG8gPSBmdW5jdGlvbiBjb252ZXJ0VG8gKG51bSkge1xuICAgIHZhciByID0gbnVtLnVtb2QodGhpcy5tKTtcblxuICAgIHJldHVybiByID09PSBudW0gPyByLmNsb25lKCkgOiByO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuY29udmVydEZyb20gPSBmdW5jdGlvbiBjb252ZXJ0RnJvbSAobnVtKSB7XG4gICAgdmFyIHJlcyA9IG51bS5jbG9uZSgpO1xuICAgIHJlcy5yZWQgPSBudWxsO1xuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgLy9cbiAgLy8gTW9udGdvbWVyeSBtZXRob2QgZW5naW5lXG4gIC8vXG5cbiAgQk4ubW9udCA9IGZ1bmN0aW9uIG1vbnQgKG51bSkge1xuICAgIHJldHVybiBuZXcgTW9udChudW0pO1xuICB9O1xuXG4gIGZ1bmN0aW9uIE1vbnQgKG0pIHtcbiAgICBSZWQuY2FsbCh0aGlzLCBtKTtcblxuICAgIHRoaXMuc2hpZnQgPSB0aGlzLm0uYml0TGVuZ3RoKCk7XG4gICAgaWYgKHRoaXMuc2hpZnQgJSAyNiAhPT0gMCkge1xuICAgICAgdGhpcy5zaGlmdCArPSAyNiAtICh0aGlzLnNoaWZ0ICUgMjYpO1xuICAgIH1cblxuICAgIHRoaXMuciA9IG5ldyBCTigxKS5pdXNobG4odGhpcy5zaGlmdCk7XG4gICAgdGhpcy5yMiA9IHRoaXMuaW1vZCh0aGlzLnIuc3FyKCkpO1xuICAgIHRoaXMucmludiA9IHRoaXMuci5faW52bXAodGhpcy5tKTtcblxuICAgIHRoaXMubWludiA9IHRoaXMucmludi5tdWwodGhpcy5yKS5pc3VibigxKS5kaXYodGhpcy5tKTtcbiAgICB0aGlzLm1pbnYgPSB0aGlzLm1pbnYudW1vZCh0aGlzLnIpO1xuICAgIHRoaXMubWludiA9IHRoaXMuci5zdWIodGhpcy5taW52KTtcbiAgfVxuICBpbmhlcml0cyhNb250LCBSZWQpO1xuXG4gIE1vbnQucHJvdG90eXBlLmNvbnZlcnRUbyA9IGZ1bmN0aW9uIGNvbnZlcnRUbyAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuaW1vZChudW0udXNobG4odGhpcy5zaGlmdCkpO1xuICB9O1xuXG4gIE1vbnQucHJvdG90eXBlLmNvbnZlcnRGcm9tID0gZnVuY3Rpb24gY29udmVydEZyb20gKG51bSkge1xuICAgIHZhciByID0gdGhpcy5pbW9kKG51bS5tdWwodGhpcy5yaW52KSk7XG4gICAgci5yZWQgPSBudWxsO1xuICAgIHJldHVybiByO1xuICB9O1xuXG4gIE1vbnQucHJvdG90eXBlLmltdWwgPSBmdW5jdGlvbiBpbXVsIChhLCBiKSB7XG4gICAgaWYgKGEuaXNaZXJvKCkgfHwgYi5pc1plcm8oKSkge1xuICAgICAgYS53b3Jkc1swXSA9IDA7XG4gICAgICBhLmxlbmd0aCA9IDE7XG4gICAgICByZXR1cm4gYTtcbiAgICB9XG5cbiAgICB2YXIgdCA9IGEuaW11bChiKTtcbiAgICB2YXIgYyA9IHQubWFza24odGhpcy5zaGlmdCkubXVsKHRoaXMubWludikuaW1hc2tuKHRoaXMuc2hpZnQpLm11bCh0aGlzLm0pO1xuICAgIHZhciB1ID0gdC5pc3ViKGMpLml1c2hybih0aGlzLnNoaWZ0KTtcbiAgICB2YXIgcmVzID0gdTtcblxuICAgIGlmICh1LmNtcCh0aGlzLm0pID49IDApIHtcbiAgICAgIHJlcyA9IHUuaXN1Yih0aGlzLm0pO1xuICAgIH0gZWxzZSBpZiAodS5jbXBuKDApIDwgMCkge1xuICAgICAgcmVzID0gdS5pYWRkKHRoaXMubSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcy5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgTW9udC5wcm90b3R5cGUubXVsID0gZnVuY3Rpb24gbXVsIChhLCBiKSB7XG4gICAgaWYgKGEuaXNaZXJvKCkgfHwgYi5pc1plcm8oKSkgcmV0dXJuIG5ldyBCTigwKS5fZm9yY2VSZWQodGhpcyk7XG5cbiAgICB2YXIgdCA9IGEubXVsKGIpO1xuICAgIHZhciBjID0gdC5tYXNrbih0aGlzLnNoaWZ0KS5tdWwodGhpcy5taW52KS5pbWFza24odGhpcy5zaGlmdCkubXVsKHRoaXMubSk7XG4gICAgdmFyIHUgPSB0LmlzdWIoYykuaXVzaHJuKHRoaXMuc2hpZnQpO1xuICAgIHZhciByZXMgPSB1O1xuICAgIGlmICh1LmNtcCh0aGlzLm0pID49IDApIHtcbiAgICAgIHJlcyA9IHUuaXN1Yih0aGlzLm0pO1xuICAgIH0gZWxzZSBpZiAodS5jbXBuKDApIDwgMCkge1xuICAgICAgcmVzID0gdS5pYWRkKHRoaXMubSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcy5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgTW9udC5wcm90b3R5cGUuaW52bSA9IGZ1bmN0aW9uIGludm0gKGEpIHtcbiAgICAvLyAoQVIpXi0xICogUl4yID0gKEFeLTEgKiBSXi0xKSAqIFJeMiA9IEFeLTEgKiBSXG4gICAgdmFyIHJlcyA9IHRoaXMuaW1vZChhLl9pbnZtcCh0aGlzLm0pLm11bCh0aGlzLnIyKSk7XG4gICAgcmV0dXJuIHJlcy5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG59KSh0eXBlb2YgbW9kdWxlID09PSAndW5kZWZpbmVkJyB8fCBtb2R1bGUsIHRoaXMpO1xuIiwidmFyIHI7XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcmFuZChsZW4pIHtcbiAgaWYgKCFyKVxuICAgIHIgPSBuZXcgUmFuZChudWxsKTtcblxuICByZXR1cm4gci5nZW5lcmF0ZShsZW4pO1xufTtcblxuZnVuY3Rpb24gUmFuZChyYW5kKSB7XG4gIHRoaXMucmFuZCA9IHJhbmQ7XG59XG5tb2R1bGUuZXhwb3J0cy5SYW5kID0gUmFuZDtcblxuUmFuZC5wcm90b3R5cGUuZ2VuZXJhdGUgPSBmdW5jdGlvbiBnZW5lcmF0ZShsZW4pIHtcbiAgcmV0dXJuIHRoaXMuX3JhbmQobGVuKTtcbn07XG5cbmlmICh0eXBlb2Ygd2luZG93ID09PSAnb2JqZWN0Jykge1xuICBpZiAod2luZG93LmNyeXB0byAmJiB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcykge1xuICAgIC8vIE1vZGVybiBicm93c2Vyc1xuICAgIFJhbmQucHJvdG90eXBlLl9yYW5kID0gZnVuY3Rpb24gX3JhbmQobikge1xuICAgICAgdmFyIGFyciA9IG5ldyBVaW50OEFycmF5KG4pO1xuICAgICAgd2luZG93LmNyeXB0by5nZXRSYW5kb21WYWx1ZXMoYXJyKTtcbiAgICAgIHJldHVybiBhcnI7XG4gICAgfTtcbiAgfSBlbHNlIGlmICh3aW5kb3cubXNDcnlwdG8gJiYgd2luZG93Lm1zQ3J5cHRvLmdldFJhbmRvbVZhbHVlcykge1xuICAgIC8vIElFXG4gICAgUmFuZC5wcm90b3R5cGUuX3JhbmQgPSBmdW5jdGlvbiBfcmFuZChuKSB7XG4gICAgICB2YXIgYXJyID0gbmV3IFVpbnQ4QXJyYXkobik7XG4gICAgICB3aW5kb3cubXNDcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGFycik7XG4gICAgICByZXR1cm4gYXJyO1xuICAgIH07XG4gIH0gZWxzZSB7XG4gICAgLy8gT2xkIGp1bmtcbiAgICBSYW5kLnByb3RvdHlwZS5fcmFuZCA9IGZ1bmN0aW9uKCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgaW1wbGVtZW50ZWQgeWV0Jyk7XG4gICAgfTtcbiAgfVxufSBlbHNlIHtcbiAgLy8gTm9kZS5qcyBvciBXZWIgd29ya2VyXG4gIHRyeSB7XG4gICAgdmFyIGNyeXB0byA9IHJlcXVpcmUoJ2NyeScgKyAncHRvJyk7XG5cbiAgICBSYW5kLnByb3RvdHlwZS5fcmFuZCA9IGZ1bmN0aW9uIF9yYW5kKG4pIHtcbiAgICAgIHJldHVybiBjcnlwdG8ucmFuZG9tQnl0ZXMobik7XG4gICAgfTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIC8vIEVtdWxhdGUgY3J5cHRvIEFQSSB1c2luZyByYW5keVxuICAgIFJhbmQucHJvdG90eXBlLl9yYW5kID0gZnVuY3Rpb24gX3JhbmQobikge1xuICAgICAgdmFyIHJlcyA9IG5ldyBVaW50OEFycmF5KG4pO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCByZXMubGVuZ3RoOyBpKyspXG4gICAgICAgIHJlc1tpXSA9IHRoaXMucmFuZC5nZXRCeXRlKCk7XG4gICAgICByZXR1cm4gcmVzO1xuICAgIH07XG4gIH1cbn1cbiIsIi8qIVxuICogVGhlIGJ1ZmZlciBtb2R1bGUgZnJvbSBub2RlLmpzLCBmb3IgdGhlIGJyb3dzZXIuXG4gKlxuICogQGF1dGhvciAgIEZlcm9zcyBBYm91a2hhZGlqZWggPGZlcm9zc0BmZXJvc3Mub3JnPiA8aHR0cDovL2Zlcm9zcy5vcmc+XG4gKiBAbGljZW5zZSAgTUlUXG4gKi9cbi8qIGVzbGludC1kaXNhYmxlIG5vLXByb3RvICovXG5cbid1c2Ugc3RyaWN0J1xuXG52YXIgYmFzZTY0ID0gcmVxdWlyZSgnYmFzZTY0LWpzJylcbnZhciBpZWVlNzU0ID0gcmVxdWlyZSgnaWVlZTc1NCcpXG52YXIgaXNBcnJheSA9IHJlcXVpcmUoJ2lzYXJyYXknKVxuXG5leHBvcnRzLkJ1ZmZlciA9IEJ1ZmZlclxuZXhwb3J0cy5TbG93QnVmZmVyID0gU2xvd0J1ZmZlclxuZXhwb3J0cy5JTlNQRUNUX01BWF9CWVRFUyA9IDUwXG5cbi8qKlxuICogSWYgYEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUYDpcbiAqICAgPT09IHRydWUgICAgVXNlIFVpbnQ4QXJyYXkgaW1wbGVtZW50YXRpb24gKGZhc3Rlc3QpXG4gKiAgID09PSBmYWxzZSAgIFVzZSBPYmplY3QgaW1wbGVtZW50YXRpb24gKG1vc3QgY29tcGF0aWJsZSwgZXZlbiBJRTYpXG4gKlxuICogQnJvd3NlcnMgdGhhdCBzdXBwb3J0IHR5cGVkIGFycmF5cyBhcmUgSUUgMTArLCBGaXJlZm94IDQrLCBDaHJvbWUgNyssIFNhZmFyaSA1LjErLFxuICogT3BlcmEgMTEuNissIGlPUyA0LjIrLlxuICpcbiAqIER1ZSB0byB2YXJpb3VzIGJyb3dzZXIgYnVncywgc29tZXRpbWVzIHRoZSBPYmplY3QgaW1wbGVtZW50YXRpb24gd2lsbCBiZSB1c2VkIGV2ZW5cbiAqIHdoZW4gdGhlIGJyb3dzZXIgc3VwcG9ydHMgdHlwZWQgYXJyYXlzLlxuICpcbiAqIE5vdGU6XG4gKlxuICogICAtIEZpcmVmb3ggNC0yOSBsYWNrcyBzdXBwb3J0IGZvciBhZGRpbmcgbmV3IHByb3BlcnRpZXMgdG8gYFVpbnQ4QXJyYXlgIGluc3RhbmNlcyxcbiAqICAgICBTZWU6IGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTY5NTQzOC5cbiAqXG4gKiAgIC0gQ2hyb21lIDktMTAgaXMgbWlzc2luZyB0aGUgYFR5cGVkQXJyYXkucHJvdG90eXBlLnN1YmFycmF5YCBmdW5jdGlvbi5cbiAqXG4gKiAgIC0gSUUxMCBoYXMgYSBicm9rZW4gYFR5cGVkQXJyYXkucHJvdG90eXBlLnN1YmFycmF5YCBmdW5jdGlvbiB3aGljaCByZXR1cm5zIGFycmF5cyBvZlxuICogICAgIGluY29ycmVjdCBsZW5ndGggaW4gc29tZSBzaXR1YXRpb25zLlxuXG4gKiBXZSBkZXRlY3QgdGhlc2UgYnVnZ3kgYnJvd3NlcnMgYW5kIHNldCBgQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlRgIHRvIGBmYWxzZWAgc28gdGhleVxuICogZ2V0IHRoZSBPYmplY3QgaW1wbGVtZW50YXRpb24sIHdoaWNoIGlzIHNsb3dlciBidXQgYmVoYXZlcyBjb3JyZWN0bHkuXG4gKi9cbkJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUID0gZ2xvYmFsLlRZUEVEX0FSUkFZX1NVUFBPUlQgIT09IHVuZGVmaW5lZFxuICA/IGdsb2JhbC5UWVBFRF9BUlJBWV9TVVBQT1JUXG4gIDogdHlwZWRBcnJheVN1cHBvcnQoKVxuXG4vKlxuICogRXhwb3J0IGtNYXhMZW5ndGggYWZ0ZXIgdHlwZWQgYXJyYXkgc3VwcG9ydCBpcyBkZXRlcm1pbmVkLlxuICovXG5leHBvcnRzLmtNYXhMZW5ndGggPSBrTWF4TGVuZ3RoKClcblxuZnVuY3Rpb24gdHlwZWRBcnJheVN1cHBvcnQgKCkge1xuICB0cnkge1xuICAgIHZhciBhcnIgPSBuZXcgVWludDhBcnJheSgxKVxuICAgIGFyci5mb28gPSBmdW5jdGlvbiAoKSB7IHJldHVybiA0MiB9XG4gICAgcmV0dXJuIGFyci5mb28oKSA9PT0gNDIgJiYgLy8gdHlwZWQgYXJyYXkgaW5zdGFuY2VzIGNhbiBiZSBhdWdtZW50ZWRcbiAgICAgICAgdHlwZW9mIGFyci5zdWJhcnJheSA9PT0gJ2Z1bmN0aW9uJyAmJiAvLyBjaHJvbWUgOS0xMCBsYWNrIGBzdWJhcnJheWBcbiAgICAgICAgYXJyLnN1YmFycmF5KDEsIDEpLmJ5dGVMZW5ndGggPT09IDAgLy8gaWUxMCBoYXMgYnJva2VuIGBzdWJhcnJheWBcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBmYWxzZVxuICB9XG59XG5cbmZ1bmN0aW9uIGtNYXhMZW5ndGggKCkge1xuICByZXR1cm4gQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlRcbiAgICA/IDB4N2ZmZmZmZmZcbiAgICA6IDB4M2ZmZmZmZmZcbn1cblxuZnVuY3Rpb24gY3JlYXRlQnVmZmVyICh0aGF0LCBsZW5ndGgpIHtcbiAgaWYgKGtNYXhMZW5ndGgoKSA8IGxlbmd0aCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdJbnZhbGlkIHR5cGVkIGFycmF5IGxlbmd0aCcpXG4gIH1cbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgLy8gUmV0dXJuIGFuIGF1Z21lbnRlZCBgVWludDhBcnJheWAgaW5zdGFuY2UsIGZvciBiZXN0IHBlcmZvcm1hbmNlXG4gICAgdGhhdCA9IG5ldyBVaW50OEFycmF5KGxlbmd0aClcbiAgICB0aGF0Ll9fcHJvdG9fXyA9IEJ1ZmZlci5wcm90b3R5cGVcbiAgfSBlbHNlIHtcbiAgICAvLyBGYWxsYmFjazogUmV0dXJuIGFuIG9iamVjdCBpbnN0YW5jZSBvZiB0aGUgQnVmZmVyIGNsYXNzXG4gICAgaWYgKHRoYXQgPT09IG51bGwpIHtcbiAgICAgIHRoYXQgPSBuZXcgQnVmZmVyKGxlbmd0aClcbiAgICB9XG4gICAgdGhhdC5sZW5ndGggPSBsZW5ndGhcbiAgfVxuXG4gIHJldHVybiB0aGF0XG59XG5cbi8qKlxuICogVGhlIEJ1ZmZlciBjb25zdHJ1Y3RvciByZXR1cm5zIGluc3RhbmNlcyBvZiBgVWludDhBcnJheWAgdGhhdCBoYXZlIHRoZWlyXG4gKiBwcm90b3R5cGUgY2hhbmdlZCB0byBgQnVmZmVyLnByb3RvdHlwZWAuIEZ1cnRoZXJtb3JlLCBgQnVmZmVyYCBpcyBhIHN1YmNsYXNzIG9mXG4gKiBgVWludDhBcnJheWAsIHNvIHRoZSByZXR1cm5lZCBpbnN0YW5jZXMgd2lsbCBoYXZlIGFsbCB0aGUgbm9kZSBgQnVmZmVyYCBtZXRob2RzXG4gKiBhbmQgdGhlIGBVaW50OEFycmF5YCBtZXRob2RzLiBTcXVhcmUgYnJhY2tldCBub3RhdGlvbiB3b3JrcyBhcyBleHBlY3RlZCAtLSBpdFxuICogcmV0dXJucyBhIHNpbmdsZSBvY3RldC5cbiAqXG4gKiBUaGUgYFVpbnQ4QXJyYXlgIHByb3RvdHlwZSByZW1haW5zIHVubW9kaWZpZWQuXG4gKi9cblxuZnVuY3Rpb24gQnVmZmVyIChhcmcsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aCkge1xuICBpZiAoIUJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUICYmICEodGhpcyBpbnN0YW5jZW9mIEJ1ZmZlcikpIHtcbiAgICByZXR1cm4gbmV3IEJ1ZmZlcihhcmcsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aClcbiAgfVxuXG4gIC8vIENvbW1vbiBjYXNlLlxuICBpZiAodHlwZW9mIGFyZyA9PT0gJ251bWJlcicpIHtcbiAgICBpZiAodHlwZW9mIGVuY29kaW5nT3JPZmZzZXQgPT09ICdzdHJpbmcnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICdJZiBlbmNvZGluZyBpcyBzcGVjaWZpZWQgdGhlbiB0aGUgZmlyc3QgYXJndW1lbnQgbXVzdCBiZSBhIHN0cmluZydcbiAgICAgIClcbiAgICB9XG4gICAgcmV0dXJuIGFsbG9jVW5zYWZlKHRoaXMsIGFyZylcbiAgfVxuICByZXR1cm4gZnJvbSh0aGlzLCBhcmcsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aClcbn1cblxuQnVmZmVyLnBvb2xTaXplID0gODE5MiAvLyBub3QgdXNlZCBieSB0aGlzIGltcGxlbWVudGF0aW9uXG5cbi8vIFRPRE86IExlZ2FjeSwgbm90IG5lZWRlZCBhbnltb3JlLiBSZW1vdmUgaW4gbmV4dCBtYWpvciB2ZXJzaW9uLlxuQnVmZmVyLl9hdWdtZW50ID0gZnVuY3Rpb24gKGFycikge1xuICBhcnIuX19wcm90b19fID0gQnVmZmVyLnByb3RvdHlwZVxuICByZXR1cm4gYXJyXG59XG5cbmZ1bmN0aW9uIGZyb20gKHRoYXQsIHZhbHVlLCBlbmNvZGluZ09yT2Zmc2V0LCBsZW5ndGgpIHtcbiAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ251bWJlcicpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInZhbHVlXCIgYXJndW1lbnQgbXVzdCBub3QgYmUgYSBudW1iZXInKVxuICB9XG5cbiAgaWYgKHR5cGVvZiBBcnJheUJ1ZmZlciAhPT0gJ3VuZGVmaW5lZCcgJiYgdmFsdWUgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikge1xuICAgIHJldHVybiBmcm9tQXJyYXlCdWZmZXIodGhhdCwgdmFsdWUsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aClcbiAgfVxuXG4gIGlmICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIGZyb21TdHJpbmcodGhhdCwgdmFsdWUsIGVuY29kaW5nT3JPZmZzZXQpXG4gIH1cblxuICByZXR1cm4gZnJvbU9iamVjdCh0aGF0LCB2YWx1ZSlcbn1cblxuLyoqXG4gKiBGdW5jdGlvbmFsbHkgZXF1aXZhbGVudCB0byBCdWZmZXIoYXJnLCBlbmNvZGluZykgYnV0IHRocm93cyBhIFR5cGVFcnJvclxuICogaWYgdmFsdWUgaXMgYSBudW1iZXIuXG4gKiBCdWZmZXIuZnJvbShzdHJbLCBlbmNvZGluZ10pXG4gKiBCdWZmZXIuZnJvbShhcnJheSlcbiAqIEJ1ZmZlci5mcm9tKGJ1ZmZlcilcbiAqIEJ1ZmZlci5mcm9tKGFycmF5QnVmZmVyWywgYnl0ZU9mZnNldFssIGxlbmd0aF1dKVxuICoqL1xuQnVmZmVyLmZyb20gPSBmdW5jdGlvbiAodmFsdWUsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aCkge1xuICByZXR1cm4gZnJvbShudWxsLCB2YWx1ZSwgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKVxufVxuXG5pZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgQnVmZmVyLnByb3RvdHlwZS5fX3Byb3RvX18gPSBVaW50OEFycmF5LnByb3RvdHlwZVxuICBCdWZmZXIuX19wcm90b19fID0gVWludDhBcnJheVxuICBpZiAodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnNwZWNpZXMgJiZcbiAgICAgIEJ1ZmZlcltTeW1ib2wuc3BlY2llc10gPT09IEJ1ZmZlcikge1xuICAgIC8vIEZpeCBzdWJhcnJheSgpIGluIEVTMjAxNi4gU2VlOiBodHRwczovL2dpdGh1Yi5jb20vZmVyb3NzL2J1ZmZlci9wdWxsLzk3XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KEJ1ZmZlciwgU3ltYm9sLnNwZWNpZXMsIHtcbiAgICAgIHZhbHVlOiBudWxsLFxuICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSlcbiAgfVxufVxuXG5mdW5jdGlvbiBhc3NlcnRTaXplIChzaXplKSB7XG4gIGlmICh0eXBlb2Ygc2l6ZSAhPT0gJ251bWJlcicpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInNpemVcIiBhcmd1bWVudCBtdXN0IGJlIGEgbnVtYmVyJylcbiAgfVxufVxuXG5mdW5jdGlvbiBhbGxvYyAodGhhdCwgc2l6ZSwgZmlsbCwgZW5jb2RpbmcpIHtcbiAgYXNzZXJ0U2l6ZShzaXplKVxuICBpZiAoc2l6ZSA8PSAwKSB7XG4gICAgcmV0dXJuIGNyZWF0ZUJ1ZmZlcih0aGF0LCBzaXplKVxuICB9XG4gIGlmIChmaWxsICE9PSB1bmRlZmluZWQpIHtcbiAgICAvLyBPbmx5IHBheSBhdHRlbnRpb24gdG8gZW5jb2RpbmcgaWYgaXQncyBhIHN0cmluZy4gVGhpc1xuICAgIC8vIHByZXZlbnRzIGFjY2lkZW50YWxseSBzZW5kaW5nIGluIGEgbnVtYmVyIHRoYXQgd291bGRcbiAgICAvLyBiZSBpbnRlcnByZXR0ZWQgYXMgYSBzdGFydCBvZmZzZXQuXG4gICAgcmV0dXJuIHR5cGVvZiBlbmNvZGluZyA9PT0gJ3N0cmluZydcbiAgICAgID8gY3JlYXRlQnVmZmVyKHRoYXQsIHNpemUpLmZpbGwoZmlsbCwgZW5jb2RpbmcpXG4gICAgICA6IGNyZWF0ZUJ1ZmZlcih0aGF0LCBzaXplKS5maWxsKGZpbGwpXG4gIH1cbiAgcmV0dXJuIGNyZWF0ZUJ1ZmZlcih0aGF0LCBzaXplKVxufVxuXG4vKipcbiAqIENyZWF0ZXMgYSBuZXcgZmlsbGVkIEJ1ZmZlciBpbnN0YW5jZS5cbiAqIGFsbG9jKHNpemVbLCBmaWxsWywgZW5jb2RpbmddXSlcbiAqKi9cbkJ1ZmZlci5hbGxvYyA9IGZ1bmN0aW9uIChzaXplLCBmaWxsLCBlbmNvZGluZykge1xuICByZXR1cm4gYWxsb2MobnVsbCwgc2l6ZSwgZmlsbCwgZW5jb2RpbmcpXG59XG5cbmZ1bmN0aW9uIGFsbG9jVW5zYWZlICh0aGF0LCBzaXplKSB7XG4gIGFzc2VydFNpemUoc2l6ZSlcbiAgdGhhdCA9IGNyZWF0ZUJ1ZmZlcih0aGF0LCBzaXplIDwgMCA/IDAgOiBjaGVja2VkKHNpemUpIHwgMClcbiAgaWYgKCFCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2l6ZTsgaSsrKSB7XG4gICAgICB0aGF0W2ldID0gMFxuICAgIH1cbiAgfVxuICByZXR1cm4gdGhhdFxufVxuXG4vKipcbiAqIEVxdWl2YWxlbnQgdG8gQnVmZmVyKG51bSksIGJ5IGRlZmF1bHQgY3JlYXRlcyBhIG5vbi16ZXJvLWZpbGxlZCBCdWZmZXIgaW5zdGFuY2UuXG4gKiAqL1xuQnVmZmVyLmFsbG9jVW5zYWZlID0gZnVuY3Rpb24gKHNpemUpIHtcbiAgcmV0dXJuIGFsbG9jVW5zYWZlKG51bGwsIHNpemUpXG59XG4vKipcbiAqIEVxdWl2YWxlbnQgdG8gU2xvd0J1ZmZlcihudW0pLCBieSBkZWZhdWx0IGNyZWF0ZXMgYSBub24temVyby1maWxsZWQgQnVmZmVyIGluc3RhbmNlLlxuICovXG5CdWZmZXIuYWxsb2NVbnNhZmVTbG93ID0gZnVuY3Rpb24gKHNpemUpIHtcbiAgcmV0dXJuIGFsbG9jVW5zYWZlKG51bGwsIHNpemUpXG59XG5cbmZ1bmN0aW9uIGZyb21TdHJpbmcgKHRoYXQsIHN0cmluZywgZW5jb2RpbmcpIHtcbiAgaWYgKHR5cGVvZiBlbmNvZGluZyAhPT0gJ3N0cmluZycgfHwgZW5jb2RpbmcgPT09ICcnKSB7XG4gICAgZW5jb2RpbmcgPSAndXRmOCdcbiAgfVxuXG4gIGlmICghQnVmZmVyLmlzRW5jb2RpbmcoZW5jb2RpbmcpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJlbmNvZGluZ1wiIG11c3QgYmUgYSB2YWxpZCBzdHJpbmcgZW5jb2RpbmcnKVxuICB9XG5cbiAgdmFyIGxlbmd0aCA9IGJ5dGVMZW5ndGgoc3RyaW5nLCBlbmNvZGluZykgfCAwXG4gIHRoYXQgPSBjcmVhdGVCdWZmZXIodGhhdCwgbGVuZ3RoKVxuXG4gIHRoYXQud3JpdGUoc3RyaW5nLCBlbmNvZGluZylcbiAgcmV0dXJuIHRoYXRcbn1cblxuZnVuY3Rpb24gZnJvbUFycmF5TGlrZSAodGhhdCwgYXJyYXkpIHtcbiAgdmFyIGxlbmd0aCA9IGNoZWNrZWQoYXJyYXkubGVuZ3RoKSB8IDBcbiAgdGhhdCA9IGNyZWF0ZUJ1ZmZlcih0aGF0LCBsZW5ndGgpXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IDEpIHtcbiAgICB0aGF0W2ldID0gYXJyYXlbaV0gJiAyNTVcbiAgfVxuICByZXR1cm4gdGhhdFxufVxuXG5mdW5jdGlvbiBmcm9tQXJyYXlCdWZmZXIgKHRoYXQsIGFycmF5LCBieXRlT2Zmc2V0LCBsZW5ndGgpIHtcbiAgYXJyYXkuYnl0ZUxlbmd0aCAvLyB0aGlzIHRocm93cyBpZiBgYXJyYXlgIGlzIG5vdCBhIHZhbGlkIEFycmF5QnVmZmVyXG5cbiAgaWYgKGJ5dGVPZmZzZXQgPCAwIHx8IGFycmF5LmJ5dGVMZW5ndGggPCBieXRlT2Zmc2V0KSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ1xcJ29mZnNldFxcJyBpcyBvdXQgb2YgYm91bmRzJylcbiAgfVxuXG4gIGlmIChhcnJheS5ieXRlTGVuZ3RoIDwgYnl0ZU9mZnNldCArIChsZW5ndGggfHwgMCkpIHtcbiAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcignXFwnbGVuZ3RoXFwnIGlzIG91dCBvZiBib3VuZHMnKVxuICB9XG5cbiAgaWYgKGxlbmd0aCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgYXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheSwgYnl0ZU9mZnNldClcbiAgfSBlbHNlIHtcbiAgICBhcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5LCBieXRlT2Zmc2V0LCBsZW5ndGgpXG4gIH1cblxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICAvLyBSZXR1cm4gYW4gYXVnbWVudGVkIGBVaW50OEFycmF5YCBpbnN0YW5jZSwgZm9yIGJlc3QgcGVyZm9ybWFuY2VcbiAgICB0aGF0ID0gYXJyYXlcbiAgICB0aGF0Ll9fcHJvdG9fXyA9IEJ1ZmZlci5wcm90b3R5cGVcbiAgfSBlbHNlIHtcbiAgICAvLyBGYWxsYmFjazogUmV0dXJuIGFuIG9iamVjdCBpbnN0YW5jZSBvZiB0aGUgQnVmZmVyIGNsYXNzXG4gICAgdGhhdCA9IGZyb21BcnJheUxpa2UodGhhdCwgYXJyYXkpXG4gIH1cbiAgcmV0dXJuIHRoYXRcbn1cblxuZnVuY3Rpb24gZnJvbU9iamVjdCAodGhhdCwgb2JqKSB7XG4gIGlmIChCdWZmZXIuaXNCdWZmZXIob2JqKSkge1xuICAgIHZhciBsZW4gPSBjaGVja2VkKG9iai5sZW5ndGgpIHwgMFxuICAgIHRoYXQgPSBjcmVhdGVCdWZmZXIodGhhdCwgbGVuKVxuXG4gICAgaWYgKHRoYXQubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4gdGhhdFxuICAgIH1cblxuICAgIG9iai5jb3B5KHRoYXQsIDAsIDAsIGxlbilcbiAgICByZXR1cm4gdGhhdFxuICB9XG5cbiAgaWYgKG9iaikge1xuICAgIGlmICgodHlwZW9mIEFycmF5QnVmZmVyICE9PSAndW5kZWZpbmVkJyAmJlxuICAgICAgICBvYmouYnVmZmVyIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpIHx8ICdsZW5ndGgnIGluIG9iaikge1xuICAgICAgaWYgKHR5cGVvZiBvYmoubGVuZ3RoICE9PSAnbnVtYmVyJyB8fCBpc25hbihvYmoubGVuZ3RoKSkge1xuICAgICAgICByZXR1cm4gY3JlYXRlQnVmZmVyKHRoYXQsIDApXG4gICAgICB9XG4gICAgICByZXR1cm4gZnJvbUFycmF5TGlrZSh0aGF0LCBvYmopXG4gICAgfVxuXG4gICAgaWYgKG9iai50eXBlID09PSAnQnVmZmVyJyAmJiBpc0FycmF5KG9iai5kYXRhKSkge1xuICAgICAgcmV0dXJuIGZyb21BcnJheUxpa2UodGhhdCwgb2JqLmRhdGEpXG4gICAgfVxuICB9XG5cbiAgdGhyb3cgbmV3IFR5cGVFcnJvcignRmlyc3QgYXJndW1lbnQgbXVzdCBiZSBhIHN0cmluZywgQnVmZmVyLCBBcnJheUJ1ZmZlciwgQXJyYXksIG9yIGFycmF5LWxpa2Ugb2JqZWN0LicpXG59XG5cbmZ1bmN0aW9uIGNoZWNrZWQgKGxlbmd0aCkge1xuICAvLyBOb3RlOiBjYW5ub3QgdXNlIGBsZW5ndGggPCBrTWF4TGVuZ3RoYCBoZXJlIGJlY2F1c2UgdGhhdCBmYWlscyB3aGVuXG4gIC8vIGxlbmd0aCBpcyBOYU4gKHdoaWNoIGlzIG90aGVyd2lzZSBjb2VyY2VkIHRvIHplcm8uKVxuICBpZiAobGVuZ3RoID49IGtNYXhMZW5ndGgoKSkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdBdHRlbXB0IHRvIGFsbG9jYXRlIEJ1ZmZlciBsYXJnZXIgdGhhbiBtYXhpbXVtICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICdzaXplOiAweCcgKyBrTWF4TGVuZ3RoKCkudG9TdHJpbmcoMTYpICsgJyBieXRlcycpXG4gIH1cbiAgcmV0dXJuIGxlbmd0aCB8IDBcbn1cblxuZnVuY3Rpb24gU2xvd0J1ZmZlciAobGVuZ3RoKSB7XG4gIGlmICgrbGVuZ3RoICE9IGxlbmd0aCkgeyAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGVxZXFlcVxuICAgIGxlbmd0aCA9IDBcbiAgfVxuICByZXR1cm4gQnVmZmVyLmFsbG9jKCtsZW5ndGgpXG59XG5cbkJ1ZmZlci5pc0J1ZmZlciA9IGZ1bmN0aW9uIGlzQnVmZmVyIChiKSB7XG4gIHJldHVybiAhIShiICE9IG51bGwgJiYgYi5faXNCdWZmZXIpXG59XG5cbkJ1ZmZlci5jb21wYXJlID0gZnVuY3Rpb24gY29tcGFyZSAoYSwgYikge1xuICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcihhKSB8fCAhQnVmZmVyLmlzQnVmZmVyKGIpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQXJndW1lbnRzIG11c3QgYmUgQnVmZmVycycpXG4gIH1cblxuICBpZiAoYSA9PT0gYikgcmV0dXJuIDBcblxuICB2YXIgeCA9IGEubGVuZ3RoXG4gIHZhciB5ID0gYi5sZW5ndGhcblxuICBmb3IgKHZhciBpID0gMCwgbGVuID0gTWF0aC5taW4oeCwgeSk7IGkgPCBsZW47ICsraSkge1xuICAgIGlmIChhW2ldICE9PSBiW2ldKSB7XG4gICAgICB4ID0gYVtpXVxuICAgICAgeSA9IGJbaV1cbiAgICAgIGJyZWFrXG4gICAgfVxuICB9XG5cbiAgaWYgKHggPCB5KSByZXR1cm4gLTFcbiAgaWYgKHkgPCB4KSByZXR1cm4gMVxuICByZXR1cm4gMFxufVxuXG5CdWZmZXIuaXNFbmNvZGluZyA9IGZ1bmN0aW9uIGlzRW5jb2RpbmcgKGVuY29kaW5nKSB7XG4gIHN3aXRjaCAoU3RyaW5nKGVuY29kaW5nKS50b0xvd2VyQ2FzZSgpKSB7XG4gICAgY2FzZSAnaGV4JzpcbiAgICBjYXNlICd1dGY4JzpcbiAgICBjYXNlICd1dGYtOCc6XG4gICAgY2FzZSAnYXNjaWknOlxuICAgIGNhc2UgJ2JpbmFyeSc6XG4gICAgY2FzZSAnYmFzZTY0JzpcbiAgICBjYXNlICdyYXcnOlxuICAgIGNhc2UgJ3VjczInOlxuICAgIGNhc2UgJ3Vjcy0yJzpcbiAgICBjYXNlICd1dGYxNmxlJzpcbiAgICBjYXNlICd1dGYtMTZsZSc6XG4gICAgICByZXR1cm4gdHJ1ZVxuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gZmFsc2VcbiAgfVxufVxuXG5CdWZmZXIuY29uY2F0ID0gZnVuY3Rpb24gY29uY2F0IChsaXN0LCBsZW5ndGgpIHtcbiAgaWYgKCFpc0FycmF5KGxpc3QpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJsaXN0XCIgYXJndW1lbnQgbXVzdCBiZSBhbiBBcnJheSBvZiBCdWZmZXJzJylcbiAgfVxuXG4gIGlmIChsaXN0Lmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybiBCdWZmZXIuYWxsb2MoMClcbiAgfVxuXG4gIHZhciBpXG4gIGlmIChsZW5ndGggPT09IHVuZGVmaW5lZCkge1xuICAgIGxlbmd0aCA9IDBcbiAgICBmb3IgKGkgPSAwOyBpIDwgbGlzdC5sZW5ndGg7IGkrKykge1xuICAgICAgbGVuZ3RoICs9IGxpc3RbaV0ubGVuZ3RoXG4gICAgfVxuICB9XG5cbiAgdmFyIGJ1ZmZlciA9IEJ1ZmZlci5hbGxvY1Vuc2FmZShsZW5ndGgpXG4gIHZhciBwb3MgPSAwXG4gIGZvciAoaSA9IDA7IGkgPCBsaXN0Lmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIGJ1ZiA9IGxpc3RbaV1cbiAgICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcihidWYpKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcImxpc3RcIiBhcmd1bWVudCBtdXN0IGJlIGFuIEFycmF5IG9mIEJ1ZmZlcnMnKVxuICAgIH1cbiAgICBidWYuY29weShidWZmZXIsIHBvcylcbiAgICBwb3MgKz0gYnVmLmxlbmd0aFxuICB9XG4gIHJldHVybiBidWZmZXJcbn1cblxuZnVuY3Rpb24gYnl0ZUxlbmd0aCAoc3RyaW5nLCBlbmNvZGluZykge1xuICBpZiAoQnVmZmVyLmlzQnVmZmVyKHN0cmluZykpIHtcbiAgICByZXR1cm4gc3RyaW5nLmxlbmd0aFxuICB9XG4gIGlmICh0eXBlb2YgQXJyYXlCdWZmZXIgIT09ICd1bmRlZmluZWQnICYmIHR5cGVvZiBBcnJheUJ1ZmZlci5pc1ZpZXcgPT09ICdmdW5jdGlvbicgJiZcbiAgICAgIChBcnJheUJ1ZmZlci5pc1ZpZXcoc3RyaW5nKSB8fCBzdHJpbmcgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikpIHtcbiAgICByZXR1cm4gc3RyaW5nLmJ5dGVMZW5ndGhcbiAgfVxuICBpZiAodHlwZW9mIHN0cmluZyAhPT0gJ3N0cmluZycpIHtcbiAgICBzdHJpbmcgPSAnJyArIHN0cmluZ1xuICB9XG5cbiAgdmFyIGxlbiA9IHN0cmluZy5sZW5ndGhcbiAgaWYgKGxlbiA9PT0gMCkgcmV0dXJuIDBcblxuICAvLyBVc2UgYSBmb3IgbG9vcCB0byBhdm9pZCByZWN1cnNpb25cbiAgdmFyIGxvd2VyZWRDYXNlID0gZmFsc2VcbiAgZm9yICg7Oykge1xuICAgIHN3aXRjaCAoZW5jb2RpbmcpIHtcbiAgICAgIGNhc2UgJ2FzY2lpJzpcbiAgICAgIGNhc2UgJ2JpbmFyeSc6XG4gICAgICAvLyBEZXByZWNhdGVkXG4gICAgICBjYXNlICdyYXcnOlxuICAgICAgY2FzZSAncmF3cyc6XG4gICAgICAgIHJldHVybiBsZW5cbiAgICAgIGNhc2UgJ3V0ZjgnOlxuICAgICAgY2FzZSAndXRmLTgnOlxuICAgICAgY2FzZSB1bmRlZmluZWQ6XG4gICAgICAgIHJldHVybiB1dGY4VG9CeXRlcyhzdHJpbmcpLmxlbmd0aFxuICAgICAgY2FzZSAndWNzMic6XG4gICAgICBjYXNlICd1Y3MtMic6XG4gICAgICBjYXNlICd1dGYxNmxlJzpcbiAgICAgIGNhc2UgJ3V0Zi0xNmxlJzpcbiAgICAgICAgcmV0dXJuIGxlbiAqIDJcbiAgICAgIGNhc2UgJ2hleCc6XG4gICAgICAgIHJldHVybiBsZW4gPj4+IDFcbiAgICAgIGNhc2UgJ2Jhc2U2NCc6XG4gICAgICAgIHJldHVybiBiYXNlNjRUb0J5dGVzKHN0cmluZykubGVuZ3RoXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBpZiAobG93ZXJlZENhc2UpIHJldHVybiB1dGY4VG9CeXRlcyhzdHJpbmcpLmxlbmd0aCAvLyBhc3N1bWUgdXRmOFxuICAgICAgICBlbmNvZGluZyA9ICgnJyArIGVuY29kaW5nKS50b0xvd2VyQ2FzZSgpXG4gICAgICAgIGxvd2VyZWRDYXNlID0gdHJ1ZVxuICAgIH1cbiAgfVxufVxuQnVmZmVyLmJ5dGVMZW5ndGggPSBieXRlTGVuZ3RoXG5cbmZ1bmN0aW9uIHNsb3dUb1N0cmluZyAoZW5jb2RpbmcsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIGxvd2VyZWRDYXNlID0gZmFsc2VcblxuICAvLyBObyBuZWVkIHRvIHZlcmlmeSB0aGF0IFwidGhpcy5sZW5ndGggPD0gTUFYX1VJTlQzMlwiIHNpbmNlIGl0J3MgYSByZWFkLW9ubHlcbiAgLy8gcHJvcGVydHkgb2YgYSB0eXBlZCBhcnJheS5cblxuICAvLyBUaGlzIGJlaGF2ZXMgbmVpdGhlciBsaWtlIFN0cmluZyBub3IgVWludDhBcnJheSBpbiB0aGF0IHdlIHNldCBzdGFydC9lbmRcbiAgLy8gdG8gdGhlaXIgdXBwZXIvbG93ZXIgYm91bmRzIGlmIHRoZSB2YWx1ZSBwYXNzZWQgaXMgb3V0IG9mIHJhbmdlLlxuICAvLyB1bmRlZmluZWQgaXMgaGFuZGxlZCBzcGVjaWFsbHkgYXMgcGVyIEVDTUEtMjYyIDZ0aCBFZGl0aW9uLFxuICAvLyBTZWN0aW9uIDEzLjMuMy43IFJ1bnRpbWUgU2VtYW50aWNzOiBLZXllZEJpbmRpbmdJbml0aWFsaXphdGlvbi5cbiAgaWYgKHN0YXJ0ID09PSB1bmRlZmluZWQgfHwgc3RhcnQgPCAwKSB7XG4gICAgc3RhcnQgPSAwXG4gIH1cbiAgLy8gUmV0dXJuIGVhcmx5IGlmIHN0YXJ0ID4gdGhpcy5sZW5ndGguIERvbmUgaGVyZSB0byBwcmV2ZW50IHBvdGVudGlhbCB1aW50MzJcbiAgLy8gY29lcmNpb24gZmFpbCBiZWxvdy5cbiAgaWYgKHN0YXJ0ID4gdGhpcy5sZW5ndGgpIHtcbiAgICByZXR1cm4gJydcbiAgfVxuXG4gIGlmIChlbmQgPT09IHVuZGVmaW5lZCB8fCBlbmQgPiB0aGlzLmxlbmd0aCkge1xuICAgIGVuZCA9IHRoaXMubGVuZ3RoXG4gIH1cblxuICBpZiAoZW5kIDw9IDApIHtcbiAgICByZXR1cm4gJydcbiAgfVxuXG4gIC8vIEZvcmNlIGNvZXJzaW9uIHRvIHVpbnQzMi4gVGhpcyB3aWxsIGFsc28gY29lcmNlIGZhbHNleS9OYU4gdmFsdWVzIHRvIDAuXG4gIGVuZCA+Pj49IDBcbiAgc3RhcnQgPj4+PSAwXG5cbiAgaWYgKGVuZCA8PSBzdGFydCkge1xuICAgIHJldHVybiAnJ1xuICB9XG5cbiAgaWYgKCFlbmNvZGluZykgZW5jb2RpbmcgPSAndXRmOCdcblxuICB3aGlsZSAodHJ1ZSkge1xuICAgIHN3aXRjaCAoZW5jb2RpbmcpIHtcbiAgICAgIGNhc2UgJ2hleCc6XG4gICAgICAgIHJldHVybiBoZXhTbGljZSh0aGlzLCBzdGFydCwgZW5kKVxuXG4gICAgICBjYXNlICd1dGY4JzpcbiAgICAgIGNhc2UgJ3V0Zi04JzpcbiAgICAgICAgcmV0dXJuIHV0ZjhTbGljZSh0aGlzLCBzdGFydCwgZW5kKVxuXG4gICAgICBjYXNlICdhc2NpaSc6XG4gICAgICAgIHJldHVybiBhc2NpaVNsaWNlKHRoaXMsIHN0YXJ0LCBlbmQpXG5cbiAgICAgIGNhc2UgJ2JpbmFyeSc6XG4gICAgICAgIHJldHVybiBiaW5hcnlTbGljZSh0aGlzLCBzdGFydCwgZW5kKVxuXG4gICAgICBjYXNlICdiYXNlNjQnOlxuICAgICAgICByZXR1cm4gYmFzZTY0U2xpY2UodGhpcywgc3RhcnQsIGVuZClcblxuICAgICAgY2FzZSAndWNzMic6XG4gICAgICBjYXNlICd1Y3MtMic6XG4gICAgICBjYXNlICd1dGYxNmxlJzpcbiAgICAgIGNhc2UgJ3V0Zi0xNmxlJzpcbiAgICAgICAgcmV0dXJuIHV0ZjE2bGVTbGljZSh0aGlzLCBzdGFydCwgZW5kKVxuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBpZiAobG93ZXJlZENhc2UpIHRocm93IG5ldyBUeXBlRXJyb3IoJ1Vua25vd24gZW5jb2Rpbmc6ICcgKyBlbmNvZGluZylcbiAgICAgICAgZW5jb2RpbmcgPSAoZW5jb2RpbmcgKyAnJykudG9Mb3dlckNhc2UoKVxuICAgICAgICBsb3dlcmVkQ2FzZSA9IHRydWVcbiAgICB9XG4gIH1cbn1cblxuLy8gVGhlIHByb3BlcnR5IGlzIHVzZWQgYnkgYEJ1ZmZlci5pc0J1ZmZlcmAgYW5kIGBpcy1idWZmZXJgIChpbiBTYWZhcmkgNS03KSB0byBkZXRlY3Rcbi8vIEJ1ZmZlciBpbnN0YW5jZXMuXG5CdWZmZXIucHJvdG90eXBlLl9pc0J1ZmZlciA9IHRydWVcblxuZnVuY3Rpb24gc3dhcCAoYiwgbiwgbSkge1xuICB2YXIgaSA9IGJbbl1cbiAgYltuXSA9IGJbbV1cbiAgYlttXSA9IGlcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5zd2FwMTYgPSBmdW5jdGlvbiBzd2FwMTYgKCkge1xuICB2YXIgbGVuID0gdGhpcy5sZW5ndGhcbiAgaWYgKGxlbiAlIDIgIT09IDApIHtcbiAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcignQnVmZmVyIHNpemUgbXVzdCBiZSBhIG11bHRpcGxlIG9mIDE2LWJpdHMnKVxuICB9XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpICs9IDIpIHtcbiAgICBzd2FwKHRoaXMsIGksIGkgKyAxKVxuICB9XG4gIHJldHVybiB0aGlzXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUuc3dhcDMyID0gZnVuY3Rpb24gc3dhcDMyICgpIHtcbiAgdmFyIGxlbiA9IHRoaXMubGVuZ3RoXG4gIGlmIChsZW4gJSA0ICE9PSAwKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0J1ZmZlciBzaXplIG11c3QgYmUgYSBtdWx0aXBsZSBvZiAzMi1iaXRzJylcbiAgfVxuICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbjsgaSArPSA0KSB7XG4gICAgc3dhcCh0aGlzLCBpLCBpICsgMylcbiAgICBzd2FwKHRoaXMsIGkgKyAxLCBpICsgMilcbiAgfVxuICByZXR1cm4gdGhpc1xufVxuXG5CdWZmZXIucHJvdG90eXBlLnRvU3RyaW5nID0gZnVuY3Rpb24gdG9TdHJpbmcgKCkge1xuICB2YXIgbGVuZ3RoID0gdGhpcy5sZW5ndGggfCAwXG4gIGlmIChsZW5ndGggPT09IDApIHJldHVybiAnJ1xuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHV0ZjhTbGljZSh0aGlzLCAwLCBsZW5ndGgpXG4gIHJldHVybiBzbG93VG9TdHJpbmcuYXBwbHkodGhpcywgYXJndW1lbnRzKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLmVxdWFscyA9IGZ1bmN0aW9uIGVxdWFscyAoYikge1xuICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcihiKSkgdGhyb3cgbmV3IFR5cGVFcnJvcignQXJndW1lbnQgbXVzdCBiZSBhIEJ1ZmZlcicpXG4gIGlmICh0aGlzID09PSBiKSByZXR1cm4gdHJ1ZVxuICByZXR1cm4gQnVmZmVyLmNvbXBhcmUodGhpcywgYikgPT09IDBcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCAoKSB7XG4gIHZhciBzdHIgPSAnJ1xuICB2YXIgbWF4ID0gZXhwb3J0cy5JTlNQRUNUX01BWF9CWVRFU1xuICBpZiAodGhpcy5sZW5ndGggPiAwKSB7XG4gICAgc3RyID0gdGhpcy50b1N0cmluZygnaGV4JywgMCwgbWF4KS5tYXRjaCgvLnsyfS9nKS5qb2luKCcgJylcbiAgICBpZiAodGhpcy5sZW5ndGggPiBtYXgpIHN0ciArPSAnIC4uLiAnXG4gIH1cbiAgcmV0dXJuICc8QnVmZmVyICcgKyBzdHIgKyAnPidcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5jb21wYXJlID0gZnVuY3Rpb24gY29tcGFyZSAodGFyZ2V0LCBzdGFydCwgZW5kLCB0aGlzU3RhcnQsIHRoaXNFbmQpIHtcbiAgaWYgKCFCdWZmZXIuaXNCdWZmZXIodGFyZ2V0KSkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0FyZ3VtZW50IG11c3QgYmUgYSBCdWZmZXInKVxuICB9XG5cbiAgaWYgKHN0YXJ0ID09PSB1bmRlZmluZWQpIHtcbiAgICBzdGFydCA9IDBcbiAgfVxuICBpZiAoZW5kID09PSB1bmRlZmluZWQpIHtcbiAgICBlbmQgPSB0YXJnZXQgPyB0YXJnZXQubGVuZ3RoIDogMFxuICB9XG4gIGlmICh0aGlzU3RhcnQgPT09IHVuZGVmaW5lZCkge1xuICAgIHRoaXNTdGFydCA9IDBcbiAgfVxuICBpZiAodGhpc0VuZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgdGhpc0VuZCA9IHRoaXMubGVuZ3RoXG4gIH1cblxuICBpZiAoc3RhcnQgPCAwIHx8IGVuZCA+IHRhcmdldC5sZW5ndGggfHwgdGhpc1N0YXJ0IDwgMCB8fCB0aGlzRW5kID4gdGhpcy5sZW5ndGgpIHtcbiAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcignb3V0IG9mIHJhbmdlIGluZGV4JylcbiAgfVxuXG4gIGlmICh0aGlzU3RhcnQgPj0gdGhpc0VuZCAmJiBzdGFydCA+PSBlbmQpIHtcbiAgICByZXR1cm4gMFxuICB9XG4gIGlmICh0aGlzU3RhcnQgPj0gdGhpc0VuZCkge1xuICAgIHJldHVybiAtMVxuICB9XG4gIGlmIChzdGFydCA+PSBlbmQpIHtcbiAgICByZXR1cm4gMVxuICB9XG5cbiAgc3RhcnQgPj4+PSAwXG4gIGVuZCA+Pj49IDBcbiAgdGhpc1N0YXJ0ID4+Pj0gMFxuICB0aGlzRW5kID4+Pj0gMFxuXG4gIGlmICh0aGlzID09PSB0YXJnZXQpIHJldHVybiAwXG5cbiAgdmFyIHggPSB0aGlzRW5kIC0gdGhpc1N0YXJ0XG4gIHZhciB5ID0gZW5kIC0gc3RhcnRcbiAgdmFyIGxlbiA9IE1hdGgubWluKHgsIHkpXG5cbiAgdmFyIHRoaXNDb3B5ID0gdGhpcy5zbGljZSh0aGlzU3RhcnQsIHRoaXNFbmQpXG4gIHZhciB0YXJnZXRDb3B5ID0gdGFyZ2V0LnNsaWNlKHN0YXJ0LCBlbmQpXG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47ICsraSkge1xuICAgIGlmICh0aGlzQ29weVtpXSAhPT0gdGFyZ2V0Q29weVtpXSkge1xuICAgICAgeCA9IHRoaXNDb3B5W2ldXG4gICAgICB5ID0gdGFyZ2V0Q29weVtpXVxuICAgICAgYnJlYWtcbiAgICB9XG4gIH1cblxuICBpZiAoeCA8IHkpIHJldHVybiAtMVxuICBpZiAoeSA8IHgpIHJldHVybiAxXG4gIHJldHVybiAwXG59XG5cbmZ1bmN0aW9uIGFycmF5SW5kZXhPZiAoYXJyLCB2YWwsIGJ5dGVPZmZzZXQsIGVuY29kaW5nKSB7XG4gIHZhciBpbmRleFNpemUgPSAxXG4gIHZhciBhcnJMZW5ndGggPSBhcnIubGVuZ3RoXG4gIHZhciB2YWxMZW5ndGggPSB2YWwubGVuZ3RoXG5cbiAgaWYgKGVuY29kaW5nICE9PSB1bmRlZmluZWQpIHtcbiAgICBlbmNvZGluZyA9IFN0cmluZyhlbmNvZGluZykudG9Mb3dlckNhc2UoKVxuICAgIGlmIChlbmNvZGluZyA9PT0gJ3VjczInIHx8IGVuY29kaW5nID09PSAndWNzLTInIHx8XG4gICAgICAgIGVuY29kaW5nID09PSAndXRmMTZsZScgfHwgZW5jb2RpbmcgPT09ICd1dGYtMTZsZScpIHtcbiAgICAgIGlmIChhcnIubGVuZ3RoIDwgMiB8fCB2YWwubGVuZ3RoIDwgMikge1xuICAgICAgICByZXR1cm4gLTFcbiAgICAgIH1cbiAgICAgIGluZGV4U2l6ZSA9IDJcbiAgICAgIGFyckxlbmd0aCAvPSAyXG4gICAgICB2YWxMZW5ndGggLz0gMlxuICAgICAgYnl0ZU9mZnNldCAvPSAyXG4gICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gcmVhZCAoYnVmLCBpKSB7XG4gICAgaWYgKGluZGV4U2l6ZSA9PT0gMSkge1xuICAgICAgcmV0dXJuIGJ1ZltpXVxuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gYnVmLnJlYWRVSW50MTZCRShpICogaW5kZXhTaXplKVxuICAgIH1cbiAgfVxuXG4gIHZhciBmb3VuZEluZGV4ID0gLTFcbiAgZm9yICh2YXIgaSA9IDA7IGJ5dGVPZmZzZXQgKyBpIDwgYXJyTGVuZ3RoOyBpKyspIHtcbiAgICBpZiAocmVhZChhcnIsIGJ5dGVPZmZzZXQgKyBpKSA9PT0gcmVhZCh2YWwsIGZvdW5kSW5kZXggPT09IC0xID8gMCA6IGkgLSBmb3VuZEluZGV4KSkge1xuICAgICAgaWYgKGZvdW5kSW5kZXggPT09IC0xKSBmb3VuZEluZGV4ID0gaVxuICAgICAgaWYgKGkgLSBmb3VuZEluZGV4ICsgMSA9PT0gdmFsTGVuZ3RoKSByZXR1cm4gKGJ5dGVPZmZzZXQgKyBmb3VuZEluZGV4KSAqIGluZGV4U2l6ZVxuICAgIH0gZWxzZSB7XG4gICAgICBpZiAoZm91bmRJbmRleCAhPT0gLTEpIGkgLT0gaSAtIGZvdW5kSW5kZXhcbiAgICAgIGZvdW5kSW5kZXggPSAtMVxuICAgIH1cbiAgfVxuICByZXR1cm4gLTFcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5pbmRleE9mID0gZnVuY3Rpb24gaW5kZXhPZiAodmFsLCBieXRlT2Zmc2V0LCBlbmNvZGluZykge1xuICBpZiAodHlwZW9mIGJ5dGVPZmZzZXQgPT09ICdzdHJpbmcnKSB7XG4gICAgZW5jb2RpbmcgPSBieXRlT2Zmc2V0XG4gICAgYnl0ZU9mZnNldCA9IDBcbiAgfSBlbHNlIGlmIChieXRlT2Zmc2V0ID4gMHg3ZmZmZmZmZikge1xuICAgIGJ5dGVPZmZzZXQgPSAweDdmZmZmZmZmXG4gIH0gZWxzZSBpZiAoYnl0ZU9mZnNldCA8IC0weDgwMDAwMDAwKSB7XG4gICAgYnl0ZU9mZnNldCA9IC0weDgwMDAwMDAwXG4gIH1cbiAgYnl0ZU9mZnNldCA+Pj0gMFxuXG4gIGlmICh0aGlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIC0xXG4gIGlmIChieXRlT2Zmc2V0ID49IHRoaXMubGVuZ3RoKSByZXR1cm4gLTFcblxuICAvLyBOZWdhdGl2ZSBvZmZzZXRzIHN0YXJ0IGZyb20gdGhlIGVuZCBvZiB0aGUgYnVmZmVyXG4gIGlmIChieXRlT2Zmc2V0IDwgMCkgYnl0ZU9mZnNldCA9IE1hdGgubWF4KHRoaXMubGVuZ3RoICsgYnl0ZU9mZnNldCwgMClcblxuICBpZiAodHlwZW9mIHZhbCA9PT0gJ3N0cmluZycpIHtcbiAgICB2YWwgPSBCdWZmZXIuZnJvbSh2YWwsIGVuY29kaW5nKVxuICB9XG5cbiAgaWYgKEJ1ZmZlci5pc0J1ZmZlcih2YWwpKSB7XG4gICAgLy8gc3BlY2lhbCBjYXNlOiBsb29raW5nIGZvciBlbXB0eSBzdHJpbmcvYnVmZmVyIGFsd2F5cyBmYWlsc1xuICAgIGlmICh2YWwubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4gLTFcbiAgICB9XG4gICAgcmV0dXJuIGFycmF5SW5kZXhPZih0aGlzLCB2YWwsIGJ5dGVPZmZzZXQsIGVuY29kaW5nKVxuICB9XG4gIGlmICh0eXBlb2YgdmFsID09PSAnbnVtYmVyJykge1xuICAgIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCAmJiBVaW50OEFycmF5LnByb3RvdHlwZS5pbmRleE9mID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICByZXR1cm4gVWludDhBcnJheS5wcm90b3R5cGUuaW5kZXhPZi5jYWxsKHRoaXMsIHZhbCwgYnl0ZU9mZnNldClcbiAgICB9XG4gICAgcmV0dXJuIGFycmF5SW5kZXhPZih0aGlzLCBbIHZhbCBdLCBieXRlT2Zmc2V0LCBlbmNvZGluZylcbiAgfVxuXG4gIHRocm93IG5ldyBUeXBlRXJyb3IoJ3ZhbCBtdXN0IGJlIHN0cmluZywgbnVtYmVyIG9yIEJ1ZmZlcicpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUuaW5jbHVkZXMgPSBmdW5jdGlvbiBpbmNsdWRlcyAodmFsLCBieXRlT2Zmc2V0LCBlbmNvZGluZykge1xuICByZXR1cm4gdGhpcy5pbmRleE9mKHZhbCwgYnl0ZU9mZnNldCwgZW5jb2RpbmcpICE9PSAtMVxufVxuXG5mdW5jdGlvbiBoZXhXcml0ZSAoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIG9mZnNldCA9IE51bWJlcihvZmZzZXQpIHx8IDBcbiAgdmFyIHJlbWFpbmluZyA9IGJ1Zi5sZW5ndGggLSBvZmZzZXRcbiAgaWYgKCFsZW5ndGgpIHtcbiAgICBsZW5ndGggPSByZW1haW5pbmdcbiAgfSBlbHNlIHtcbiAgICBsZW5ndGggPSBOdW1iZXIobGVuZ3RoKVxuICAgIGlmIChsZW5ndGggPiByZW1haW5pbmcpIHtcbiAgICAgIGxlbmd0aCA9IHJlbWFpbmluZ1xuICAgIH1cbiAgfVxuXG4gIC8vIG11c3QgYmUgYW4gZXZlbiBudW1iZXIgb2YgZGlnaXRzXG4gIHZhciBzdHJMZW4gPSBzdHJpbmcubGVuZ3RoXG4gIGlmIChzdHJMZW4gJSAyICE9PSAwKSB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgaGV4IHN0cmluZycpXG5cbiAgaWYgKGxlbmd0aCA+IHN0ckxlbiAvIDIpIHtcbiAgICBsZW5ndGggPSBzdHJMZW4gLyAyXG4gIH1cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW5ndGg7IGkrKykge1xuICAgIHZhciBwYXJzZWQgPSBwYXJzZUludChzdHJpbmcuc3Vic3RyKGkgKiAyLCAyKSwgMTYpXG4gICAgaWYgKGlzTmFOKHBhcnNlZCkpIHJldHVybiBpXG4gICAgYnVmW29mZnNldCArIGldID0gcGFyc2VkXG4gIH1cbiAgcmV0dXJuIGlcbn1cblxuZnVuY3Rpb24gdXRmOFdyaXRlIChidWYsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgcmV0dXJuIGJsaXRCdWZmZXIodXRmOFRvQnl0ZXMoc3RyaW5nLCBidWYubGVuZ3RoIC0gb2Zmc2V0KSwgYnVmLCBvZmZzZXQsIGxlbmd0aClcbn1cblxuZnVuY3Rpb24gYXNjaWlXcml0ZSAoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIHJldHVybiBibGl0QnVmZmVyKGFzY2lpVG9CeXRlcyhzdHJpbmcpLCBidWYsIG9mZnNldCwgbGVuZ3RoKVxufVxuXG5mdW5jdGlvbiBiaW5hcnlXcml0ZSAoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIHJldHVybiBhc2NpaVdyaXRlKGJ1Ziwgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcbn1cblxuZnVuY3Rpb24gYmFzZTY0V3JpdGUgKGJ1Ziwgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aCkge1xuICByZXR1cm4gYmxpdEJ1ZmZlcihiYXNlNjRUb0J5dGVzKHN0cmluZyksIGJ1Ziwgb2Zmc2V0LCBsZW5ndGgpXG59XG5cbmZ1bmN0aW9uIHVjczJXcml0ZSAoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIHJldHVybiBibGl0QnVmZmVyKHV0ZjE2bGVUb0J5dGVzKHN0cmluZywgYnVmLmxlbmd0aCAtIG9mZnNldCksIGJ1Ziwgb2Zmc2V0LCBsZW5ndGgpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGUgPSBmdW5jdGlvbiB3cml0ZSAoc3RyaW5nLCBvZmZzZXQsIGxlbmd0aCwgZW5jb2RpbmcpIHtcbiAgLy8gQnVmZmVyI3dyaXRlKHN0cmluZylcbiAgaWYgKG9mZnNldCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgZW5jb2RpbmcgPSAndXRmOCdcbiAgICBsZW5ndGggPSB0aGlzLmxlbmd0aFxuICAgIG9mZnNldCA9IDBcbiAgLy8gQnVmZmVyI3dyaXRlKHN0cmluZywgZW5jb2RpbmcpXG4gIH0gZWxzZSBpZiAobGVuZ3RoID09PSB1bmRlZmluZWQgJiYgdHlwZW9mIG9mZnNldCA9PT0gJ3N0cmluZycpIHtcbiAgICBlbmNvZGluZyA9IG9mZnNldFxuICAgIGxlbmd0aCA9IHRoaXMubGVuZ3RoXG4gICAgb2Zmc2V0ID0gMFxuICAvLyBCdWZmZXIjd3JpdGUoc3RyaW5nLCBvZmZzZXRbLCBsZW5ndGhdWywgZW5jb2RpbmddKVxuICB9IGVsc2UgaWYgKGlzRmluaXRlKG9mZnNldCkpIHtcbiAgICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gICAgaWYgKGlzRmluaXRlKGxlbmd0aCkpIHtcbiAgICAgIGxlbmd0aCA9IGxlbmd0aCB8IDBcbiAgICAgIGlmIChlbmNvZGluZyA9PT0gdW5kZWZpbmVkKSBlbmNvZGluZyA9ICd1dGY4J1xuICAgIH0gZWxzZSB7XG4gICAgICBlbmNvZGluZyA9IGxlbmd0aFxuICAgICAgbGVuZ3RoID0gdW5kZWZpbmVkXG4gICAgfVxuICAvLyBsZWdhY3kgd3JpdGUoc3RyaW5nLCBlbmNvZGluZywgb2Zmc2V0LCBsZW5ndGgpIC0gcmVtb3ZlIGluIHYwLjEzXG4gIH0gZWxzZSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgJ0J1ZmZlci53cml0ZShzdHJpbmcsIGVuY29kaW5nLCBvZmZzZXRbLCBsZW5ndGhdKSBpcyBubyBsb25nZXIgc3VwcG9ydGVkJ1xuICAgIClcbiAgfVxuXG4gIHZhciByZW1haW5pbmcgPSB0aGlzLmxlbmd0aCAtIG9mZnNldFxuICBpZiAobGVuZ3RoID09PSB1bmRlZmluZWQgfHwgbGVuZ3RoID4gcmVtYWluaW5nKSBsZW5ndGggPSByZW1haW5pbmdcblxuICBpZiAoKHN0cmluZy5sZW5ndGggPiAwICYmIChsZW5ndGggPCAwIHx8IG9mZnNldCA8IDApKSB8fCBvZmZzZXQgPiB0aGlzLmxlbmd0aCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdBdHRlbXB0IHRvIHdyaXRlIG91dHNpZGUgYnVmZmVyIGJvdW5kcycpXG4gIH1cblxuICBpZiAoIWVuY29kaW5nKSBlbmNvZGluZyA9ICd1dGY4J1xuXG4gIHZhciBsb3dlcmVkQ2FzZSA9IGZhbHNlXG4gIGZvciAoOzspIHtcbiAgICBzd2l0Y2ggKGVuY29kaW5nKSB7XG4gICAgICBjYXNlICdoZXgnOlxuICAgICAgICByZXR1cm4gaGV4V3JpdGUodGhpcywgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcblxuICAgICAgY2FzZSAndXRmOCc6XG4gICAgICBjYXNlICd1dGYtOCc6XG4gICAgICAgIHJldHVybiB1dGY4V3JpdGUodGhpcywgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcblxuICAgICAgY2FzZSAnYXNjaWknOlxuICAgICAgICByZXR1cm4gYXNjaWlXcml0ZSh0aGlzLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxuXG4gICAgICBjYXNlICdiaW5hcnknOlxuICAgICAgICByZXR1cm4gYmluYXJ5V3JpdGUodGhpcywgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcblxuICAgICAgY2FzZSAnYmFzZTY0JzpcbiAgICAgICAgLy8gV2FybmluZzogbWF4TGVuZ3RoIG5vdCB0YWtlbiBpbnRvIGFjY291bnQgaW4gYmFzZTY0V3JpdGVcbiAgICAgICAgcmV0dXJuIGJhc2U2NFdyaXRlKHRoaXMsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpXG5cbiAgICAgIGNhc2UgJ3VjczInOlxuICAgICAgY2FzZSAndWNzLTInOlxuICAgICAgY2FzZSAndXRmMTZsZSc6XG4gICAgICBjYXNlICd1dGYtMTZsZSc6XG4gICAgICAgIHJldHVybiB1Y3MyV3JpdGUodGhpcywgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcblxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgaWYgKGxvd2VyZWRDYXNlKSB0aHJvdyBuZXcgVHlwZUVycm9yKCdVbmtub3duIGVuY29kaW5nOiAnICsgZW5jb2RpbmcpXG4gICAgICAgIGVuY29kaW5nID0gKCcnICsgZW5jb2RpbmcpLnRvTG93ZXJDYXNlKClcbiAgICAgICAgbG93ZXJlZENhc2UgPSB0cnVlXG4gICAgfVxuICB9XG59XG5cbkJ1ZmZlci5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24gdG9KU09OICgpIHtcbiAgcmV0dXJuIHtcbiAgICB0eXBlOiAnQnVmZmVyJyxcbiAgICBkYXRhOiBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbCh0aGlzLl9hcnIgfHwgdGhpcywgMClcbiAgfVxufVxuXG5mdW5jdGlvbiBiYXNlNjRTbGljZSAoYnVmLCBzdGFydCwgZW5kKSB7XG4gIGlmIChzdGFydCA9PT0gMCAmJiBlbmQgPT09IGJ1Zi5sZW5ndGgpIHtcbiAgICByZXR1cm4gYmFzZTY0LmZyb21CeXRlQXJyYXkoYnVmKVxuICB9IGVsc2Uge1xuICAgIHJldHVybiBiYXNlNjQuZnJvbUJ5dGVBcnJheShidWYuc2xpY2Uoc3RhcnQsIGVuZCkpXG4gIH1cbn1cblxuZnVuY3Rpb24gdXRmOFNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgZW5kID0gTWF0aC5taW4oYnVmLmxlbmd0aCwgZW5kKVxuICB2YXIgcmVzID0gW11cblxuICB2YXIgaSA9IHN0YXJ0XG4gIHdoaWxlIChpIDwgZW5kKSB7XG4gICAgdmFyIGZpcnN0Qnl0ZSA9IGJ1ZltpXVxuICAgIHZhciBjb2RlUG9pbnQgPSBudWxsXG4gICAgdmFyIGJ5dGVzUGVyU2VxdWVuY2UgPSAoZmlyc3RCeXRlID4gMHhFRikgPyA0XG4gICAgICA6IChmaXJzdEJ5dGUgPiAweERGKSA/IDNcbiAgICAgIDogKGZpcnN0Qnl0ZSA+IDB4QkYpID8gMlxuICAgICAgOiAxXG5cbiAgICBpZiAoaSArIGJ5dGVzUGVyU2VxdWVuY2UgPD0gZW5kKSB7XG4gICAgICB2YXIgc2Vjb25kQnl0ZSwgdGhpcmRCeXRlLCBmb3VydGhCeXRlLCB0ZW1wQ29kZVBvaW50XG5cbiAgICAgIHN3aXRjaCAoYnl0ZXNQZXJTZXF1ZW5jZSkge1xuICAgICAgICBjYXNlIDE6XG4gICAgICAgICAgaWYgKGZpcnN0Qnl0ZSA8IDB4ODApIHtcbiAgICAgICAgICAgIGNvZGVQb2ludCA9IGZpcnN0Qnl0ZVxuICAgICAgICAgIH1cbiAgICAgICAgICBicmVha1xuICAgICAgICBjYXNlIDI6XG4gICAgICAgICAgc2Vjb25kQnl0ZSA9IGJ1ZltpICsgMV1cbiAgICAgICAgICBpZiAoKHNlY29uZEJ5dGUgJiAweEMwKSA9PT0gMHg4MCkge1xuICAgICAgICAgICAgdGVtcENvZGVQb2ludCA9IChmaXJzdEJ5dGUgJiAweDFGKSA8PCAweDYgfCAoc2Vjb25kQnl0ZSAmIDB4M0YpXG4gICAgICAgICAgICBpZiAodGVtcENvZGVQb2ludCA+IDB4N0YpIHtcbiAgICAgICAgICAgICAgY29kZVBvaW50ID0gdGVtcENvZGVQb2ludFxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICBicmVha1xuICAgICAgICBjYXNlIDM6XG4gICAgICAgICAgc2Vjb25kQnl0ZSA9IGJ1ZltpICsgMV1cbiAgICAgICAgICB0aGlyZEJ5dGUgPSBidWZbaSArIDJdXG4gICAgICAgICAgaWYgKChzZWNvbmRCeXRlICYgMHhDMCkgPT09IDB4ODAgJiYgKHRoaXJkQnl0ZSAmIDB4QzApID09PSAweDgwKSB7XG4gICAgICAgICAgICB0ZW1wQ29kZVBvaW50ID0gKGZpcnN0Qnl0ZSAmIDB4RikgPDwgMHhDIHwgKHNlY29uZEJ5dGUgJiAweDNGKSA8PCAweDYgfCAodGhpcmRCeXRlICYgMHgzRilcbiAgICAgICAgICAgIGlmICh0ZW1wQ29kZVBvaW50ID4gMHg3RkYgJiYgKHRlbXBDb2RlUG9pbnQgPCAweEQ4MDAgfHwgdGVtcENvZGVQb2ludCA+IDB4REZGRikpIHtcbiAgICAgICAgICAgICAgY29kZVBvaW50ID0gdGVtcENvZGVQb2ludFxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICBicmVha1xuICAgICAgICBjYXNlIDQ6XG4gICAgICAgICAgc2Vjb25kQnl0ZSA9IGJ1ZltpICsgMV1cbiAgICAgICAgICB0aGlyZEJ5dGUgPSBidWZbaSArIDJdXG4gICAgICAgICAgZm91cnRoQnl0ZSA9IGJ1ZltpICsgM11cbiAgICAgICAgICBpZiAoKHNlY29uZEJ5dGUgJiAweEMwKSA9PT0gMHg4MCAmJiAodGhpcmRCeXRlICYgMHhDMCkgPT09IDB4ODAgJiYgKGZvdXJ0aEJ5dGUgJiAweEMwKSA9PT0gMHg4MCkge1xuICAgICAgICAgICAgdGVtcENvZGVQb2ludCA9IChmaXJzdEJ5dGUgJiAweEYpIDw8IDB4MTIgfCAoc2Vjb25kQnl0ZSAmIDB4M0YpIDw8IDB4QyB8ICh0aGlyZEJ5dGUgJiAweDNGKSA8PCAweDYgfCAoZm91cnRoQnl0ZSAmIDB4M0YpXG4gICAgICAgICAgICBpZiAodGVtcENvZGVQb2ludCA+IDB4RkZGRiAmJiB0ZW1wQ29kZVBvaW50IDwgMHgxMTAwMDApIHtcbiAgICAgICAgICAgICAgY29kZVBvaW50ID0gdGVtcENvZGVQb2ludFxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoY29kZVBvaW50ID09PSBudWxsKSB7XG4gICAgICAvLyB3ZSBkaWQgbm90IGdlbmVyYXRlIGEgdmFsaWQgY29kZVBvaW50IHNvIGluc2VydCBhXG4gICAgICAvLyByZXBsYWNlbWVudCBjaGFyIChVK0ZGRkQpIGFuZCBhZHZhbmNlIG9ubHkgMSBieXRlXG4gICAgICBjb2RlUG9pbnQgPSAweEZGRkRcbiAgICAgIGJ5dGVzUGVyU2VxdWVuY2UgPSAxXG4gICAgfSBlbHNlIGlmIChjb2RlUG9pbnQgPiAweEZGRkYpIHtcbiAgICAgIC8vIGVuY29kZSB0byB1dGYxNiAoc3Vycm9nYXRlIHBhaXIgZGFuY2UpXG4gICAgICBjb2RlUG9pbnQgLT0gMHgxMDAwMFxuICAgICAgcmVzLnB1c2goY29kZVBvaW50ID4+PiAxMCAmIDB4M0ZGIHwgMHhEODAwKVxuICAgICAgY29kZVBvaW50ID0gMHhEQzAwIHwgY29kZVBvaW50ICYgMHgzRkZcbiAgICB9XG5cbiAgICByZXMucHVzaChjb2RlUG9pbnQpXG4gICAgaSArPSBieXRlc1BlclNlcXVlbmNlXG4gIH1cblxuICByZXR1cm4gZGVjb2RlQ29kZVBvaW50c0FycmF5KHJlcylcbn1cblxuLy8gQmFzZWQgb24gaHR0cDovL3N0YWNrb3ZlcmZsb3cuY29tL2EvMjI3NDcyNzIvNjgwNzQyLCB0aGUgYnJvd3NlciB3aXRoXG4vLyB0aGUgbG93ZXN0IGxpbWl0IGlzIENocm9tZSwgd2l0aCAweDEwMDAwIGFyZ3MuXG4vLyBXZSBnbyAxIG1hZ25pdHVkZSBsZXNzLCBmb3Igc2FmZXR5XG52YXIgTUFYX0FSR1VNRU5UU19MRU5HVEggPSAweDEwMDBcblxuZnVuY3Rpb24gZGVjb2RlQ29kZVBvaW50c0FycmF5IChjb2RlUG9pbnRzKSB7XG4gIHZhciBsZW4gPSBjb2RlUG9pbnRzLmxlbmd0aFxuICBpZiAobGVuIDw9IE1BWF9BUkdVTUVOVFNfTEVOR1RIKSB7XG4gICAgcmV0dXJuIFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkoU3RyaW5nLCBjb2RlUG9pbnRzKSAvLyBhdm9pZCBleHRyYSBzbGljZSgpXG4gIH1cblxuICAvLyBEZWNvZGUgaW4gY2h1bmtzIHRvIGF2b2lkIFwiY2FsbCBzdGFjayBzaXplIGV4Y2VlZGVkXCIuXG4gIHZhciByZXMgPSAnJ1xuICB2YXIgaSA9IDBcbiAgd2hpbGUgKGkgPCBsZW4pIHtcbiAgICByZXMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShcbiAgICAgIFN0cmluZyxcbiAgICAgIGNvZGVQb2ludHMuc2xpY2UoaSwgaSArPSBNQVhfQVJHVU1FTlRTX0xFTkdUSClcbiAgICApXG4gIH1cbiAgcmV0dXJuIHJlc1xufVxuXG5mdW5jdGlvbiBhc2NpaVNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIHJldCA9ICcnXG4gIGVuZCA9IE1hdGgubWluKGJ1Zi5sZW5ndGgsIGVuZClcblxuICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7IGkrKykge1xuICAgIHJldCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ1ZltpXSAmIDB4N0YpXG4gIH1cbiAgcmV0dXJuIHJldFxufVxuXG5mdW5jdGlvbiBiaW5hcnlTbGljZSAoYnVmLCBzdGFydCwgZW5kKSB7XG4gIHZhciByZXQgPSAnJ1xuICBlbmQgPSBNYXRoLm1pbihidWYubGVuZ3RoLCBlbmQpXG5cbiAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyBpKyspIHtcbiAgICByZXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShidWZbaV0pXG4gIH1cbiAgcmV0dXJuIHJldFxufVxuXG5mdW5jdGlvbiBoZXhTbGljZSAoYnVmLCBzdGFydCwgZW5kKSB7XG4gIHZhciBsZW4gPSBidWYubGVuZ3RoXG5cbiAgaWYgKCFzdGFydCB8fCBzdGFydCA8IDApIHN0YXJ0ID0gMFxuICBpZiAoIWVuZCB8fCBlbmQgPCAwIHx8IGVuZCA+IGxlbikgZW5kID0gbGVuXG5cbiAgdmFyIG91dCA9ICcnXG4gIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgaSsrKSB7XG4gICAgb3V0ICs9IHRvSGV4KGJ1ZltpXSlcbiAgfVxuICByZXR1cm4gb3V0XG59XG5cbmZ1bmN0aW9uIHV0ZjE2bGVTbGljZSAoYnVmLCBzdGFydCwgZW5kKSB7XG4gIHZhciBieXRlcyA9IGJ1Zi5zbGljZShzdGFydCwgZW5kKVxuICB2YXIgcmVzID0gJydcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlcy5sZW5ndGg7IGkgKz0gMikge1xuICAgIHJlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVzW2ldICsgYnl0ZXNbaSArIDFdICogMjU2KVxuICB9XG4gIHJldHVybiByZXNcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5zbGljZSA9IGZ1bmN0aW9uIHNsaWNlIChzdGFydCwgZW5kKSB7XG4gIHZhciBsZW4gPSB0aGlzLmxlbmd0aFxuICBzdGFydCA9IH5+c3RhcnRcbiAgZW5kID0gZW5kID09PSB1bmRlZmluZWQgPyBsZW4gOiB+fmVuZFxuXG4gIGlmIChzdGFydCA8IDApIHtcbiAgICBzdGFydCArPSBsZW5cbiAgICBpZiAoc3RhcnQgPCAwKSBzdGFydCA9IDBcbiAgfSBlbHNlIGlmIChzdGFydCA+IGxlbikge1xuICAgIHN0YXJ0ID0gbGVuXG4gIH1cblxuICBpZiAoZW5kIDwgMCkge1xuICAgIGVuZCArPSBsZW5cbiAgICBpZiAoZW5kIDwgMCkgZW5kID0gMFxuICB9IGVsc2UgaWYgKGVuZCA+IGxlbikge1xuICAgIGVuZCA9IGxlblxuICB9XG5cbiAgaWYgKGVuZCA8IHN0YXJ0KSBlbmQgPSBzdGFydFxuXG4gIHZhciBuZXdCdWZcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgbmV3QnVmID0gdGhpcy5zdWJhcnJheShzdGFydCwgZW5kKVxuICAgIG5ld0J1Zi5fX3Byb3RvX18gPSBCdWZmZXIucHJvdG90eXBlXG4gIH0gZWxzZSB7XG4gICAgdmFyIHNsaWNlTGVuID0gZW5kIC0gc3RhcnRcbiAgICBuZXdCdWYgPSBuZXcgQnVmZmVyKHNsaWNlTGVuLCB1bmRlZmluZWQpXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzbGljZUxlbjsgaSsrKSB7XG4gICAgICBuZXdCdWZbaV0gPSB0aGlzW2kgKyBzdGFydF1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gbmV3QnVmXG59XG5cbi8qXG4gKiBOZWVkIHRvIG1ha2Ugc3VyZSB0aGF0IGJ1ZmZlciBpc24ndCB0cnlpbmcgdG8gd3JpdGUgb3V0IG9mIGJvdW5kcy5cbiAqL1xuZnVuY3Rpb24gY2hlY2tPZmZzZXQgKG9mZnNldCwgZXh0LCBsZW5ndGgpIHtcbiAgaWYgKChvZmZzZXQgJSAxKSAhPT0gMCB8fCBvZmZzZXQgPCAwKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignb2Zmc2V0IGlzIG5vdCB1aW50JylcbiAgaWYgKG9mZnNldCArIGV4dCA+IGxlbmd0aCkgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ1RyeWluZyB0byBhY2Nlc3MgYmV5b25kIGJ1ZmZlciBsZW5ndGgnKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRVSW50TEUgPSBmdW5jdGlvbiByZWFkVUludExFIChvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgYnl0ZUxlbmd0aCwgdGhpcy5sZW5ndGgpXG5cbiAgdmFyIHZhbCA9IHRoaXNbb2Zmc2V0XVxuICB2YXIgbXVsID0gMVxuICB2YXIgaSA9IDBcbiAgd2hpbGUgKCsraSA8IGJ5dGVMZW5ndGggJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICB2YWwgKz0gdGhpc1tvZmZzZXQgKyBpXSAqIG11bFxuICB9XG5cbiAgcmV0dXJuIHZhbFxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRVSW50QkUgPSBmdW5jdGlvbiByZWFkVUludEJFIChvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIHtcbiAgICBjaGVja09mZnNldChvZmZzZXQsIGJ5dGVMZW5ndGgsIHRoaXMubGVuZ3RoKVxuICB9XG5cbiAgdmFyIHZhbCA9IHRoaXNbb2Zmc2V0ICsgLS1ieXRlTGVuZ3RoXVxuICB2YXIgbXVsID0gMVxuICB3aGlsZSAoYnl0ZUxlbmd0aCA+IDAgJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICB2YWwgKz0gdGhpc1tvZmZzZXQgKyAtLWJ5dGVMZW5ndGhdICogbXVsXG4gIH1cblxuICByZXR1cm4gdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZFVJbnQ4ID0gZnVuY3Rpb24gcmVhZFVJbnQ4IChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgMSwgdGhpcy5sZW5ndGgpXG4gIHJldHVybiB0aGlzW29mZnNldF1cbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkVUludDE2TEUgPSBmdW5jdGlvbiByZWFkVUludDE2TEUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCAyLCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuIHRoaXNbb2Zmc2V0XSB8ICh0aGlzW29mZnNldCArIDFdIDw8IDgpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZFVJbnQxNkJFID0gZnVuY3Rpb24gcmVhZFVJbnQxNkJFIChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgMiwgdGhpcy5sZW5ndGgpXG4gIHJldHVybiAodGhpc1tvZmZzZXRdIDw8IDgpIHwgdGhpc1tvZmZzZXQgKyAxXVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRVSW50MzJMRSA9IGZ1bmN0aW9uIHJlYWRVSW50MzJMRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuXG4gIHJldHVybiAoKHRoaXNbb2Zmc2V0XSkgfFxuICAgICAgKHRoaXNbb2Zmc2V0ICsgMV0gPDwgOCkgfFxuICAgICAgKHRoaXNbb2Zmc2V0ICsgMl0gPDwgMTYpKSArXG4gICAgICAodGhpc1tvZmZzZXQgKyAzXSAqIDB4MTAwMDAwMClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkVUludDMyQkUgPSBmdW5jdGlvbiByZWFkVUludDMyQkUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA0LCB0aGlzLmxlbmd0aClcblxuICByZXR1cm4gKHRoaXNbb2Zmc2V0XSAqIDB4MTAwMDAwMCkgK1xuICAgICgodGhpc1tvZmZzZXQgKyAxXSA8PCAxNikgfFxuICAgICh0aGlzW29mZnNldCArIDJdIDw8IDgpIHxcbiAgICB0aGlzW29mZnNldCArIDNdKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnRMRSA9IGZ1bmN0aW9uIHJlYWRJbnRMRSAob2Zmc2V0LCBieXRlTGVuZ3RoLCBub0Fzc2VydCkge1xuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGJ5dGVMZW5ndGggPSBieXRlTGVuZ3RoIHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIGJ5dGVMZW5ndGgsIHRoaXMubGVuZ3RoKVxuXG4gIHZhciB2YWwgPSB0aGlzW29mZnNldF1cbiAgdmFyIG11bCA9IDFcbiAgdmFyIGkgPSAwXG4gIHdoaWxlICgrK2kgPCBieXRlTGVuZ3RoICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgdmFsICs9IHRoaXNbb2Zmc2V0ICsgaV0gKiBtdWxcbiAgfVxuICBtdWwgKj0gMHg4MFxuXG4gIGlmICh2YWwgPj0gbXVsKSB2YWwgLT0gTWF0aC5wb3coMiwgOCAqIGJ5dGVMZW5ndGgpXG5cbiAgcmV0dXJuIHZhbFxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnRCRSA9IGZ1bmN0aW9uIHJlYWRJbnRCRSAob2Zmc2V0LCBieXRlTGVuZ3RoLCBub0Fzc2VydCkge1xuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGJ5dGVMZW5ndGggPSBieXRlTGVuZ3RoIHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIGJ5dGVMZW5ndGgsIHRoaXMubGVuZ3RoKVxuXG4gIHZhciBpID0gYnl0ZUxlbmd0aFxuICB2YXIgbXVsID0gMVxuICB2YXIgdmFsID0gdGhpc1tvZmZzZXQgKyAtLWldXG4gIHdoaWxlIChpID4gMCAmJiAobXVsICo9IDB4MTAwKSkge1xuICAgIHZhbCArPSB0aGlzW29mZnNldCArIC0taV0gKiBtdWxcbiAgfVxuICBtdWwgKj0gMHg4MFxuXG4gIGlmICh2YWwgPj0gbXVsKSB2YWwgLT0gTWF0aC5wb3coMiwgOCAqIGJ5dGVMZW5ndGgpXG5cbiAgcmV0dXJuIHZhbFxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnQ4ID0gZnVuY3Rpb24gcmVhZEludDggKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCAxLCB0aGlzLmxlbmd0aClcbiAgaWYgKCEodGhpc1tvZmZzZXRdICYgMHg4MCkpIHJldHVybiAodGhpc1tvZmZzZXRdKVxuICByZXR1cm4gKCgweGZmIC0gdGhpc1tvZmZzZXRdICsgMSkgKiAtMSlcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkSW50MTZMRSA9IGZ1bmN0aW9uIHJlYWRJbnQxNkxFIChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgMiwgdGhpcy5sZW5ndGgpXG4gIHZhciB2YWwgPSB0aGlzW29mZnNldF0gfCAodGhpc1tvZmZzZXQgKyAxXSA8PCA4KVxuICByZXR1cm4gKHZhbCAmIDB4ODAwMCkgPyB2YWwgfCAweEZGRkYwMDAwIDogdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludDE2QkUgPSBmdW5jdGlvbiByZWFkSW50MTZCRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDIsIHRoaXMubGVuZ3RoKVxuICB2YXIgdmFsID0gdGhpc1tvZmZzZXQgKyAxXSB8ICh0aGlzW29mZnNldF0gPDwgOClcbiAgcmV0dXJuICh2YWwgJiAweDgwMDApID8gdmFsIHwgMHhGRkZGMDAwMCA6IHZhbFxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnQzMkxFID0gZnVuY3Rpb24gcmVhZEludDMyTEUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA0LCB0aGlzLmxlbmd0aClcblxuICByZXR1cm4gKHRoaXNbb2Zmc2V0XSkgfFxuICAgICh0aGlzW29mZnNldCArIDFdIDw8IDgpIHxcbiAgICAodGhpc1tvZmZzZXQgKyAyXSA8PCAxNikgfFxuICAgICh0aGlzW29mZnNldCArIDNdIDw8IDI0KVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnQzMkJFID0gZnVuY3Rpb24gcmVhZEludDMyQkUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA0LCB0aGlzLmxlbmd0aClcblxuICByZXR1cm4gKHRoaXNbb2Zmc2V0XSA8PCAyNCkgfFxuICAgICh0aGlzW29mZnNldCArIDFdIDw8IDE2KSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgMl0gPDwgOCkgfFxuICAgICh0aGlzW29mZnNldCArIDNdKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRGbG9hdExFID0gZnVuY3Rpb24gcmVhZEZsb2F0TEUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA0LCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuIGllZWU3NTQucmVhZCh0aGlzLCBvZmZzZXQsIHRydWUsIDIzLCA0KVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRGbG9hdEJFID0gZnVuY3Rpb24gcmVhZEZsb2F0QkUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA0LCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuIGllZWU3NTQucmVhZCh0aGlzLCBvZmZzZXQsIGZhbHNlLCAyMywgNClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkRG91YmxlTEUgPSBmdW5jdGlvbiByZWFkRG91YmxlTEUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCA4LCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuIGllZWU3NTQucmVhZCh0aGlzLCBvZmZzZXQsIHRydWUsIDUyLCA4KVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWREb3VibGVCRSA9IGZ1bmN0aW9uIHJlYWREb3VibGVCRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDgsIHRoaXMubGVuZ3RoKVxuICByZXR1cm4gaWVlZTc1NC5yZWFkKHRoaXMsIG9mZnNldCwgZmFsc2UsIDUyLCA4KVxufVxuXG5mdW5jdGlvbiBjaGVja0ludCAoYnVmLCB2YWx1ZSwgb2Zmc2V0LCBleHQsIG1heCwgbWluKSB7XG4gIGlmICghQnVmZmVyLmlzQnVmZmVyKGJ1ZikpIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wiYnVmZmVyXCIgYXJndW1lbnQgbXVzdCBiZSBhIEJ1ZmZlciBpbnN0YW5jZScpXG4gIGlmICh2YWx1ZSA+IG1heCB8fCB2YWx1ZSA8IG1pbikgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ1widmFsdWVcIiBhcmd1bWVudCBpcyBvdXQgb2YgYm91bmRzJylcbiAgaWYgKG9mZnNldCArIGV4dCA+IGJ1Zi5sZW5ndGgpIHRocm93IG5ldyBSYW5nZUVycm9yKCdJbmRleCBvdXQgb2YgcmFuZ2UnKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlVUludExFID0gZnVuY3Rpb24gd3JpdGVVSW50TEUgKHZhbHVlLCBvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIHtcbiAgICB2YXIgbWF4Qnl0ZXMgPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aCkgLSAxXG4gICAgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbWF4Qnl0ZXMsIDApXG4gIH1cblxuICB2YXIgbXVsID0gMVxuICB2YXIgaSA9IDBcbiAgdGhpc1tvZmZzZXRdID0gdmFsdWUgJiAweEZGXG4gIHdoaWxlICgrK2kgPCBieXRlTGVuZ3RoICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgdGhpc1tvZmZzZXQgKyBpXSA9ICh2YWx1ZSAvIG11bCkgJiAweEZGXG4gIH1cblxuICByZXR1cm4gb2Zmc2V0ICsgYnl0ZUxlbmd0aFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlVUludEJFID0gZnVuY3Rpb24gd3JpdGVVSW50QkUgKHZhbHVlLCBvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIHtcbiAgICB2YXIgbWF4Qnl0ZXMgPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aCkgLSAxXG4gICAgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbWF4Qnl0ZXMsIDApXG4gIH1cblxuICB2YXIgaSA9IGJ5dGVMZW5ndGggLSAxXG4gIHZhciBtdWwgPSAxXG4gIHRoaXNbb2Zmc2V0ICsgaV0gPSB2YWx1ZSAmIDB4RkZcbiAgd2hpbGUgKC0taSA+PSAwICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgdGhpc1tvZmZzZXQgKyBpXSA9ICh2YWx1ZSAvIG11bCkgJiAweEZGXG4gIH1cblxuICByZXR1cm4gb2Zmc2V0ICsgYnl0ZUxlbmd0aFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlVUludDggPSBmdW5jdGlvbiB3cml0ZVVJbnQ4ICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrSW50KHRoaXMsIHZhbHVlLCBvZmZzZXQsIDEsIDB4ZmYsIDApXG4gIGlmICghQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHZhbHVlID0gTWF0aC5mbG9vcih2YWx1ZSlcbiAgdGhpc1tvZmZzZXRdID0gKHZhbHVlICYgMHhmZilcbiAgcmV0dXJuIG9mZnNldCArIDFcbn1cblxuZnVuY3Rpb24gb2JqZWN0V3JpdGVVSW50MTYgKGJ1ZiwgdmFsdWUsIG9mZnNldCwgbGl0dGxlRW5kaWFuKSB7XG4gIGlmICh2YWx1ZSA8IDApIHZhbHVlID0gMHhmZmZmICsgdmFsdWUgKyAxXG4gIGZvciAodmFyIGkgPSAwLCBqID0gTWF0aC5taW4oYnVmLmxlbmd0aCAtIG9mZnNldCwgMik7IGkgPCBqOyBpKyspIHtcbiAgICBidWZbb2Zmc2V0ICsgaV0gPSAodmFsdWUgJiAoMHhmZiA8PCAoOCAqIChsaXR0bGVFbmRpYW4gPyBpIDogMSAtIGkpKSkpID4+PlxuICAgICAgKGxpdHRsZUVuZGlhbiA/IGkgOiAxIC0gaSkgKiA4XG4gIH1cbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZVVJbnQxNkxFID0gZnVuY3Rpb24gd3JpdGVVSW50MTZMRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCAyLCAweGZmZmYsIDApXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSAmIDB4ZmYpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSA+Pj4gOClcbiAgfSBlbHNlIHtcbiAgICBvYmplY3RXcml0ZVVJbnQxNih0aGlzLCB2YWx1ZSwgb2Zmc2V0LCB0cnVlKVxuICB9XG4gIHJldHVybiBvZmZzZXQgKyAyXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVVSW50MTZCRSA9IGZ1bmN0aW9uIHdyaXRlVUludDE2QkUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgMiwgMHhmZmZmLCAwKVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgPj4+IDgpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MTYodGhpcywgdmFsdWUsIG9mZnNldCwgZmFsc2UpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDJcbn1cblxuZnVuY3Rpb24gb2JqZWN0V3JpdGVVSW50MzIgKGJ1ZiwgdmFsdWUsIG9mZnNldCwgbGl0dGxlRW5kaWFuKSB7XG4gIGlmICh2YWx1ZSA8IDApIHZhbHVlID0gMHhmZmZmZmZmZiArIHZhbHVlICsgMVxuICBmb3IgKHZhciBpID0gMCwgaiA9IE1hdGgubWluKGJ1Zi5sZW5ndGggLSBvZmZzZXQsIDQpOyBpIDwgajsgaSsrKSB7XG4gICAgYnVmW29mZnNldCArIGldID0gKHZhbHVlID4+PiAobGl0dGxlRW5kaWFuID8gaSA6IDMgLSBpKSAqIDgpICYgMHhmZlxuICB9XG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVVSW50MzJMRSA9IGZ1bmN0aW9uIHdyaXRlVUludDMyTEUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgNCwgMHhmZmZmZmZmZiwgMClcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgdGhpc1tvZmZzZXQgKyAzXSA9ICh2YWx1ZSA+Pj4gMjQpXG4gICAgdGhpc1tvZmZzZXQgKyAyXSA9ICh2YWx1ZSA+Pj4gMTYpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSA+Pj4gOClcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgJiAweGZmKVxuICB9IGVsc2Uge1xuICAgIG9iamVjdFdyaXRlVUludDMyKHRoaXMsIHZhbHVlLCBvZmZzZXQsIHRydWUpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDRcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZVVJbnQzMkJFID0gZnVuY3Rpb24gd3JpdGVVSW50MzJCRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCA0LCAweGZmZmZmZmZmLCAwKVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgPj4+IDI0KVxuICAgIHRoaXNbb2Zmc2V0ICsgMV0gPSAodmFsdWUgPj4+IDE2KVxuICAgIHRoaXNbb2Zmc2V0ICsgMl0gPSAodmFsdWUgPj4+IDgpXG4gICAgdGhpc1tvZmZzZXQgKyAzXSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MzIodGhpcywgdmFsdWUsIG9mZnNldCwgZmFsc2UpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDRcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludExFID0gZnVuY3Rpb24gd3JpdGVJbnRMRSAodmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSB7XG4gICAgdmFyIGxpbWl0ID0gTWF0aC5wb3coMiwgOCAqIGJ5dGVMZW5ndGggLSAxKVxuXG4gICAgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbGltaXQgLSAxLCAtbGltaXQpXG4gIH1cblxuICB2YXIgaSA9IDBcbiAgdmFyIG11bCA9IDFcbiAgdmFyIHN1YiA9IDBcbiAgdGhpc1tvZmZzZXRdID0gdmFsdWUgJiAweEZGXG4gIHdoaWxlICgrK2kgPCBieXRlTGVuZ3RoICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgaWYgKHZhbHVlIDwgMCAmJiBzdWIgPT09IDAgJiYgdGhpc1tvZmZzZXQgKyBpIC0gMV0gIT09IDApIHtcbiAgICAgIHN1YiA9IDFcbiAgICB9XG4gICAgdGhpc1tvZmZzZXQgKyBpXSA9ICgodmFsdWUgLyBtdWwpID4+IDApIC0gc3ViICYgMHhGRlxuICB9XG5cbiAgcmV0dXJuIG9mZnNldCArIGJ5dGVMZW5ndGhcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludEJFID0gZnVuY3Rpb24gd3JpdGVJbnRCRSAodmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSB7XG4gICAgdmFyIGxpbWl0ID0gTWF0aC5wb3coMiwgOCAqIGJ5dGVMZW5ndGggLSAxKVxuXG4gICAgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbGltaXQgLSAxLCAtbGltaXQpXG4gIH1cblxuICB2YXIgaSA9IGJ5dGVMZW5ndGggLSAxXG4gIHZhciBtdWwgPSAxXG4gIHZhciBzdWIgPSAwXG4gIHRoaXNbb2Zmc2V0ICsgaV0gPSB2YWx1ZSAmIDB4RkZcbiAgd2hpbGUgKC0taSA+PSAwICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgaWYgKHZhbHVlIDwgMCAmJiBzdWIgPT09IDAgJiYgdGhpc1tvZmZzZXQgKyBpICsgMV0gIT09IDApIHtcbiAgICAgIHN1YiA9IDFcbiAgICB9XG4gICAgdGhpc1tvZmZzZXQgKyBpXSA9ICgodmFsdWUgLyBtdWwpID4+IDApIC0gc3ViICYgMHhGRlxuICB9XG5cbiAgcmV0dXJuIG9mZnNldCArIGJ5dGVMZW5ndGhcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludDggPSBmdW5jdGlvbiB3cml0ZUludDggKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgMSwgMHg3ZiwgLTB4ODApXG4gIGlmICghQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHZhbHVlID0gTWF0aC5mbG9vcih2YWx1ZSlcbiAgaWYgKHZhbHVlIDwgMCkgdmFsdWUgPSAweGZmICsgdmFsdWUgKyAxXG4gIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIHJldHVybiBvZmZzZXQgKyAxXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVJbnQxNkxFID0gZnVuY3Rpb24gd3JpdGVJbnQxNkxFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrSW50KHRoaXMsIHZhbHVlLCBvZmZzZXQsIDIsIDB4N2ZmZiwgLTB4ODAwMClcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgdGhpc1tvZmZzZXRdID0gKHZhbHVlICYgMHhmZilcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlID4+PiA4KVxuICB9IGVsc2Uge1xuICAgIG9iamVjdFdyaXRlVUludDE2KHRoaXMsIHZhbHVlLCBvZmZzZXQsIHRydWUpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDJcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludDE2QkUgPSBmdW5jdGlvbiB3cml0ZUludDE2QkUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgMiwgMHg3ZmZmLCAtMHg4MDAwKVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgPj4+IDgpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MTYodGhpcywgdmFsdWUsIG9mZnNldCwgZmFsc2UpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDJcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludDMyTEUgPSBmdW5jdGlvbiB3cml0ZUludDMyTEUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgNCwgMHg3ZmZmZmZmZiwgLTB4ODAwMDAwMDApXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSAmIDB4ZmYpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSA+Pj4gOClcbiAgICB0aGlzW29mZnNldCArIDJdID0gKHZhbHVlID4+PiAxNilcbiAgICB0aGlzW29mZnNldCArIDNdID0gKHZhbHVlID4+PiAyNClcbiAgfSBlbHNlIHtcbiAgICBvYmplY3RXcml0ZVVJbnQzMih0aGlzLCB2YWx1ZSwgb2Zmc2V0LCB0cnVlKVxuICB9XG4gIHJldHVybiBvZmZzZXQgKyA0XG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVJbnQzMkJFID0gZnVuY3Rpb24gd3JpdGVJbnQzMkJFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrSW50KHRoaXMsIHZhbHVlLCBvZmZzZXQsIDQsIDB4N2ZmZmZmZmYsIC0weDgwMDAwMDAwKVxuICBpZiAodmFsdWUgPCAwKSB2YWx1ZSA9IDB4ZmZmZmZmZmYgKyB2YWx1ZSArIDFcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgdGhpc1tvZmZzZXRdID0gKHZhbHVlID4+PiAyNClcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlID4+PiAxNilcbiAgICB0aGlzW29mZnNldCArIDJdID0gKHZhbHVlID4+PiA4KVxuICAgIHRoaXNbb2Zmc2V0ICsgM10gPSAodmFsdWUgJiAweGZmKVxuICB9IGVsc2Uge1xuICAgIG9iamVjdFdyaXRlVUludDMyKHRoaXMsIHZhbHVlLCBvZmZzZXQsIGZhbHNlKVxuICB9XG4gIHJldHVybiBvZmZzZXQgKyA0XG59XG5cbmZ1bmN0aW9uIGNoZWNrSUVFRTc1NCAoYnVmLCB2YWx1ZSwgb2Zmc2V0LCBleHQsIG1heCwgbWluKSB7XG4gIGlmIChvZmZzZXQgKyBleHQgPiBidWYubGVuZ3RoKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignSW5kZXggb3V0IG9mIHJhbmdlJylcbiAgaWYgKG9mZnNldCA8IDApIHRocm93IG5ldyBSYW5nZUVycm9yKCdJbmRleCBvdXQgb2YgcmFuZ2UnKVxufVxuXG5mdW5jdGlvbiB3cml0ZUZsb2F0IChidWYsIHZhbHVlLCBvZmZzZXQsIGxpdHRsZUVuZGlhbiwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkge1xuICAgIGNoZWNrSUVFRTc1NChidWYsIHZhbHVlLCBvZmZzZXQsIDQsIDMuNDAyODIzNDY2Mzg1Mjg4NmUrMzgsIC0zLjQwMjgyMzQ2NjM4NTI4ODZlKzM4KVxuICB9XG4gIGllZWU3NTQud3JpdGUoYnVmLCB2YWx1ZSwgb2Zmc2V0LCBsaXR0bGVFbmRpYW4sIDIzLCA0KVxuICByZXR1cm4gb2Zmc2V0ICsgNFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlRmxvYXRMRSA9IGZ1bmN0aW9uIHdyaXRlRmxvYXRMRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgcmV0dXJuIHdyaXRlRmxvYXQodGhpcywgdmFsdWUsIG9mZnNldCwgdHJ1ZSwgbm9Bc3NlcnQpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVGbG9hdEJFID0gZnVuY3Rpb24gd3JpdGVGbG9hdEJFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICByZXR1cm4gd3JpdGVGbG9hdCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBmYWxzZSwgbm9Bc3NlcnQpXG59XG5cbmZ1bmN0aW9uIHdyaXRlRG91YmxlIChidWYsIHZhbHVlLCBvZmZzZXQsIGxpdHRsZUVuZGlhbiwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkge1xuICAgIGNoZWNrSUVFRTc1NChidWYsIHZhbHVlLCBvZmZzZXQsIDgsIDEuNzk3NjkzMTM0ODYyMzE1N0UrMzA4LCAtMS43OTc2OTMxMzQ4NjIzMTU3RSszMDgpXG4gIH1cbiAgaWVlZTc1NC53cml0ZShidWYsIHZhbHVlLCBvZmZzZXQsIGxpdHRsZUVuZGlhbiwgNTIsIDgpXG4gIHJldHVybiBvZmZzZXQgKyA4XG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVEb3VibGVMRSA9IGZ1bmN0aW9uIHdyaXRlRG91YmxlTEUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHJldHVybiB3cml0ZURvdWJsZSh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCB0cnVlLCBub0Fzc2VydClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZURvdWJsZUJFID0gZnVuY3Rpb24gd3JpdGVEb3VibGVCRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgcmV0dXJuIHdyaXRlRG91YmxlKHRoaXMsIHZhbHVlLCBvZmZzZXQsIGZhbHNlLCBub0Fzc2VydClcbn1cblxuLy8gY29weSh0YXJnZXRCdWZmZXIsIHRhcmdldFN0YXJ0PTAsIHNvdXJjZVN0YXJ0PTAsIHNvdXJjZUVuZD1idWZmZXIubGVuZ3RoKVxuQnVmZmVyLnByb3RvdHlwZS5jb3B5ID0gZnVuY3Rpb24gY29weSAodGFyZ2V0LCB0YXJnZXRTdGFydCwgc3RhcnQsIGVuZCkge1xuICBpZiAoIXN0YXJ0KSBzdGFydCA9IDBcbiAgaWYgKCFlbmQgJiYgZW5kICE9PSAwKSBlbmQgPSB0aGlzLmxlbmd0aFxuICBpZiAodGFyZ2V0U3RhcnQgPj0gdGFyZ2V0Lmxlbmd0aCkgdGFyZ2V0U3RhcnQgPSB0YXJnZXQubGVuZ3RoXG4gIGlmICghdGFyZ2V0U3RhcnQpIHRhcmdldFN0YXJ0ID0gMFxuICBpZiAoZW5kID4gMCAmJiBlbmQgPCBzdGFydCkgZW5kID0gc3RhcnRcblxuICAvLyBDb3B5IDAgYnl0ZXM7IHdlJ3JlIGRvbmVcbiAgaWYgKGVuZCA9PT0gc3RhcnQpIHJldHVybiAwXG4gIGlmICh0YXJnZXQubGVuZ3RoID09PSAwIHx8IHRoaXMubGVuZ3RoID09PSAwKSByZXR1cm4gMFxuXG4gIC8vIEZhdGFsIGVycm9yIGNvbmRpdGlvbnNcbiAgaWYgKHRhcmdldFN0YXJ0IDwgMCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCd0YXJnZXRTdGFydCBvdXQgb2YgYm91bmRzJylcbiAgfVxuICBpZiAoc3RhcnQgPCAwIHx8IHN0YXJ0ID49IHRoaXMubGVuZ3RoKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignc291cmNlU3RhcnQgb3V0IG9mIGJvdW5kcycpXG4gIGlmIChlbmQgPCAwKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignc291cmNlRW5kIG91dCBvZiBib3VuZHMnKVxuXG4gIC8vIEFyZSB3ZSBvb2I/XG4gIGlmIChlbmQgPiB0aGlzLmxlbmd0aCkgZW5kID0gdGhpcy5sZW5ndGhcbiAgaWYgKHRhcmdldC5sZW5ndGggLSB0YXJnZXRTdGFydCA8IGVuZCAtIHN0YXJ0KSB7XG4gICAgZW5kID0gdGFyZ2V0Lmxlbmd0aCAtIHRhcmdldFN0YXJ0ICsgc3RhcnRcbiAgfVxuXG4gIHZhciBsZW4gPSBlbmQgLSBzdGFydFxuICB2YXIgaVxuXG4gIGlmICh0aGlzID09PSB0YXJnZXQgJiYgc3RhcnQgPCB0YXJnZXRTdGFydCAmJiB0YXJnZXRTdGFydCA8IGVuZCkge1xuICAgIC8vIGRlc2NlbmRpbmcgY29weSBmcm9tIGVuZFxuICAgIGZvciAoaSA9IGxlbiAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgICB0YXJnZXRbaSArIHRhcmdldFN0YXJ0XSA9IHRoaXNbaSArIHN0YXJ0XVxuICAgIH1cbiAgfSBlbHNlIGlmIChsZW4gPCAxMDAwIHx8ICFCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIC8vIGFzY2VuZGluZyBjb3B5IGZyb20gc3RhcnRcbiAgICBmb3IgKGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIHRhcmdldFtpICsgdGFyZ2V0U3RhcnRdID0gdGhpc1tpICsgc3RhcnRdXG4gICAgfVxuICB9IGVsc2Uge1xuICAgIFVpbnQ4QXJyYXkucHJvdG90eXBlLnNldC5jYWxsKFxuICAgICAgdGFyZ2V0LFxuICAgICAgdGhpcy5zdWJhcnJheShzdGFydCwgc3RhcnQgKyBsZW4pLFxuICAgICAgdGFyZ2V0U3RhcnRcbiAgICApXG4gIH1cblxuICByZXR1cm4gbGVuXG59XG5cbi8vIFVzYWdlOlxuLy8gICAgYnVmZmVyLmZpbGwobnVtYmVyWywgb2Zmc2V0WywgZW5kXV0pXG4vLyAgICBidWZmZXIuZmlsbChidWZmZXJbLCBvZmZzZXRbLCBlbmRdXSlcbi8vICAgIGJ1ZmZlci5maWxsKHN0cmluZ1ssIG9mZnNldFssIGVuZF1dWywgZW5jb2RpbmddKVxuQnVmZmVyLnByb3RvdHlwZS5maWxsID0gZnVuY3Rpb24gZmlsbCAodmFsLCBzdGFydCwgZW5kLCBlbmNvZGluZykge1xuICAvLyBIYW5kbGUgc3RyaW5nIGNhc2VzOlxuICBpZiAodHlwZW9mIHZhbCA9PT0gJ3N0cmluZycpIHtcbiAgICBpZiAodHlwZW9mIHN0YXJ0ID09PSAnc3RyaW5nJykge1xuICAgICAgZW5jb2RpbmcgPSBzdGFydFxuICAgICAgc3RhcnQgPSAwXG4gICAgICBlbmQgPSB0aGlzLmxlbmd0aFxuICAgIH0gZWxzZSBpZiAodHlwZW9mIGVuZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGVuY29kaW5nID0gZW5kXG4gICAgICBlbmQgPSB0aGlzLmxlbmd0aFxuICAgIH1cbiAgICBpZiAodmFsLmxlbmd0aCA9PT0gMSkge1xuICAgICAgdmFyIGNvZGUgPSB2YWwuY2hhckNvZGVBdCgwKVxuICAgICAgaWYgKGNvZGUgPCAyNTYpIHtcbiAgICAgICAgdmFsID0gY29kZVxuICAgICAgfVxuICAgIH1cbiAgICBpZiAoZW5jb2RpbmcgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgZW5jb2RpbmcgIT09ICdzdHJpbmcnKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdlbmNvZGluZyBtdXN0IGJlIGEgc3RyaW5nJylcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBlbmNvZGluZyA9PT0gJ3N0cmluZycgJiYgIUJ1ZmZlci5pc0VuY29kaW5nKGVuY29kaW5nKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVW5rbm93biBlbmNvZGluZzogJyArIGVuY29kaW5nKVxuICAgIH1cbiAgfSBlbHNlIGlmICh0eXBlb2YgdmFsID09PSAnbnVtYmVyJykge1xuICAgIHZhbCA9IHZhbCAmIDI1NVxuICB9XG5cbiAgLy8gSW52YWxpZCByYW5nZXMgYXJlIG5vdCBzZXQgdG8gYSBkZWZhdWx0LCBzbyBjYW4gcmFuZ2UgY2hlY2sgZWFybHkuXG4gIGlmIChzdGFydCA8IDAgfHwgdGhpcy5sZW5ndGggPCBzdGFydCB8fCB0aGlzLmxlbmd0aCA8IGVuZCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdPdXQgb2YgcmFuZ2UgaW5kZXgnKVxuICB9XG5cbiAgaWYgKGVuZCA8PSBzdGFydCkge1xuICAgIHJldHVybiB0aGlzXG4gIH1cblxuICBzdGFydCA9IHN0YXJ0ID4+PiAwXG4gIGVuZCA9IGVuZCA9PT0gdW5kZWZpbmVkID8gdGhpcy5sZW5ndGggOiBlbmQgPj4+IDBcblxuICBpZiAoIXZhbCkgdmFsID0gMFxuXG4gIHZhciBpXG4gIGlmICh0eXBlb2YgdmFsID09PSAnbnVtYmVyJykge1xuICAgIGZvciAoaSA9IHN0YXJ0OyBpIDwgZW5kOyBpKyspIHtcbiAgICAgIHRoaXNbaV0gPSB2YWxcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgdmFyIGJ5dGVzID0gQnVmZmVyLmlzQnVmZmVyKHZhbClcbiAgICAgID8gdmFsXG4gICAgICA6IHV0ZjhUb0J5dGVzKG5ldyBCdWZmZXIodmFsLCBlbmNvZGluZykudG9TdHJpbmcoKSlcbiAgICB2YXIgbGVuID0gYnl0ZXMubGVuZ3RoXG4gICAgZm9yIChpID0gMDsgaSA8IGVuZCAtIHN0YXJ0OyBpKyspIHtcbiAgICAgIHRoaXNbaSArIHN0YXJ0XSA9IGJ5dGVzW2kgJSBsZW5dXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHRoaXNcbn1cblxuLy8gSEVMUEVSIEZVTkNUSU9OU1xuLy8gPT09PT09PT09PT09PT09PVxuXG52YXIgSU5WQUxJRF9CQVNFNjRfUkUgPSAvW14rXFwvMC05QS1aYS16LV9dL2dcblxuZnVuY3Rpb24gYmFzZTY0Y2xlYW4gKHN0cikge1xuICAvLyBOb2RlIHN0cmlwcyBvdXQgaW52YWxpZCBjaGFyYWN0ZXJzIGxpa2UgXFxuIGFuZCBcXHQgZnJvbSB0aGUgc3RyaW5nLCBiYXNlNjQtanMgZG9lcyBub3RcbiAgc3RyID0gc3RyaW5ndHJpbShzdHIpLnJlcGxhY2UoSU5WQUxJRF9CQVNFNjRfUkUsICcnKVxuICAvLyBOb2RlIGNvbnZlcnRzIHN0cmluZ3Mgd2l0aCBsZW5ndGggPCAyIHRvICcnXG4gIGlmIChzdHIubGVuZ3RoIDwgMikgcmV0dXJuICcnXG4gIC8vIE5vZGUgYWxsb3dzIGZvciBub24tcGFkZGVkIGJhc2U2NCBzdHJpbmdzIChtaXNzaW5nIHRyYWlsaW5nID09PSksIGJhc2U2NC1qcyBkb2VzIG5vdFxuICB3aGlsZSAoc3RyLmxlbmd0aCAlIDQgIT09IDApIHtcbiAgICBzdHIgPSBzdHIgKyAnPSdcbiAgfVxuICByZXR1cm4gc3RyXG59XG5cbmZ1bmN0aW9uIHN0cmluZ3RyaW0gKHN0cikge1xuICBpZiAoc3RyLnRyaW0pIHJldHVybiBzdHIudHJpbSgpXG4gIHJldHVybiBzdHIucmVwbGFjZSgvXlxccyt8XFxzKyQvZywgJycpXG59XG5cbmZ1bmN0aW9uIHRvSGV4IChuKSB7XG4gIGlmIChuIDwgMTYpIHJldHVybiAnMCcgKyBuLnRvU3RyaW5nKDE2KVxuICByZXR1cm4gbi50b1N0cmluZygxNilcbn1cblxuZnVuY3Rpb24gdXRmOFRvQnl0ZXMgKHN0cmluZywgdW5pdHMpIHtcbiAgdW5pdHMgPSB1bml0cyB8fCBJbmZpbml0eVxuICB2YXIgY29kZVBvaW50XG4gIHZhciBsZW5ndGggPSBzdHJpbmcubGVuZ3RoXG4gIHZhciBsZWFkU3Vycm9nYXRlID0gbnVsbFxuICB2YXIgYnl0ZXMgPSBbXVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuZ3RoOyBpKyspIHtcbiAgICBjb2RlUG9pbnQgPSBzdHJpbmcuY2hhckNvZGVBdChpKVxuXG4gICAgLy8gaXMgc3Vycm9nYXRlIGNvbXBvbmVudFxuICAgIGlmIChjb2RlUG9pbnQgPiAweEQ3RkYgJiYgY29kZVBvaW50IDwgMHhFMDAwKSB7XG4gICAgICAvLyBsYXN0IGNoYXIgd2FzIGEgbGVhZFxuICAgICAgaWYgKCFsZWFkU3Vycm9nYXRlKSB7XG4gICAgICAgIC8vIG5vIGxlYWQgeWV0XG4gICAgICAgIGlmIChjb2RlUG9pbnQgPiAweERCRkYpIHtcbiAgICAgICAgICAvLyB1bmV4cGVjdGVkIHRyYWlsXG4gICAgICAgICAgaWYgKCh1bml0cyAtPSAzKSA+IC0xKSBieXRlcy5wdXNoKDB4RUYsIDB4QkYsIDB4QkQpXG4gICAgICAgICAgY29udGludWVcbiAgICAgICAgfSBlbHNlIGlmIChpICsgMSA9PT0gbGVuZ3RoKSB7XG4gICAgICAgICAgLy8gdW5wYWlyZWQgbGVhZFxuICAgICAgICAgIGlmICgodW5pdHMgLT0gMykgPiAtMSkgYnl0ZXMucHVzaCgweEVGLCAweEJGLCAweEJEKVxuICAgICAgICAgIGNvbnRpbnVlXG4gICAgICAgIH1cblxuICAgICAgICAvLyB2YWxpZCBsZWFkXG4gICAgICAgIGxlYWRTdXJyb2dhdGUgPSBjb2RlUG9pbnRcblxuICAgICAgICBjb250aW51ZVxuICAgICAgfVxuXG4gICAgICAvLyAyIGxlYWRzIGluIGEgcm93XG4gICAgICBpZiAoY29kZVBvaW50IDwgMHhEQzAwKSB7XG4gICAgICAgIGlmICgodW5pdHMgLT0gMykgPiAtMSkgYnl0ZXMucHVzaCgweEVGLCAweEJGLCAweEJEKVxuICAgICAgICBsZWFkU3Vycm9nYXRlID0gY29kZVBvaW50XG4gICAgICAgIGNvbnRpbnVlXG4gICAgICB9XG5cbiAgICAgIC8vIHZhbGlkIHN1cnJvZ2F0ZSBwYWlyXG4gICAgICBjb2RlUG9pbnQgPSAobGVhZFN1cnJvZ2F0ZSAtIDB4RDgwMCA8PCAxMCB8IGNvZGVQb2ludCAtIDB4REMwMCkgKyAweDEwMDAwXG4gICAgfSBlbHNlIGlmIChsZWFkU3Vycm9nYXRlKSB7XG4gICAgICAvLyB2YWxpZCBibXAgY2hhciwgYnV0IGxhc3QgY2hhciB3YXMgYSBsZWFkXG4gICAgICBpZiAoKHVuaXRzIC09IDMpID4gLTEpIGJ5dGVzLnB1c2goMHhFRiwgMHhCRiwgMHhCRClcbiAgICB9XG5cbiAgICBsZWFkU3Vycm9nYXRlID0gbnVsbFxuXG4gICAgLy8gZW5jb2RlIHV0ZjhcbiAgICBpZiAoY29kZVBvaW50IDwgMHg4MCkge1xuICAgICAgaWYgKCh1bml0cyAtPSAxKSA8IDApIGJyZWFrXG4gICAgICBieXRlcy5wdXNoKGNvZGVQb2ludClcbiAgICB9IGVsc2UgaWYgKGNvZGVQb2ludCA8IDB4ODAwKSB7XG4gICAgICBpZiAoKHVuaXRzIC09IDIpIDwgMCkgYnJlYWtcbiAgICAgIGJ5dGVzLnB1c2goXG4gICAgICAgIGNvZGVQb2ludCA+PiAweDYgfCAweEMwLFxuICAgICAgICBjb2RlUG9pbnQgJiAweDNGIHwgMHg4MFxuICAgICAgKVxuICAgIH0gZWxzZSBpZiAoY29kZVBvaW50IDwgMHgxMDAwMCkge1xuICAgICAgaWYgKCh1bml0cyAtPSAzKSA8IDApIGJyZWFrXG4gICAgICBieXRlcy5wdXNoKFxuICAgICAgICBjb2RlUG9pbnQgPj4gMHhDIHwgMHhFMCxcbiAgICAgICAgY29kZVBvaW50ID4+IDB4NiAmIDB4M0YgfCAweDgwLFxuICAgICAgICBjb2RlUG9pbnQgJiAweDNGIHwgMHg4MFxuICAgICAgKVxuICAgIH0gZWxzZSBpZiAoY29kZVBvaW50IDwgMHgxMTAwMDApIHtcbiAgICAgIGlmICgodW5pdHMgLT0gNCkgPCAwKSBicmVha1xuICAgICAgYnl0ZXMucHVzaChcbiAgICAgICAgY29kZVBvaW50ID4+IDB4MTIgfCAweEYwLFxuICAgICAgICBjb2RlUG9pbnQgPj4gMHhDICYgMHgzRiB8IDB4ODAsXG4gICAgICAgIGNvZGVQb2ludCA+PiAweDYgJiAweDNGIHwgMHg4MCxcbiAgICAgICAgY29kZVBvaW50ICYgMHgzRiB8IDB4ODBcbiAgICAgIClcbiAgICB9IGVsc2Uge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGNvZGUgcG9pbnQnKVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBieXRlc1xufVxuXG5mdW5jdGlvbiBhc2NpaVRvQnl0ZXMgKHN0cikge1xuICB2YXIgYnl0ZUFycmF5ID0gW11cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBzdHIubGVuZ3RoOyBpKyspIHtcbiAgICAvLyBOb2RlJ3MgY29kZSBzZWVtcyB0byBiZSBkb2luZyB0aGlzIGFuZCBub3QgJiAweDdGLi5cbiAgICBieXRlQXJyYXkucHVzaChzdHIuY2hhckNvZGVBdChpKSAmIDB4RkYpXG4gIH1cbiAgcmV0dXJuIGJ5dGVBcnJheVxufVxuXG5mdW5jdGlvbiB1dGYxNmxlVG9CeXRlcyAoc3RyLCB1bml0cykge1xuICB2YXIgYywgaGksIGxvXG4gIHZhciBieXRlQXJyYXkgPSBbXVxuICBmb3IgKHZhciBpID0gMDsgaSA8IHN0ci5sZW5ndGg7IGkrKykge1xuICAgIGlmICgodW5pdHMgLT0gMikgPCAwKSBicmVha1xuXG4gICAgYyA9IHN0ci5jaGFyQ29kZUF0KGkpXG4gICAgaGkgPSBjID4+IDhcbiAgICBsbyA9IGMgJSAyNTZcbiAgICBieXRlQXJyYXkucHVzaChsbylcbiAgICBieXRlQXJyYXkucHVzaChoaSlcbiAgfVxuXG4gIHJldHVybiBieXRlQXJyYXlcbn1cblxuZnVuY3Rpb24gYmFzZTY0VG9CeXRlcyAoc3RyKSB7XG4gIHJldHVybiBiYXNlNjQudG9CeXRlQXJyYXkoYmFzZTY0Y2xlYW4oc3RyKSlcbn1cblxuZnVuY3Rpb24gYmxpdEJ1ZmZlciAoc3JjLCBkc3QsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuZ3RoOyBpKyspIHtcbiAgICBpZiAoKGkgKyBvZmZzZXQgPj0gZHN0Lmxlbmd0aCkgfHwgKGkgPj0gc3JjLmxlbmd0aCkpIGJyZWFrXG4gICAgZHN0W2kgKyBvZmZzZXRdID0gc3JjW2ldXG4gIH1cbiAgcmV0dXJuIGlcbn1cblxuZnVuY3Rpb24gaXNuYW4gKHZhbCkge1xuICByZXR1cm4gdmFsICE9PSB2YWwgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby1zZWxmLWNvbXBhcmVcbn1cbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGVsbGlwdGljID0gZXhwb3J0cztcblxuZWxsaXB0aWMudmVyc2lvbiA9IHJlcXVpcmUoJy4uL3BhY2thZ2UuanNvbicpLnZlcnNpb247XG5lbGxpcHRpYy51dGlscyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvdXRpbHMnKTtcbmVsbGlwdGljLnJhbmQgPSByZXF1aXJlKCdicm9yYW5kJyk7XG5lbGxpcHRpYy5obWFjRFJCRyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvaG1hYy1kcmJnJyk7XG5lbGxpcHRpYy5jdXJ2ZSA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvY3VydmUnKTtcbmVsbGlwdGljLmN1cnZlcyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvY3VydmVzJyk7XG5cbi8vIFByb3RvY29sc1xuZWxsaXB0aWMuZWMgPSByZXF1aXJlKCcuL2VsbGlwdGljL2VjJyk7XG5lbGxpcHRpYy5lZGRzYSA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvZWRkc2EnKTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBnZXROQUYgPSB1dGlscy5nZXROQUY7XG52YXIgZ2V0SlNGID0gdXRpbHMuZ2V0SlNGO1xudmFyIGFzc2VydCA9IHV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gQmFzZUN1cnZlKHR5cGUsIGNvbmYpIHtcbiAgdGhpcy50eXBlID0gdHlwZTtcbiAgdGhpcy5wID0gbmV3IEJOKGNvbmYucCwgMTYpO1xuXG4gIC8vIFVzZSBNb250Z29tZXJ5LCB3aGVuIHRoZXJlIGlzIG5vIGZhc3QgcmVkdWN0aW9uIGZvciB0aGUgcHJpbWVcbiAgdGhpcy5yZWQgPSBjb25mLnByaW1lID8gQk4ucmVkKGNvbmYucHJpbWUpIDogQk4ubW9udCh0aGlzLnApO1xuXG4gIC8vIFVzZWZ1bCBmb3IgbWFueSBjdXJ2ZXNcbiAgdGhpcy56ZXJvID0gbmV3IEJOKDApLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5vbmUgPSBuZXcgQk4oMSkudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLnR3byA9IG5ldyBCTigyKS50b1JlZCh0aGlzLnJlZCk7XG5cbiAgLy8gQ3VydmUgY29uZmlndXJhdGlvbiwgb3B0aW9uYWxcbiAgdGhpcy5uID0gY29uZi5uICYmIG5ldyBCTihjb25mLm4sIDE2KTtcbiAgdGhpcy5nID0gY29uZi5nICYmIHRoaXMucG9pbnRGcm9tSlNPTihjb25mLmcsIGNvbmYuZ1JlZCk7XG5cbiAgLy8gVGVtcG9yYXJ5IGFycmF5c1xuICB0aGlzLl93bmFmVDEgPSBuZXcgQXJyYXkoNCk7XG4gIHRoaXMuX3duYWZUMiA9IG5ldyBBcnJheSg0KTtcbiAgdGhpcy5fd25hZlQzID0gbmV3IEFycmF5KDQpO1xuICB0aGlzLl93bmFmVDQgPSBuZXcgQXJyYXkoNCk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEJhc2VDdXJ2ZTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5wb2ludCA9IGZ1bmN0aW9uIHBvaW50KCkge1xuICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCcpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKCkge1xuICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCcpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5fZml4ZWROYWZNdWwgPSBmdW5jdGlvbiBfZml4ZWROYWZNdWwocCwgaykge1xuICBhc3NlcnQocC5wcmVjb21wdXRlZCk7XG4gIHZhciBkb3VibGVzID0gcC5fZ2V0RG91YmxlcygpO1xuXG4gIHZhciBuYWYgPSBnZXROQUYoaywgMSk7XG4gIHZhciBJID0gKDEgPDwgKGRvdWJsZXMuc3RlcCArIDEpKSAtIChkb3VibGVzLnN0ZXAgJSAyID09PSAwID8gMiA6IDEpO1xuICBJIC89IDM7XG5cbiAgLy8gVHJhbnNsYXRlIGludG8gbW9yZSB3aW5kb3dlZCBmb3JtXG4gIHZhciByZXByID0gW107XG4gIGZvciAodmFyIGogPSAwOyBqIDwgbmFmLmxlbmd0aDsgaiArPSBkb3VibGVzLnN0ZXApIHtcbiAgICB2YXIgbmFmVyA9IDA7XG4gICAgZm9yICh2YXIgayA9IGogKyBkb3VibGVzLnN0ZXAgLSAxOyBrID49IGo7IGstLSlcbiAgICAgIG5hZlcgPSAobmFmVyA8PCAxKSArIG5hZltrXTtcbiAgICByZXByLnB1c2gobmFmVyk7XG4gIH1cblxuICB2YXIgYSA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICB2YXIgYiA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICBmb3IgKHZhciBpID0gSTsgaSA+IDA7IGktLSkge1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgcmVwci5sZW5ndGg7IGorKykge1xuICAgICAgdmFyIG5hZlcgPSByZXByW2pdO1xuICAgICAgaWYgKG5hZlcgPT09IGkpXG4gICAgICAgIGIgPSBiLm1peGVkQWRkKGRvdWJsZXMucG9pbnRzW2pdKTtcbiAgICAgIGVsc2UgaWYgKG5hZlcgPT09IC1pKVxuICAgICAgICBiID0gYi5taXhlZEFkZChkb3VibGVzLnBvaW50c1tqXS5uZWcoKSk7XG4gICAgfVxuICAgIGEgPSBhLmFkZChiKTtcbiAgfVxuICByZXR1cm4gYS50b1AoKTtcbn07XG5cbkJhc2VDdXJ2ZS5wcm90b3R5cGUuX3duYWZNdWwgPSBmdW5jdGlvbiBfd25hZk11bChwLCBrKSB7XG4gIHZhciB3ID0gNDtcblxuICAvLyBQcmVjb21wdXRlIHdpbmRvd1xuICB2YXIgbmFmUG9pbnRzID0gcC5fZ2V0TkFGUG9pbnRzKHcpO1xuICB3ID0gbmFmUG9pbnRzLnduZDtcbiAgdmFyIHduZCA9IG5hZlBvaW50cy5wb2ludHM7XG5cbiAgLy8gR2V0IE5BRiBmb3JtXG4gIHZhciBuYWYgPSBnZXROQUYoaywgdyk7XG5cbiAgLy8gQWRkIGB0aGlzYCooTisxKSBmb3IgZXZlcnkgdy1OQUYgaW5kZXhcbiAgdmFyIGFjYyA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICBmb3IgKHZhciBpID0gbmFmLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgLy8gQ291bnQgemVyb2VzXG4gICAgZm9yICh2YXIgayA9IDA7IGkgPj0gMCAmJiBuYWZbaV0gPT09IDA7IGktLSlcbiAgICAgIGsrKztcbiAgICBpZiAoaSA+PSAwKVxuICAgICAgaysrO1xuICAgIGFjYyA9IGFjYy5kYmxwKGspO1xuXG4gICAgaWYgKGkgPCAwKVxuICAgICAgYnJlYWs7XG4gICAgdmFyIHogPSBuYWZbaV07XG4gICAgYXNzZXJ0KHogIT09IDApO1xuICAgIGlmIChwLnR5cGUgPT09ICdhZmZpbmUnKSB7XG4gICAgICAvLyBKICstIFBcbiAgICAgIGlmICh6ID4gMClcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHduZFsoeiAtIDEpID4+IDFdKTtcbiAgICAgIGVsc2VcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHduZFsoLXogLSAxKSA+PiAxXS5uZWcoKSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEogKy0gSlxuICAgICAgaWYgKHogPiAwKVxuICAgICAgICBhY2MgPSBhY2MuYWRkKHduZFsoeiAtIDEpID4+IDFdKTtcbiAgICAgIGVsc2VcbiAgICAgICAgYWNjID0gYWNjLmFkZCh3bmRbKC16IC0gMSkgPj4gMV0ubmVnKCkpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcC50eXBlID09PSAnYWZmaW5lJyA/IGFjYy50b1AoKSA6IGFjYztcbn07XG5cbkJhc2VDdXJ2ZS5wcm90b3R5cGUuX3duYWZNdWxBZGQgPSBmdW5jdGlvbiBfd25hZk11bEFkZChkZWZXLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvaW50cyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2VmZnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGVuKSB7XG4gIHZhciB3bmRXaWR0aCA9IHRoaXMuX3duYWZUMTtcbiAgdmFyIHduZCA9IHRoaXMuX3duYWZUMjtcbiAgdmFyIG5hZiA9IHRoaXMuX3duYWZUMztcblxuICAvLyBGaWxsIGFsbCBhcnJheXNcbiAgdmFyIG1heCA9IDA7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICB2YXIgcCA9IHBvaW50c1tpXTtcbiAgICB2YXIgbmFmUG9pbnRzID0gcC5fZ2V0TkFGUG9pbnRzKGRlZlcpO1xuICAgIHduZFdpZHRoW2ldID0gbmFmUG9pbnRzLnduZDtcbiAgICB3bmRbaV0gPSBuYWZQb2ludHMucG9pbnRzO1xuICB9XG5cbiAgLy8gQ29tYiBzbWFsbCB3aW5kb3cgTkFGc1xuICBmb3IgKHZhciBpID0gbGVuIC0gMTsgaSA+PSAxOyBpIC09IDIpIHtcbiAgICB2YXIgYSA9IGkgLSAxO1xuICAgIHZhciBiID0gaTtcbiAgICBpZiAod25kV2lkdGhbYV0gIT09IDEgfHwgd25kV2lkdGhbYl0gIT09IDEpIHtcbiAgICAgIG5hZlthXSA9IGdldE5BRihjb2VmZnNbYV0sIHduZFdpZHRoW2FdKTtcbiAgICAgIG5hZltiXSA9IGdldE5BRihjb2VmZnNbYl0sIHduZFdpZHRoW2JdKTtcbiAgICAgIG1heCA9IE1hdGgubWF4KG5hZlthXS5sZW5ndGgsIG1heCk7XG4gICAgICBtYXggPSBNYXRoLm1heChuYWZbYl0ubGVuZ3RoLCBtYXgpO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgdmFyIGNvbWIgPSBbXG4gICAgICBwb2ludHNbYV0sIC8qIDEgKi9cbiAgICAgIG51bGwsIC8qIDMgKi9cbiAgICAgIG51bGwsIC8qIDUgKi9cbiAgICAgIHBvaW50c1tiXSAvKiA3ICovXG4gICAgXTtcblxuICAgIC8vIFRyeSB0byBhdm9pZCBQcm9qZWN0aXZlIHBvaW50cywgaWYgcG9zc2libGVcbiAgICBpZiAocG9pbnRzW2FdLnkuY21wKHBvaW50c1tiXS55KSA9PT0gMCkge1xuICAgICAgY29tYlsxXSA9IHBvaW50c1thXS5hZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdLm5lZygpKTtcbiAgICB9IGVsc2UgaWYgKHBvaW50c1thXS55LmNtcChwb2ludHNbYl0ueS5yZWROZWcoKSkgPT09IDApIHtcbiAgICAgIGNvbWJbMV0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0uYWRkKHBvaW50c1tiXS5uZWcoKSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbWJbMV0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdLm5lZygpKTtcbiAgICB9XG5cbiAgICB2YXIgaW5kZXggPSBbXG4gICAgICAtMywgLyogLTEgLTEgKi9cbiAgICAgIC0xLCAvKiAtMSAwICovXG4gICAgICAtNSwgLyogLTEgMSAqL1xuICAgICAgLTcsIC8qIDAgLTEgKi9cbiAgICAgIDAsIC8qIDAgMCAqL1xuICAgICAgNywgLyogMCAxICovXG4gICAgICA1LCAvKiAxIC0xICovXG4gICAgICAxLCAvKiAxIDAgKi9cbiAgICAgIDMgIC8qIDEgMSAqL1xuICAgIF07XG5cbiAgICB2YXIganNmID0gZ2V0SlNGKGNvZWZmc1thXSwgY29lZmZzW2JdKTtcbiAgICBtYXggPSBNYXRoLm1heChqc2ZbMF0ubGVuZ3RoLCBtYXgpO1xuICAgIG5hZlthXSA9IG5ldyBBcnJheShtYXgpO1xuICAgIG5hZltiXSA9IG5ldyBBcnJheShtYXgpO1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgbWF4OyBqKyspIHtcbiAgICAgIHZhciBqYSA9IGpzZlswXVtqXSB8IDA7XG4gICAgICB2YXIgamIgPSBqc2ZbMV1bal0gfCAwO1xuXG4gICAgICBuYWZbYV1bal0gPSBpbmRleFsoamEgKyAxKSAqIDMgKyAoamIgKyAxKV07XG4gICAgICBuYWZbYl1bal0gPSAwO1xuICAgICAgd25kW2FdID0gY29tYjtcbiAgICB9XG4gIH1cblxuICB2YXIgYWNjID0gdGhpcy5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gIHZhciB0bXAgPSB0aGlzLl93bmFmVDQ7XG4gIGZvciAodmFyIGkgPSBtYXg7IGkgPj0gMDsgaS0tKSB7XG4gICAgdmFyIGsgPSAwO1xuXG4gICAgd2hpbGUgKGkgPj0gMCkge1xuICAgICAgdmFyIHplcm8gPSB0cnVlO1xuICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCBsZW47IGorKykge1xuICAgICAgICB0bXBbal0gPSBuYWZbal1baV0gfCAwO1xuICAgICAgICBpZiAodG1wW2pdICE9PSAwKVxuICAgICAgICAgIHplcm8gPSBmYWxzZTtcbiAgICAgIH1cbiAgICAgIGlmICghemVybylcbiAgICAgICAgYnJlYWs7XG4gICAgICBrKys7XG4gICAgICBpLS07XG4gICAgfVxuICAgIGlmIChpID49IDApXG4gICAgICBrKys7XG4gICAgYWNjID0gYWNjLmRibHAoayk7XG4gICAgaWYgKGkgPCAwKVxuICAgICAgYnJlYWs7XG5cbiAgICBmb3IgKHZhciBqID0gMDsgaiA8IGxlbjsgaisrKSB7XG4gICAgICB2YXIgeiA9IHRtcFtqXTtcbiAgICAgIHZhciBwO1xuICAgICAgaWYgKHogPT09IDApXG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgZWxzZSBpZiAoeiA+IDApXG4gICAgICAgIHAgPSB3bmRbal1bKHogLSAxKSA+PiAxXTtcbiAgICAgIGVsc2UgaWYgKHogPCAwKVxuICAgICAgICBwID0gd25kW2pdWygteiAtIDEpID4+IDFdLm5lZygpO1xuXG4gICAgICBpZiAocC50eXBlID09PSAnYWZmaW5lJylcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHApO1xuICAgICAgZWxzZVxuICAgICAgICBhY2MgPSBhY2MuYWRkKHApO1xuICAgIH1cbiAgfVxuICAvLyBaZXJvaWZ5IHJlZmVyZW5jZXNcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47IGkrKylcbiAgICB3bmRbaV0gPSBudWxsO1xuICByZXR1cm4gYWNjLnRvUCgpO1xufTtcblxuZnVuY3Rpb24gQmFzZVBvaW50KGN1cnZlLCB0eXBlKSB7XG4gIHRoaXMuY3VydmUgPSBjdXJ2ZTtcbiAgdGhpcy50eXBlID0gdHlwZTtcbiAgdGhpcy5wcmVjb21wdXRlZCA9IG51bGw7XG59XG5CYXNlQ3VydmUuQmFzZVBvaW50ID0gQmFzZVBvaW50O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLmVxID0gZnVuY3Rpb24gZXEoLypvdGhlciovKSB7XG4gIHRocm93IG5ldyBFcnJvcignTm90IGltcGxlbWVudGVkJyk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLnZhbGlkYXRlID0gZnVuY3Rpb24gdmFsaWRhdGUoKSB7XG4gIHJldHVybiB0aGlzLmN1cnZlLnZhbGlkYXRlKHRoaXMpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5kZWNvZGVQb2ludCA9IGZ1bmN0aW9uIGRlY29kZVBvaW50KGJ5dGVzLCBlbmMpIHtcbiAgYnl0ZXMgPSB1dGlscy50b0FycmF5KGJ5dGVzLCBlbmMpO1xuXG4gIHZhciBsZW4gPSB0aGlzLnAuYnl0ZUxlbmd0aCgpO1xuICBpZiAoYnl0ZXNbMF0gPT09IDB4MDQgJiYgYnl0ZXMubGVuZ3RoIC0gMSA9PT0gMiAqIGxlbikge1xuICAgIHJldHVybiB0aGlzLnBvaW50KGJ5dGVzLnNsaWNlKDEsIDEgKyBsZW4pLFxuICAgICAgICAgICAgICAgICAgICAgIGJ5dGVzLnNsaWNlKDEgKyBsZW4sIDEgKyAyICogbGVuKSk7XG4gIH0gZWxzZSBpZiAoKGJ5dGVzWzBdID09PSAweDAyIHx8IGJ5dGVzWzBdID09PSAweDAzKSAmJlxuICAgICAgICAgICAgICBieXRlcy5sZW5ndGggLSAxID09PSBsZW4pIHtcbiAgICByZXR1cm4gdGhpcy5wb2ludEZyb21YKGJ5dGVzLnNsaWNlKDEsIDEgKyBsZW4pLCBieXRlc1swXSA9PT0gMHgwMyk7XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKCdVbmtub3duIHBvaW50IGZvcm1hdCcpO1xufTtcblxuQmFzZVBvaW50LnByb3RvdHlwZS5lbmNvZGVDb21wcmVzc2VkID0gZnVuY3Rpb24gZW5jb2RlQ29tcHJlc3NlZChlbmMpIHtcbiAgcmV0dXJuIHRoaXMuZW5jb2RlKGVuYywgdHJ1ZSk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLl9lbmNvZGUgPSBmdW5jdGlvbiBfZW5jb2RlKGNvbXBhY3QpIHtcbiAgdmFyIGxlbiA9IHRoaXMuY3VydmUucC5ieXRlTGVuZ3RoKCk7XG4gIHZhciB4ID0gdGhpcy5nZXRYKCkudG9BcnJheSgnYmUnLCBsZW4pO1xuXG4gIGlmIChjb21wYWN0KVxuICAgIHJldHVybiBbIHRoaXMuZ2V0WSgpLmlzRXZlbigpID8gMHgwMiA6IDB4MDMgXS5jb25jYXQoeCk7XG5cbiAgcmV0dXJuIFsgMHgwNCBdLmNvbmNhdCh4LCB0aGlzLmdldFkoKS50b0FycmF5KCdiZScsIGxlbikpIDtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuZW5jb2RlID0gZnVuY3Rpb24gZW5jb2RlKGVuYywgY29tcGFjdCkge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMuX2VuY29kZShjb21wYWN0KSwgZW5jKTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUucHJlY29tcHV0ZSA9IGZ1bmN0aW9uIHByZWNvbXB1dGUocG93ZXIpIHtcbiAgaWYgKHRoaXMucHJlY29tcHV0ZWQpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgdmFyIHByZWNvbXB1dGVkID0ge1xuICAgIGRvdWJsZXM6IG51bGwsXG4gICAgbmFmOiBudWxsLFxuICAgIGJldGE6IG51bGxcbiAgfTtcbiAgcHJlY29tcHV0ZWQubmFmID0gdGhpcy5fZ2V0TkFGUG9pbnRzKDgpO1xuICBwcmVjb21wdXRlZC5kb3VibGVzID0gdGhpcy5fZ2V0RG91Ymxlcyg0LCBwb3dlcik7XG4gIHByZWNvbXB1dGVkLmJldGEgPSB0aGlzLl9nZXRCZXRhKCk7XG4gIHRoaXMucHJlY29tcHV0ZWQgPSBwcmVjb21wdXRlZDtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2hhc0RvdWJsZXMgPSBmdW5jdGlvbiBfaGFzRG91YmxlcyhrKSB7XG4gIGlmICghdGhpcy5wcmVjb21wdXRlZClcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgdmFyIGRvdWJsZXMgPSB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXM7XG4gIGlmICghZG91YmxlcylcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIGRvdWJsZXMucG9pbnRzLmxlbmd0aCA+PSBNYXRoLmNlaWwoKGsuYml0TGVuZ3RoKCkgKyAxKSAvIGRvdWJsZXMuc3RlcCk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLl9nZXREb3VibGVzID0gZnVuY3Rpb24gX2dldERvdWJsZXMoc3RlcCwgcG93ZXIpIHtcbiAgaWYgKHRoaXMucHJlY29tcHV0ZWQgJiYgdGhpcy5wcmVjb21wdXRlZC5kb3VibGVzKVxuICAgIHJldHVybiB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXM7XG5cbiAgdmFyIGRvdWJsZXMgPSBbIHRoaXMgXTtcbiAgdmFyIGFjYyA9IHRoaXM7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcG93ZXI7IGkgKz0gc3RlcCkge1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgc3RlcDsgaisrKVxuICAgICAgYWNjID0gYWNjLmRibCgpO1xuICAgIGRvdWJsZXMucHVzaChhY2MpO1xuICB9XG4gIHJldHVybiB7XG4gICAgc3RlcDogc3RlcCxcbiAgICBwb2ludHM6IGRvdWJsZXNcbiAgfTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2dldE5BRlBvaW50cyA9IGZ1bmN0aW9uIF9nZXROQUZQb2ludHMod25kKSB7XG4gIGlmICh0aGlzLnByZWNvbXB1dGVkICYmIHRoaXMucHJlY29tcHV0ZWQubmFmKVxuICAgIHJldHVybiB0aGlzLnByZWNvbXB1dGVkLm5hZjtcblxuICB2YXIgcmVzID0gWyB0aGlzIF07XG4gIHZhciBtYXggPSAoMSA8PCB3bmQpIC0gMTtcbiAgdmFyIGRibCA9IG1heCA9PT0gMSA/IG51bGwgOiB0aGlzLmRibCgpO1xuICBmb3IgKHZhciBpID0gMTsgaSA8IG1heDsgaSsrKVxuICAgIHJlc1tpXSA9IHJlc1tpIC0gMV0uYWRkKGRibCk7XG4gIHJldHVybiB7XG4gICAgd25kOiB3bmQsXG4gICAgcG9pbnRzOiByZXNcbiAgfTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2dldEJldGEgPSBmdW5jdGlvbiBfZ2V0QmV0YSgpIHtcbiAgcmV0dXJuIG51bGw7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLmRibHAgPSBmdW5jdGlvbiBkYmxwKGspIHtcbiAgdmFyIHIgPSB0aGlzO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGs7IGkrKylcbiAgICByID0gci5kYmwoKTtcbiAgcmV0dXJuIHI7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgY3VydmUgPSByZXF1aXJlKCcuLi9jdXJ2ZScpO1xudmFyIGVsbGlwdGljID0gcmVxdWlyZSgnLi4vLi4vZWxsaXB0aWMnKTtcbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIEJhc2UgPSBjdXJ2ZS5iYXNlO1xuXG52YXIgYXNzZXJ0ID0gZWxsaXB0aWMudXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBFZHdhcmRzQ3VydmUoY29uZikge1xuICAvLyBOT1RFOiBJbXBvcnRhbnQgYXMgd2UgYXJlIGNyZWF0aW5nIHBvaW50IGluIEJhc2UuY2FsbCgpXG4gIHRoaXMudHdpc3RlZCA9IChjb25mLmEgfCAwKSAhPT0gMTtcbiAgdGhpcy5tT25lQSA9IHRoaXMudHdpc3RlZCAmJiAoY29uZi5hIHwgMCkgPT09IC0xO1xuICB0aGlzLmV4dGVuZGVkID0gdGhpcy5tT25lQTtcblxuICBCYXNlLmNhbGwodGhpcywgJ2Vkd2FyZHMnLCBjb25mKTtcblxuICB0aGlzLmEgPSBuZXcgQk4oY29uZi5hLCAxNikudW1vZCh0aGlzLnJlZC5tKTtcbiAgdGhpcy5hID0gdGhpcy5hLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5jID0gbmV3IEJOKGNvbmYuYywgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5jMiA9IHRoaXMuYy5yZWRTcXIoKTtcbiAgdGhpcy5kID0gbmV3IEJOKGNvbmYuZCwgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5kZCA9IHRoaXMuZC5yZWRBZGQodGhpcy5kKTtcblxuICBhc3NlcnQoIXRoaXMudHdpc3RlZCB8fCB0aGlzLmMuZnJvbVJlZCgpLmNtcG4oMSkgPT09IDApO1xuICB0aGlzLm9uZUMgPSAoY29uZi5jIHwgMCkgPT09IDE7XG59XG5pbmhlcml0cyhFZHdhcmRzQ3VydmUsIEJhc2UpO1xubW9kdWxlLmV4cG9ydHMgPSBFZHdhcmRzQ3VydmU7XG5cbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUuX211bEEgPSBmdW5jdGlvbiBfbXVsQShudW0pIHtcbiAgaWYgKHRoaXMubU9uZUEpXG4gICAgcmV0dXJuIG51bS5yZWROZWcoKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmEucmVkTXVsKG51bSk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLl9tdWxDID0gZnVuY3Rpb24gX211bEMobnVtKSB7XG4gIGlmICh0aGlzLm9uZUMpXG4gICAgcmV0dXJuIG51bTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmMucmVkTXVsKG51bSk7XG59O1xuXG4vLyBKdXN0IGZvciBjb21wYXRpYmlsaXR5IHdpdGggU2hvcnQgY3VydmVcbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUuanBvaW50ID0gZnVuY3Rpb24ganBvaW50KHgsIHksIHosIHQpIHtcbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSwgeiwgdCk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbVggPSBmdW5jdGlvbiBwb2ludEZyb21YKHgsIG9kZCkge1xuICB4ID0gbmV3IEJOKHgsIDE2KTtcbiAgaWYgKCF4LnJlZClcbiAgICB4ID0geC50b1JlZCh0aGlzLnJlZCk7XG5cbiAgdmFyIHgyID0geC5yZWRTcXIoKTtcbiAgdmFyIHJocyA9IHRoaXMuYzIucmVkU3ViKHRoaXMuYS5yZWRNdWwoeDIpKTtcbiAgdmFyIGxocyA9IHRoaXMub25lLnJlZFN1Yih0aGlzLmMyLnJlZE11bCh0aGlzLmQpLnJlZE11bCh4MikpO1xuXG4gIHZhciB5MiA9IHJocy5yZWRNdWwobGhzLnJlZEludm0oKSk7XG4gIHZhciB5ID0geTIucmVkU3FydCgpO1xuICBpZiAoeS5yZWRTcXIoKS5yZWRTdWIoeTIpLmNtcCh0aGlzLnplcm8pICE9PSAwKVxuICAgIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBwb2ludCcpO1xuXG4gIHZhciBpc09kZCA9IHkuZnJvbVJlZCgpLmlzT2RkKCk7XG4gIGlmIChvZGQgJiYgIWlzT2RkIHx8ICFvZGQgJiYgaXNPZGQpXG4gICAgeSA9IHkucmVkTmVnKCk7XG5cbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbVkgPSBmdW5jdGlvbiBwb2ludEZyb21ZKHksIG9kZCkge1xuICB5ID0gbmV3IEJOKHksIDE2KTtcbiAgaWYgKCF5LnJlZClcbiAgICB5ID0geS50b1JlZCh0aGlzLnJlZCk7XG5cbiAgLy8geF4yID0gKHleMiAtIDEpIC8gKGQgeV4yICsgMSlcbiAgdmFyIHkyID0geS5yZWRTcXIoKTtcbiAgdmFyIGxocyA9IHkyLnJlZFN1Yih0aGlzLm9uZSk7XG4gIHZhciByaHMgPSB5Mi5yZWRNdWwodGhpcy5kKS5yZWRBZGQodGhpcy5vbmUpO1xuICB2YXIgeDIgPSBsaHMucmVkTXVsKHJocy5yZWRJbnZtKCkpO1xuXG4gIGlmICh4Mi5jbXAodGhpcy56ZXJvKSA9PT0gMCkge1xuICAgIGlmIChvZGQpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcG9pbnQnKTtcbiAgICBlbHNlXG4gICAgICByZXR1cm4gdGhpcy5wb2ludCh0aGlzLnplcm8sIHkpO1xuICB9XG5cbiAgdmFyIHggPSB4Mi5yZWRTcXJ0KCk7XG4gIGlmICh4LnJlZFNxcigpLnJlZFN1Yih4MikuY21wKHRoaXMuemVybykgIT09IDApXG4gICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHBvaW50Jyk7XG5cbiAgaWYgKHguaXNPZGQoKSAhPT0gb2RkKVxuICAgIHggPSB4LnJlZE5lZygpO1xuXG4gIHJldHVybiB0aGlzLnBvaW50KHgsIHkpO1xufTtcblxuRWR3YXJkc0N1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIGlmIChwb2ludC5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgLy8gQ3VydmU6IEEgKiBYXjIgKyBZXjIgPSBDXjIgKiAoMSArIEQgKiBYXjIgKiBZXjIpXG4gIHBvaW50Lm5vcm1hbGl6ZSgpO1xuXG4gIHZhciB4MiA9IHBvaW50LngucmVkU3FyKCk7XG4gIHZhciB5MiA9IHBvaW50LnkucmVkU3FyKCk7XG4gIHZhciBsaHMgPSB4Mi5yZWRNdWwodGhpcy5hKS5yZWRBZGQoeTIpO1xuICB2YXIgcmhzID0gdGhpcy5jMi5yZWRNdWwodGhpcy5vbmUucmVkQWRkKHRoaXMuZC5yZWRNdWwoeDIpLnJlZE11bCh5MikpKTtcblxuICByZXR1cm4gbGhzLmNtcChyaHMpID09PSAwO1xufTtcblxuZnVuY3Rpb24gUG9pbnQoY3VydmUsIHgsIHksIHosIHQpIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ3Byb2plY3RpdmUnKTtcbiAgaWYgKHggPT09IG51bGwgJiYgeSA9PT0gbnVsbCAmJiB6ID09PSBudWxsKSB7XG4gICAgdGhpcy54ID0gdGhpcy5jdXJ2ZS56ZXJvO1xuICAgIHRoaXMueSA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMueiA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMudCA9IHRoaXMuY3VydmUuemVybztcbiAgICB0aGlzLnpPbmUgPSB0cnVlO1xuICB9IGVsc2Uge1xuICAgIHRoaXMueCA9IG5ldyBCTih4LCAxNik7XG4gICAgdGhpcy55ID0gbmV3IEJOKHksIDE2KTtcbiAgICB0aGlzLnogPSB6ID8gbmV3IEJOKHosIDE2KSA6IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMudCA9IHQgJiYgbmV3IEJOKHQsIDE2KTtcbiAgICBpZiAoIXRoaXMueC5yZWQpXG4gICAgICB0aGlzLnggPSB0aGlzLngudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIGlmICghdGhpcy55LnJlZClcbiAgICAgIHRoaXMueSA9IHRoaXMueS50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgaWYgKCF0aGlzLnoucmVkKVxuICAgICAgdGhpcy56ID0gdGhpcy56LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICBpZiAodGhpcy50ICYmICF0aGlzLnQucmVkKVxuICAgICAgdGhpcy50ID0gdGhpcy50LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICB0aGlzLnpPbmUgPSB0aGlzLnogPT09IHRoaXMuY3VydmUub25lO1xuXG4gICAgLy8gVXNlIGV4dGVuZGVkIGNvb3JkaW5hdGVzXG4gICAgaWYgKHRoaXMuY3VydmUuZXh0ZW5kZWQgJiYgIXRoaXMudCkge1xuICAgICAgdGhpcy50ID0gdGhpcy54LnJlZE11bCh0aGlzLnkpO1xuICAgICAgaWYgKCF0aGlzLnpPbmUpXG4gICAgICAgIHRoaXMudCA9IHRoaXMudC5yZWRNdWwodGhpcy56LnJlZEludm0oKSk7XG4gICAgfVxuICB9XG59XG5pbmhlcml0cyhQb2ludCwgQmFzZS5CYXNlUG9pbnQpO1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaikge1xuICByZXR1cm4gUG9pbnQuZnJvbUpTT04odGhpcywgb2JqKTtcbn07XG5cbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB5LCB6LCB0KSB7XG4gIHJldHVybiBuZXcgUG9pbnQodGhpcywgeCwgeSwgeiwgdCk7XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmopIHtcbiAgcmV0dXJuIG5ldyBQb2ludChjdXJ2ZSwgb2JqWzBdLCBvYmpbMV0sIG9ialsyXSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaW5zcGVjdCA9IGZ1bmN0aW9uIGluc3BlY3QoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gJzxFQyBQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBQb2ludCB4OiAnICsgdGhpcy54LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB6OiAnICsgdGhpcy56LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgKyAnPic7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaXNJbmZpbml0eSA9IGZ1bmN0aW9uIGlzSW5maW5pdHkoKSB7XG4gIC8vIFhYWCBUaGlzIGNvZGUgYXNzdW1lcyB0aGF0IHplcm8gaXMgYWx3YXlzIHplcm8gaW4gcmVkXG4gIHJldHVybiB0aGlzLnguY21wbigwKSA9PT0gMCAmJlxuICAgICAgICAgdGhpcy55LmNtcCh0aGlzLnopID09PSAwO1xufTtcblxuUG9pbnQucHJvdG90eXBlLl9leHREYmwgPSBmdW5jdGlvbiBfZXh0RGJsKCkge1xuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tdHdpc3RlZC1leHRlbmRlZC0xLmh0bWxcbiAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwOC1od2NkXG4gIC8vIDRNICsgNFNcblxuICAvLyBBID0gWDFeMlxuICB2YXIgYSA9IHRoaXMueC5yZWRTcXIoKTtcbiAgLy8gQiA9IFkxXjJcbiAgdmFyIGIgPSB0aGlzLnkucmVkU3FyKCk7XG4gIC8vIEMgPSAyICogWjFeMlxuICB2YXIgYyA9IHRoaXMuei5yZWRTcXIoKTtcbiAgYyA9IGMucmVkSUFkZChjKTtcbiAgLy8gRCA9IGEgKiBBXG4gIHZhciBkID0gdGhpcy5jdXJ2ZS5fbXVsQShhKTtcbiAgLy8gRSA9IChYMSArIFkxKV4yIC0gQSAtIEJcbiAgdmFyIGUgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkU3FyKCkucmVkSVN1YihhKS5yZWRJU3ViKGIpO1xuICAvLyBHID0gRCArIEJcbiAgdmFyIGcgPSBkLnJlZEFkZChiKTtcbiAgLy8gRiA9IEcgLSBDXG4gIHZhciBmID0gZy5yZWRTdWIoYyk7XG4gIC8vIEggPSBEIC0gQlxuICB2YXIgaCA9IGQucmVkU3ViKGIpO1xuICAvLyBYMyA9IEUgKiBGXG4gIHZhciBueCA9IGUucmVkTXVsKGYpO1xuICAvLyBZMyA9IEcgKiBIXG4gIHZhciBueSA9IGcucmVkTXVsKGgpO1xuICAvLyBUMyA9IEUgKiBIXG4gIHZhciBudCA9IGUucmVkTXVsKGgpO1xuICAvLyBaMyA9IEYgKiBHXG4gIHZhciBueiA9IGYucmVkTXVsKGcpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnksIG56LCBudCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX3Byb2pEYmwgPSBmdW5jdGlvbiBfcHJvakRibCgpIHtcbiAgLy8gaHlwZXJlbGxpcHRpYy5vcmcvRUZEL2cxcC9hdXRvLXR3aXN0ZWQtcHJvamVjdGl2ZS5odG1sXG4gIC8vICAgICAjZG91YmxpbmctZGJsLTIwMDgtYmJqbHBcbiAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwNy1ibFxuICAvLyBhbmQgb3RoZXJzXG4gIC8vIEdlbmVyYWxseSAzTSArIDRTIG9yIDJNICsgNFNcblxuICAvLyBCID0gKFgxICsgWTEpXjJcbiAgdmFyIGIgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkU3FyKCk7XG4gIC8vIEMgPSBYMV4yXG4gIHZhciBjID0gdGhpcy54LnJlZFNxcigpO1xuICAvLyBEID0gWTFeMlxuICB2YXIgZCA9IHRoaXMueS5yZWRTcXIoKTtcblxuICB2YXIgbng7XG4gIHZhciBueTtcbiAgdmFyIG56O1xuICBpZiAodGhpcy5jdXJ2ZS50d2lzdGVkKSB7XG4gICAgLy8gRSA9IGEgKiBDXG4gICAgdmFyIGUgPSB0aGlzLmN1cnZlLl9tdWxBKGMpO1xuICAgIC8vIEYgPSBFICsgRFxuICAgIHZhciBmID0gZS5yZWRBZGQoZCk7XG4gICAgaWYgKHRoaXMuek9uZSkge1xuICAgICAgLy8gWDMgPSAoQiAtIEMgLSBEKSAqIChGIC0gMilcbiAgICAgIG54ID0gYi5yZWRTdWIoYykucmVkU3ViKGQpLnJlZE11bChmLnJlZFN1Yih0aGlzLmN1cnZlLnR3bykpO1xuICAgICAgLy8gWTMgPSBGICogKEUgLSBEKVxuICAgICAgbnkgPSBmLnJlZE11bChlLnJlZFN1YihkKSk7XG4gICAgICAvLyBaMyA9IEZeMiAtIDIgKiBGXG4gICAgICBueiA9IGYucmVkU3FyKCkucmVkU3ViKGYpLnJlZFN1YihmKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gSCA9IFoxXjJcbiAgICAgIHZhciBoID0gdGhpcy56LnJlZFNxcigpO1xuICAgICAgLy8gSiA9IEYgLSAyICogSFxuICAgICAgdmFyIGogPSBmLnJlZFN1YihoKS5yZWRJU3ViKGgpO1xuICAgICAgLy8gWDMgPSAoQi1DLUQpKkpcbiAgICAgIG54ID0gYi5yZWRTdWIoYykucmVkSVN1YihkKS5yZWRNdWwoaik7XG4gICAgICAvLyBZMyA9IEYgKiAoRSAtIEQpXG4gICAgICBueSA9IGYucmVkTXVsKGUucmVkU3ViKGQpKTtcbiAgICAgIC8vIFozID0gRiAqIEpcbiAgICAgIG56ID0gZi5yZWRNdWwoaik7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIC8vIEUgPSBDICsgRFxuICAgIHZhciBlID0gYy5yZWRBZGQoZCk7XG4gICAgLy8gSCA9IChjICogWjEpXjJcbiAgICB2YXIgaCA9IHRoaXMuY3VydmUuX211bEModGhpcy5jLnJlZE11bCh0aGlzLnopKS5yZWRTcXIoKTtcbiAgICAvLyBKID0gRSAtIDIgKiBIXG4gICAgdmFyIGogPSBlLnJlZFN1YihoKS5yZWRTdWIoaCk7XG4gICAgLy8gWDMgPSBjICogKEIgLSBFKSAqIEpcbiAgICBueCA9IHRoaXMuY3VydmUuX211bEMoYi5yZWRJU3ViKGUpKS5yZWRNdWwoaik7XG4gICAgLy8gWTMgPSBjICogRSAqIChDIC0gRClcbiAgICBueSA9IHRoaXMuY3VydmUuX211bEMoZSkucmVkTXVsKGMucmVkSVN1YihkKSk7XG4gICAgLy8gWjMgPSBFICogSlxuICAgIG56ID0gZS5yZWRNdWwoaik7XG4gIH1cbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobngsIG55LCBueik7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gRG91YmxlIGluIGV4dGVuZGVkIGNvb3JkaW5hdGVzXG4gIGlmICh0aGlzLmN1cnZlLmV4dGVuZGVkKVxuICAgIHJldHVybiB0aGlzLl9leHREYmwoKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLl9wcm9qRGJsKCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX2V4dEFkZCA9IGZ1bmN0aW9uIF9leHRBZGQocCkge1xuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tdHdpc3RlZC1leHRlbmRlZC0xLmh0bWxcbiAgLy8gICAgICNhZGRpdGlvbi1hZGQtMjAwOC1od2NkLTNcbiAgLy8gOE1cblxuICAvLyBBID0gKFkxIC0gWDEpICogKFkyIC0gWDIpXG4gIHZhciBhID0gdGhpcy55LnJlZFN1Yih0aGlzLngpLnJlZE11bChwLnkucmVkU3ViKHAueCkpO1xuICAvLyBCID0gKFkxICsgWDEpICogKFkyICsgWDIpXG4gIHZhciBiID0gdGhpcy55LnJlZEFkZCh0aGlzLngpLnJlZE11bChwLnkucmVkQWRkKHAueCkpO1xuICAvLyBDID0gVDEgKiBrICogVDJcbiAgdmFyIGMgPSB0aGlzLnQucmVkTXVsKHRoaXMuY3VydmUuZGQpLnJlZE11bChwLnQpO1xuICAvLyBEID0gWjEgKiAyICogWjJcbiAgdmFyIGQgPSB0aGlzLnoucmVkTXVsKHAuei5yZWRBZGQocC56KSk7XG4gIC8vIEUgPSBCIC0gQVxuICB2YXIgZSA9IGIucmVkU3ViKGEpO1xuICAvLyBGID0gRCAtIENcbiAgdmFyIGYgPSBkLnJlZFN1YihjKTtcbiAgLy8gRyA9IEQgKyBDXG4gIHZhciBnID0gZC5yZWRBZGQoYyk7XG4gIC8vIEggPSBCICsgQVxuICB2YXIgaCA9IGIucmVkQWRkKGEpO1xuICAvLyBYMyA9IEUgKiBGXG4gIHZhciBueCA9IGUucmVkTXVsKGYpO1xuICAvLyBZMyA9IEcgKiBIXG4gIHZhciBueSA9IGcucmVkTXVsKGgpO1xuICAvLyBUMyA9IEUgKiBIXG4gIHZhciBudCA9IGUucmVkTXVsKGgpO1xuICAvLyBaMyA9IEYgKiBHXG4gIHZhciBueiA9IGYucmVkTXVsKGcpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnksIG56LCBudCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX3Byb2pBZGQgPSBmdW5jdGlvbiBfcHJvakFkZChwKSB7XG4gIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by10d2lzdGVkLXByb2plY3RpdmUuaHRtbFxuICAvLyAgICAgI2FkZGl0aW9uLWFkZC0yMDA4LWJiamxwXG4gIC8vICAgICAjYWRkaXRpb24tYWRkLTIwMDctYmxcbiAgLy8gMTBNICsgMVNcblxuICAvLyBBID0gWjEgKiBaMlxuICB2YXIgYSA9IHRoaXMuei5yZWRNdWwocC56KTtcbiAgLy8gQiA9IEFeMlxuICB2YXIgYiA9IGEucmVkU3FyKCk7XG4gIC8vIEMgPSBYMSAqIFgyXG4gIHZhciBjID0gdGhpcy54LnJlZE11bChwLngpO1xuICAvLyBEID0gWTEgKiBZMlxuICB2YXIgZCA9IHRoaXMueS5yZWRNdWwocC55KTtcbiAgLy8gRSA9IGQgKiBDICogRFxuICB2YXIgZSA9IHRoaXMuY3VydmUuZC5yZWRNdWwoYykucmVkTXVsKGQpO1xuICAvLyBGID0gQiAtIEVcbiAgdmFyIGYgPSBiLnJlZFN1YihlKTtcbiAgLy8gRyA9IEIgKyBFXG4gIHZhciBnID0gYi5yZWRBZGQoZSk7XG4gIC8vIFgzID0gQSAqIEYgKiAoKFgxICsgWTEpICogKFgyICsgWTIpIC0gQyAtIEQpXG4gIHZhciB0bXAgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkTXVsKHAueC5yZWRBZGQocC55KSkucmVkSVN1YihjKS5yZWRJU3ViKGQpO1xuICB2YXIgbnggPSBhLnJlZE11bChmKS5yZWRNdWwodG1wKTtcbiAgdmFyIG55O1xuICB2YXIgbno7XG4gIGlmICh0aGlzLmN1cnZlLnR3aXN0ZWQpIHtcbiAgICAvLyBZMyA9IEEgKiBHICogKEQgLSBhICogQylcbiAgICBueSA9IGEucmVkTXVsKGcpLnJlZE11bChkLnJlZFN1Yih0aGlzLmN1cnZlLl9tdWxBKGMpKSk7XG4gICAgLy8gWjMgPSBGICogR1xuICAgIG56ID0gZi5yZWRNdWwoZyk7XG4gIH0gZWxzZSB7XG4gICAgLy8gWTMgPSBBICogRyAqIChEIC0gQylcbiAgICBueSA9IGEucmVkTXVsKGcpLnJlZE11bChkLnJlZFN1YihjKSk7XG4gICAgLy8gWjMgPSBjICogRiAqIEdcbiAgICBueiA9IHRoaXMuY3VydmUuX211bEMoZikucmVkTXVsKGcpO1xuICB9XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSwgbnopO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZChwKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gcDtcbiAgaWYgKHAuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiB0aGlzO1xuXG4gIGlmICh0aGlzLmN1cnZlLmV4dGVuZGVkKVxuICAgIHJldHVybiB0aGlzLl9leHRBZGQocCk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5fcHJvakFkZChwKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICBpZiAodGhpcy5faGFzRG91YmxlcyhrKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZml4ZWROYWZNdWwodGhpcywgayk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fd25hZk11bCh0aGlzLCBrKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWxBZGQgPSBmdW5jdGlvbiBtdWxBZGQoazEsIHAsIGsyKSB7XG4gIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsQWRkKDEsIFsgdGhpcywgcCBdLCBbIGsxLCBrMiBdLCAyKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5ub3JtYWxpemUgPSBmdW5jdGlvbiBub3JtYWxpemUoKSB7XG4gIGlmICh0aGlzLnpPbmUpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gTm9ybWFsaXplIGNvb3JkaW5hdGVzXG4gIHZhciB6aSA9IHRoaXMuei5yZWRJbnZtKCk7XG4gIHRoaXMueCA9IHRoaXMueC5yZWRNdWwoemkpO1xuICB0aGlzLnkgPSB0aGlzLnkucmVkTXVsKHppKTtcbiAgaWYgKHRoaXMudClcbiAgICB0aGlzLnQgPSB0aGlzLnQucmVkTXVsKHppKTtcbiAgdGhpcy56ID0gdGhpcy5jdXJ2ZS5vbmU7XG4gIHRoaXMuek9uZSA9IHRydWU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuUG9pbnQucHJvdG90eXBlLm5lZyA9IGZ1bmN0aW9uIG5lZygpIHtcbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQodGhpcy54LnJlZE5lZygpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnksXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMueixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy50ICYmIHRoaXMudC5yZWROZWcoKSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIHRoaXMubm9ybWFsaXplKCk7XG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmdldFkgPSBmdW5jdGlvbiBnZXRZKCkge1xuICB0aGlzLm5vcm1hbGl6ZSgpO1xuICByZXR1cm4gdGhpcy55LmZyb21SZWQoKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5lcSA9IGZ1bmN0aW9uIGVxKG90aGVyKSB7XG4gIHJldHVybiB0aGlzID09PSBvdGhlciB8fFxuICAgICAgICAgdGhpcy5nZXRYKCkuY21wKG90aGVyLmdldFgoKSkgPT09IDAgJiZcbiAgICAgICAgIHRoaXMuZ2V0WSgpLmNtcChvdGhlci5nZXRZKCkpID09PSAwO1xufTtcblxuLy8gQ29tcGF0aWJpbGl0eSB3aXRoIEJhc2VDdXJ2ZVxuUG9pbnQucHJvdG90eXBlLnRvUCA9IFBvaW50LnByb3RvdHlwZS5ub3JtYWxpemU7XG5Qb2ludC5wcm90b3R5cGUubWl4ZWRBZGQgPSBQb2ludC5wcm90b3R5cGUuYWRkO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgY3VydmUgPSBleHBvcnRzO1xuXG5jdXJ2ZS5iYXNlID0gcmVxdWlyZSgnLi9iYXNlJyk7XG5jdXJ2ZS5zaG9ydCA9IHJlcXVpcmUoJy4vc2hvcnQnKTtcbmN1cnZlLm1vbnQgPSByZXF1aXJlKCcuL21vbnQnKTtcbmN1cnZlLmVkd2FyZHMgPSByZXF1aXJlKCcuL2Vkd2FyZHMnKTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlID0gcmVxdWlyZSgnLi4vY3VydmUnKTtcbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIEJhc2UgPSBjdXJ2ZS5iYXNlO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG5cbmZ1bmN0aW9uIE1vbnRDdXJ2ZShjb25mKSB7XG4gIEJhc2UuY2FsbCh0aGlzLCAnbW9udCcsIGNvbmYpO1xuXG4gIHRoaXMuYSA9IG5ldyBCTihjb25mLmEsIDE2KS50b1JlZCh0aGlzLnJlZCk7XG4gIHRoaXMuYiA9IG5ldyBCTihjb25mLmIsIDE2KS50b1JlZCh0aGlzLnJlZCk7XG4gIHRoaXMuaTQgPSBuZXcgQk4oNCkudG9SZWQodGhpcy5yZWQpLnJlZEludm0oKTtcbiAgdGhpcy50d28gPSBuZXcgQk4oMikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLmEyNCA9IHRoaXMuaTQucmVkTXVsKHRoaXMuYS5yZWRBZGQodGhpcy50d28pKTtcbn1cbmluaGVyaXRzKE1vbnRDdXJ2ZSwgQmFzZSk7XG5tb2R1bGUuZXhwb3J0cyA9IE1vbnRDdXJ2ZTtcblxuTW9udEN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIHZhciB4ID0gcG9pbnQubm9ybWFsaXplKCkueDtcbiAgdmFyIHgyID0geC5yZWRTcXIoKTtcbiAgdmFyIHJocyA9IHgyLnJlZE11bCh4KS5yZWRBZGQoeDIucmVkTXVsKHRoaXMuYSkpLnJlZEFkZCh4KTtcbiAgdmFyIHkgPSByaHMucmVkU3FydCgpO1xuXG4gIHJldHVybiB5LnJlZFNxcigpLmNtcChyaHMpID09PSAwO1xufTtcblxuZnVuY3Rpb24gUG9pbnQoY3VydmUsIHgsIHopIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ3Byb2plY3RpdmUnKTtcbiAgaWYgKHggPT09IG51bGwgJiYgeiA9PT0gbnVsbCkge1xuICAgIHRoaXMueCA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMueiA9IHRoaXMuY3VydmUuemVybztcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnggPSBuZXcgQk4oeCwgMTYpO1xuICAgIHRoaXMueiA9IG5ldyBCTih6LCAxNik7XG4gICAgaWYgKCF0aGlzLngucmVkKVxuICAgICAgdGhpcy54ID0gdGhpcy54LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICBpZiAoIXRoaXMuei5yZWQpXG4gICAgICB0aGlzLnogPSB0aGlzLnoudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICB9XG59XG5pbmhlcml0cyhQb2ludCwgQmFzZS5CYXNlUG9pbnQpO1xuXG5Nb250Q3VydmUucHJvdG90eXBlLmRlY29kZVBvaW50ID0gZnVuY3Rpb24gZGVjb2RlUG9pbnQoYnl0ZXMsIGVuYykge1xuICByZXR1cm4gdGhpcy5wb2ludCh1dGlscy50b0FycmF5KGJ5dGVzLCBlbmMpLCAxKTtcbn07XG5cbk1vbnRDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB6KSB7XG4gIHJldHVybiBuZXcgUG9pbnQodGhpcywgeCwgeik7XG59O1xuXG5Nb250Q3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaikge1xuICByZXR1cm4gUG9pbnQuZnJvbUpTT04odGhpcywgb2JqKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5wcmVjb21wdXRlID0gZnVuY3Rpb24gcHJlY29tcHV0ZSgpIHtcbiAgLy8gTm8tb3Bcbn07XG5cblBvaW50LnByb3RvdHlwZS5fZW5jb2RlID0gZnVuY3Rpb24gX2VuY29kZSgpIHtcbiAgcmV0dXJuIHRoaXMuZ2V0WCgpLnRvQXJyYXkoJ2JlJywgdGhpcy5jdXJ2ZS5wLmJ5dGVMZW5ndGgoKSk7XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmopIHtcbiAgcmV0dXJuIG5ldyBQb2ludChjdXJ2ZSwgb2JqWzBdLCBvYmpbMV0gfHwgY3VydmUub25lKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCgpIHtcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiAnPEVDIFBvaW50IEluZmluaXR5Pic7XG4gIHJldHVybiAnPEVDIFBvaW50IHg6ICcgKyB0aGlzLnguZnJvbVJlZCgpLnRvU3RyaW5nKDE2LCAyKSArXG4gICAgICAnIHo6ICcgKyB0aGlzLnouZnJvbVJlZCgpLnRvU3RyaW5nKDE2LCAyKSArICc+Jztcbn07XG5cblBvaW50LnByb3RvdHlwZS5pc0luZmluaXR5ID0gZnVuY3Rpb24gaXNJbmZpbml0eSgpIHtcbiAgLy8gWFhYIFRoaXMgY29kZSBhc3N1bWVzIHRoYXQgemVybyBpcyBhbHdheXMgemVybyBpbiByZWRcbiAgcmV0dXJuIHRoaXMuei5jbXBuKDApID09PSAwO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmRibCA9IGZ1bmN0aW9uIGRibCgpIHtcbiAgLy8gaHR0cDovL2h5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1tb250Z29tLXh6Lmh0bWwjZG91YmxpbmctZGJsLTE5ODctbS0zXG4gIC8vIDJNICsgMlMgKyA0QVxuXG4gIC8vIEEgPSBYMSArIFoxXG4gIHZhciBhID0gdGhpcy54LnJlZEFkZCh0aGlzLnopO1xuICAvLyBBQSA9IEFeMlxuICB2YXIgYWEgPSBhLnJlZFNxcigpO1xuICAvLyBCID0gWDEgLSBaMVxuICB2YXIgYiA9IHRoaXMueC5yZWRTdWIodGhpcy56KTtcbiAgLy8gQkIgPSBCXjJcbiAgdmFyIGJiID0gYi5yZWRTcXIoKTtcbiAgLy8gQyA9IEFBIC0gQkJcbiAgdmFyIGMgPSBhYS5yZWRTdWIoYmIpO1xuICAvLyBYMyA9IEFBICogQkJcbiAgdmFyIG54ID0gYWEucmVkTXVsKGJiKTtcbiAgLy8gWjMgPSBDICogKEJCICsgQTI0ICogQylcbiAgdmFyIG56ID0gYy5yZWRNdWwoYmIucmVkQWRkKHRoaXMuY3VydmUuYTI0LnJlZE11bChjKSkpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnopO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZCgpIHtcbiAgdGhyb3cgbmV3IEVycm9yKCdOb3Qgc3VwcG9ydGVkIG9uIE1vbnRnb21lcnkgY3VydmUnKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5kaWZmQWRkID0gZnVuY3Rpb24gZGlmZkFkZChwLCBkaWZmKSB7XG4gIC8vIGh0dHA6Ly9oeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tbW9udGdvbS14ei5odG1sI2RpZmZhZGQtZGFkZC0xOTg3LW0tM1xuICAvLyA0TSArIDJTICsgNkFcblxuICAvLyBBID0gWDIgKyBaMlxuICB2YXIgYSA9IHRoaXMueC5yZWRBZGQodGhpcy56KTtcbiAgLy8gQiA9IFgyIC0gWjJcbiAgdmFyIGIgPSB0aGlzLngucmVkU3ViKHRoaXMueik7XG4gIC8vIEMgPSBYMyArIFozXG4gIHZhciBjID0gcC54LnJlZEFkZChwLnopO1xuICAvLyBEID0gWDMgLSBaM1xuICB2YXIgZCA9IHAueC5yZWRTdWIocC56KTtcbiAgLy8gREEgPSBEICogQVxuICB2YXIgZGEgPSBkLnJlZE11bChhKTtcbiAgLy8gQ0IgPSBDICogQlxuICB2YXIgY2IgPSBjLnJlZE11bChiKTtcbiAgLy8gWDUgPSBaMSAqIChEQSArIENCKV4yXG4gIHZhciBueCA9IGRpZmYuei5yZWRNdWwoZGEucmVkQWRkKGNiKS5yZWRTcXIoKSk7XG4gIC8vIFo1ID0gWDEgKiAoREEgLSBDQileMlxuICB2YXIgbnogPSBkaWZmLngucmVkTXVsKGRhLnJlZElTdWIoY2IpLnJlZFNxcigpKTtcbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobngsIG56KTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICB2YXIgdCA9IGsuY2xvbmUoKTtcbiAgdmFyIGEgPSB0aGlzOyAvLyAoTiAvIDIpICogUSArIFFcbiAgdmFyIGIgPSB0aGlzLmN1cnZlLnBvaW50KG51bGwsIG51bGwpOyAvLyAoTiAvIDIpICogUVxuICB2YXIgYyA9IHRoaXM7IC8vIFFcblxuICBmb3IgKHZhciBiaXRzID0gW107IHQuY21wbigwKSAhPT0gMDsgdC5pdXNocm4oMSkpXG4gICAgYml0cy5wdXNoKHQuYW5kbG4oMSkpO1xuXG4gIGZvciAodmFyIGkgPSBiaXRzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgaWYgKGJpdHNbaV0gPT09IDApIHtcbiAgICAgIC8vIE4gKiBRICsgUSA9ICgoTiAvIDIpICogUSArIFEpKSArIChOIC8gMikgKiBRXG4gICAgICBhID0gYS5kaWZmQWRkKGIsIGMpO1xuICAgICAgLy8gTiAqIFEgPSAyICogKChOIC8gMikgKiBRICsgUSkpXG4gICAgICBiID0gYi5kYmwoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gTiAqIFEgPSAoKE4gLyAyKSAqIFEgKyBRKSArICgoTiAvIDIpICogUSlcbiAgICAgIGIgPSBhLmRpZmZBZGQoYiwgYyk7XG4gICAgICAvLyBOICogUSArIFEgPSAyICogKChOIC8gMikgKiBRICsgUSlcbiAgICAgIGEgPSBhLmRibCgpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gYjtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWxBZGQgPSBmdW5jdGlvbiBtdWxBZGQoKSB7XG4gIHRocm93IG5ldyBFcnJvcignTm90IHN1cHBvcnRlZCBvbiBNb250Z29tZXJ5IGN1cnZlJyk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZXEgPSBmdW5jdGlvbiBlcShvdGhlcikge1xuICByZXR1cm4gdGhpcy5nZXRYKCkuY21wKG90aGVyLmdldFgoKSkgPT09IDA7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUubm9ybWFsaXplID0gZnVuY3Rpb24gbm9ybWFsaXplKCkge1xuICB0aGlzLnggPSB0aGlzLngucmVkTXVsKHRoaXMuei5yZWRJbnZtKCkpO1xuICB0aGlzLnogPSB0aGlzLmN1cnZlLm9uZTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIC8vIE5vcm1hbGl6ZSBjb29yZGluYXRlc1xuICB0aGlzLm5vcm1hbGl6ZSgpO1xuXG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlID0gcmVxdWlyZSgnLi4vY3VydmUnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgQk4gPSByZXF1aXJlKCdibi5qcycpO1xudmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcbnZhciBCYXNlID0gY3VydmUuYmFzZTtcblxudmFyIGFzc2VydCA9IGVsbGlwdGljLnV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gU2hvcnRDdXJ2ZShjb25mKSB7XG4gIEJhc2UuY2FsbCh0aGlzLCAnc2hvcnQnLCBjb25mKTtcblxuICB0aGlzLmEgPSBuZXcgQk4oY29uZi5hLCAxNikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLmIgPSBuZXcgQk4oY29uZi5iLCAxNikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLnRpbnYgPSB0aGlzLnR3by5yZWRJbnZtKCk7XG5cbiAgdGhpcy56ZXJvQSA9IHRoaXMuYS5mcm9tUmVkKCkuY21wbigwKSA9PT0gMDtcbiAgdGhpcy50aHJlZUEgPSB0aGlzLmEuZnJvbVJlZCgpLnN1Yih0aGlzLnApLmNtcG4oLTMpID09PSAwO1xuXG4gIC8vIElmIHRoZSBjdXJ2ZSBpcyBlbmRvbW9ycGhpYywgcHJlY2FsY3VsYXRlIGJldGEgYW5kIGxhbWJkYVxuICB0aGlzLmVuZG8gPSB0aGlzLl9nZXRFbmRvbW9ycGhpc20oY29uZik7XG4gIHRoaXMuX2VuZG9XbmFmVDEgPSBuZXcgQXJyYXkoNCk7XG4gIHRoaXMuX2VuZG9XbmFmVDIgPSBuZXcgQXJyYXkoNCk7XG59XG5pbmhlcml0cyhTaG9ydEN1cnZlLCBCYXNlKTtcbm1vZHVsZS5leHBvcnRzID0gU2hvcnRDdXJ2ZTtcblxuU2hvcnRDdXJ2ZS5wcm90b3R5cGUuX2dldEVuZG9tb3JwaGlzbSA9IGZ1bmN0aW9uIF9nZXRFbmRvbW9ycGhpc20oY29uZikge1xuICAvLyBObyBlZmZpY2llbnQgZW5kb21vcnBoaXNtXG4gIGlmICghdGhpcy56ZXJvQSB8fCAhdGhpcy5nIHx8ICF0aGlzLm4gfHwgdGhpcy5wLm1vZG4oMykgIT09IDEpXG4gICAgcmV0dXJuO1xuXG4gIC8vIENvbXB1dGUgYmV0YSBhbmQgbGFtYmRhLCB0aGF0IGxhbWJkYSAqIFAgPSAoYmV0YSAqIFB4OyBQeSlcbiAgdmFyIGJldGE7XG4gIHZhciBsYW1iZGE7XG4gIGlmIChjb25mLmJldGEpIHtcbiAgICBiZXRhID0gbmV3IEJOKGNvbmYuYmV0YSwgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgfSBlbHNlIHtcbiAgICB2YXIgYmV0YXMgPSB0aGlzLl9nZXRFbmRvUm9vdHModGhpcy5wKTtcbiAgICAvLyBDaG9vc2UgdGhlIHNtYWxsZXN0IGJldGFcbiAgICBiZXRhID0gYmV0YXNbMF0uY21wKGJldGFzWzFdKSA8IDAgPyBiZXRhc1swXSA6IGJldGFzWzFdO1xuICAgIGJldGEgPSBiZXRhLnRvUmVkKHRoaXMucmVkKTtcbiAgfVxuICBpZiAoY29uZi5sYW1iZGEpIHtcbiAgICBsYW1iZGEgPSBuZXcgQk4oY29uZi5sYW1iZGEsIDE2KTtcbiAgfSBlbHNlIHtcbiAgICAvLyBDaG9vc2UgdGhlIGxhbWJkYSB0aGF0IGlzIG1hdGNoaW5nIHNlbGVjdGVkIGJldGFcbiAgICB2YXIgbGFtYmRhcyA9IHRoaXMuX2dldEVuZG9Sb290cyh0aGlzLm4pO1xuICAgIGlmICh0aGlzLmcubXVsKGxhbWJkYXNbMF0pLnguY21wKHRoaXMuZy54LnJlZE11bChiZXRhKSkgPT09IDApIHtcbiAgICAgIGxhbWJkYSA9IGxhbWJkYXNbMF07XG4gICAgfSBlbHNlIHtcbiAgICAgIGxhbWJkYSA9IGxhbWJkYXNbMV07XG4gICAgICBhc3NlcnQodGhpcy5nLm11bChsYW1iZGEpLnguY21wKHRoaXMuZy54LnJlZE11bChiZXRhKSkgPT09IDApO1xuICAgIH1cbiAgfVxuXG4gIC8vIEdldCBiYXNpcyB2ZWN0b3JzLCB1c2VkIGZvciBiYWxhbmNlZCBsZW5ndGgtdHdvIHJlcHJlc2VudGF0aW9uXG4gIHZhciBiYXNpcztcbiAgaWYgKGNvbmYuYmFzaXMpIHtcbiAgICBiYXNpcyA9IGNvbmYuYmFzaXMubWFwKGZ1bmN0aW9uKHZlYykge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgYTogbmV3IEJOKHZlYy5hLCAxNiksXG4gICAgICAgIGI6IG5ldyBCTih2ZWMuYiwgMTYpXG4gICAgICB9O1xuICAgIH0pO1xuICB9IGVsc2Uge1xuICAgIGJhc2lzID0gdGhpcy5fZ2V0RW5kb0Jhc2lzKGxhbWJkYSk7XG4gIH1cblxuICByZXR1cm4ge1xuICAgIGJldGE6IGJldGEsXG4gICAgbGFtYmRhOiBsYW1iZGEsXG4gICAgYmFzaXM6IGJhc2lzXG4gIH07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZ2V0RW5kb1Jvb3RzID0gZnVuY3Rpb24gX2dldEVuZG9Sb290cyhudW0pIHtcbiAgLy8gRmluZCByb290cyBvZiBmb3IgeF4yICsgeCArIDEgaW4gRlxuICAvLyBSb290ID0gKC0xICstIFNxcnQoLTMpKSAvIDJcbiAgLy9cbiAgdmFyIHJlZCA9IG51bSA9PT0gdGhpcy5wID8gdGhpcy5yZWQgOiBCTi5tb250KG51bSk7XG4gIHZhciB0aW52ID0gbmV3IEJOKDIpLnRvUmVkKHJlZCkucmVkSW52bSgpO1xuICB2YXIgbnRpbnYgPSB0aW52LnJlZE5lZygpO1xuXG4gIHZhciBzID0gbmV3IEJOKDMpLnRvUmVkKHJlZCkucmVkTmVnKCkucmVkU3FydCgpLnJlZE11bCh0aW52KTtcblxuICB2YXIgbDEgPSBudGludi5yZWRBZGQocykuZnJvbVJlZCgpO1xuICB2YXIgbDIgPSBudGludi5yZWRTdWIocykuZnJvbVJlZCgpO1xuICByZXR1cm4gWyBsMSwgbDIgXTtcbn07XG5cblNob3J0Q3VydmUucHJvdG90eXBlLl9nZXRFbmRvQmFzaXMgPSBmdW5jdGlvbiBfZ2V0RW5kb0Jhc2lzKGxhbWJkYSkge1xuICAvLyBhcHJ4U3FydCA+PSBzcXJ0KHRoaXMubilcbiAgdmFyIGFwcnhTcXJ0ID0gdGhpcy5uLnVzaHJuKE1hdGguZmxvb3IodGhpcy5uLmJpdExlbmd0aCgpIC8gMikpO1xuXG4gIC8vIDMuNzRcbiAgLy8gUnVuIEVHQ0QsIHVudGlsIHIoTCArIDEpIDwgYXByeFNxcnRcbiAgdmFyIHUgPSBsYW1iZGE7XG4gIHZhciB2ID0gdGhpcy5uLmNsb25lKCk7XG4gIHZhciB4MSA9IG5ldyBCTigxKTtcbiAgdmFyIHkxID0gbmV3IEJOKDApO1xuICB2YXIgeDIgPSBuZXcgQk4oMCk7XG4gIHZhciB5MiA9IG5ldyBCTigxKTtcblxuICAvLyBOT1RFOiBhbGwgdmVjdG9ycyBhcmUgcm9vdHMgb2Y6IGEgKyBiICogbGFtYmRhID0gMCAobW9kIG4pXG4gIHZhciBhMDtcbiAgdmFyIGIwO1xuICAvLyBGaXJzdCB2ZWN0b3JcbiAgdmFyIGExO1xuICB2YXIgYjE7XG4gIC8vIFNlY29uZCB2ZWN0b3JcbiAgdmFyIGEyO1xuICB2YXIgYjI7XG5cbiAgdmFyIHByZXZSO1xuICB2YXIgaSA9IDA7XG4gIHZhciByO1xuICB2YXIgeDtcbiAgd2hpbGUgKHUuY21wbigwKSAhPT0gMCkge1xuICAgIHZhciBxID0gdi5kaXYodSk7XG4gICAgciA9IHYuc3ViKHEubXVsKHUpKTtcbiAgICB4ID0geDIuc3ViKHEubXVsKHgxKSk7XG4gICAgdmFyIHkgPSB5Mi5zdWIocS5tdWwoeTEpKTtcblxuICAgIGlmICghYTEgJiYgci5jbXAoYXByeFNxcnQpIDwgMCkge1xuICAgICAgYTAgPSBwcmV2Ui5uZWcoKTtcbiAgICAgIGIwID0geDE7XG4gICAgICBhMSA9IHIubmVnKCk7XG4gICAgICBiMSA9IHg7XG4gICAgfSBlbHNlIGlmIChhMSAmJiArK2kgPT09IDIpIHtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgICBwcmV2UiA9IHI7XG5cbiAgICB2ID0gdTtcbiAgICB1ID0gcjtcbiAgICB4MiA9IHgxO1xuICAgIHgxID0geDtcbiAgICB5MiA9IHkxO1xuICAgIHkxID0geTtcbiAgfVxuICBhMiA9IHIubmVnKCk7XG4gIGIyID0geDtcblxuICB2YXIgbGVuMSA9IGExLnNxcigpLmFkZChiMS5zcXIoKSk7XG4gIHZhciBsZW4yID0gYTIuc3FyKCkuYWRkKGIyLnNxcigpKTtcbiAgaWYgKGxlbjIuY21wKGxlbjEpID49IDApIHtcbiAgICBhMiA9IGEwO1xuICAgIGIyID0gYjA7XG4gIH1cblxuICAvLyBOb3JtYWxpemUgc2lnbnNcbiAgaWYgKGExLm5lZ2F0aXZlKSB7XG4gICAgYTEgPSBhMS5uZWcoKTtcbiAgICBiMSA9IGIxLm5lZygpO1xuICB9XG4gIGlmIChhMi5uZWdhdGl2ZSkge1xuICAgIGEyID0gYTIubmVnKCk7XG4gICAgYjIgPSBiMi5uZWcoKTtcbiAgfVxuXG4gIHJldHVybiBbXG4gICAgeyBhOiBhMSwgYjogYjEgfSxcbiAgICB7IGE6IGEyLCBiOiBiMiB9XG4gIF07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZW5kb1NwbGl0ID0gZnVuY3Rpb24gX2VuZG9TcGxpdChrKSB7XG4gIHZhciBiYXNpcyA9IHRoaXMuZW5kby5iYXNpcztcbiAgdmFyIHYxID0gYmFzaXNbMF07XG4gIHZhciB2MiA9IGJhc2lzWzFdO1xuXG4gIHZhciBjMSA9IHYyLmIubXVsKGspLmRpdlJvdW5kKHRoaXMubik7XG4gIHZhciBjMiA9IHYxLmIubmVnKCkubXVsKGspLmRpdlJvdW5kKHRoaXMubik7XG5cbiAgdmFyIHAxID0gYzEubXVsKHYxLmEpO1xuICB2YXIgcDIgPSBjMi5tdWwodjIuYSk7XG4gIHZhciBxMSA9IGMxLm11bCh2MS5iKTtcbiAgdmFyIHEyID0gYzIubXVsKHYyLmIpO1xuXG4gIC8vIENhbGN1bGF0ZSBhbnN3ZXJcbiAgdmFyIGsxID0gay5zdWIocDEpLnN1YihwMik7XG4gIHZhciBrMiA9IHExLmFkZChxMikubmVnKCk7XG4gIHJldHVybiB7IGsxOiBrMSwgazI6IGsyIH07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5wb2ludEZyb21YID0gZnVuY3Rpb24gcG9pbnRGcm9tWCh4LCBvZGQpIHtcbiAgeCA9IG5ldyBCTih4LCAxNik7XG4gIGlmICgheC5yZWQpXG4gICAgeCA9IHgudG9SZWQodGhpcy5yZWQpO1xuXG4gIHZhciB5MiA9IHgucmVkU3FyKCkucmVkTXVsKHgpLnJlZElBZGQoeC5yZWRNdWwodGhpcy5hKSkucmVkSUFkZCh0aGlzLmIpO1xuICB2YXIgeSA9IHkyLnJlZFNxcnQoKTtcbiAgaWYgKHkucmVkU3FyKCkucmVkU3ViKHkyKS5jbXAodGhpcy56ZXJvKSAhPT0gMClcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcG9pbnQnKTtcblxuICAvLyBYWFggSXMgdGhlcmUgYW55IHdheSB0byB0ZWxsIGlmIHRoZSBudW1iZXIgaXMgb2RkIHdpdGhvdXQgY29udmVydGluZyBpdFxuICAvLyB0byBub24tcmVkIGZvcm0/XG4gIHZhciBpc09kZCA9IHkuZnJvbVJlZCgpLmlzT2RkKCk7XG4gIGlmIChvZGQgJiYgIWlzT2RkIHx8ICFvZGQgJiYgaXNPZGQpXG4gICAgeSA9IHkucmVkTmVnKCk7XG5cbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSk7XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIGlmIChwb2ludC5pbmYpXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgdmFyIHggPSBwb2ludC54O1xuICB2YXIgeSA9IHBvaW50Lnk7XG5cbiAgdmFyIGF4ID0gdGhpcy5hLnJlZE11bCh4KTtcbiAgdmFyIHJocyA9IHgucmVkU3FyKCkucmVkTXVsKHgpLnJlZElBZGQoYXgpLnJlZElBZGQodGhpcy5iKTtcbiAgcmV0dXJuIHkucmVkU3FyKCkucmVkSVN1YihyaHMpLmNtcG4oMCkgPT09IDA7XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZW5kb1duYWZNdWxBZGQgPVxuICAgIGZ1bmN0aW9uIF9lbmRvV25hZk11bEFkZChwb2ludHMsIGNvZWZmcykge1xuICB2YXIgbnBvaW50cyA9IHRoaXMuX2VuZG9XbmFmVDE7XG4gIHZhciBuY29lZmZzID0gdGhpcy5fZW5kb1duYWZUMjtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwb2ludHMubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgc3BsaXQgPSB0aGlzLl9lbmRvU3BsaXQoY29lZmZzW2ldKTtcbiAgICB2YXIgcCA9IHBvaW50c1tpXTtcbiAgICB2YXIgYmV0YSA9IHAuX2dldEJldGEoKTtcblxuICAgIGlmIChzcGxpdC5rMS5uZWdhdGl2ZSkge1xuICAgICAgc3BsaXQuazEuaW5lZygpO1xuICAgICAgcCA9IHAubmVnKHRydWUpO1xuICAgIH1cbiAgICBpZiAoc3BsaXQuazIubmVnYXRpdmUpIHtcbiAgICAgIHNwbGl0LmsyLmluZWcoKTtcbiAgICAgIGJldGEgPSBiZXRhLm5lZyh0cnVlKTtcbiAgICB9XG5cbiAgICBucG9pbnRzW2kgKiAyXSA9IHA7XG4gICAgbnBvaW50c1tpICogMiArIDFdID0gYmV0YTtcbiAgICBuY29lZmZzW2kgKiAyXSA9IHNwbGl0LmsxO1xuICAgIG5jb2VmZnNbaSAqIDIgKyAxXSA9IHNwbGl0LmsyO1xuICB9XG4gIHZhciByZXMgPSB0aGlzLl93bmFmTXVsQWRkKDEsIG5wb2ludHMsIG5jb2VmZnMsIGkgKiAyKTtcblxuICAvLyBDbGVhbi11cCByZWZlcmVuY2VzIHRvIHBvaW50cyBhbmQgY29lZmZpY2llbnRzXG4gIGZvciAodmFyIGogPSAwOyBqIDwgaSAqIDI7IGorKykge1xuICAgIG5wb2ludHNbal0gPSBudWxsO1xuICAgIG5jb2VmZnNbal0gPSBudWxsO1xuICB9XG4gIHJldHVybiByZXM7XG59O1xuXG5mdW5jdGlvbiBQb2ludChjdXJ2ZSwgeCwgeSwgaXNSZWQpIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ2FmZmluZScpO1xuICBpZiAoeCA9PT0gbnVsbCAmJiB5ID09PSBudWxsKSB7XG4gICAgdGhpcy54ID0gbnVsbDtcbiAgICB0aGlzLnkgPSBudWxsO1xuICAgIHRoaXMuaW5mID0gdHJ1ZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnggPSBuZXcgQk4oeCwgMTYpO1xuICAgIHRoaXMueSA9IG5ldyBCTih5LCAxNik7XG4gICAgLy8gRm9yY2UgcmVkZ29tZXJ5IHJlcHJlc2VudGF0aW9uIHdoZW4gbG9hZGluZyBmcm9tIEpTT05cbiAgICBpZiAoaXNSZWQpIHtcbiAgICAgIHRoaXMueC5mb3JjZVJlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgICB0aGlzLnkuZm9yY2VSZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIH1cbiAgICBpZiAoIXRoaXMueC5yZWQpXG4gICAgICB0aGlzLnggPSB0aGlzLngudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIGlmICghdGhpcy55LnJlZClcbiAgICAgIHRoaXMueSA9IHRoaXMueS50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgdGhpcy5pbmYgPSBmYWxzZTtcbiAgfVxufVxuaW5oZXJpdHMoUG9pbnQsIEJhc2UuQmFzZVBvaW50KTtcblxuU2hvcnRDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB5LCBpc1JlZCkge1xuICByZXR1cm4gbmV3IFBvaW50KHRoaXMsIHgsIHksIGlzUmVkKTtcbn07XG5cblNob3J0Q3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaiwgcmVkKSB7XG4gIHJldHVybiBQb2ludC5mcm9tSlNPTih0aGlzLCBvYmosIHJlZCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX2dldEJldGEgPSBmdW5jdGlvbiBfZ2V0QmV0YSgpIHtcbiAgaWYgKCF0aGlzLmN1cnZlLmVuZG8pXG4gICAgcmV0dXJuO1xuXG4gIHZhciBwcmUgPSB0aGlzLnByZWNvbXB1dGVkO1xuICBpZiAocHJlICYmIHByZS5iZXRhKVxuICAgIHJldHVybiBwcmUuYmV0YTtcblxuICB2YXIgYmV0YSA9IHRoaXMuY3VydmUucG9pbnQodGhpcy54LnJlZE11bCh0aGlzLmN1cnZlLmVuZG8uYmV0YSksIHRoaXMueSk7XG4gIGlmIChwcmUpIHtcbiAgICB2YXIgY3VydmUgPSB0aGlzLmN1cnZlO1xuICAgIHZhciBlbmRvTXVsID0gZnVuY3Rpb24ocCkge1xuICAgICAgcmV0dXJuIGN1cnZlLnBvaW50KHAueC5yZWRNdWwoY3VydmUuZW5kby5iZXRhKSwgcC55KTtcbiAgICB9O1xuICAgIHByZS5iZXRhID0gYmV0YTtcbiAgICBiZXRhLnByZWNvbXB1dGVkID0ge1xuICAgICAgYmV0YTogbnVsbCxcbiAgICAgIG5hZjogcHJlLm5hZiAmJiB7XG4gICAgICAgIHduZDogcHJlLm5hZi53bmQsXG4gICAgICAgIHBvaW50czogcHJlLm5hZi5wb2ludHMubWFwKGVuZG9NdWwpXG4gICAgICB9LFxuICAgICAgZG91YmxlczogcHJlLmRvdWJsZXMgJiYge1xuICAgICAgICBzdGVwOiBwcmUuZG91Ymxlcy5zdGVwLFxuICAgICAgICBwb2ludHM6IHByZS5kb3VibGVzLnBvaW50cy5tYXAoZW5kb011bClcbiAgICAgIH1cbiAgICB9O1xuICB9XG4gIHJldHVybiBiZXRhO1xufTtcblxuUG9pbnQucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uIHRvSlNPTigpIHtcbiAgaWYgKCF0aGlzLnByZWNvbXB1dGVkKVxuICAgIHJldHVybiBbIHRoaXMueCwgdGhpcy55IF07XG5cbiAgcmV0dXJuIFsgdGhpcy54LCB0aGlzLnksIHRoaXMucHJlY29tcHV0ZWQgJiYge1xuICAgIGRvdWJsZXM6IHRoaXMucHJlY29tcHV0ZWQuZG91YmxlcyAmJiB7XG4gICAgICBzdGVwOiB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXMuc3RlcCxcbiAgICAgIHBvaW50czogdGhpcy5wcmVjb21wdXRlZC5kb3VibGVzLnBvaW50cy5zbGljZSgxKVxuICAgIH0sXG4gICAgbmFmOiB0aGlzLnByZWNvbXB1dGVkLm5hZiAmJiB7XG4gICAgICB3bmQ6IHRoaXMucHJlY29tcHV0ZWQubmFmLnduZCxcbiAgICAgIHBvaW50czogdGhpcy5wcmVjb21wdXRlZC5uYWYucG9pbnRzLnNsaWNlKDEpXG4gICAgfVxuICB9IF07XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmosIHJlZCkge1xuICBpZiAodHlwZW9mIG9iaiA9PT0gJ3N0cmluZycpXG4gICAgb2JqID0gSlNPTi5wYXJzZShvYmopO1xuICB2YXIgcmVzID0gY3VydmUucG9pbnQob2JqWzBdLCBvYmpbMV0sIHJlZCk7XG4gIGlmICghb2JqWzJdKVxuICAgIHJldHVybiByZXM7XG5cbiAgZnVuY3Rpb24gb2JqMnBvaW50KG9iaikge1xuICAgIHJldHVybiBjdXJ2ZS5wb2ludChvYmpbMF0sIG9ialsxXSwgcmVkKTtcbiAgfVxuXG4gIHZhciBwcmUgPSBvYmpbMl07XG4gIHJlcy5wcmVjb21wdXRlZCA9IHtcbiAgICBiZXRhOiBudWxsLFxuICAgIGRvdWJsZXM6IHByZS5kb3VibGVzICYmIHtcbiAgICAgIHN0ZXA6IHByZS5kb3VibGVzLnN0ZXAsXG4gICAgICBwb2ludHM6IFsgcmVzIF0uY29uY2F0KHByZS5kb3VibGVzLnBvaW50cy5tYXAob2JqMnBvaW50KSlcbiAgICB9LFxuICAgIG5hZjogcHJlLm5hZiAmJiB7XG4gICAgICB3bmQ6IHByZS5uYWYud25kLFxuICAgICAgcG9pbnRzOiBbIHJlcyBdLmNvbmNhdChwcmUubmFmLnBvaW50cy5tYXAob2JqMnBvaW50KSlcbiAgICB9XG4gIH07XG4gIHJldHVybiByZXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaW5zcGVjdCA9IGZ1bmN0aW9uIGluc3BlY3QoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gJzxFQyBQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBQb2ludCB4OiAnICsgdGhpcy54LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgKyAnPic7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaXNJbmZpbml0eSA9IGZ1bmN0aW9uIGlzSW5maW5pdHkoKSB7XG4gIHJldHVybiB0aGlzLmluZjtcbn07XG5cblBvaW50LnByb3RvdHlwZS5hZGQgPSBmdW5jdGlvbiBhZGQocCkge1xuICAvLyBPICsgUCA9IFBcbiAgaWYgKHRoaXMuaW5mKVxuICAgIHJldHVybiBwO1xuXG4gIC8vIFAgKyBPID0gUFxuICBpZiAocC5pbmYpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gUCArIFAgPSAyUFxuICBpZiAodGhpcy5lcShwKSlcbiAgICByZXR1cm4gdGhpcy5kYmwoKTtcblxuICAvLyBQICsgKC1QKSA9IE9cbiAgaWYgKHRoaXMubmVnKCkuZXEocCkpXG4gICAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobnVsbCwgbnVsbCk7XG5cbiAgLy8gUCArIFEgPSBPXG4gIGlmICh0aGlzLnguY21wKHAueCkgPT09IDApXG4gICAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobnVsbCwgbnVsbCk7XG5cbiAgdmFyIGMgPSB0aGlzLnkucmVkU3ViKHAueSk7XG4gIGlmIChjLmNtcG4oMCkgIT09IDApXG4gICAgYyA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIocC54KS5yZWRJbnZtKCkpO1xuICB2YXIgbnggPSBjLnJlZFNxcigpLnJlZElTdWIodGhpcy54KS5yZWRJU3ViKHAueCk7XG4gIHZhciBueSA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIobngpKS5yZWRJU3ViKHRoaXMueSk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pbmYpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gMlAgPSBPXG4gIHZhciB5czEgPSB0aGlzLnkucmVkQWRkKHRoaXMueSk7XG4gIGlmICh5czEuY21wbigwKSA9PT0gMClcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChudWxsLCBudWxsKTtcblxuICB2YXIgYSA9IHRoaXMuY3VydmUuYTtcblxuICB2YXIgeDIgPSB0aGlzLngucmVkU3FyKCk7XG4gIHZhciBkeWludiA9IHlzMS5yZWRJbnZtKCk7XG4gIHZhciBjID0geDIucmVkQWRkKHgyKS5yZWRJQWRkKHgyKS5yZWRJQWRkKGEpLnJlZE11bChkeWludik7XG5cbiAgdmFyIG54ID0gYy5yZWRTcXIoKS5yZWRJU3ViKHRoaXMueC5yZWRBZGQodGhpcy54KSk7XG4gIHZhciBueSA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIobngpKS5yZWRJU3ViKHRoaXMueSk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmdldFkgPSBmdW5jdGlvbiBnZXRZKCkge1xuICByZXR1cm4gdGhpcy55LmZyb21SZWQoKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICBrID0gbmV3IEJOKGssIDE2KTtcblxuICBpZiAodGhpcy5faGFzRG91YmxlcyhrKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZml4ZWROYWZNdWwodGhpcywgayk7XG4gIGVsc2UgaWYgKHRoaXMuY3VydmUuZW5kbylcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZW5kb1duYWZNdWxBZGQoWyB0aGlzIF0sIFsgayBdKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsKHRoaXMsIGspO1xufTtcblxuUG9pbnQucHJvdG90eXBlLm11bEFkZCA9IGZ1bmN0aW9uIG11bEFkZChrMSwgcDIsIGsyKSB7XG4gIHZhciBwb2ludHMgPSBbIHRoaXMsIHAyIF07XG4gIHZhciBjb2VmZnMgPSBbIGsxLCBrMiBdO1xuICBpZiAodGhpcy5jdXJ2ZS5lbmRvKVxuICAgIHJldHVybiB0aGlzLmN1cnZlLl9lbmRvV25hZk11bEFkZChwb2ludHMsIGNvZWZmcyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fd25hZk11bEFkZCgxLCBwb2ludHMsIGNvZWZmcywgMik7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZXEgPSBmdW5jdGlvbiBlcShwKSB7XG4gIHJldHVybiB0aGlzID09PSBwIHx8XG4gICAgICAgICB0aGlzLmluZiA9PT0gcC5pbmYgJiZcbiAgICAgICAgICAgICAodGhpcy5pbmYgfHwgdGhpcy54LmNtcChwLngpID09PSAwICYmIHRoaXMueS5jbXAocC55KSA9PT0gMCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUubmVnID0gZnVuY3Rpb24gbmVnKF9wcmVjb21wdXRlKSB7XG4gIGlmICh0aGlzLmluZilcbiAgICByZXR1cm4gdGhpcztcblxuICB2YXIgcmVzID0gdGhpcy5jdXJ2ZS5wb2ludCh0aGlzLngsIHRoaXMueS5yZWROZWcoKSk7XG4gIGlmIChfcHJlY29tcHV0ZSAmJiB0aGlzLnByZWNvbXB1dGVkKSB7XG4gICAgdmFyIHByZSA9IHRoaXMucHJlY29tcHV0ZWQ7XG4gICAgdmFyIG5lZ2F0ZSA9IGZ1bmN0aW9uKHApIHtcbiAgICAgIHJldHVybiBwLm5lZygpO1xuICAgIH07XG4gICAgcmVzLnByZWNvbXB1dGVkID0ge1xuICAgICAgbmFmOiBwcmUubmFmICYmIHtcbiAgICAgICAgd25kOiBwcmUubmFmLnduZCxcbiAgICAgICAgcG9pbnRzOiBwcmUubmFmLnBvaW50cy5tYXAobmVnYXRlKVxuICAgICAgfSxcbiAgICAgIGRvdWJsZXM6IHByZS5kb3VibGVzICYmIHtcbiAgICAgICAgc3RlcDogcHJlLmRvdWJsZXMuc3RlcCxcbiAgICAgICAgcG9pbnRzOiBwcmUuZG91Ymxlcy5wb2ludHMubWFwKG5lZ2F0ZSlcbiAgICAgIH1cbiAgICB9O1xuICB9XG4gIHJldHVybiByZXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUudG9KID0gZnVuY3Rpb24gdG9KKCkge1xuICBpZiAodGhpcy5pbmYpXG4gICAgcmV0dXJuIHRoaXMuY3VydmUuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuXG4gIHZhciByZXMgPSB0aGlzLmN1cnZlLmpwb2ludCh0aGlzLngsIHRoaXMueSwgdGhpcy5jdXJ2ZS5vbmUpO1xuICByZXR1cm4gcmVzO1xufTtcblxuZnVuY3Rpb24gSlBvaW50KGN1cnZlLCB4LCB5LCB6KSB7XG4gIEJhc2UuQmFzZVBvaW50LmNhbGwodGhpcywgY3VydmUsICdqYWNvYmlhbicpO1xuICBpZiAoeCA9PT0gbnVsbCAmJiB5ID09PSBudWxsICYmIHogPT09IG51bGwpIHtcbiAgICB0aGlzLnggPSB0aGlzLmN1cnZlLm9uZTtcbiAgICB0aGlzLnkgPSB0aGlzLmN1cnZlLm9uZTtcbiAgICB0aGlzLnogPSBuZXcgQk4oMCk7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy54ID0gbmV3IEJOKHgsIDE2KTtcbiAgICB0aGlzLnkgPSBuZXcgQk4oeSwgMTYpO1xuICAgIHRoaXMueiA9IG5ldyBCTih6LCAxNik7XG4gIH1cbiAgaWYgKCF0aGlzLngucmVkKVxuICAgIHRoaXMueCA9IHRoaXMueC50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gIGlmICghdGhpcy55LnJlZClcbiAgICB0aGlzLnkgPSB0aGlzLnkudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICBpZiAoIXRoaXMuei5yZWQpXG4gICAgdGhpcy56ID0gdGhpcy56LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcblxuICB0aGlzLnpPbmUgPSB0aGlzLnogPT09IHRoaXMuY3VydmUub25lO1xufVxuaW5oZXJpdHMoSlBvaW50LCBCYXNlLkJhc2VQb2ludCk7XG5cblNob3J0Q3VydmUucHJvdG90eXBlLmpwb2ludCA9IGZ1bmN0aW9uIGpwb2ludCh4LCB5LCB6KSB7XG4gIHJldHVybiBuZXcgSlBvaW50KHRoaXMsIHgsIHksIHopO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS50b1AgPSBmdW5jdGlvbiB0b1AoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChudWxsLCBudWxsKTtcblxuICB2YXIgemludiA9IHRoaXMuei5yZWRJbnZtKCk7XG4gIHZhciB6aW52MiA9IHppbnYucmVkU3FyKCk7XG4gIHZhciBheCA9IHRoaXMueC5yZWRNdWwoemludjIpO1xuICB2YXIgYXkgPSB0aGlzLnkucmVkTXVsKHppbnYyKS5yZWRNdWwoemludik7XG5cbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQoYXgsIGF5KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUubmVnID0gZnVuY3Rpb24gbmVnKCkge1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQodGhpcy54LCB0aGlzLnkucmVkTmVnKCksIHRoaXMueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZChwKSB7XG4gIC8vIE8gKyBQID0gUFxuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHA7XG5cbiAgLy8gUCArIE8gPSBQXG4gIGlmIChwLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gdGhpcztcblxuICAvLyAxMk0gKyA0UyArIDdBXG4gIHZhciBwejIgPSBwLnoucmVkU3FyKCk7XG4gIHZhciB6MiA9IHRoaXMuei5yZWRTcXIoKTtcbiAgdmFyIHUxID0gdGhpcy54LnJlZE11bChwejIpO1xuICB2YXIgdTIgPSBwLngucmVkTXVsKHoyKTtcbiAgdmFyIHMxID0gdGhpcy55LnJlZE11bChwejIucmVkTXVsKHAueikpO1xuICB2YXIgczIgPSBwLnkucmVkTXVsKHoyLnJlZE11bCh0aGlzLnopKTtcblxuICB2YXIgaCA9IHUxLnJlZFN1Yih1Mik7XG4gIHZhciByID0gczEucmVkU3ViKHMyKTtcbiAgaWYgKGguY21wbigwKSA9PT0gMCkge1xuICAgIGlmIChyLmNtcG4oMCkgIT09IDApXG4gICAgICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIHRoaXMuZGJsKCk7XG4gIH1cblxuICB2YXIgaDIgPSBoLnJlZFNxcigpO1xuICB2YXIgaDMgPSBoMi5yZWRNdWwoaCk7XG4gIHZhciB2ID0gdTEucmVkTXVsKGgyKTtcblxuICB2YXIgbnggPSByLnJlZFNxcigpLnJlZElBZGQoaDMpLnJlZElTdWIodikucmVkSVN1Yih2KTtcbiAgdmFyIG55ID0gci5yZWRNdWwodi5yZWRJU3ViKG54KSkucmVkSVN1YihzMS5yZWRNdWwoaDMpKTtcbiAgdmFyIG56ID0gdGhpcy56LnJlZE11bChwLnopLnJlZE11bChoKTtcblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLm1peGVkQWRkID0gZnVuY3Rpb24gbWl4ZWRBZGQocCkge1xuICAvLyBPICsgUCA9IFBcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiBwLnRvSigpO1xuXG4gIC8vIFAgKyBPID0gUFxuICBpZiAocC5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gOE0gKyAzUyArIDdBXG4gIHZhciB6MiA9IHRoaXMuei5yZWRTcXIoKTtcbiAgdmFyIHUxID0gdGhpcy54O1xuICB2YXIgdTIgPSBwLngucmVkTXVsKHoyKTtcbiAgdmFyIHMxID0gdGhpcy55O1xuICB2YXIgczIgPSBwLnkucmVkTXVsKHoyKS5yZWRNdWwodGhpcy56KTtcblxuICB2YXIgaCA9IHUxLnJlZFN1Yih1Mik7XG4gIHZhciByID0gczEucmVkU3ViKHMyKTtcbiAgaWYgKGguY21wbigwKSA9PT0gMCkge1xuICAgIGlmIChyLmNtcG4oMCkgIT09IDApXG4gICAgICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIHRoaXMuZGJsKCk7XG4gIH1cblxuICB2YXIgaDIgPSBoLnJlZFNxcigpO1xuICB2YXIgaDMgPSBoMi5yZWRNdWwoaCk7XG4gIHZhciB2ID0gdTEucmVkTXVsKGgyKTtcblxuICB2YXIgbnggPSByLnJlZFNxcigpLnJlZElBZGQoaDMpLnJlZElTdWIodikucmVkSVN1Yih2KTtcbiAgdmFyIG55ID0gci5yZWRNdWwodi5yZWRJU3ViKG54KSkucmVkSVN1YihzMS5yZWRNdWwoaDMpKTtcbiAgdmFyIG56ID0gdGhpcy56LnJlZE11bChoKTtcblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLmRibHAgPSBmdW5jdGlvbiBkYmxwKHBvdykge1xuICBpZiAocG93ID09PSAwKVxuICAgIHJldHVybiB0aGlzO1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG4gIGlmICghcG93KVxuICAgIHJldHVybiB0aGlzLmRibCgpO1xuXG4gIGlmICh0aGlzLmN1cnZlLnplcm9BIHx8IHRoaXMuY3VydmUudGhyZWVBKSB7XG4gICAgdmFyIHIgPSB0aGlzO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcG93OyBpKyspXG4gICAgICByID0gci5kYmwoKTtcbiAgICByZXR1cm4gcjtcbiAgfVxuXG4gIC8vIDFNICsgMlMgKyAxQSArIE4gKiAoNFMgKyA1TSArIDhBKVxuICAvLyBOID0gMSA9PiA2TSArIDZTICsgOUFcbiAgdmFyIGEgPSB0aGlzLmN1cnZlLmE7XG4gIHZhciB0aW52ID0gdGhpcy5jdXJ2ZS50aW52O1xuXG4gIHZhciBqeCA9IHRoaXMueDtcbiAgdmFyIGp5ID0gdGhpcy55O1xuICB2YXIganogPSB0aGlzLno7XG4gIHZhciBqejQgPSBqei5yZWRTcXIoKS5yZWRTcXIoKTtcblxuICAvLyBSZXVzZSByZXN1bHRzXG4gIHZhciBqeWQgPSBqeS5yZWRBZGQoankpO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHBvdzsgaSsrKSB7XG4gICAgdmFyIGp4MiA9IGp4LnJlZFNxcigpO1xuICAgIHZhciBqeWQyID0ganlkLnJlZFNxcigpO1xuICAgIHZhciBqeWQ0ID0ganlkMi5yZWRTcXIoKTtcbiAgICB2YXIgYyA9IGp4Mi5yZWRBZGQoangyKS5yZWRJQWRkKGp4MikucmVkSUFkZChhLnJlZE11bChqejQpKTtcblxuICAgIHZhciB0MSA9IGp4LnJlZE11bChqeWQyKTtcbiAgICB2YXIgbnggPSBjLnJlZFNxcigpLnJlZElTdWIodDEucmVkQWRkKHQxKSk7XG4gICAgdmFyIHQyID0gdDEucmVkSVN1YihueCk7XG4gICAgdmFyIGRueSA9IGMucmVkTXVsKHQyKTtcbiAgICBkbnkgPSBkbnkucmVkSUFkZChkbnkpLnJlZElTdWIoanlkNCk7XG4gICAgdmFyIG56ID0ganlkLnJlZE11bChqeik7XG4gICAgaWYgKGkgKyAxIDwgcG93KVxuICAgICAgano0ID0gano0LnJlZE11bChqeWQ0KTtcblxuICAgIGp4ID0gbng7XG4gICAganogPSBuejtcbiAgICBqeWQgPSBkbnk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQoangsIGp5ZC5yZWRNdWwodGludiksIGp6KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgaWYgKHRoaXMuY3VydmUuemVyb0EpXG4gICAgcmV0dXJuIHRoaXMuX3plcm9EYmwoKTtcbiAgZWxzZSBpZiAodGhpcy5jdXJ2ZS50aHJlZUEpXG4gICAgcmV0dXJuIHRoaXMuX3RocmVlRGJsKCk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5fZGJsKCk7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLl96ZXJvRGJsID0gZnVuY3Rpb24gX3plcm9EYmwoKSB7XG4gIHZhciBueDtcbiAgdmFyIG55O1xuICB2YXIgbno7XG4gIC8vIFogPSAxXG4gIGlmICh0aGlzLnpPbmUpIHtcbiAgICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tc2hvcnR3LWphY29iaWFuLTAuaHRtbFxuICAgIC8vICAgICAjZG91YmxpbmctbWRibC0yMDA3LWJsXG4gICAgLy8gMU0gKyA1UyArIDE0QVxuXG4gICAgLy8gWFggPSBYMV4yXG4gICAgdmFyIHh4ID0gdGhpcy54LnJlZFNxcigpO1xuICAgIC8vIFlZID0gWTFeMlxuICAgIHZhciB5eSA9IHRoaXMueS5yZWRTcXIoKTtcbiAgICAvLyBZWVlZID0gWVleMlxuICAgIHZhciB5eXl5ID0geXkucmVkU3FyKCk7XG4gICAgLy8gUyA9IDIgKiAoKFgxICsgWVkpXjIgLSBYWCAtIFlZWVkpXG4gICAgdmFyIHMgPSB0aGlzLngucmVkQWRkKHl5KS5yZWRTcXIoKS5yZWRJU3ViKHh4KS5yZWRJU3ViKHl5eXkpO1xuICAgIHMgPSBzLnJlZElBZGQocyk7XG4gICAgLy8gTSA9IDMgKiBYWCArIGE7IGEgPSAwXG4gICAgdmFyIG0gPSB4eC5yZWRBZGQoeHgpLnJlZElBZGQoeHgpO1xuICAgIC8vIFQgPSBNIF4gMiAtIDIqU1xuICAgIHZhciB0ID0gbS5yZWRTcXIoKS5yZWRJU3ViKHMpLnJlZElTdWIocyk7XG5cbiAgICAvLyA4ICogWVlZWVxuICAgIHZhciB5eXl5OCA9IHl5eXkucmVkSUFkZCh5eXl5KTtcbiAgICB5eXl5OCA9IHl5eXk4LnJlZElBZGQoeXl5eTgpO1xuICAgIHl5eXk4ID0geXl5eTgucmVkSUFkZCh5eXl5OCk7XG5cbiAgICAvLyBYMyA9IFRcbiAgICBueCA9IHQ7XG4gICAgLy8gWTMgPSBNICogKFMgLSBUKSAtIDggKiBZWVlZXG4gICAgbnkgPSBtLnJlZE11bChzLnJlZElTdWIodCkpLnJlZElTdWIoeXl5eTgpO1xuICAgIC8vIFozID0gMipZMVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnkpO1xuICB9IGVsc2Uge1xuICAgIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1zaG9ydHctamFjb2JpYW4tMC5odG1sXG4gICAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwOS1sXG4gICAgLy8gMk0gKyA1UyArIDEzQVxuXG4gICAgLy8gQSA9IFgxXjJcbiAgICB2YXIgYSA9IHRoaXMueC5yZWRTcXIoKTtcbiAgICAvLyBCID0gWTFeMlxuICAgIHZhciBiID0gdGhpcy55LnJlZFNxcigpO1xuICAgIC8vIEMgPSBCXjJcbiAgICB2YXIgYyA9IGIucmVkU3FyKCk7XG4gICAgLy8gRCA9IDIgKiAoKFgxICsgQileMiAtIEEgLSBDKVxuICAgIHZhciBkID0gdGhpcy54LnJlZEFkZChiKS5yZWRTcXIoKS5yZWRJU3ViKGEpLnJlZElTdWIoYyk7XG4gICAgZCA9IGQucmVkSUFkZChkKTtcbiAgICAvLyBFID0gMyAqIEFcbiAgICB2YXIgZSA9IGEucmVkQWRkKGEpLnJlZElBZGQoYSk7XG4gICAgLy8gRiA9IEVeMlxuICAgIHZhciBmID0gZS5yZWRTcXIoKTtcblxuICAgIC8vIDggKiBDXG4gICAgdmFyIGM4ID0gYy5yZWRJQWRkKGMpO1xuICAgIGM4ID0gYzgucmVkSUFkZChjOCk7XG4gICAgYzggPSBjOC5yZWRJQWRkKGM4KTtcblxuICAgIC8vIFgzID0gRiAtIDIgKiBEXG4gICAgbnggPSBmLnJlZElTdWIoZCkucmVkSVN1YihkKTtcbiAgICAvLyBZMyA9IEUgKiAoRCAtIFgzKSAtIDggKiBDXG4gICAgbnkgPSBlLnJlZE11bChkLnJlZElTdWIobngpKS5yZWRJU3ViKGM4KTtcbiAgICAvLyBaMyA9IDIgKiBZMSAqIFoxXG4gICAgbnogPSB0aGlzLnkucmVkTXVsKHRoaXMueik7XG4gICAgbnogPSBuei5yZWRJQWRkKG56KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLmN1cnZlLmpwb2ludChueCwgbnksIG56KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUuX3RocmVlRGJsID0gZnVuY3Rpb24gX3RocmVlRGJsKCkge1xuICB2YXIgbng7XG4gIHZhciBueTtcbiAgdmFyIG56O1xuICAvLyBaID0gMVxuICBpZiAodGhpcy56T25lKSB7XG4gICAgLy8gaHlwZXJlbGxpcHRpYy5vcmcvRUZEL2cxcC9hdXRvLXNob3J0dy1qYWNvYmlhbi0zLmh0bWxcbiAgICAvLyAgICAgI2RvdWJsaW5nLW1kYmwtMjAwNy1ibFxuICAgIC8vIDFNICsgNVMgKyAxNUFcblxuICAgIC8vIFhYID0gWDFeMlxuICAgIHZhciB4eCA9IHRoaXMueC5yZWRTcXIoKTtcbiAgICAvLyBZWSA9IFkxXjJcbiAgICB2YXIgeXkgPSB0aGlzLnkucmVkU3FyKCk7XG4gICAgLy8gWVlZWSA9IFlZXjJcbiAgICB2YXIgeXl5eSA9IHl5LnJlZFNxcigpO1xuICAgIC8vIFMgPSAyICogKChYMSArIFlZKV4yIC0gWFggLSBZWVlZKVxuICAgIHZhciBzID0gdGhpcy54LnJlZEFkZCh5eSkucmVkU3FyKCkucmVkSVN1Yih4eCkucmVkSVN1Yih5eXl5KTtcbiAgICBzID0gcy5yZWRJQWRkKHMpO1xuICAgIC8vIE0gPSAzICogWFggKyBhXG4gICAgdmFyIG0gPSB4eC5yZWRBZGQoeHgpLnJlZElBZGQoeHgpLnJlZElBZGQodGhpcy5jdXJ2ZS5hKTtcbiAgICAvLyBUID0gTV4yIC0gMiAqIFNcbiAgICB2YXIgdCA9IG0ucmVkU3FyKCkucmVkSVN1YihzKS5yZWRJU3ViKHMpO1xuICAgIC8vIFgzID0gVFxuICAgIG54ID0gdDtcbiAgICAvLyBZMyA9IE0gKiAoUyAtIFQpIC0gOCAqIFlZWVlcbiAgICB2YXIgeXl5eTggPSB5eXl5LnJlZElBZGQoeXl5eSk7XG4gICAgeXl5eTggPSB5eXl5OC5yZWRJQWRkKHl5eXk4KTtcbiAgICB5eXl5OCA9IHl5eXk4LnJlZElBZGQoeXl5eTgpO1xuICAgIG55ID0gbS5yZWRNdWwocy5yZWRJU3ViKHQpKS5yZWRJU3ViKHl5eXk4KTtcbiAgICAvLyBaMyA9IDIgKiBZMVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnkpO1xuICB9IGVsc2Uge1xuICAgIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1zaG9ydHctamFjb2JpYW4tMy5odG1sI2RvdWJsaW5nLWRibC0yMDAxLWJcbiAgICAvLyAzTSArIDVTXG5cbiAgICAvLyBkZWx0YSA9IFoxXjJcbiAgICB2YXIgZGVsdGEgPSB0aGlzLnoucmVkU3FyKCk7XG4gICAgLy8gZ2FtbWEgPSBZMV4yXG4gICAgdmFyIGdhbW1hID0gdGhpcy55LnJlZFNxcigpO1xuICAgIC8vIGJldGEgPSBYMSAqIGdhbW1hXG4gICAgdmFyIGJldGEgPSB0aGlzLngucmVkTXVsKGdhbW1hKTtcbiAgICAvLyBhbHBoYSA9IDMgKiAoWDEgLSBkZWx0YSkgKiAoWDEgKyBkZWx0YSlcbiAgICB2YXIgYWxwaGEgPSB0aGlzLngucmVkU3ViKGRlbHRhKS5yZWRNdWwodGhpcy54LnJlZEFkZChkZWx0YSkpO1xuICAgIGFscGhhID0gYWxwaGEucmVkQWRkKGFscGhhKS5yZWRJQWRkKGFscGhhKTtcbiAgICAvLyBYMyA9IGFscGhhXjIgLSA4ICogYmV0YVxuICAgIHZhciBiZXRhNCA9IGJldGEucmVkSUFkZChiZXRhKTtcbiAgICBiZXRhNCA9IGJldGE0LnJlZElBZGQoYmV0YTQpO1xuICAgIHZhciBiZXRhOCA9IGJldGE0LnJlZEFkZChiZXRhNCk7XG4gICAgbnggPSBhbHBoYS5yZWRTcXIoKS5yZWRJU3ViKGJldGE4KTtcbiAgICAvLyBaMyA9IChZMSArIFoxKV4yIC0gZ2FtbWEgLSBkZWx0YVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnopLnJlZFNxcigpLnJlZElTdWIoZ2FtbWEpLnJlZElTdWIoZGVsdGEpO1xuICAgIC8vIFkzID0gYWxwaGEgKiAoNCAqIGJldGEgLSBYMykgLSA4ICogZ2FtbWFeMlxuICAgIHZhciBnZ2FtbWE4ID0gZ2FtbWEucmVkU3FyKCk7XG4gICAgZ2dhbW1hOCA9IGdnYW1tYTgucmVkSUFkZChnZ2FtbWE4KTtcbiAgICBnZ2FtbWE4ID0gZ2dhbW1hOC5yZWRJQWRkKGdnYW1tYTgpO1xuICAgIGdnYW1tYTggPSBnZ2FtbWE4LnJlZElBZGQoZ2dhbW1hOCk7XG4gICAgbnkgPSBhbHBoYS5yZWRNdWwoYmV0YTQucmVkSVN1YihueCkpLnJlZElTdWIoZ2dhbW1hOCk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLl9kYmwgPSBmdW5jdGlvbiBfZGJsKCkge1xuICB2YXIgYSA9IHRoaXMuY3VydmUuYTtcblxuICAvLyA0TSArIDZTICsgMTBBXG4gIHZhciBqeCA9IHRoaXMueDtcbiAgdmFyIGp5ID0gdGhpcy55O1xuICB2YXIganogPSB0aGlzLno7XG4gIHZhciBqejQgPSBqei5yZWRTcXIoKS5yZWRTcXIoKTtcblxuICB2YXIgangyID0gangucmVkU3FyKCk7XG4gIHZhciBqeTIgPSBqeS5yZWRTcXIoKTtcblxuICB2YXIgYyA9IGp4Mi5yZWRBZGQoangyKS5yZWRJQWRkKGp4MikucmVkSUFkZChhLnJlZE11bChqejQpKTtcblxuICB2YXIganhkNCA9IGp4LnJlZEFkZChqeCk7XG4gIGp4ZDQgPSBqeGQ0LnJlZElBZGQoanhkNCk7XG4gIHZhciB0MSA9IGp4ZDQucmVkTXVsKGp5Mik7XG4gIHZhciBueCA9IGMucmVkU3FyKCkucmVkSVN1Yih0MS5yZWRBZGQodDEpKTtcbiAgdmFyIHQyID0gdDEucmVkSVN1YihueCk7XG5cbiAgdmFyIGp5ZDggPSBqeTIucmVkU3FyKCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIHZhciBueSA9IGMucmVkTXVsKHQyKS5yZWRJU3ViKGp5ZDgpO1xuICB2YXIgbnogPSBqeS5yZWRBZGQoankpLnJlZE11bChqeik7XG5cbiAgcmV0dXJuIHRoaXMuY3VydmUuanBvaW50KG54LCBueSwgbnopO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS50cnBsID0gZnVuY3Rpb24gdHJwbCgpIHtcbiAgaWYgKCF0aGlzLmN1cnZlLnplcm9BKVxuICAgIHJldHVybiB0aGlzLmRibCgpLmFkZCh0aGlzKTtcblxuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tc2hvcnR3LWphY29iaWFuLTAuaHRtbCN0cmlwbGluZy10cGwtMjAwNy1ibFxuICAvLyA1TSArIDEwUyArIC4uLlxuXG4gIC8vIFhYID0gWDFeMlxuICB2YXIgeHggPSB0aGlzLngucmVkU3FyKCk7XG4gIC8vIFlZID0gWTFeMlxuICB2YXIgeXkgPSB0aGlzLnkucmVkU3FyKCk7XG4gIC8vIFpaID0gWjFeMlxuICB2YXIgenogPSB0aGlzLnoucmVkU3FyKCk7XG4gIC8vIFlZWVkgPSBZWV4yXG4gIHZhciB5eXl5ID0geXkucmVkU3FyKCk7XG4gIC8vIE0gPSAzICogWFggKyBhICogWloyOyBhID0gMFxuICB2YXIgbSA9IHh4LnJlZEFkZCh4eCkucmVkSUFkZCh4eCk7XG4gIC8vIE1NID0gTV4yXG4gIHZhciBtbSA9IG0ucmVkU3FyKCk7XG4gIC8vIEUgPSA2ICogKChYMSArIFlZKV4yIC0gWFggLSBZWVlZKSAtIE1NXG4gIHZhciBlID0gdGhpcy54LnJlZEFkZCh5eSkucmVkU3FyKCkucmVkSVN1Yih4eCkucmVkSVN1Yih5eXl5KTtcbiAgZSA9IGUucmVkSUFkZChlKTtcbiAgZSA9IGUucmVkQWRkKGUpLnJlZElBZGQoZSk7XG4gIGUgPSBlLnJlZElTdWIobW0pO1xuICAvLyBFRSA9IEVeMlxuICB2YXIgZWUgPSBlLnJlZFNxcigpO1xuICAvLyBUID0gMTYqWVlZWVxuICB2YXIgdCA9IHl5eXkucmVkSUFkZCh5eXl5KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgLy8gVSA9IChNICsgRSleMiAtIE1NIC0gRUUgLSBUXG4gIHZhciB1ID0gbS5yZWRJQWRkKGUpLnJlZFNxcigpLnJlZElTdWIobW0pLnJlZElTdWIoZWUpLnJlZElTdWIodCk7XG4gIC8vIFgzID0gNCAqIChYMSAqIEVFIC0gNCAqIFlZICogVSlcbiAgdmFyIHl5dTQgPSB5eS5yZWRNdWwodSk7XG4gIHl5dTQgPSB5eXU0LnJlZElBZGQoeXl1NCk7XG4gIHl5dTQgPSB5eXU0LnJlZElBZGQoeXl1NCk7XG4gIHZhciBueCA9IHRoaXMueC5yZWRNdWwoZWUpLnJlZElTdWIoeXl1NCk7XG4gIG54ID0gbngucmVkSUFkZChueCk7XG4gIG54ID0gbngucmVkSUFkZChueCk7XG4gIC8vIFkzID0gOCAqIFkxICogKFUgKiAoVCAtIFUpIC0gRSAqIEVFKVxuICB2YXIgbnkgPSB0aGlzLnkucmVkTXVsKHUucmVkTXVsKHQucmVkSVN1Yih1KSkucmVkSVN1YihlLnJlZE11bChlZSkpKTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgLy8gWjMgPSAoWjEgKyBFKV4yIC0gWlogLSBFRVxuICB2YXIgbnogPSB0aGlzLnoucmVkQWRkKGUpLnJlZFNxcigpLnJlZElTdWIoenopLnJlZElTdWIoZWUpO1xuXG4gIHJldHVybiB0aGlzLmN1cnZlLmpwb2ludChueCwgbnksIG56KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUubXVsID0gZnVuY3Rpb24gbXVsKGssIGtiYXNlKSB7XG4gIGsgPSBuZXcgQk4oaywga2Jhc2UpO1xuXG4gIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsKHRoaXMsIGspO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5lcSA9IGZ1bmN0aW9uIGVxKHApIHtcbiAgaWYgKHAudHlwZSA9PT0gJ2FmZmluZScpXG4gICAgcmV0dXJuIHRoaXMuZXEocC50b0ooKSk7XG5cbiAgaWYgKHRoaXMgPT09IHApXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgLy8geDEgKiB6Ml4yID09IHgyICogejFeMlxuICB2YXIgejIgPSB0aGlzLnoucmVkU3FyKCk7XG4gIHZhciBwejIgPSBwLnoucmVkU3FyKCk7XG4gIGlmICh0aGlzLngucmVkTXVsKHB6MikucmVkSVN1YihwLngucmVkTXVsKHoyKSkuY21wbigwKSAhPT0gMClcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgLy8geTEgKiB6Ml4zID09IHkyICogejFeM1xuICB2YXIgejMgPSB6Mi5yZWRNdWwodGhpcy56KTtcbiAgdmFyIHB6MyA9IHB6Mi5yZWRNdWwocC56KTtcbiAgcmV0dXJuIHRoaXMueS5yZWRNdWwocHozKS5yZWRJU3ViKHAueS5yZWRNdWwoejMpKS5jbXBuKDApID09PSAwO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCgpIHtcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiAnPEVDIEpQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBKUG9pbnQgeDogJyArIHRoaXMueC50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LnRvU3RyaW5nKDE2LCAyKSArXG4gICAgICAnIHo6ICcgKyB0aGlzLnoudG9TdHJpbmcoMTYsIDIpICsgJz4nO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5pc0luZmluaXR5ID0gZnVuY3Rpb24gaXNJbmZpbml0eSgpIHtcbiAgLy8gWFhYIFRoaXMgY29kZSBhc3N1bWVzIHRoYXQgemVybyBpcyBhbHdheXMgemVybyBpbiByZWRcbiAgcmV0dXJuIHRoaXMuei5jbXBuKDApID09PSAwO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlcyA9IGV4cG9ydHM7XG5cbnZhciBoYXNoID0gcmVxdWlyZSgnaGFzaC5qcycpO1xudmFyIGVsbGlwdGljID0gcmVxdWlyZSgnLi4vZWxsaXB0aWMnKTtcblxudmFyIGFzc2VydCA9IGVsbGlwdGljLnV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gUHJlc2V0Q3VydmUob3B0aW9ucykge1xuICBpZiAob3B0aW9ucy50eXBlID09PSAnc2hvcnQnKVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUuc2hvcnQob3B0aW9ucyk7XG4gIGVsc2UgaWYgKG9wdGlvbnMudHlwZSA9PT0gJ2Vkd2FyZHMnKVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUuZWR3YXJkcyhvcHRpb25zKTtcbiAgZWxzZVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUubW9udChvcHRpb25zKTtcbiAgdGhpcy5nID0gdGhpcy5jdXJ2ZS5nO1xuICB0aGlzLm4gPSB0aGlzLmN1cnZlLm47XG4gIHRoaXMuaGFzaCA9IG9wdGlvbnMuaGFzaDtcblxuICBhc3NlcnQodGhpcy5nLnZhbGlkYXRlKCksICdJbnZhbGlkIGN1cnZlJyk7XG4gIGFzc2VydCh0aGlzLmcubXVsKHRoaXMubikuaXNJbmZpbml0eSgpLCAnSW52YWxpZCBjdXJ2ZSwgRypOICE9IE8nKTtcbn1cbmN1cnZlcy5QcmVzZXRDdXJ2ZSA9IFByZXNldEN1cnZlO1xuXG5mdW5jdGlvbiBkZWZpbmVDdXJ2ZShuYW1lLCBvcHRpb25zKSB7XG4gIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjdXJ2ZXMsIG5hbWUsIHtcbiAgICBjb25maWd1cmFibGU6IHRydWUsXG4gICAgZW51bWVyYWJsZTogdHJ1ZSxcbiAgICBnZXQ6IGZ1bmN0aW9uKCkge1xuICAgICAgdmFyIGN1cnZlID0gbmV3IFByZXNldEN1cnZlKG9wdGlvbnMpO1xuICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGN1cnZlcywgbmFtZSwge1xuICAgICAgICBjb25maWd1cmFibGU6IHRydWUsXG4gICAgICAgIGVudW1lcmFibGU6IHRydWUsXG4gICAgICAgIHZhbHVlOiBjdXJ2ZVxuICAgICAgfSk7XG4gICAgICByZXR1cm4gY3VydmU7XG4gICAgfVxuICB9KTtcbn1cblxuZGVmaW5lQ3VydmUoJ3AxOTInLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiAncDE5MicsXG4gIHA6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmZicsXG4gIGE6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmYycsXG4gIGI6ICc2NDIxMDUxOSBlNTljODBlNyAwZmE3ZTlhYiA3MjI0MzA0OSBmZWI4ZGVlYyBjMTQ2YjliMScsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiA5OWRlZjgzNiAxNDZiYzliMSBiNGQyMjgzMScsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICcxODhkYTgwZSBiMDMwOTBmNiA3Y2JmMjBlYiA0M2ExODgwMCBmNGZmMGFmZCA4MmZmMTAxMicsXG4gICAgJzA3MTkyYjk1IGZmYzhkYTc4IDYzMTAxMWVkIDZiMjRjZGQ1IDczZjk3N2ExIDFlNzk0ODExJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3AyMjQnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiAncDIyNCcsXG4gIHA6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiAwMDAwMDAwMCAwMDAwMDAwMCAwMDAwMDAwMScsXG4gIGE6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZScsXG4gIGI6ICdiNDA1MGE4NSAwYzA0YjNhYiBmNTQxMzI1NiA1MDQ0YjBiNyBkN2JmZDhiYSAyNzBiMzk0MyAyMzU1ZmZiNCcsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmMTZhMiBlMGI4ZjAzZSAxM2RkMjk0NSA1YzVjMmEzZCcsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICdiNzBlMGNiZCA2YmI0YmY3ZiAzMjEzOTBiOSA0YTAzYzFkMyA1NmMyMTEyMiAzNDMyODBkNiAxMTVjMWQyMScsXG4gICAgJ2JkMzc2Mzg4IGI1ZjcyM2ZiIDRjMjJkZmU2IGNkNDM3NWEwIDVhMDc0NzY0IDQ0ZDU4MTk5IDg1MDA3ZTM0J1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3AyNTYnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiBudWxsLFxuICBwOiAnZmZmZmZmZmYgMDAwMDAwMDEgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYnLFxuICBhOiAnZmZmZmZmZmYgMDAwMDAwMDEgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmMnLFxuICBiOiAnNWFjNjM1ZDggYWEzYTkzZTcgYjNlYmJkNTUgNzY5ODg2YmMgNjUxZDA2YjAgY2M1M2IwZjYgM2JjZTNjM2UgMjdkMjYwNGInLFxuICBuOiAnZmZmZmZmZmYgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgYmNlNmZhYWQgYTcxNzllODQgZjNiOWNhYzIgZmM2MzI1NTEnLFxuICBoYXNoOiBoYXNoLnNoYTI1NixcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnNmIxN2QxZjIgZTEyYzQyNDcgZjhiY2U2ZTUgNjNhNDQwZjIgNzcwMzdkODEgMmRlYjMzYTAgZjRhMTM5NDUgZDg5OGMyOTYnLFxuICAgICc0ZmUzNDJlMiBmZTFhN2Y5YiA4ZWU3ZWI0YSA3YzBmOWUxNiAyYmNlMzM1NyA2YjMxNWVjZSBjYmI2NDA2OCAzN2JmNTFmNSdcbiAgXVxufSk7XG5cbmRlZmluZUN1cnZlKCdwMzg0Jywge1xuICB0eXBlOiAnc2hvcnQnLFxuICBwcmltZTogbnVsbCxcbiAgcDogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmICcgK1xuICAgICAnZmZmZmZmZmUgZmZmZmZmZmYgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYnLFxuICBhOiAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZSBmZmZmZmZmZiAwMDAwMDAwMCAwMDAwMDAwMCBmZmZmZmZmYycsXG4gIGI6ICdiMzMxMmZhNyBlMjNlZTdlNCA5ODhlMDU2YiBlM2Y4MmQxOSAxODFkOWM2ZSBmZTgxNDExMiAwMzE0MDg4ZiAnICtcbiAgICAgJzUwMTM4NzVhIGM2NTYzOThkIDhhMmVkMTlkIDJhODVjOGVkIGQzZWMyYWVmJyxcbiAgbjogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGM3NjM0ZDgxICcgK1xuICAgICAnZjQzNzJkZGYgNTgxYTBkYjIgNDhiMGE3N2EgZWNlYzE5NmEgY2NjNTI5NzMnLFxuICBoYXNoOiBoYXNoLnNoYTM4NCxcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnYWE4N2NhMjIgYmU4YjA1MzcgOGViMWM3MWUgZjMyMGFkNzQgNmUxZDNiNjIgOGJhNzliOTggNTlmNzQxZTAgODI1NDJhMzggJyArXG4gICAgJzU1MDJmMjVkIGJmNTUyOTZjIDNhNTQ1ZTM4IDcyNzYwYWI3JyxcbiAgICAnMzYxN2RlNGEgOTYyNjJjNmYgNWQ5ZTk4YmYgOTI5MmRjMjkgZjhmNDFkYmQgMjg5YTE0N2MgZTlkYTMxMTMgYjVmMGI4YzAgJyArXG4gICAgJzBhNjBiMWNlIDFkN2U4MTlkIDdhNDMxZDdjIDkwZWEwZTVmJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3A1MjEnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiBudWxsLFxuICBwOiAnMDAwMDAxZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiAnICtcbiAgICAgJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmJyxcbiAgYTogJzAwMDAwMWZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmICcgK1xuICAgICAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmYycsXG4gIGI6ICcwMDAwMDA1MSA5NTNlYjk2MSA4ZTFjOWExZiA5MjlhMjFhMCBiNjg1NDBlZSBhMmRhNzI1YiAnICtcbiAgICAgJzk5YjMxNWYzIGI4YjQ4OTkxIDhlZjEwOWUxIDU2MTkzOTUxIGVjN2U5MzdiIDE2NTJjMGJkICcgK1xuICAgICAnM2JiMWJmMDcgMzU3M2RmODggM2QyYzM0ZjEgZWY0NTFmZDQgNmI1MDNmMDAnLFxuICBuOiAnMDAwMDAxZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmYSA1MTg2ODc4MyBiZjJmOTY2YiA3ZmNjMDE0OCAnICtcbiAgICAgJ2Y3MDlhNWQwIDNiYjVjOWI4IDg5OWM0N2FlIGJiNmZiNzFlIDkxMzg2NDA5JyxcbiAgaGFzaDogaGFzaC5zaGE1MTIsXG4gIGdSZWQ6IGZhbHNlLFxuICBnOiBbXG4gICAgJzAwMDAwMGM2IDg1OGUwNmI3IDA0MDRlOWNkIDllM2VjYjY2IDIzOTViNDQyIDljNjQ4MTM5ICcgK1xuICAgICcwNTNmYjUyMSBmODI4YWY2MCA2YjRkM2RiYSBhMTRiNWU3NyBlZmU3NTkyOCBmZTFkYzEyNyAnICtcbiAgICAnYTJmZmE4ZGUgMzM0OGIzYzEgODU2YTQyOWIgZjk3ZTdlMzEgYzJlNWJkNjYnLFxuICAgICcwMDAwMDExOCAzOTI5NmE3OCA5YTNiYzAwNCA1YzhhNWZiNCAyYzdkMWJkOSA5OGY1NDQ0OSAnICtcbiAgICAnNTc5YjQ0NjggMTdhZmJkMTcgMjczZTY2MmMgOTdlZTcyOTkgNWVmNDI2NDAgYzU1MGI5MDEgJyArXG4gICAgJzNmYWQwNzYxIDM1M2M3MDg2IGEyNzJjMjQwIDg4YmU5NDc2IDlmZDE2NjUwJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ2N1cnZlMjU1MTknLCB7XG4gIHR5cGU6ICdtb250JyxcbiAgcHJpbWU6ICdwMjU1MTknLFxuICBwOiAnN2ZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZlZCcsXG4gIGE6ICc3NmQwNicsXG4gIGI6ICcwJyxcbiAgbjogJzEwMDAwMDAwMDAwMDAwMDAgMDAwMDAwMDAwMDAwMDAwMCAxNGRlZjlkZWEyZjc5Y2Q2IDU4MTI2MzFhNWNmNWQzZWQnLFxuICBoYXNoOiBoYXNoLnNoYTI1NixcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnOSdcbiAgXVxufSk7XG5cbmRlZmluZUN1cnZlKCdlZDI1NTE5Jywge1xuICB0eXBlOiAnZWR3YXJkcycsXG4gIHByaW1lOiAncDI1NTE5JyxcbiAgcDogJzdmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZWQnLFxuICBhOiAnLTEnLFxuICBjOiAnMScsXG4gIC8vIC0xMjE2NjUgKiAoMTIxNjY2XigtMSkpIChtb2QgUClcbiAgZDogJzUyMDM2Y2VlMmI2ZmZlNzMgOGNjNzQwNzk3Nzc5ZTg5OCAwMDcwMGE0ZDQxNDFkOGFiIDc1ZWI0ZGNhMTM1OTc4YTMnLFxuICBuOiAnMTAwMDAwMDAwMDAwMDAwMCAwMDAwMDAwMDAwMDAwMDAwIDE0ZGVmOWRlYTJmNzljZDYgNTgxMjYzMWE1Y2Y1ZDNlZCcsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICcyMTY5MzZkM2NkNmU1M2ZlYzBhNGUyMzFmZGQ2ZGM1YzY5MmNjNzYwOTUyNWE3YjJjOTU2MmQ2MDhmMjVkNTFhJyxcblxuICAgIC8vIDQvNVxuICAgICc2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjU4J1xuICBdXG59KTtcblxudmFyIHByZTtcbnRyeSB7XG4gIHByZSA9IHJlcXVpcmUoJy4vcHJlY29tcHV0ZWQvc2VjcDI1NmsxJyk7XG59IGNhdGNoIChlKSB7XG4gIHByZSA9IHVuZGVmaW5lZDtcbn1cblxuZGVmaW5lQ3VydmUoJ3NlY3AyNTZrMScsIHtcbiAgdHlwZTogJ3Nob3J0JyxcbiAgcHJpbWU6ICdrMjU2JyxcbiAgcDogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZlIGZmZmZmYzJmJyxcbiAgYTogJzAnLFxuICBiOiAnNycsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBiYWFlZGNlNiBhZjQ4YTAzYiBiZmQyNWU4YyBkMDM2NDE0MScsXG4gIGg6ICcxJyxcbiAgaGFzaDogaGFzaC5zaGEyNTYsXG5cbiAgLy8gUHJlY29tcHV0ZWQgZW5kb21vcnBoaXNtXG4gIGJldGE6ICc3YWU5NmEyYjY1N2MwNzEwNmU2NDQ3OWVhYzM0MzRlOTljZjA0OTc1MTJmNTg5OTVjMTM5NmMyODcxOTUwMWVlJyxcbiAgbGFtYmRhOiAnNTM2M2FkNGNjMDVjMzBlMGE1MjYxYzAyODgxMjY0NWExMjJlMjJlYTIwODE2Njc4ZGYwMjk2N2MxYjIzYmQ3MicsXG4gIGJhc2lzOiBbXG4gICAge1xuICAgICAgYTogJzMwODZkMjIxYTdkNDZiY2RlODZjOTBlNDkyODRlYjE1JyxcbiAgICAgIGI6ICctZTQ0MzdlZDYwMTBlODgyODZmNTQ3ZmE5MGFiZmU0YzMnXG4gICAgfSxcbiAgICB7XG4gICAgICBhOiAnMTE0Y2E1MGY3YThlMmYzZjY1N2MxMTA4ZDlkNDRjZmQ4JyxcbiAgICAgIGI6ICczMDg2ZDIyMWE3ZDQ2YmNkZTg2YzkwZTQ5Mjg0ZWIxNSdcbiAgICB9XG4gIF0sXG5cbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnNzliZTY2N2VmOWRjYmJhYzU1YTA2Mjk1Y2U4NzBiMDcwMjliZmNkYjJkY2UyOGQ5NTlmMjgxNWIxNmY4MTc5OCcsXG4gICAgJzQ4M2FkYTc3MjZhM2M0NjU1ZGE0ZmJmYzBlMTEwOGE4ZmQxN2I0NDhhNjg1NTQxOTljNDdkMDhmZmIxMGQ0YjgnLFxuICAgIHByZVxuICBdXG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbnZhciBLZXlQYWlyID0gcmVxdWlyZSgnLi9rZXknKTtcbnZhciBTaWduYXR1cmUgPSByZXF1aXJlKCcuL3NpZ25hdHVyZScpO1xuXG5mdW5jdGlvbiBFQyhvcHRpb25zKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBFQykpXG4gICAgcmV0dXJuIG5ldyBFQyhvcHRpb25zKTtcblxuICAvLyBTaG9ydGN1dCBgZWxsaXB0aWMuZWMoY3VydmUtbmFtZSlgXG4gIGlmICh0eXBlb2Ygb3B0aW9ucyA9PT0gJ3N0cmluZycpIHtcbiAgICBhc3NlcnQoZWxsaXB0aWMuY3VydmVzLmhhc093blByb3BlcnR5KG9wdGlvbnMpLCAnVW5rbm93biBjdXJ2ZSAnICsgb3B0aW9ucyk7XG5cbiAgICBvcHRpb25zID0gZWxsaXB0aWMuY3VydmVzW29wdGlvbnNdO1xuICB9XG5cbiAgLy8gU2hvcnRjdXQgZm9yIGBlbGxpcHRpYy5lYyhlbGxpcHRpYy5jdXJ2ZXMuY3VydmVOYW1lKWBcbiAgaWYgKG9wdGlvbnMgaW5zdGFuY2VvZiBlbGxpcHRpYy5jdXJ2ZXMuUHJlc2V0Q3VydmUpXG4gICAgb3B0aW9ucyA9IHsgY3VydmU6IG9wdGlvbnMgfTtcblxuICB0aGlzLmN1cnZlID0gb3B0aW9ucy5jdXJ2ZS5jdXJ2ZTtcbiAgdGhpcy5uID0gdGhpcy5jdXJ2ZS5uO1xuICB0aGlzLm5oID0gdGhpcy5uLnVzaHJuKDEpO1xuICB0aGlzLmcgPSB0aGlzLmN1cnZlLmc7XG5cbiAgLy8gUG9pbnQgb24gY3VydmVcbiAgdGhpcy5nID0gb3B0aW9ucy5jdXJ2ZS5nO1xuICB0aGlzLmcucHJlY29tcHV0ZShvcHRpb25zLmN1cnZlLm4uYml0TGVuZ3RoKCkgKyAxKTtcblxuICAvLyBIYXNoIGZvciBmdW5jdGlvbiBmb3IgRFJCR1xuICB0aGlzLmhhc2ggPSBvcHRpb25zLmhhc2ggfHwgb3B0aW9ucy5jdXJ2ZS5oYXNoO1xufVxubW9kdWxlLmV4cG9ydHMgPSBFQztcblxuRUMucHJvdG90eXBlLmtleVBhaXIgPSBmdW5jdGlvbiBrZXlQYWlyKG9wdGlvbnMpIHtcbiAgcmV0dXJuIG5ldyBLZXlQYWlyKHRoaXMsIG9wdGlvbnMpO1xufTtcblxuRUMucHJvdG90eXBlLmtleUZyb21Qcml2YXRlID0gZnVuY3Rpb24ga2V5RnJvbVByaXZhdGUocHJpdiwgZW5jKSB7XG4gIHJldHVybiBLZXlQYWlyLmZyb21Qcml2YXRlKHRoaXMsIHByaXYsIGVuYyk7XG59O1xuXG5FQy5wcm90b3R5cGUua2V5RnJvbVB1YmxpYyA9IGZ1bmN0aW9uIGtleUZyb21QdWJsaWMocHViLCBlbmMpIHtcbiAgcmV0dXJuIEtleVBhaXIuZnJvbVB1YmxpYyh0aGlzLCBwdWIsIGVuYyk7XG59O1xuXG5FQy5wcm90b3R5cGUuZ2VuS2V5UGFpciA9IGZ1bmN0aW9uIGdlbktleVBhaXIob3B0aW9ucykge1xuICBpZiAoIW9wdGlvbnMpXG4gICAgb3B0aW9ucyA9IHt9O1xuXG4gIC8vIEluc3RhbnRpYXRlIEhtYWNfRFJCR1xuICB2YXIgZHJiZyA9IG5ldyBlbGxpcHRpYy5obWFjRFJCRyh7XG4gICAgaGFzaDogdGhpcy5oYXNoLFxuICAgIHBlcnM6IG9wdGlvbnMucGVycyxcbiAgICBlbnRyb3B5OiBvcHRpb25zLmVudHJvcHkgfHwgZWxsaXB0aWMucmFuZCh0aGlzLmhhc2guaG1hY1N0cmVuZ3RoKSxcbiAgICBub25jZTogdGhpcy5uLnRvQXJyYXkoKVxuICB9KTtcblxuICB2YXIgYnl0ZXMgPSB0aGlzLm4uYnl0ZUxlbmd0aCgpO1xuICB2YXIgbnMyID0gdGhpcy5uLnN1YihuZXcgQk4oMikpO1xuICBkbyB7XG4gICAgdmFyIHByaXYgPSBuZXcgQk4oZHJiZy5nZW5lcmF0ZShieXRlcykpO1xuICAgIGlmIChwcml2LmNtcChuczIpID4gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgcHJpdi5pYWRkbigxKTtcbiAgICByZXR1cm4gdGhpcy5rZXlGcm9tUHJpdmF0ZShwcml2KTtcbiAgfSB3aGlsZSAodHJ1ZSk7XG59O1xuXG5FQy5wcm90b3R5cGUuX3RydW5jYXRlVG9OID0gZnVuY3Rpb24gdHJ1bmNhdGVUb04obXNnLCB0cnVuY09ubHkpIHtcbiAgdmFyIGRlbHRhID0gbXNnLmJ5dGVMZW5ndGgoKSAqIDggLSB0aGlzLm4uYml0TGVuZ3RoKCk7XG4gIGlmIChkZWx0YSA+IDApXG4gICAgbXNnID0gbXNnLnVzaHJuKGRlbHRhKTtcbiAgaWYgKCF0cnVuY09ubHkgJiYgbXNnLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIG1zZy5zdWIodGhpcy5uKTtcbiAgZWxzZVxuICAgIHJldHVybiBtc2c7XG59O1xuXG5FQy5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obXNnLCBrZXksIGVuYywgb3B0aW9ucykge1xuICBpZiAodHlwZW9mIGVuYyA9PT0gJ29iamVjdCcpIHtcbiAgICBvcHRpb25zID0gZW5jO1xuICAgIGVuYyA9IG51bGw7XG4gIH1cbiAgaWYgKCFvcHRpb25zKVxuICAgIG9wdGlvbnMgPSB7fTtcblxuICBrZXkgPSB0aGlzLmtleUZyb21Qcml2YXRlKGtleSwgZW5jKTtcbiAgbXNnID0gdGhpcy5fdHJ1bmNhdGVUb04obmV3IEJOKG1zZywgMTYpKTtcblxuICAvLyBaZXJvLWV4dGVuZCBrZXkgdG8gcHJvdmlkZSBlbm91Z2ggZW50cm9weVxuICB2YXIgYnl0ZXMgPSB0aGlzLm4uYnl0ZUxlbmd0aCgpO1xuICB2YXIgYmtleSA9IGtleS5nZXRQcml2YXRlKCkudG9BcnJheSgnYmUnLCBieXRlcyk7XG5cbiAgLy8gWmVyby1leHRlbmQgbm9uY2UgdG8gaGF2ZSB0aGUgc2FtZSBieXRlIHNpemUgYXMgTlxuICB2YXIgbm9uY2UgPSBtc2cudG9BcnJheSgnYmUnLCBieXRlcyk7XG5cbiAgLy8gSW5zdGFudGlhdGUgSG1hY19EUkJHXG4gIHZhciBkcmJnID0gbmV3IGVsbGlwdGljLmhtYWNEUkJHKHtcbiAgICBoYXNoOiB0aGlzLmhhc2gsXG4gICAgZW50cm9weTogYmtleSxcbiAgICBub25jZTogbm9uY2UsXG4gICAgcGVyczogb3B0aW9ucy5wZXJzLFxuICAgIHBlcnNFbmM6IG9wdGlvbnMucGVyc0VuY1xuICB9KTtcblxuICAvLyBOdW1iZXIgb2YgYnl0ZXMgdG8gZ2VuZXJhdGVcbiAgdmFyIG5zMSA9IHRoaXMubi5zdWIobmV3IEJOKDEpKTtcblxuICBmb3IgKHZhciBpdGVyID0gMDsgdHJ1ZTsgaXRlcisrKSB7XG4gICAgdmFyIGsgPSBvcHRpb25zLmsgP1xuICAgICAgICBvcHRpb25zLmsoaXRlcikgOlxuICAgICAgICBuZXcgQk4oZHJiZy5nZW5lcmF0ZSh0aGlzLm4uYnl0ZUxlbmd0aCgpKSk7XG4gICAgayA9IHRoaXMuX3RydW5jYXRlVG9OKGssIHRydWUpO1xuICAgIGlmIChrLmNtcG4oMSkgPD0gMCB8fCBrLmNtcChuczEpID49IDApXG4gICAgICBjb250aW51ZTtcblxuICAgIHZhciBrcCA9IHRoaXMuZy5tdWwoayk7XG4gICAgaWYgKGtwLmlzSW5maW5pdHkoKSlcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIGtwWCA9IGtwLmdldFgoKTtcbiAgICB2YXIgciA9IGtwWC51bW9kKHRoaXMubik7XG4gICAgaWYgKHIuY21wbigwKSA9PT0gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIHMgPSBrLmludm0odGhpcy5uKS5tdWwoci5tdWwoa2V5LmdldFByaXZhdGUoKSkuaWFkZChtc2cpKTtcbiAgICBzID0gcy51bW9kKHRoaXMubik7XG4gICAgaWYgKHMuY21wbigwKSA9PT0gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIHJlY292ZXJ5UGFyYW0gPSAoa3AuZ2V0WSgpLmlzT2RkKCkgPyAxIDogMCkgfFxuICAgICAgICAgICAgICAgICAgICAgICAgKGtwWC5jbXAocikgIT09IDAgPyAyIDogMCk7XG5cbiAgICAvLyBVc2UgY29tcGxlbWVudCBvZiBgc2AsIGlmIGl0IGlzID4gYG4gLyAyYFxuICAgIGlmIChvcHRpb25zLmNhbm9uaWNhbCAmJiBzLmNtcCh0aGlzLm5oKSA+IDApIHtcbiAgICAgIHMgPSB0aGlzLm4uc3ViKHMpO1xuICAgICAgcmVjb3ZlcnlQYXJhbSBePSAxO1xuICAgIH1cblxuICAgIHJldHVybiBuZXcgU2lnbmF0dXJlKHsgcjogciwgczogcywgcmVjb3ZlcnlQYXJhbTogcmVjb3ZlcnlQYXJhbSB9KTtcbiAgfVxufTtcblxuRUMucHJvdG90eXBlLnZlcmlmeSA9IGZ1bmN0aW9uIHZlcmlmeShtc2csIHNpZ25hdHVyZSwga2V5LCBlbmMpIHtcbiAgbXNnID0gdGhpcy5fdHJ1bmNhdGVUb04obmV3IEJOKG1zZywgMTYpKTtcbiAga2V5ID0gdGhpcy5rZXlGcm9tUHVibGljKGtleSwgZW5jKTtcbiAgc2lnbmF0dXJlID0gbmV3IFNpZ25hdHVyZShzaWduYXR1cmUsICdoZXgnKTtcblxuICAvLyBQZXJmb3JtIHByaW1pdGl2ZSB2YWx1ZXMgdmFsaWRhdGlvblxuICB2YXIgciA9IHNpZ25hdHVyZS5yO1xuICB2YXIgcyA9IHNpZ25hdHVyZS5zO1xuICBpZiAoci5jbXBuKDEpIDwgMCB8fCByLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIGZhbHNlO1xuICBpZiAocy5jbXBuKDEpIDwgMCB8fCBzLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIGZhbHNlO1xuXG4gIC8vIFZhbGlkYXRlIHNpZ25hdHVyZVxuICB2YXIgc2ludiA9IHMuaW52bSh0aGlzLm4pO1xuICB2YXIgdTEgPSBzaW52Lm11bChtc2cpLnVtb2QodGhpcy5uKTtcbiAgdmFyIHUyID0gc2ludi5tdWwocikudW1vZCh0aGlzLm4pO1xuXG4gIHZhciBwID0gdGhpcy5nLm11bEFkZCh1MSwga2V5LmdldFB1YmxpYygpLCB1Mik7XG4gIGlmIChwLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIHAuZ2V0WCgpLnVtb2QodGhpcy5uKS5jbXAocikgPT09IDA7XG59O1xuXG5FQy5wcm90b3R5cGUucmVjb3ZlclB1YktleSA9IGZ1bmN0aW9uKG1zZywgc2lnbmF0dXJlLCBqLCBlbmMpIHtcbiAgYXNzZXJ0KCgzICYgaikgPT09IGosICdUaGUgcmVjb3ZlcnkgcGFyYW0gaXMgbW9yZSB0aGFuIHR3byBiaXRzJyk7XG4gIHNpZ25hdHVyZSA9IG5ldyBTaWduYXR1cmUoc2lnbmF0dXJlLCBlbmMpO1xuXG4gIHZhciBuID0gdGhpcy5uO1xuICB2YXIgZSA9IG5ldyBCTihtc2cpO1xuICB2YXIgciA9IHNpZ25hdHVyZS5yO1xuICB2YXIgcyA9IHNpZ25hdHVyZS5zO1xuXG4gIC8vIEEgc2V0IExTQiBzaWduaWZpZXMgdGhhdCB0aGUgeS1jb29yZGluYXRlIGlzIG9kZFxuICB2YXIgaXNZT2RkID0gaiAmIDE7XG4gIHZhciBpc1NlY29uZEtleSA9IGogPj4gMTtcbiAgaWYgKHIuY21wKHRoaXMuY3VydmUucC51bW9kKHRoaXMuY3VydmUubikpID49IDAgJiYgaXNTZWNvbmRLZXkpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gZmluZCBzZW5jb25kIGtleSBjYW5kaW5hdGUnKTtcblxuICAvLyAxLjEuIExldCB4ID0gciArIGpuLlxuICBpZiAoaXNTZWNvbmRLZXkpXG4gICAgciA9IHRoaXMuY3VydmUucG9pbnRGcm9tWChyLmFkZCh0aGlzLmN1cnZlLm4pLCBpc1lPZGQpO1xuICBlbHNlXG4gICAgciA9IHRoaXMuY3VydmUucG9pbnRGcm9tWChyLCBpc1lPZGQpO1xuXG4gIHZhciBlTmVnID0gbi5zdWIoZSk7XG5cbiAgLy8gMS42LjEgQ29tcHV0ZSBRID0gcl4tMSAoc1IgLSAgZUcpXG4gIC8vICAgICAgICAgICAgICAgUSA9IHJeLTEgKHNSICsgLWVHKVxuICB2YXIgckludiA9IHNpZ25hdHVyZS5yLmludm0obik7XG4gIHJldHVybiB0aGlzLmcubXVsQWRkKGVOZWcsIHIsIHMpLm11bChySW52KTtcbn07XG5cbkVDLnByb3RvdHlwZS5nZXRLZXlSZWNvdmVyeVBhcmFtID0gZnVuY3Rpb24oZSwgc2lnbmF0dXJlLCBRLCBlbmMpIHtcbiAgc2lnbmF0dXJlID0gbmV3IFNpZ25hdHVyZShzaWduYXR1cmUsIGVuYyk7XG4gIGlmIChzaWduYXR1cmUucmVjb3ZlcnlQYXJhbSAhPT0gbnVsbClcbiAgICByZXR1cm4gc2lnbmF0dXJlLnJlY292ZXJ5UGFyYW07XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcbiAgICB2YXIgUXByaW1lO1xuICAgIHRyeSB7XG4gICAgICBRcHJpbWUgPSB0aGlzLnJlY292ZXJQdWJLZXkoZSwgc2lnbmF0dXJlLCBpKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICBpZiAoUXByaW1lLmVxKFEpKVxuICAgICAgcmV0dXJuIGk7XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gZmluZCB2YWxpZCByZWNvdmVyeSBmYWN0b3InKTtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG5cbmZ1bmN0aW9uIEtleVBhaXIoZWMsIG9wdGlvbnMpIHtcbiAgdGhpcy5lYyA9IGVjO1xuICB0aGlzLnByaXYgPSBudWxsO1xuICB0aGlzLnB1YiA9IG51bGw7XG5cbiAgLy8gS2V5UGFpcihlYywgeyBwcml2OiAuLi4sIHB1YjogLi4uIH0pXG4gIGlmIChvcHRpb25zLnByaXYpXG4gICAgdGhpcy5faW1wb3J0UHJpdmF0ZShvcHRpb25zLnByaXYsIG9wdGlvbnMucHJpdkVuYyk7XG4gIGlmIChvcHRpb25zLnB1YilcbiAgICB0aGlzLl9pbXBvcnRQdWJsaWMob3B0aW9ucy5wdWIsIG9wdGlvbnMucHViRW5jKTtcbn1cbm1vZHVsZS5leHBvcnRzID0gS2V5UGFpcjtcblxuS2V5UGFpci5mcm9tUHVibGljID0gZnVuY3Rpb24gZnJvbVB1YmxpYyhlYywgcHViLCBlbmMpIHtcbiAgaWYgKHB1YiBpbnN0YW5jZW9mIEtleVBhaXIpXG4gICAgcmV0dXJuIHB1YjtcblxuICByZXR1cm4gbmV3IEtleVBhaXIoZWMsIHtcbiAgICBwdWI6IHB1YixcbiAgICBwdWJFbmM6IGVuY1xuICB9KTtcbn07XG5cbktleVBhaXIuZnJvbVByaXZhdGUgPSBmdW5jdGlvbiBmcm9tUHJpdmF0ZShlYywgcHJpdiwgZW5jKSB7XG4gIGlmIChwcml2IGluc3RhbmNlb2YgS2V5UGFpcilcbiAgICByZXR1cm4gcHJpdjtcblxuICByZXR1cm4gbmV3IEtleVBhaXIoZWMsIHtcbiAgICBwcml2OiBwcml2LFxuICAgIHByaXZFbmM6IGVuY1xuICB9KTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLnZhbGlkYXRlID0gZnVuY3Rpb24gdmFsaWRhdGUoKSB7XG4gIHZhciBwdWIgPSB0aGlzLmdldFB1YmxpYygpO1xuXG4gIGlmIChwdWIuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiB7IHJlc3VsdDogZmFsc2UsIHJlYXNvbjogJ0ludmFsaWQgcHVibGljIGtleScgfTtcbiAgaWYgKCFwdWIudmFsaWRhdGUoKSlcbiAgICByZXR1cm4geyByZXN1bHQ6IGZhbHNlLCByZWFzb246ICdQdWJsaWMga2V5IGlzIG5vdCBhIHBvaW50JyB9O1xuICBpZiAoIXB1Yi5tdWwodGhpcy5lYy5jdXJ2ZS5uKS5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHsgcmVzdWx0OiBmYWxzZSwgcmVhc29uOiAnUHVibGljIGtleSAqIE4gIT0gTycgfTtcblxuICByZXR1cm4geyByZXN1bHQ6IHRydWUsIHJlYXNvbjogbnVsbCB9O1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHVibGljID0gZnVuY3Rpb24gZ2V0UHVibGljKGNvbXBhY3QsIGVuYykge1xuICAvLyBjb21wYWN0IGlzIG9wdGlvbmFsIGFyZ3VtZW50XG4gIGlmICh0eXBlb2YgY29tcGFjdCA9PT0gJ3N0cmluZycpIHtcbiAgICBlbmMgPSBjb21wYWN0O1xuICAgIGNvbXBhY3QgPSBudWxsO1xuICB9XG5cbiAgaWYgKCF0aGlzLnB1YilcbiAgICB0aGlzLnB1YiA9IHRoaXMuZWMuZy5tdWwodGhpcy5wcml2KTtcblxuICBpZiAoIWVuYylcbiAgICByZXR1cm4gdGhpcy5wdWI7XG5cbiAgcmV0dXJuIHRoaXMucHViLmVuY29kZShlbmMsIGNvbXBhY3QpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHJpdmF0ZSA9IGZ1bmN0aW9uIGdldFByaXZhdGUoZW5jKSB7XG4gIGlmIChlbmMgPT09ICdoZXgnKVxuICAgIHJldHVybiB0aGlzLnByaXYudG9TdHJpbmcoMTYsIDIpO1xuICBlbHNlXG4gICAgcmV0dXJuIHRoaXMucHJpdjtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLl9pbXBvcnRQcml2YXRlID0gZnVuY3Rpb24gX2ltcG9ydFByaXZhdGUoa2V5LCBlbmMpIHtcbiAgdGhpcy5wcml2ID0gbmV3IEJOKGtleSwgZW5jIHx8IDE2KTtcblxuICAvLyBFbnN1cmUgdGhhdCB0aGUgcHJpdiB3b24ndCBiZSBiaWdnZXIgdGhhbiBuLCBvdGhlcndpc2Ugd2UgbWF5IGZhaWxcbiAgLy8gaW4gZml4ZWQgbXVsdGlwbGljYXRpb24gbWV0aG9kXG4gIHRoaXMucHJpdiA9IHRoaXMucHJpdi51bW9kKHRoaXMuZWMuY3VydmUubik7XG59O1xuXG5LZXlQYWlyLnByb3RvdHlwZS5faW1wb3J0UHVibGljID0gZnVuY3Rpb24gX2ltcG9ydFB1YmxpYyhrZXksIGVuYykge1xuICBpZiAoa2V5LnggfHwga2V5LnkpIHtcbiAgICB0aGlzLnB1YiA9IHRoaXMuZWMuY3VydmUucG9pbnQoa2V5LngsIGtleS55KTtcbiAgICByZXR1cm47XG4gIH1cbiAgdGhpcy5wdWIgPSB0aGlzLmVjLmN1cnZlLmRlY29kZVBvaW50KGtleSwgZW5jKTtcbn07XG5cbi8vIEVDREhcbktleVBhaXIucHJvdG90eXBlLmRlcml2ZSA9IGZ1bmN0aW9uIGRlcml2ZShwdWIpIHtcbiAgcmV0dXJuIHB1Yi5tdWwodGhpcy5wcml2KS5nZXRYKCk7XG59O1xuXG4vLyBFQ0RTQVxuS2V5UGFpci5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obXNnLCBlbmMsIG9wdGlvbnMpIHtcbiAgcmV0dXJuIHRoaXMuZWMuc2lnbihtc2csIHRoaXMsIGVuYywgb3B0aW9ucyk7XG59O1xuXG5LZXlQYWlyLnByb3RvdHlwZS52ZXJpZnkgPSBmdW5jdGlvbiB2ZXJpZnkobXNnLCBzaWduYXR1cmUpIHtcbiAgcmV0dXJuIHRoaXMuZWMudmVyaWZ5KG1zZywgc2lnbmF0dXJlLCB0aGlzKTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLmluc3BlY3QgPSBmdW5jdGlvbiBpbnNwZWN0KCkge1xuICByZXR1cm4gJzxLZXkgcHJpdjogJyArICh0aGlzLnByaXYgJiYgdGhpcy5wcml2LnRvU3RyaW5nKDE2LCAyKSkgK1xuICAgICAgICAgJyBwdWI6ICcgKyAodGhpcy5wdWIgJiYgdGhpcy5wdWIuaW5zcGVjdCgpKSArICcgPic7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgQk4gPSByZXF1aXJlKCdibi5qcycpO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBTaWduYXR1cmUob3B0aW9ucywgZW5jKSB7XG4gIGlmIChvcHRpb25zIGluc3RhbmNlb2YgU2lnbmF0dXJlKVxuICAgIHJldHVybiBvcHRpb25zO1xuXG4gIGlmICh0aGlzLl9pbXBvcnRERVIob3B0aW9ucywgZW5jKSlcbiAgICByZXR1cm47XG5cbiAgYXNzZXJ0KG9wdGlvbnMuciAmJiBvcHRpb25zLnMsICdTaWduYXR1cmUgd2l0aG91dCByIG9yIHMnKTtcbiAgdGhpcy5yID0gbmV3IEJOKG9wdGlvbnMuciwgMTYpO1xuICB0aGlzLnMgPSBuZXcgQk4ob3B0aW9ucy5zLCAxNik7XG4gIGlmIChvcHRpb25zLnJlY292ZXJ5UGFyYW0gPT09IHVuZGVmaW5lZClcbiAgICB0aGlzLnJlY292ZXJ5UGFyYW0gPSBudWxsO1xuICBlbHNlXG4gICAgdGhpcy5yZWNvdmVyeVBhcmFtID0gb3B0aW9ucy5yZWNvdmVyeVBhcmFtO1xufVxubW9kdWxlLmV4cG9ydHMgPSBTaWduYXR1cmU7XG5cbmZ1bmN0aW9uIFBvc2l0aW9uKCkge1xuICB0aGlzLnBsYWNlID0gMDtcbn1cblxuZnVuY3Rpb24gZ2V0TGVuZ3RoKGJ1ZiwgcCkge1xuICB2YXIgaW5pdGlhbCA9IGJ1ZltwLnBsYWNlKytdO1xuICBpZiAoIShpbml0aWFsICYgMHg4MCkpIHtcbiAgICByZXR1cm4gaW5pdGlhbDtcbiAgfVxuICB2YXIgb2N0ZXRMZW4gPSBpbml0aWFsICYgMHhmO1xuICB2YXIgdmFsID0gMDtcbiAgZm9yICh2YXIgaSA9IDAsIG9mZiA9IHAucGxhY2U7IGkgPCBvY3RldExlbjsgaSsrLCBvZmYrKykge1xuICAgIHZhbCA8PD0gODtcbiAgICB2YWwgfD0gYnVmW29mZl07XG4gIH1cbiAgcC5wbGFjZSA9IG9mZjtcbiAgcmV0dXJuIHZhbDtcbn1cblxuZnVuY3Rpb24gcm1QYWRkaW5nKGJ1Zikge1xuICB2YXIgaSA9IDA7XG4gIHZhciBsZW4gPSBidWYubGVuZ3RoIC0gMTtcbiAgd2hpbGUgKCFidWZbaV0gJiYgIShidWZbaSArIDFdICYgMHg4MCkgJiYgaSA8IGxlbikge1xuICAgIGkrKztcbiAgfVxuICBpZiAoaSA9PT0gMCkge1xuICAgIHJldHVybiBidWY7XG4gIH1cbiAgcmV0dXJuIGJ1Zi5zbGljZShpKTtcbn1cblxuU2lnbmF0dXJlLnByb3RvdHlwZS5faW1wb3J0REVSID0gZnVuY3Rpb24gX2ltcG9ydERFUihkYXRhLCBlbmMpIHtcbiAgZGF0YSA9IHV0aWxzLnRvQXJyYXkoZGF0YSwgZW5jKTtcbiAgdmFyIHAgPSBuZXcgUG9zaXRpb24oKTtcbiAgaWYgKGRhdGFbcC5wbGFjZSsrXSAhPT0gMHgzMCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICB2YXIgbGVuID0gZ2V0TGVuZ3RoKGRhdGEsIHApO1xuICBpZiAoKGxlbiArIHAucGxhY2UpICE9PSBkYXRhLmxlbmd0aCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICBpZiAoZGF0YVtwLnBsYWNlKytdICE9PSAweDAyKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIHZhciBybGVuID0gZ2V0TGVuZ3RoKGRhdGEsIHApO1xuICB2YXIgciA9IGRhdGEuc2xpY2UocC5wbGFjZSwgcmxlbiArIHAucGxhY2UpO1xuICBwLnBsYWNlICs9IHJsZW47XG4gIGlmIChkYXRhW3AucGxhY2UrK10gIT09IDB4MDIpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgdmFyIHNsZW4gPSBnZXRMZW5ndGgoZGF0YSwgcCk7XG4gIGlmIChkYXRhLmxlbmd0aCAhPT0gc2xlbiArIHAucGxhY2UpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgdmFyIHMgPSBkYXRhLnNsaWNlKHAucGxhY2UsIHNsZW4gKyBwLnBsYWNlKTtcbiAgaWYgKHJbMF0gPT09IDAgJiYgKHJbMV0gJiAweDgwKSkge1xuICAgIHIgPSByLnNsaWNlKDEpO1xuICB9XG4gIGlmIChzWzBdID09PSAwICYmIChzWzFdICYgMHg4MCkpIHtcbiAgICBzID0gcy5zbGljZSgxKTtcbiAgfVxuXG4gIHRoaXMuciA9IG5ldyBCTihyKTtcbiAgdGhpcy5zID0gbmV3IEJOKHMpO1xuICB0aGlzLnJlY292ZXJ5UGFyYW0gPSBudWxsO1xuXG4gIHJldHVybiB0cnVlO1xufTtcblxuZnVuY3Rpb24gY29uc3RydWN0TGVuZ3RoKGFyciwgbGVuKSB7XG4gIGlmIChsZW4gPCAweDgwKSB7XG4gICAgYXJyLnB1c2gobGVuKTtcbiAgICByZXR1cm47XG4gIH1cbiAgdmFyIG9jdGV0cyA9IDEgKyAoTWF0aC5sb2cobGVuKSAvIE1hdGguTE4yID4+PiAzKTtcbiAgYXJyLnB1c2gob2N0ZXRzIHwgMHg4MCk7XG4gIHdoaWxlICgtLW9jdGV0cykge1xuICAgIGFyci5wdXNoKChsZW4gPj4+IChvY3RldHMgPDwgMykpICYgMHhmZik7XG4gIH1cbiAgYXJyLnB1c2gobGVuKTtcbn1cblxuU2lnbmF0dXJlLnByb3RvdHlwZS50b0RFUiA9IGZ1bmN0aW9uIHRvREVSKGVuYykge1xuICB2YXIgciA9IHRoaXMuci50b0FycmF5KCk7XG4gIHZhciBzID0gdGhpcy5zLnRvQXJyYXkoKTtcblxuICAvLyBQYWQgdmFsdWVzXG4gIGlmIChyWzBdICYgMHg4MClcbiAgICByID0gWyAwIF0uY29uY2F0KHIpO1xuICAvLyBQYWQgdmFsdWVzXG4gIGlmIChzWzBdICYgMHg4MClcbiAgICBzID0gWyAwIF0uY29uY2F0KHMpO1xuXG4gIHIgPSBybVBhZGRpbmcocik7XG4gIHMgPSBybVBhZGRpbmcocyk7XG5cbiAgd2hpbGUgKCFzWzBdICYmICEoc1sxXSAmIDB4ODApKSB7XG4gICAgcyA9IHMuc2xpY2UoMSk7XG4gIH1cbiAgdmFyIGFyciA9IFsgMHgwMiBdO1xuICBjb25zdHJ1Y3RMZW5ndGgoYXJyLCByLmxlbmd0aCk7XG4gIGFyciA9IGFyci5jb25jYXQocik7XG4gIGFyci5wdXNoKDB4MDIpO1xuICBjb25zdHJ1Y3RMZW5ndGgoYXJyLCBzLmxlbmd0aCk7XG4gIHZhciBiYWNrSGFsZiA9IGFyci5jb25jYXQocyk7XG4gIHZhciByZXMgPSBbIDB4MzAgXTtcbiAgY29uc3RydWN0TGVuZ3RoKHJlcywgYmFja0hhbGYubGVuZ3RoKTtcbiAgcmVzID0gcmVzLmNvbmNhdChiYWNrSGFsZik7XG4gIHJldHVybiB1dGlscy5lbmNvZGUocmVzLCBlbmMpO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGhhc2ggPSByZXF1aXJlKCdoYXNoLmpzJyk7XG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xudmFyIHBhcnNlQnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzO1xudmFyIEtleVBhaXIgPSByZXF1aXJlKCcuL2tleScpO1xudmFyIFNpZ25hdHVyZSA9IHJlcXVpcmUoJy4vc2lnbmF0dXJlJyk7XG5cbmZ1bmN0aW9uIEVERFNBKGN1cnZlKSB7XG4gIGFzc2VydChjdXJ2ZSA9PT0gJ2VkMjU1MTknLCAnb25seSB0ZXN0ZWQgd2l0aCBlZDI1NTE5IHNvIGZhcicpO1xuXG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBFRERTQSkpXG4gICAgcmV0dXJuIG5ldyBFRERTQShjdXJ2ZSk7XG5cbiAgdmFyIGN1cnZlID0gZWxsaXB0aWMuY3VydmVzW2N1cnZlXS5jdXJ2ZTtcbiAgdGhpcy5jdXJ2ZSA9IGN1cnZlO1xuICB0aGlzLmcgPSBjdXJ2ZS5nO1xuICB0aGlzLmcucHJlY29tcHV0ZShjdXJ2ZS5uLmJpdExlbmd0aCgpICsgMSk7XG5cbiAgdGhpcy5wb2ludENsYXNzID0gY3VydmUucG9pbnQoKS5jb25zdHJ1Y3RvcjtcbiAgdGhpcy5lbmNvZGluZ0xlbmd0aCA9IE1hdGguY2VpbChjdXJ2ZS5uLmJpdExlbmd0aCgpIC8gOCk7XG4gIHRoaXMuaGFzaCA9IGhhc2guc2hhNTEyO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IEVERFNBO1xuXG4vKipcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd9IG1lc3NhZ2UgLSBtZXNzYWdlIGJ5dGVzXG4qIEBwYXJhbSB7QXJyYXl8U3RyaW5nfEtleVBhaXJ9IHNlY3JldCAtIHNlY3JldCBieXRlcyBvciBhIGtleXBhaXJcbiogQHJldHVybnMge1NpZ25hdHVyZX0gLSBzaWduYXR1cmVcbiovXG5FRERTQS5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obWVzc2FnZSwgc2VjcmV0KSB7XG4gIG1lc3NhZ2UgPSBwYXJzZUJ5dGVzKG1lc3NhZ2UpO1xuICB2YXIga2V5ID0gdGhpcy5rZXlGcm9tU2VjcmV0KHNlY3JldCk7XG4gIHZhciByID0gdGhpcy5oYXNoSW50KGtleS5tZXNzYWdlUHJlZml4KCksIG1lc3NhZ2UpO1xuICB2YXIgUiA9IHRoaXMuZy5tdWwocik7XG4gIHZhciBSZW5jb2RlZCA9IHRoaXMuZW5jb2RlUG9pbnQoUik7XG4gIHZhciBzXyA9IHRoaXMuaGFzaEludChSZW5jb2RlZCwga2V5LnB1YkJ5dGVzKCksIG1lc3NhZ2UpXG4gICAgICAgICAgICAgICAubXVsKGtleS5wcml2KCkpO1xuICB2YXIgUyA9IHIuYWRkKHNfKS51bW9kKHRoaXMuY3VydmUubik7XG4gIHJldHVybiB0aGlzLm1ha2VTaWduYXR1cmUoeyBSOiBSLCBTOiBTLCBSZW5jb2RlZDogUmVuY29kZWQgfSk7XG59O1xuXG4vKipcbiogQHBhcmFtIHtBcnJheX0gbWVzc2FnZSAtIG1lc3NhZ2UgYnl0ZXNcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd8U2lnbmF0dXJlfSBzaWcgLSBzaWcgYnl0ZXNcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd8UG9pbnR8S2V5UGFpcn0gcHViIC0gcHVibGljIGtleVxuKiBAcmV0dXJucyB7Qm9vbGVhbn0gLSB0cnVlIGlmIHB1YmxpYyBrZXkgbWF0Y2hlcyBzaWcgb2YgbWVzc2FnZVxuKi9cbkVERFNBLnByb3RvdHlwZS52ZXJpZnkgPSBmdW5jdGlvbiB2ZXJpZnkobWVzc2FnZSwgc2lnLCBwdWIpIHtcbiAgbWVzc2FnZSA9IHBhcnNlQnl0ZXMobWVzc2FnZSk7XG4gIHNpZyA9IHRoaXMubWFrZVNpZ25hdHVyZShzaWcpO1xuICB2YXIga2V5ID0gdGhpcy5rZXlGcm9tUHVibGljKHB1Yik7XG4gIHZhciBoID0gdGhpcy5oYXNoSW50KHNpZy5SZW5jb2RlZCgpLCBrZXkucHViQnl0ZXMoKSwgbWVzc2FnZSk7XG4gIHZhciBTRyA9IHRoaXMuZy5tdWwoc2lnLlMoKSk7XG4gIHZhciBScGx1c0FoID0gc2lnLlIoKS5hZGQoa2V5LnB1YigpLm11bChoKSk7XG4gIHJldHVybiBScGx1c0FoLmVxKFNHKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5oYXNoSW50ID0gZnVuY3Rpb24gaGFzaEludCgpIHtcbiAgdmFyIGhhc2ggPSB0aGlzLmhhc2goKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXG4gICAgaGFzaC51cGRhdGUoYXJndW1lbnRzW2ldKTtcbiAgcmV0dXJuIHV0aWxzLmludEZyb21MRShoYXNoLmRpZ2VzdCgpKS51bW9kKHRoaXMuY3VydmUubik7XG59O1xuXG5FRERTQS5wcm90b3R5cGUua2V5RnJvbVB1YmxpYyA9IGZ1bmN0aW9uIGtleUZyb21QdWJsaWMocHViKSB7XG4gIHJldHVybiBLZXlQYWlyLmZyb21QdWJsaWModGhpcywgcHViKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5rZXlGcm9tU2VjcmV0ID0gZnVuY3Rpb24ga2V5RnJvbVNlY3JldChzZWNyZXQpIHtcbiAgcmV0dXJuIEtleVBhaXIuZnJvbVNlY3JldCh0aGlzLCBzZWNyZXQpO1xufTtcblxuRUREU0EucHJvdG90eXBlLm1ha2VTaWduYXR1cmUgPSBmdW5jdGlvbiBtYWtlU2lnbmF0dXJlKHNpZykge1xuICBpZiAoc2lnIGluc3RhbmNlb2YgU2lnbmF0dXJlKVxuICAgIHJldHVybiBzaWc7XG4gIHJldHVybiBuZXcgU2lnbmF0dXJlKHRoaXMsIHNpZyk7XG59O1xuXG4vKipcbiogKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvZHJhZnQtam9zZWZzc29uLWVkZHNhLWVkMjU1MTktMDMjc2VjdGlvbi01LjJcbipcbiogRUREU0EgZGVmaW5lcyBtZXRob2RzIGZvciBlbmNvZGluZyBhbmQgZGVjb2RpbmcgcG9pbnRzIGFuZCBpbnRlZ2Vycy4gVGhlc2UgYXJlXG4qIGhlbHBlciBjb252ZW5pZW5jZSBtZXRob2RzLCB0aGF0IHBhc3MgYWxvbmcgdG8gdXRpbGl0eSBmdW5jdGlvbnMgaW1wbGllZFxuKiBwYXJhbWV0ZXJzLlxuKlxuKi9cbkVERFNBLnByb3RvdHlwZS5lbmNvZGVQb2ludCA9IGZ1bmN0aW9uIGVuY29kZVBvaW50KHBvaW50KSB7XG4gIHZhciBlbmMgPSBwb2ludC5nZXRZKCkudG9BcnJheSgnbGUnLCB0aGlzLmVuY29kaW5nTGVuZ3RoKTtcbiAgZW5jW3RoaXMuZW5jb2RpbmdMZW5ndGggLSAxXSB8PSBwb2ludC5nZXRYKCkuaXNPZGQoKSA/IDB4ODAgOiAwO1xuICByZXR1cm4gZW5jO1xufTtcblxuRUREU0EucHJvdG90eXBlLmRlY29kZVBvaW50ID0gZnVuY3Rpb24gZGVjb2RlUG9pbnQoYnl0ZXMpIHtcbiAgYnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzKGJ5dGVzKTtcblxuICB2YXIgbGFzdEl4ID0gYnl0ZXMubGVuZ3RoIC0gMTtcbiAgdmFyIG5vcm1lZCA9IGJ5dGVzLnNsaWNlKDAsIGxhc3RJeCkuY29uY2F0KGJ5dGVzW2xhc3RJeF0gJiB+MHg4MCk7XG4gIHZhciB4SXNPZGQgPSAoYnl0ZXNbbGFzdEl4XSAmIDB4ODApICE9PSAwO1xuXG4gIHZhciB5ID0gdXRpbHMuaW50RnJvbUxFKG5vcm1lZCk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50RnJvbVkoeSwgeElzT2RkKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5lbmNvZGVJbnQgPSBmdW5jdGlvbiBlbmNvZGVJbnQobnVtKSB7XG4gIHJldHVybiBudW0udG9BcnJheSgnbGUnLCB0aGlzLmVuY29kaW5nTGVuZ3RoKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5kZWNvZGVJbnQgPSBmdW5jdGlvbiBkZWNvZGVJbnQoYnl0ZXMpIHtcbiAgcmV0dXJuIHV0aWxzLmludEZyb21MRShieXRlcyk7XG59O1xuXG5FRERTQS5wcm90b3R5cGUuaXNQb2ludCA9IGZ1bmN0aW9uIGlzUG9pbnQodmFsKSB7XG4gIHJldHVybiB2YWwgaW5zdGFuY2VvZiB0aGlzLnBvaW50Q2xhc3M7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xudmFyIHBhcnNlQnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzO1xudmFyIGNhY2hlZFByb3BlcnR5ID0gdXRpbHMuY2FjaGVkUHJvcGVydHk7XG5cbi8qKlxuKiBAcGFyYW0ge0VERFNBfSBlZGRzYSAtIGluc3RhbmNlXG4qIEBwYXJhbSB7T2JqZWN0fSBwYXJhbXMgLSBwdWJsaWMvcHJpdmF0ZSBrZXkgcGFyYW1ldGVyc1xuKlxuKiBAcGFyYW0ge0FycmF5PEJ5dGU+fSBbcGFyYW1zLnNlY3JldF0gLSBzZWNyZXQgc2VlZCBieXRlc1xuKiBAcGFyYW0ge1BvaW50fSBbcGFyYW1zLnB1Yl0gLSBwdWJsaWMga2V5IHBvaW50IChha2EgYEFgIGluIGVkZHNhIHRlcm1zKVxuKiBAcGFyYW0ge0FycmF5PEJ5dGU+fSBbcGFyYW1zLnB1Yl0gLSBwdWJsaWMga2V5IHBvaW50IGVuY29kZWQgYXMgYnl0ZXNcbipcbiovXG5mdW5jdGlvbiBLZXlQYWlyKGVkZHNhLCBwYXJhbXMpIHtcbiAgdGhpcy5lZGRzYSA9IGVkZHNhO1xuICB0aGlzLl9zZWNyZXQgPSBwYXJzZUJ5dGVzKHBhcmFtcy5zZWNyZXQpO1xuICBpZiAoZWRkc2EuaXNQb2ludChwYXJhbXMucHViKSlcbiAgICB0aGlzLl9wdWIgPSBwYXJhbXMucHViO1xuICBlbHNlXG4gICAgdGhpcy5fcHViQnl0ZXMgPSBwYXJzZUJ5dGVzKHBhcmFtcy5wdWIpO1xufVxuXG5LZXlQYWlyLmZyb21QdWJsaWMgPSBmdW5jdGlvbiBmcm9tUHVibGljKGVkZHNhLCBwdWIpIHtcbiAgaWYgKHB1YiBpbnN0YW5jZW9mIEtleVBhaXIpXG4gICAgcmV0dXJuIHB1YjtcbiAgcmV0dXJuIG5ldyBLZXlQYWlyKGVkZHNhLCB7IHB1YjogcHViIH0pO1xufTtcblxuS2V5UGFpci5mcm9tU2VjcmV0ID0gZnVuY3Rpb24gZnJvbVNlY3JldChlZGRzYSwgc2VjcmV0KSB7XG4gIGlmIChzZWNyZXQgaW5zdGFuY2VvZiBLZXlQYWlyKVxuICAgIHJldHVybiBzZWNyZXQ7XG4gIHJldHVybiBuZXcgS2V5UGFpcihlZGRzYSwgeyBzZWNyZXQ6IHNlY3JldCB9KTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLnNlY3JldCA9IGZ1bmN0aW9uIHNlY3JldCgpIHtcbiAgcmV0dXJuIHRoaXMuX3NlY3JldDtcbn07XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdwdWJCeXRlcycsIGZ1bmN0aW9uIHB1YkJ5dGVzKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5lbmNvZGVQb2ludCh0aGlzLnB1YigpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShLZXlQYWlyLCAncHViJywgZnVuY3Rpb24gcHViKCkge1xuICBpZiAodGhpcy5fcHViQnl0ZXMpXG4gICAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlUG9pbnQodGhpcy5fcHViQnl0ZXMpO1xuICByZXR1cm4gdGhpcy5lZGRzYS5nLm11bCh0aGlzLnByaXYoKSk7XG59KTtcblxuY2FjaGVkUHJvcGVydHkoS2V5UGFpciwgJ3ByaXZCeXRlcycsIGZ1bmN0aW9uIHByaXZCeXRlcygpIHtcbiAgdmFyIGVkZHNhID0gdGhpcy5lZGRzYTtcbiAgdmFyIGhhc2ggPSB0aGlzLmhhc2goKTtcbiAgdmFyIGxhc3RJeCA9IGVkZHNhLmVuY29kaW5nTGVuZ3RoIC0gMTtcblxuICB2YXIgYSA9IGhhc2guc2xpY2UoMCwgZWRkc2EuZW5jb2RpbmdMZW5ndGgpO1xuICBhWzBdICY9IDI0ODtcbiAgYVtsYXN0SXhdICY9IDEyNztcbiAgYVtsYXN0SXhdIHw9IDY0O1xuXG4gIHJldHVybiBhO1xufSk7XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdwcml2JywgZnVuY3Rpb24gcHJpdigpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlSW50KHRoaXMucHJpdkJ5dGVzKCkpO1xufSk7XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdoYXNoJywgZnVuY3Rpb24gaGFzaCgpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuaGFzaCgpLnVwZGF0ZSh0aGlzLnNlY3JldCgpKS5kaWdlc3QoKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShLZXlQYWlyLCAnbWVzc2FnZVByZWZpeCcsIGZ1bmN0aW9uIG1lc3NhZ2VQcmVmaXgoKSB7XG4gIHJldHVybiB0aGlzLmhhc2goKS5zbGljZSh0aGlzLmVkZHNhLmVuY29kaW5nTGVuZ3RoKTtcbn0pO1xuXG5LZXlQYWlyLnByb3RvdHlwZS5zaWduID0gZnVuY3Rpb24gc2lnbihtZXNzYWdlKSB7XG4gIGFzc2VydCh0aGlzLl9zZWNyZXQsICdLZXlQYWlyIGNhbiBvbmx5IHZlcmlmeScpO1xuICByZXR1cm4gdGhpcy5lZGRzYS5zaWduKG1lc3NhZ2UsIHRoaXMpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUudmVyaWZ5ID0gZnVuY3Rpb24gdmVyaWZ5KG1lc3NhZ2UsIHNpZykge1xuICByZXR1cm4gdGhpcy5lZGRzYS52ZXJpZnkobWVzc2FnZSwgc2lnLCB0aGlzKTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLmdldFNlY3JldCA9IGZ1bmN0aW9uIGdldFNlY3JldChlbmMpIHtcbiAgYXNzZXJ0KHRoaXMuX3NlY3JldCwgJ0tleVBhaXIgaXMgcHVibGljIG9ubHknKTtcbiAgcmV0dXJuIHV0aWxzLmVuY29kZSh0aGlzLnNlY3JldCgpLCBlbmMpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHVibGljID0gZnVuY3Rpb24gZ2V0UHVibGljKGVuYykge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMucHViQnl0ZXMoKSwgZW5jKTtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gS2V5UGFpcjtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG52YXIgY2FjaGVkUHJvcGVydHkgPSB1dGlscy5jYWNoZWRQcm9wZXJ0eTtcbnZhciBwYXJzZUJ5dGVzID0gdXRpbHMucGFyc2VCeXRlcztcblxuLyoqXG4qIEBwYXJhbSB7RUREU0F9IGVkZHNhIC0gZWRkc2EgaW5zdGFuY2VcbiogQHBhcmFtIHtBcnJheTxCeXRlcz58T2JqZWN0fSBzaWcgLVxuKiBAcGFyYW0ge0FycmF5PEJ5dGVzPnxQb2ludH0gW3NpZy5SXSAtIFIgcG9pbnQgYXMgUG9pbnQgb3IgYnl0ZXNcbiogQHBhcmFtIHtBcnJheTxCeXRlcz58Ym59IFtzaWcuU10gLSBTIHNjYWxhciBhcyBibiBvciBieXRlc1xuKiBAcGFyYW0ge0FycmF5PEJ5dGVzPn0gW3NpZy5SZW5jb2RlZF0gLSBSIHBvaW50IGVuY29kZWRcbiogQHBhcmFtIHtBcnJheTxCeXRlcz59IFtzaWcuU2VuY29kZWRdIC0gUyBzY2FsYXIgZW5jb2RlZFxuKi9cbmZ1bmN0aW9uIFNpZ25hdHVyZShlZGRzYSwgc2lnKSB7XG4gIHRoaXMuZWRkc2EgPSBlZGRzYTtcblxuICBpZiAodHlwZW9mIHNpZyAhPT0gJ29iamVjdCcpXG4gICAgc2lnID0gcGFyc2VCeXRlcyhzaWcpO1xuXG4gIGlmIChBcnJheS5pc0FycmF5KHNpZykpIHtcbiAgICBzaWcgPSB7XG4gICAgICBSOiBzaWcuc2xpY2UoMCwgZWRkc2EuZW5jb2RpbmdMZW5ndGgpLFxuICAgICAgUzogc2lnLnNsaWNlKGVkZHNhLmVuY29kaW5nTGVuZ3RoKVxuICAgIH07XG4gIH1cblxuICBhc3NlcnQoc2lnLlIgJiYgc2lnLlMsICdTaWduYXR1cmUgd2l0aG91dCBSIG9yIFMnKTtcblxuICBpZiAoZWRkc2EuaXNQb2ludChzaWcuUikpXG4gICAgdGhpcy5fUiA9IHNpZy5SO1xuICBpZiAoc2lnLlMgaW5zdGFuY2VvZiBCTilcbiAgICB0aGlzLl9TID0gc2lnLlM7XG5cbiAgdGhpcy5fUmVuY29kZWQgPSBBcnJheS5pc0FycmF5KHNpZy5SKSA/IHNpZy5SIDogc2lnLlJlbmNvZGVkO1xuICB0aGlzLl9TZW5jb2RlZCA9IEFycmF5LmlzQXJyYXkoc2lnLlMpID8gc2lnLlMgOiBzaWcuU2VuY29kZWQ7XG59XG5cbmNhY2hlZFByb3BlcnR5KFNpZ25hdHVyZSwgJ1MnLCBmdW5jdGlvbiBTKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5kZWNvZGVJbnQodGhpcy5TZW5jb2RlZCgpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShTaWduYXR1cmUsICdSJywgZnVuY3Rpb24gUigpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlUG9pbnQodGhpcy5SZW5jb2RlZCgpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShTaWduYXR1cmUsICdSZW5jb2RlZCcsIGZ1bmN0aW9uIFJlbmNvZGVkKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5lbmNvZGVQb2ludCh0aGlzLlIoKSk7XG59KTtcblxuY2FjaGVkUHJvcGVydHkoU2lnbmF0dXJlLCAnU2VuY29kZWQnLCBmdW5jdGlvbiBTZW5jb2RlZCgpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZW5jb2RlSW50KHRoaXMuUygpKTtcbn0pO1xuXG5TaWduYXR1cmUucHJvdG90eXBlLnRvQnl0ZXMgPSBmdW5jdGlvbiB0b0J5dGVzKCkge1xuICByZXR1cm4gdGhpcy5SZW5jb2RlZCgpLmNvbmNhdCh0aGlzLlNlbmNvZGVkKCkpO1xufTtcblxuU2lnbmF0dXJlLnByb3RvdHlwZS50b0hleCA9IGZ1bmN0aW9uIHRvSGV4KCkge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMudG9CeXRlcygpLCAnaGV4JykudG9VcHBlckNhc2UoKTtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gU2lnbmF0dXJlO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgaGFzaCA9IHJlcXVpcmUoJ2hhc2guanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbmZ1bmN0aW9uIEhtYWNEUkJHKG9wdGlvbnMpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIEhtYWNEUkJHKSlcbiAgICByZXR1cm4gbmV3IEhtYWNEUkJHKG9wdGlvbnMpO1xuICB0aGlzLmhhc2ggPSBvcHRpb25zLmhhc2g7XG4gIHRoaXMucHJlZFJlc2lzdCA9ICEhb3B0aW9ucy5wcmVkUmVzaXN0O1xuXG4gIHRoaXMub3V0TGVuID0gdGhpcy5oYXNoLm91dFNpemU7XG4gIHRoaXMubWluRW50cm9weSA9IG9wdGlvbnMubWluRW50cm9weSB8fCB0aGlzLmhhc2guaG1hY1N0cmVuZ3RoO1xuXG4gIHRoaXMucmVzZWVkID0gbnVsbDtcbiAgdGhpcy5yZXNlZWRJbnRlcnZhbCA9IG51bGw7XG4gIHRoaXMuSyA9IG51bGw7XG4gIHRoaXMuViA9IG51bGw7XG5cbiAgdmFyIGVudHJvcHkgPSB1dGlscy50b0FycmF5KG9wdGlvbnMuZW50cm9weSwgb3B0aW9ucy5lbnRyb3B5RW5jKTtcbiAgdmFyIG5vbmNlID0gdXRpbHMudG9BcnJheShvcHRpb25zLm5vbmNlLCBvcHRpb25zLm5vbmNlRW5jKTtcbiAgdmFyIHBlcnMgPSB1dGlscy50b0FycmF5KG9wdGlvbnMucGVycywgb3B0aW9ucy5wZXJzRW5jKTtcbiAgYXNzZXJ0KGVudHJvcHkubGVuZ3RoID49ICh0aGlzLm1pbkVudHJvcHkgLyA4KSxcbiAgICAgICAgICdOb3QgZW5vdWdoIGVudHJvcHkuIE1pbmltdW0gaXM6ICcgKyB0aGlzLm1pbkVudHJvcHkgKyAnIGJpdHMnKTtcbiAgdGhpcy5faW5pdChlbnRyb3B5LCBub25jZSwgcGVycyk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEhtYWNEUkJHO1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX2luaXQgPSBmdW5jdGlvbiBpbml0KGVudHJvcHksIG5vbmNlLCBwZXJzKSB7XG4gIHZhciBzZWVkID0gZW50cm9weS5jb25jYXQobm9uY2UpLmNvbmNhdChwZXJzKTtcblxuICB0aGlzLksgPSBuZXcgQXJyYXkodGhpcy5vdXRMZW4gLyA4KTtcbiAgdGhpcy5WID0gbmV3IEFycmF5KHRoaXMub3V0TGVuIC8gOCk7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5WLmxlbmd0aDsgaSsrKSB7XG4gICAgdGhpcy5LW2ldID0gMHgwMDtcbiAgICB0aGlzLlZbaV0gPSAweDAxO1xuICB9XG5cbiAgdGhpcy5fdXBkYXRlKHNlZWQpO1xuICB0aGlzLnJlc2VlZCA9IDE7XG4gIHRoaXMucmVzZWVkSW50ZXJ2YWwgPSAweDEwMDAwMDAwMDAwMDA7ICAvLyAyXjQ4XG59O1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX2htYWMgPSBmdW5jdGlvbiBobWFjKCkge1xuICByZXR1cm4gbmV3IGhhc2guaG1hYyh0aGlzLmhhc2gsIHRoaXMuSyk7XG59O1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX3VwZGF0ZSA9IGZ1bmN0aW9uIHVwZGF0ZShzZWVkKSB7XG4gIHZhciBrbWFjID0gdGhpcy5faG1hYygpXG4gICAgICAgICAgICAgICAgIC51cGRhdGUodGhpcy5WKVxuICAgICAgICAgICAgICAgICAudXBkYXRlKFsgMHgwMCBdKTtcbiAgaWYgKHNlZWQpXG4gICAga21hYyA9IGttYWMudXBkYXRlKHNlZWQpO1xuICB0aGlzLksgPSBrbWFjLmRpZ2VzdCgpO1xuICB0aGlzLlYgPSB0aGlzLl9obWFjKCkudXBkYXRlKHRoaXMuVikuZGlnZXN0KCk7XG4gIGlmICghc2VlZClcbiAgICByZXR1cm47XG5cbiAgdGhpcy5LID0gdGhpcy5faG1hYygpXG4gICAgICAgICAgICAgICAudXBkYXRlKHRoaXMuVilcbiAgICAgICAgICAgICAgIC51cGRhdGUoWyAweDAxIF0pXG4gICAgICAgICAgICAgICAudXBkYXRlKHNlZWQpXG4gICAgICAgICAgICAgICAuZGlnZXN0KCk7XG4gIHRoaXMuViA9IHRoaXMuX2htYWMoKS51cGRhdGUodGhpcy5WKS5kaWdlc3QoKTtcbn07XG5cbkhtYWNEUkJHLnByb3RvdHlwZS5yZXNlZWQgPSBmdW5jdGlvbiByZXNlZWQoZW50cm9weSwgZW50cm9weUVuYywgYWRkLCBhZGRFbmMpIHtcbiAgLy8gT3B0aW9uYWwgZW50cm9weSBlbmNcbiAgaWYgKHR5cGVvZiBlbnRyb3B5RW5jICE9PSAnc3RyaW5nJykge1xuICAgIGFkZEVuYyA9IGFkZDtcbiAgICBhZGQgPSBlbnRyb3B5RW5jO1xuICAgIGVudHJvcHlFbmMgPSBudWxsO1xuICB9XG5cbiAgZW50cm9weSA9IHV0aWxzLnRvQnVmZmVyKGVudHJvcHksIGVudHJvcHlFbmMpO1xuICBhZGQgPSB1dGlscy50b0J1ZmZlcihhZGQsIGFkZEVuYyk7XG5cbiAgYXNzZXJ0KGVudHJvcHkubGVuZ3RoID49ICh0aGlzLm1pbkVudHJvcHkgLyA4KSxcbiAgICAgICAgICdOb3QgZW5vdWdoIGVudHJvcHkuIE1pbmltdW0gaXM6ICcgKyB0aGlzLm1pbkVudHJvcHkgKyAnIGJpdHMnKTtcblxuICB0aGlzLl91cGRhdGUoZW50cm9weS5jb25jYXQoYWRkIHx8IFtdKSk7XG4gIHRoaXMucmVzZWVkID0gMTtcbn07XG5cbkhtYWNEUkJHLnByb3RvdHlwZS5nZW5lcmF0ZSA9IGZ1bmN0aW9uIGdlbmVyYXRlKGxlbiwgZW5jLCBhZGQsIGFkZEVuYykge1xuICBpZiAodGhpcy5yZXNlZWQgPiB0aGlzLnJlc2VlZEludGVydmFsKVxuICAgIHRocm93IG5ldyBFcnJvcignUmVzZWVkIGlzIHJlcXVpcmVkJyk7XG5cbiAgLy8gT3B0aW9uYWwgZW5jb2RpbmdcbiAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnKSB7XG4gICAgYWRkRW5jID0gYWRkO1xuICAgIGFkZCA9IGVuYztcbiAgICBlbmMgPSBudWxsO1xuICB9XG5cbiAgLy8gT3B0aW9uYWwgYWRkaXRpb25hbCBkYXRhXG4gIGlmIChhZGQpIHtcbiAgICBhZGQgPSB1dGlscy50b0FycmF5KGFkZCwgYWRkRW5jKTtcbiAgICB0aGlzLl91cGRhdGUoYWRkKTtcbiAgfVxuXG4gIHZhciB0ZW1wID0gW107XG4gIHdoaWxlICh0ZW1wLmxlbmd0aCA8IGxlbikge1xuICAgIHRoaXMuViA9IHRoaXMuX2htYWMoKS51cGRhdGUodGhpcy5WKS5kaWdlc3QoKTtcbiAgICB0ZW1wID0gdGVtcC5jb25jYXQodGhpcy5WKTtcbiAgfVxuXG4gIHZhciByZXMgPSB0ZW1wLnNsaWNlKDAsIGxlbik7XG4gIHRoaXMuX3VwZGF0ZShhZGQpO1xuICB0aGlzLnJlc2VlZCsrO1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHJlcywgZW5jKTtcbn07XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHtcbiAgZG91Ymxlczoge1xuICAgIHN0ZXA6IDQsXG4gICAgcG9pbnRzOiBbXG4gICAgICBbXG4gICAgICAgICdlNjBmY2U5M2I1OWU5ZWM1MzAxMWFhYmMyMWMyM2U5N2IyYTMxMzY5Yjg3YTVhZTljNDRlZTg5ZTJhNmRlYzBhJyxcbiAgICAgICAgJ2Y3ZTM1MDczOTllNTk1OTI5ZGI5OWYzNGY1NzkzNzEwMTI5Njg5MWU0NGQyM2YwYmUxZjMyY2NlNjk2MTY4MjEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnODI4MjI2MzIxMmM2MDlkOWVhMmE2ZTNlMTcyZGUyMzhkOGMzOWNhYmQ1YWMxY2ExMDY0NmUyM2ZkNWY1MTUwOCcsXG4gICAgICAgICcxMWY4YTgwOTg1NTdkZmU0NWU4MjU2ZTgzMGI2MGFjZTYyZDYxM2FjMmY3YjE3YmVkMzFiNmVhZmY2ZTI2Y2FmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzE3NWUxNTlmNzI4Yjg2NWE3MmY5OWNjNmM2ZmM4NDZkZTBiOTM4MzNmZDIyMjJlZDczZmNlNWI1NTFlNWI3MzknLFxuICAgICAgICAnZDM1MDZlMGQ5ZTNjNzllYmE0ZWY5N2E1MWZmNzFmNWVhY2I1OTU1YWRkMjQzNDVjNmVmYTZmZmVlOWZlZDY5NSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNjNkOTBkNDQ3YjAwYzljOTljZWFjMDViNjI2MmVlMDUzNDQxYzdlNTU1NTJmZmU1MjZiYWQ4ZjgzZmY0NjQwJyxcbiAgICAgICAgJzRlMjczYWRmYzczMjIyMTk1M2I0NDUzOTdmMzM2MzE0NWI5YTg5MDA4MTk5ZWNiNjIwMDNjN2YzYmVlOWRlOSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4YjRiNWYxNjVkZjNjMmJlOGM2MjQ0YjViNzQ1NjM4ODQzZTRhNzgxYTE1YmNkMWI2OWY3OWE1NWRmZmRmODBjJyxcbiAgICAgICAgJzRhYWQwYTZmNjhkMzA4YjRiM2ZiZDc4MTNhYjBkYTA0ZjllMzM2NTQ2MTYyZWU1NmIzZWZmMGM2NWZkNGZkMzYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzIzY2JhYTZlNWRiOTk2ZDZiZjc3MWMwMGJkNTQ4YzdiNzAwZGJmZmE2YzBlNzdiY2I2MTE1OTI1MjMyZmNkYScsXG4gICAgICAgICc5NmU4NjdiNTU5NWNjNDk4YTkyMTEzNzQ4ODgyNGQ2ZTI2NjBhMDY1Mzc3OTQ5NDgwMWRjMDY5ZDllYjM5ZjVmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2VlYmZhNGQ0OTNiZWJmOThiYTVmZWVjODEyYzJkM2I1MDk0Nzk2MTIzN2E5MTk4MzlhNTMzZWNhMGU3ZGQ3ZmEnLFxuICAgICAgICAnNWQ5YThjYTM5NzBlZjBmMjY5ZWU3ZWRhZjE3ODA4OWQ5YWU0Y2RjM2E3MTFmNzEyZGRmZDRmZGFlMWRlODk5OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxMDBmNDRkYTY5NmU3MTY3Mjc5MWQwYTA5YjdiZGU0NTlmMTIxNWEyOWIzYzAzYmZlZmQ3ODM1YjM5YTQ4ZGIwJyxcbiAgICAgICAgJ2NkZDllMTMxOTJhMDBiNzcyZWM4ZjMzMDBjMDkwNjY2YjdmZjRhMThmZjUxOTVhYzBmYmQ1Y2Q2MmJjNjVhMDknXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTEwMzFiZTI2MmM3ZWQxYjFkYzkyMjdhNGEwNGMwMTdhNzdmOGQ0NDY0ZjNiMzg1MmM4YWNkZTZlNTM0ZmQyZCcsXG4gICAgICAgICc5ZDcwNjE5Mjg5NDA0MDVlNmJiNmE0MTc2NTk3NTM1YWYyOTJkZDQxOWUxY2VkNzlhNDRmMThmMjk0NTZhMDBkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2ZlZWE2Y2FlNDZkNTViNTMwYWMyODM5ZjE0M2JkN2VjNWNmOGIyNjZhNDFkNmFmNTJkNWU2ODhkOTA5NDY5NmQnLFxuICAgICAgICAnZTU3YzZiNmM5N2RjZTFiYWIwNmU0ZTEyYmYzZWNkNWM5ODFjODk1N2NjNDE0NDJkMzE1NWRlYmYxODA5MDA4OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkYTY3YTkxZDkxMDQ5Y2RjYjM2N2JlNGJlNmZmY2EzY2ZlZWQ2NTdkODA4NTgzZGUzM2ZhOTc4YmMxZWM2Y2IxJyxcbiAgICAgICAgJzliYWNhYTM1NDgxNjQyYmM0MWY0NjNmN2VjOTc4MGU1ZGVjN2FkYzUwOGY3NDBhMTdlOWVhOGUyN2E2OGJlMWQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNTM5MDRmYWEwYjMzNGNkZGE2ZTAwMDkzNWVmMjIxNTFlYzA4ZDBmN2JiMTEwNjlmNTc1NDVjY2MxYTM3YjdjMCcsXG4gICAgICAgICc1YmMwODdkMGJjODAxMDZkODhjOWVjY2FjMjBkM2MxYzEzOTk5OTgxZTE0NDM0Njk5ZGNiMDk2YjAyMjc3MWM4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhlN2JjZDBiZDM1OTgzYTc3MTljY2E3NzY0Y2E5MDY3NzliNTNhMDQzYTliOGJjYWVmZjk1OWY0M2FkODYwNDcnLFxuICAgICAgICAnMTBiNzc3MGIyYTNkYTRiMzk0MDMxMDQyMGNhOTUxNDU3OWU4OGUyZTQ3ZmQ2OGIzZWExMDA0N2U4NDYwMzcyYSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczODVlZWQzNGMxY2RmZjIxZTZkMDgxODY4OWI4MWJkZTcxYTdmNGYxODM5N2U2NjkwYTg0MWUxNTk5YzQzODYyJyxcbiAgICAgICAgJzI4M2JlYmMzZThlYTIzZjU2NzAxZGUxOWU5ZWJmNDU3NmIzMDRlZWMyMDg2ZGM4Y2MwNDU4ZmU1NTQyZTU0NTMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNmY5ZDliODAzZWNmMTkxNjM3YzczYTQ0MTNkZmExODBmZGRmODRhNTk0N2ZiYzljNjA2ZWQ4NmMzZmFjM2E3JyxcbiAgICAgICAgJzdjODBjNjhlNjAzMDU5YmE2OWI4ZTJhMzBlNDVjNGQ0N2VhNGRkMmY1YzI4MTAwMmQ4Njg5MDYwM2E4NDIxNjAnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzMyMmQ0MDEyNDNjNGUyNTgyYTIxNDdjMTA0ZDZlY2JmNzc0ZDE2M2RiMGY1ZTUzMTNiN2UwZTc0MmQwZTZiZCcsXG4gICAgICAgICc1NmU3MDc5N2U5NjY0ZWY1YmZiMDE5YmM0ZGRhZjliNzI4MDVmNjNlYTI4NzNhZjYyNGYzYTJlOTZjMjhiMmEwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzg1NjcyYzdkMmRlMGI3ZGEyYmQxNzcwZDg5NjY1ODY4NzQxYjNmOWFmNzY0MzM5NzcyMWQ3NGQyODEzNGFiODMnLFxuICAgICAgICAnN2M0ODFiOWI1YjQzYjJlYjYzNzQwNDliZmE2MmMyZTVlNzdmMTdmY2M1Mjk4ZjQ0YzhlMzA5NGY3OTAzMTNhNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5NDhiZjgwOWIxOTg4YTQ2YjA2YzlmMTkxOTQxM2IxMGY5MjI2YzYwZjY2ODgzMmZmZDk1OWFmNjBjODJhMGEnLFxuICAgICAgICAnNTNhNTYyODU2ZGNiNjY0NmRjNmI3NGM1ZDFjMzQxOGM2ZDRkZmYwOGM5N2NkMmJlZDRjYjdmODhkOGM4ZTU4OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2MjYwY2U3ZjQ2MTgwMWMzNGYwNjdjZTBmMDI4NzNhOGYxYjBlNDRkZmM2OTc1MmFjY2VjZDgxOWYzOGZkOGU4JyxcbiAgICAgICAgJ2JjMmRhODJiNmZhNWI1NzFhN2YwOTA0OTc3NmExZWY3ZWNkMjkyMjM4MDUxYzE5OGMxYTg0ZTk1YjJiNGFlMTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTUwMzdkZTBhZmMxZDhkNDNkODM0ODQxNGJiZjQxMDMwNDNlYzhmNTc1YmZkYzQzMjk1M2NjOGQyMDM3ZmEyZCcsXG4gICAgICAgICc0NTcxNTM0YmFhOTRkM2I1ZjlmOThkMDlmYjk5MGJkZGJkNWY1YjAzZWM0ODFmMTBlMGU1ZGM4NDFkNzU1YmRhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UwNjM3MmIwZjRhMjA3YWRmNWVhOTA1ZThmMTc3MWI0ZTdlOGRiZDFjNmE2YzViNzI1ODY2YTBhZTRmY2U3MjUnLFxuICAgICAgICAnN2E5MDg5NzRiY2UxOGNmZTEyYTI3YmIyYWQ1YTQ4OGNkNzQ4NGE3Nzg3MTA0ODcwYjI3MDM0Zjk0ZWVlMzFkZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyMTNjN2E3MTVjZDVkNDUzNThkMGJiZjlkYzBjZTAyMjA0YjEwYmRkZTJhM2Y1ODU0MGFkNjkwOGQwNTU5NzU0JyxcbiAgICAgICAgJzRiNmRhZDBiNWFlNDYyNTA3MDEzYWQwNjI0NWJhMTkwYmI0ODUwZjVmMzZhN2VlZGRmZjJjMjc1MzRiNDU4ZjInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNGU3YzI3MmE3YWY0YjM0ZThkYmI5MzUyYTU0MTlhODdlMjgzOGM3MGFkYzYyY2RkZjBjYzNhM2IwOGZiZDUzYycsXG4gICAgICAgICcxNzc0OWM3NjZjOWQwYjE4ZTE2ZmQwOWY2ZGVmNjgxYjUzMGI5NjE0YmZmN2RkMzNlMGIzOTQxODE3ZGNhYWU2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2ZlYTc0ZTNkYmU3NzhiMWIxMGYyMzhhZDYxNjg2YWE1Yzc2ZTNkYjJiZTQzMDU3NjMyNDI3ZTI4NDBmYjI3YjYnLFxuICAgICAgICAnNmUwNTY4ZGI5YjBiMTMyOTdjZjY3NGRlY2NiNmFmOTMxMjZiNTk2Yjk3M2Y3Yjc3NzAxZDNkYjdmMjNjYjk2ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3NmU2NDExM2Y2NzdjZjBlMTBhMjU3MGQ1OTk5NjhkMzE1NDRlMTc5Yjc2MDQzMjk1MmMwMmE0NDE3YmRkZTM5JyxcbiAgICAgICAgJ2M5MGRkZjhkZWU0ZTk1Y2Y1NzcwNjZkNzA2ODFmMGQzNWUyYTMzZDJiNTZkMjAzMmI0YjE3NTJkMTkwMWFjMDEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYzczOGM1NmIwM2IyYWJlMWU4MjgxYmFhNzQzZjhmOWE4ZjdjYzY0M2RmMjZjYmVlM2FiMTUwMjQyYmNiYjg5MScsXG4gICAgICAgICc4OTNmYjU3ODk1MWFkMjUzN2Y3MThmMmVhY2JmYmJiYjgyMzE0ZWVmNzg4MGNmZTkxN2U3MzVkOTY5OWE4NGMzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2Q4OTU2MjY1NDhiNjViODFlMjY0Yzc2MzdjOTcyODc3ZDFkNzJlNWYzYTkyNTAxNDM3MmU5ZjY1ODhmNmMxNGInLFxuICAgICAgICAnZmViZmFhMzhmMmJjN2VhZTcyOGVjNjA4MThjMzQwZWIwMzQyOGQ2MzJiYjA2N2UxNzkzNjNlZDc1ZDdkOTkxZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiOGRhOTQwMzJhOTU3NTE4ZWIwZjY0MzM1NzFlODc2MWNlZmZjNzM2OTNlODRlZGQ0OTE1MGE1NjRmNjc2ZTAzJyxcbiAgICAgICAgJzI4MDRkZmE0NDgwNWExZTRkN2M5OWNjOTc2MjgwOGIwOTJjYzU4NGQ5NWZmM2I1MTE0ODhlNGU3NGVmZGY2ZTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTgwZmVhMTQ0NDFmYjMzYTdkOGFkYWI5NDc1ZDdmYWIyMDE5ZWZmYjUxNTZhNzkyZjFhMTE3NzhlM2MwZGY1ZCcsXG4gICAgICAgICdlZWQxZGU3ZjYzOGUwMDc3MWU4OTc2OGNhM2NhOTQ0NzJkMTU1ZTgwYWYzMjJlYTlmY2I0MjkxYjZhYzllYzc4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2EzMDE2OTdiZGZjZDcwNDMxM2JhNDhlNTFkNTY3NTQzZjJhMTgyMDMxZWZkNjkxNWRkYzA3YmJjYzRlMTYwNzAnLFxuICAgICAgICAnNzM3MGY5MWNmYjY3ZTRmNTA4MTgwOWZhMjVkNDBmOWIxNzM1ZGJmN2MwYTExYTEzMGMwZDFhMDQxZTE3N2VhMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5MGFkODViMzg5ZDZiOTM2NDYzZjlkMDUxMjY3OGRlMjA4Y2MzMzBiMTEzMDdmZmZhYjdhYzYzZTNmYjA0ZWQ0JyxcbiAgICAgICAgJ2U1MDdhMzYyMGEzODI2MWFmZmRjYmQ5NDI3MjIyYjgzOWFlZmFiZTE1ODI4OTRkOTkxZDRkNDhjYjZlZjE1MCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4ZjY4YjlkMmY2M2I1ZjMzOTIzOWMxYWQ5ODFmMTYyZWU4OGM1Njc4NzIzZWEzMzUxYjdiNDQ0YzllYzRjMGRhJyxcbiAgICAgICAgJzY2MmE5ZjJkYmEwNjM5ODZkZTFkOTBjMmI2YmUyMTVkYmJlYTJjZmU5NTUxMGJmZGYyM2NiZjc5NTAxZmZmODInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTRmM2ZiMDE3NmFmODVkNjVmZjk5ZmY5MTk4YzM2MDkxZjQ4ZTg2NTAzNjgxZTNlNjY4NmZkNTA1MzIzMWUxMScsXG4gICAgICAgICcxZTYzNjMzYWQwZWY0ZjFjMTY2MWE2ZDBlYTAyYjcyODZjYzdlNzRlYzk1MWQxYzk4MjJjMzg1NzZmZWI3M2JjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhjMDBmYTliMThlYmYzMzFlYjk2MTUzN2E0NWE0MjY2YzcwMzRmMmYwZDRlMWQwNzE2ZmI2ZWFlMjBlYWUyOWUnLFxuICAgICAgICAnZWZhNDcyNjdmZWE1MjFhMWE5ZGMzNDNhMzczNmM5NzRjMmZhZGFmYTgxZTM2YzU0ZTdkMmE0YzY2NzAyNDE0YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlN2EyNmNlNjlkZDQ4MjlmM2UxMGNlYzBhOWU5OGVkMzE0M2QwODRmMzA4YjkyYzA5OTdmZGRmYzYwY2IzZTQxJyxcbiAgICAgICAgJzJhNzU4ZTMwMGZhNzk4NGI0NzFiMDA2YTFhYWZiYjE4ZDBhNmIyYzA0MjBlODNlMjBlOGE5NDIxY2YyY2ZkNTEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYjY0NTllMGVlMzY2MmVjOGQyMzU0MGMyMjNiY2JkYzU3MWNiY2I5NjdkNzk0MjRmM2NmMjllYjNkZTZiODBlZicsXG4gICAgICAgICc2N2M4NzZkMDZmM2UwNmRlMWRhZGYxNmU1NjYxZGIzYzRiM2FlNmQ0OGUzNWIyZmYzMGJmMGI2MWE3MWJhNDUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDY4YTgwYzgyODBiYjg0MDc5MzIzNGFhMTE4ZjA2MjMxZDZmMWZjNjdlNzNjNWE1ZGVkYTBmNWI0OTY5NDNlOCcsXG4gICAgICAgICdkYjhiYTlmZmY0YjU4NmQwMGM0YjFmOTE3N2IwZTI4YjViMGU3YjhmNzg0NTI5NWEyOTRjODQyNjZiMTMzMTIwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyNGFlZDdkZjY1YzgwNDI1MmRjMDI3MDkwN2EzMGIwOTYxMmFlYjk3MzQ0OWNlYTQwOTU5ODBmYzI4ZDNkNWQnLFxuICAgICAgICAnNjQ4YTM2NTc3NGI2MWYyZmYxMzBjMGMzNWFlYzFmNGYxOTIxM2IwYzdlMzMyODQzOTY3MjI0YWY5NmFiN2M4NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc0ZGY5YzE0OTE5Y2RlNjFmNmQ1MWRmZGJlNWZlZTVkY2VlYzQxNDNiYThkMWNhODg4ZThiZDM3M2ZkMDU0Yzk2JyxcbiAgICAgICAgJzM1ZWM1MTA5MmQ4NzI4MDUwOTc0YzIzYTFkODVkNGI1ZDUwNmNkYzI4ODQ5MDE5MmViYWMwNmNhZDEwZDVkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzljMzkxOWE4NGE0NzQ4NzBmYWVkOGE5YzFjYzY2MDIxNTIzNDg5MDU0ZDdmMDMwOGNiZmM5OWM4YWMxZjk4Y2QnLFxuICAgICAgICAnZGRiODRmMGY0YTRkZGQ1NzU4NGYwNDRiZjI2MGU2NDE5MDUzMjZmNzZjNjRjOGU2YmU3ZTVlMDNkNGZjNTk5ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2MDU3MTcwYjFkZDEyZmRmOGRlMDVmMjgxZDhlMDZiYjkxZTE0OTNhOGI5MWQ0Y2M1YTIxMzgyMTIwYTk1OWU1JyxcbiAgICAgICAgJzlhMWFmMGIyNmE2YTQ4MDdhZGQ5YTJkYWY3MWRmMjYyNDY1MTUyYmMzZWUyNGM2NWU4OTliZTkzMjM4NWEyYTgnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTU3NmRmOGUyM2EwODQxMTQyMTQzOWE0NTE4ZGEzMTg4MGNlZjBmYmE3ZDRkZjEyYjFhNjk3M2VlY2I5NDI2NicsXG4gICAgICAgICc0MGE2YmYyMGU3NjY0MGIyYzkyYjk3YWZlNThjZDgyYzQzMmUxMGE3ZjUxNGQ5ZjNlZThiZTExYWUxYjI4ZWM4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3NzhhNzhjMjhkZWMzZTMwYTA1ZmU5NjI5ZGU4YzM4YmIzMGQxZjVjZjlhM2EyMDhmNzYzODg5YmU1OGFkNzEnLFxuICAgICAgICAnMzQ2MjZkOWFiNWE1YjIyZmY3MDk4ZTEyZjJmZjU4MDA4N2IzODQxMWZmMjRhYzU2M2I1MTNmYzFmZDlmNDNhYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5Mjg5NTVlZTYzN2E4NDQ2MzcyOWZkMzBlN2FmZDJlZDVmOTYyNzRlNWFkN2U1Y2IwOWVkYTljMDZkOTAzYWMnLFxuICAgICAgICAnYzI1NjIxMDAzZDNmNDJhODI3Yjc4YTEzMDkzYTk1ZWVhYzNkMjZlZmE4YThkODNmYzUxODBlOTM1YmNkMDkxZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NWQwZmVmM2VjNmRiMTA5Mzk5MDY0ZjNhMGUzYjI4NTU2NDViNGE5MDdhZDM1NDUyN2FhZTc1MTYzZDgyNzUxJyxcbiAgICAgICAgJzFmMDM2NDg0MTNhMzhjMGJlMjlkNDk2ZTU4MmNmNTY2M2U4NzUxZTk2ODc3MzMxNTgyYzIzN2EyNGViMWY5NjInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmYyYjBkY2U5N2VlY2U5N2MxYzliNjA0MTc5OGI4NWRmZGZiNmQ4ODgyZGEyMDMwOGY1NDA0ODI0NTI2MDg3ZScsXG4gICAgICAgICc0OTNkMTNmZWY1MjRiYTE4OGFmNGM0ZGM1NGQwNzkzNmM3YjdlZDZmYjkwZTJjZWIyYzk1MWUwMWYwYzI5OTA3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzgyN2ZiYmU0YjFlODgwZWE5ZWQyYjJlNjMwMWIyMTJiNTdmMWVlMTQ4Y2Q2ZGQyODc4MGU1ZTJjZjg1NmUyNDEnLFxuICAgICAgICAnYzYwZjljOTIzYzcyN2IwYjcxYmVmMmM2N2QxZDEyNjg3ZmY3YTYzMTg2OTAzMTY2ZDYwNWI2OGJhZWMyOTNlYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYWE2NDlmMjFmNTFiZGJhZTdiZTRhZTM0Y2U2ZTUyMTdhNThmZGNlN2Y0N2Y5YWE3ZjNiNThmYTIxMjBlMmIzJyxcbiAgICAgICAgJ2JlMzI3OWVkNWJiYmIwM2FjNjlhODBmODk4NzlhYTVhMDFhNmI5NjVmMTNmN2U1OWQ0N2E1MzA1YmE1YWQ5M2QnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTRhNDJkNDNjNWNmMTY5ZDkzOTFkZjZkZWNmNDJlZTU0MWI2ZDhmMGM5YTEzNzQwMWUyMzYzMmRkYTM0ZDI0ZicsXG4gICAgICAgICc0ZDlmOTJlNzE2ZDFjNzM1MjZmYzk5Y2NmYjhhZDM0Y2U4ODZlZWRmYThkOGU0ZjEzYTdmNzEzMWRlYmE5NDE0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzFlYzgwZmVmMzYwY2JkZDk1NDE2MGZhZGFiMzUyYjZiOTJiNTM1NzZhODhmZWE0OTQ3MTczYjlkNDMwMGJmMTknLFxuICAgICAgICAnYWVlZmU5Mzc1NmI1MzQwZDJmM2E0OTU4YTdhYmJmNWUwMTQ2ZTc3ZjYyOTVhMDdiNjcxY2RjMWNjMTA3Y2VmZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNDZhNzc4YzA0NjcwYzJmOTFiMDBhZjQ2ODBkZmE4YmNlMzQ5MDcxN2Q1OGJhODg5ZGRiNTkyODM2NjY0MmJlJyxcbiAgICAgICAgJ2IzMThlMGVjMzM1NDAyOGFkZDY2OTgyN2Y5ZDRiMjg3MGFhYTk3MWQyZjdlNWVkMWQwYjI5NzQ4M2Q4M2VmZDAnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmE1MGMwZjYxZDIyZTVmMDdlM2FjZWJiMWFhMDdiMTI4ZDAwMTIyMDlhMjhiOTc3NmQ3NmE4NzkzMTgwZWVmOScsXG4gICAgICAgICc2Yjg0YzY5MjIzOTdlYmE5YjcyY2QyODcyMjgxYTY4YTVlNjgzMjkzYTU3YTIxM2IzOGNkOGQ3ZDNmNGYyODExJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2RhMWQ2MWQwY2E3MjFhMTFiMWE1YmY2YjdkODhlODQyMWEyODhhYjVkNWJiYTUyMjBlNTNkMzJiNWYwNjdlYzInLFxuICAgICAgICAnODE1N2Y1NWE3Yzk5MzA2Yzc5YzA3NjYxNjFjOTFlMjk2NmE3Mzg5OWQyNzliNDhhNjU1ZmJhMGYxYWQ4MzZmMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhOGUyODJmZjBjOTcwNjkwNzIxNWZmOThlOGZkNDE2NjE1MzExZGUwNDQ2ZjFlMDYyYTczYjA2MTBkMDY0ZTEzJyxcbiAgICAgICAgJzdmOTczNTViOGRiODFjMDlhYmZiN2YzYzViMjUxNTg4OGI2NzlhM2U1MGRkNmJkNmNlZjdjNzMxMTFmNGNjMGMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTc0YTUzYjljOWEyODU4NzJkMzllNTZlNjkxM2NhYjE1ZDU5YjFmYTUxMjUwOGMwMjJmMzgyZGU4MzE5NDk3YycsXG4gICAgICAgICdjY2M5ZGMzN2FiZmM5YzE2NTdiNDE1NWYyYzQ3ZjllNjY0NmIzYTFkOGNiOTg1NDM4M2RhMTNhYzA3OWFmYTczJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzk1OTM5Njk4MTk0Mzc4NWMzZDNlNTdlZGY1MDE4Y2RiZTAzOWU3MzBlNDkxOGIzZDg4NGZkZmYwOTQ3NWI3YmEnLFxuICAgICAgICAnMmU3ZTU1Mjg4OGMzMzFkZDhiYTAzODZhNGI5Y2Q2ODQ5YzY1M2Y2NGM4NzA5Mzg1ZTliOGFiZjg3NTI0ZjJmZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkMmE2M2E1MGFlNDAxZTU2ZDY0NWExMTUzYjEwOWE4ZmNjYTBhNDNkNTYxZmJhMmRiYjUxMzQwYzlkODJiMTUxJyxcbiAgICAgICAgJ2U4MmQ4NmZiNjQ0M2ZjYjc1NjVhZWU1OGIyOTQ4MjIwYTcwZjc1MGFmNDg0Y2E1MmQ0MTQyMTc0ZGNmODk0MDUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNjQ1ODdlMjMzNTQ3MWViODkwZWU3ODk2ZDdjZmRjODY2YmFjYmRiZDM4MzkzMTdiMzQzNmY5YjQ1NjE3ZTA3MycsXG4gICAgICAgICdkOTlmY2RkNWJmNjkwMmUyYWU5NmRkNjQ0N2MyOTlhMTg1YjkwYTM5MTMzYWVhYjM1ODI5OWU1ZTlmYWY2NTg5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzg0ODFiZGUwZTRlNGQ4ODViM2E1NDZkM2U1NDlkZTA0MmYwYWE2Y2VhMjUwZTdmZDM1OGQ2Yzg2ZGQ0NWU0NTgnLFxuICAgICAgICAnMzhlZTdiOGNiYTU0MDRkZDg0YTI1YmYzOWNlY2IyY2E5MDBhNzljNDJiMjYyZTU1NmQ2NGIxYjU5Nzc5MDU3ZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxMzQ2NGE1N2E3ODEwMmFhNjJiNjk3OWFlODE3ZjQ2MzdmZmNmZWQzYzRiMWNlMzBiY2Q2MzAzZjZjYWY2NjZiJyxcbiAgICAgICAgJzY5YmUxNTkwMDQ2MTQ1ODBlZjdlNDMzNDUzY2NiMGNhNDhmMzAwYTgxZDA5NDJlMTNmNDk1YTkwN2Y2ZWNjMjcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYmM0YTlkZjViNzEzZmUyZTlhZWY0MzBiY2MxZGM5N2EwY2Q5Y2NlZGUyZjI4NTg4Y2FkYTNhMGQyZDgzZjM2NicsXG4gICAgICAgICdkM2E4MWNhNmU3ODVjMDYzODM5MzdhZGY0Yjc5OGNhYTZlOGE5ZmJmYTU0N2IxNmQ3NThkNjY2NTgxZjMzYzEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnOGMyOGE5N2JmODI5OGJjMGQyM2Q4Yzc0OTQ1MmEzMmU2OTRiNjVlMzBhOTQ3MmEzOTU0YWIzMGZlNTMyNGNhYScsXG4gICAgICAgICc0MGEzMDQ2M2EzMzA1MTkzMzc4ZmVkZjMxZjdjYzBlYjdhZTc4NGYwNDUxY2I5NDU5ZTcxZGM3M2NiZWY5NDgyJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhlYTk2NjYxMzk1MjdhOGMxZGQ5NGNlNGYwNzFmZDIzYzhiMzUwYzVhNGJiMzM3NDhjNGJhMTExZmFjY2FlMCcsXG4gICAgICAgICc2MjBlZmFiYmM4ZWUyNzgyZTI0ZTdjMGNmYjk1YzVkNzM1Yjc4M2JlOWNmMGY4ZTk1NWFmMzRhMzBlNjJiOTQ1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2RkMzYyNWZhZWY1YmEwNjA3NDY2OTcxNmJiZDM3ODhkODliZGRlODE1OTU5OTY4MDkyZjc2Y2M0ZWI5YTk3ODcnLFxuICAgICAgICAnN2ExODhmYTM1MjBlMzBkNDYxZGEyNTAxMDQ1NzMxY2E5NDE0NjE5ODI4ODMzOTU5MzdmNjhkMDBjNjQ0YTU3MydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmNzEwZDc5ZDllYjk2MjI5N2U0ZjYyMzJiNDBlOGY3ZmViMmJjNjM4MTQ2MTRkNjkyYzEyZGU3NTI0MDgyMjFlJyxcbiAgICAgICAgJ2VhOThlNjcyMzJkM2IzMjk1ZDNiNTM1NTMyMTE1Y2NhYzg2MTJjNzIxODUxNjE3NTI2YWU0N2E5Yzc3YmZjODInXG4gICAgICBdXG4gICAgXVxuICB9LFxuICBuYWY6IHtcbiAgICB3bmQ6IDcsXG4gICAgcG9pbnRzOiBbXG4gICAgICBbXG4gICAgICAgICdmOTMwOGEwMTkyNThjMzEwNDkzNDRmODVmODlkNTIyOWI1MzFjODQ1ODM2Zjk5YjA4NjAxZjExM2JjZTAzNmY5JyxcbiAgICAgICAgJzM4OGY3YjBmNjMyZGU4MTQwZmUzMzdlNjJhMzdmMzU2NjUwMGE5OTkzNGMyMjMxYjZjYjlmZDc1ODRiOGU2NzInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMmY4YmRlNGQxYTA3MjA5MzU1YjRhNzI1MGE1YzUxMjhlODhiODRiZGRjNjE5YWI3Y2JhOGQ1NjliMjQwZWZlNCcsXG4gICAgICAgICdkOGFjMjIyNjM2ZTVlM2Q2ZDRkYmE5ZGRhNmM5YzQyNmY3ODgyNzFiYWIwZDY4NDBkY2E4N2QzYWE2YWM2MmQ2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzVjYmRmMDY0NmU1ZGI0ZWFhMzk4ZjM2NWYyZWE3YTBlM2Q0MTliN2UwMzMwZTM5Y2U5MmJkZGVkY2FjNGY5YmMnLFxuICAgICAgICAnNmFlYmNhNDBiYTI1NTk2MGEzMTc4ZDZkODYxYTU0ZGJhODEzZDBiODEzZmRlN2I1YTUwODI2MjgwODcyNjRkYSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhY2Q0ODRlMmYwYzdmNjUzMDlhZDE3OGE5ZjU1OWFiZGUwOTc5Njk3NGM1N2U3MTRjMzVmMTEwZGZjMjdjY2JlJyxcbiAgICAgICAgJ2NjMzM4OTIxYjBhN2Q5ZmQ2NDM4MDk3MTc2M2I2MWU5YWRkODg4YTQzNzVmOGUwZjA1Y2MyNjJhYzY0ZjljMzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzc0YWU3Zjg1OGE5NDExZTVlZjQyNDZiNzBjNjVhYWM1NjQ5OTgwYmU1YzE3ODkxYmJlYzE3ODk1ZGEwMDhjYicsXG4gICAgICAgICdkOTg0YTAzMmViNmI1ZTE5MDI0M2RkNTZkN2I3YjM2NTM3MmRiMWUyZGZmOWQ2YTgzMDFkNzRjOWM5NTNjNjFiJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2YyODc3M2MyZDk3NTI4OGJjN2QxZDIwNWMzNzQ4NjUxYjA3NWZiYzY2MTBlNThjZGRlZWRkZjhmMTk0MDVhYTgnLFxuICAgICAgICAnYWIwOTAyZThkODgwYTg5NzU4MjEyZWI2NWNkYWY0NzNhMWEwNmRhNTIxZmE5MWYyOWI1Y2I1MmRiMDNlZDgxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2Q3OTI0ZDRmN2Q0M2VhOTY1YTQ2NWFlMzA5NWZmNDExMzFlNTk0NmYzYzg1Zjc5ZTQ0YWRiY2Y4ZTI3ZTA4MGUnLFxuICAgICAgICAnNTgxZTI4NzJhODZjNzJhNjgzODQyZWMyMjhjYzZkZWZlYTQwYWYyYmQ4OTZkM2E1YzUwNGRjOWZmNmEyNmI1OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkZWZkZWE0Y2RiNjc3NzUwYTQyMGZlZTgwN2VhY2YyMWViOTg5OGFlNzliOTc2ODc2NmU0ZmFhMDRhMmQ0YTM0JyxcbiAgICAgICAgJzQyMTFhYjA2OTQ2MzUxNjhlOTk3YjBlYWQyYTkzZGFlY2VkMWY0YTA0YTk1YzBmNmNmYjE5OWY2OWU1NmViNzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMmI0ZWEwYTc5N2E0NDNkMjkzZWY1Y2ZmNDQ0ZjQ5NzlmMDZhY2ZlYmQ3ZTg2ZDI3NzQ3NTY1NjEzODM4NWI2YycsXG4gICAgICAgICc4NWU4OWJjMDM3OTQ1ZDkzYjM0MzA4M2I1YTFjODYxMzFhMDFmNjBjNTAyNjk3NjNiNTcwYzg1NGU1YzA5YjdhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzM1MmJiZjRhNGNkZDEyNTY0ZjkzZmEzMzJjZTMzMzMwMWQ5YWQ0MDI3MWY4MTA3MTgxMzQwYWVmMjViZTU5ZDUnLFxuICAgICAgICAnMzIxZWI0MDc1MzQ4ZjUzNGQ1OWMxODI1OWRkYTNlMWY0YTFiM2IyZTcxYjEwMzljNjdiZDNkOGJjZjgxOTk4YydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyZmEyMTA0ZDZiMzhkMTFiMDIzMDAxMDU1OTg3OTEyNGU0MmFiOGRmZWZmNWZmMjlkYzljZGFkZDRlY2FjYzNmJyxcbiAgICAgICAgJzJkZTEwNjgyOTVkZDg2NWI2NDU2OTMzNWJkNWRkODAxODFkNzBlY2ZjODgyNjQ4NDIzYmE3NmI1MzJiN2Q2NydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5MjQ4Mjc5YjA5YjRkNjhkYWIyMWE5YjA2NmVkZGE4MzI2M2MzZDg0ZTA5NTcyZTI2OWNhMGNkN2Y1NDUzNzE0JyxcbiAgICAgICAgJzczMDE2ZjdiZjIzNGFhZGU1ZDFhYTcxYmRlYTJiMWZmM2ZjMGRlMmE4ODc5MTJmZmU1NGEzMmNlOTdjYjM0MDInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGFlZDRmMmJlM2E4YmYyNzhlNzAxMzJmYjBiZWI3NTIyZjU3MGUxNDRiZjYxNWMwN2U5OTZkNDQzZGVlODcyOScsXG4gICAgICAgICdhNjlkY2U0YTdkNmM5OGU4ZDRhMWFjYTg3ZWY4ZDcwMDNmODNjMjMwZjNhZmE3MjZhYjQwZTUyMjkwYmUxYzU1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M0NGQxMmM3MDY1ZDgxMmU4YWNmMjhkN2NiYjE5ZjkwMTFlY2Q5ZTlmZGYyODFiMGU2YTNiNWU4N2QyMmU3ZGInLFxuICAgICAgICAnMjExOWE0NjBjZTMyNmNkYzc2YzQ1OTI2Yzk4MmZkYWMwZTEwNmU4NjFlZGY2MWM1YTAzOTA2M2YwZTBlNjQ4MidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2YTI0NWJmNmRjNjk4NTA0Yzg5YTIwY2ZkZWQ2MDg1MzE1MmI2OTUzMzZjMjgwNjNiNjFjNjVjYmQyNjllNmI0JyxcbiAgICAgICAgJ2UwMjJjZjQyYzJiZDRhNzA4YjNmNTEyNmYxNmEyNGFkOGIzM2JhNDhkMDQyM2I2ZWZkNWU2MzQ4MTAwZDhhODInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTY5N2ZmYTZmZDlkZTYyN2MwNzdlM2QyZmU1NDEwODRjZTEzMzAwYjBiZWMxMTQ2Zjk1YWU1N2YwZDBiZDZhNScsXG4gICAgICAgICdiOWMzOThmMTg2ODA2ZjVkMjc1NjE1MDZlNDU1NzQzM2EyY2YxNTAwOWU0OThhZTdhZGVlOWQ2M2QwMWIyMzk2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzYwNWJkYjAxOTk4MTcxOGI5ODZkMGYwN2U4MzRjYjBkOWRlYjgzNjBmZmI3ZjYxZGY5ODIzNDVlZjI3YTc0NzknLFxuICAgICAgICAnMjk3MmQyZGU0ZjhkMjA2ODFhNzhkOTNlYzk2ZmUyM2MyNmJmYWU4NGZiMTRkYjQzYjAxZTFlOTA1NmI4YzQ5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzYyZDE0ZGFiNDE1MGJmNDk3NDAyZmRjNDVhMjE1ZTEwZGNiMDFjMzU0OTU5YjEwY2ZlMzFjN2U5ZDg3ZmYzM2QnLFxuICAgICAgICAnODBmYzA2YmQ4Y2M1YjAxMDk4MDg4YTE5NTBlZWQwZGIwMWFhMTMyOTY3YWI0NzIyMzVmNTY0MjQ4M2IyNWVhZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4MGM2MGFkMDA0MGYyN2RhZGU1YjRiMDZjNDA4ZTU2YjJjNTBlOWY1NmI5YjhiNDI1ZTU1NWMyZjg2MzA4YjZmJyxcbiAgICAgICAgJzFjMzgzMDNmMWNjNWMzMGYyNmU2NmJhZDdmZTcyZjcwYTY1ZWVkNGNiZTcwMjRlYjFhYTAxZjU2NDMwYmQ1N2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnN2E5Mzc1YWQ2MTY3YWQ1NGFhNzRjNjM0OGNjNTRkMzQ0Y2M1ZGM5NDg3ZDg0NzA0OWQ1ZWFiYjBmYTAzYzhmYicsXG4gICAgICAgICdkMGUzZmE5ZWNhODcyNjkwOTU1OWUwZDc5MjY5MDQ2YmRjNTllYTEwYzcwY2UyYjAyZDQ5OWVjMjI0ZGM3ZjcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDUyOGVjZDliNjk2YjU0YzkwN2E5ZWQwNDU0NDdhNzliYjQwOGVjMzliNjhkZjUwNGJiNTFmNDU5YmMzZmZjOScsXG4gICAgICAgICdlZWNmNDEyNTMxMzZlNWY5OTk2NmYyMTg4MWZkNjU2ZWJjNDM0NTQwNWM1MjBkYmMwNjM0NjViNTIxNDA5OTMzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ5MzcwYTRiNWY0MzQxMmVhMjVmNTE0ZThlY2RhZDA1MjY2MTE1ZTRhN2VjYjEzODcyMzE4MDhmOGI0NTk2MycsXG4gICAgICAgICc3NThmM2Y0MWFmZDZlZDQyOGIzMDgxYjA1MTJmZDYyYTU0YzNmM2FmYmI1YjY3NjRiNjUzMDUyYTEyOTQ5YzlhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3ZjIzMDkzNmVlODhjYmJkNzNkZjkzMGQ2NDcwMmVmODgxZDgxMWUwZTE0OThlMmYxYzEzZWIxZmMzNDVkNzQnLFxuICAgICAgICAnOTU4ZWY0MmE3ODg2YjY0MDBhMDgyNjZlOWJhMWIzNzg5NmM5NTMzMGQ5NzA3N2NiYmU4ZWIzYzc2NzFjNjBkNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmMmRhYzk5MWNjNGNlNGI5ZWE0NDg4N2U1YzdjMGJjZTU4YzgwMDc0YWI5ZDRkYmFlYjI4NTMxYjc3MzlmNTMwJyxcbiAgICAgICAgJ2UwZGVkYzliM2IyZjhkYWQ0ZGExZjMyZGVjMjUzMWRmOWViNWZiZWIwNTk4ZTRmZDFhMTE3ZGJhNzAzYTNjMzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNDYzYjNkOWY2NjI2MjFmYjFiNGJlOGZiYmUyNTIwMTI1YTIxNmNkZmM5ZGFlM2RlYmNiYTQ4NTBjNjkwZDQ1YicsXG4gICAgICAgICc1ZWQ0MzBkNzhjMjk2YzM1NDMxMTQzMDZkZDg2MjJkN2M2MjJlMjdjOTcwYTFkZTMxY2IzNzdiMDFhZjczMDdlJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2YxNmY4MDQyNDRlNDZlMmEwOTIzMmQ0YWZmM2I1OTk3NmI5OGZhYzE0MzI4YTJkMWEzMjQ5NmI0OTk5OGYyNDcnLFxuICAgICAgICAnY2VkYWJkOWI4MjIwM2Y3ZTEzZDIwNmZjZGY0ZTMzZDkyYTZjNTNjMjZlNWNjZTI2ZDY1Nzk5NjJjNGUzMWRmNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjYWY3NTQyNzJkYzg0NTYzYjAzNTJiN2ExNDMxMWFmNTVkMjQ1MzE1YWNlMjdjNjUzNjllMTVmNzE1MWQ0MWQxJyxcbiAgICAgICAgJ2NiNDc0NjYwZWYzNWY1ZjJhNDFiNjQzZmE1ZTQ2MDU3NWY0ZmE5Yjc5NjIyMzJhNWMzMmY5MDgzMThhMDQ0NzYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMjYwMGNhNGIyODJjYjk4NmY4NWQwZjE3MDk5NzlkOGI0NGEwOWMwN2NiODZkN2MxMjQ0OTdiYzg2ZjA4MjEyMCcsXG4gICAgICAgICc0MTE5Yjg4NzUzYzE1YmQ2YTY5M2IwM2ZjZGRiYjQ1ZDVhYzZiZTc0YWI1ZjBlZjQ0YjBiZTk0NzVhN2U0YjQwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc2MzVjYTcyZDdlODQzMmMzMzhlYzUzY2QxMjIyMGJjMDFjNDg2ODVlMjRmN2RjOGM2MDJhNzc0Njk5OGU0MzUnLFxuICAgICAgICAnOTFiNjQ5NjA5NDg5ZDYxM2QxZDVlNTkwZjc4ZTZkNzRlY2ZjMDYxZDU3MDQ4YmFkOWU3NmYzMDJjNWI5YzYxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc1NGUzMjM5ZjMyNTU3MGNkYmJmNGE4N2RlZWU4YTY2YjdmMmIzMzQ3OWQ0NjhmYmMxYTUwNzQzYmY1NmNjMTgnLFxuICAgICAgICAnNjczZmI4NmU1YmRhMzBmYjNjZDBlZDMwNGVhNDlhMDIzZWUzM2QwMTk3YTY5NWQwYzVkOTgwOTNjNTM2NjgzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UzZTZiZDEwNzFhMWU5NmFmZjU3ODU5YzgyZDU3MGYwMzMwODAwNjYxZDFjOTUyZjlmZTI2OTQ2OTFkOWI5ZTgnLFxuICAgICAgICAnNTljOWUwYmJhMzk0ZTc2ZjQwYzBhYTU4Mzc5YTNjYjZhNWEyMjgzOTkzZTkwYzQxNjcwMDJhZjQ5MjBlMzdmNSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxODZiNDgzZDA1NmEwMzM4MjZhZTczZDg4ZjczMjk4NWM0Y2NiMWYzMmJhMzVmNGI0Y2M0N2ZkY2YwNGFhNmViJyxcbiAgICAgICAgJzNiOTUyZDMyYzY3Y2Y3N2UyZTE3NDQ2ZTIwNDE4MGFiMjFmYjgwOTA4OTUxMzhiNGE0YTc5N2Y4NmU4MDg4OGInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGY5ZDcwYTZiOTg3NmNlNTQ0Yzk4NTYxZjRiZTRmNzI1NDQyZTZkMmI3MzdkOWM5MWE4MzIxNzI0Y2UwOTYzZicsXG4gICAgICAgICc1NWViMmRhZmQ4NGQ2Y2NkNWY4NjJiNzg1ZGMzOWQ0YWIxNTcyMjI3MjBlZjlkYTIxN2I4YzQ1Y2YyYmEyNDE3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzVlZGQ1Y2MyM2M1MWU4N2E0OTdjYTgxNWQ1ZGNlMGY4YWI1MjU1NGY4NDllZDg5OTVkZTY0YzVmMzRjZTcxNDMnLFxuICAgICAgICAnZWZhZTljOGRiYzE0MTMwNjYxZThjZWMwMzBjODlhZDBjMTNjNjZjMGQxN2EyOTA1Y2RjNzA2YWI3Mzk5YTg2OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyOTA3OThjMmI2NDc2ODMwZGExMmZlMDIyODdlOWU3NzdhYTNmYmExYzM1NWIxN2E3MjJkMzYyZjg0NjE0ZmJhJyxcbiAgICAgICAgJ2UzOGRhNzZkY2Q0NDA2MjE5ODhkMDBiY2Y3OWFmMjVkNWIyOWMwOTRkYjJhMjMxNDZkMDAzYWZkNDE5NDNlN2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYWYzYzQyM2E5NWQ5ZjViMzA1NDc1NGVmYTE1MGFjMzljZDI5NTUyZmUzNjAyNTczNjJkZmRlY2VmNDA1M2I0NScsXG4gICAgICAgICdmOThhM2ZkODMxZWIyYjc0OWE5M2IwZTZmMzVjZmI0MGM4Y2Q1YWE2NjdhMTU1ODFiYzJmZWRlZDQ5OGZkOWM2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc2NmRiYjI0ZDEzNGU3NDVjY2NhYTI4Yzk5YmYyNzQ5MDZiYjY2YjI2ZGNmOThkZjhkMmZlZDUwZDg4NDI0OWEnLFxuICAgICAgICAnNzQ0YjExNTJlYWNiZTVlMzhkY2M4ODc5ODBkYTM4Yjg5NzU4NGE2NWZhMDZjZWRkMmM5MjRmOTdjYmFjNTk5NidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1OWRiZjQ2ZjhjOTQ3NTliYTIxMjc3YzMzNzg0ZjQxNjQ1ZjdiNDRmNmM1OTZhNThjZTkyZTY2NjE5MWFiZTNlJyxcbiAgICAgICAgJ2M1MzRhZDQ0MTc1ZmJjMzAwZjRlYTZjZTY0ODMwOWEwNDJjZTczOWE3OTE5Nzk4Y2Q4NWUyMTZjNGEzMDdmNmUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZjEzYWRhOTUxMDNjNDUzNzMwNWU2OTFlNzRlOWE0YThkZDY0N2U3MTFhOTVlNzNjYjYyZGM2MDE4Y2ZkODdiOCcsXG4gICAgICAgICdlMTM4MTdiNDRlZTE0ZGU2NjNiZjRiYzgwODM0MWYzMjY5NDllMjFhNmE3NWMyNTcwNzc4NDE5YmRhZjU3MzNkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3NTRiNGZhMGU4YWNlZDA2ZDQxNjdhMmM1OWNjYTRjZGExODY5YzA2ZWJhZGZiNjQ4ODU1MDAxNWE4ODUyMmMnLFxuICAgICAgICAnMzBlOTNlODY0ZTY2OWQ4MjIyNGI5NjdjMzAyMGI4ZmE4ZDFlNGUzNTBiNmNiY2M1MzdhNDhiNTc4NDExNjNhMidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5NDhkY2FkZjU5OTBlMDQ4YWEzODc0ZDQ2YWJlZjlkNzAxODU4Zjk1ZGU4MDQxZDJhNjgyOGM5OWUyMjYyNTE5JyxcbiAgICAgICAgJ2U0OTFhNDI1MzdmNmU1OTdkNWQyOGEzMjI0YjFiYzI1ZGY5MTU0ZWZiZDJlZjFkMmNiYmEyY2FlNTM0N2Q1N2UnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzk2MjQxNDQ1MGM3NmMxNjg5YzdiNDhmODIwMmVjMzdmYjIyNGNmNWFjMGJmYTE1NzAzMjhhOGEzZDdjNzdhYicsXG4gICAgICAgICcxMDBiNjEwZWM0ZmZiNDc2MGQ1YzFmYzEzM2VmNmY2YjEyNTA3YTA1MWYwNGFjNTc2MGFmYTViMjlkYjgzNDM3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzM1MTQwODc4MzQ5NjRiNTRiMTViMTYwNjQ0ZDkxNTQ4NWExNjk3NzIyNWI4ODQ3YmIwZGQwODUxMzdlYzQ3Y2EnLFxuICAgICAgICAnZWYwYWZiYjIwNTYyMDU0NDhlMTY1MmM0OGU4MTI3ZmM2MDM5ZTc3YzE1YzIzNzhiN2U3ZDE1YTBkZTI5MzMxMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkM2NjMzBhZDZiNDgzZTRiYzc5Y2UyYzlkZDhiYzU0OTkzZTk0N2ViOGRmNzg3YjQ0Mjk0M2QzZjdiNTI3ZWFmJyxcbiAgICAgICAgJzhiMzc4YTIyZDgyNzI3OGQ4OWM1ZTliZThmOTUwOGFlM2MyYWQ0NjI5MDM1ODYzMGFmYjM0ZGIwNGVlZGUwYTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTYyNGQ4NDc4MDczMjg2MGNlMWM3OGZjYmZlZmUwOGIyYjI5ODIzZGI5MTNmNjQ5Mzk3NWJhMGZmNDg0NzYxMCcsXG4gICAgICAgICc2ODY1MWNmOWI2ZGE5MDNlMDkxNDQ0OGM2Y2Q5ZDRjYTg5Njg3OGY1MjgyYmU0YzhjYzA2ZTJhNDA0MDc4NTc1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzczM2NlODBkYTk1NWE4YTI2OTAyYzk1NjMzZTYyYTk4NTE5MjQ3NGI1YWYyMDdkYTZkZjdiNGZkNWZjNjFjZDQnLFxuICAgICAgICAnZjU0MzVhMmJkMmJhZGY3ZDQ4NWE0ZDhiOGRiOWZjY2UzZTFlZjhlMDIwMWU0NTc4YzU0NjczYmMxZGM1ZWExZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNWQ5NDQxMjU0OTQ1MDY0Y2YxYTFjMzNiYmQzYjQ5Zjg5NjZjNTA5MjE3MWU2OTllZjI1OGRmYWI4MWMwNDVjJyxcbiAgICAgICAgJ2Q1NmViMzBiNjk0NjNlNzIzNGY1MTM3YjczYjg0MTc3NDM0ODAwYmFjZWJmYzY4NWZjMzdiYmU5ZWZlNDA3MGQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTFkMGZjZjJlYzlkZTY3NWI2MTIxMzZlNWNlNzBkMjcxYzIxNDE3YzlkMmI4YWFhYWMxMzg1OTlkMDcxNzk0MCcsXG4gICAgICAgICdlZGQ3N2Y1MGJjYjVhM2NhYjJlOTA3MzczMDk2NjdmMjY0MTQ2MmE1NDA3MGYzZDUxOTIxMmQzOWMxOTdhNjI5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UyMmZiZTE1YzBhZjhjY2M1NzgwYzA3MzVmODRkYmU5YTc5MGJhZGVlODI0NWMwNmM3Y2EzNzMzMWNiMzY5ODAnLFxuICAgICAgICAnYTg1NWJhYmFkNWNkNjBjODhiNDMwYTY5ZjUzYTFhN2EzODI4OTE1NDk2NDc5OWJlNDNkMDZkNzdkMzFkYTA2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMxMTA5MWRkOTg2MGU4ZTIwZWUxMzQ3M2MxMTU1ZjVmNjk2MzVlMzk0NzA0ZWFhNzQwMDk0NTIyNDZjZmE5YjMnLFxuICAgICAgICAnNjZkYjY1NmY4N2QxZjA0ZmZmZDFmMDQ3ODhjMDY4MzA4NzFlYzVhNjRmZWVlNjg1YmQ4MGYwYjEyODZkODM3NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNGMxZmQwNGQzMDFiZTg5YjMxYzA0NDJkM2U2YWMyNDg4MzkyOGI0NWE5MzQwNzgxODY3ZDQyMzJlYzJkYmRmJyxcbiAgICAgICAgJzk0MTQ2ODVlOTdiMWI1OTU0YmQ0NmY3MzAxNzQxMzZkNTdmMWNlZWI0ODc0NDNkYzUzMjE4NTdiYTczYWJlZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmMjE5ZWE1ZDZiNTQ3MDFjMWMxNGRlNWI1NTdlYjQyYThkMTNmM2FiYmNkMDhhZmZjYzJhNWU2YjA0OWI4ZDYzJyxcbiAgICAgICAgJzRjYjk1OTU3ZTgzZDQwYjBmNzNhZjQ1NDRjY2NmNmIxZjRiMDhkM2MwN2IyN2ZiOGQ4YzI5NjJhNDAwNzY2ZDEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDdiODc0MGY3NGE4ZmJhYWIxZjY4M2RiOGY0NWRlMjY1NDNhNTQ5MGJjYTYyNzA4NzIzNjkxMjQ2OWEwYjQ0OCcsXG4gICAgICAgICdmYTc3OTY4MTI4ZDljOTJlZTEwMTBmMzM3YWQ0NzE3ZWZmMTVkYjVlZDNjMDQ5YjM0MTFlMDMxNWVhYTQ1OTNiJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyZDMxYzIyMmY4ZjZmMGVmODZmN2M5OGQzYTMzMzVlYWQ1YmNkMzJhYmRkOTQyODlmZTRkMzA5MWFhODI0YmYnLFxuICAgICAgICAnNWYzMDMyZjU4OTIxNTZlMzljY2QzZDc5MTViOWUxZGEyZTZkYWM5ZTZmMjZlOTYxMTE4ZDE0Yjg0NjJlMTY2MSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3NDYxZjM3MTkxNGFiMzI2NzEwNDVhMTU1ZDk4MzFlYTg3OTNkNzdjZDU5NTkyYzQzNDBmODZjYmMxODM0N2I1JyxcbiAgICAgICAgJzhlYzBiYTIzOGI5NmJlYzBjYmRkZGNhZTBhYTQ0MjU0MmVlZTFmZjUwYzk4NmVhNmIzOTg0N2IzY2MwOTJmZjYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZWUwNzlhZGIxZGYxODYwMDc0MzU2YTI1YWEzODIwNmE2ZDcxNmIyYzNlNjc0NTNkMjg3Njk4YmFkN2IyYjJkNicsXG4gICAgICAgICc4ZGMyNDEyYWFmZTNiZTVjNGM1ZjM3ZTBlY2M1ZjlmNmE0NDY5ODlhZjA0YzRlMjVlYmFhYzQ3OWVjMWM4YzFlJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzE2ZWM5M2U0NDdlYzgzZjA0NjdiMTgzMDJlZTYyMGY3ZTY1ZGUzMzE4NzRjOWRjNzJiZmQ4NjE2YmE5ZGE2YjUnLFxuICAgICAgICAnNWU0NjMxMTUwZTYyZmI0MGQwZThjMmE3Y2E1ODA0YTM5ZDU4MTg2YTUwZTQ5NzEzOTYyNjc3OGUyNWIwNjc0ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYWE1Zjk4MGMyNDVmNmYwMzg5NzgyOTBhZmE3MGI2YmQ4ODU1ODk3Zjk4YjZhYTQ4NWI5NjA2NWQ1MzdiZDk5JyxcbiAgICAgICAgJ2Y2NWY1ZDNlMjkyYzJlMDgxOWE1MjgzOTFjOTk0NjI0ZDc4NDg2OWQ3ZTZlYTY3ZmIxODA0MTAyNGVkYzA3ZGMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzhjOTQwNzU0NGFjMTMyNjkyZWUxOTEwYTAyNDM5OTU4YWUwNDg3NzE1MTM0MmVhOTZjNGI2YjM1YTQ5ZjUxJyxcbiAgICAgICAgJ2YzZTAzMTkxNjllYjliODVkNTQwNDc5NTUzOWE1ZTY4ZmExZmJkNTgzYzA2NGQyNDYyYjY3NWYxOTRhM2RkYjQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNDk0ZjRiZTIxOWExYTc3MDE2ZGNkODM4NDMxYWVhMDAwMWNkYzhhZTdhNmZjNjg4NzI2NTc4ZDk3MDI4NTdhNScsXG4gICAgICAgICc0MjI0MmE5NjkyODNhNWYzMzliYTdmMDc1ZTM2YmEyYWY5MjVjZTMwZDc2N2VkNmU1NWY0YjAzMTg4MGQ1NjJjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2E1OThhODAzMGRhNmQ4NmM2YmM3ZjJmNTE0NGVhNTQ5ZDI4MjExZWE1OGZhYTcwZWJmNGMxZTY2NWMxZmU5YjUnLFxuICAgICAgICAnMjA0YjVkNmY4NDgyMmMzMDdlNGI0YTcxNDA3MzdhZWMyM2ZjNjNiNjViMzVmODZhMTAwMjZkYmQyZDg2NGU2YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjNDE5MTYzNjVhYmIyYjVkMDkxOTJmNWYyZGJlYWZlYzIwOGYwMjBmMTI1NzBhMTg0ZGJhZGMzZTU4NTk1OTk3JyxcbiAgICAgICAgJzRmMTQzNTFkMDA4N2VmYTQ5ZDI0NWIzMjg5ODQ5ODlkNWNhZjk0NTBmMzRiZmMwZWQxNmU5NmI1OGZhOTkxMydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NDFkNjA2M2E1ODZmYTQ3NWE3MjQ2MDRkYTAzYmM1YjkyYTJlMGQyZTBhMzZhY2ZlNGM3M2E1NTE0NzQyODgxJyxcbiAgICAgICAgJzczODY3ZjU5YzA2NTllODE5MDRmOWExYzc1NDM2OThlNjI1NjJkNjc0NGMxNjljZTdhMzZkZTAxYThkNjE1NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1ZTk1YmIzOTlhNjk3MWQzNzYwMjY5NDdmODliZGUyZjI4MmIzMzgxMDkyOGJlNGRlZDExMmFjNGQ3MGUyMGQ1JyxcbiAgICAgICAgJzM5ZjIzZjM2NjgwOTA4NWJlZWJmYzcxMTgxMzEzNzc1YTk5YzlhZWQ3ZDhiYTM4YjE2MTM4NGM3NDYwMTI4NjUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzZlNDY0MWE1Mzk0OGZkNDc2YzM5ZjhhOTlmZDk3NGU1ZWMwNzU2NGI1MzE1ZDhiZjk5NDcxYmNhMGVmMmY2NicsXG4gICAgICAgICdkMjQyNGIxYjFhYmU0ZWI4MTY0MjI3YjA4NWM5YWE5NDU2ZWExMzQ5M2ZkNTYzZTA2ZmQ1MWNmNTY5NGM3OGZjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMzNjU4MWVhN2JmYmJiMjkwYzE5MWEyZjUwN2E0MWNmNTY0Mzg0MjE3MGU5MTRmYWVhYjI3YzJjNTc5ZjcyNicsXG4gICAgICAgICdlYWQxMjE2ODU5NWZlMWJlOTkyNTIxMjliNmU1NmIzMzkxZjdhYjE0MTBjZDFlMGVmM2RjZGNhYmQyZmRhMjI0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhhYjg5ODE2ZGFkZmQ2YjZhMWYyNjM0ZmNmMDBlYzg0MDM3ODEwMjVlZDY4OTBjNDg0OTc0MjcwNmJkNDNlZGUnLFxuICAgICAgICAnNmZkY2VmMDlmMmY2ZDBhMDQ0ZTY1NGFlZjYyNDEzNmY1MDNkNDU5YzNlODk4NDU4NThhNDdhOTEyOWNkZDI0ZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxZTMzZjFhNzQ2YzljNTc3ODEzMzM0NGQ5Mjk5ZmNhYTIwYjA5MzhlOGFjZmYyNTQ0YmI0MDI4NGI4YzVmYjk0JyxcbiAgICAgICAgJzYwNjYwMjU3ZGQxMWIzYWE5YzhlZDYxOGQyNGVkZmYyMzA2ZDMyMGYxZDAzMDEwZTMzYTdkMjA1N2YzYjNiNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NWI3YzFkY2IzY2VjMWI3ZWU3ZjMwZGVkNzlkZDIwYTBlZDFmNGNjMThjYmNmY2ZhNDEwMzYxZmQ4ZjA4ZjMxJyxcbiAgICAgICAgJzNkOThhOWNkZDAyNmRkNDNmMzkwNDhmMjVhODg0N2Y0ZmNhZmFkMTg5NWQ3YTYzM2M2ZmVkM2MzNWU5OTk1MTEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMjlkZjlmYmQ4ZDllNDY1MDkyNzVmNGIxMjVkNmQ0NWQ3ZmJlOWEzYjg3OGE3YWY4NzJhMjgwMDY2MWFjNWY1MScsXG4gICAgICAgICdiNGM0ZmU5OWM3NzVhNjA2ZTJkODg2MjE3OTEzOWZmZGE2MWRjODYxYzAxOWU1NWNkMjg3NmViMmEyN2Q4NGInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTBiMWNhZTA2YjBhODQ3YTNmZWE2ZTY3MWFhZjhhZGZkZmU1OGNhMmY3NjgxMDVjODA4MmIyZTQ0OWZjZTI1MicsXG4gICAgICAgICdhZTQzNDEwMmVkZGUwOTU4ZWM0YjE5ZDkxN2E2YTI4ZTZiNzJkYTE4MzRhZmYwZTY1MGYwNDk1MDNhMjk2Y2YyJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzRlOGNlYWZiOWIzZTlhMTM2ZGM3ZmY2N2U4NDAyOTViNDk5ZGZiM2IyMTMzZTRiYTExM2YyZTRjMGUxMjFlNScsXG4gICAgICAgICdjZjIxNzQxMThjOGI2ZDdhNGI0OGY2ZDUzNGNlNWM3OTQyMmMwODZhNjM0NjA1MDJiODI3Y2U2MmEzMjY2ODNjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2QyNGE0NGUwNDdlMTliNmY1YWZiODFjN2NhMmY2OTA4MGE1MDc2Njg5YTAxMDkxOWY0MjcyNWMyYjc4OWEzM2InLFxuICAgICAgICAnNmZiOGQ1NTkxYjQ2NmY4ZmM2M2RiNTBmMWMwZjFjNjkwMTNmOTk2ODg3YjgyNDRkMmNkZWM0MTdhZmVhOGZhMydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYTAxNjA2YTdhNmM5Y2RkMjQ5ZmRmY2ZhY2I5OTU4NDAwMWVkZDI4YWJiYWI3N2I1MTA0ZTk4ZThlM2IzNWQ0JyxcbiAgICAgICAgJzMyMmFmNDkwOGM3MzEyYjBjZmJmZTM2OWY3YTdiM2NkYjdkNDQ5NGJjMjgyMzcwMGNmZDY1MjE4OGEzZWE5OGQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYWY4YWRkYmYyYjY2MWM4YTZjNjMyODY1NWViOTY2NTEyNTIwMDdkOGM1ZWEzMWJlNGFkMTk2ZGU4Y2UyMTMxZicsXG4gICAgICAgICc2NzQ5ZTY3YzAyOWI4NWY1MmEwMzRlYWZkMDk2ODM2YjI1MjA4MTg2ODBlMjZhYzhmM2RmYmNkYjcxNzQ5NzAwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UzYWUxOTc0NTY2Y2EwNmNjNTE2ZDQ3ZTBmYjE2NWE2NzRhM2RhYmNmY2ExNWU3MjJmMGUzNDUwZjQ1ODg5JyxcbiAgICAgICAgJzJhZWFiZTdlNDUzMTUxMDExNjIxN2YwN2JmNGQwNzMwMGRlOTdlNDg3NGY4MWY1MzM0MjBhNzJlZWIwYmQ2YTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNTkxZWUzNTUzMTNkOTk3MjFjZjY5OTNmZmVkMWUzZTMwMTk5M2ZmM2VkMjU4ODAyMDc1ZWE4Y2VkMzk3ZTI0NicsXG4gICAgICAgICdiMGVhNTU4YTExM2MzMGJlYTYwZmM0Nzc1NDYwYzc5MDFmZjBiMDUzZDI1Y2EyYmRlZWU5OGYxYTRiZTVkMTk2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzExMzk2ZDU1ZmRhNTRjNDlmMTlhYTk3MzE4ZDhkYTYxZmE4NTg0ZTQ3YjA4NDk0NTA3N2NmMDMyNTViNTI5ODQnLFxuICAgICAgICAnOTk4Yzc0YThjZDQ1YWMwMTI4OWQ1ODMzYTdiZWI0NzQ0ZmY1MzZiMDFiMjU3YmU0YzU3NjdiZWE5M2VhNTdhNCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczYzVkMmExYmEzOWM1YTE3OTAwMDA3MzhjOWUwYzQwYjhkY2RmZDU0Njg3NTRiNjQwNTU0MDE1N2UwMTdhYTdhJyxcbiAgICAgICAgJ2IyMjg0Mjc5OTk1YTM0ZTJmOWQ0ZGU3Mzk2ZmMxOGI4MGY5YjhiOWZkZDI3MGY2NjYxZjc5Y2E0YzgxYmQyNTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnY2M4NzA0YjhhNjBhMGRlZmEzYTk5YTcyOTlmMmU5YzNmYmMzOTVhZmIwNGFjMDc4NDI1ZWY4YTE3OTNjYzAzMCcsXG4gICAgICAgICdiZGQ0NjAzOWZlZWQxNzg4MWQxZTA4NjJkYjM0N2Y4Y2YzOTViNzRmYzRiY2RjNGU5NDBiNzRlM2FjMWYxYjEzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M1MzNlNGY3ZWE4NTU1YWFjZDk3NzdhYzVjYWQyOWI5N2RkNGRlZmNjYzUzZWU3ZWEyMDQxMTliMjg4OWIxOTcnLFxuICAgICAgICAnNmYwYTI1NmJjNWVmZGY0MjlhMmZiNjI0MmYxYTQzYTJkOWI5MjViYjRhNGIzYTI2YmI4ZTBmNDVlYjU5NjA5NidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjMTRmOGYyY2NiMjdkNmYxMDlmNmQwOGQwM2NjOTZhNjliYThjMzRlZWMwN2JiY2Y1NjZkNDhlMzNkYTY1OTMnLFxuICAgICAgICAnYzM1OWQ2OTIzYmIzOThmN2ZkNDQ3M2UxNmZlMWMyODQ3NWI3NDBkZDA5ODA3NWU2YzBlODY0OTExM2RjM2EzOCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhNmNiYzMwNDZiYzZhNDUwYmFjMjQ3ODlmYTE3MTE1YTRjOTczOWVkNzVmOGYyMWNlNDQxZjcyZTBiOTBlNmVmJyxcbiAgICAgICAgJzIxYWU3ZjQ2ODBlODg5YmIxMzA2MTllMmMwZjk1YTM2MGNlYjU3M2M3MDYwMzEzOTg2MmFmZDYxN2ZhOWI5ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNDdkNmQ5YTAyYzQ4OTI3ZWJmYjg2YzEzNTliMWNhZjEzMGEzYzAyNjdkMTFjZTYzNDRiMzlmOTlkNDNjYzM4JyxcbiAgICAgICAgJzYwZWE3ZjYxYTM1MzUyNGQxYzk4N2Y2ZWNlYzkyZjA4NmQ1NjVhYjY4Nzg3MGNiMTI2ODlmZjFlMzFjNzQ0NDgnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGE2NTQ1ZDIxODFkYjhkOTgzZjdkY2IzNzVlZjU4NjZkNDdjNjdiMWJmMzFjOGNmODU1ZWY3NDM3YjcyNjU2YScsXG4gICAgICAgICc0OWI5NjcxNWFiNjg3OGE3OWU3OGYwN2NlNTY4MGM1ZDY2NzMwNTFiNDkzNWJkODk3ZmVhODI0Yjc3ZGMyMDhhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M0MDc0N2NjOWQwMTJjYjFhMTNiODE0ODMwOWM2ZGU3ZWMyNWQ2OTQ1ZDY1NzE0NmI5ZDU5OTRiOGZlYjExMTEnLFxuICAgICAgICAnNWNhNTYwNzUzYmUyYTEyZmM2ZGU2Y2FmMmNiNDg5NTY1ZGI5MzYxNTZiOTUxNGUxYmI1ZTgzMDM3ZTBmYTJkNCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc0ZTQyYzhlYzgyYzk5Nzk4Y2NmM2E2MTBiZTg3MGU3ODMzOGM3ZjcxMzM0OGJkMzRjODIwM2VmNDAzN2YzNTAyJyxcbiAgICAgICAgJzc1NzFkNzRlZTVlMGZiOTJhN2E4YjMzYTA3NzgzMzQxYTU0OTIxNDRjYzU0YmNjNDBhOTQ0NzM2OTM2MDY0MzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzc3NWFiNzA4OWJjNmFmODIzYWJhMmUxYWY3MGIyMzZkMjUxY2FkYjBjODY3NDMyODc1MjJhMWIzYjBkZWRlYScsXG4gICAgICAgICdiZTUyZDEwN2JjZmEwOWQ4YmNiOTczNmE4MjhjZmE3ZmFjOGRiMTdiZjdhNzZhMmM0MmFkOTYxNDA5MDE4Y2Y3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2NlZTMxY2JmN2UzNGVjMzc5ZDk0ZmI4MTRkM2Q3NzVhZDk1NDU5NWQxMzE0YmE4ODQ2OTU5ZTNlODJmNzRlMjYnLFxuICAgICAgICAnOGZkNjRhMTRjMDZiNTg5YzI2Yjk0N2FlMmJjZjZiZmEwMTQ5ZWYwYmUxNGVkNGQ4MGY0NDhhMDFjNDNiMWM2ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiNGY5ZWFlYTA5YjY5MTc2MTlmNmVhNmE0ZWI1NDY0ZWZkZGI1OGZkNDViMWViZWZjZGMxYTAxZDA4YjQ3OTg2JyxcbiAgICAgICAgJzM5ZTVjOTkyNWI1YTU0YjA3NDMzYTRmMThjNjE3MjZmOGJiMTMxYzAxMmNhNTQyZWIyNGE4YWMwNzIwMDY4MmEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDQyNjNkZmMzZDJkZjkyM2EwMTc5YTQ4OTY2ZDMwY2U4NGUyNTE1YWZjM2RjY2MxYjc3OTA3NzkyZWJjYzYwZScsXG4gICAgICAgICc2MmRmYWYwN2EwZjc4ZmViMzBlMzBkNjI5NTg1M2NlMTg5ZTEyNzc2MGFkNmNmN2ZhZTE2NGUxMjJhMjA4ZDU0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ4NDU3NTI0ODIwZmE2NWE0ZjhkMzVlYjY5MzA4NTdjMDAzMmFjYzBhNGEyZGU0MjIyMzNlZWRhODk3NjEyYzQnLFxuICAgICAgICAnMjVhNzQ4YWIzNjc5NzlkOTg3MzNjMzhhMWZhMWMyZTdkYzZjYzA3ZGIyZDYwYTlhZTdhNzZhYWE0OWJkMGY3NydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkZmVlZWYxODgxMTAxZjJjYjExNjQ0ZjNhMmFmZGZjMjA0NWUxOTkxOTE1MjkyM2YzNjdhMTc2N2MxMWNjZWRhJyxcbiAgICAgICAgJ2VjZmI3MDU2Y2YxZGUwNDJmOTQyMGJhYjM5Njc5M2MwYzM5MGJkZTc0YjRiYmRmZjE2YTgzYWUwOWE5YTc1MTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNmQ3ZWY2YjE3NTQzZjgzNzNjNTczZjQ0ZTFmMzg5ODM1ZDg5YmNiYzYwNjJjZWQzNmM4MmRmODNiOGZhZTg1OScsXG4gICAgICAgICdjZDQ1MGVjMzM1NDM4OTg2ZGZlZmExMGM1N2ZlYTliY2M1MjFhMDk1OWIyZDgwYmJmNzRiMTkwZGNhNzEyZDEwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2U3NTYwNWQ1OTEwMmE1YTI2ODQ1MDBkM2I5OTFmMmUzZjNjODhiOTMyMjU1NDcwMzVhZjI1YWY2NmUwNDU0MWYnLFxuICAgICAgICAnZjVjNTQ3NTRhOGY3MWVlNTQwYjliNDg3Mjg0NzNlMzE0ZjcyOWFjNTMwOGIwNjkzODM2MDk5MGUyYmZhZDEyNSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYjk4NjYwZjRjNGRmYWEwNmEyYmU0NTNkNTAyMGJjOTlhMGMyZTYwYWJlMzg4NDU3ZGQ0M2ZlZmIxZWQ2MjBjJyxcbiAgICAgICAgJzZjYjlhODg3NmQ5Y2I4NTIwNjA5YWYzYWRkMjZjZDIwYTBhN2NkOGE5NDExMTMxY2U4NWY0NDEwMDA5OTIyM2UnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTNlODdiMDI3ZDg1MTRkMzU5MzlmMmU2ODkyYjE5OTIyMTU0NTk2OTQxODg4MzM2ZGMzNTYzZTNiOGRiYTk0MicsXG4gICAgICAgICdmZWY1YTNjNjgwNTlhNmRlYzVkNjI0MTE0YmYxZTkxYWFjMmI5ZGE1NjhkNmFiZWIyNTcwZDU1NjQ2YjhhZGYxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2VlMTYzMDI2ZTlmZDZmZTAxN2MzOGYwNmE1YmU2ZmMxMjU0MjRiMzcxY2UyNzA4ZTdiZjQ0OTE2OTFlNTc2NGEnLFxuICAgICAgICAnMWFjYjI1MGYyNTVkZDYxYzQzZDk0Y2NjNjcwZDBmNThmNDlhZTNmYTE1Yjk2NjIzZTU0MzBkYTBhZDZjNjJiMidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiMjY4ZjVlZjlhZDUxZTRkNzhkZTNhNzUwYzJkYzg5YjFlNjI2ZDQzNTA1ODY3OTk5OTMyZTVkYjMzYWYzZDgwJyxcbiAgICAgICAgJzVmMzEwZDRiM2M5OWI5ZWJiMTlmNzdkNDFjMWRlZTAxOGNmMGQzNGZkNDE5MTYxNDAwM2U5NDVhMTIxNmU0MjMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmYwN2YzMTE4YTlkZjAzNWU5ZmFkODVlYjZjN2JmZTQyYjAyZjAxY2E5OWNlZWEzYmY3ZmZkYmE5M2M0NzUwZCcsXG4gICAgICAgICc0MzgxMzZkNjAzZTg1OGEzYTVjNDQwYzM4ZWNjYmFkZGMxZDI5NDIxMTRlMmVkZGQ0NzQwZDA5OGNlZDFmMGQ4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhkOGI5ODU1YzdjMDUyYTM0MTQ2ZmQyMGZmYjY1OGJlYTRiOWY2OWUwZDgyNWViZWMxNmU4YzNjZTJiNTI2YTEnLFxuICAgICAgICAnY2RiNTU5ZWVkYzJkNzlmOTI2YmFmNDRmYjg0ZWE0ZDQ0YmNmNTBmZWU1MWQ3Y2ViMzBlMmU3ZjQ2MzAzNjc1OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1MmRiMGI1Mzg0ZGZiZjA1YmZhOWQ0NzJkN2FlMjZkZmU0Yjg1MWNlY2E5MWIxZWJhNTQyNjMxODBkYTMyYjYzJyxcbiAgICAgICAgJ2MzYjk5N2QwNTBlZTVkNDIzZWJhZjY2YTZkYjlmNTdiMzE4MGM5MDI4NzU2NzlkZTkyNGI2OWQ4NGE3YjM3NSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlNjJmOTQ5MGQzZDUxZGE2Mzk1ZWZkMjRlODA5MTljYzdkMGYyOWMzZjNmYTQ4YzZmZmY1NDNiZWNiZDQzMzUyJyxcbiAgICAgICAgJzZkODlhZDdiYTQ4NzZiMGIyMmMyY2EyODBjNjgyODYyZjM0MmM4NTkxZjFkYWY1MTcwZTA3YmZkOWNjYWZhN2QnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnN2YzMGVhMjQ3NmIzOTliNDk1NzUwOWM4OGY3N2QwMTkxYWZhMmZmNWNiN2IxNGZkNmQ4ZTdkNjVhYWFiMTE5MycsXG4gICAgICAgICdjYTVlZjdkNGIyMzFjOTRjM2IxNTM4OWE1ZjYzMTFlOWRhZmY3YmI2N2IxMDNlOTg4MGVmNGJmZjYzN2FjYWVjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzUwOThmZjFlMWQ5ZjE0ZmI0NmEyMTBmYWRhNmM5MDNmZWYwZmI3YjRhMWRkMWQ5YWM2MGEwMzYxODAwYjdhMDAnLFxuICAgICAgICAnOTczMTE0MWQ4MWZjOGY4MDg0ZDM3YzZlNzU0MjAwNmIzZWUxYjQwZDYwZGZlNTM2MmE1YjEzMmZkMTdkZGMwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyYjc4YzdkZTllZTUxMmE3Mjg5NWJlNmI5Y2JlZmE2ZTJmM2M0Y2NjZTQ0NWM5NmI5ZjJjODFlMjc3OGFkNTgnLFxuICAgICAgICAnZWUxODQ5ZjUxM2RmNzFlMzJlZmMzODk2ZWUyODI2MGM3M2JiODA1NDdhZTIyNzViYTQ5NzIzNzc5NGM4NzUzYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlMmNiNzRmZGRjOGU5ZmJjZDA3NmVlZjJhN2M3MmIwY2UzN2Q1MGYwODI2OWRmYzA3NGI1ODE1NTA1NDdhNGY3JyxcbiAgICAgICAgJ2QzYWEyZWQ3MWM5ZGQyMjQ3YTYyZGYwNjI3MzZlYjBiYWRkZWE5ZTM2MTIyZDJiZTg2NDFhYmNiMDA1Y2M0YTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnODQzODQ0NzU2NmQ0ZDdiZWRhZGMyOTk0OTZhYjM1NzQyNjAwOWEzNWYyMzVjYjE0MWJlMGQ5OWNkMTBhZTNhOCcsXG4gICAgICAgICdjNGUxMDIwOTE2OTgwYTRkYTVkMDFhYzVlNmFkMzMwNzM0ZWYwZDc5MDY2MzFjNGYyMzkwNDI2YjJlZGQ3OTFmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQxNjJkNDg4Yjg5NDAyMDM5YjU4NGM2ZmM2YzMwODg3MDU4N2Q5YzQ2ZjY2MGI4NzhhYjY1YzgyYzcxMWQ2N2UnLFxuICAgICAgICAnNjcxNjNlOTAzMjM2Mjg5Zjc3NmYyMmMyNWZiOGEzYWZjMTczMmYyYjg0YjRlOTVkYmRhNDdhZTVhMDg1MjY0OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczZmFkM2ZhODRjYWYwZjM0ZjBmODliZmQyZGNmNTRmYzE3NWQ3NjdhZWMzZTUwNjg0ZjNiYTRhNGJmNWY2ODNkJyxcbiAgICAgICAgJ2NkMWJjN2NiNmNjNDA3YmIyZjBjYTY0N2M3MThhNzMwY2Y3MTg3MmU3ZDBkMmE1M2ZhMjBlZmNkZmU2MTgyNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2NzRmMjYwMGEzMDA3YTAwNTY4YzFhN2NlMDVkMDgxNmMxZmI4NGJmMTM3MDc5OGYxYzY5NTMyZmFlYjFhODZiJyxcbiAgICAgICAgJzI5OWQyMWY5NDEzZjMzYjNlZGY0M2IyNTcwMDQ1ODBiNzBkYjU3ZGEwYjE4MjI1OWUwOWVlY2M2OWUwZDM4YTUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDMyZjRkYTU0YWRlNzRhYmI4MWI4MTVhZDFmYjNiMjYzZDgyZDZjNjkyNzE0YmNmZjg3ZDI5YmQ1ZWU5ZjA4ZicsXG4gICAgICAgICdmOTQyOWU3MzhiOGU1M2I5NjhlOTkwMTZjMDU5NzA3NzgyZTE0ZjQ1MzUzNTlkNTgyZmM0MTY5MTBiM2VlYTg3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMwZTRlNjcwNDM1Mzg1NTU2ZTU5MzY1NzEzNTg0NWQzNmZiYjY5MzFmNzJiMDhjYjFlZDk1NGYxZTNjZTNmZjYnLFxuICAgICAgICAnNDYyZjliY2U2MTk4OTg2Mzg0OTkzNTAxMTNiYmM5YjEwYTg3OGQzNWRhNzA3NDBkYzY5NWE1NTllYjg4ZGI3YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiZTIwNjIwMDNjNTFjYzMwMDQ2ODI5MDQzMzBlNGRlZTdmM2RjZDEwYjAxZTU4MGJmMTk3MWIwNGQ0Y2FkMjk3JyxcbiAgICAgICAgJzYyMTg4YmM0OWQ2MWU1NDI4NTczZDQ4YTc0ZTFjNjU1YjFjNjEwOTA5MDU2ODJhMGQ1NTU4ZWQ3MmRjY2I5YmMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnOTMxNDQ0MjNhY2UzNDUxZWQyOWUwZmI5YWMyYWYyMTFjYjZlODRhNjAxZGY1OTkzYzQxOTg1OWZmZjVkZjA0YScsXG4gICAgICAgICc3YzEwZGZiMTY0YzM0MjVmNWM3MWEzZjlkNzk5MjAzOGYxMDY1MjI0ZjcyYmI5ZDFkOTAyYTZkMTMwMzdiNDdjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2IwMTVmODA0NGY1ZmNiZGNmMjFjYTI2ZDZjMzRmYjgxOTc4MjkyMDVjN2I3ZDJhN2NiNjY0MThjMTU3YjExMmMnLFxuICAgICAgICAnYWI4YzFlMDg2ZDA0ZTgxMzc0NGE2NTViMmRmOGQ1ZjgzYjNjZGM2ZmFhMzA4OGMxZDNhZWExNDU0ZTNhMWQ1ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkNWU5ZTFkYTY0OWQ5N2Q4OWU0ODY4MTE3YTQ2NWEzYTRmOGExOGRlNTdhMTQwZDM2YjNmMmFmMzQxYTIxYjUyJyxcbiAgICAgICAgJzRjYjA0NDM3ZjM5MWVkNzMxMTFhMTNjYzFkNGRkMGRiMTY5MzQ2NWMyMjQwNDgwZDg5NTVlODU5MmYyNzQ0N2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDNhZTQxMDQ3ZGQ3Y2EwNjVkYmY4ZWQ3N2I5OTI0Mzk5ODMwMDVjZDcyZTE2ZDZmOTk2YTUzMTZkMzY5NjZiYicsXG4gICAgICAgICdiZDFhZWIyMWFkMjJlYmIyMmExMGYwMzAzNDE3YzZkOTY0ZjhjZGQ3ZGYwYWNhNjE0YjEwZGMxNGQxMjVhYzQ2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ2M2UyNzYzZDg4NWY5NThmYzY2Y2RkMjI4MDBmMGE0ODcxOTdkMGE4MmUzNzdiNDlmODBhZjg3Yzg5N2IwNjUnLFxuICAgICAgICAnYmZlZmFjZGIwZTVkMGZkN2RmM2EzMTFhOTRkZTA2MmIyNmI4MGM2MWZiYzk3NTA4Yjc5OTkyNjcxZWY3Y2E3ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3OTg1ZmRmZDEyN2MwNTY3YzZmNTNlYzFiYjYzZWMzMTU4ZTU5N2M0MGJmZTc0N2M4M2NkZGZjOTEwNjQxOTE3JyxcbiAgICAgICAgJzYwM2MxMmRhZjNkOTg2MmVmMmIyNWZlMWRlMjg5YWVkMjRlZDI5MWUwZWM2NzA4NzAzYTViZDU2N2YzMmVkMDMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzRhMWFkNmI1Zjc2ZTM5ZGIyZGQyNDk0MTBlYWM3Zjk5ZTc0YzU5Y2I4M2QyZDBlZDVmZjE1NDNkYTc3MDNlOScsXG4gICAgICAgICdjYzYxNTdlZjE4YzljNjNjZDYxOTNkODM2MzFiYmVhMDA5M2UwOTY4OTQyZThjMzNkNTczN2ZkNzkwZTBkYjA4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMwNjgyYTUwNzAzMzc1ZjYwMmQ0MTY2NjRiYTE5YjdmYzliYWI0MmM3Mjc0NzQ2M2E3MWQwODk2YjIyZjZkYTMnLFxuICAgICAgICAnNTUzZTA0ZjZiMDE4YjRmYTZjOGYzOWU3ZjMxMWQzMTc2MjkwZDBlMGYxOWNhNzNmMTc3MTRkOTk3N2EyMmZmOCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5ZTIxNThmMGQ3YzBkNWYyNmMzNzkxZWZlZmE3OTU5NzY1NGU3YTJiMjQ2NGY1MmIxZWU2YzEzNDc3NjllZjU3JyxcbiAgICAgICAgJzcxMmZjZGQxYjkwNTNmMDkwMDNhMzQ4MWZhNzc2MmU5ZmZkN2M4ZWYzNWEzODUwOWUyZmJmMjYyOTAwODM3MydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNzZlMjY5ODlhNDNjOWNmZWJhNDAyOWMyMDI1MzhjMjgxNzJlNTY2ZTNjNGZjZTczMjI4NTdmM2JlMzI3ZDY2JyxcbiAgICAgICAgJ2VkOGNjOWQwNGIyOWViODc3ZDI3MGI0ODc4ZGM0M2MxOWFlZmQzMWY0ZWVlMDllZTdiNDc4MzRjMWZhNGIxYzMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzVkNDZlZmVhMzc3MWU2ZTY4YWJiODlhMTNhZDc0N2VjZjE4OTIzOTNkZmM0ZjFiNzAwNDc4OGM1MDM3NGRhOCcsXG4gICAgICAgICc5ODUyMzkwYTk5NTA3Njc5ZmQwYjg2ZmQyYjM5YTg2OGQ3ZWZjMjIxNTEzNDZlMWEzY2E0NzI2NTg2YTZiZWQ4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzgwOWEyMGM2N2Q2NDkwMGZmYjY5OGM0YzgyNWY2ZDVmMjMxMGZiMDQ1MWM4NjkzNDViNzMxOWY2NDU2MDU3MjEnLFxuICAgICAgICAnOWU5OTQ5ODBkOTkxN2UyMmI3NmIwNjE5MjdmYTA0MTQzZDA5NmNjYzU0OTYzZTZhNWViZmE1ZjNmOGUyODZjMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxYjM4OTAzYTQzZjdmMTE0ZWQ0NTAwYjRlYWM3MDgzZmRlZmVjZTFjZjI5YzYzNTI4ZDU2MzQ0NmY5NzJjMTgwJyxcbiAgICAgICAgJzQwMzZlZGM5MzFhNjBhZTg4OTM1M2Y3N2ZkNTNkZTRhMjcwOGIyNmI2ZjVkYTcyYWQzMzk0MTE5ZGFmNDA4ZjknXG4gICAgICBdXG4gICAgXVxuICB9XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgdXRpbHMgPSBleHBvcnRzO1xudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcblxudXRpbHMuYXNzZXJ0ID0gZnVuY3Rpb24gYXNzZXJ0KHZhbCwgbXNnKSB7XG4gIGlmICghdmFsKVxuICAgIHRocm93IG5ldyBFcnJvcihtc2cgfHwgJ0Fzc2VydGlvbiBmYWlsZWQnKTtcbn07XG5cbmZ1bmN0aW9uIHRvQXJyYXkobXNnLCBlbmMpIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkobXNnKSlcbiAgICByZXR1cm4gbXNnLnNsaWNlKCk7XG4gIGlmICghbXNnKVxuICAgIHJldHVybiBbXTtcbiAgdmFyIHJlcyA9IFtdO1xuICBpZiAodHlwZW9mIG1zZyAhPT0gJ3N0cmluZycpIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKylcbiAgICAgIHJlc1tpXSA9IG1zZ1tpXSB8IDA7XG4gICAgcmV0dXJuIHJlcztcbiAgfVxuICBpZiAoIWVuYykge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgYyA9IG1zZy5jaGFyQ29kZUF0KGkpO1xuICAgICAgdmFyIGhpID0gYyA+PiA4O1xuICAgICAgdmFyIGxvID0gYyAmIDB4ZmY7XG4gICAgICBpZiAoaGkpXG4gICAgICAgIHJlcy5wdXNoKGhpLCBsbyk7XG4gICAgICBlbHNlXG4gICAgICAgIHJlcy5wdXNoKGxvKTtcbiAgICB9XG4gIH0gZWxzZSBpZiAoZW5jID09PSAnaGV4Jykge1xuICAgIG1zZyA9IG1zZy5yZXBsYWNlKC9bXmEtejAtOV0rL2lnLCAnJyk7XG4gICAgaWYgKG1zZy5sZW5ndGggJSAyICE9PSAwKVxuICAgICAgbXNnID0gJzAnICsgbXNnO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSArPSAyKVxuICAgICAgcmVzLnB1c2gocGFyc2VJbnQobXNnW2ldICsgbXNnW2kgKyAxXSwgMTYpKTtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxudXRpbHMudG9BcnJheSA9IHRvQXJyYXk7XG5cbmZ1bmN0aW9uIHplcm8yKHdvcmQpIHtcbiAgaWYgKHdvcmQubGVuZ3RoID09PSAxKVxuICAgIHJldHVybiAnMCcgKyB3b3JkO1xuICBlbHNlXG4gICAgcmV0dXJuIHdvcmQ7XG59XG51dGlscy56ZXJvMiA9IHplcm8yO1xuXG5mdW5jdGlvbiB0b0hleChtc2cpIHtcbiAgdmFyIHJlcyA9ICcnO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKylcbiAgICByZXMgKz0gemVybzIobXNnW2ldLnRvU3RyaW5nKDE2KSk7XG4gIHJldHVybiByZXM7XG59XG51dGlscy50b0hleCA9IHRvSGV4O1xuXG51dGlscy5lbmNvZGUgPSBmdW5jdGlvbiBlbmNvZGUoYXJyLCBlbmMpIHtcbiAgaWYgKGVuYyA9PT0gJ2hleCcpXG4gICAgcmV0dXJuIHRvSGV4KGFycik7XG4gIGVsc2VcbiAgICByZXR1cm4gYXJyO1xufTtcblxuLy8gUmVwcmVzZW50IG51bSBpbiBhIHctTkFGIGZvcm1cbmZ1bmN0aW9uIGdldE5BRihudW0sIHcpIHtcbiAgdmFyIG5hZiA9IFtdO1xuICB2YXIgd3MgPSAxIDw8ICh3ICsgMSk7XG4gIHZhciBrID0gbnVtLmNsb25lKCk7XG4gIHdoaWxlIChrLmNtcG4oMSkgPj0gMCkge1xuICAgIHZhciB6O1xuICAgIGlmIChrLmlzT2RkKCkpIHtcbiAgICAgIHZhciBtb2QgPSBrLmFuZGxuKHdzIC0gMSk7XG4gICAgICBpZiAobW9kID4gKHdzID4+IDEpIC0gMSlcbiAgICAgICAgeiA9ICh3cyA+PiAxKSAtIG1vZDtcbiAgICAgIGVsc2VcbiAgICAgICAgeiA9IG1vZDtcbiAgICAgIGsuaXN1Ym4oeik7XG4gICAgfSBlbHNlIHtcbiAgICAgIHogPSAwO1xuICAgIH1cbiAgICBuYWYucHVzaCh6KTtcblxuICAgIC8vIE9wdGltaXphdGlvbiwgc2hpZnQgYnkgd29yZCBpZiBwb3NzaWJsZVxuICAgIHZhciBzaGlmdCA9IChrLmNtcG4oMCkgIT09IDAgJiYgay5hbmRsbih3cyAtIDEpID09PSAwKSA/ICh3ICsgMSkgOiAxO1xuICAgIGZvciAodmFyIGkgPSAxOyBpIDwgc2hpZnQ7IGkrKylcbiAgICAgIG5hZi5wdXNoKDApO1xuICAgIGsuaXVzaHJuKHNoaWZ0KTtcbiAgfVxuXG4gIHJldHVybiBuYWY7XG59XG51dGlscy5nZXROQUYgPSBnZXROQUY7XG5cbi8vIFJlcHJlc2VudCBrMSwgazIgaW4gYSBKb2ludCBTcGFyc2UgRm9ybVxuZnVuY3Rpb24gZ2V0SlNGKGsxLCBrMikge1xuICB2YXIganNmID0gW1xuICAgIFtdLFxuICAgIFtdXG4gIF07XG5cbiAgazEgPSBrMS5jbG9uZSgpO1xuICBrMiA9IGsyLmNsb25lKCk7XG4gIHZhciBkMSA9IDA7XG4gIHZhciBkMiA9IDA7XG4gIHdoaWxlIChrMS5jbXBuKC1kMSkgPiAwIHx8IGsyLmNtcG4oLWQyKSA+IDApIHtcblxuICAgIC8vIEZpcnN0IHBoYXNlXG4gICAgdmFyIG0xNCA9IChrMS5hbmRsbigzKSArIGQxKSAmIDM7XG4gICAgdmFyIG0yNCA9IChrMi5hbmRsbigzKSArIGQyKSAmIDM7XG4gICAgaWYgKG0xNCA9PT0gMylcbiAgICAgIG0xNCA9IC0xO1xuICAgIGlmIChtMjQgPT09IDMpXG4gICAgICBtMjQgPSAtMTtcbiAgICB2YXIgdTE7XG4gICAgaWYgKChtMTQgJiAxKSA9PT0gMCkge1xuICAgICAgdTEgPSAwO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbTggPSAoazEuYW5kbG4oNykgKyBkMSkgJiA3O1xuICAgICAgaWYgKChtOCA9PT0gMyB8fCBtOCA9PT0gNSkgJiYgbTI0ID09PSAyKVxuICAgICAgICB1MSA9IC1tMTQ7XG4gICAgICBlbHNlXG4gICAgICAgIHUxID0gbTE0O1xuICAgIH1cbiAgICBqc2ZbMF0ucHVzaCh1MSk7XG5cbiAgICB2YXIgdTI7XG4gICAgaWYgKChtMjQgJiAxKSA9PT0gMCkge1xuICAgICAgdTIgPSAwO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbTggPSAoazIuYW5kbG4oNykgKyBkMikgJiA3O1xuICAgICAgaWYgKChtOCA9PT0gMyB8fCBtOCA9PT0gNSkgJiYgbTE0ID09PSAyKVxuICAgICAgICB1MiA9IC1tMjQ7XG4gICAgICBlbHNlXG4gICAgICAgIHUyID0gbTI0O1xuICAgIH1cbiAgICBqc2ZbMV0ucHVzaCh1Mik7XG5cbiAgICAvLyBTZWNvbmQgcGhhc2VcbiAgICBpZiAoMiAqIGQxID09PSB1MSArIDEpXG4gICAgICBkMSA9IDEgLSBkMTtcbiAgICBpZiAoMiAqIGQyID09PSB1MiArIDEpXG4gICAgICBkMiA9IDEgLSBkMjtcbiAgICBrMS5pdXNocm4oMSk7XG4gICAgazIuaXVzaHJuKDEpO1xuICB9XG5cbiAgcmV0dXJuIGpzZjtcbn1cbnV0aWxzLmdldEpTRiA9IGdldEpTRjtcblxuZnVuY3Rpb24gY2FjaGVkUHJvcGVydHkob2JqLCBuYW1lLCBjb21wdXRlcikge1xuICB2YXIga2V5ID0gJ18nICsgbmFtZTtcbiAgb2JqLnByb3RvdHlwZVtuYW1lXSA9IGZ1bmN0aW9uIGNhY2hlZFByb3BlcnR5KCkge1xuICAgIHJldHVybiB0aGlzW2tleV0gIT09IHVuZGVmaW5lZCA/IHRoaXNba2V5XSA6XG4gICAgICAgICAgIHRoaXNba2V5XSA9IGNvbXB1dGVyLmNhbGwodGhpcyk7XG4gIH07XG59XG51dGlscy5jYWNoZWRQcm9wZXJ0eSA9IGNhY2hlZFByb3BlcnR5O1xuXG5mdW5jdGlvbiBwYXJzZUJ5dGVzKGJ5dGVzKSB7XG4gIHJldHVybiB0eXBlb2YgYnl0ZXMgPT09ICdzdHJpbmcnID8gdXRpbHMudG9BcnJheShieXRlcywgJ2hleCcpIDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBieXRlcztcbn1cbnV0aWxzLnBhcnNlQnl0ZXMgPSBwYXJzZUJ5dGVzO1xuXG5mdW5jdGlvbiBpbnRGcm9tTEUoYnl0ZXMpIHtcbiAgcmV0dXJuIG5ldyBCTihieXRlcywgJ2hleCcsICdsZScpO1xufVxudXRpbHMuaW50RnJvbUxFID0gaW50RnJvbUxFO1xuXG4iLCJtb2R1bGUuZXhwb3J0cz17XG4gIFwiX2FyZ3NcIjogW1xuICAgIFtcbiAgICAgIFwiZWxsaXB0aWNAXjYuMC4wXCIsXG4gICAgICBcIi9Vc2Vycy9jbWV0Y2FsZi9wcm9qZWN0cy9nZW4tY3NyL25vZGVfbW9kdWxlcy9icm93c2VyaWZ5LXNpZ25cIlxuICAgIF1cbiAgXSxcbiAgXCJfZnJvbVwiOiBcImVsbGlwdGljQD49Ni4wLjAgPDcuMC4wXCIsXG4gIFwiX2lkXCI6IFwiZWxsaXB0aWNANi4yLjdcIixcbiAgXCJfaW5DYWNoZVwiOiB0cnVlLFxuICBcIl9pbnN0YWxsYWJsZVwiOiB0cnVlLFxuICBcIl9sb2NhdGlvblwiOiBcIi9lbGxpcHRpY1wiLFxuICBcIl9ub2RlVmVyc2lvblwiOiBcIjYuMC4wXCIsXG4gIFwiX25wbU9wZXJhdGlvbmFsSW50ZXJuYWxcIjoge1xuICAgIFwiaG9zdFwiOiBcInBhY2thZ2VzLTEyLXdlc3QuaW50ZXJuYWwubnBtanMuY29tXCIsXG4gICAgXCJ0bXBcIjogXCJ0bXAvZWxsaXB0aWMtNi4yLjcudGd6XzE0NjQyMDE3OTMyMDJfMC4xMjQ3OTg3ODI4NjgzMTA4MVwiXG4gIH0sXG4gIFwiX25wbVVzZXJcIjoge1xuICAgIFwiZW1haWxcIjogXCJmZWRvckBpbmR1dG55LmNvbVwiLFxuICAgIFwibmFtZVwiOiBcImluZHV0bnlcIlxuICB9LFxuICBcIl9ucG1WZXJzaW9uXCI6IFwiMy44LjZcIixcbiAgXCJfcGhhbnRvbUNoaWxkcmVuXCI6IHt9LFxuICBcIl9yZXF1ZXN0ZWRcIjoge1xuICAgIFwibmFtZVwiOiBcImVsbGlwdGljXCIsXG4gICAgXCJyYXdcIjogXCJlbGxpcHRpY0BeNi4wLjBcIixcbiAgICBcInJhd1NwZWNcIjogXCJeNi4wLjBcIixcbiAgICBcInNjb3BlXCI6IG51bGwsXG4gICAgXCJzcGVjXCI6IFwiPj02LjAuMCA8Ny4wLjBcIixcbiAgICBcInR5cGVcIjogXCJyYW5nZVwiXG4gIH0sXG4gIFwiX3JlcXVpcmVkQnlcIjogW1xuICAgIFwiL2Jyb3dzZXJpZnktc2lnblwiLFxuICAgIFwiL2NyZWF0ZS1lY2RoXCJcbiAgXSxcbiAgXCJfcmVzb2x2ZWRcIjogXCJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZy9lbGxpcHRpYy8tL2VsbGlwdGljLTYuMi43LnRnelwiLFxuICBcIl9zaGFzdW1cIjogXCJkY2U4MmVmYmYxNzZlZWZhNzQ5NWQ0YmUzZThiOWY1YjU2OTRiMjk1XCIsXG4gIFwiX3Nocmlua3dyYXBcIjogbnVsbCxcbiAgXCJfc3BlY1wiOiBcImVsbGlwdGljQF42LjAuMFwiLFxuICBcIl93aGVyZVwiOiBcIi9Vc2Vycy9jbWV0Y2FsZi9wcm9qZWN0cy9nZW4tY3NyL25vZGVfbW9kdWxlcy9icm93c2VyaWZ5LXNpZ25cIixcbiAgXCJhdXRob3JcIjoge1xuICAgIFwiZW1haWxcIjogXCJmZWRvckBpbmR1dG55LmNvbVwiLFxuICAgIFwibmFtZVwiOiBcIkZlZG9yIEluZHV0bnlcIlxuICB9LFxuICBcImJ1Z3NcIjoge1xuICAgIFwidXJsXCI6IFwiaHR0cHM6Ly9naXRodWIuY29tL2luZHV0bnkvZWxsaXB0aWMvaXNzdWVzXCJcbiAgfSxcbiAgXCJkZXBlbmRlbmNpZXNcIjoge1xuICAgIFwiYm4uanNcIjogXCJeNC4wLjBcIixcbiAgICBcImJyb3JhbmRcIjogXCJeMS4wLjFcIixcbiAgICBcImhhc2guanNcIjogXCJeMS4wLjBcIixcbiAgICBcImluaGVyaXRzXCI6IFwiXjIuMC4xXCJcbiAgfSxcbiAgXCJkZXNjcmlwdGlvblwiOiBcIkVDIGNyeXB0b2dyYXBoeVwiLFxuICBcImRldkRlcGVuZGVuY2llc1wiOiB7XG4gICAgXCJicmZzXCI6IFwiXjEuNC4zXCIsXG4gICAgXCJjb3ZlcmFsbHNcIjogXCJeMi4xMS4zXCIsXG4gICAgXCJncnVudFwiOiBcIl4wLjQuNVwiLFxuICAgIFwiZ3J1bnQtYnJvd3NlcmlmeVwiOiBcIl41LjAuMFwiLFxuICAgIFwiZ3J1bnQtY29udHJpYi1jb25uZWN0XCI6IFwiXjEuMC4wXCIsXG4gICAgXCJncnVudC1jb250cmliLWNvcHlcIjogXCJeMS4wLjBcIixcbiAgICBcImdydW50LWNvbnRyaWItdWdsaWZ5XCI6IFwiXjEuMC4xXCIsXG4gICAgXCJncnVudC1tb2NoYS1pc3RhbmJ1bFwiOiBcIl4zLjAuMVwiLFxuICAgIFwiZ3J1bnQtc2F1Y2VsYWJzXCI6IFwiXjguNi4yXCIsXG4gICAgXCJpc3RhbmJ1bFwiOiBcIl4wLjQuMlwiLFxuICAgIFwianNjc1wiOiBcIl4yLjkuMFwiLFxuICAgIFwianNoaW50XCI6IFwiXjIuNi4wXCIsXG4gICAgXCJtb2NoYVwiOiBcIl4yLjEuMFwiXG4gIH0sXG4gIFwiZGlyZWN0b3JpZXNcIjoge30sXG4gIFwiZGlzdFwiOiB7XG4gICAgXCJzaGFzdW1cIjogXCJkY2U4MmVmYmYxNzZlZWZhNzQ5NWQ0YmUzZThiOWY1YjU2OTRiMjk1XCIsXG4gICAgXCJ0YXJiYWxsXCI6IFwiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmcvZWxsaXB0aWMvLS9lbGxpcHRpYy02LjIuNy50Z3pcIlxuICB9LFxuICBcImZpbGVzXCI6IFtcbiAgICBcImxpYlwiXG4gIF0sXG4gIFwiZ2l0SGVhZFwiOiBcIjZhOGVmMTQ1N2JiOGY0NTEwMmQ2Njc4ZmMxMDk1MTY1Zjc3ZDU1ZDNcIixcbiAgXCJob21lcGFnZVwiOiBcImh0dHBzOi8vZ2l0aHViLmNvbS9pbmR1dG55L2VsbGlwdGljXCIsXG4gIFwia2V5d29yZHNcIjogW1xuICAgIFwiRUNcIixcbiAgICBcIkVsbGlwdGljXCIsXG4gICAgXCJjdXJ2ZVwiLFxuICAgIFwiQ3J5cHRvZ3JhcGh5XCJcbiAgXSxcbiAgXCJsaWNlbnNlXCI6IFwiTUlUXCIsXG4gIFwibWFpblwiOiBcImxpYi9lbGxpcHRpYy5qc1wiLFxuICBcIm1haW50YWluZXJzXCI6IFtcbiAgICB7XG4gICAgICBcImVtYWlsXCI6IFwiZmVkb3JAaW5kdXRueS5jb21cIixcbiAgICAgIFwibmFtZVwiOiBcImluZHV0bnlcIlxuICAgIH1cbiAgXSxcbiAgXCJuYW1lXCI6IFwiZWxsaXB0aWNcIixcbiAgXCJvcHRpb25hbERlcGVuZGVuY2llc1wiOiB7fSxcbiAgXCJyZWFkbWVcIjogXCJFUlJPUjogTm8gUkVBRE1FIGRhdGEgZm91bmQhXCIsXG4gIFwicmVwb3NpdG9yeVwiOiB7XG4gICAgXCJ0eXBlXCI6IFwiZ2l0XCIsXG4gICAgXCJ1cmxcIjogXCJnaXQrc3NoOi8vZ2l0QGdpdGh1Yi5jb20vaW5kdXRueS9lbGxpcHRpYy5naXRcIlxuICB9LFxuICBcInNjcmlwdHNcIjoge1xuICAgIFwianNjc1wiOiBcImpzY3MgYmVuY2htYXJrcy8qLmpzIGxpYi8qLmpzIGxpYi8qKi8qLmpzIGxpYi8qKi8qKi8qLmpzIHRlc3QvaW5kZXguanNcIixcbiAgICBcImpzaGludFwiOiBcImpzY3MgYmVuY2htYXJrcy8qLmpzIGxpYi8qLmpzIGxpYi8qKi8qLmpzIGxpYi8qKi8qKi8qLmpzIHRlc3QvaW5kZXguanNcIixcbiAgICBcImxpbnRcIjogXCJucG0gcnVuIGpzY3MgJiYgbnBtIHJ1biBqc2hpbnRcIixcbiAgICBcInRlc3RcIjogXCJucG0gcnVuIGxpbnQgJiYgbnBtIHJ1biB1bml0XCIsXG4gICAgXCJ1bml0XCI6IFwiaXN0YW5idWwgdGVzdCBfbW9jaGEgLS1yZXBvcnRlcj1zcGVjIHRlc3QvaW5kZXguanNcIixcbiAgICBcInZlcnNpb25cIjogXCJncnVudCBkaXN0ICYmIGdpdCBhZGQgZGlzdC9cIlxuICB9LFxuICBcInZlcnNpb25cIjogXCI2LjIuN1wiXG59XG4iLCJ2YXIgaGFzaCA9IGV4cG9ydHM7XG5cbmhhc2gudXRpbHMgPSByZXF1aXJlKCcuL2hhc2gvdXRpbHMnKTtcbmhhc2guY29tbW9uID0gcmVxdWlyZSgnLi9oYXNoL2NvbW1vbicpO1xuaGFzaC5zaGEgPSByZXF1aXJlKCcuL2hhc2gvc2hhJyk7XG5oYXNoLnJpcGVtZCA9IHJlcXVpcmUoJy4vaGFzaC9yaXBlbWQnKTtcbmhhc2guaG1hYyA9IHJlcXVpcmUoJy4vaGFzaC9obWFjJyk7XG5cbi8vIFByb3h5IGhhc2ggZnVuY3Rpb25zIHRvIHRoZSBtYWluIG9iamVjdFxuaGFzaC5zaGExID0gaGFzaC5zaGEuc2hhMTtcbmhhc2guc2hhMjU2ID0gaGFzaC5zaGEuc2hhMjU2O1xuaGFzaC5zaGEyMjQgPSBoYXNoLnNoYS5zaGEyMjQ7XG5oYXNoLnNoYTM4NCA9IGhhc2guc2hhLnNoYTM4NDtcbmhhc2guc2hhNTEyID0gaGFzaC5zaGEuc2hhNTEyO1xuaGFzaC5yaXBlbWQxNjAgPSBoYXNoLnJpcGVtZC5yaXBlbWQxNjA7XG4iLCJ2YXIgaGFzaCA9IHJlcXVpcmUoJy4uL2hhc2gnKTtcbnZhciB1dGlscyA9IGhhc2gudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBCbG9ja0hhc2goKSB7XG4gIHRoaXMucGVuZGluZyA9IG51bGw7XG4gIHRoaXMucGVuZGluZ1RvdGFsID0gMDtcbiAgdGhpcy5ibG9ja1NpemUgPSB0aGlzLmNvbnN0cnVjdG9yLmJsb2NrU2l6ZTtcbiAgdGhpcy5vdXRTaXplID0gdGhpcy5jb25zdHJ1Y3Rvci5vdXRTaXplO1xuICB0aGlzLmhtYWNTdHJlbmd0aCA9IHRoaXMuY29uc3RydWN0b3IuaG1hY1N0cmVuZ3RoO1xuICB0aGlzLnBhZExlbmd0aCA9IHRoaXMuY29uc3RydWN0b3IucGFkTGVuZ3RoIC8gODtcbiAgdGhpcy5lbmRpYW4gPSAnYmlnJztcblxuICB0aGlzLl9kZWx0YTggPSB0aGlzLmJsb2NrU2l6ZSAvIDg7XG4gIHRoaXMuX2RlbHRhMzIgPSB0aGlzLmJsb2NrU2l6ZSAvIDMyO1xufVxuZXhwb3J0cy5CbG9ja0hhc2ggPSBCbG9ja0hhc2g7XG5cbkJsb2NrSGFzaC5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24gdXBkYXRlKG1zZywgZW5jKSB7XG4gIC8vIENvbnZlcnQgbWVzc2FnZSB0byBhcnJheSwgcGFkIGl0LCBhbmQgam9pbiBpbnRvIDMyYml0IGJsb2Nrc1xuICBtc2cgPSB1dGlscy50b0FycmF5KG1zZywgZW5jKTtcbiAgaWYgKCF0aGlzLnBlbmRpbmcpXG4gICAgdGhpcy5wZW5kaW5nID0gbXNnO1xuICBlbHNlXG4gICAgdGhpcy5wZW5kaW5nID0gdGhpcy5wZW5kaW5nLmNvbmNhdChtc2cpO1xuICB0aGlzLnBlbmRpbmdUb3RhbCArPSBtc2cubGVuZ3RoO1xuXG4gIC8vIEVub3VnaCBkYXRhLCB0cnkgdXBkYXRpbmdcbiAgaWYgKHRoaXMucGVuZGluZy5sZW5ndGggPj0gdGhpcy5fZGVsdGE4KSB7XG4gICAgbXNnID0gdGhpcy5wZW5kaW5nO1xuXG4gICAgLy8gUHJvY2VzcyBwZW5kaW5nIGRhdGEgaW4gYmxvY2tzXG4gICAgdmFyIHIgPSBtc2cubGVuZ3RoICUgdGhpcy5fZGVsdGE4O1xuICAgIHRoaXMucGVuZGluZyA9IG1zZy5zbGljZShtc2cubGVuZ3RoIC0gciwgbXNnLmxlbmd0aCk7XG4gICAgaWYgKHRoaXMucGVuZGluZy5sZW5ndGggPT09IDApXG4gICAgICB0aGlzLnBlbmRpbmcgPSBudWxsO1xuXG4gICAgbXNnID0gdXRpbHMuam9pbjMyKG1zZywgMCwgbXNnLmxlbmd0aCAtIHIsIHRoaXMuZW5kaWFuKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkgKz0gdGhpcy5fZGVsdGEzMilcbiAgICAgIHRoaXMuX3VwZGF0ZShtc2csIGksIGkgKyB0aGlzLl9kZWx0YTMyKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuQmxvY2tIYXNoLnByb3RvdHlwZS5kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIHRoaXMudXBkYXRlKHRoaXMuX3BhZCgpKTtcbiAgYXNzZXJ0KHRoaXMucGVuZGluZyA9PT0gbnVsbCk7XG5cbiAgcmV0dXJuIHRoaXMuX2RpZ2VzdChlbmMpO1xufTtcblxuQmxvY2tIYXNoLnByb3RvdHlwZS5fcGFkID0gZnVuY3Rpb24gcGFkKCkge1xuICB2YXIgbGVuID0gdGhpcy5wZW5kaW5nVG90YWw7XG4gIHZhciBieXRlcyA9IHRoaXMuX2RlbHRhODtcbiAgdmFyIGsgPSBieXRlcyAtICgobGVuICsgdGhpcy5wYWRMZW5ndGgpICUgYnl0ZXMpO1xuICB2YXIgcmVzID0gbmV3IEFycmF5KGsgKyB0aGlzLnBhZExlbmd0aCk7XG4gIHJlc1swXSA9IDB4ODA7XG4gIGZvciAodmFyIGkgPSAxOyBpIDwgazsgaSsrKVxuICAgIHJlc1tpXSA9IDA7XG5cbiAgLy8gQXBwZW5kIGxlbmd0aFxuICBsZW4gPDw9IDM7XG4gIGlmICh0aGlzLmVuZGlhbiA9PT0gJ2JpZycpIHtcbiAgICBmb3IgKHZhciB0ID0gODsgdCA8IHRoaXMucGFkTGVuZ3RoOyB0KyspXG4gICAgICByZXNbaSsrXSA9IDA7XG5cbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAwO1xuICAgIHJlc1tpKytdID0gMDtcbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAobGVuID4+PiAyNCkgJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gMTYpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IChsZW4gPj4+IDgpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IGxlbiAmIDB4ZmY7XG4gIH0gZWxzZSB7XG4gICAgcmVzW2krK10gPSBsZW4gJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gOCkgJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gMTYpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IChsZW4gPj4+IDI0KSAmIDB4ZmY7XG4gICAgcmVzW2krK10gPSAwO1xuICAgIHJlc1tpKytdID0gMDtcbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAwO1xuXG4gICAgZm9yICh2YXIgdCA9IDg7IHQgPCB0aGlzLnBhZExlbmd0aDsgdCsrKVxuICAgICAgcmVzW2krK10gPSAwO1xuICB9XG5cbiAgcmV0dXJuIHJlcztcbn07XG4iLCJ2YXIgaG1hYyA9IGV4cG9ydHM7XG5cbnZhciBoYXNoID0gcmVxdWlyZSgnLi4vaGFzaCcpO1xudmFyIHV0aWxzID0gaGFzaC51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbmZ1bmN0aW9uIEhtYWMoaGFzaCwga2V5LCBlbmMpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIEhtYWMpKVxuICAgIHJldHVybiBuZXcgSG1hYyhoYXNoLCBrZXksIGVuYyk7XG4gIHRoaXMuSGFzaCA9IGhhc2g7XG4gIHRoaXMuYmxvY2tTaXplID0gaGFzaC5ibG9ja1NpemUgLyA4O1xuICB0aGlzLm91dFNpemUgPSBoYXNoLm91dFNpemUgLyA4O1xuICB0aGlzLmlubmVyID0gbnVsbDtcbiAgdGhpcy5vdXRlciA9IG51bGw7XG5cbiAgdGhpcy5faW5pdCh1dGlscy50b0FycmF5KGtleSwgZW5jKSk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEhtYWM7XG5cbkhtYWMucHJvdG90eXBlLl9pbml0ID0gZnVuY3Rpb24gaW5pdChrZXkpIHtcbiAgLy8gU2hvcnRlbiBrZXksIGlmIG5lZWRlZFxuICBpZiAoa2V5Lmxlbmd0aCA+IHRoaXMuYmxvY2tTaXplKVxuICAgIGtleSA9IG5ldyB0aGlzLkhhc2goKS51cGRhdGUoa2V5KS5kaWdlc3QoKTtcbiAgYXNzZXJ0KGtleS5sZW5ndGggPD0gdGhpcy5ibG9ja1NpemUpO1xuXG4gIC8vIEFkZCBwYWRkaW5nIHRvIGtleVxuICBmb3IgKHZhciBpID0ga2V5Lmxlbmd0aDsgaSA8IHRoaXMuYmxvY2tTaXplOyBpKyspXG4gICAga2V5LnB1c2goMCk7XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBrZXkubGVuZ3RoOyBpKyspXG4gICAga2V5W2ldIF49IDB4MzY7XG4gIHRoaXMuaW5uZXIgPSBuZXcgdGhpcy5IYXNoKCkudXBkYXRlKGtleSk7XG5cbiAgLy8gMHgzNiBeIDB4NWMgPSAweDZhXG4gIGZvciAodmFyIGkgPSAwOyBpIDwga2V5Lmxlbmd0aDsgaSsrKVxuICAgIGtleVtpXSBePSAweDZhO1xuICB0aGlzLm91dGVyID0gbmV3IHRoaXMuSGFzaCgpLnVwZGF0ZShrZXkpO1xufTtcblxuSG1hYy5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24gdXBkYXRlKG1zZywgZW5jKSB7XG4gIHRoaXMuaW5uZXIudXBkYXRlKG1zZywgZW5jKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5IbWFjLnByb3RvdHlwZS5kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIHRoaXMub3V0ZXIudXBkYXRlKHRoaXMuaW5uZXIuZGlnZXN0KCkpO1xuICByZXR1cm4gdGhpcy5vdXRlci5kaWdlc3QoZW5jKTtcbn07XG4iLCJ2YXIgaGFzaCA9IHJlcXVpcmUoJy4uL2hhc2gnKTtcbnZhciB1dGlscyA9IGhhc2gudXRpbHM7XG5cbnZhciByb3RsMzIgPSB1dGlscy5yb3RsMzI7XG52YXIgc3VtMzIgPSB1dGlscy5zdW0zMjtcbnZhciBzdW0zMl8zID0gdXRpbHMuc3VtMzJfMztcbnZhciBzdW0zMl80ID0gdXRpbHMuc3VtMzJfNDtcbnZhciBCbG9ja0hhc2ggPSBoYXNoLmNvbW1vbi5CbG9ja0hhc2g7XG5cbmZ1bmN0aW9uIFJJUEVNRDE2MCgpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIFJJUEVNRDE2MCkpXG4gICAgcmV0dXJuIG5ldyBSSVBFTUQxNjAoKTtcblxuICBCbG9ja0hhc2guY2FsbCh0aGlzKTtcblxuICB0aGlzLmggPSBbIDB4Njc0NTIzMDEsIDB4ZWZjZGFiODksIDB4OThiYWRjZmUsIDB4MTAzMjU0NzYsIDB4YzNkMmUxZjAgXTtcbiAgdGhpcy5lbmRpYW4gPSAnbGl0dGxlJztcbn1cbnV0aWxzLmluaGVyaXRzKFJJUEVNRDE2MCwgQmxvY2tIYXNoKTtcbmV4cG9ydHMucmlwZW1kMTYwID0gUklQRU1EMTYwO1xuXG5SSVBFTUQxNjAuYmxvY2tTaXplID0gNTEyO1xuUklQRU1EMTYwLm91dFNpemUgPSAxNjA7XG5SSVBFTUQxNjAuaG1hY1N0cmVuZ3RoID0gMTkyO1xuUklQRU1EMTYwLnBhZExlbmd0aCA9IDY0O1xuXG5SSVBFTUQxNjAucHJvdG90eXBlLl91cGRhdGUgPSBmdW5jdGlvbiB1cGRhdGUobXNnLCBzdGFydCkge1xuICB2YXIgQSA9IHRoaXMuaFswXTtcbiAgdmFyIEIgPSB0aGlzLmhbMV07XG4gIHZhciBDID0gdGhpcy5oWzJdO1xuICB2YXIgRCA9IHRoaXMuaFszXTtcbiAgdmFyIEUgPSB0aGlzLmhbNF07XG4gIHZhciBBaCA9IEE7XG4gIHZhciBCaCA9IEI7XG4gIHZhciBDaCA9IEM7XG4gIHZhciBEaCA9IEQ7XG4gIHZhciBFaCA9IEU7XG4gIGZvciAodmFyIGogPSAwOyBqIDwgODA7IGorKykge1xuICAgIHZhciBUID0gc3VtMzIoXG4gICAgICByb3RsMzIoXG4gICAgICAgIHN1bTMyXzQoQSwgZihqLCBCLCBDLCBEKSwgbXNnW3Jbal0gKyBzdGFydF0sIEsoaikpLFxuICAgICAgICBzW2pdKSxcbiAgICAgIEUpO1xuICAgIEEgPSBFO1xuICAgIEUgPSBEO1xuICAgIEQgPSByb3RsMzIoQywgMTApO1xuICAgIEMgPSBCO1xuICAgIEIgPSBUO1xuICAgIFQgPSBzdW0zMihcbiAgICAgIHJvdGwzMihcbiAgICAgICAgc3VtMzJfNChBaCwgZig3OSAtIGosIEJoLCBDaCwgRGgpLCBtc2dbcmhbal0gKyBzdGFydF0sIEtoKGopKSxcbiAgICAgICAgc2hbal0pLFxuICAgICAgRWgpO1xuICAgIEFoID0gRWg7XG4gICAgRWggPSBEaDtcbiAgICBEaCA9IHJvdGwzMihDaCwgMTApO1xuICAgIENoID0gQmg7XG4gICAgQmggPSBUO1xuICB9XG4gIFQgPSBzdW0zMl8zKHRoaXMuaFsxXSwgQywgRGgpO1xuICB0aGlzLmhbMV0gPSBzdW0zMl8zKHRoaXMuaFsyXSwgRCwgRWgpO1xuICB0aGlzLmhbMl0gPSBzdW0zMl8zKHRoaXMuaFszXSwgRSwgQWgpO1xuICB0aGlzLmhbM10gPSBzdW0zMl8zKHRoaXMuaFs0XSwgQSwgQmgpO1xuICB0aGlzLmhbNF0gPSBzdW0zMl8zKHRoaXMuaFswXSwgQiwgQ2gpO1xuICB0aGlzLmhbMF0gPSBUO1xufTtcblxuUklQRU1EMTYwLnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmgsICdsaXR0bGUnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaCwgJ2xpdHRsZScpO1xufTtcblxuZnVuY3Rpb24gZihqLCB4LCB5LCB6KSB7XG4gIGlmIChqIDw9IDE1KVxuICAgIHJldHVybiB4IF4geSBeIHo7XG4gIGVsc2UgaWYgKGogPD0gMzEpXG4gICAgcmV0dXJuICh4ICYgeSkgfCAoKH54KSAmIHopO1xuICBlbHNlIGlmIChqIDw9IDQ3KVxuICAgIHJldHVybiAoeCB8ICh+eSkpIF4gejtcbiAgZWxzZSBpZiAoaiA8PSA2MylcbiAgICByZXR1cm4gKHggJiB6KSB8ICh5ICYgKH56KSk7XG4gIGVsc2VcbiAgICByZXR1cm4geCBeICh5IHwgKH56KSk7XG59XG5cbmZ1bmN0aW9uIEsoaikge1xuICBpZiAoaiA8PSAxNSlcbiAgICByZXR1cm4gMHgwMDAwMDAwMDtcbiAgZWxzZSBpZiAoaiA8PSAzMSlcbiAgICByZXR1cm4gMHg1YTgyNzk5OTtcbiAgZWxzZSBpZiAoaiA8PSA0NylcbiAgICByZXR1cm4gMHg2ZWQ5ZWJhMTtcbiAgZWxzZSBpZiAoaiA8PSA2MylcbiAgICByZXR1cm4gMHg4ZjFiYmNkYztcbiAgZWxzZVxuICAgIHJldHVybiAweGE5NTNmZDRlO1xufVxuXG5mdW5jdGlvbiBLaChqKSB7XG4gIGlmIChqIDw9IDE1KVxuICAgIHJldHVybiAweDUwYTI4YmU2O1xuICBlbHNlIGlmIChqIDw9IDMxKVxuICAgIHJldHVybiAweDVjNGRkMTI0O1xuICBlbHNlIGlmIChqIDw9IDQ3KVxuICAgIHJldHVybiAweDZkNzAzZWYzO1xuICBlbHNlIGlmIChqIDw9IDYzKVxuICAgIHJldHVybiAweDdhNmQ3NmU5O1xuICBlbHNlXG4gICAgcmV0dXJuIDB4MDAwMDAwMDA7XG59XG5cbnZhciByID0gW1xuICAwLCAxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5LCAxMCwgMTEsIDEyLCAxMywgMTQsIDE1LFxuICA3LCA0LCAxMywgMSwgMTAsIDYsIDE1LCAzLCAxMiwgMCwgOSwgNSwgMiwgMTQsIDExLCA4LFxuICAzLCAxMCwgMTQsIDQsIDksIDE1LCA4LCAxLCAyLCA3LCAwLCA2LCAxMywgMTEsIDUsIDEyLFxuICAxLCA5LCAxMSwgMTAsIDAsIDgsIDEyLCA0LCAxMywgMywgNywgMTUsIDE0LCA1LCA2LCAyLFxuICA0LCAwLCA1LCA5LCA3LCAxMiwgMiwgMTAsIDE0LCAxLCAzLCA4LCAxMSwgNiwgMTUsIDEzXG5dO1xuXG52YXIgcmggPSBbXG4gIDUsIDE0LCA3LCAwLCA5LCAyLCAxMSwgNCwgMTMsIDYsIDE1LCA4LCAxLCAxMCwgMywgMTIsXG4gIDYsIDExLCAzLCA3LCAwLCAxMywgNSwgMTAsIDE0LCAxNSwgOCwgMTIsIDQsIDksIDEsIDIsXG4gIDE1LCA1LCAxLCAzLCA3LCAxNCwgNiwgOSwgMTEsIDgsIDEyLCAyLCAxMCwgMCwgNCwgMTMsXG4gIDgsIDYsIDQsIDEsIDMsIDExLCAxNSwgMCwgNSwgMTIsIDIsIDEzLCA5LCA3LCAxMCwgMTQsXG4gIDEyLCAxNSwgMTAsIDQsIDEsIDUsIDgsIDcsIDYsIDIsIDEzLCAxNCwgMCwgMywgOSwgMTFcbl07XG5cbnZhciBzID0gW1xuICAxMSwgMTQsIDE1LCAxMiwgNSwgOCwgNywgOSwgMTEsIDEzLCAxNCwgMTUsIDYsIDcsIDksIDgsXG4gIDcsIDYsIDgsIDEzLCAxMSwgOSwgNywgMTUsIDcsIDEyLCAxNSwgOSwgMTEsIDcsIDEzLCAxMixcbiAgMTEsIDEzLCA2LCA3LCAxNCwgOSwgMTMsIDE1LCAxNCwgOCwgMTMsIDYsIDUsIDEyLCA3LCA1LFxuICAxMSwgMTIsIDE0LCAxNSwgMTQsIDE1LCA5LCA4LCA5LCAxNCwgNSwgNiwgOCwgNiwgNSwgMTIsXG4gIDksIDE1LCA1LCAxMSwgNiwgOCwgMTMsIDEyLCA1LCAxMiwgMTMsIDE0LCAxMSwgOCwgNSwgNlxuXTtcblxudmFyIHNoID0gW1xuICA4LCA5LCA5LCAxMSwgMTMsIDE1LCAxNSwgNSwgNywgNywgOCwgMTEsIDE0LCAxNCwgMTIsIDYsXG4gIDksIDEzLCAxNSwgNywgMTIsIDgsIDksIDExLCA3LCA3LCAxMiwgNywgNiwgMTUsIDEzLCAxMSxcbiAgOSwgNywgMTUsIDExLCA4LCA2LCA2LCAxNCwgMTIsIDEzLCA1LCAxNCwgMTMsIDEzLCA3LCA1LFxuICAxNSwgNSwgOCwgMTEsIDE0LCAxNCwgNiwgMTQsIDYsIDksIDEyLCA5LCAxMiwgNSwgMTUsIDgsXG4gIDgsIDUsIDEyLCA5LCAxMiwgNSwgMTQsIDYsIDgsIDEzLCA2LCA1LCAxNSwgMTMsIDExLCAxMVxuXTtcbiIsInZhciBoYXNoID0gcmVxdWlyZSgnLi4vaGFzaCcpO1xudmFyIHV0aWxzID0gaGFzaC51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbnZhciByb3RyMzIgPSB1dGlscy5yb3RyMzI7XG52YXIgcm90bDMyID0gdXRpbHMucm90bDMyO1xudmFyIHN1bTMyID0gdXRpbHMuc3VtMzI7XG52YXIgc3VtMzJfNCA9IHV0aWxzLnN1bTMyXzQ7XG52YXIgc3VtMzJfNSA9IHV0aWxzLnN1bTMyXzU7XG52YXIgcm90cjY0X2hpID0gdXRpbHMucm90cjY0X2hpO1xudmFyIHJvdHI2NF9sbyA9IHV0aWxzLnJvdHI2NF9sbztcbnZhciBzaHI2NF9oaSA9IHV0aWxzLnNocjY0X2hpO1xudmFyIHNocjY0X2xvID0gdXRpbHMuc2hyNjRfbG87XG52YXIgc3VtNjQgPSB1dGlscy5zdW02NDtcbnZhciBzdW02NF9oaSA9IHV0aWxzLnN1bTY0X2hpO1xudmFyIHN1bTY0X2xvID0gdXRpbHMuc3VtNjRfbG87XG52YXIgc3VtNjRfNF9oaSA9IHV0aWxzLnN1bTY0XzRfaGk7XG52YXIgc3VtNjRfNF9sbyA9IHV0aWxzLnN1bTY0XzRfbG87XG52YXIgc3VtNjRfNV9oaSA9IHV0aWxzLnN1bTY0XzVfaGk7XG52YXIgc3VtNjRfNV9sbyA9IHV0aWxzLnN1bTY0XzVfbG87XG52YXIgQmxvY2tIYXNoID0gaGFzaC5jb21tb24uQmxvY2tIYXNoO1xuXG52YXIgc2hhMjU2X0sgPSBbXG4gIDB4NDI4YTJmOTgsIDB4NzEzNzQ0OTEsIDB4YjVjMGZiY2YsIDB4ZTliNWRiYTUsXG4gIDB4Mzk1NmMyNWIsIDB4NTlmMTExZjEsIDB4OTIzZjgyYTQsIDB4YWIxYzVlZDUsXG4gIDB4ZDgwN2FhOTgsIDB4MTI4MzViMDEsIDB4MjQzMTg1YmUsIDB4NTUwYzdkYzMsXG4gIDB4NzJiZTVkNzQsIDB4ODBkZWIxZmUsIDB4OWJkYzA2YTcsIDB4YzE5YmYxNzQsXG4gIDB4ZTQ5YjY5YzEsIDB4ZWZiZTQ3ODYsIDB4MGZjMTlkYzYsIDB4MjQwY2ExY2MsXG4gIDB4MmRlOTJjNmYsIDB4NGE3NDg0YWEsIDB4NWNiMGE5ZGMsIDB4NzZmOTg4ZGEsXG4gIDB4OTgzZTUxNTIsIDB4YTgzMWM2NmQsIDB4YjAwMzI3YzgsIDB4YmY1OTdmYzcsXG4gIDB4YzZlMDBiZjMsIDB4ZDVhNzkxNDcsIDB4MDZjYTYzNTEsIDB4MTQyOTI5NjcsXG4gIDB4MjdiNzBhODUsIDB4MmUxYjIxMzgsIDB4NGQyYzZkZmMsIDB4NTMzODBkMTMsXG4gIDB4NjUwYTczNTQsIDB4NzY2YTBhYmIsIDB4ODFjMmM5MmUsIDB4OTI3MjJjODUsXG4gIDB4YTJiZmU4YTEsIDB4YTgxYTY2NGIsIDB4YzI0YjhiNzAsIDB4Yzc2YzUxYTMsXG4gIDB4ZDE5MmU4MTksIDB4ZDY5OTA2MjQsIDB4ZjQwZTM1ODUsIDB4MTA2YWEwNzAsXG4gIDB4MTlhNGMxMTYsIDB4MWUzNzZjMDgsIDB4Mjc0ODc3NGMsIDB4MzRiMGJjYjUsXG4gIDB4MzkxYzBjYjMsIDB4NGVkOGFhNGEsIDB4NWI5Y2NhNGYsIDB4NjgyZTZmZjMsXG4gIDB4NzQ4ZjgyZWUsIDB4NzhhNTYzNmYsIDB4ODRjODc4MTQsIDB4OGNjNzAyMDgsXG4gIDB4OTBiZWZmZmEsIDB4YTQ1MDZjZWIsIDB4YmVmOWEzZjcsIDB4YzY3MTc4ZjJcbl07XG5cbnZhciBzaGE1MTJfSyA9IFtcbiAgMHg0MjhhMmY5OCwgMHhkNzI4YWUyMiwgMHg3MTM3NDQ5MSwgMHgyM2VmNjVjZCxcbiAgMHhiNWMwZmJjZiwgMHhlYzRkM2IyZiwgMHhlOWI1ZGJhNSwgMHg4MTg5ZGJiYyxcbiAgMHgzOTU2YzI1YiwgMHhmMzQ4YjUzOCwgMHg1OWYxMTFmMSwgMHhiNjA1ZDAxOSxcbiAgMHg5MjNmODJhNCwgMHhhZjE5NGY5YiwgMHhhYjFjNWVkNSwgMHhkYTZkODExOCxcbiAgMHhkODA3YWE5OCwgMHhhMzAzMDI0MiwgMHgxMjgzNWIwMSwgMHg0NTcwNmZiZSxcbiAgMHgyNDMxODViZSwgMHg0ZWU0YjI4YywgMHg1NTBjN2RjMywgMHhkNWZmYjRlMixcbiAgMHg3MmJlNWQ3NCwgMHhmMjdiODk2ZiwgMHg4MGRlYjFmZSwgMHgzYjE2OTZiMSxcbiAgMHg5YmRjMDZhNywgMHgyNWM3MTIzNSwgMHhjMTliZjE3NCwgMHhjZjY5MjY5NCxcbiAgMHhlNDliNjljMSwgMHg5ZWYxNGFkMiwgMHhlZmJlNDc4NiwgMHgzODRmMjVlMyxcbiAgMHgwZmMxOWRjNiwgMHg4YjhjZDViNSwgMHgyNDBjYTFjYywgMHg3N2FjOWM2NSxcbiAgMHgyZGU5MmM2ZiwgMHg1OTJiMDI3NSwgMHg0YTc0ODRhYSwgMHg2ZWE2ZTQ4MyxcbiAgMHg1Y2IwYTlkYywgMHhiZDQxZmJkNCwgMHg3NmY5ODhkYSwgMHg4MzExNTNiNSxcbiAgMHg5ODNlNTE1MiwgMHhlZTY2ZGZhYiwgMHhhODMxYzY2ZCwgMHgyZGI0MzIxMCxcbiAgMHhiMDAzMjdjOCwgMHg5OGZiMjEzZiwgMHhiZjU5N2ZjNywgMHhiZWVmMGVlNCxcbiAgMHhjNmUwMGJmMywgMHgzZGE4OGZjMiwgMHhkNWE3OTE0NywgMHg5MzBhYTcyNSxcbiAgMHgwNmNhNjM1MSwgMHhlMDAzODI2ZiwgMHgxNDI5Mjk2NywgMHgwYTBlNmU3MCxcbiAgMHgyN2I3MGE4NSwgMHg0NmQyMmZmYywgMHgyZTFiMjEzOCwgMHg1YzI2YzkyNixcbiAgMHg0ZDJjNmRmYywgMHg1YWM0MmFlZCwgMHg1MzM4MGQxMywgMHg5ZDk1YjNkZixcbiAgMHg2NTBhNzM1NCwgMHg4YmFmNjNkZSwgMHg3NjZhMGFiYiwgMHgzYzc3YjJhOCxcbiAgMHg4MWMyYzkyZSwgMHg0N2VkYWVlNiwgMHg5MjcyMmM4NSwgMHgxNDgyMzUzYixcbiAgMHhhMmJmZThhMSwgMHg0Y2YxMDM2NCwgMHhhODFhNjY0YiwgMHhiYzQyMzAwMSxcbiAgMHhjMjRiOGI3MCwgMHhkMGY4OTc5MSwgMHhjNzZjNTFhMywgMHgwNjU0YmUzMCxcbiAgMHhkMTkyZTgxOSwgMHhkNmVmNTIxOCwgMHhkNjk5MDYyNCwgMHg1NTY1YTkxMCxcbiAgMHhmNDBlMzU4NSwgMHg1NzcxMjAyYSwgMHgxMDZhYTA3MCwgMHgzMmJiZDFiOCxcbiAgMHgxOWE0YzExNiwgMHhiOGQyZDBjOCwgMHgxZTM3NmMwOCwgMHg1MTQxYWI1MyxcbiAgMHgyNzQ4Nzc0YywgMHhkZjhlZWI5OSwgMHgzNGIwYmNiNSwgMHhlMTliNDhhOCxcbiAgMHgzOTFjMGNiMywgMHhjNWM5NWE2MywgMHg0ZWQ4YWE0YSwgMHhlMzQxOGFjYixcbiAgMHg1YjljY2E0ZiwgMHg3NzYzZTM3MywgMHg2ODJlNmZmMywgMHhkNmIyYjhhMyxcbiAgMHg3NDhmODJlZSwgMHg1ZGVmYjJmYywgMHg3OGE1NjM2ZiwgMHg0MzE3MmY2MCxcbiAgMHg4NGM4NzgxNCwgMHhhMWYwYWI3MiwgMHg4Y2M3MDIwOCwgMHgxYTY0MzllYyxcbiAgMHg5MGJlZmZmYSwgMHgyMzYzMWUyOCwgMHhhNDUwNmNlYiwgMHhkZTgyYmRlOSxcbiAgMHhiZWY5YTNmNywgMHhiMmM2NzkxNSwgMHhjNjcxNzhmMiwgMHhlMzcyNTMyYixcbiAgMHhjYTI3M2VjZSwgMHhlYTI2NjE5YywgMHhkMTg2YjhjNywgMHgyMWMwYzIwNyxcbiAgMHhlYWRhN2RkNiwgMHhjZGUwZWIxZSwgMHhmNTdkNGY3ZiwgMHhlZTZlZDE3OCxcbiAgMHgwNmYwNjdhYSwgMHg3MjE3NmZiYSwgMHgwYTYzN2RjNSwgMHhhMmM4OThhNixcbiAgMHgxMTNmOTgwNCwgMHhiZWY5MGRhZSwgMHgxYjcxMGIzNSwgMHgxMzFjNDcxYixcbiAgMHgyOGRiNzdmNSwgMHgyMzA0N2Q4NCwgMHgzMmNhYWI3YiwgMHg0MGM3MjQ5MyxcbiAgMHgzYzllYmUwYSwgMHgxNWM5YmViYywgMHg0MzFkNjdjNCwgMHg5YzEwMGQ0YyxcbiAgMHg0Y2M1ZDRiZSwgMHhjYjNlNDJiNiwgMHg1OTdmMjk5YywgMHhmYzY1N2UyYSxcbiAgMHg1ZmNiNmZhYiwgMHgzYWQ2ZmFlYywgMHg2YzQ0MTk4YywgMHg0YTQ3NTgxN1xuXTtcblxudmFyIHNoYTFfSyA9IFtcbiAgMHg1QTgyNzk5OSwgMHg2RUQ5RUJBMSxcbiAgMHg4RjFCQkNEQywgMHhDQTYyQzFENlxuXTtcblxuZnVuY3Rpb24gU0hBMjU2KCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMjU2KSlcbiAgICByZXR1cm4gbmV3IFNIQTI1NigpO1xuXG4gIEJsb2NrSGFzaC5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4NmEwOWU2NjcsIDB4YmI2N2FlODUsIDB4M2M2ZWYzNzIsIDB4YTU0ZmY1M2EsXG4gICAgICAgICAgICAgMHg1MTBlNTI3ZiwgMHg5YjA1Njg4YywgMHgxZjgzZDlhYiwgMHg1YmUwY2QxOSBdO1xuICB0aGlzLmsgPSBzaGEyNTZfSztcbiAgdGhpcy5XID0gbmV3IEFycmF5KDY0KTtcbn1cbnV0aWxzLmluaGVyaXRzKFNIQTI1NiwgQmxvY2tIYXNoKTtcbmV4cG9ydHMuc2hhMjU2ID0gU0hBMjU2O1xuXG5TSEEyNTYuYmxvY2tTaXplID0gNTEyO1xuU0hBMjU2Lm91dFNpemUgPSAyNTY7XG5TSEEyNTYuaG1hY1N0cmVuZ3RoID0gMTkyO1xuU0hBMjU2LnBhZExlbmd0aCA9IDY0O1xuXG5TSEEyNTYucHJvdG90eXBlLl91cGRhdGUgPSBmdW5jdGlvbiBfdXBkYXRlKG1zZywgc3RhcnQpIHtcbiAgdmFyIFcgPSB0aGlzLlc7XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKVxuICAgIFdbaV0gPSBtc2dbc3RhcnQgKyBpXTtcbiAgZm9yICg7IGkgPCBXLmxlbmd0aDsgaSsrKVxuICAgIFdbaV0gPSBzdW0zMl80KGcxXzI1NihXW2kgLSAyXSksIFdbaSAtIDddLCBnMF8yNTYoV1tpIC0gMTVdKSwgV1tpIC0gMTZdKTtcblxuICB2YXIgYSA9IHRoaXMuaFswXTtcbiAgdmFyIGIgPSB0aGlzLmhbMV07XG4gIHZhciBjID0gdGhpcy5oWzJdO1xuICB2YXIgZCA9IHRoaXMuaFszXTtcbiAgdmFyIGUgPSB0aGlzLmhbNF07XG4gIHZhciBmID0gdGhpcy5oWzVdO1xuICB2YXIgZyA9IHRoaXMuaFs2XTtcbiAgdmFyIGggPSB0aGlzLmhbN107XG5cbiAgYXNzZXJ0KHRoaXMuay5sZW5ndGggPT09IFcubGVuZ3RoKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIFQxID0gc3VtMzJfNShoLCBzMV8yNTYoZSksIGNoMzIoZSwgZiwgZyksIHRoaXMua1tpXSwgV1tpXSk7XG4gICAgdmFyIFQyID0gc3VtMzIoczBfMjU2KGEpLCBtYWozMihhLCBiLCBjKSk7XG4gICAgaCA9IGc7XG4gICAgZyA9IGY7XG4gICAgZiA9IGU7XG4gICAgZSA9IHN1bTMyKGQsIFQxKTtcbiAgICBkID0gYztcbiAgICBjID0gYjtcbiAgICBiID0gYTtcbiAgICBhID0gc3VtMzIoVDEsIFQyKTtcbiAgfVxuXG4gIHRoaXMuaFswXSA9IHN1bTMyKHRoaXMuaFswXSwgYSk7XG4gIHRoaXMuaFsxXSA9IHN1bTMyKHRoaXMuaFsxXSwgYik7XG4gIHRoaXMuaFsyXSA9IHN1bTMyKHRoaXMuaFsyXSwgYyk7XG4gIHRoaXMuaFszXSA9IHN1bTMyKHRoaXMuaFszXSwgZCk7XG4gIHRoaXMuaFs0XSA9IHN1bTMyKHRoaXMuaFs0XSwgZSk7XG4gIHRoaXMuaFs1XSA9IHN1bTMyKHRoaXMuaFs1XSwgZik7XG4gIHRoaXMuaFs2XSA9IHN1bTMyKHRoaXMuaFs2XSwgZyk7XG4gIHRoaXMuaFs3XSA9IHN1bTMyKHRoaXMuaFs3XSwgaCk7XG59O1xuXG5TSEEyNTYucHJvdG90eXBlLl9kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIGlmIChlbmMgPT09ICdoZXgnKVxuICAgIHJldHVybiB1dGlscy50b0hleDMyKHRoaXMuaCwgJ2JpZycpO1xuICBlbHNlXG4gICAgcmV0dXJuIHV0aWxzLnNwbGl0MzIodGhpcy5oLCAnYmlnJyk7XG59O1xuXG5mdW5jdGlvbiBTSEEyMjQoKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBTSEEyMjQpKVxuICAgIHJldHVybiBuZXcgU0hBMjI0KCk7XG5cbiAgU0hBMjU2LmNhbGwodGhpcyk7XG4gIHRoaXMuaCA9IFsgMHhjMTA1OWVkOCwgMHgzNjdjZDUwNywgMHgzMDcwZGQxNywgMHhmNzBlNTkzOSxcbiAgICAgICAgICAgICAweGZmYzAwYjMxLCAweDY4NTgxNTExLCAweDY0Zjk4ZmE3LCAweGJlZmE0ZmE0IF07XG59XG51dGlscy5pbmhlcml0cyhTSEEyMjQsIFNIQTI1Nik7XG5leHBvcnRzLnNoYTIyNCA9IFNIQTIyNDtcblxuU0hBMjI0LmJsb2NrU2l6ZSA9IDUxMjtcblNIQTIyNC5vdXRTaXplID0gMjI0O1xuU0hBMjI0LmhtYWNTdHJlbmd0aCA9IDE5MjtcblNIQTIyNC5wYWRMZW5ndGggPSA2NDtcblxuU0hBMjI0LnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICAvLyBKdXN0IHRydW5jYXRlIG91dHB1dFxuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmguc2xpY2UoMCwgNyksICdiaWcnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaC5zbGljZSgwLCA3KSwgJ2JpZycpO1xufTtcblxuZnVuY3Rpb24gU0hBNTEyKCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBNTEyKSlcbiAgICByZXR1cm4gbmV3IFNIQTUxMigpO1xuXG4gIEJsb2NrSGFzaC5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4NmEwOWU2NjcsIDB4ZjNiY2M5MDgsXG4gICAgICAgICAgICAgMHhiYjY3YWU4NSwgMHg4NGNhYTczYixcbiAgICAgICAgICAgICAweDNjNmVmMzcyLCAweGZlOTRmODJiLFxuICAgICAgICAgICAgIDB4YTU0ZmY1M2EsIDB4NWYxZDM2ZjEsXG4gICAgICAgICAgICAgMHg1MTBlNTI3ZiwgMHhhZGU2ODJkMSxcbiAgICAgICAgICAgICAweDliMDU2ODhjLCAweDJiM2U2YzFmLFxuICAgICAgICAgICAgIDB4MWY4M2Q5YWIsIDB4ZmI0MWJkNmIsXG4gICAgICAgICAgICAgMHg1YmUwY2QxOSwgMHgxMzdlMjE3OSBdO1xuICB0aGlzLmsgPSBzaGE1MTJfSztcbiAgdGhpcy5XID0gbmV3IEFycmF5KDE2MCk7XG59XG51dGlscy5pbmhlcml0cyhTSEE1MTIsIEJsb2NrSGFzaCk7XG5leHBvcnRzLnNoYTUxMiA9IFNIQTUxMjtcblxuU0hBNTEyLmJsb2NrU2l6ZSA9IDEwMjQ7XG5TSEE1MTIub3V0U2l6ZSA9IDUxMjtcblNIQTUxMi5obWFjU3RyZW5ndGggPSAxOTI7XG5TSEE1MTIucGFkTGVuZ3RoID0gMTI4O1xuXG5TSEE1MTIucHJvdG90eXBlLl9wcmVwYXJlQmxvY2sgPSBmdW5jdGlvbiBfcHJlcGFyZUJsb2NrKG1zZywgc3RhcnQpIHtcbiAgdmFyIFcgPSB0aGlzLlc7XG5cbiAgLy8gMzIgeCAzMmJpdCB3b3Jkc1xuICBmb3IgKHZhciBpID0gMDsgaSA8IDMyOyBpKyspXG4gICAgV1tpXSA9IG1zZ1tzdGFydCArIGldO1xuICBmb3IgKDsgaSA8IFcubGVuZ3RoOyBpICs9IDIpIHtcbiAgICB2YXIgYzBfaGkgPSBnMV81MTJfaGkoV1tpIC0gNF0sIFdbaSAtIDNdKTsgIC8vIGkgLSAyXG4gICAgdmFyIGMwX2xvID0gZzFfNTEyX2xvKFdbaSAtIDRdLCBXW2kgLSAzXSk7XG4gICAgdmFyIGMxX2hpID0gV1tpIC0gMTRdOyAgLy8gaSAtIDdcbiAgICB2YXIgYzFfbG8gPSBXW2kgLSAxM107XG4gICAgdmFyIGMyX2hpID0gZzBfNTEyX2hpKFdbaSAtIDMwXSwgV1tpIC0gMjldKTsgIC8vIGkgLSAxNVxuICAgIHZhciBjMl9sbyA9IGcwXzUxMl9sbyhXW2kgLSAzMF0sIFdbaSAtIDI5XSk7XG4gICAgdmFyIGMzX2hpID0gV1tpIC0gMzJdOyAgLy8gaSAtIDE2XG4gICAgdmFyIGMzX2xvID0gV1tpIC0gMzFdO1xuXG4gICAgV1tpXSA9IHN1bTY0XzRfaGkoYzBfaGksIGMwX2xvLFxuICAgICAgICAgICAgICAgICAgICAgIGMxX2hpLCBjMV9sbyxcbiAgICAgICAgICAgICAgICAgICAgICBjMl9oaSwgYzJfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgYzNfaGksIGMzX2xvKTtcbiAgICBXW2kgKyAxXSA9IHN1bTY0XzRfbG8oYzBfaGksIGMwX2xvLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBjMV9oaSwgYzFfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGMyX2hpLCBjMl9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgYzNfaGksIGMzX2xvKTtcbiAgfVxufTtcblxuU0hBNTEyLnByb3RvdHlwZS5fdXBkYXRlID0gZnVuY3Rpb24gX3VwZGF0ZShtc2csIHN0YXJ0KSB7XG4gIHRoaXMuX3ByZXBhcmVCbG9jayhtc2csIHN0YXJ0KTtcblxuICB2YXIgVyA9IHRoaXMuVztcblxuICB2YXIgYWggPSB0aGlzLmhbMF07XG4gIHZhciBhbCA9IHRoaXMuaFsxXTtcbiAgdmFyIGJoID0gdGhpcy5oWzJdO1xuICB2YXIgYmwgPSB0aGlzLmhbM107XG4gIHZhciBjaCA9IHRoaXMuaFs0XTtcbiAgdmFyIGNsID0gdGhpcy5oWzVdO1xuICB2YXIgZGggPSB0aGlzLmhbNl07XG4gIHZhciBkbCA9IHRoaXMuaFs3XTtcbiAgdmFyIGVoID0gdGhpcy5oWzhdO1xuICB2YXIgZWwgPSB0aGlzLmhbOV07XG4gIHZhciBmaCA9IHRoaXMuaFsxMF07XG4gIHZhciBmbCA9IHRoaXMuaFsxMV07XG4gIHZhciBnaCA9IHRoaXMuaFsxMl07XG4gIHZhciBnbCA9IHRoaXMuaFsxM107XG4gIHZhciBoaCA9IHRoaXMuaFsxNF07XG4gIHZhciBobCA9IHRoaXMuaFsxNV07XG5cbiAgYXNzZXJ0KHRoaXMuay5sZW5ndGggPT09IFcubGVuZ3RoKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSArPSAyKSB7XG4gICAgdmFyIGMwX2hpID0gaGg7XG4gICAgdmFyIGMwX2xvID0gaGw7XG4gICAgdmFyIGMxX2hpID0gczFfNTEyX2hpKGVoLCBlbCk7XG4gICAgdmFyIGMxX2xvID0gczFfNTEyX2xvKGVoLCBlbCk7XG4gICAgdmFyIGMyX2hpID0gY2g2NF9oaShlaCwgZWwsIGZoLCBmbCwgZ2gsIGdsKTtcbiAgICB2YXIgYzJfbG8gPSBjaDY0X2xvKGVoLCBlbCwgZmgsIGZsLCBnaCwgZ2wpO1xuICAgIHZhciBjM19oaSA9IHRoaXMua1tpXTtcbiAgICB2YXIgYzNfbG8gPSB0aGlzLmtbaSArIDFdO1xuICAgIHZhciBjNF9oaSA9IFdbaV07XG4gICAgdmFyIGM0X2xvID0gV1tpICsgMV07XG5cbiAgICB2YXIgVDFfaGkgPSBzdW02NF81X2hpKGMwX2hpLCBjMF9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMxX2hpLCBjMV9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMyX2hpLCBjMl9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMzX2hpLCBjM19sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGM0X2hpLCBjNF9sbyk7XG4gICAgdmFyIFQxX2xvID0gc3VtNjRfNV9sbyhjMF9oaSwgYzBfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjMV9oaSwgYzFfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjMl9oaSwgYzJfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjM19oaSwgYzNfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjNF9oaSwgYzRfbG8pO1xuXG4gICAgdmFyIGMwX2hpID0gczBfNTEyX2hpKGFoLCBhbCk7XG4gICAgdmFyIGMwX2xvID0gczBfNTEyX2xvKGFoLCBhbCk7XG4gICAgdmFyIGMxX2hpID0gbWFqNjRfaGkoYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCk7XG4gICAgdmFyIGMxX2xvID0gbWFqNjRfbG8oYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCk7XG5cbiAgICB2YXIgVDJfaGkgPSBzdW02NF9oaShjMF9oaSwgYzBfbG8sIGMxX2hpLCBjMV9sbyk7XG4gICAgdmFyIFQyX2xvID0gc3VtNjRfbG8oYzBfaGksIGMwX2xvLCBjMV9oaSwgYzFfbG8pO1xuXG4gICAgaGggPSBnaDtcbiAgICBobCA9IGdsO1xuXG4gICAgZ2ggPSBmaDtcbiAgICBnbCA9IGZsO1xuXG4gICAgZmggPSBlaDtcbiAgICBmbCA9IGVsO1xuXG4gICAgZWggPSBzdW02NF9oaShkaCwgZGwsIFQxX2hpLCBUMV9sbyk7XG4gICAgZWwgPSBzdW02NF9sbyhkbCwgZGwsIFQxX2hpLCBUMV9sbyk7XG5cbiAgICBkaCA9IGNoO1xuICAgIGRsID0gY2w7XG5cbiAgICBjaCA9IGJoO1xuICAgIGNsID0gYmw7XG5cbiAgICBiaCA9IGFoO1xuICAgIGJsID0gYWw7XG5cbiAgICBhaCA9IHN1bTY0X2hpKFQxX2hpLCBUMV9sbywgVDJfaGksIFQyX2xvKTtcbiAgICBhbCA9IHN1bTY0X2xvKFQxX2hpLCBUMV9sbywgVDJfaGksIFQyX2xvKTtcbiAgfVxuXG4gIHN1bTY0KHRoaXMuaCwgMCwgYWgsIGFsKTtcbiAgc3VtNjQodGhpcy5oLCAyLCBiaCwgYmwpO1xuICBzdW02NCh0aGlzLmgsIDQsIGNoLCBjbCk7XG4gIHN1bTY0KHRoaXMuaCwgNiwgZGgsIGRsKTtcbiAgc3VtNjQodGhpcy5oLCA4LCBlaCwgZWwpO1xuICBzdW02NCh0aGlzLmgsIDEwLCBmaCwgZmwpO1xuICBzdW02NCh0aGlzLmgsIDEyLCBnaCwgZ2wpO1xuICBzdW02NCh0aGlzLmgsIDE0LCBoaCwgaGwpO1xufTtcblxuU0hBNTEyLnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmgsICdiaWcnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaCwgJ2JpZycpO1xufTtcblxuZnVuY3Rpb24gU0hBMzg0KCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMzg0KSlcbiAgICByZXR1cm4gbmV3IFNIQTM4NCgpO1xuXG4gIFNIQTUxMi5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4Y2JiYjlkNWQsIDB4YzEwNTllZDgsXG4gICAgICAgICAgICAgMHg2MjlhMjkyYSwgMHgzNjdjZDUwNyxcbiAgICAgICAgICAgICAweDkxNTkwMTVhLCAweDMwNzBkZDE3LFxuICAgICAgICAgICAgIDB4MTUyZmVjZDgsIDB4ZjcwZTU5MzksXG4gICAgICAgICAgICAgMHg2NzMzMjY2NywgMHhmZmMwMGIzMSxcbiAgICAgICAgICAgICAweDhlYjQ0YTg3LCAweDY4NTgxNTExLFxuICAgICAgICAgICAgIDB4ZGIwYzJlMGQsIDB4NjRmOThmYTcsXG4gICAgICAgICAgICAgMHg0N2I1NDgxZCwgMHhiZWZhNGZhNCBdO1xufVxudXRpbHMuaW5oZXJpdHMoU0hBMzg0LCBTSEE1MTIpO1xuZXhwb3J0cy5zaGEzODQgPSBTSEEzODQ7XG5cblNIQTM4NC5ibG9ja1NpemUgPSAxMDI0O1xuU0hBMzg0Lm91dFNpemUgPSAzODQ7XG5TSEEzODQuaG1hY1N0cmVuZ3RoID0gMTkyO1xuU0hBMzg0LnBhZExlbmd0aCA9IDEyODtcblxuU0hBMzg0LnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmguc2xpY2UoMCwgMTIpLCAnYmlnJyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdXRpbHMuc3BsaXQzMih0aGlzLmguc2xpY2UoMCwgMTIpLCAnYmlnJyk7XG59O1xuXG5mdW5jdGlvbiBTSEExKCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMSkpXG4gICAgcmV0dXJuIG5ldyBTSEExKCk7XG5cbiAgQmxvY2tIYXNoLmNhbGwodGhpcyk7XG4gIHRoaXMuaCA9IFsgMHg2NzQ1MjMwMSwgMHhlZmNkYWI4OSwgMHg5OGJhZGNmZSxcbiAgICAgICAgICAgICAweDEwMzI1NDc2LCAweGMzZDJlMWYwIF07XG4gIHRoaXMuVyA9IG5ldyBBcnJheSg4MCk7XG59XG5cbnV0aWxzLmluaGVyaXRzKFNIQTEsIEJsb2NrSGFzaCk7XG5leHBvcnRzLnNoYTEgPSBTSEExO1xuXG5TSEExLmJsb2NrU2l6ZSA9IDUxMjtcblNIQTEub3V0U2l6ZSA9IDE2MDtcblNIQTEuaG1hY1N0cmVuZ3RoID0gODA7XG5TSEExLnBhZExlbmd0aCA9IDY0O1xuXG5TSEExLnByb3RvdHlwZS5fdXBkYXRlID0gZnVuY3Rpb24gX3VwZGF0ZShtc2csIHN0YXJ0KSB7XG4gIHZhciBXID0gdGhpcy5XO1xuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcbiAgICBXW2ldID0gbXNnW3N0YXJ0ICsgaV07XG5cbiAgZm9yKDsgaSA8IFcubGVuZ3RoOyBpKyspXG4gICAgV1tpXSA9IHJvdGwzMihXW2kgLSAzXSBeIFdbaSAtIDhdIF4gV1tpIC0gMTRdIF4gV1tpIC0gMTZdLCAxKTtcblxuICB2YXIgYSA9IHRoaXMuaFswXTtcbiAgdmFyIGIgPSB0aGlzLmhbMV07XG4gIHZhciBjID0gdGhpcy5oWzJdO1xuICB2YXIgZCA9IHRoaXMuaFszXTtcbiAgdmFyIGUgPSB0aGlzLmhbNF07XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIHMgPSB+fihpIC8gMjApO1xuICAgIHZhciB0ID0gc3VtMzJfNShyb3RsMzIoYSwgNSksIGZ0XzEocywgYiwgYywgZCksIGUsIFdbaV0sIHNoYTFfS1tzXSk7XG4gICAgZSA9IGQ7XG4gICAgZCA9IGM7XG4gICAgYyA9IHJvdGwzMihiLCAzMCk7XG4gICAgYiA9IGE7XG4gICAgYSA9IHQ7XG4gIH1cblxuICB0aGlzLmhbMF0gPSBzdW0zMih0aGlzLmhbMF0sIGEpO1xuICB0aGlzLmhbMV0gPSBzdW0zMih0aGlzLmhbMV0sIGIpO1xuICB0aGlzLmhbMl0gPSBzdW0zMih0aGlzLmhbMl0sIGMpO1xuICB0aGlzLmhbM10gPSBzdW0zMih0aGlzLmhbM10sIGQpO1xuICB0aGlzLmhbNF0gPSBzdW0zMih0aGlzLmhbNF0sIGUpO1xufTtcblxuU0hBMS5wcm90b3R5cGUuX2RpZ2VzdCA9IGZ1bmN0aW9uIGRpZ2VzdChlbmMpIHtcbiAgaWYgKGVuYyA9PT0gJ2hleCcpXG4gICAgcmV0dXJuIHV0aWxzLnRvSGV4MzIodGhpcy5oLCAnYmlnJyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdXRpbHMuc3BsaXQzMih0aGlzLmgsICdiaWcnKTtcbn07XG5cbmZ1bmN0aW9uIGNoMzIoeCwgeSwgeikge1xuICByZXR1cm4gKHggJiB5KSBeICgofngpICYgeik7XG59XG5cbmZ1bmN0aW9uIG1hajMyKHgsIHksIHopIHtcbiAgcmV0dXJuICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KTtcbn1cblxuZnVuY3Rpb24gcDMyKHgsIHksIHopIHtcbiAgcmV0dXJuIHggXiB5IF4gejtcbn1cblxuZnVuY3Rpb24gczBfMjU2KHgpIHtcbiAgcmV0dXJuIHJvdHIzMih4LCAyKSBeIHJvdHIzMih4LCAxMykgXiByb3RyMzIoeCwgMjIpO1xufVxuXG5mdW5jdGlvbiBzMV8yNTYoeCkge1xuICByZXR1cm4gcm90cjMyKHgsIDYpIF4gcm90cjMyKHgsIDExKSBeIHJvdHIzMih4LCAyNSk7XG59XG5cbmZ1bmN0aW9uIGcwXzI1Nih4KSB7XG4gIHJldHVybiByb3RyMzIoeCwgNykgXiByb3RyMzIoeCwgMTgpIF4gKHggPj4+IDMpO1xufVxuXG5mdW5jdGlvbiBnMV8yNTYoeCkge1xuICByZXR1cm4gcm90cjMyKHgsIDE3KSBeIHJvdHIzMih4LCAxOSkgXiAoeCA+Pj4gMTApO1xufVxuXG5mdW5jdGlvbiBmdF8xKHMsIHgsIHksIHopIHtcbiAgaWYgKHMgPT09IDApXG4gICAgcmV0dXJuIGNoMzIoeCwgeSwgeik7XG4gIGlmIChzID09PSAxIHx8IHMgPT09IDMpXG4gICAgcmV0dXJuIHAzMih4LCB5LCB6KTtcbiAgaWYgKHMgPT09IDIpXG4gICAgcmV0dXJuIG1hajMyKHgsIHksIHopO1xufVxuXG5mdW5jdGlvbiBjaDY0X2hpKHhoLCB4bCwgeWgsIHlsLCB6aCwgemwpIHtcbiAgdmFyIHIgPSAoeGggJiB5aCkgXiAoKH54aCkgJiB6aCk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gY2g2NF9sbyh4aCwgeGwsIHloLCB5bCwgemgsIHpsKSB7XG4gIHZhciByID0gKHhsICYgeWwpIF4gKCh+eGwpICYgemwpO1xuICBpZiAociA8IDApXG4gICAgciArPSAweDEwMDAwMDAwMDtcbiAgcmV0dXJuIHI7XG59XG5cbmZ1bmN0aW9uIG1hajY0X2hpKHhoLCB4bCwgeWgsIHlsLCB6aCwgemwpIHtcbiAgdmFyIHIgPSAoeGggJiB5aCkgXiAoeGggJiB6aCkgXiAoeWggJiB6aCk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gbWFqNjRfbG8oeGgsIHhsLCB5aCwgeWwsIHpoLCB6bCkge1xuICB2YXIgciA9ICh4bCAmIHlsKSBeICh4bCAmIHpsKSBeICh5bCAmIHpsKTtcbiAgaWYgKHIgPCAwKVxuICAgIHIgKz0gMHgxMDAwMDAwMDA7XG4gIHJldHVybiByO1xufVxuXG5mdW5jdGlvbiBzMF81MTJfaGkoeGgsIHhsKSB7XG4gIHZhciBjMF9oaSA9IHJvdHI2NF9oaSh4aCwgeGwsIDI4KTtcbiAgdmFyIGMxX2hpID0gcm90cjY0X2hpKHhsLCB4aCwgMik7ICAvLyAzNFxuICB2YXIgYzJfaGkgPSByb3RyNjRfaGkoeGwsIHhoLCA3KTsgIC8vIDM5XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gczBfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAyOCk7XG4gIHZhciBjMV9sbyA9IHJvdHI2NF9sbyh4bCwgeGgsIDIpOyAgLy8gMzRcbiAgdmFyIGMyX2xvID0gcm90cjY0X2xvKHhsLCB4aCwgNyk7ICAvLyAzOVxuXG4gIHZhciByID0gYzBfbG8gXiBjMV9sbyBeIGMyX2xvO1xuICBpZiAociA8IDApXG4gICAgciArPSAweDEwMDAwMDAwMDtcbiAgcmV0dXJuIHI7XG59XG5cbmZ1bmN0aW9uIHMxXzUxMl9oaSh4aCwgeGwpIHtcbiAgdmFyIGMwX2hpID0gcm90cjY0X2hpKHhoLCB4bCwgMTQpO1xuICB2YXIgYzFfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxOCk7XG4gIHZhciBjMl9oaSA9IHJvdHI2NF9oaSh4bCwgeGgsIDkpOyAgLy8gNDFcblxuICB2YXIgciA9IGMwX2hpIF4gYzFfaGkgXiBjMl9oaTtcbiAgaWYgKHIgPCAwKVxuICAgIHIgKz0gMHgxMDAwMDAwMDA7XG4gIHJldHVybiByO1xufVxuXG5mdW5jdGlvbiBzMV81MTJfbG8oeGgsIHhsKSB7XG4gIHZhciBjMF9sbyA9IHJvdHI2NF9sbyh4aCwgeGwsIDE0KTtcbiAgdmFyIGMxX2xvID0gcm90cjY0X2xvKHhoLCB4bCwgMTgpO1xuICB2YXIgYzJfbG8gPSByb3RyNjRfbG8oeGwsIHhoLCA5KTsgIC8vIDQxXG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzBfNTEyX2hpKHhoLCB4bCkge1xuICB2YXIgYzBfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxKTtcbiAgdmFyIGMxX2hpID0gcm90cjY0X2hpKHhoLCB4bCwgOCk7XG4gIHZhciBjMl9oaSA9IHNocjY0X2hpKHhoLCB4bCwgNyk7XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzBfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAxKTtcbiAgdmFyIGMxX2xvID0gcm90cjY0X2xvKHhoLCB4bCwgOCk7XG4gIHZhciBjMl9sbyA9IHNocjY0X2xvKHhoLCB4bCwgNyk7XG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzFfNTEyX2hpKHhoLCB4bCkge1xuICB2YXIgYzBfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxOSk7XG4gIHZhciBjMV9oaSA9IHJvdHI2NF9oaSh4bCwgeGgsIDI5KTsgIC8vIDYxXG4gIHZhciBjMl9oaSA9IHNocjY0X2hpKHhoLCB4bCwgNik7XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzFfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAxOSk7XG4gIHZhciBjMV9sbyA9IHJvdHI2NF9sbyh4bCwgeGgsIDI5KTsgIC8vIDYxXG4gIHZhciBjMl9sbyA9IHNocjY0X2xvKHhoLCB4bCwgNik7XG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cbiIsInZhciB1dGlscyA9IGV4cG9ydHM7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG5mdW5jdGlvbiB0b0FycmF5KG1zZywgZW5jKSB7XG4gIGlmIChBcnJheS5pc0FycmF5KG1zZykpXG4gICAgcmV0dXJuIG1zZy5zbGljZSgpO1xuICBpZiAoIW1zZylcbiAgICByZXR1cm4gW107XG4gIHZhciByZXMgPSBbXTtcbiAgaWYgKHR5cGVvZiBtc2cgPT09ICdzdHJpbmcnKSB7XG4gICAgaWYgKCFlbmMpIHtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciBjID0gbXNnLmNoYXJDb2RlQXQoaSk7XG4gICAgICAgIHZhciBoaSA9IGMgPj4gODtcbiAgICAgICAgdmFyIGxvID0gYyAmIDB4ZmY7XG4gICAgICAgIGlmIChoaSlcbiAgICAgICAgICByZXMucHVzaChoaSwgbG8pO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgcmVzLnB1c2gobG8pO1xuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoZW5jID09PSAnaGV4Jykge1xuICAgICAgbXNnID0gbXNnLnJlcGxhY2UoL1teYS16MC05XSsvaWcsICcnKTtcbiAgICAgIGlmIChtc2cubGVuZ3RoICUgMiAhPT0gMClcbiAgICAgICAgbXNnID0gJzAnICsgbXNnO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBtc2cubGVuZ3RoOyBpICs9IDIpXG4gICAgICAgIHJlcy5wdXNoKHBhcnNlSW50KG1zZ1tpXSArIG1zZ1tpICsgMV0sIDE2KSk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKVxuICAgICAgcmVzW2ldID0gbXNnW2ldIHwgMDtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxudXRpbHMudG9BcnJheSA9IHRvQXJyYXk7XG5cbmZ1bmN0aW9uIHRvSGV4KG1zZykge1xuICB2YXIgcmVzID0gJyc7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKVxuICAgIHJlcyArPSB6ZXJvMihtc2dbaV0udG9TdHJpbmcoMTYpKTtcbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnRvSGV4ID0gdG9IZXg7XG5cbmZ1bmN0aW9uIGh0b25sKHcpIHtcbiAgdmFyIHJlcyA9ICh3ID4+PiAyNCkgfFxuICAgICAgICAgICAgKCh3ID4+PiA4KSAmIDB4ZmYwMCkgfFxuICAgICAgICAgICAgKCh3IDw8IDgpICYgMHhmZjAwMDApIHxcbiAgICAgICAgICAgICgodyAmIDB4ZmYpIDw8IDI0KTtcbiAgcmV0dXJuIHJlcyA+Pj4gMDtcbn1cbnV0aWxzLmh0b25sID0gaHRvbmw7XG5cbmZ1bmN0aW9uIHRvSGV4MzIobXNnLCBlbmRpYW4pIHtcbiAgdmFyIHJlcyA9ICcnO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKykge1xuICAgIHZhciB3ID0gbXNnW2ldO1xuICAgIGlmIChlbmRpYW4gPT09ICdsaXR0bGUnKVxuICAgICAgdyA9IGh0b25sKHcpO1xuICAgIHJlcyArPSB6ZXJvOCh3LnRvU3RyaW5nKDE2KSk7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnRvSGV4MzIgPSB0b0hleDMyO1xuXG5mdW5jdGlvbiB6ZXJvMih3b3JkKSB7XG4gIGlmICh3b3JkLmxlbmd0aCA9PT0gMSlcbiAgICByZXR1cm4gJzAnICsgd29yZDtcbiAgZWxzZVxuICAgIHJldHVybiB3b3JkO1xufVxudXRpbHMuemVybzIgPSB6ZXJvMjtcblxuZnVuY3Rpb24gemVybzgod29yZCkge1xuICBpZiAod29yZC5sZW5ndGggPT09IDcpXG4gICAgcmV0dXJuICcwJyArIHdvcmQ7XG4gIGVsc2UgaWYgKHdvcmQubGVuZ3RoID09PSA2KVxuICAgIHJldHVybiAnMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDUpXG4gICAgcmV0dXJuICcwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDQpXG4gICAgcmV0dXJuICcwMDAwJyArIHdvcmQ7XG4gIGVsc2UgaWYgKHdvcmQubGVuZ3RoID09PSAzKVxuICAgIHJldHVybiAnMDAwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDIpXG4gICAgcmV0dXJuICcwMDAwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDEpXG4gICAgcmV0dXJuICcwMDAwMDAwJyArIHdvcmQ7XG4gIGVsc2VcbiAgICByZXR1cm4gd29yZDtcbn1cbnV0aWxzLnplcm84ID0gemVybzg7XG5cbmZ1bmN0aW9uIGpvaW4zMihtc2csIHN0YXJ0LCBlbmQsIGVuZGlhbikge1xuICB2YXIgbGVuID0gZW5kIC0gc3RhcnQ7XG4gIGFzc2VydChsZW4gJSA0ID09PSAwKTtcbiAgdmFyIHJlcyA9IG5ldyBBcnJheShsZW4gLyA0KTtcbiAgZm9yICh2YXIgaSA9IDAsIGsgPSBzdGFydDsgaSA8IHJlcy5sZW5ndGg7IGkrKywgayArPSA0KSB7XG4gICAgdmFyIHc7XG4gICAgaWYgKGVuZGlhbiA9PT0gJ2JpZycpXG4gICAgICB3ID0gKG1zZ1trXSA8PCAyNCkgfCAobXNnW2sgKyAxXSA8PCAxNikgfCAobXNnW2sgKyAyXSA8PCA4KSB8IG1zZ1trICsgM107XG4gICAgZWxzZVxuICAgICAgdyA9IChtc2dbayArIDNdIDw8IDI0KSB8IChtc2dbayArIDJdIDw8IDE2KSB8IChtc2dbayArIDFdIDw8IDgpIHwgbXNnW2tdO1xuICAgIHJlc1tpXSA9IHcgPj4+IDA7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLmpvaW4zMiA9IGpvaW4zMjtcblxuZnVuY3Rpb24gc3BsaXQzMihtc2csIGVuZGlhbikge1xuICB2YXIgcmVzID0gbmV3IEFycmF5KG1zZy5sZW5ndGggKiA0KTtcbiAgZm9yICh2YXIgaSA9IDAsIGsgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrLCBrICs9IDQpIHtcbiAgICB2YXIgbSA9IG1zZ1tpXTtcbiAgICBpZiAoZW5kaWFuID09PSAnYmlnJykge1xuICAgICAgcmVzW2tdID0gbSA+Pj4gMjQ7XG4gICAgICByZXNbayArIDFdID0gKG0gPj4+IDE2KSAmIDB4ZmY7XG4gICAgICByZXNbayArIDJdID0gKG0gPj4+IDgpICYgMHhmZjtcbiAgICAgIHJlc1trICsgM10gPSBtICYgMHhmZjtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzW2sgKyAzXSA9IG0gPj4+IDI0O1xuICAgICAgcmVzW2sgKyAyXSA9IChtID4+PiAxNikgJiAweGZmO1xuICAgICAgcmVzW2sgKyAxXSA9IChtID4+PiA4KSAmIDB4ZmY7XG4gICAgICByZXNba10gPSBtICYgMHhmZjtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnNwbGl0MzIgPSBzcGxpdDMyO1xuXG5mdW5jdGlvbiByb3RyMzIodywgYikge1xuICByZXR1cm4gKHcgPj4+IGIpIHwgKHcgPDwgKDMyIC0gYikpO1xufVxudXRpbHMucm90cjMyID0gcm90cjMyO1xuXG5mdW5jdGlvbiByb3RsMzIodywgYikge1xuICByZXR1cm4gKHcgPDwgYikgfCAodyA+Pj4gKDMyIC0gYikpO1xufVxudXRpbHMucm90bDMyID0gcm90bDMyO1xuXG5mdW5jdGlvbiBzdW0zMihhLCBiKSB7XG4gIHJldHVybiAoYSArIGIpID4+PiAwO1xufVxudXRpbHMuc3VtMzIgPSBzdW0zMjtcblxuZnVuY3Rpb24gc3VtMzJfMyhhLCBiLCBjKSB7XG4gIHJldHVybiAoYSArIGIgKyBjKSA+Pj4gMDtcbn1cbnV0aWxzLnN1bTMyXzMgPSBzdW0zMl8zO1xuXG5mdW5jdGlvbiBzdW0zMl80KGEsIGIsIGMsIGQpIHtcbiAgcmV0dXJuIChhICsgYiArIGMgKyBkKSA+Pj4gMDtcbn1cbnV0aWxzLnN1bTMyXzQgPSBzdW0zMl80O1xuXG5mdW5jdGlvbiBzdW0zMl81KGEsIGIsIGMsIGQsIGUpIHtcbiAgcmV0dXJuIChhICsgYiArIGMgKyBkICsgZSkgPj4+IDA7XG59XG51dGlscy5zdW0zMl81ID0gc3VtMzJfNTtcblxuZnVuY3Rpb24gYXNzZXJ0KGNvbmQsIG1zZykge1xuICBpZiAoIWNvbmQpXG4gICAgdGhyb3cgbmV3IEVycm9yKG1zZyB8fCAnQXNzZXJ0aW9uIGZhaWxlZCcpO1xufVxudXRpbHMuYXNzZXJ0ID0gYXNzZXJ0O1xuXG51dGlscy5pbmhlcml0cyA9IGluaGVyaXRzO1xuXG5mdW5jdGlvbiBzdW02NChidWYsIHBvcywgYWgsIGFsKSB7XG4gIHZhciBiaCA9IGJ1Zltwb3NdO1xuICB2YXIgYmwgPSBidWZbcG9zICsgMV07XG5cbiAgdmFyIGxvID0gKGFsICsgYmwpID4+PiAwO1xuICB2YXIgaGkgPSAobG8gPCBhbCA/IDEgOiAwKSArIGFoICsgYmg7XG4gIGJ1Zltwb3NdID0gaGkgPj4+IDA7XG4gIGJ1Zltwb3MgKyAxXSA9IGxvO1xufVxuZXhwb3J0cy5zdW02NCA9IHN1bTY0O1xuXG5mdW5jdGlvbiBzdW02NF9oaShhaCwgYWwsIGJoLCBibCkge1xuICB2YXIgbG8gPSAoYWwgKyBibCkgPj4+IDA7XG4gIHZhciBoaSA9IChsbyA8IGFsID8gMSA6IDApICsgYWggKyBiaDtcbiAgcmV0dXJuIGhpID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfaGkgPSBzdW02NF9oaTtcblxuZnVuY3Rpb24gc3VtNjRfbG8oYWgsIGFsLCBiaCwgYmwpIHtcbiAgdmFyIGxvID0gYWwgKyBibDtcbiAgcmV0dXJuIGxvID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfbG8gPSBzdW02NF9sbztcblxuZnVuY3Rpb24gc3VtNjRfNF9oaShhaCwgYWwsIGJoLCBibCwgY2gsIGNsLCBkaCwgZGwpIHtcbiAgdmFyIGNhcnJ5ID0gMDtcbiAgdmFyIGxvID0gYWw7XG4gIGxvID0gKGxvICsgYmwpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGFsID8gMSA6IDA7XG4gIGxvID0gKGxvICsgY2wpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGNsID8gMSA6IDA7XG4gIGxvID0gKGxvICsgZGwpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGRsID8gMSA6IDA7XG5cbiAgdmFyIGhpID0gYWggKyBiaCArIGNoICsgZGggKyBjYXJyeTtcbiAgcmV0dXJuIGhpID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfNF9oaSA9IHN1bTY0XzRfaGk7XG5cbmZ1bmN0aW9uIHN1bTY0XzRfbG8oYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCwgZGgsIGRsKSB7XG4gIHZhciBsbyA9IGFsICsgYmwgKyBjbCArIGRsO1xuICByZXR1cm4gbG8gPj4+IDA7XG59O1xuZXhwb3J0cy5zdW02NF80X2xvID0gc3VtNjRfNF9sbztcblxuZnVuY3Rpb24gc3VtNjRfNV9oaShhaCwgYWwsIGJoLCBibCwgY2gsIGNsLCBkaCwgZGwsIGVoLCBlbCkge1xuICB2YXIgY2FycnkgPSAwO1xuICB2YXIgbG8gPSBhbDtcbiAgbG8gPSAobG8gKyBibCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgYWwgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBjbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgY2wgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBkbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgZGwgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBlbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgZWwgPyAxIDogMDtcblxuICB2YXIgaGkgPSBhaCArIGJoICsgY2ggKyBkaCArIGVoICsgY2Fycnk7XG4gIHJldHVybiBoaSA+Pj4gMDtcbn07XG5leHBvcnRzLnN1bTY0XzVfaGkgPSBzdW02NF81X2hpO1xuXG5mdW5jdGlvbiBzdW02NF81X2xvKGFoLCBhbCwgYmgsIGJsLCBjaCwgY2wsIGRoLCBkbCwgZWgsIGVsKSB7XG4gIHZhciBsbyA9IGFsICsgYmwgKyBjbCArIGRsICsgZWw7XG5cbiAgcmV0dXJuIGxvID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfNV9sbyA9IHN1bTY0XzVfbG87XG5cbmZ1bmN0aW9uIHJvdHI2NF9oaShhaCwgYWwsIG51bSkge1xuICB2YXIgciA9IChhbCA8PCAoMzIgLSBudW0pKSB8IChhaCA+Pj4gbnVtKTtcbiAgcmV0dXJuIHIgPj4+IDA7XG59O1xuZXhwb3J0cy5yb3RyNjRfaGkgPSByb3RyNjRfaGk7XG5cbmZ1bmN0aW9uIHJvdHI2NF9sbyhhaCwgYWwsIG51bSkge1xuICB2YXIgciA9IChhaCA8PCAoMzIgLSBudW0pKSB8IChhbCA+Pj4gbnVtKTtcbiAgcmV0dXJuIHIgPj4+IDA7XG59O1xuZXhwb3J0cy5yb3RyNjRfbG8gPSByb3RyNjRfbG87XG5cbmZ1bmN0aW9uIHNocjY0X2hpKGFoLCBhbCwgbnVtKSB7XG4gIHJldHVybiBhaCA+Pj4gbnVtO1xufTtcbmV4cG9ydHMuc2hyNjRfaGkgPSBzaHI2NF9oaTtcblxuZnVuY3Rpb24gc2hyNjRfbG8oYWgsIGFsLCBudW0pIHtcbiAgdmFyIHIgPSAoYWggPDwgKDMyIC0gbnVtKSkgfCAoYWwgPj4+IG51bSk7XG4gIHJldHVybiByID4+PiAwO1xufTtcbmV4cG9ydHMuc2hyNjRfbG8gPSBzaHI2NF9sbztcbiIsImV4cG9ydHMucmVhZCA9IGZ1bmN0aW9uIChidWZmZXIsIG9mZnNldCwgaXNMRSwgbUxlbiwgbkJ5dGVzKSB7XG4gIHZhciBlLCBtXG4gIHZhciBlTGVuID0gbkJ5dGVzICogOCAtIG1MZW4gLSAxXG4gIHZhciBlTWF4ID0gKDEgPDwgZUxlbikgLSAxXG4gIHZhciBlQmlhcyA9IGVNYXggPj4gMVxuICB2YXIgbkJpdHMgPSAtN1xuICB2YXIgaSA9IGlzTEUgPyAobkJ5dGVzIC0gMSkgOiAwXG4gIHZhciBkID0gaXNMRSA/IC0xIDogMVxuICB2YXIgcyA9IGJ1ZmZlcltvZmZzZXQgKyBpXVxuXG4gIGkgKz0gZFxuXG4gIGUgPSBzICYgKCgxIDw8ICgtbkJpdHMpKSAtIDEpXG4gIHMgPj49ICgtbkJpdHMpXG4gIG5CaXRzICs9IGVMZW5cbiAgZm9yICg7IG5CaXRzID4gMDsgZSA9IGUgKiAyNTYgKyBidWZmZXJbb2Zmc2V0ICsgaV0sIGkgKz0gZCwgbkJpdHMgLT0gOCkge31cblxuICBtID0gZSAmICgoMSA8PCAoLW5CaXRzKSkgLSAxKVxuICBlID4+PSAoLW5CaXRzKVxuICBuQml0cyArPSBtTGVuXG4gIGZvciAoOyBuQml0cyA+IDA7IG0gPSBtICogMjU2ICsgYnVmZmVyW29mZnNldCArIGldLCBpICs9IGQsIG5CaXRzIC09IDgpIHt9XG5cbiAgaWYgKGUgPT09IDApIHtcbiAgICBlID0gMSAtIGVCaWFzXG4gIH0gZWxzZSBpZiAoZSA9PT0gZU1heCkge1xuICAgIHJldHVybiBtID8gTmFOIDogKChzID8gLTEgOiAxKSAqIEluZmluaXR5KVxuICB9IGVsc2Uge1xuICAgIG0gPSBtICsgTWF0aC5wb3coMiwgbUxlbilcbiAgICBlID0gZSAtIGVCaWFzXG4gIH1cbiAgcmV0dXJuIChzID8gLTEgOiAxKSAqIG0gKiBNYXRoLnBvdygyLCBlIC0gbUxlbilcbn1cblxuZXhwb3J0cy53cml0ZSA9IGZ1bmN0aW9uIChidWZmZXIsIHZhbHVlLCBvZmZzZXQsIGlzTEUsIG1MZW4sIG5CeXRlcykge1xuICB2YXIgZSwgbSwgY1xuICB2YXIgZUxlbiA9IG5CeXRlcyAqIDggLSBtTGVuIC0gMVxuICB2YXIgZU1heCA9ICgxIDw8IGVMZW4pIC0gMVxuICB2YXIgZUJpYXMgPSBlTWF4ID4+IDFcbiAgdmFyIHJ0ID0gKG1MZW4gPT09IDIzID8gTWF0aC5wb3coMiwgLTI0KSAtIE1hdGgucG93KDIsIC03NykgOiAwKVxuICB2YXIgaSA9IGlzTEUgPyAwIDogKG5CeXRlcyAtIDEpXG4gIHZhciBkID0gaXNMRSA/IDEgOiAtMVxuICB2YXIgcyA9IHZhbHVlIDwgMCB8fCAodmFsdWUgPT09IDAgJiYgMSAvIHZhbHVlIDwgMCkgPyAxIDogMFxuXG4gIHZhbHVlID0gTWF0aC5hYnModmFsdWUpXG5cbiAgaWYgKGlzTmFOKHZhbHVlKSB8fCB2YWx1ZSA9PT0gSW5maW5pdHkpIHtcbiAgICBtID0gaXNOYU4odmFsdWUpID8gMSA6IDBcbiAgICBlID0gZU1heFxuICB9IGVsc2Uge1xuICAgIGUgPSBNYXRoLmZsb29yKE1hdGgubG9nKHZhbHVlKSAvIE1hdGguTE4yKVxuICAgIGlmICh2YWx1ZSAqIChjID0gTWF0aC5wb3coMiwgLWUpKSA8IDEpIHtcbiAgICAgIGUtLVxuICAgICAgYyAqPSAyXG4gICAgfVxuICAgIGlmIChlICsgZUJpYXMgPj0gMSkge1xuICAgICAgdmFsdWUgKz0gcnQgLyBjXG4gICAgfSBlbHNlIHtcbiAgICAgIHZhbHVlICs9IHJ0ICogTWF0aC5wb3coMiwgMSAtIGVCaWFzKVxuICAgIH1cbiAgICBpZiAodmFsdWUgKiBjID49IDIpIHtcbiAgICAgIGUrK1xuICAgICAgYyAvPSAyXG4gICAgfVxuXG4gICAgaWYgKGUgKyBlQmlhcyA+PSBlTWF4KSB7XG4gICAgICBtID0gMFxuICAgICAgZSA9IGVNYXhcbiAgICB9IGVsc2UgaWYgKGUgKyBlQmlhcyA+PSAxKSB7XG4gICAgICBtID0gKHZhbHVlICogYyAtIDEpICogTWF0aC5wb3coMiwgbUxlbilcbiAgICAgIGUgPSBlICsgZUJpYXNcbiAgICB9IGVsc2Uge1xuICAgICAgbSA9IHZhbHVlICogTWF0aC5wb3coMiwgZUJpYXMgLSAxKSAqIE1hdGgucG93KDIsIG1MZW4pXG4gICAgICBlID0gMFxuICAgIH1cbiAgfVxuXG4gIGZvciAoOyBtTGVuID49IDg7IGJ1ZmZlcltvZmZzZXQgKyBpXSA9IG0gJiAweGZmLCBpICs9IGQsIG0gLz0gMjU2LCBtTGVuIC09IDgpIHt9XG5cbiAgZSA9IChlIDw8IG1MZW4pIHwgbVxuICBlTGVuICs9IG1MZW5cbiAgZm9yICg7IGVMZW4gPiAwOyBidWZmZXJbb2Zmc2V0ICsgaV0gPSBlICYgMHhmZiwgaSArPSBkLCBlIC89IDI1NiwgZUxlbiAtPSA4KSB7fVxuXG4gIGJ1ZmZlcltvZmZzZXQgKyBpIC0gZF0gfD0gcyAqIDEyOFxufVxuIiwiXG52YXIgaW5kZXhPZiA9IFtdLmluZGV4T2Y7XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24oYXJyLCBvYmope1xuICBpZiAoaW5kZXhPZikgcmV0dXJuIGFyci5pbmRleE9mKG9iaik7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgYXJyLmxlbmd0aDsgKytpKSB7XG4gICAgaWYgKGFycltpXSA9PT0gb2JqKSByZXR1cm4gaTtcbiAgfVxuICByZXR1cm4gLTE7XG59OyIsImlmICh0eXBlb2YgT2JqZWN0LmNyZWF0ZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAvLyBpbXBsZW1lbnRhdGlvbiBmcm9tIHN0YW5kYXJkIG5vZGUuanMgJ3V0aWwnIG1vZHVsZVxuICBtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGluaGVyaXRzKGN0b3IsIHN1cGVyQ3Rvcikge1xuICAgIGN0b3Iuc3VwZXJfID0gc3VwZXJDdG9yXG4gICAgY3Rvci5wcm90b3R5cGUgPSBPYmplY3QuY3JlYXRlKHN1cGVyQ3Rvci5wcm90b3R5cGUsIHtcbiAgICAgIGNvbnN0cnVjdG9yOiB7XG4gICAgICAgIHZhbHVlOiBjdG9yLFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgd3JpdGFibGU6IHRydWUsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgICAgfVxuICAgIH0pO1xuICB9O1xufSBlbHNlIHtcbiAgLy8gb2xkIHNjaG9vbCBzaGltIGZvciBvbGQgYnJvd3NlcnNcbiAgbW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBpbmhlcml0cyhjdG9yLCBzdXBlckN0b3IpIHtcbiAgICBjdG9yLnN1cGVyXyA9IHN1cGVyQ3RvclxuICAgIHZhciBUZW1wQ3RvciA9IGZ1bmN0aW9uICgpIHt9XG4gICAgVGVtcEN0b3IucHJvdG90eXBlID0gc3VwZXJDdG9yLnByb3RvdHlwZVxuICAgIGN0b3IucHJvdG90eXBlID0gbmV3IFRlbXBDdG9yKClcbiAgICBjdG9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IGN0b3JcbiAgfVxufVxuIiwidmFyIHRvU3RyaW5nID0ge30udG9TdHJpbmc7XG5cbm1vZHVsZS5leHBvcnRzID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoYXJyKSB7XG4gIHJldHVybiB0b1N0cmluZy5jYWxsKGFycikgPT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBCTiA9IHJlcXVpcmUoJ2FzbjEuanMnKS5iaWdudW07XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gYmFzZTY0VG9CaWdOdW0odmFsLCB6ZXJvKSB7XG5cdHZhciBidWYgPSBuZXcgQnVmZmVyKHZhbCwgJ2Jhc2U2NCcpO1xuXHR2YXIgYm4gPSB2YWwgPSBuZXcgQk4oYnVmLCAxMCwgJ2JlJykuaWFicygpO1xuXHRpZiAoemVybykge1xuXHRcdGJ1Zi5maWxsKDApO1xuXHR9XG5cdHJldHVybiBibjtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpLFxuXHRFQyA9IHJlcXVpcmUoJ2VsbGlwdGljJykuZWM7XG5cbnZhciBiNjRUb0JuID0gcmVxdWlyZSgnLi9iNjQtdG8tYm4nKTtcblxudmFyIGN1cnZlcyA9IHtcblx0XHQnUC0yNTYnOiAncDI1NicsXG5cdFx0J1AtMzg0JzogJ3AzODQnLFxuXHRcdCdQLTUyMSc6ICdwNTIxJ1xuXHR9LFxuXHRvaWRzID0ge1xuXHRcdCdQLTI1Nic6IFsxLCAyLCA4NDAsIDEwMDQ1LCAzLCAxLCA3XSxcblx0XHQnUC0zODQnOiBbMSwgMywgMTMyLCAwLCAzNF0sXG5cdFx0J1AtNTIxJzogWzEsIDMsIDEzMiwgMCwgMzVdXG5cdH07XG5cbmZ1bmN0aW9uIGVjSndrVG9CdWZmZXIoandrLCBvcHRzKSB7XG5cdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5jcnYpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5jcnZcIiB0byBiZSBhIFN0cmluZycpO1xuXHR9XG5cblx0dmFyIGhhc0QgPSAnc3RyaW5nJyA9PT0gdHlwZW9mIGp3ay5kO1xuXHR2YXIgeHlUeXBlcyA9IGhhc0Rcblx0XHQ/IFsndW5kZWZpbmVkJywgJ3N0cmluZyddXG5cdFx0OiBbJ3N0cmluZyddO1xuXG5cdGlmICgtMSA9PT0geHlUeXBlcy5pbmRleE9mKHR5cGVvZiBqd2sueCkpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay54XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmICgtMSA9PT0geHlUeXBlcy5pbmRleE9mKHR5cGVvZiBqd2sueSkpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay55XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmIChvcHRzLnByaXZhdGUgJiYgIWhhc0QpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdHZhciBjdXJ2ZU5hbWUgPSBjdXJ2ZXNbandrLmNydl07XG5cdGlmICghY3VydmVOYW1lKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKCdVbnN1cHBvcnRlZCBjdXJ2ZSBcIicgKyBqd2suY3J2ICsgJ1wiJyk7XG5cdH1cblxuXHR2YXIgY3VydmUgPSBuZXcgRUMoY3VydmVOYW1lKTtcblxuXHR2YXIga2V5ID0ge307XG5cblx0dmFyIGhhc1B1YiA9IGp3ay54ICYmIGp3ay55O1xuXHRpZiAoaGFzUHViKSB7XG5cdFx0a2V5LnB1YiA9IHtcblx0XHRcdHg6IGI2NFRvQm4oandrLngsIGZhbHNlKSxcblx0XHRcdHk6IGI2NFRvQm4oandrLnksIGZhbHNlKVxuXHRcdH07XG5cdH1cblxuXHRpZiAob3B0cy5wcml2YXRlIHx8ICFoYXNQdWIpIHtcblx0XHRrZXkucHJpdiA9IGI2NFRvQm4oandrLmQsIHRydWUpO1xuXHR9XG5cblx0a2V5ID0gY3VydmUua2V5UGFpcihrZXkpO1xuXG5cdHZhciBrZXlWYWxpZGF0aW9uID0ga2V5LnZhbGlkYXRlKCk7XG5cdGlmICgha2V5VmFsaWRhdGlvbi5yZXN1bHQpIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQga2V5IGZvciBjdXJ2ZTogXCInICsga2V5VmFsaWRhdGlvbi5yZWFzb24gKyAnXCInKTtcblx0fVxuXG5cdHZhciByZXN1bHQgPSBrZXlUb1BlbShqd2suY3J2LCBrZXksIG9wdHMpO1xuXG5cdHJldHVybiByZXN1bHQ7XG59XG5cbmZ1bmN0aW9uIGtleVRvUGVtKGNydiwga2V5LCBvcHRzKSB7XG5cdHZhciBjb21wYWN0ID0gZmFsc2U7XG5cdHZhciBzdWJqZWN0UHVibGljS2V5ID0ga2V5LmdldFB1YmxpYyhjb21wYWN0LCAnaGV4Jyk7XG5cdHN1YmplY3RQdWJsaWNLZXkgPSBuZXcgQnVmZmVyKHN1YmplY3RQdWJsaWNLZXksICdoZXgnKTtcblx0c3ViamVjdFB1YmxpY0tleSA9IHtcblx0XHR1bnVzZWQ6IDAsXG5cdFx0ZGF0YTogc3ViamVjdFB1YmxpY0tleVxuXHR9O1xuXG5cdHZhciBwYXJhbWV0ZXJzID0gRUNQYXJhbWV0ZXJzLmVuY29kZSh7XG5cdFx0dHlwZTogJ25hbWVkQ3VydmUnLFxuXHRcdHZhbHVlOiBvaWRzW2Nydl1cblx0fSwgJ2RlcicpO1xuXG5cdHZhciByZXN1bHQ7XG5cdGlmIChvcHRzLnByaXZhdGUpIHtcblx0XHR2YXIgcHJpdmF0ZUtleSA9IGtleS5nZXRQcml2YXRlKCdoZXgnKTtcblx0XHRwcml2YXRlS2V5ID0gbmV3IEJ1ZmZlcihwcml2YXRlS2V5LCAnaGV4Jyk7XG5cblx0XHRyZXN1bHQgPSBFQ1ByaXZhdGVLZXkuZW5jb2RlKHtcblx0XHRcdHZlcnNpb246IGVjUHJpdmtleVZlcjEsXG5cdFx0XHRwcml2YXRlS2V5OiBwcml2YXRlS2V5LFxuXHRcdFx0cGFyYW1ldGVyczogcGFyYW1ldGVycyxcblx0XHRcdHB1YmxpY0tleTogc3ViamVjdFB1YmxpY0tleVxuXHRcdH0sICdwZW0nLCB7XG5cdFx0XHRsYWJlbDogJ0VDIFBSSVZBVEUgS0VZJ1xuXHRcdH0pO1xuXG5cdFx0cHJpdmF0ZUtleS5maWxsKDApO1xuXHR9IGVsc2Uge1xuXHRcdHJlc3VsdCA9IFN1YmplY3RQdWJsaWNLZXlJbmZvLmVuY29kZSh7XG5cdFx0XHRhbGdvcml0aG06IHtcblx0XHRcdFx0YWxnb3JpdGhtOiBbMSwgMiwgODQwLCAxMDA0NSwgMiwgMV0sXG5cdFx0XHRcdHBhcmFtZXRlcnM6IHBhcmFtZXRlcnNcblx0XHRcdH0sXG5cdFx0XHRzdWJqZWN0UHVibGljS2V5OiBzdWJqZWN0UHVibGljS2V5XG5cdFx0fSwgJ3BlbScsIHtcblx0XHRcdGxhYmVsOiAnUFVCTElDIEtFWSdcblx0XHR9KTtcblx0fVxuXG5cdC8vIFRoaXMgaXMgaW4gYW4gaWYgaW5jYXNlIGFzbjEuanMgYWRkcyBhIHRyYWlsaW5nIFxcblxuXHQvLyBpc3RhbmJ1bCBpZ25vcmUgZWxzZVxuXHRpZiAoJ1xcbicgIT09IHJlc3VsdC5zbGljZSgtMSkpIHtcblx0XHRyZXN1bHQgKz0gJ1xcbic7XG5cdH1cblxuXHRyZXR1cm4gcmVzdWx0O1xufVxuXG52YXIgRUNQYXJhbWV0ZXJzID0gYXNuMS5kZWZpbmUoJ0VDUGFyYW1ldGVycycsIC8qIEB0aGlzICovIGZ1bmN0aW9uKCkge1xuXHR0aGlzLmNob2ljZSh7XG5cdFx0bmFtZWRDdXJ2ZTogdGhpcy5vYmppZCgpXG5cdH0pO1xufSk7XG5cbnZhciBlY1ByaXZrZXlWZXIxID0gMTtcblxudmFyIEVDUHJpdmF0ZUtleSA9IGFzbjEuZGVmaW5lKCdFQ1ByaXZhdGVLZXknLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5zZXEoKS5vYmooXG5cdFx0dGhpcy5rZXkoJ3ZlcnNpb24nKS5pbnQoKSxcblx0XHR0aGlzLmtleSgncHJpdmF0ZUtleScpLm9jdHN0cigpLFxuXHRcdHRoaXMua2V5KCdwYXJhbWV0ZXJzJykuZXhwbGljaXQoMCkub3B0aW9uYWwoKS5hbnkoKSxcblx0XHR0aGlzLmtleSgncHVibGljS2V5JykuZXhwbGljaXQoMSkub3B0aW9uYWwoKS5iaXRzdHIoKVxuXHQpO1xufSk7XG5cbnZhciBBbGdvcml0aG1JZGVudGlmaWVyID0gYXNuMS5kZWZpbmUoJ0FsZ29yaXRobUlkZW50aWZpZXInLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5zZXEoKS5vYmooXG5cdFx0dGhpcy5rZXkoJ2FsZ29yaXRobScpLm9iamlkKCksXG5cdFx0dGhpcy5rZXkoJ3BhcmFtZXRlcnMnKS5vcHRpb25hbCgpLmFueSgpXG5cdCk7XG59KTtcblxudmFyIFN1YmplY3RQdWJsaWNLZXlJbmZvID0gYXNuMS5kZWZpbmUoJ1N1YmplY3RQdWJsaWNLZXlJbmZvJywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCdhbGdvcml0aG0nKS51c2UoQWxnb3JpdGhtSWRlbnRpZmllciksXG5cdFx0dGhpcy5rZXkoJ3N1YmplY3RQdWJsaWNLZXknKS5iaXRzdHIoKVxuXHQpO1xufSk7XG5cbm1vZHVsZS5leHBvcnRzID0gZWNKd2tUb0J1ZmZlcjtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGVjID0gcmVxdWlyZSgnLi9lYycpLFxuXHRyc2EgPSByZXF1aXJlKCcuL3JzYScpO1xuXG5mdW5jdGlvbiBqd2tUb0J1ZmZlcihqd2ssIG9wdHMpIHtcblx0aWYgKCdvYmplY3QnICE9PSB0eXBlb2YgandrIHx8IG51bGwgPT09IGp3aykge1xuXHRcdHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiandrXCIgdG8gYmUgYW4gT2JqZWN0Jyk7XG5cdH1cblxuXHR2YXIga3R5ID0gandrLmt0eTtcblx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2Yga3R5KSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sua3R5XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdG9wdHMgPSBvcHRzIHx8IHt9O1xuXHRvcHRzLnByaXZhdGUgPSBvcHRzLnByaXZhdGUgPT09IHRydWU7XG5cblx0c3dpdGNoIChrdHkpIHtcblx0XHRjYXNlICdFQyc6IHtcblx0XHRcdHJldHVybiBlYyhqd2ssIG9wdHMpO1xuXHRcdH1cblx0XHRjYXNlICdSU0EnOiB7XG5cdFx0XHRyZXR1cm4gcnNhKGp3aywgb3B0cyk7XG5cdFx0fVxuXHRcdGRlZmF1bHQ6IHtcblx0XHRcdHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQga2V5IHR5cGUgXCInICsga3R5ICsgJ1wiJyk7XG5cdFx0fVxuXHR9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gandrVG9CdWZmZXI7XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpO1xuXG52YXIgYjY0VG9CbiA9IHJlcXVpcmUoJy4vYjY0LXRvLWJuJyk7XG5cbnZhciBWZXJzaW9uID0gYXNuMS5kZWZpbmUoJ1ZlcnNpb24nLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5pbnQoKTtcbn0pO1xuXG52YXIgUlNBUHJpdmF0ZUtleSA9IGFzbjEuZGVmaW5lKCdSU0FQcml2YXRlS2V5JywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCd2ZXJzaW9uJykudXNlKFZlcnNpb24pLFxuXHRcdHRoaXMua2V5KCdtb2R1bHVzJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3B1YmxpY0V4cG9uZW50JykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3ByaXZhdGVFeHBvbmVudCcpLmludCgpLFxuXHRcdHRoaXMua2V5KCdwcmltZTEnKS5pbnQoKSxcblx0XHR0aGlzLmtleSgncHJpbWUyJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ2V4cG9uZW50MScpLmludCgpLFxuXHRcdHRoaXMua2V5KCdleHBvbmVudDInKS5pbnQoKSxcblx0XHR0aGlzLmtleSgnY29lZmZpY2llbnQnKS5pbnQoKVxuXHQpO1xufSk7XG5cbnZhciBSU0FQdWJsaWNLZXkgPSBhc24xLmRlZmluZSgnUlNBUHVibGljS2V5JywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCdtb2R1bHVzJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3B1YmxpY0V4cG9uZW50JykuaW50KClcblx0KTtcbn0pO1xuXG5mdW5jdGlvbiByc2FKd2tUb0J1ZmZlcihqd2ssIG9wdHMpIHtcblx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmUpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5lXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5uKSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sublwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdH1cblxuXHRpZiAob3B0cy5wcml2YXRlKSB7XG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmQpIHtcblx0XHRcdHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiandrLmRcIiB0byBiZSBhIFN0cmluZycpO1xuXHRcdH1cblxuXHRcdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5wKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5wXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0XHR9XG5cblx0XHRpZiAoJ3N0cmluZycgIT09IHR5cGVvZiBqd2sucSkge1xuXHRcdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sucVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmRwKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kcFwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmRxKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kcVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLnFpKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5xaVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXHR9XG5cblx0dmFyIHBlbTtcblx0aWYgKG9wdHMucHJpdmF0ZSkge1xuXHRcdHBlbSA9IFJTQVByaXZhdGVLZXkuZW5jb2RlKHtcblx0XHRcdHZlcnNpb246IDAsXG5cdFx0XHRtb2R1bHVzOiBiNjRUb0JuKGp3ay5uLCBmYWxzZSksXG5cdFx0XHRwdWJsaWNFeHBvbmVudDogYjY0VG9Cbihqd2suZSwgZmFsc2UpLFxuXHRcdFx0cHJpdmF0ZUV4cG9uZW50OiBiNjRUb0JuKGp3ay5kLCB0cnVlKSxcblx0XHRcdHByaW1lMTogYjY0VG9Cbihqd2sucCwgdHJ1ZSksXG5cdFx0XHRwcmltZTI6IGI2NFRvQm4oandrLnEsIHRydWUpLFxuXHRcdFx0ZXhwb25lbnQxOiBiNjRUb0JuKGp3ay5kcCwgdHJ1ZSksXG5cdFx0XHRleHBvbmVudDI6IGI2NFRvQm4oandrLmRxLCB0cnVlKSxcblx0XHRcdGNvZWZmaWNpZW50OiBiNjRUb0JuKGp3ay5xaSwgdHJ1ZSlcblx0XHR9LCAncGVtJywge1xuXHRcdFx0bGFiZWw6ICdSU0EgUFJJVkFURSBLRVknXG5cdFx0fSk7XG5cdH0gZWxzZSB7XG5cdFx0cGVtID0gUlNBUHVibGljS2V5LmVuY29kZSh7XG5cdFx0XHRtb2R1bHVzOiBiNjRUb0JuKGp3ay5uLCBmYWxzZSksXG5cdFx0XHRwdWJsaWNFeHBvbmVudDogYjY0VG9Cbihqd2suZSwgZmFsc2UpXG5cdFx0fSwgJ3BlbScsIHtcblx0XHRcdGxhYmVsOiAnUlNBIFBVQkxJQyBLRVknXG5cdFx0fSk7XG5cdH1cblxuXHQvLyBUaGlzIGlzIGluIGFuIGlmIGluY2FzZSBhc24xLmpzIGFkZHMgYSB0cmFpbGluZyBcXG5cblx0Ly8gaXN0YW5idWwgaWdub3JlIGVsc2Vcblx0aWYgKCdcXG4nICE9PSBwZW0uc2xpY2UoLTEpKSB7XG5cdFx0cGVtICs9ICdcXG4nO1xuXHR9XG5cblx0cmV0dXJuIHBlbTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSByc2FKd2tUb0J1ZmZlcjtcbiIsIm1vZHVsZS5leHBvcnRzID0gYXNzZXJ0O1xuXG5mdW5jdGlvbiBhc3NlcnQodmFsLCBtc2cpIHtcbiAgaWYgKCF2YWwpXG4gICAgdGhyb3cgbmV3IEVycm9yKG1zZyB8fCAnQXNzZXJ0aW9uIGZhaWxlZCcpO1xufVxuXG5hc3NlcnQuZXF1YWwgPSBmdW5jdGlvbiBhc3NlcnRFcXVhbChsLCByLCBtc2cpIHtcbiAgaWYgKGwgIT0gcilcbiAgICB0aHJvdyBuZXcgRXJyb3IobXNnIHx8ICgnQXNzZXJ0aW9uIGZhaWxlZDogJyArIGwgKyAnICE9ICcgKyByKSk7XG59O1xuIiwidmFyIGluZGV4T2YgPSByZXF1aXJlKCdpbmRleG9mJyk7XG5cbnZhciBPYmplY3Rfa2V5cyA9IGZ1bmN0aW9uIChvYmopIHtcbiAgICBpZiAoT2JqZWN0LmtleXMpIHJldHVybiBPYmplY3Qua2V5cyhvYmopXG4gICAgZWxzZSB7XG4gICAgICAgIHZhciByZXMgPSBbXTtcbiAgICAgICAgZm9yICh2YXIga2V5IGluIG9iaikgcmVzLnB1c2goa2V5KVxuICAgICAgICByZXR1cm4gcmVzO1xuICAgIH1cbn07XG5cbnZhciBmb3JFYWNoID0gZnVuY3Rpb24gKHhzLCBmbikge1xuICAgIGlmICh4cy5mb3JFYWNoKSByZXR1cm4geHMuZm9yRWFjaChmbilcbiAgICBlbHNlIGZvciAodmFyIGkgPSAwOyBpIDwgeHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgZm4oeHNbaV0sIGksIHhzKTtcbiAgICB9XG59O1xuXG52YXIgZGVmaW5lUHJvcCA9IChmdW5jdGlvbigpIHtcbiAgICB0cnkge1xuICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoe30sICdfJywge30pO1xuICAgICAgICByZXR1cm4gZnVuY3Rpb24ob2JqLCBuYW1lLCB2YWx1ZSkge1xuICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KG9iaiwgbmFtZSwge1xuICAgICAgICAgICAgICAgIHdyaXRhYmxlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZSxcbiAgICAgICAgICAgICAgICB2YWx1ZTogdmFsdWVcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH07XG4gICAgfSBjYXRjaChlKSB7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbihvYmosIG5hbWUsIHZhbHVlKSB7XG4gICAgICAgICAgICBvYmpbbmFtZV0gPSB2YWx1ZTtcbiAgICAgICAgfTtcbiAgICB9XG59KCkpO1xuXG52YXIgZ2xvYmFscyA9IFsnQXJyYXknLCAnQm9vbGVhbicsICdEYXRlJywgJ0Vycm9yJywgJ0V2YWxFcnJvcicsICdGdW5jdGlvbicsXG4nSW5maW5pdHknLCAnSlNPTicsICdNYXRoJywgJ05hTicsICdOdW1iZXInLCAnT2JqZWN0JywgJ1JhbmdlRXJyb3InLFxuJ1JlZmVyZW5jZUVycm9yJywgJ1JlZ0V4cCcsICdTdHJpbmcnLCAnU3ludGF4RXJyb3InLCAnVHlwZUVycm9yJywgJ1VSSUVycm9yJyxcbidkZWNvZGVVUkknLCAnZGVjb2RlVVJJQ29tcG9uZW50JywgJ2VuY29kZVVSSScsICdlbmNvZGVVUklDb21wb25lbnQnLCAnZXNjYXBlJyxcbidldmFsJywgJ2lzRmluaXRlJywgJ2lzTmFOJywgJ3BhcnNlRmxvYXQnLCAncGFyc2VJbnQnLCAndW5kZWZpbmVkJywgJ3VuZXNjYXBlJ107XG5cbmZ1bmN0aW9uIENvbnRleHQoKSB7fVxuQ29udGV4dC5wcm90b3R5cGUgPSB7fTtcblxudmFyIFNjcmlwdCA9IGV4cG9ydHMuU2NyaXB0ID0gZnVuY3Rpb24gTm9kZVNjcmlwdCAoY29kZSkge1xuICAgIGlmICghKHRoaXMgaW5zdGFuY2VvZiBTY3JpcHQpKSByZXR1cm4gbmV3IFNjcmlwdChjb2RlKTtcbiAgICB0aGlzLmNvZGUgPSBjb2RlO1xufTtcblxuU2NyaXB0LnByb3RvdHlwZS5ydW5JbkNvbnRleHQgPSBmdW5jdGlvbiAoY29udGV4dCkge1xuICAgIGlmICghKGNvbnRleHQgaW5zdGFuY2VvZiBDb250ZXh0KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwibmVlZHMgYSAnY29udGV4dCcgYXJndW1lbnQuXCIpO1xuICAgIH1cbiAgICBcbiAgICB2YXIgaWZyYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgaWYgKCFpZnJhbWUuc3R5bGUpIGlmcmFtZS5zdHlsZSA9IHt9O1xuICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgIFxuICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcbiAgICBcbiAgICB2YXIgd2luID0gaWZyYW1lLmNvbnRlbnRXaW5kb3c7XG4gICAgdmFyIHdFdmFsID0gd2luLmV2YWwsIHdFeGVjU2NyaXB0ID0gd2luLmV4ZWNTY3JpcHQ7XG5cbiAgICBpZiAoIXdFdmFsICYmIHdFeGVjU2NyaXB0KSB7XG4gICAgICAgIC8vIHdpbi5ldmFsKCkgbWFnaWNhbGx5IGFwcGVhcnMgd2hlbiB0aGlzIGlzIGNhbGxlZCBpbiBJRTpcbiAgICAgICAgd0V4ZWNTY3JpcHQuY2FsbCh3aW4sICdudWxsJyk7XG4gICAgICAgIHdFdmFsID0gd2luLmV2YWw7XG4gICAgfVxuICAgIFxuICAgIGZvckVhY2goT2JqZWN0X2tleXMoY29udGV4dCksIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgd2luW2tleV0gPSBjb250ZXh0W2tleV07XG4gICAgfSk7XG4gICAgZm9yRWFjaChnbG9iYWxzLCBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIGlmIChjb250ZXh0W2tleV0pIHtcbiAgICAgICAgICAgIHdpbltrZXldID0gY29udGV4dFtrZXldO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgXG4gICAgdmFyIHdpbktleXMgPSBPYmplY3Rfa2V5cyh3aW4pO1xuXG4gICAgdmFyIHJlcyA9IHdFdmFsLmNhbGwod2luLCB0aGlzLmNvZGUpO1xuICAgIFxuICAgIGZvckVhY2goT2JqZWN0X2tleXMod2luKSwgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICAvLyBBdm9pZCBjb3B5aW5nIGNpcmN1bGFyIG9iamVjdHMgbGlrZSBgdG9wYCBhbmQgYHdpbmRvd2AgYnkgb25seVxuICAgICAgICAvLyB1cGRhdGluZyBleGlzdGluZyBjb250ZXh0IHByb3BlcnRpZXMgb3IgbmV3IHByb3BlcnRpZXMgaW4gdGhlIGB3aW5gXG4gICAgICAgIC8vIHRoYXQgd2FzIG9ubHkgaW50cm9kdWNlZCBhZnRlciB0aGUgZXZhbC5cbiAgICAgICAgaWYgKGtleSBpbiBjb250ZXh0IHx8IGluZGV4T2Yod2luS2V5cywga2V5KSA9PT0gLTEpIHtcbiAgICAgICAgICAgIGNvbnRleHRba2V5XSA9IHdpbltrZXldO1xuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICBmb3JFYWNoKGdsb2JhbHMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgaWYgKCEoa2V5IGluIGNvbnRleHQpKSB7XG4gICAgICAgICAgICBkZWZpbmVQcm9wKGNvbnRleHQsIGtleSwgd2luW2tleV0pO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgXG4gICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChpZnJhbWUpO1xuICAgIFxuICAgIHJldHVybiByZXM7XG59O1xuXG5TY3JpcHQucHJvdG90eXBlLnJ1bkluVGhpc0NvbnRleHQgPSBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIGV2YWwodGhpcy5jb2RlKTsgLy8gbWF5YmUuLi5cbn07XG5cblNjcmlwdC5wcm90b3R5cGUucnVuSW5OZXdDb250ZXh0ID0gZnVuY3Rpb24gKGNvbnRleHQpIHtcbiAgICB2YXIgY3R4ID0gU2NyaXB0LmNyZWF0ZUNvbnRleHQoY29udGV4dCk7XG4gICAgdmFyIHJlcyA9IHRoaXMucnVuSW5Db250ZXh0KGN0eCk7XG5cbiAgICBmb3JFYWNoKE9iamVjdF9rZXlzKGN0eCksIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgY29udGV4dFtrZXldID0gY3R4W2tleV07XG4gICAgfSk7XG5cbiAgICByZXR1cm4gcmVzO1xufTtcblxuZm9yRWFjaChPYmplY3Rfa2V5cyhTY3JpcHQucHJvdG90eXBlKSwgZnVuY3Rpb24gKG5hbWUpIHtcbiAgICBleHBvcnRzW25hbWVdID0gU2NyaXB0W25hbWVdID0gZnVuY3Rpb24gKGNvZGUpIHtcbiAgICAgICAgdmFyIHMgPSBTY3JpcHQoY29kZSk7XG4gICAgICAgIHJldHVybiBzW25hbWVdLmFwcGx5KHMsIFtdLnNsaWNlLmNhbGwoYXJndW1lbnRzLCAxKSk7XG4gICAgfTtcbn0pO1xuXG5leHBvcnRzLmNyZWF0ZVNjcmlwdCA9IGZ1bmN0aW9uIChjb2RlKSB7XG4gICAgcmV0dXJuIGV4cG9ydHMuU2NyaXB0KGNvZGUpO1xufTtcblxuZXhwb3J0cy5jcmVhdGVDb250ZXh0ID0gU2NyaXB0LmNyZWF0ZUNvbnRleHQgPSBmdW5jdGlvbiAoY29udGV4dCkge1xuICAgIHZhciBjb3B5ID0gbmV3IENvbnRleHQoKTtcbiAgICBpZih0eXBlb2YgY29udGV4dCA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgZm9yRWFjaChPYmplY3Rfa2V5cyhjb250ZXh0KSwgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICAgICAgY29weVtrZXldID0gY29udGV4dFtrZXldO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgcmV0dXJuIGNvcHk7XG59O1xuIl19
