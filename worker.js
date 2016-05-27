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

},{"asn1.js":5,"buffer":22}],2:[function(require,module,exports){
(function (global,Buffer){
'use strict';
var csr = require('./csr');
var asn1 = require('asn1.js');
var EC = require('elliptic').ec;
var b64ToBn = require('./b64-to-bn');
var exp = new Uint8Array([1,0,1]);
var jwkToPem = require('jwk-to-pem');
var der = require('ecc-web-sig');

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
var blankable = ['subjectAltName', 'organizationalUnitName'];
function createInfo(info) {
  return Object.keys(info).map(function (name) {
    if (attrIds[name]) {
      var val = info[name].trim();
      if (blankable.indexOf(name) > -1 && !val) {
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
        sig = der.toDer(new Buffer(sig));
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

},{"./b64-to-bn":1,"./csr":3,"asn1.js":5,"buffer":22,"ecc-web-sig":23,"elliptic":24,"jwk-to-pem":53}],3:[function(require,module,exports){
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

},{"asn1.js":5}],4:[function(require,module,exports){
(function (process){
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

}).call(this,require('_process'))

},{"./create":2,"_process":56}],5:[function(require,module,exports){
var asn1 = exports;

asn1.bignum = require('bn.js');

asn1.define = require('./asn1/api').define;
asn1.base = require('./asn1/base');
asn1.constants = require('./asn1/constants');
asn1.decoders = require('./asn1/decoders');
asn1.encoders = require('./asn1/encoders');

},{"./asn1/api":6,"./asn1/base":8,"./asn1/constants":12,"./asn1/decoders":14,"./asn1/encoders":17,"bn.js":20}],6:[function(require,module,exports){
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

},{"../asn1":5,"inherits":49,"vm":57}],7:[function(require,module,exports){
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

},{"../base":8,"buffer":22,"inherits":49}],8:[function(require,module,exports){
var base = exports;

base.Reporter = require('./reporter').Reporter;
base.DecoderBuffer = require('./buffer').DecoderBuffer;
base.EncoderBuffer = require('./buffer').EncoderBuffer;
base.Node = require('./node');

},{"./buffer":7,"./node":9,"./reporter":10}],9:[function(require,module,exports){
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

},{"../base":8,"minimalistic-assert":55}],10:[function(require,module,exports){
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

},{"inherits":49}],11:[function(require,module,exports){
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

},{"../constants":12}],12:[function(require,module,exports){
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

},{"./der":11}],13:[function(require,module,exports){
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

},{"../../asn1":5,"inherits":49}],14:[function(require,module,exports){
var decoders = exports;

decoders.der = require('./der');
decoders.pem = require('./pem');

},{"./der":13,"./pem":15}],15:[function(require,module,exports){
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

},{"./der":13,"buffer":22,"inherits":49}],16:[function(require,module,exports){
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

},{"../../asn1":5,"buffer":22,"inherits":49}],17:[function(require,module,exports){
var encoders = exports;

encoders.der = require('./der');
encoders.pem = require('./pem');

},{"./der":16,"./pem":18}],18:[function(require,module,exports){
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

},{"./der":16,"inherits":49}],19:[function(require,module,exports){
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

},{}],20:[function(require,module,exports){
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

},{}],21:[function(require,module,exports){
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

},{}],22:[function(require,module,exports){
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

},{"base64-js":19,"ieee754":47,"isarray":50}],23:[function(require,module,exports){
(function (Buffer){
'use strict';
var assert = require('minimalistic-assert');

exports.fromDer = fromDer;
exports.toDer = toDER;

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
var lens = {
  'p-256': 32,
  'p256': 32,
  'p-384': 48,
  'p384': 48,
  'p-521': 66,
  'p521': 66
};
function fromDer(input, curve) {
  assert(typeof curve === 'string');
  var len = lens[curve.toLowerCase()];
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

},{"buffer":22,"minimalistic-assert":55}],24:[function(require,module,exports){
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

},{"../package.json":40,"./elliptic/curve":27,"./elliptic/curves":30,"./elliptic/ec":31,"./elliptic/eddsa":34,"./elliptic/hmac-drbg":37,"./elliptic/utils":39,"brorand":21}],25:[function(require,module,exports){
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

},{"../../elliptic":24,"bn.js":20}],26:[function(require,module,exports){
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

},{"../../elliptic":24,"../curve":27,"bn.js":20,"inherits":49}],27:[function(require,module,exports){
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

},{"../../elliptic":24,"../curve":27,"bn.js":20,"inherits":49}],29:[function(require,module,exports){
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

},{"../../elliptic":24,"../curve":27,"bn.js":20,"inherits":49}],30:[function(require,module,exports){
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

},{"../../elliptic":24,"./key":32,"./signature":33,"bn.js":20}],32:[function(require,module,exports){
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

},{"bn.js":20}],33:[function(require,module,exports){
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

},{"../../elliptic":24,"bn.js":20}],34:[function(require,module,exports){
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

},{"../../elliptic":24,"bn.js":20}],37:[function(require,module,exports){
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


},{"bn.js":20}],40:[function(require,module,exports){
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

},{"asn1.js":5,"buffer":22}],52:[function(require,module,exports){
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

},{"./b64-to-bn":51,"asn1.js":5,"buffer":22,"elliptic":24}],53:[function(require,module,exports){
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

},{"./b64-to-bn":51,"asn1.js":5}],55:[function(require,module,exports){
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
// shim for using process in browser

var process = module.exports = {};
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = setTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    clearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        setTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],57:[function(require,module,exports){
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

},{"indexof":48}]},{},[4])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJiNjQtdG8tYm4uanMiLCJjcmVhdGUuanMiLCJjc3IuanMiLCJpbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYXBpLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9idWZmZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9iYXNlL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9ub2RlLmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvYmFzZS9yZXBvcnRlci5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2NvbnN0YW50cy9kZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9jb25zdGFudHMvaW5kZXguanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9kZWNvZGVycy9kZXIuanMiLCJub2RlX21vZHVsZXMvYXNuMS5qcy9saWIvYXNuMS9kZWNvZGVycy9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2RlY29kZXJzL3BlbS5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2VuY29kZXJzL2Rlci5qcyIsIm5vZGVfbW9kdWxlcy9hc24xLmpzL2xpYi9hc24xL2VuY29kZXJzL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2FzbjEuanMvbGliL2FzbjEvZW5jb2RlcnMvcGVtLmpzIiwibm9kZV9tb2R1bGVzL2Jhc2U2NC1qcy9saWIvYjY0LmpzIiwibm9kZV9tb2R1bGVzL2JuLmpzL2xpYi9ibi5qcyIsIm5vZGVfbW9kdWxlcy9icm9yYW5kL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2J1ZmZlci9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9lY2Mtd2ViLXNpZy9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2Jhc2UuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2Vkd2FyZHMuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2N1cnZlL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9jdXJ2ZS9tb250LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9jdXJ2ZS9zaG9ydC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvY3VydmVzLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lYy9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvZWMva2V5LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lYy9zaWduYXR1cmUuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2VkZHNhL2luZGV4LmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9lZGRzYS9rZXkuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL2VkZHNhL3NpZ25hdHVyZS5qcyIsIm5vZGVfbW9kdWxlcy9lbGxpcHRpYy9saWIvZWxsaXB0aWMvaG1hYy1kcmJnLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL2xpYi9lbGxpcHRpYy9wcmVjb21wdXRlZC9zZWNwMjU2azEuanMiLCJub2RlX21vZHVsZXMvZWxsaXB0aWMvbGliL2VsbGlwdGljL3V0aWxzLmpzIiwibm9kZV9tb2R1bGVzL2VsbGlwdGljL3BhY2thZ2UuanNvbiIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoLmpzIiwibm9kZV9tb2R1bGVzL2hhc2guanMvbGliL2hhc2gvY29tbW9uLmpzIiwibm9kZV9tb2R1bGVzL2hhc2guanMvbGliL2hhc2gvaG1hYy5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3JpcGVtZC5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3NoYS5qcyIsIm5vZGVfbW9kdWxlcy9oYXNoLmpzL2xpYi9oYXNoL3V0aWxzLmpzIiwibm9kZV9tb2R1bGVzL2llZWU3NTQvaW5kZXguanMiLCJub2RlX21vZHVsZXMvaW5kZXhvZi9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy9pbmhlcml0cy9pbmhlcml0c19icm93c2VyLmpzIiwibm9kZV9tb2R1bGVzL2lzYXJyYXkvaW5kZXguanMiLCJub2RlX21vZHVsZXMvandrLXRvLXBlbS9zcmMvYjY0LXRvLWJuLmpzIiwibm9kZV9tb2R1bGVzL2p3ay10by1wZW0vc3JjL2VjLmpzIiwibm9kZV9tb2R1bGVzL2p3ay10by1wZW0vc3JjL2p3ay10by1wZW0uanMiLCJub2RlX21vZHVsZXMvandrLXRvLXBlbS9zcmMvcnNhLmpzIiwibm9kZV9tb2R1bGVzL21pbmltYWxpc3RpYy1hc3NlcnQvaW5kZXguanMiLCJub2RlX21vZHVsZXMvcHJvY2Vzcy9icm93c2VyLmpzIiwibm9kZV9tb2R1bGVzL3ZtLWJyb3dzZXJpZnkvaW5kZXguanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7OztBQ1hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ3hQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDOUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ1hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDN0RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdm1CQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN0R0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2pVQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakRBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNyU0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNyQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM3R0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzMxR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQ3pEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7OztBQy9xREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7O0FDckdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNkQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMvVkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzFaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM3NEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDN01BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzlOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM0dBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3ZJQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbEVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2xIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM1d0JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDNUtBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5R0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDZkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaERBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqUUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcEZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7QUNaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7QUMzSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3BHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5RkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbiBlKHQsbixyKXtmdW5jdGlvbiBzKG8sdSl7aWYoIW5bb10pe2lmKCF0W29dKXt2YXIgYT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2lmKCF1JiZhKXJldHVybiBhKG8sITApO2lmKGkpcmV0dXJuIGkobywhMCk7dmFyIGY9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitvK1wiJ1wiKTt0aHJvdyBmLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsZn12YXIgbD1uW29dPXtleHBvcnRzOnt9fTt0W29dWzBdLmNhbGwobC5leHBvcnRzLGZ1bmN0aW9uKGUpe3ZhciBuPXRbb11bMV1bZV07cmV0dXJuIHMobj9uOmUpfSxsLGwuZXhwb3J0cyxlLHQsbixyKX1yZXR1cm4gbltvXS5leHBvcnRzfXZhciBpPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7Zm9yKHZhciBvPTA7bzxyLmxlbmd0aDtvKyspcyhyW29dKTtyZXR1cm4gc30pIiwiLy8gZnJvbSBodHRwczovL2dpdGh1Yi5jb20vQnJpZ2h0c3BhY2Uvbm9kZS1qd2stdG8tcGVtL2Jsb2IvbWFzdGVyL3NyYy9iNjQtdG8tYm4uanNcbnZhciBCTiA9IHJlcXVpcmUoJ2FzbjEuanMnKS5iaWdudW07XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gYmFzZTY0VG9CaWdOdW0odmFsLCB6ZXJvKSB7XG4gIHZhciBidWYgPSBuZXcgQnVmZmVyKHZhbCwgJ2Jhc2U2NCcpO1xuICB2YXIgYm4gPSB2YWwgPSBuZXcgQk4oYnVmLCAxMCwgJ2JlJykuaWFicygpO1xuICBpZiAoemVybykge1xuICAgIGJ1Zi5maWxsKDApO1xuICB9XG4gIHJldHVybiBibjtcbn07XG4iLCIndXNlIHN0cmljdCc7XG52YXIgY3NyID0gcmVxdWlyZSgnLi9jc3InKTtcbnZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpO1xudmFyIEVDID0gcmVxdWlyZSgnZWxsaXB0aWMnKS5lYztcbnZhciBiNjRUb0JuID0gcmVxdWlyZSgnLi9iNjQtdG8tYm4nKTtcbnZhciBleHAgPSBuZXcgVWludDhBcnJheShbMSwwLDFdKTtcbnZhciBqd2tUb1BlbSA9IHJlcXVpcmUoJ2p3ay10by1wZW0nKTtcbnZhciBkZXIgPSByZXF1aXJlKCdlY2Mtd2ViLXNpZycpO1xuXG52YXIgRUNQYXJhbWV0ZXJzID0gYXNuMS5kZWZpbmUoJ0VDUGFyYW1ldGVycycsIC8qIEB0aGlzICovIGZ1bmN0aW9uKCkge1xuICB0aGlzLmNob2ljZSh7XG4gICAgbmFtZWRDdXJ2ZTogdGhpcy5vYmppZCgpXG4gIH0pO1xufSk7XG52YXIgUlNBUHVibGljS2V5ID0gYXNuMS5kZWZpbmUoJ1JTQVB1YmxpY0tleScsIC8qIEB0aGlzICovIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgnbW9kdWx1cycpLmludCgpLFxuICAgIHRoaXMua2V5KCdwdWJsaWNFeHBvbmVudCcpLmludCgpXG4gICk7XG59KTtcbnZhciBwYXJhbXMgPSB7XG4gICdQLTI1Nic6IGNzci5BdHRyaWJ1dGVUeXBlLmVuY29kZShbMSwgMiwgODQwLCAxMDA0NSwgMywgMSwgN10sICdwZW0nLCB7XG4gICAgbGFiZWw6ICdFQyBQQVJBTUVURVJTJ1xuICB9KSxcbiAgJ1AtMzg0JzogY3NyLkF0dHJpYnV0ZVR5cGUuZW5jb2RlKFsxLCAzLCAxMzIsIDAsIDM0XSwgJ3BlbScsIHtcbiAgICBsYWJlbDogJ0VDIFBBUkFNRVRFUlMnXG4gIH0pLFxuICAnUC01MjEnOiBjc3IuQXR0cmlidXRlVHlwZS5lbmNvZGUoWzEsIDMsIDEzMiwgMCwgMzVdLCAncGVtJywge1xuICAgIGxhYmVsOiAnRUMgUEFSQU1FVEVSUydcbiAgfSlcbn1cbnZhciBlY29pZHMgPSB7XG4gICdQLTI1Nic6IFsxLCAyLCA4NDAsIDEwMDQ1LCAzLCAxLCA3XSxcbiAgJ1AtMzg0JzogWzEsIDMsIDEzMiwgMCwgMzRdLFxuICAnUC01MjEnOiBbMSwgMywgMTMyLCAwLCAzNV1cbn07XG52YXIgY3VydmVzID0ge1xuICAnUC0yNTYnOiAncDI1NicsXG4gICdQLTM4NCc6ICdwMzg0JyxcbiAgJ1AtNTIxJzogJ3A1MjEnXG59O1xudmFyIGhhc2ggPSB7XG4gICdQLTI1Nic6ICdTSEEtMjU2JyxcbiAgJ1AtMzg0JzogJ1NIQS0zODQnLFxuICAnUC01MjEnOiAnU0hBLTUxMidcbn1cbmZ1bmN0aW9uIGNyZWF0ZVNpZ25hYmxlKGluZm8sIGtleSwgYWxnbykge1xuICB2YXIgb2JqID0ge1xuICAgIGluZm86IGNyZWF0ZUluZm8oaW5mbyksXG4gICAgdmVyc2lvbjogMCxcbiAgICBwdWJsaWNLZXk6IHB1YmxpY0tleShrZXksIGFsZ28pLFxuICAgIGF0dHJpYnV0ZXM6IFtdXG4gIH07XG4gIHZhciBkZXIgPSBjc3IuQ2VydGlmaWNhdGlvblJlcXVlc3RJbmZvLmVuY29kZShvYmosICdkZXInKTtcbiAgcmV0dXJuIHtcbiAgICBqc29uOiBvYmosXG4gICAgZGVyOiBkZXJcbiAgfTtcbn1cbmZ1bmN0aW9uIGdlbmVyYXRlRWNkc2EoY3VydmUpIHtcbiAgcmV0dXJuIGdsb2JhbC5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgIHtcbiAgICAgIG5hbWU6ICdFQ0RTQScsXG4gICAgICBuYW1lZEN1cnZlOiBjdXJ2ZVxuICAgIH0sXG4gICAgdHJ1ZSxcbiAgICBbJ3NpZ24nLCAndmVyaWZ5J11cbiAgKS50aGVuKGZ1bmN0aW9uIChwYWlyKSB7XG4gICAgcmV0dXJuIGdsb2JhbC5jcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywgcGFpci5wcml2YXRlS2V5KS50aGVuKGZ1bmN0aW9uIChqd2spIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHBhaXI6IHBhaXIsXG4gICAgICAgIGp3azogandrXG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xufVxuZnVuY3Rpb24gZ2VuZXJhdGVSc2EobGVuKSB7XG4gIHJldHVybiBnbG9iYWwuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7XG4gICAgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyxcbiAgICBtb2R1bHVzTGVuZ3RoOiBsZW4sXG4gICAgcHVibGljRXhwb25lbnQ6IGV4cCxcbiAgICBoYXNoOiB7bmFtZTogJ1NIQS0yNTYnfVxuICB9LFxuICB0cnVlLFxuICAgIFsnc2lnbicsICd2ZXJpZnknXVxuICApLnRoZW4oZnVuY3Rpb24gKHBhaXIpIHtcbiAgICByZXR1cm4gZ2xvYmFsLmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBwYWlyLnByaXZhdGVLZXkpLnRoZW4oZnVuY3Rpb24gKGp3aykge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgcGFpcjogcGFpcixcbiAgICAgICAgandrOiBqd2tcbiAgICAgIH1cbiAgICB9KTtcbiAgfSk7XG59XG52YXIgYXR0cklkcyA9IHtcbiAgY29tbW9uTmFtZTogJzIuNS40LjMnLnNwbGl0KCcuJyksXG4gIGNvdW50cnlOYW1lOiAnMi41LjQuNicuc3BsaXQoJy4nKSxcbiAgc3RhdGVPclByb3ZpbmNlTmFtZTogJzIuNS40LjgnLnNwbGl0KCcuJyksXG4gIGxvY2FsaXR5TmFtZTogJzIuNS40LjcnLnNwbGl0KCcuJyksXG4gIG9yZ2FuaXphdGlvbk5hbWU6ICcyLjUuNC4xMCcuc3BsaXQoJy4nKSxcbiAgb3JnYW5pemF0aW9uYWxVbml0TmFtZTogJzIuNS40LjExJy5zcGxpdCgnLicpLFxuICBzdWJqZWN0QWx0TmFtZTogJzIuNS4yOS4xNycuc3BsaXQoJy4nKVxufVxudmFyIGJsYW5rYWJsZSA9IFsnc3ViamVjdEFsdE5hbWUnLCAnb3JnYW5pemF0aW9uYWxVbml0TmFtZSddO1xuZnVuY3Rpb24gY3JlYXRlSW5mbyhpbmZvKSB7XG4gIHJldHVybiBPYmplY3Qua2V5cyhpbmZvKS5tYXAoZnVuY3Rpb24gKG5hbWUpIHtcbiAgICBpZiAoYXR0cklkc1tuYW1lXSkge1xuICAgICAgdmFyIHZhbCA9IGluZm9bbmFtZV0udHJpbSgpO1xuICAgICAgaWYgKGJsYW5rYWJsZS5pbmRleE9mKG5hbWUpID4gLTEgJiYgIXZhbCkge1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICByZXR1cm4gW3tcbiAgICAgICAgdHlwZTogYXR0cklkc1tuYW1lXSxcbiAgICAgICAgdmFsdWU6IHZhbFxuICAgICAgfV1cbiAgICB9XG4gIH0pLmZpbHRlcihmdW5jdGlvbiAoaXRlbSkge1xuICAgIHJldHVybiBpdGVtO1xuICB9KTtcbn1cbmZ1bmN0aW9uIHB1YmxpY0tleShrZXksIGFsZ28pIHtcbiAgaWYgKGFsZ28gPT09ICdyc2EnKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN1YmplY3RQdWJsaWNLZXk6IHtcbiAgICAgICAgdW51c2VkOiAwLFxuICAgICAgICBkYXRhOiBSU0FQdWJsaWNLZXkuZW5jb2RlKHtcbiAgICAgICAgICBtb2R1bHVzOiBiNjRUb0JuKGtleS5qd2subiwgZmFsc2UpLFxuICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBiNjRUb0JuKGtleS5qd2suZSwgZmFsc2UpXG4gICAgICAgIH0sICdkZXInKVxuICAgICAgfSxcbiAgICAgIGFsZ29yaXRobToge1xuICAgICAgICB0eXBlOiAnQWxnb3JpdGhtSWRlbnRpZmllclJTQScsXG4gICAgICAgIHZhbHVlOiB7XG4gICAgICAgICAgYWxnb3JpdGhtOiAnMS4yLjg0MC4xMTM1NDkuMS4xLjEnLnNwbGl0KCcuJyksXG4gICAgICAgICAgcGFyYW1ldGVyczogbnVsbFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9IGVsc2UgaWYgKGFsZ28gPT09ICdlYycpIHtcbiAgICB2YXIgY3VydmVOYW1lID0gY3VydmVzW2tleS5qd2suY3J2XTtcbiAgICB2YXIgY3VydmUgPSBuZXcgRUMoY3VydmVOYW1lKTtcbiAgICB2YXIgayA9ICBjdXJ2ZS5rZXlQYWlyKHtcbiAgICAgIHB1Yjoge1xuICAgICAgICB4OiBiNjRUb0JuKGtleS5qd2sueCwgZmFsc2UpLFxuICAgICAgICB5OiBiNjRUb0JuKGtleS5qd2sueSwgZmFsc2UpXG4gICAgICB9XG4gICAgfSk7XG4gICAgdmFyIHN1YmplY3RQdWJsaWNLZXkgPSBrLmdldFB1YmxpYyhmYWxzZSwgJ2hleCcpO1xuICAgIHN1YmplY3RQdWJsaWNLZXkgPSBuZXcgQnVmZmVyKHN1YmplY3RQdWJsaWNLZXksICdoZXgnKTtcbiAgICBzdWJqZWN0UHVibGljS2V5ID0ge1xuICAgICAgdW51c2VkOiAwLFxuICAgICAgZGF0YTogc3ViamVjdFB1YmxpY0tleVxuICAgIH07XG4gICAgdmFyIHBhcmFtZXRlcnMgPSBFQ1BhcmFtZXRlcnMuZW5jb2RlKHtcbiAgICAgIHR5cGU6ICduYW1lZEN1cnZlJyxcbiAgICAgIHZhbHVlOiBlY29pZHNba2V5Lmp3ay5jcnZdXG4gICAgfSwgJ2RlcicpO1xuICAgIHJldHVybiB7XG4gICAgICBhbGdvcml0aG06IHtcbiAgICAgICAgdHlwZTogJ0FsZ29yaXRobUlkZW50aWZpZXInLFxuICAgICAgICB2YWx1ZToge1xuICAgICAgICAgIGFsZ29yaXRobTogWzEsIDIsIDg0MCwgMTAwNDUsIDIsIDFdLFxuICAgICAgICAgIHBhcmFtZXRlcnM6IHBhcmFtZXRlcnNcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIHN1YmplY3RQdWJsaWNLZXk6IHN1YmplY3RQdWJsaWNLZXlcbiAgICB9XG4gIH1cbn1cbmZ1bmN0aW9uIGNyZWF0ZUtleShpZCkge1xuICBzd2l0Y2ggKGlkKSB7XG4gIGNhc2UgJzEnOlxuICAgIHJldHVybiBnZW5lcmF0ZUVjZHNhKCdQLTI1NicpO1xuICBjYXNlICc0JzpcbiAgICByZXR1cm4gZ2VuZXJhdGVFY2RzYSgnUC0zODQnKTtcbiAgY2FzZSAnNSc6XG4gICAgcmV0dXJuIGdlbmVyYXRlRWNkc2EoJ1AtNTIxJyk7XG4gIGNhc2UgJzInOlxuICAgIHJldHVybiBnZW5lcmF0ZVJzYSgyMDQ4KTtcbiAgY2FzZSAnMyc6XG4gICAgcmV0dXJuIGdlbmVyYXRlUnNhKDQwOTYpO1xuICB9XG59XG5mdW5jdGlvbiBtYWtlSWQoa2V5VHlwZSkge1xuICBzd2l0Y2ggKGtleVR5cGUpIHtcbiAgY2FzZSAnMic6XG4gIGNhc2UgJzMnOlxuICAgIHJldHVybiB7XG4gICAgICBwYXJhbWV0ZXJzOiBudWxsLFxuICAgICAgYWxnb3JpdGhtOiAnMS4yLjg0MC4xMTM1NDkuMS4xLjExJy5zcGxpdCgnLicpXG4gICAgfTtcbiAgY2FzZSAnMSc6XG4gICAgcmV0dXJuIHtcbiAgICAgIGFsZ29yaXRobTogJzEuMi44NDAuMTAwNDUuNC4zLjInLnNwbGl0KCcuJylcbiAgICB9O1xuICBjYXNlICc0JzpcbiAgICByZXR1cm4ge1xuICAgICAgYWxnb3JpdGhtOiAnMS4yLjg0MC4xMDA0NS40LjMuMycuc3BsaXQoJy4nKVxuICAgIH07XG4gIGNhc2UgJzUnOlxuICAgIHJldHVybiB7XG4gICAgICBhbGdvcml0aG06ICcxLjIuODQwLjEwMDQ1LjQuMy40Jy5zcGxpdCgnLicpXG4gICAgfTtcbiAgfVxufVxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiAoa2V5VHlwZSwgaW5mbykge1xuICByZXR1cm4gY3JlYXRlS2V5KGtleVR5cGUpLnRoZW4oZnVuY3Rpb24gKGtleSkge1xuICAgIHZhciBhbGdvID0gJ2VjJztcbiAgICBpZiAoa2V5VHlwZSA9PT0gJzInIHx8IGtleVR5cGUgPT09ICczJykge1xuICAgICAgYWxnbyA9ICdyc2EnO1xuICAgIH1cbiAgICB2YXIgc2lnbmFibGUgPSBjcmVhdGVTaWduYWJsZShpbmZvLCBrZXksIGFsZ28pO1xuICAgIHZhciBzaWduUHJvbTtcbiAgICBpZiAoYWxnbyA9PT0gJ3JzYScpIHtcbiAgICAgIHNpZ25Qcm9tID0gZ2xvYmFsLmNyeXB0by5zdWJ0bGUuc2lnbih7bmFtZTogJ1JTQVNTQS1QS0NTMS12MV81J30sIGtleS5wYWlyLnByaXZhdGVLZXksIHNpZ25hYmxlLmRlcilcbiAgICB9IGVsc2Uge1xuICAgICAgc2lnblByb20gPSBnbG9iYWwuY3J5cHRvLnN1YnRsZS5zaWduKHtuYW1lOiAnRUNEU0EnLCBoYXNoOiB7bmFtZTogaGFzaFtrZXkuandrLmNydl19fSwga2V5LnBhaXIucHJpdmF0ZUtleSwgc2lnbmFibGUuZGVyKTtcbiAgICB9XG4gICAgcmV0dXJuIFByb21pc2UuYWxsKFtzaWduUHJvbS50aGVuKGZ1bmN0aW9uIChzaWcpIHtcbiAgICAgIHZhciBtZXRob2QgPSBhbGdvID09PSAncnNhJyA/ICdDZXJ0aWZpY2F0aW9uUmVxdWVzdFJTQScgOiAnQ2VydGlmaWNhdGlvblJlcXVlc3QnO1xuICAgICAgaWYgKGFsZ28gIT09ICdyc2EnKSB7XG4gICAgICAgIHNpZyA9IGRlci50b0RlcihuZXcgQnVmZmVyKHNpZykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgc2lnID0gbmV3IEJ1ZmZlcihzaWcpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGNzclttZXRob2RdLmVuY29kZSh7XG4gICAgICAgIGNlcnRpZmljYXRpb25SZXF1ZXN0SW5mbzogc2lnbmFibGUuanNvbixcbiAgICAgICAgc2lnbmF0dXJlOiB7XG4gICAgICAgICAgdW51c2VkOiAwLFxuICAgICAgICAgIGRhdGE6IHNpZ1xuICAgICAgICB9LFxuICAgICAgICBzaWduYXR1cmVBbGdvcml0aG06IG1ha2VJZChrZXlUeXBlKVxuICAgICAgfSwgJ3BlbScsIHtcbiAgICAgICAgbGFiZWw6ICdDRVJUSUZJQ0FURSBSRVFVRVNUJ1xuICAgICAgfSlcbiAgICB9KSxcbiAgICBQcm9taXNlLnJlc29sdmUoandrVG9QZW0oa2V5Lmp3aywge1xuICAgICAgcHJpdmF0ZTogdHJ1ZVxuICAgIH0pKS50aGVuKGZ1bmN0aW9uIChrZXlQZW0pIHtcbiAgICAgIGlmIChhbGdvID09PSAncnNhJykge1xuICAgICAgICByZXR1cm4ga2V5UGVtXG4gICAgICB9XG4gICAgICB2YXIgcGFyYW0gPSBwYXJhbXNba2V5Lmp3ay5jcnZdO1xuICAgICAgcmV0dXJuIHBhcmFtICsgJ1xcbicgKyBrZXlQZW07XG4gICAgfSlcbiAgXSk7XG4gIH0pO1xufVxuIiwidmFyIGFzbjEgPSByZXF1aXJlKCdhc24xLmpzJyk7XG5cbnZhciBBbGdvcml0aG1JZGVudGlmaWVyUlNBID0gZXhwb3J0cy5BbGdvcml0aG1JZGVudGlmaWVyUlNBID0gYXNuMS5kZWZpbmUoJ0FsZ29yaXRobUlkZW50aWZpZXJSU0EnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ2FsZ29yaXRobScpLm9iamlkKCksXG4gICAgdGhpcy5rZXkoJ3BhcmFtZXRlcnMnKS5vcHRpb25hbCgpLm51bGxfKClcbiAgKTtcbn0pO1xudmFyIEFsZ29yaXRobUlkZW50aWZpZXIgPSBleHBvcnRzLkFsZ29yaXRobUlkZW50aWZpZXIgPSBhc24xLmRlZmluZSgnQWxnb3JpdGhtSWRlbnRpZmllcicsIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgnYWxnb3JpdGhtJykub2JqaWQoKSxcbiAgICB0aGlzLmtleSgncGFyYW1ldGVycycpLm9wdGlvbmFsKCkuYW55KClcbiAgKTtcbn0pO1xudmFyIEFsZ29DaG9pY2UgPSAgYXNuMS5kZWZpbmUoJ0FsZ29DaG9pY2UnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5jaG9pY2Uoe1xuICAgIEFsZ29yaXRobUlkZW50aWZpZXI6IHRoaXMudXNlKEFsZ29yaXRobUlkZW50aWZpZXIpLFxuICAgIEFsZ29yaXRobUlkZW50aWZpZXJSU0E6IHRoaXMudXNlKEFsZ29yaXRobUlkZW50aWZpZXJSU0EpXG4gIH0pO1xufSk7XG52YXIgVmVyc2lvbiA9IGV4cG9ydHMuVmVyc2lvbiA9IGFzbjEuZGVmaW5lKCdWZXJzaW9uJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMuaW50KHtcbiAgICAwOiAndjEnLFxuICAgIDE6ICd2MicsXG4gICAgMjogJ3YzJ1xuICB9KTtcbn0pO1xudmFyIEludCA9IGFzbjEuZGVmaW5lKCdJbnQnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5pbnQoKTtcbn0pO1xudmFyIFN1YmplY3RQdWJsaWNLZXlJbmZvID0gZXhwb3J0cy5TdWJqZWN0UHVibGljS2V5SW5mbyA9IGFzbjEuZGVmaW5lKCdTdWJqZWN0UHVibGljS2V5SW5mbycsIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgnYWxnb3JpdGhtJykudXNlKEFsZ29DaG9pY2UpLFxuICAgIHRoaXMua2V5KCdzdWJqZWN0UHVibGljS2V5JykuYml0c3RyKClcbiAgKTtcbn0pO1xuXG52YXIgQXR0cmlidXRlVmFsdWUgPSBhc24xLmRlZmluZSgnQXR0cmlidXRlVmFsdWUnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy51dGY4c3RyKCk7XG59KTtcbnZhciBBdHRyaWJ1dGVUeXBlID0gZXhwb3J0cy5BdHRyaWJ1dGVUeXBlID0gYXNuMS5kZWZpbmUoJ0F0dHJpYnV0ZVR5cGUnLCBmdW5jdGlvbigpIHtcbiAgdGhpcy5vYmppZCgpO1xufSk7XG52YXIgQXR0cmlidXRlVHlwZUFuZFZhbHVlID0gYXNuMS5kZWZpbmUoJ0F0dHJpYnV0ZVR5cGVBbmRWYWx1ZScsIGZ1bmN0aW9uICgpIHtcbiAgdGhpcy5zZXEoKS5vYmooXG4gICAgdGhpcy5rZXkoJ3R5cGUnKS51c2UoQXR0cmlidXRlVHlwZSksXG4gICAgdGhpcy5rZXkoJ3ZhbHVlJykudXNlKEF0dHJpYnV0ZVZhbHVlKVxuICApO1xufSlcblxudmFyIFJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUgPSBleHBvcnRzLlJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUgPSBhc24xLmRlZmluZSgnUmVsYXRpdmVEaXN0aW5ndWlzaGVkTmFtZScsZnVuY3Rpb24oKSB7XG4gIHRoaXMuc2V0b2YoQXR0cmlidXRlVHlwZUFuZFZhbHVlKTtcbn0pO1xudmFyIFNlcU9mUmVsYXRpdmVEaXN0aW5ndWlzaGVkTmFtZSA9IGFzbjEuZGVmaW5lKCdTZXFPZlJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUnLGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcW9mKFJlbGF0aXZlRGlzdGluZ3Vpc2hlZE5hbWUpO1xufSk7XG52YXIgQ2VydGlmaWNhdGlvblJlcXVlc3RJbmZvID0gZXhwb3J0cy5DZXJ0aWZpY2F0aW9uUmVxdWVzdEluZm8gPSBhc24xLmRlZmluZSgnQ2VydGlmaWNhdGlvblJlcXVlc3RJbmZvJywgZnVuY3Rpb24oKSB7XG4gIHRoaXMuc2VxKCkub2JqKFxuICAgIHRoaXMua2V5KCd2ZXJzaW9uJykudXNlKFZlcnNpb24pLFxuICAgIHRoaXMua2V5KCdpbmZvJykudXNlKFNlcU9mUmVsYXRpdmVEaXN0aW5ndWlzaGVkTmFtZSksXG4gICAgdGhpcy5rZXkoJ3B1YmxpY0tleScpLnVzZShTdWJqZWN0UHVibGljS2V5SW5mbyksXG4gICAgdGhpcy5rZXkoJ2F0dHJpYnV0ZXMnKS5zZXFvZihJbnQpLmltcGxpY2l0KDApLm9wdGlvbmFsKClcbiAgKTtcbn0pO1xuZXhwb3J0cy5DZXJ0aWZpY2F0aW9uUmVxdWVzdCA9IGFzbjEuZGVmaW5lKCdDZXJ0aWZpY2F0aW9uUmVxdWVzdCcsIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgnY2VydGlmaWNhdGlvblJlcXVlc3RJbmZvJykudXNlKENlcnRpZmljYXRpb25SZXF1ZXN0SW5mbyksXG4gICAgdGhpcy5rZXkoJ3NpZ25hdHVyZUFsZ29yaXRobScpLnVzZShBbGdvcml0aG1JZGVudGlmaWVyKSxcbiAgICB0aGlzLmtleSgnc2lnbmF0dXJlJykuYml0c3RyKClcbiAgKTtcbn0pO1xuZXhwb3J0cy5DZXJ0aWZpY2F0aW9uUmVxdWVzdFJTQSA9IGFzbjEuZGVmaW5lKCdDZXJ0aWZpY2F0aW9uUmVxdWVzdFJTQScsIGZ1bmN0aW9uKCkge1xuICB0aGlzLnNlcSgpLm9iaihcbiAgICB0aGlzLmtleSgnY2VydGlmaWNhdGlvblJlcXVlc3RJbmZvJykudXNlKENlcnRpZmljYXRpb25SZXF1ZXN0SW5mbyksXG4gICAgdGhpcy5rZXkoJ3NpZ25hdHVyZUFsZ29yaXRobScpLnVzZShBbGdvcml0aG1JZGVudGlmaWVyUlNBKSxcbiAgICB0aGlzLmtleSgnc2lnbmF0dXJlJykuYml0c3RyKClcbiAgKTtcbn0pO1xuIiwidmFyIG1ha2VDc3IgPSByZXF1aXJlKCcuL2NyZWF0ZScpO1xuXG5zZWxmLmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBmdW5jdGlvbiAoZSkge1xuICBtYWtlQ3NyKGUuZGF0YVswXSwgZS5kYXRhWzFdKS50aGVuKGZ1bmN0aW9uIChyZXNwKSB7XG4gICAgc2VsZi5wb3N0TWVzc2FnZShyZXNwKTtcbiAgfSkuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICBwcm9jZXNzLm5leHRUaWNrKGZ1bmN0aW9uICgpIHtcbiAgICAgIHRocm93IGU7XG4gICAgfSk7XG4gIH0pO1xufSk7XG4iLCJ2YXIgYXNuMSA9IGV4cG9ydHM7XG5cbmFzbjEuYmlnbnVtID0gcmVxdWlyZSgnYm4uanMnKTtcblxuYXNuMS5kZWZpbmUgPSByZXF1aXJlKCcuL2FzbjEvYXBpJykuZGVmaW5lO1xuYXNuMS5iYXNlID0gcmVxdWlyZSgnLi9hc24xL2Jhc2UnKTtcbmFzbjEuY29uc3RhbnRzID0gcmVxdWlyZSgnLi9hc24xL2NvbnN0YW50cycpO1xuYXNuMS5kZWNvZGVycyA9IHJlcXVpcmUoJy4vYXNuMS9kZWNvZGVycycpO1xuYXNuMS5lbmNvZGVycyA9IHJlcXVpcmUoJy4vYXNuMS9lbmNvZGVycycpO1xuIiwidmFyIGFzbjEgPSByZXF1aXJlKCcuLi9hc24xJyk7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG52YXIgYXBpID0gZXhwb3J0cztcblxuYXBpLmRlZmluZSA9IGZ1bmN0aW9uIGRlZmluZShuYW1lLCBib2R5KSB7XG4gIHJldHVybiBuZXcgRW50aXR5KG5hbWUsIGJvZHkpO1xufTtcblxuZnVuY3Rpb24gRW50aXR5KG5hbWUsIGJvZHkpIHtcbiAgdGhpcy5uYW1lID0gbmFtZTtcbiAgdGhpcy5ib2R5ID0gYm9keTtcblxuICB0aGlzLmRlY29kZXJzID0ge307XG4gIHRoaXMuZW5jb2RlcnMgPSB7fTtcbn07XG5cbkVudGl0eS5wcm90b3R5cGUuX2NyZWF0ZU5hbWVkID0gZnVuY3Rpb24gY3JlYXRlTmFtZWQoYmFzZSkge1xuICB2YXIgbmFtZWQ7XG4gIHRyeSB7XG4gICAgbmFtZWQgPSByZXF1aXJlKCd2bScpLnJ1bkluVGhpc0NvbnRleHQoXG4gICAgICAnKGZ1bmN0aW9uICcgKyB0aGlzLm5hbWUgKyAnKGVudGl0eSkge1xcbicgK1xuICAgICAgJyAgdGhpcy5faW5pdE5hbWVkKGVudGl0eSk7XFxuJyArXG4gICAgICAnfSknXG4gICAgKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIG5hbWVkID0gZnVuY3Rpb24gKGVudGl0eSkge1xuICAgICAgdGhpcy5faW5pdE5hbWVkKGVudGl0eSk7XG4gICAgfTtcbiAgfVxuICBpbmhlcml0cyhuYW1lZCwgYmFzZSk7XG4gIG5hbWVkLnByb3RvdHlwZS5faW5pdE5hbWVkID0gZnVuY3Rpb24gaW5pdG5hbWVkKGVudGl0eSkge1xuICAgIGJhc2UuY2FsbCh0aGlzLCBlbnRpdHkpO1xuICB9O1xuXG4gIHJldHVybiBuZXcgbmFtZWQodGhpcyk7XG59O1xuXG5FbnRpdHkucHJvdG90eXBlLl9nZXREZWNvZGVyID0gZnVuY3Rpb24gX2dldERlY29kZXIoZW5jKSB7XG4gIGVuYyA9IGVuYyB8fCAnZGVyJztcbiAgLy8gTGF6aWx5IGNyZWF0ZSBkZWNvZGVyXG4gIGlmICghdGhpcy5kZWNvZGVycy5oYXNPd25Qcm9wZXJ0eShlbmMpKVxuICAgIHRoaXMuZGVjb2RlcnNbZW5jXSA9IHRoaXMuX2NyZWF0ZU5hbWVkKGFzbjEuZGVjb2RlcnNbZW5jXSk7XG4gIHJldHVybiB0aGlzLmRlY29kZXJzW2VuY107XG59O1xuXG5FbnRpdHkucHJvdG90eXBlLmRlY29kZSA9IGZ1bmN0aW9uIGRlY29kZShkYXRhLCBlbmMsIG9wdGlvbnMpIHtcbiAgcmV0dXJuIHRoaXMuX2dldERlY29kZXIoZW5jKS5kZWNvZGUoZGF0YSwgb3B0aW9ucyk7XG59O1xuXG5FbnRpdHkucHJvdG90eXBlLl9nZXRFbmNvZGVyID0gZnVuY3Rpb24gX2dldEVuY29kZXIoZW5jKSB7XG4gIGVuYyA9IGVuYyB8fCAnZGVyJztcbiAgLy8gTGF6aWx5IGNyZWF0ZSBlbmNvZGVyXG4gIGlmICghdGhpcy5lbmNvZGVycy5oYXNPd25Qcm9wZXJ0eShlbmMpKVxuICAgIHRoaXMuZW5jb2RlcnNbZW5jXSA9IHRoaXMuX2NyZWF0ZU5hbWVkKGFzbjEuZW5jb2RlcnNbZW5jXSk7XG4gIHJldHVybiB0aGlzLmVuY29kZXJzW2VuY107XG59O1xuXG5FbnRpdHkucHJvdG90eXBlLmVuY29kZSA9IGZ1bmN0aW9uIGVuY29kZShkYXRhLCBlbmMsIC8qIGludGVybmFsICovIHJlcG9ydGVyKSB7XG4gIHJldHVybiB0aGlzLl9nZXRFbmNvZGVyKGVuYykuZW5jb2RlKGRhdGEsIHJlcG9ydGVyKTtcbn07XG4iLCJ2YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIFJlcG9ydGVyID0gcmVxdWlyZSgnLi4vYmFzZScpLlJlcG9ydGVyO1xudmFyIEJ1ZmZlciA9IHJlcXVpcmUoJ2J1ZmZlcicpLkJ1ZmZlcjtcblxuZnVuY3Rpb24gRGVjb2RlckJ1ZmZlcihiYXNlLCBvcHRpb25zKSB7XG4gIFJlcG9ydGVyLmNhbGwodGhpcywgb3B0aW9ucyk7XG4gIGlmICghQnVmZmVyLmlzQnVmZmVyKGJhc2UpKSB7XG4gICAgdGhpcy5lcnJvcignSW5wdXQgbm90IEJ1ZmZlcicpO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIHRoaXMuYmFzZSA9IGJhc2U7XG4gIHRoaXMub2Zmc2V0ID0gMDtcbiAgdGhpcy5sZW5ndGggPSBiYXNlLmxlbmd0aDtcbn1cbmluaGVyaXRzKERlY29kZXJCdWZmZXIsIFJlcG9ydGVyKTtcbmV4cG9ydHMuRGVjb2RlckJ1ZmZlciA9IERlY29kZXJCdWZmZXI7XG5cbkRlY29kZXJCdWZmZXIucHJvdG90eXBlLnNhdmUgPSBmdW5jdGlvbiBzYXZlKCkge1xuICByZXR1cm4geyBvZmZzZXQ6IHRoaXMub2Zmc2V0LCByZXBvcnRlcjogUmVwb3J0ZXIucHJvdG90eXBlLnNhdmUuY2FsbCh0aGlzKSB9O1xufTtcblxuRGVjb2RlckJ1ZmZlci5wcm90b3R5cGUucmVzdG9yZSA9IGZ1bmN0aW9uIHJlc3RvcmUoc2F2ZSkge1xuICAvLyBSZXR1cm4gc2tpcHBlZCBkYXRhXG4gIHZhciByZXMgPSBuZXcgRGVjb2RlckJ1ZmZlcih0aGlzLmJhc2UpO1xuICByZXMub2Zmc2V0ID0gc2F2ZS5vZmZzZXQ7XG4gIHJlcy5sZW5ndGggPSB0aGlzLm9mZnNldDtcblxuICB0aGlzLm9mZnNldCA9IHNhdmUub2Zmc2V0O1xuICBSZXBvcnRlci5wcm90b3R5cGUucmVzdG9yZS5jYWxsKHRoaXMsIHNhdmUucmVwb3J0ZXIpO1xuXG4gIHJldHVybiByZXM7XG59O1xuXG5EZWNvZGVyQnVmZmVyLnByb3RvdHlwZS5pc0VtcHR5ID0gZnVuY3Rpb24gaXNFbXB0eSgpIHtcbiAgcmV0dXJuIHRoaXMub2Zmc2V0ID09PSB0aGlzLmxlbmd0aDtcbn07XG5cbkRlY29kZXJCdWZmZXIucHJvdG90eXBlLnJlYWRVSW50OCA9IGZ1bmN0aW9uIHJlYWRVSW50OChmYWlsKSB7XG4gIGlmICh0aGlzLm9mZnNldCArIDEgPD0gdGhpcy5sZW5ndGgpXG4gICAgcmV0dXJuIHRoaXMuYmFzZS5yZWFkVUludDgodGhpcy5vZmZzZXQrKywgdHJ1ZSk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5lcnJvcihmYWlsIHx8ICdEZWNvZGVyQnVmZmVyIG92ZXJydW4nKTtcbn1cblxuRGVjb2RlckJ1ZmZlci5wcm90b3R5cGUuc2tpcCA9IGZ1bmN0aW9uIHNraXAoYnl0ZXMsIGZhaWwpIHtcbiAgaWYgKCEodGhpcy5vZmZzZXQgKyBieXRlcyA8PSB0aGlzLmxlbmd0aCkpXG4gICAgcmV0dXJuIHRoaXMuZXJyb3IoZmFpbCB8fCAnRGVjb2RlckJ1ZmZlciBvdmVycnVuJyk7XG5cbiAgdmFyIHJlcyA9IG5ldyBEZWNvZGVyQnVmZmVyKHRoaXMuYmFzZSk7XG5cbiAgLy8gU2hhcmUgcmVwb3J0ZXIgc3RhdGVcbiAgcmVzLl9yZXBvcnRlclN0YXRlID0gdGhpcy5fcmVwb3J0ZXJTdGF0ZTtcblxuICByZXMub2Zmc2V0ID0gdGhpcy5vZmZzZXQ7XG4gIHJlcy5sZW5ndGggPSB0aGlzLm9mZnNldCArIGJ5dGVzO1xuICB0aGlzLm9mZnNldCArPSBieXRlcztcbiAgcmV0dXJuIHJlcztcbn1cblxuRGVjb2RlckJ1ZmZlci5wcm90b3R5cGUucmF3ID0gZnVuY3Rpb24gcmF3KHNhdmUpIHtcbiAgcmV0dXJuIHRoaXMuYmFzZS5zbGljZShzYXZlID8gc2F2ZS5vZmZzZXQgOiB0aGlzLm9mZnNldCwgdGhpcy5sZW5ndGgpO1xufVxuXG5mdW5jdGlvbiBFbmNvZGVyQnVmZmVyKHZhbHVlLCByZXBvcnRlcikge1xuICBpZiAoQXJyYXkuaXNBcnJheSh2YWx1ZSkpIHtcbiAgICB0aGlzLmxlbmd0aCA9IDA7XG4gICAgdGhpcy52YWx1ZSA9IHZhbHVlLm1hcChmdW5jdGlvbihpdGVtKSB7XG4gICAgICBpZiAoIShpdGVtIGluc3RhbmNlb2YgRW5jb2RlckJ1ZmZlcikpXG4gICAgICAgIGl0ZW0gPSBuZXcgRW5jb2RlckJ1ZmZlcihpdGVtLCByZXBvcnRlcik7XG4gICAgICB0aGlzLmxlbmd0aCArPSBpdGVtLmxlbmd0aDtcbiAgICAgIHJldHVybiBpdGVtO1xuICAgIH0sIHRoaXMpO1xuICB9IGVsc2UgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ251bWJlcicpIHtcbiAgICBpZiAoISgwIDw9IHZhbHVlICYmIHZhbHVlIDw9IDB4ZmYpKVxuICAgICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdub24tYnl0ZSBFbmNvZGVyQnVmZmVyIHZhbHVlJyk7XG4gICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgIHRoaXMubGVuZ3RoID0gMTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnKSB7XG4gICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgIHRoaXMubGVuZ3RoID0gQnVmZmVyLmJ5dGVMZW5ndGgodmFsdWUpO1xuICB9IGVsc2UgaWYgKEJ1ZmZlci5pc0J1ZmZlcih2YWx1ZSkpIHtcbiAgICB0aGlzLnZhbHVlID0gdmFsdWU7XG4gICAgdGhpcy5sZW5ndGggPSB2YWx1ZS5sZW5ndGg7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdVbnN1cHBvcnRlZCB0eXBlOiAnICsgdHlwZW9mIHZhbHVlKTtcbiAgfVxufVxuZXhwb3J0cy5FbmNvZGVyQnVmZmVyID0gRW5jb2RlckJ1ZmZlcjtcblxuRW5jb2RlckJ1ZmZlci5wcm90b3R5cGUuam9pbiA9IGZ1bmN0aW9uIGpvaW4ob3V0LCBvZmZzZXQpIHtcbiAgaWYgKCFvdXQpXG4gICAgb3V0ID0gbmV3IEJ1ZmZlcih0aGlzLmxlbmd0aCk7XG4gIGlmICghb2Zmc2V0KVxuICAgIG9mZnNldCA9IDA7XG5cbiAgaWYgKHRoaXMubGVuZ3RoID09PSAwKVxuICAgIHJldHVybiBvdXQ7XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkodGhpcy52YWx1ZSkpIHtcbiAgICB0aGlzLnZhbHVlLmZvckVhY2goZnVuY3Rpb24oaXRlbSkge1xuICAgICAgaXRlbS5qb2luKG91dCwgb2Zmc2V0KTtcbiAgICAgIG9mZnNldCArPSBpdGVtLmxlbmd0aDtcbiAgICB9KTtcbiAgfSBlbHNlIHtcbiAgICBpZiAodHlwZW9mIHRoaXMudmFsdWUgPT09ICdudW1iZXInKVxuICAgICAgb3V0W29mZnNldF0gPSB0aGlzLnZhbHVlO1xuICAgIGVsc2UgaWYgKHR5cGVvZiB0aGlzLnZhbHVlID09PSAnc3RyaW5nJylcbiAgICAgIG91dC53cml0ZSh0aGlzLnZhbHVlLCBvZmZzZXQpO1xuICAgIGVsc2UgaWYgKEJ1ZmZlci5pc0J1ZmZlcih0aGlzLnZhbHVlKSlcbiAgICAgIHRoaXMudmFsdWUuY29weShvdXQsIG9mZnNldCk7XG4gICAgb2Zmc2V0ICs9IHRoaXMubGVuZ3RoO1xuICB9XG5cbiAgcmV0dXJuIG91dDtcbn07XG4iLCJ2YXIgYmFzZSA9IGV4cG9ydHM7XG5cbmJhc2UuUmVwb3J0ZXIgPSByZXF1aXJlKCcuL3JlcG9ydGVyJykuUmVwb3J0ZXI7XG5iYXNlLkRlY29kZXJCdWZmZXIgPSByZXF1aXJlKCcuL2J1ZmZlcicpLkRlY29kZXJCdWZmZXI7XG5iYXNlLkVuY29kZXJCdWZmZXIgPSByZXF1aXJlKCcuL2J1ZmZlcicpLkVuY29kZXJCdWZmZXI7XG5iYXNlLk5vZGUgPSByZXF1aXJlKCcuL25vZGUnKTtcbiIsInZhciBSZXBvcnRlciA9IHJlcXVpcmUoJy4uL2Jhc2UnKS5SZXBvcnRlcjtcbnZhciBFbmNvZGVyQnVmZmVyID0gcmVxdWlyZSgnLi4vYmFzZScpLkVuY29kZXJCdWZmZXI7XG52YXIgRGVjb2RlckJ1ZmZlciA9IHJlcXVpcmUoJy4uL2Jhc2UnKS5EZWNvZGVyQnVmZmVyO1xudmFyIGFzc2VydCA9IHJlcXVpcmUoJ21pbmltYWxpc3RpYy1hc3NlcnQnKTtcblxuLy8gU3VwcG9ydGVkIHRhZ3NcbnZhciB0YWdzID0gW1xuICAnc2VxJywgJ3NlcW9mJywgJ3NldCcsICdzZXRvZicsICdvYmppZCcsICdib29sJyxcbiAgJ2dlbnRpbWUnLCAndXRjdGltZScsICdudWxsXycsICdlbnVtJywgJ2ludCcsXG4gICdiaXRzdHInLCAnYm1wc3RyJywgJ2NoYXJzdHInLCAnZ2Vuc3RyJywgJ2dyYXBoc3RyJywgJ2lhNXN0cicsICdpc282NDZzdHInLFxuICAnbnVtc3RyJywgJ29jdHN0cicsICdwcmludHN0cicsICd0NjFzdHInLCAndW5pc3RyJywgJ3V0ZjhzdHInLCAndmlkZW9zdHInXG5dO1xuXG4vLyBQdWJsaWMgbWV0aG9kcyBsaXN0XG52YXIgbWV0aG9kcyA9IFtcbiAgJ2tleScsICdvYmonLCAndXNlJywgJ29wdGlvbmFsJywgJ2V4cGxpY2l0JywgJ2ltcGxpY2l0JywgJ2RlZicsICdjaG9pY2UnLFxuICAnYW55JywgJ2NvbnRhaW5zJ1xuXS5jb25jYXQodGFncyk7XG5cbi8vIE92ZXJyaWRlZCBtZXRob2RzIGxpc3RcbnZhciBvdmVycmlkZWQgPSBbXG4gICdfcGVla1RhZycsICdfZGVjb2RlVGFnJywgJ191c2UnLFxuICAnX2RlY29kZVN0cicsICdfZGVjb2RlT2JqaWQnLCAnX2RlY29kZVRpbWUnLFxuICAnX2RlY29kZU51bGwnLCAnX2RlY29kZUludCcsICdfZGVjb2RlQm9vbCcsICdfZGVjb2RlTGlzdCcsXG5cbiAgJ19lbmNvZGVDb21wb3NpdGUnLCAnX2VuY29kZVN0cicsICdfZW5jb2RlT2JqaWQnLCAnX2VuY29kZVRpbWUnLFxuICAnX2VuY29kZU51bGwnLCAnX2VuY29kZUludCcsICdfZW5jb2RlQm9vbCdcbl07XG5cbmZ1bmN0aW9uIE5vZGUoZW5jLCBwYXJlbnQpIHtcbiAgdmFyIHN0YXRlID0ge307XG4gIHRoaXMuX2Jhc2VTdGF0ZSA9IHN0YXRlO1xuXG4gIHN0YXRlLmVuYyA9IGVuYztcblxuICBzdGF0ZS5wYXJlbnQgPSBwYXJlbnQgfHwgbnVsbDtcbiAgc3RhdGUuY2hpbGRyZW4gPSBudWxsO1xuXG4gIC8vIFN0YXRlXG4gIHN0YXRlLnRhZyA9IG51bGw7XG4gIHN0YXRlLmFyZ3MgPSBudWxsO1xuICBzdGF0ZS5yZXZlcnNlQXJncyA9IG51bGw7XG4gIHN0YXRlLmNob2ljZSA9IG51bGw7XG4gIHN0YXRlLm9wdGlvbmFsID0gZmFsc2U7XG4gIHN0YXRlLmFueSA9IGZhbHNlO1xuICBzdGF0ZS5vYmogPSBmYWxzZTtcbiAgc3RhdGUudXNlID0gbnVsbDtcbiAgc3RhdGUudXNlRGVjb2RlciA9IG51bGw7XG4gIHN0YXRlLmtleSA9IG51bGw7XG4gIHN0YXRlWydkZWZhdWx0J10gPSBudWxsO1xuICBzdGF0ZS5leHBsaWNpdCA9IG51bGw7XG4gIHN0YXRlLmltcGxpY2l0ID0gbnVsbDtcbiAgc3RhdGUuY29udGFpbnMgPSBudWxsO1xuXG4gIC8vIFNob3VsZCBjcmVhdGUgbmV3IGluc3RhbmNlIG9uIGVhY2ggbWV0aG9kXG4gIGlmICghc3RhdGUucGFyZW50KSB7XG4gICAgc3RhdGUuY2hpbGRyZW4gPSBbXTtcbiAgICB0aGlzLl93cmFwKCk7XG4gIH1cbn1cbm1vZHVsZS5leHBvcnRzID0gTm9kZTtcblxudmFyIHN0YXRlUHJvcHMgPSBbXG4gICdlbmMnLCAncGFyZW50JywgJ2NoaWxkcmVuJywgJ3RhZycsICdhcmdzJywgJ3JldmVyc2VBcmdzJywgJ2Nob2ljZScsXG4gICdvcHRpb25hbCcsICdhbnknLCAnb2JqJywgJ3VzZScsICdhbHRlcmVkVXNlJywgJ2tleScsICdkZWZhdWx0JywgJ2V4cGxpY2l0JyxcbiAgJ2ltcGxpY2l0J1xuXTtcblxuTm9kZS5wcm90b3R5cGUuY2xvbmUgPSBmdW5jdGlvbiBjbG9uZSgpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICB2YXIgY3N0YXRlID0ge307XG4gIHN0YXRlUHJvcHMuZm9yRWFjaChmdW5jdGlvbihwcm9wKSB7XG4gICAgY3N0YXRlW3Byb3BdID0gc3RhdGVbcHJvcF07XG4gIH0pO1xuICB2YXIgcmVzID0gbmV3IHRoaXMuY29uc3RydWN0b3IoY3N0YXRlLnBhcmVudCk7XG4gIHJlcy5fYmFzZVN0YXRlID0gY3N0YXRlO1xuICByZXR1cm4gcmVzO1xufTtcblxuTm9kZS5wcm90b3R5cGUuX3dyYXAgPSBmdW5jdGlvbiB3cmFwKCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG4gIG1ldGhvZHMuZm9yRWFjaChmdW5jdGlvbihtZXRob2QpIHtcbiAgICB0aGlzW21ldGhvZF0gPSBmdW5jdGlvbiBfd3JhcHBlZE1ldGhvZCgpIHtcbiAgICAgIHZhciBjbG9uZSA9IG5ldyB0aGlzLmNvbnN0cnVjdG9yKHRoaXMpO1xuICAgICAgc3RhdGUuY2hpbGRyZW4ucHVzaChjbG9uZSk7XG4gICAgICByZXR1cm4gY2xvbmVbbWV0aG9kXS5hcHBseShjbG9uZSwgYXJndW1lbnRzKTtcbiAgICB9O1xuICB9LCB0aGlzKTtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9pbml0ID0gZnVuY3Rpb24gaW5pdChib2R5KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGUucGFyZW50ID09PSBudWxsKTtcbiAgYm9keS5jYWxsKHRoaXMpO1xuXG4gIC8vIEZpbHRlciBjaGlsZHJlblxuICBzdGF0ZS5jaGlsZHJlbiA9IHN0YXRlLmNoaWxkcmVuLmZpbHRlcihmdW5jdGlvbihjaGlsZCkge1xuICAgIHJldHVybiBjaGlsZC5fYmFzZVN0YXRlLnBhcmVudCA9PT0gdGhpcztcbiAgfSwgdGhpcyk7XG4gIGFzc2VydC5lcXVhbChzdGF0ZS5jaGlsZHJlbi5sZW5ndGgsIDEsICdSb290IG5vZGUgY2FuIGhhdmUgb25seSBvbmUgY2hpbGQnKTtcbn07XG5cbk5vZGUucHJvdG90eXBlLl91c2VBcmdzID0gZnVuY3Rpb24gdXNlQXJncyhhcmdzKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICAvLyBGaWx0ZXIgY2hpbGRyZW4gYW5kIGFyZ3NcbiAgdmFyIGNoaWxkcmVuID0gYXJncy5maWx0ZXIoZnVuY3Rpb24oYXJnKSB7XG4gICAgcmV0dXJuIGFyZyBpbnN0YW5jZW9mIHRoaXMuY29uc3RydWN0b3I7XG4gIH0sIHRoaXMpO1xuICBhcmdzID0gYXJncy5maWx0ZXIoZnVuY3Rpb24oYXJnKSB7XG4gICAgcmV0dXJuICEoYXJnIGluc3RhbmNlb2YgdGhpcy5jb25zdHJ1Y3Rvcik7XG4gIH0sIHRoaXMpO1xuXG4gIGlmIChjaGlsZHJlbi5sZW5ndGggIT09IDApIHtcbiAgICBhc3NlcnQoc3RhdGUuY2hpbGRyZW4gPT09IG51bGwpO1xuICAgIHN0YXRlLmNoaWxkcmVuID0gY2hpbGRyZW47XG5cbiAgICAvLyBSZXBsYWNlIHBhcmVudCB0byBtYWludGFpbiBiYWNrd2FyZCBsaW5rXG4gICAgY2hpbGRyZW4uZm9yRWFjaChmdW5jdGlvbihjaGlsZCkge1xuICAgICAgY2hpbGQuX2Jhc2VTdGF0ZS5wYXJlbnQgPSB0aGlzO1xuICAgIH0sIHRoaXMpO1xuICB9XG4gIGlmIChhcmdzLmxlbmd0aCAhPT0gMCkge1xuICAgIGFzc2VydChzdGF0ZS5hcmdzID09PSBudWxsKTtcbiAgICBzdGF0ZS5hcmdzID0gYXJncztcbiAgICBzdGF0ZS5yZXZlcnNlQXJncyA9IGFyZ3MubWFwKGZ1bmN0aW9uKGFyZykge1xuICAgICAgaWYgKHR5cGVvZiBhcmcgIT09ICdvYmplY3QnIHx8IGFyZy5jb25zdHJ1Y3RvciAhPT0gT2JqZWN0KVxuICAgICAgICByZXR1cm4gYXJnO1xuXG4gICAgICB2YXIgcmVzID0ge307XG4gICAgICBPYmplY3Qua2V5cyhhcmcpLmZvckVhY2goZnVuY3Rpb24oa2V5KSB7XG4gICAgICAgIGlmIChrZXkgPT0gKGtleSB8IDApKVxuICAgICAgICAgIGtleSB8PSAwO1xuICAgICAgICB2YXIgdmFsdWUgPSBhcmdba2V5XTtcbiAgICAgICAgcmVzW3ZhbHVlXSA9IGtleTtcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlcztcbiAgICB9KTtcbiAgfVxufTtcblxuLy9cbi8vIE92ZXJyaWRlZCBtZXRob2RzXG4vL1xuXG5vdmVycmlkZWQuZm9yRWFjaChmdW5jdGlvbihtZXRob2QpIHtcbiAgTm9kZS5wcm90b3R5cGVbbWV0aG9kXSA9IGZ1bmN0aW9uIF9vdmVycmlkZWQoKSB7XG4gICAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICAgIHRocm93IG5ldyBFcnJvcihtZXRob2QgKyAnIG5vdCBpbXBsZW1lbnRlZCBmb3IgZW5jb2Rpbmc6ICcgKyBzdGF0ZS5lbmMpO1xuICB9O1xufSk7XG5cbi8vXG4vLyBQdWJsaWMgbWV0aG9kc1xuLy9cblxudGFncy5mb3JFYWNoKGZ1bmN0aW9uKHRhZykge1xuICBOb2RlLnByb3RvdHlwZVt0YWddID0gZnVuY3Rpb24gX3RhZ01ldGhvZCgpIHtcbiAgICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG4gICAgdmFyIGFyZ3MgPSBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChhcmd1bWVudHMpO1xuXG4gICAgYXNzZXJ0KHN0YXRlLnRhZyA9PT0gbnVsbCk7XG4gICAgc3RhdGUudGFnID0gdGFnO1xuXG4gICAgdGhpcy5fdXNlQXJncyhhcmdzKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9O1xufSk7XG5cbk5vZGUucHJvdG90eXBlLnVzZSA9IGZ1bmN0aW9uIHVzZShpdGVtKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGUudXNlID09PSBudWxsKTtcbiAgc3RhdGUudXNlID0gaXRlbTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLm9wdGlvbmFsID0gZnVuY3Rpb24gb3B0aW9uYWwoKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBzdGF0ZS5vcHRpb25hbCA9IHRydWU7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5kZWYgPSBmdW5jdGlvbiBkZWYodmFsKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGVbJ2RlZmF1bHQnXSA9PT0gbnVsbCk7XG4gIHN0YXRlWydkZWZhdWx0J10gPSB2YWw7XG4gIHN0YXRlLm9wdGlvbmFsID0gdHJ1ZTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLmV4cGxpY2l0ID0gZnVuY3Rpb24gZXhwbGljaXQobnVtKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGUuZXhwbGljaXQgPT09IG51bGwgJiYgc3RhdGUuaW1wbGljaXQgPT09IG51bGwpO1xuICBzdGF0ZS5leHBsaWNpdCA9IG51bTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLmltcGxpY2l0ID0gZnVuY3Rpb24gaW1wbGljaXQobnVtKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBhc3NlcnQoc3RhdGUuZXhwbGljaXQgPT09IG51bGwgJiYgc3RhdGUuaW1wbGljaXQgPT09IG51bGwpO1xuICBzdGF0ZS5pbXBsaWNpdCA9IG51bTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLm9iaiA9IGZ1bmN0aW9uIG9iaigpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICB2YXIgYXJncyA9IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3VtZW50cyk7XG5cbiAgc3RhdGUub2JqID0gdHJ1ZTtcblxuICBpZiAoYXJncy5sZW5ndGggIT09IDApXG4gICAgdGhpcy5fdXNlQXJncyhhcmdzKTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLmtleSA9IGZ1bmN0aW9uIGtleShuZXdLZXkpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gIGFzc2VydChzdGF0ZS5rZXkgPT09IG51bGwpO1xuICBzdGF0ZS5rZXkgPSBuZXdLZXk7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5hbnkgPSBmdW5jdGlvbiBhbnkoKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBzdGF0ZS5hbnkgPSB0cnVlO1xuXG4gIHJldHVybiB0aGlzO1xufTtcblxuTm9kZS5wcm90b3R5cGUuY2hvaWNlID0gZnVuY3Rpb24gY2hvaWNlKG9iaikge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLmNob2ljZSA9PT0gbnVsbCk7XG4gIHN0YXRlLmNob2ljZSA9IG9iajtcbiAgdGhpcy5fdXNlQXJncyhPYmplY3Qua2V5cyhvYmopLm1hcChmdW5jdGlvbihrZXkpIHtcbiAgICByZXR1cm4gb2JqW2tleV07XG4gIH0pKTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbk5vZGUucHJvdG90eXBlLmNvbnRhaW5zID0gZnVuY3Rpb24gY29udGFpbnMoaXRlbSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgYXNzZXJ0KHN0YXRlLnVzZSA9PT0gbnVsbCk7XG4gIHN0YXRlLmNvbnRhaW5zID0gaXRlbTtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8vXG4vLyBEZWNvZGluZ1xuLy9cblxuTm9kZS5wcm90b3R5cGUuX2RlY29kZSA9IGZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgLy8gRGVjb2RlIHJvb3Qgbm9kZVxuICBpZiAoc3RhdGUucGFyZW50ID09PSBudWxsKVxuICAgIHJldHVybiBpbnB1dC53cmFwUmVzdWx0KHN0YXRlLmNoaWxkcmVuWzBdLl9kZWNvZGUoaW5wdXQpKTtcblxuICB2YXIgcmVzdWx0ID0gc3RhdGVbJ2RlZmF1bHQnXTtcbiAgdmFyIHByZXNlbnQgPSB0cnVlO1xuXG4gIHZhciBwcmV2S2V5O1xuICBpZiAoc3RhdGUua2V5ICE9PSBudWxsKVxuICAgIHByZXZLZXkgPSBpbnB1dC5lbnRlcktleShzdGF0ZS5rZXkpO1xuXG4gIC8vIENoZWNrIGlmIHRhZyBpcyB0aGVyZVxuICBpZiAoc3RhdGUub3B0aW9uYWwpIHtcbiAgICB2YXIgdGFnID0gbnVsbDtcbiAgICBpZiAoc3RhdGUuZXhwbGljaXQgIT09IG51bGwpXG4gICAgICB0YWcgPSBzdGF0ZS5leHBsaWNpdDtcbiAgICBlbHNlIGlmIChzdGF0ZS5pbXBsaWNpdCAhPT0gbnVsbClcbiAgICAgIHRhZyA9IHN0YXRlLmltcGxpY2l0O1xuICAgIGVsc2UgaWYgKHN0YXRlLnRhZyAhPT0gbnVsbClcbiAgICAgIHRhZyA9IHN0YXRlLnRhZztcblxuICAgIGlmICh0YWcgPT09IG51bGwgJiYgIXN0YXRlLmFueSkge1xuICAgICAgLy8gVHJpYWwgYW5kIEVycm9yXG4gICAgICB2YXIgc2F2ZSA9IGlucHV0LnNhdmUoKTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGlmIChzdGF0ZS5jaG9pY2UgPT09IG51bGwpXG4gICAgICAgICAgdGhpcy5fZGVjb2RlR2VuZXJpYyhzdGF0ZS50YWcsIGlucHV0KTtcbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRoaXMuX2RlY29kZUNob2ljZShpbnB1dCk7XG4gICAgICAgIHByZXNlbnQgPSB0cnVlO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBwcmVzZW50ID0gZmFsc2U7XG4gICAgICB9XG4gICAgICBpbnB1dC5yZXN0b3JlKHNhdmUpO1xuICAgIH0gZWxzZSB7XG4gICAgICBwcmVzZW50ID0gdGhpcy5fcGVla1RhZyhpbnB1dCwgdGFnLCBzdGF0ZS5hbnkpO1xuXG4gICAgICBpZiAoaW5wdXQuaXNFcnJvcihwcmVzZW50KSlcbiAgICAgICAgcmV0dXJuIHByZXNlbnQ7XG4gICAgfVxuICB9XG5cbiAgLy8gUHVzaCBvYmplY3Qgb24gc3RhY2tcbiAgdmFyIHByZXZPYmo7XG4gIGlmIChzdGF0ZS5vYmogJiYgcHJlc2VudClcbiAgICBwcmV2T2JqID0gaW5wdXQuZW50ZXJPYmplY3QoKTtcblxuICBpZiAocHJlc2VudCkge1xuICAgIC8vIFVud3JhcCBleHBsaWNpdCB2YWx1ZXNcbiAgICBpZiAoc3RhdGUuZXhwbGljaXQgIT09IG51bGwpIHtcbiAgICAgIHZhciBleHBsaWNpdCA9IHRoaXMuX2RlY29kZVRhZyhpbnB1dCwgc3RhdGUuZXhwbGljaXQpO1xuICAgICAgaWYgKGlucHV0LmlzRXJyb3IoZXhwbGljaXQpKVxuICAgICAgICByZXR1cm4gZXhwbGljaXQ7XG4gICAgICBpbnB1dCA9IGV4cGxpY2l0O1xuICAgIH1cblxuICAgIC8vIFVud3JhcCBpbXBsaWNpdCBhbmQgbm9ybWFsIHZhbHVlc1xuICAgIGlmIChzdGF0ZS51c2UgPT09IG51bGwgJiYgc3RhdGUuY2hvaWNlID09PSBudWxsKSB7XG4gICAgICBpZiAoc3RhdGUuYW55KVxuICAgICAgICB2YXIgc2F2ZSA9IGlucHV0LnNhdmUoKTtcbiAgICAgIHZhciBib2R5ID0gdGhpcy5fZGVjb2RlVGFnKFxuICAgICAgICBpbnB1dCxcbiAgICAgICAgc3RhdGUuaW1wbGljaXQgIT09IG51bGwgPyBzdGF0ZS5pbXBsaWNpdCA6IHN0YXRlLnRhZyxcbiAgICAgICAgc3RhdGUuYW55XG4gICAgICApO1xuICAgICAgaWYgKGlucHV0LmlzRXJyb3IoYm9keSkpXG4gICAgICAgIHJldHVybiBib2R5O1xuXG4gICAgICBpZiAoc3RhdGUuYW55KVxuICAgICAgICByZXN1bHQgPSBpbnB1dC5yYXcoc2F2ZSk7XG4gICAgICBlbHNlXG4gICAgICAgIGlucHV0ID0gYm9keTtcbiAgICB9XG5cbiAgICAvLyBTZWxlY3QgcHJvcGVyIG1ldGhvZCBmb3IgdGFnXG4gICAgaWYgKHN0YXRlLmFueSlcbiAgICAgIHJlc3VsdCA9IHJlc3VsdDtcbiAgICBlbHNlIGlmIChzdGF0ZS5jaG9pY2UgPT09IG51bGwpXG4gICAgICByZXN1bHQgPSB0aGlzLl9kZWNvZGVHZW5lcmljKHN0YXRlLnRhZywgaW5wdXQpO1xuICAgIGVsc2VcbiAgICAgIHJlc3VsdCA9IHRoaXMuX2RlY29kZUNob2ljZShpbnB1dCk7XG5cbiAgICBpZiAoaW5wdXQuaXNFcnJvcihyZXN1bHQpKVxuICAgICAgcmV0dXJuIHJlc3VsdDtcblxuICAgIC8vIERlY29kZSBjaGlsZHJlblxuICAgIGlmICghc3RhdGUuYW55ICYmIHN0YXRlLmNob2ljZSA9PT0gbnVsbCAmJiBzdGF0ZS5jaGlsZHJlbiAhPT0gbnVsbCkge1xuICAgICAgc3RhdGUuY2hpbGRyZW4uZm9yRWFjaChmdW5jdGlvbiBkZWNvZGVDaGlsZHJlbihjaGlsZCkge1xuICAgICAgICAvLyBOT1RFOiBXZSBhcmUgaWdub3JpbmcgZXJyb3JzIGhlcmUsIHRvIGxldCBwYXJzZXIgY29udGludWUgd2l0aCBvdGhlclxuICAgICAgICAvLyBwYXJ0cyBvZiBlbmNvZGVkIGRhdGFcbiAgICAgICAgY2hpbGQuX2RlY29kZShpbnB1dCk7XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBEZWNvZGUgY29udGFpbmVkL2VuY29kZWQgYnkgc2NoZW1hLCBvbmx5IGluIGJpdCBvciBvY3RldCBzdHJpbmdzXG4gICAgaWYgKHN0YXRlLmNvbnRhaW5zICYmIChzdGF0ZS50YWcgPT09ICdvY3RzdHInIHx8IHN0YXRlLnRhZyA9PT0gJ2JpdHN0cicpKSB7XG4gICAgICB2YXIgZGF0YSA9IG5ldyBEZWNvZGVyQnVmZmVyKHJlc3VsdCk7XG4gICAgICByZXN1bHQgPSB0aGlzLl9nZXRVc2Uoc3RhdGUuY29udGFpbnMsIGlucHV0Ll9yZXBvcnRlclN0YXRlLm9iaikuX2RlY29kZShkYXRhKTtcbiAgICB9XG4gIH1cblxuICAvLyBQb3Agb2JqZWN0XG4gIGlmIChzdGF0ZS5vYmogJiYgcHJlc2VudClcbiAgICByZXN1bHQgPSBpbnB1dC5sZWF2ZU9iamVjdChwcmV2T2JqKTtcblxuICAvLyBTZXQga2V5XG4gIGlmIChzdGF0ZS5rZXkgIT09IG51bGwgJiYgKHJlc3VsdCAhPT0gbnVsbCB8fCBwcmVzZW50ID09PSB0cnVlKSlcbiAgICBpbnB1dC5sZWF2ZUtleShwcmV2S2V5LCBzdGF0ZS5rZXksIHJlc3VsdCk7XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9kZWNvZGVHZW5lcmljID0gZnVuY3Rpb24gZGVjb2RlR2VuZXJpYyh0YWcsIGlucHV0KSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX2Jhc2VTdGF0ZTtcblxuICBpZiAodGFnID09PSAnc2VxJyB8fCB0YWcgPT09ICdzZXQnKVxuICAgIHJldHVybiBudWxsO1xuICBpZiAodGFnID09PSAnc2Vxb2YnIHx8IHRhZyA9PT0gJ3NldG9mJylcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlTGlzdChpbnB1dCwgdGFnLCBzdGF0ZS5hcmdzWzBdKTtcbiAgZWxzZSBpZiAoL3N0ciQvLnRlc3QodGFnKSlcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlU3RyKGlucHV0LCB0YWcpO1xuICBlbHNlIGlmICh0YWcgPT09ICdvYmppZCcgJiYgc3RhdGUuYXJncylcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlT2JqaWQoaW5wdXQsIHN0YXRlLmFyZ3NbMF0sIHN0YXRlLmFyZ3NbMV0pO1xuICBlbHNlIGlmICh0YWcgPT09ICdvYmppZCcpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZU9iamlkKGlucHV0LCBudWxsLCBudWxsKTtcbiAgZWxzZSBpZiAodGFnID09PSAnZ2VudGltZScgfHwgdGFnID09PSAndXRjdGltZScpXG4gICAgcmV0dXJuIHRoaXMuX2RlY29kZVRpbWUoaW5wdXQsIHRhZyk7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ251bGxfJylcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlTnVsbChpbnB1dCk7XG4gIGVsc2UgaWYgKHRhZyA9PT0gJ2Jvb2wnKVxuICAgIHJldHVybiB0aGlzLl9kZWNvZGVCb29sKGlucHV0KTtcbiAgZWxzZSBpZiAodGFnID09PSAnaW50JyB8fCB0YWcgPT09ICdlbnVtJylcbiAgICByZXR1cm4gdGhpcy5fZGVjb2RlSW50KGlucHV0LCBzdGF0ZS5hcmdzICYmIHN0YXRlLmFyZ3NbMF0pO1xuICBlbHNlIGlmIChzdGF0ZS51c2UgIT09IG51bGwpXG4gICAgcmV0dXJuIHRoaXMuX2dldFVzZShzdGF0ZS51c2UsIGlucHV0Ll9yZXBvcnRlclN0YXRlLm9iaikuX2RlY29kZShpbnB1dCk7XG4gIGVsc2VcbiAgICByZXR1cm4gaW5wdXQuZXJyb3IoJ3Vua25vd24gdGFnOiAnICsgdGFnKTtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9nZXRVc2UgPSBmdW5jdGlvbiBfZ2V0VXNlKGVudGl0eSwgb2JqKSB7XG5cbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICAvLyBDcmVhdGUgYWx0ZXJlZCB1c2UgZGVjb2RlciBpZiBpbXBsaWNpdCBpcyBzZXRcbiAgc3RhdGUudXNlRGVjb2RlciA9IHRoaXMuX3VzZShlbnRpdHksIG9iaik7XG4gIGFzc2VydChzdGF0ZS51c2VEZWNvZGVyLl9iYXNlU3RhdGUucGFyZW50ID09PSBudWxsKTtcbiAgc3RhdGUudXNlRGVjb2RlciA9IHN0YXRlLnVzZURlY29kZXIuX2Jhc2VTdGF0ZS5jaGlsZHJlblswXTtcbiAgaWYgKHN0YXRlLmltcGxpY2l0ICE9PSBzdGF0ZS51c2VEZWNvZGVyLl9iYXNlU3RhdGUuaW1wbGljaXQpIHtcbiAgICBzdGF0ZS51c2VEZWNvZGVyID0gc3RhdGUudXNlRGVjb2Rlci5jbG9uZSgpO1xuICAgIHN0YXRlLnVzZURlY29kZXIuX2Jhc2VTdGF0ZS5pbXBsaWNpdCA9IHN0YXRlLmltcGxpY2l0O1xuICB9XG4gIHJldHVybiBzdGF0ZS51c2VEZWNvZGVyO1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2RlY29kZUNob2ljZSA9IGZ1bmN0aW9uIGRlY29kZUNob2ljZShpbnB1dCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG4gIHZhciByZXN1bHQgPSBudWxsO1xuICB2YXIgbWF0Y2ggPSBmYWxzZTtcblxuICBPYmplY3Qua2V5cyhzdGF0ZS5jaG9pY2UpLnNvbWUoZnVuY3Rpb24oa2V5KSB7XG4gICAgdmFyIHNhdmUgPSBpbnB1dC5zYXZlKCk7XG4gICAgdmFyIG5vZGUgPSBzdGF0ZS5jaG9pY2Vba2V5XTtcbiAgICB0cnkge1xuICAgICAgdmFyIHZhbHVlID0gbm9kZS5fZGVjb2RlKGlucHV0KTtcbiAgICAgIGlmIChpbnB1dC5pc0Vycm9yKHZhbHVlKSlcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuXG4gICAgICByZXN1bHQgPSB7IHR5cGU6IGtleSwgdmFsdWU6IHZhbHVlIH07XG4gICAgICBtYXRjaCA9IHRydWU7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgaW5wdXQucmVzdG9yZShzYXZlKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH0sIHRoaXMpO1xuXG4gIGlmICghbWF0Y2gpXG4gICAgcmV0dXJuIGlucHV0LmVycm9yKCdDaG9pY2Ugbm90IG1hdGNoZWQnKTtcblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuLy9cbi8vIEVuY29kaW5nXG4vL1xuXG5Ob2RlLnByb3RvdHlwZS5fY3JlYXRlRW5jb2RlckJ1ZmZlciA9IGZ1bmN0aW9uIGNyZWF0ZUVuY29kZXJCdWZmZXIoZGF0YSkge1xuICByZXR1cm4gbmV3IEVuY29kZXJCdWZmZXIoZGF0YSwgdGhpcy5yZXBvcnRlcik7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fZW5jb2RlID0gZnVuY3Rpb24gZW5jb2RlKGRhdGEsIHJlcG9ydGVyLCBwYXJlbnQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICBpZiAoc3RhdGVbJ2RlZmF1bHQnXSAhPT0gbnVsbCAmJiBzdGF0ZVsnZGVmYXVsdCddID09PSBkYXRhKVxuICAgIHJldHVybjtcblxuICB2YXIgcmVzdWx0ID0gdGhpcy5fZW5jb2RlVmFsdWUoZGF0YSwgcmVwb3J0ZXIsIHBhcmVudCk7XG4gIGlmIChyZXN1bHQgPT09IHVuZGVmaW5lZClcbiAgICByZXR1cm47XG5cbiAgaWYgKHRoaXMuX3NraXBEZWZhdWx0KHJlc3VsdCwgcmVwb3J0ZXIsIHBhcmVudCkpXG4gICAgcmV0dXJuO1xuXG4gIHJldHVybiByZXN1bHQ7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fZW5jb2RlVmFsdWUgPSBmdW5jdGlvbiBlbmNvZGUoZGF0YSwgcmVwb3J0ZXIsIHBhcmVudCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgLy8gRGVjb2RlIHJvb3Qgbm9kZVxuICBpZiAoc3RhdGUucGFyZW50ID09PSBudWxsKVxuICAgIHJldHVybiBzdGF0ZS5jaGlsZHJlblswXS5fZW5jb2RlKGRhdGEsIHJlcG9ydGVyIHx8IG5ldyBSZXBvcnRlcigpKTtcblxuICB2YXIgcmVzdWx0ID0gbnVsbDtcblxuICAvLyBTZXQgcmVwb3J0ZXIgdG8gc2hhcmUgaXQgd2l0aCBhIGNoaWxkIGNsYXNzXG4gIHRoaXMucmVwb3J0ZXIgPSByZXBvcnRlcjtcblxuICAvLyBDaGVjayBpZiBkYXRhIGlzIHRoZXJlXG4gIGlmIChzdGF0ZS5vcHRpb25hbCAmJiBkYXRhID09PSB1bmRlZmluZWQpIHtcbiAgICBpZiAoc3RhdGVbJ2RlZmF1bHQnXSAhPT0gbnVsbClcbiAgICAgIGRhdGEgPSBzdGF0ZVsnZGVmYXVsdCddXG4gICAgZWxzZVxuICAgICAgcmV0dXJuO1xuICB9XG5cbiAgLy8gRW5jb2RlIGNoaWxkcmVuIGZpcnN0XG4gIHZhciBjb250ZW50ID0gbnVsbDtcbiAgdmFyIHByaW1pdGl2ZSA9IGZhbHNlO1xuICBpZiAoc3RhdGUuYW55KSB7XG4gICAgLy8gQW55dGhpbmcgdGhhdCB3YXMgZ2l2ZW4gaXMgdHJhbnNsYXRlZCB0byBidWZmZXJcbiAgICByZXN1bHQgPSB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKGRhdGEpO1xuICB9IGVsc2UgaWYgKHN0YXRlLmNob2ljZSkge1xuICAgIHJlc3VsdCA9IHRoaXMuX2VuY29kZUNob2ljZShkYXRhLCByZXBvcnRlcik7XG4gIH0gZWxzZSBpZiAoc3RhdGUuY29udGFpbnMpIHtcbiAgICBjb250ZW50ID0gdGhpcy5fZ2V0VXNlKHN0YXRlLmNvbnRhaW5zLCBwYXJlbnQpLl9lbmNvZGUoZGF0YSwgcmVwb3J0ZXIpO1xuICAgIHByaW1pdGl2ZSA9IHRydWU7XG4gIH0gZWxzZSBpZiAoc3RhdGUuY2hpbGRyZW4pIHtcbiAgICBjb250ZW50ID0gc3RhdGUuY2hpbGRyZW4ubWFwKGZ1bmN0aW9uKGNoaWxkKSB7XG4gICAgICBpZiAoY2hpbGQuX2Jhc2VTdGF0ZS50YWcgPT09ICdudWxsXycpXG4gICAgICAgIHJldHVybiBjaGlsZC5fZW5jb2RlKG51bGwsIHJlcG9ydGVyLCBkYXRhKTtcblxuICAgICAgaWYgKGNoaWxkLl9iYXNlU3RhdGUua2V5ID09PSBudWxsKVxuICAgICAgICByZXR1cm4gcmVwb3J0ZXIuZXJyb3IoJ0NoaWxkIHNob3VsZCBoYXZlIGEga2V5Jyk7XG4gICAgICB2YXIgcHJldktleSA9IHJlcG9ydGVyLmVudGVyS2V5KGNoaWxkLl9iYXNlU3RhdGUua2V5KTtcblxuICAgICAgaWYgKHR5cGVvZiBkYXRhICE9PSAnb2JqZWN0JylcbiAgICAgICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdDaGlsZCBleHBlY3RlZCwgYnV0IGlucHV0IGlzIG5vdCBvYmplY3QnKTtcblxuICAgICAgdmFyIHJlcyA9IGNoaWxkLl9lbmNvZGUoZGF0YVtjaGlsZC5fYmFzZVN0YXRlLmtleV0sIHJlcG9ydGVyLCBkYXRhKTtcbiAgICAgIHJlcG9ydGVyLmxlYXZlS2V5KHByZXZLZXkpO1xuXG4gICAgICByZXR1cm4gcmVzO1xuICAgIH0sIHRoaXMpLmZpbHRlcihmdW5jdGlvbihjaGlsZCkge1xuICAgICAgcmV0dXJuIGNoaWxkO1xuICAgIH0pO1xuICAgIGNvbnRlbnQgPSB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKGNvbnRlbnQpO1xuICB9IGVsc2Uge1xuICAgIGlmIChzdGF0ZS50YWcgPT09ICdzZXFvZicgfHwgc3RhdGUudGFnID09PSAnc2V0b2YnKSB7XG4gICAgICAvLyBUT0RPKGluZHV0bnkpOiB0aGlzIHNob3VsZCBiZSB0aHJvd24gb24gRFNMIGxldmVsXG4gICAgICBpZiAoIShzdGF0ZS5hcmdzICYmIHN0YXRlLmFyZ3MubGVuZ3RoID09PSAxKSlcbiAgICAgICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdUb28gbWFueSBhcmdzIGZvciA6ICcgKyBzdGF0ZS50YWcpO1xuXG4gICAgICBpZiAoIUFycmF5LmlzQXJyYXkoZGF0YSkpXG4gICAgICAgIHJldHVybiByZXBvcnRlci5lcnJvcignc2Vxb2Yvc2V0b2YsIGJ1dCBkYXRhIGlzIG5vdCBBcnJheScpO1xuXG4gICAgICB2YXIgY2hpbGQgPSB0aGlzLmNsb25lKCk7XG4gICAgICBjaGlsZC5fYmFzZVN0YXRlLmltcGxpY2l0ID0gbnVsbDtcbiAgICAgIGNvbnRlbnQgPSB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKGRhdGEubWFwKGZ1bmN0aW9uKGl0ZW0pIHtcbiAgICAgICAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuXG4gICAgICAgIHJldHVybiB0aGlzLl9nZXRVc2Uoc3RhdGUuYXJnc1swXSwgZGF0YSkuX2VuY29kZShpdGVtLCByZXBvcnRlcik7XG4gICAgICB9LCBjaGlsZCkpO1xuICAgIH0gZWxzZSBpZiAoc3RhdGUudXNlICE9PSBudWxsKSB7XG4gICAgICByZXN1bHQgPSB0aGlzLl9nZXRVc2Uoc3RhdGUudXNlLCBwYXJlbnQpLl9lbmNvZGUoZGF0YSwgcmVwb3J0ZXIpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb250ZW50ID0gdGhpcy5fZW5jb2RlUHJpbWl0aXZlKHN0YXRlLnRhZywgZGF0YSk7XG4gICAgICBwcmltaXRpdmUgPSB0cnVlO1xuICAgIH1cbiAgfVxuXG4gIC8vIEVuY29kZSBkYXRhIGl0c2VsZlxuICB2YXIgcmVzdWx0O1xuICBpZiAoIXN0YXRlLmFueSAmJiBzdGF0ZS5jaG9pY2UgPT09IG51bGwpIHtcbiAgICB2YXIgdGFnID0gc3RhdGUuaW1wbGljaXQgIT09IG51bGwgPyBzdGF0ZS5pbXBsaWNpdCA6IHN0YXRlLnRhZztcbiAgICB2YXIgY2xzID0gc3RhdGUuaW1wbGljaXQgPT09IG51bGwgPyAndW5pdmVyc2FsJyA6ICdjb250ZXh0JztcblxuICAgIGlmICh0YWcgPT09IG51bGwpIHtcbiAgICAgIGlmIChzdGF0ZS51c2UgPT09IG51bGwpXG4gICAgICAgIHJlcG9ydGVyLmVycm9yKCdUYWcgY291bGQgYmUgb21taXRlZCBvbmx5IGZvciAudXNlKCknKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKHN0YXRlLnVzZSA9PT0gbnVsbClcbiAgICAgICAgcmVzdWx0ID0gdGhpcy5fZW5jb2RlQ29tcG9zaXRlKHRhZywgcHJpbWl0aXZlLCBjbHMsIGNvbnRlbnQpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFdyYXAgaW4gZXhwbGljaXRcbiAgaWYgKHN0YXRlLmV4cGxpY2l0ICE9PSBudWxsKVxuICAgIHJlc3VsdCA9IHRoaXMuX2VuY29kZUNvbXBvc2l0ZShzdGF0ZS5leHBsaWNpdCwgZmFsc2UsICdjb250ZXh0JywgcmVzdWx0KTtcblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2VuY29kZUNob2ljZSA9IGZ1bmN0aW9uIGVuY29kZUNob2ljZShkYXRhLCByZXBvcnRlcikge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgdmFyIG5vZGUgPSBzdGF0ZS5jaG9pY2VbZGF0YS50eXBlXTtcbiAgaWYgKCFub2RlKSB7XG4gICAgYXNzZXJ0KFxuICAgICAgICBmYWxzZSxcbiAgICAgICAgZGF0YS50eXBlICsgJyBub3QgZm91bmQgaW4gJyArXG4gICAgICAgICAgICBKU09OLnN0cmluZ2lmeShPYmplY3Qua2V5cyhzdGF0ZS5jaG9pY2UpKSk7XG4gIH1cbiAgcmV0dXJuIG5vZGUuX2VuY29kZShkYXRhLnZhbHVlLCByZXBvcnRlcik7XG59O1xuXG5Ob2RlLnByb3RvdHlwZS5fZW5jb2RlUHJpbWl0aXZlID0gZnVuY3Rpb24gZW5jb2RlUHJpbWl0aXZlKHRhZywgZGF0YSkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9iYXNlU3RhdGU7XG5cbiAgaWYgKC9zdHIkLy50ZXN0KHRhZykpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZVN0cihkYXRhLCB0YWcpO1xuICBlbHNlIGlmICh0YWcgPT09ICdvYmppZCcgJiYgc3RhdGUuYXJncylcbiAgICByZXR1cm4gdGhpcy5fZW5jb2RlT2JqaWQoZGF0YSwgc3RhdGUucmV2ZXJzZUFyZ3NbMF0sIHN0YXRlLmFyZ3NbMV0pO1xuICBlbHNlIGlmICh0YWcgPT09ICdvYmppZCcpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZU9iamlkKGRhdGEsIG51bGwsIG51bGwpO1xuICBlbHNlIGlmICh0YWcgPT09ICdnZW50aW1lJyB8fCB0YWcgPT09ICd1dGN0aW1lJylcbiAgICByZXR1cm4gdGhpcy5fZW5jb2RlVGltZShkYXRhLCB0YWcpO1xuICBlbHNlIGlmICh0YWcgPT09ICdudWxsXycpXG4gICAgcmV0dXJuIHRoaXMuX2VuY29kZU51bGwoKTtcbiAgZWxzZSBpZiAodGFnID09PSAnaW50JyB8fCB0YWcgPT09ICdlbnVtJylcbiAgICByZXR1cm4gdGhpcy5fZW5jb2RlSW50KGRhdGEsIHN0YXRlLmFyZ3MgJiYgc3RhdGUucmV2ZXJzZUFyZ3NbMF0pO1xuICBlbHNlIGlmICh0YWcgPT09ICdib29sJylcbiAgICByZXR1cm4gdGhpcy5fZW5jb2RlQm9vbChkYXRhKTtcbiAgZWxzZVxuICAgIHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQgdGFnOiAnICsgdGFnKTtcbn07XG5cbk5vZGUucHJvdG90eXBlLl9pc051bXN0ciA9IGZ1bmN0aW9uIGlzTnVtc3RyKHN0cikge1xuICByZXR1cm4gL15bMC05IF0qJC8udGVzdChzdHIpO1xufTtcblxuTm9kZS5wcm90b3R5cGUuX2lzUHJpbnRzdHIgPSBmdW5jdGlvbiBpc1ByaW50c3RyKHN0cikge1xuICByZXR1cm4gL15bQS1aYS16MC05ICdcXChcXClcXCssXFwtXFwuXFwvOj1cXD9dKiQvLnRlc3Qoc3RyKTtcbn07XG4iLCJ2YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG5mdW5jdGlvbiBSZXBvcnRlcihvcHRpb25zKSB7XG4gIHRoaXMuX3JlcG9ydGVyU3RhdGUgPSB7XG4gICAgb2JqOiBudWxsLFxuICAgIHBhdGg6IFtdLFxuICAgIG9wdGlvbnM6IG9wdGlvbnMgfHwge30sXG4gICAgZXJyb3JzOiBbXVxuICB9O1xufVxuZXhwb3J0cy5SZXBvcnRlciA9IFJlcG9ydGVyO1xuXG5SZXBvcnRlci5wcm90b3R5cGUuaXNFcnJvciA9IGZ1bmN0aW9uIGlzRXJyb3Iob2JqKSB7XG4gIHJldHVybiBvYmogaW5zdGFuY2VvZiBSZXBvcnRlckVycm9yO1xufTtcblxuUmVwb3J0ZXIucHJvdG90eXBlLnNhdmUgPSBmdW5jdGlvbiBzYXZlKCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9yZXBvcnRlclN0YXRlO1xuXG4gIHJldHVybiB7IG9iajogc3RhdGUub2JqLCBwYXRoTGVuOiBzdGF0ZS5wYXRoLmxlbmd0aCB9O1xufTtcblxuUmVwb3J0ZXIucHJvdG90eXBlLnJlc3RvcmUgPSBmdW5jdGlvbiByZXN0b3JlKGRhdGEpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fcmVwb3J0ZXJTdGF0ZTtcblxuICBzdGF0ZS5vYmogPSBkYXRhLm9iajtcbiAgc3RhdGUucGF0aCA9IHN0YXRlLnBhdGguc2xpY2UoMCwgZGF0YS5wYXRoTGVuKTtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5lbnRlcktleSA9IGZ1bmN0aW9uIGVudGVyS2V5KGtleSkge1xuICByZXR1cm4gdGhpcy5fcmVwb3J0ZXJTdGF0ZS5wYXRoLnB1c2goa2V5KTtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5sZWF2ZUtleSA9IGZ1bmN0aW9uIGxlYXZlS2V5KGluZGV4LCBrZXksIHZhbHVlKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgc3RhdGUucGF0aCA9IHN0YXRlLnBhdGguc2xpY2UoMCwgaW5kZXggLSAxKTtcbiAgaWYgKHN0YXRlLm9iaiAhPT0gbnVsbClcbiAgICBzdGF0ZS5vYmpba2V5XSA9IHZhbHVlO1xufTtcblxuUmVwb3J0ZXIucHJvdG90eXBlLmVudGVyT2JqZWN0ID0gZnVuY3Rpb24gZW50ZXJPYmplY3QoKSB7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgdmFyIHByZXYgPSBzdGF0ZS5vYmo7XG4gIHN0YXRlLm9iaiA9IHt9O1xuICByZXR1cm4gcHJldjtcbn07XG5cblJlcG9ydGVyLnByb3RvdHlwZS5sZWF2ZU9iamVjdCA9IGZ1bmN0aW9uIGxlYXZlT2JqZWN0KHByZXYpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fcmVwb3J0ZXJTdGF0ZTtcblxuICB2YXIgbm93ID0gc3RhdGUub2JqO1xuICBzdGF0ZS5vYmogPSBwcmV2O1xuICByZXR1cm4gbm93O1xufTtcblxuUmVwb3J0ZXIucHJvdG90eXBlLmVycm9yID0gZnVuY3Rpb24gZXJyb3IobXNnKSB7XG4gIHZhciBlcnI7XG4gIHZhciBzdGF0ZSA9IHRoaXMuX3JlcG9ydGVyU3RhdGU7XG5cbiAgdmFyIGluaGVyaXRlZCA9IG1zZyBpbnN0YW5jZW9mIFJlcG9ydGVyRXJyb3I7XG4gIGlmIChpbmhlcml0ZWQpIHtcbiAgICBlcnIgPSBtc2c7XG4gIH0gZWxzZSB7XG4gICAgZXJyID0gbmV3IFJlcG9ydGVyRXJyb3Ioc3RhdGUucGF0aC5tYXAoZnVuY3Rpb24oZWxlbSkge1xuICAgICAgcmV0dXJuICdbJyArIEpTT04uc3RyaW5naWZ5KGVsZW0pICsgJ10nO1xuICAgIH0pLmpvaW4oJycpLCBtc2cubWVzc2FnZSB8fCBtc2csIG1zZy5zdGFjayk7XG4gIH1cblxuICBpZiAoIXN0YXRlLm9wdGlvbnMucGFydGlhbClcbiAgICB0aHJvdyBlcnI7XG5cbiAgaWYgKCFpbmhlcml0ZWQpXG4gICAgc3RhdGUuZXJyb3JzLnB1c2goZXJyKTtcblxuICByZXR1cm4gZXJyO1xufTtcblxuUmVwb3J0ZXIucHJvdG90eXBlLndyYXBSZXN1bHQgPSBmdW5jdGlvbiB3cmFwUmVzdWx0KHJlc3VsdCkge1xuICB2YXIgc3RhdGUgPSB0aGlzLl9yZXBvcnRlclN0YXRlO1xuICBpZiAoIXN0YXRlLm9wdGlvbnMucGFydGlhbClcbiAgICByZXR1cm4gcmVzdWx0O1xuXG4gIHJldHVybiB7XG4gICAgcmVzdWx0OiB0aGlzLmlzRXJyb3IocmVzdWx0KSA/IG51bGwgOiByZXN1bHQsXG4gICAgZXJyb3JzOiBzdGF0ZS5lcnJvcnNcbiAgfTtcbn07XG5cbmZ1bmN0aW9uIFJlcG9ydGVyRXJyb3IocGF0aCwgbXNnKSB7XG4gIHRoaXMucGF0aCA9IHBhdGg7XG4gIHRoaXMucmV0aHJvdyhtc2cpO1xufTtcbmluaGVyaXRzKFJlcG9ydGVyRXJyb3IsIEVycm9yKTtcblxuUmVwb3J0ZXJFcnJvci5wcm90b3R5cGUucmV0aHJvdyA9IGZ1bmN0aW9uIHJldGhyb3cobXNnKSB7XG4gIHRoaXMubWVzc2FnZSA9IG1zZyArICcgYXQ6ICcgKyAodGhpcy5wYXRoIHx8ICcoc2hhbGxvdyknKTtcbiAgRXJyb3IuY2FwdHVyZVN0YWNrVHJhY2UodGhpcywgUmVwb3J0ZXJFcnJvcik7XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuIiwidmFyIGNvbnN0YW50cyA9IHJlcXVpcmUoJy4uL2NvbnN0YW50cycpO1xuXG5leHBvcnRzLnRhZ0NsYXNzID0ge1xuICAwOiAndW5pdmVyc2FsJyxcbiAgMTogJ2FwcGxpY2F0aW9uJyxcbiAgMjogJ2NvbnRleHQnLFxuICAzOiAncHJpdmF0ZSdcbn07XG5leHBvcnRzLnRhZ0NsYXNzQnlOYW1lID0gY29uc3RhbnRzLl9yZXZlcnNlKGV4cG9ydHMudGFnQ2xhc3MpO1xuXG5leHBvcnRzLnRhZyA9IHtcbiAgMHgwMDogJ2VuZCcsXG4gIDB4MDE6ICdib29sJyxcbiAgMHgwMjogJ2ludCcsXG4gIDB4MDM6ICdiaXRzdHInLFxuICAweDA0OiAnb2N0c3RyJyxcbiAgMHgwNTogJ251bGxfJyxcbiAgMHgwNjogJ29iamlkJyxcbiAgMHgwNzogJ29iakRlc2MnLFxuICAweDA4OiAnZXh0ZXJuYWwnLFxuICAweDA5OiAncmVhbCcsXG4gIDB4MGE6ICdlbnVtJyxcbiAgMHgwYjogJ2VtYmVkJyxcbiAgMHgwYzogJ3V0ZjhzdHInLFxuICAweDBkOiAncmVsYXRpdmVPaWQnLFxuICAweDEwOiAnc2VxJyxcbiAgMHgxMTogJ3NldCcsXG4gIDB4MTI6ICdudW1zdHInLFxuICAweDEzOiAncHJpbnRzdHInLFxuICAweDE0OiAndDYxc3RyJyxcbiAgMHgxNTogJ3ZpZGVvc3RyJyxcbiAgMHgxNjogJ2lhNXN0cicsXG4gIDB4MTc6ICd1dGN0aW1lJyxcbiAgMHgxODogJ2dlbnRpbWUnLFxuICAweDE5OiAnZ3JhcGhzdHInLFxuICAweDFhOiAnaXNvNjQ2c3RyJyxcbiAgMHgxYjogJ2dlbnN0cicsXG4gIDB4MWM6ICd1bmlzdHInLFxuICAweDFkOiAnY2hhcnN0cicsXG4gIDB4MWU6ICdibXBzdHInXG59O1xuZXhwb3J0cy50YWdCeU5hbWUgPSBjb25zdGFudHMuX3JldmVyc2UoZXhwb3J0cy50YWcpO1xuIiwidmFyIGNvbnN0YW50cyA9IGV4cG9ydHM7XG5cbi8vIEhlbHBlclxuY29uc3RhbnRzLl9yZXZlcnNlID0gZnVuY3Rpb24gcmV2ZXJzZShtYXApIHtcbiAgdmFyIHJlcyA9IHt9O1xuXG4gIE9iamVjdC5rZXlzKG1hcCkuZm9yRWFjaChmdW5jdGlvbihrZXkpIHtcbiAgICAvLyBDb252ZXJ0IGtleSB0byBpbnRlZ2VyIGlmIGl0IGlzIHN0cmluZ2lmaWVkXG4gICAgaWYgKChrZXkgfCAwKSA9PSBrZXkpXG4gICAgICBrZXkgPSBrZXkgfCAwO1xuXG4gICAgdmFyIHZhbHVlID0gbWFwW2tleV07XG4gICAgcmVzW3ZhbHVlXSA9IGtleTtcbiAgfSk7XG5cbiAgcmV0dXJuIHJlcztcbn07XG5cbmNvbnN0YW50cy5kZXIgPSByZXF1aXJlKCcuL2RlcicpO1xuIiwidmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcblxudmFyIGFzbjEgPSByZXF1aXJlKCcuLi8uLi9hc24xJyk7XG52YXIgYmFzZSA9IGFzbjEuYmFzZTtcbnZhciBiaWdudW0gPSBhc24xLmJpZ251bTtcblxuLy8gSW1wb3J0IERFUiBjb25zdGFudHNcbnZhciBkZXIgPSBhc24xLmNvbnN0YW50cy5kZXI7XG5cbmZ1bmN0aW9uIERFUkRlY29kZXIoZW50aXR5KSB7XG4gIHRoaXMuZW5jID0gJ2Rlcic7XG4gIHRoaXMubmFtZSA9IGVudGl0eS5uYW1lO1xuICB0aGlzLmVudGl0eSA9IGVudGl0eTtcblxuICAvLyBDb25zdHJ1Y3QgYmFzZSB0cmVlXG4gIHRoaXMudHJlZSA9IG5ldyBERVJOb2RlKCk7XG4gIHRoaXMudHJlZS5faW5pdChlbnRpdHkuYm9keSk7XG59O1xubW9kdWxlLmV4cG9ydHMgPSBERVJEZWNvZGVyO1xuXG5ERVJEZWNvZGVyLnByb3RvdHlwZS5kZWNvZGUgPSBmdW5jdGlvbiBkZWNvZGUoZGF0YSwgb3B0aW9ucykge1xuICBpZiAoIShkYXRhIGluc3RhbmNlb2YgYmFzZS5EZWNvZGVyQnVmZmVyKSlcbiAgICBkYXRhID0gbmV3IGJhc2UuRGVjb2RlckJ1ZmZlcihkYXRhLCBvcHRpb25zKTtcblxuICByZXR1cm4gdGhpcy50cmVlLl9kZWNvZGUoZGF0YSwgb3B0aW9ucyk7XG59O1xuXG4vLyBUcmVlIG1ldGhvZHNcblxuZnVuY3Rpb24gREVSTm9kZShwYXJlbnQpIHtcbiAgYmFzZS5Ob2RlLmNhbGwodGhpcywgJ2RlcicsIHBhcmVudCk7XG59XG5pbmhlcml0cyhERVJOb2RlLCBiYXNlLk5vZGUpO1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fcGVla1RhZyA9IGZ1bmN0aW9uIHBlZWtUYWcoYnVmZmVyLCB0YWcsIGFueSkge1xuICBpZiAoYnVmZmVyLmlzRW1wdHkoKSlcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgdmFyIHN0YXRlID0gYnVmZmVyLnNhdmUoKTtcbiAgdmFyIGRlY29kZWRUYWcgPSBkZXJEZWNvZGVUYWcoYnVmZmVyLCAnRmFpbGVkIHRvIHBlZWsgdGFnOiBcIicgKyB0YWcgKyAnXCInKTtcbiAgaWYgKGJ1ZmZlci5pc0Vycm9yKGRlY29kZWRUYWcpKVxuICAgIHJldHVybiBkZWNvZGVkVGFnO1xuXG4gIGJ1ZmZlci5yZXN0b3JlKHN0YXRlKTtcblxuICByZXR1cm4gZGVjb2RlZFRhZy50YWcgPT09IHRhZyB8fCBkZWNvZGVkVGFnLnRhZ1N0ciA9PT0gdGFnIHx8XG4gICAgKGRlY29kZWRUYWcudGFnU3RyICsgJ29mJykgPT09IHRhZyB8fCBhbnk7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZGVjb2RlVGFnID0gZnVuY3Rpb24gZGVjb2RlVGFnKGJ1ZmZlciwgdGFnLCBhbnkpIHtcbiAgdmFyIGRlY29kZWRUYWcgPSBkZXJEZWNvZGVUYWcoYnVmZmVyLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnRmFpbGVkIHRvIGRlY29kZSB0YWcgb2YgXCInICsgdGFnICsgJ1wiJyk7XG4gIGlmIChidWZmZXIuaXNFcnJvcihkZWNvZGVkVGFnKSlcbiAgICByZXR1cm4gZGVjb2RlZFRhZztcblxuICB2YXIgbGVuID0gZGVyRGVjb2RlTGVuKGJ1ZmZlcixcbiAgICAgICAgICAgICAgICAgICAgICAgICBkZWNvZGVkVGFnLnByaW1pdGl2ZSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAnRmFpbGVkIHRvIGdldCBsZW5ndGggb2YgXCInICsgdGFnICsgJ1wiJyk7XG5cbiAgLy8gRmFpbHVyZVxuICBpZiAoYnVmZmVyLmlzRXJyb3IobGVuKSlcbiAgICByZXR1cm4gbGVuO1xuXG4gIGlmICghYW55ICYmXG4gICAgICBkZWNvZGVkVGFnLnRhZyAhPT0gdGFnICYmXG4gICAgICBkZWNvZGVkVGFnLnRhZ1N0ciAhPT0gdGFnICYmXG4gICAgICBkZWNvZGVkVGFnLnRhZ1N0ciArICdvZicgIT09IHRhZykge1xuICAgIHJldHVybiBidWZmZXIuZXJyb3IoJ0ZhaWxlZCB0byBtYXRjaCB0YWc6IFwiJyArIHRhZyArICdcIicpO1xuICB9XG5cbiAgaWYgKGRlY29kZWRUYWcucHJpbWl0aXZlIHx8IGxlbiAhPT0gbnVsbClcbiAgICByZXR1cm4gYnVmZmVyLnNraXAobGVuLCAnRmFpbGVkIHRvIG1hdGNoIGJvZHkgb2Y6IFwiJyArIHRhZyArICdcIicpO1xuXG4gIC8vIEluZGVmaW5pdGUgbGVuZ3RoLi4uIGZpbmQgRU5EIHRhZ1xuICB2YXIgc3RhdGUgPSBidWZmZXIuc2F2ZSgpO1xuICB2YXIgcmVzID0gdGhpcy5fc2tpcFVudGlsRW5kKFxuICAgICAgYnVmZmVyLFxuICAgICAgJ0ZhaWxlZCB0byBza2lwIGluZGVmaW5pdGUgbGVuZ3RoIGJvZHk6IFwiJyArIHRoaXMudGFnICsgJ1wiJyk7XG4gIGlmIChidWZmZXIuaXNFcnJvcihyZXMpKVxuICAgIHJldHVybiByZXM7XG5cbiAgbGVuID0gYnVmZmVyLm9mZnNldCAtIHN0YXRlLm9mZnNldDtcbiAgYnVmZmVyLnJlc3RvcmUoc3RhdGUpO1xuICByZXR1cm4gYnVmZmVyLnNraXAobGVuLCAnRmFpbGVkIHRvIG1hdGNoIGJvZHkgb2Y6IFwiJyArIHRhZyArICdcIicpO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX3NraXBVbnRpbEVuZCA9IGZ1bmN0aW9uIHNraXBVbnRpbEVuZChidWZmZXIsIGZhaWwpIHtcbiAgd2hpbGUgKHRydWUpIHtcbiAgICB2YXIgdGFnID0gZGVyRGVjb2RlVGFnKGJ1ZmZlciwgZmFpbCk7XG4gICAgaWYgKGJ1ZmZlci5pc0Vycm9yKHRhZykpXG4gICAgICByZXR1cm4gdGFnO1xuICAgIHZhciBsZW4gPSBkZXJEZWNvZGVMZW4oYnVmZmVyLCB0YWcucHJpbWl0aXZlLCBmYWlsKTtcbiAgICBpZiAoYnVmZmVyLmlzRXJyb3IobGVuKSlcbiAgICAgIHJldHVybiBsZW47XG5cbiAgICB2YXIgcmVzO1xuICAgIGlmICh0YWcucHJpbWl0aXZlIHx8IGxlbiAhPT0gbnVsbClcbiAgICAgIHJlcyA9IGJ1ZmZlci5za2lwKGxlbilcbiAgICBlbHNlXG4gICAgICByZXMgPSB0aGlzLl9za2lwVW50aWxFbmQoYnVmZmVyLCBmYWlsKTtcblxuICAgIC8vIEZhaWx1cmVcbiAgICBpZiAoYnVmZmVyLmlzRXJyb3IocmVzKSlcbiAgICAgIHJldHVybiByZXM7XG5cbiAgICBpZiAodGFnLnRhZ1N0ciA9PT0gJ2VuZCcpXG4gICAgICBicmVhaztcbiAgfVxufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZUxpc3QgPSBmdW5jdGlvbiBkZWNvZGVMaXN0KGJ1ZmZlciwgdGFnLCBkZWNvZGVyKSB7XG4gIHZhciByZXN1bHQgPSBbXTtcbiAgd2hpbGUgKCFidWZmZXIuaXNFbXB0eSgpKSB7XG4gICAgdmFyIHBvc3NpYmxlRW5kID0gdGhpcy5fcGVla1RhZyhidWZmZXIsICdlbmQnKTtcbiAgICBpZiAoYnVmZmVyLmlzRXJyb3IocG9zc2libGVFbmQpKVxuICAgICAgcmV0dXJuIHBvc3NpYmxlRW5kO1xuXG4gICAgdmFyIHJlcyA9IGRlY29kZXIuZGVjb2RlKGJ1ZmZlciwgJ2RlcicpO1xuICAgIGlmIChidWZmZXIuaXNFcnJvcihyZXMpICYmIHBvc3NpYmxlRW5kKVxuICAgICAgYnJlYWs7XG4gICAgcmVzdWx0LnB1c2gocmVzKTtcbiAgfVxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZVN0ciA9IGZ1bmN0aW9uIGRlY29kZVN0cihidWZmZXIsIHRhZykge1xuICBpZiAodGFnID09PSAnYml0c3RyJykge1xuICAgIHZhciB1bnVzZWQgPSBidWZmZXIucmVhZFVJbnQ4KCk7XG4gICAgaWYgKGJ1ZmZlci5pc0Vycm9yKHVudXNlZCkpXG4gICAgICByZXR1cm4gdW51c2VkO1xuICAgIHJldHVybiB7IHVudXNlZDogdW51c2VkLCBkYXRhOiBidWZmZXIucmF3KCkgfTtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdibXBzdHInKSB7XG4gICAgdmFyIHJhdyA9IGJ1ZmZlci5yYXcoKTtcbiAgICBpZiAocmF3Lmxlbmd0aCAlIDIgPT09IDEpXG4gICAgICByZXR1cm4gYnVmZmVyLmVycm9yKCdEZWNvZGluZyBvZiBzdHJpbmcgdHlwZTogYm1wc3RyIGxlbmd0aCBtaXNtYXRjaCcpO1xuXG4gICAgdmFyIHN0ciA9ICcnO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcmF3Lmxlbmd0aCAvIDI7IGkrKykge1xuICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUocmF3LnJlYWRVSW50MTZCRShpICogMikpO1xuICAgIH1cbiAgICByZXR1cm4gc3RyO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ251bXN0cicpIHtcbiAgICB2YXIgbnVtc3RyID0gYnVmZmVyLnJhdygpLnRvU3RyaW5nKCdhc2NpaScpO1xuICAgIGlmICghdGhpcy5faXNOdW1zdHIobnVtc3RyKSkge1xuICAgICAgcmV0dXJuIGJ1ZmZlci5lcnJvcignRGVjb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6ICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAnbnVtc3RyIHVuc3VwcG9ydGVkIGNoYXJhY3RlcnMnKTtcbiAgICB9XG4gICAgcmV0dXJuIG51bXN0cjtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdvY3RzdHInKSB7XG4gICAgcmV0dXJuIGJ1ZmZlci5yYXcoKTtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdwcmludHN0cicpIHtcbiAgICB2YXIgcHJpbnRzdHIgPSBidWZmZXIucmF3KCkudG9TdHJpbmcoJ2FzY2lpJyk7XG4gICAgaWYgKCF0aGlzLl9pc1ByaW50c3RyKHByaW50c3RyKSkge1xuICAgICAgcmV0dXJuIGJ1ZmZlci5lcnJvcignRGVjb2Rpbmcgb2Ygc3RyaW5nIHR5cGU6ICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAncHJpbnRzdHIgdW5zdXBwb3J0ZWQgY2hhcmFjdGVycycpO1xuICAgIH1cbiAgICByZXR1cm4gcHJpbnRzdHI7XG4gIH0gZWxzZSBpZiAoL3N0ciQvLnRlc3QodGFnKSkge1xuICAgIHJldHVybiBidWZmZXIucmF3KCkudG9TdHJpbmcoKTtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gYnVmZmVyLmVycm9yKCdEZWNvZGluZyBvZiBzdHJpbmcgdHlwZTogJyArIHRhZyArICcgdW5zdXBwb3J0ZWQnKTtcbiAgfVxufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZU9iamlkID0gZnVuY3Rpb24gZGVjb2RlT2JqaWQoYnVmZmVyLCB2YWx1ZXMsIHJlbGF0aXZlKSB7XG4gIHZhciByZXN1bHQ7XG4gIHZhciBpZGVudGlmaWVycyA9IFtdO1xuICB2YXIgaWRlbnQgPSAwO1xuICB3aGlsZSAoIWJ1ZmZlci5pc0VtcHR5KCkpIHtcbiAgICB2YXIgc3ViaWRlbnQgPSBidWZmZXIucmVhZFVJbnQ4KCk7XG4gICAgaWRlbnQgPDw9IDc7XG4gICAgaWRlbnQgfD0gc3ViaWRlbnQgJiAweDdmO1xuICAgIGlmICgoc3ViaWRlbnQgJiAweDgwKSA9PT0gMCkge1xuICAgICAgaWRlbnRpZmllcnMucHVzaChpZGVudCk7XG4gICAgICBpZGVudCA9IDA7XG4gICAgfVxuICB9XG4gIGlmIChzdWJpZGVudCAmIDB4ODApXG4gICAgaWRlbnRpZmllcnMucHVzaChpZGVudCk7XG5cbiAgdmFyIGZpcnN0ID0gKGlkZW50aWZpZXJzWzBdIC8gNDApIHwgMDtcbiAgdmFyIHNlY29uZCA9IGlkZW50aWZpZXJzWzBdICUgNDA7XG5cbiAgaWYgKHJlbGF0aXZlKVxuICAgIHJlc3VsdCA9IGlkZW50aWZpZXJzO1xuICBlbHNlXG4gICAgcmVzdWx0ID0gW2ZpcnN0LCBzZWNvbmRdLmNvbmNhdChpZGVudGlmaWVycy5zbGljZSgxKSk7XG5cbiAgaWYgKHZhbHVlcykge1xuICAgIHZhciB0bXAgPSB2YWx1ZXNbcmVzdWx0LmpvaW4oJyAnKV07XG4gICAgaWYgKHRtcCA9PT0gdW5kZWZpbmVkKVxuICAgICAgdG1wID0gdmFsdWVzW3Jlc3VsdC5qb2luKCcuJyldO1xuICAgIGlmICh0bXAgIT09IHVuZGVmaW5lZClcbiAgICAgIHJlc3VsdCA9IHRtcDtcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZGVjb2RlVGltZSA9IGZ1bmN0aW9uIGRlY29kZVRpbWUoYnVmZmVyLCB0YWcpIHtcbiAgdmFyIHN0ciA9IGJ1ZmZlci5yYXcoKS50b1N0cmluZygpO1xuICBpZiAodGFnID09PSAnZ2VudGltZScpIHtcbiAgICB2YXIgeWVhciA9IHN0ci5zbGljZSgwLCA0KSB8IDA7XG4gICAgdmFyIG1vbiA9IHN0ci5zbGljZSg0LCA2KSB8IDA7XG4gICAgdmFyIGRheSA9IHN0ci5zbGljZSg2LCA4KSB8IDA7XG4gICAgdmFyIGhvdXIgPSBzdHIuc2xpY2UoOCwgMTApIHwgMDtcbiAgICB2YXIgbWluID0gc3RyLnNsaWNlKDEwLCAxMikgfCAwO1xuICAgIHZhciBzZWMgPSBzdHIuc2xpY2UoMTIsIDE0KSB8IDA7XG4gIH0gZWxzZSBpZiAodGFnID09PSAndXRjdGltZScpIHtcbiAgICB2YXIgeWVhciA9IHN0ci5zbGljZSgwLCAyKSB8IDA7XG4gICAgdmFyIG1vbiA9IHN0ci5zbGljZSgyLCA0KSB8IDA7XG4gICAgdmFyIGRheSA9IHN0ci5zbGljZSg0LCA2KSB8IDA7XG4gICAgdmFyIGhvdXIgPSBzdHIuc2xpY2UoNiwgOCkgfCAwO1xuICAgIHZhciBtaW4gPSBzdHIuc2xpY2UoOCwgMTApIHwgMDtcbiAgICB2YXIgc2VjID0gc3RyLnNsaWNlKDEwLCAxMikgfCAwO1xuICAgIGlmICh5ZWFyIDwgNzApXG4gICAgICB5ZWFyID0gMjAwMCArIHllYXI7XG4gICAgZWxzZVxuICAgICAgeWVhciA9IDE5MDAgKyB5ZWFyO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBidWZmZXIuZXJyb3IoJ0RlY29kaW5nICcgKyB0YWcgKyAnIHRpbWUgaXMgbm90IHN1cHBvcnRlZCB5ZXQnKTtcbiAgfVxuXG4gIHJldHVybiBEYXRlLlVUQyh5ZWFyLCBtb24gLSAxLCBkYXksIGhvdXIsIG1pbiwgc2VjLCAwKTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9kZWNvZGVOdWxsID0gZnVuY3Rpb24gZGVjb2RlTnVsbChidWZmZXIpIHtcbiAgcmV0dXJuIG51bGw7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZGVjb2RlQm9vbCA9IGZ1bmN0aW9uIGRlY29kZUJvb2woYnVmZmVyKSB7XG4gIHZhciByZXMgPSBidWZmZXIucmVhZFVJbnQ4KCk7XG4gIGlmIChidWZmZXIuaXNFcnJvcihyZXMpKVxuICAgIHJldHVybiByZXM7XG4gIGVsc2VcbiAgICByZXR1cm4gcmVzICE9PSAwO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2RlY29kZUludCA9IGZ1bmN0aW9uIGRlY29kZUludChidWZmZXIsIHZhbHVlcykge1xuICAvLyBCaWdpbnQsIHJldHVybiBhcyBpdCBpcyAoYXNzdW1lIGJpZyBlbmRpYW4pXG4gIHZhciByYXcgPSBidWZmZXIucmF3KCk7XG4gIHZhciByZXMgPSBuZXcgYmlnbnVtKHJhdyk7XG5cbiAgaWYgKHZhbHVlcylcbiAgICByZXMgPSB2YWx1ZXNbcmVzLnRvU3RyaW5nKDEwKV0gfHwgcmVzO1xuXG4gIHJldHVybiByZXM7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fdXNlID0gZnVuY3Rpb24gdXNlKGVudGl0eSwgb2JqKSB7XG4gIGlmICh0eXBlb2YgZW50aXR5ID09PSAnZnVuY3Rpb24nKVxuICAgIGVudGl0eSA9IGVudGl0eShvYmopO1xuICByZXR1cm4gZW50aXR5Ll9nZXREZWNvZGVyKCdkZXInKS50cmVlO1xufTtcblxuLy8gVXRpbGl0eSBtZXRob2RzXG5cbmZ1bmN0aW9uIGRlckRlY29kZVRhZyhidWYsIGZhaWwpIHtcbiAgdmFyIHRhZyA9IGJ1Zi5yZWFkVUludDgoZmFpbCk7XG4gIGlmIChidWYuaXNFcnJvcih0YWcpKVxuICAgIHJldHVybiB0YWc7XG5cbiAgdmFyIGNscyA9IGRlci50YWdDbGFzc1t0YWcgPj4gNl07XG4gIHZhciBwcmltaXRpdmUgPSAodGFnICYgMHgyMCkgPT09IDA7XG5cbiAgLy8gTXVsdGktb2N0ZXQgdGFnIC0gbG9hZFxuICBpZiAoKHRhZyAmIDB4MWYpID09PSAweDFmKSB7XG4gICAgdmFyIG9jdCA9IHRhZztcbiAgICB0YWcgPSAwO1xuICAgIHdoaWxlICgob2N0ICYgMHg4MCkgPT09IDB4ODApIHtcbiAgICAgIG9jdCA9IGJ1Zi5yZWFkVUludDgoZmFpbCk7XG4gICAgICBpZiAoYnVmLmlzRXJyb3Iob2N0KSlcbiAgICAgICAgcmV0dXJuIG9jdDtcblxuICAgICAgdGFnIDw8PSA3O1xuICAgICAgdGFnIHw9IG9jdCAmIDB4N2Y7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIHRhZyAmPSAweDFmO1xuICB9XG4gIHZhciB0YWdTdHIgPSBkZXIudGFnW3RhZ107XG5cbiAgcmV0dXJuIHtcbiAgICBjbHM6IGNscyxcbiAgICBwcmltaXRpdmU6IHByaW1pdGl2ZSxcbiAgICB0YWc6IHRhZyxcbiAgICB0YWdTdHI6IHRhZ1N0clxuICB9O1xufVxuXG5mdW5jdGlvbiBkZXJEZWNvZGVMZW4oYnVmLCBwcmltaXRpdmUsIGZhaWwpIHtcbiAgdmFyIGxlbiA9IGJ1Zi5yZWFkVUludDgoZmFpbCk7XG4gIGlmIChidWYuaXNFcnJvcihsZW4pKVxuICAgIHJldHVybiBsZW47XG5cbiAgLy8gSW5kZWZpbml0ZSBmb3JtXG4gIGlmICghcHJpbWl0aXZlICYmIGxlbiA9PT0gMHg4MClcbiAgICByZXR1cm4gbnVsbDtcblxuICAvLyBEZWZpbml0ZSBmb3JtXG4gIGlmICgobGVuICYgMHg4MCkgPT09IDApIHtcbiAgICAvLyBTaG9ydCBmb3JtXG4gICAgcmV0dXJuIGxlbjtcbiAgfVxuXG4gIC8vIExvbmcgZm9ybVxuICB2YXIgbnVtID0gbGVuICYgMHg3ZjtcbiAgaWYgKG51bSA+PSA0KVxuICAgIHJldHVybiBidWYuZXJyb3IoJ2xlbmd0aCBvY3RlY3QgaXMgdG9vIGxvbmcnKTtcblxuICBsZW4gPSAwO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IG51bTsgaSsrKSB7XG4gICAgbGVuIDw8PSA4O1xuICAgIHZhciBqID0gYnVmLnJlYWRVSW50OChmYWlsKTtcbiAgICBpZiAoYnVmLmlzRXJyb3IoaikpXG4gICAgICByZXR1cm4gajtcbiAgICBsZW4gfD0gajtcbiAgfVxuXG4gIHJldHVybiBsZW47XG59XG4iLCJ2YXIgZGVjb2RlcnMgPSBleHBvcnRzO1xuXG5kZWNvZGVycy5kZXIgPSByZXF1aXJlKCcuL2RlcicpO1xuZGVjb2RlcnMucGVtID0gcmVxdWlyZSgnLi9wZW0nKTtcbiIsInZhciBpbmhlcml0cyA9IHJlcXVpcmUoJ2luaGVyaXRzJyk7XG52YXIgQnVmZmVyID0gcmVxdWlyZSgnYnVmZmVyJykuQnVmZmVyO1xuXG52YXIgREVSRGVjb2RlciA9IHJlcXVpcmUoJy4vZGVyJyk7XG5cbmZ1bmN0aW9uIFBFTURlY29kZXIoZW50aXR5KSB7XG4gIERFUkRlY29kZXIuY2FsbCh0aGlzLCBlbnRpdHkpO1xuICB0aGlzLmVuYyA9ICdwZW0nO1xufTtcbmluaGVyaXRzKFBFTURlY29kZXIsIERFUkRlY29kZXIpO1xubW9kdWxlLmV4cG9ydHMgPSBQRU1EZWNvZGVyO1xuXG5QRU1EZWNvZGVyLnByb3RvdHlwZS5kZWNvZGUgPSBmdW5jdGlvbiBkZWNvZGUoZGF0YSwgb3B0aW9ucykge1xuICB2YXIgbGluZXMgPSBkYXRhLnRvU3RyaW5nKCkuc3BsaXQoL1tcXHJcXG5dKy9nKTtcblxuICB2YXIgbGFiZWwgPSBvcHRpb25zLmxhYmVsLnRvVXBwZXJDYXNlKCk7XG5cbiAgdmFyIHJlID0gL14tLS0tLShCRUdJTnxFTkQpIChbXi1dKyktLS0tLSQvO1xuICB2YXIgc3RhcnQgPSAtMTtcbiAgdmFyIGVuZCA9IC0xO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIG1hdGNoID0gbGluZXNbaV0ubWF0Y2gocmUpO1xuICAgIGlmIChtYXRjaCA9PT0gbnVsbClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgaWYgKG1hdGNoWzJdICE9PSBsYWJlbClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgaWYgKHN0YXJ0ID09PSAtMSkge1xuICAgICAgaWYgKG1hdGNoWzFdICE9PSAnQkVHSU4nKVxuICAgICAgICBicmVhaztcbiAgICAgIHN0YXJ0ID0gaTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKG1hdGNoWzFdICE9PSAnRU5EJylcbiAgICAgICAgYnJlYWs7XG4gICAgICBlbmQgPSBpO1xuICAgICAgYnJlYWs7XG4gICAgfVxuICB9XG4gIGlmIChzdGFydCA9PT0gLTEgfHwgZW5kID09PSAtMSlcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1BFTSBzZWN0aW9uIG5vdCBmb3VuZCBmb3I6ICcgKyBsYWJlbCk7XG5cbiAgdmFyIGJhc2U2NCA9IGxpbmVzLnNsaWNlKHN0YXJ0ICsgMSwgZW5kKS5qb2luKCcnKTtcbiAgLy8gUmVtb3ZlIGV4Y2Vzc2l2ZSBzeW1ib2xzXG4gIGJhc2U2NC5yZXBsYWNlKC9bXmEtejAtOVxcK1xcLz1dKy9naSwgJycpO1xuXG4gIHZhciBpbnB1dCA9IG5ldyBCdWZmZXIoYmFzZTY0LCAnYmFzZTY0Jyk7XG4gIHJldHVybiBERVJEZWNvZGVyLnByb3RvdHlwZS5kZWNvZGUuY2FsbCh0aGlzLCBpbnB1dCwgb3B0aW9ucyk7XG59O1xuIiwidmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcbnZhciBCdWZmZXIgPSByZXF1aXJlKCdidWZmZXInKS5CdWZmZXI7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnLi4vLi4vYXNuMScpO1xudmFyIGJhc2UgPSBhc24xLmJhc2U7XG5cbi8vIEltcG9ydCBERVIgY29uc3RhbnRzXG52YXIgZGVyID0gYXNuMS5jb25zdGFudHMuZGVyO1xuXG5mdW5jdGlvbiBERVJFbmNvZGVyKGVudGl0eSkge1xuICB0aGlzLmVuYyA9ICdkZXInO1xuICB0aGlzLm5hbWUgPSBlbnRpdHkubmFtZTtcbiAgdGhpcy5lbnRpdHkgPSBlbnRpdHk7XG5cbiAgLy8gQ29uc3RydWN0IGJhc2UgdHJlZVxuICB0aGlzLnRyZWUgPSBuZXcgREVSTm9kZSgpO1xuICB0aGlzLnRyZWUuX2luaXQoZW50aXR5LmJvZHkpO1xufTtcbm1vZHVsZS5leHBvcnRzID0gREVSRW5jb2RlcjtcblxuREVSRW5jb2Rlci5wcm90b3R5cGUuZW5jb2RlID0gZnVuY3Rpb24gZW5jb2RlKGRhdGEsIHJlcG9ydGVyKSB7XG4gIHJldHVybiB0aGlzLnRyZWUuX2VuY29kZShkYXRhLCByZXBvcnRlcikuam9pbigpO1xufTtcblxuLy8gVHJlZSBtZXRob2RzXG5cbmZ1bmN0aW9uIERFUk5vZGUocGFyZW50KSB7XG4gIGJhc2UuTm9kZS5jYWxsKHRoaXMsICdkZXInLCBwYXJlbnQpO1xufVxuaW5oZXJpdHMoREVSTm9kZSwgYmFzZS5Ob2RlKTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZUNvbXBvc2l0ZSA9IGZ1bmN0aW9uIGVuY29kZUNvbXBvc2l0ZSh0YWcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1pdGl2ZSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xzLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb250ZW50KSB7XG4gIHZhciBlbmNvZGVkVGFnID0gZW5jb2RlVGFnKHRhZywgcHJpbWl0aXZlLCBjbHMsIHRoaXMucmVwb3J0ZXIpO1xuXG4gIC8vIFNob3J0IGZvcm1cbiAgaWYgKGNvbnRlbnQubGVuZ3RoIDwgMHg4MCkge1xuICAgIHZhciBoZWFkZXIgPSBuZXcgQnVmZmVyKDIpO1xuICAgIGhlYWRlclswXSA9IGVuY29kZWRUYWc7XG4gICAgaGVhZGVyWzFdID0gY29udGVudC5sZW5ndGg7XG4gICAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIoWyBoZWFkZXIsIGNvbnRlbnQgXSk7XG4gIH1cblxuICAvLyBMb25nIGZvcm1cbiAgLy8gQ291bnQgb2N0ZXRzIHJlcXVpcmVkIHRvIHN0b3JlIGxlbmd0aFxuICB2YXIgbGVuT2N0ZXRzID0gMTtcbiAgZm9yICh2YXIgaSA9IGNvbnRlbnQubGVuZ3RoOyBpID49IDB4MTAwOyBpID4+PSA4KVxuICAgIGxlbk9jdGV0cysrO1xuXG4gIHZhciBoZWFkZXIgPSBuZXcgQnVmZmVyKDEgKyAxICsgbGVuT2N0ZXRzKTtcbiAgaGVhZGVyWzBdID0gZW5jb2RlZFRhZztcbiAgaGVhZGVyWzFdID0gMHg4MCB8IGxlbk9jdGV0cztcblxuICBmb3IgKHZhciBpID0gMSArIGxlbk9jdGV0cywgaiA9IGNvbnRlbnQubGVuZ3RoOyBqID4gMDsgaS0tLCBqID4+PSA4KVxuICAgIGhlYWRlcltpXSA9IGogJiAweGZmO1xuXG4gIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKFsgaGVhZGVyLCBjb250ZW50IF0pO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZVN0ciA9IGZ1bmN0aW9uIGVuY29kZVN0cihzdHIsIHRhZykge1xuICBpZiAodGFnID09PSAnYml0c3RyJykge1xuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKFsgc3RyLnVudXNlZCB8IDAsIHN0ci5kYXRhIF0pO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ2JtcHN0cicpIHtcbiAgICB2YXIgYnVmID0gbmV3IEJ1ZmZlcihzdHIubGVuZ3RoICogMik7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzdHIubGVuZ3RoOyBpKyspIHtcbiAgICAgIGJ1Zi53cml0ZVVJbnQxNkJFKHN0ci5jaGFyQ29kZUF0KGkpLCBpICogMik7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKGJ1Zik7XG4gIH0gZWxzZSBpZiAodGFnID09PSAnbnVtc3RyJykge1xuICAgIGlmICghdGhpcy5faXNOdW1zdHIoc3RyKSkge1xuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ0VuY29kaW5nIG9mIHN0cmluZyB0eXBlOiBudW1zdHIgc3VwcG9ydHMgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb25seSBkaWdpdHMgYW5kIHNwYWNlJyk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKHN0cik7XG4gIH0gZWxzZSBpZiAodGFnID09PSAncHJpbnRzdHInKSB7XG4gICAgaWYgKCF0aGlzLl9pc1ByaW50c3RyKHN0cikpIHtcbiAgICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdFbmNvZGluZyBvZiBzdHJpbmcgdHlwZTogcHJpbnRzdHIgc3VwcG9ydHMgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb25seSBsYXRpbiB1cHBlciBhbmQgbG93ZXIgY2FzZSBsZXR0ZXJzLCAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdkaWdpdHMsIHNwYWNlLCBhcG9zdHJvcGhlLCBsZWZ0IGFuZCByaWd0aCAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdwYXJlbnRoZXNpcywgcGx1cyBzaWduLCBjb21tYSwgaHlwaGVuLCAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdkb3QsIHNsYXNoLCBjb2xvbiwgZXF1YWwgc2lnbiwgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAncXVlc3Rpb24gbWFyaycpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihzdHIpO1xuICB9IGVsc2UgaWYgKC9zdHIkLy50ZXN0KHRhZykpIHtcbiAgICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihzdHIpO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiB0aGlzLnJlcG9ydGVyLmVycm9yKCdFbmNvZGluZyBvZiBzdHJpbmcgdHlwZTogJyArIHRhZyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJyB1bnN1cHBvcnRlZCcpO1xuICB9XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZW5jb2RlT2JqaWQgPSBmdW5jdGlvbiBlbmNvZGVPYmppZChpZCwgdmFsdWVzLCByZWxhdGl2ZSkge1xuICBpZiAodHlwZW9mIGlkID09PSAnc3RyaW5nJykge1xuICAgIGlmICghdmFsdWVzKVxuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ3N0cmluZyBvYmppZCBnaXZlbiwgYnV0IG5vIHZhbHVlcyBtYXAgZm91bmQnKTtcbiAgICBpZiAoIXZhbHVlcy5oYXNPd25Qcm9wZXJ0eShpZCkpXG4gICAgICByZXR1cm4gdGhpcy5yZXBvcnRlci5lcnJvcignb2JqaWQgbm90IGZvdW5kIGluIHZhbHVlcyBtYXAnKTtcbiAgICBpZCA9IHZhbHVlc1tpZF0uc3BsaXQoL1tcXHNcXC5dKy9nKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGlkLmxlbmd0aDsgaSsrKVxuICAgICAgaWRbaV0gfD0gMDtcbiAgfSBlbHNlIGlmIChBcnJheS5pc0FycmF5KGlkKSkge1xuICAgIGlkID0gaWQuc2xpY2UoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGlkLmxlbmd0aDsgaSsrKVxuICAgICAgaWRbaV0gfD0gMDtcbiAgfVxuXG4gIGlmICghQXJyYXkuaXNBcnJheShpZCkpIHtcbiAgICByZXR1cm4gdGhpcy5yZXBvcnRlci5lcnJvcignb2JqaWQoKSBzaG91bGQgYmUgZWl0aGVyIGFycmF5IG9yIHN0cmluZywgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2dvdDogJyArIEpTT04uc3RyaW5naWZ5KGlkKSk7XG4gIH1cblxuICBpZiAoIXJlbGF0aXZlKSB7XG4gICAgaWYgKGlkWzFdID49IDQwKVxuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ1NlY29uZCBvYmppZCBpZGVudGlmaWVyIE9PQicpO1xuICAgIGlkLnNwbGljZSgwLCAyLCBpZFswXSAqIDQwICsgaWRbMV0pO1xuICB9XG5cbiAgLy8gQ291bnQgbnVtYmVyIG9mIG9jdGV0c1xuICB2YXIgc2l6ZSA9IDA7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgaWQubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgaWRlbnQgPSBpZFtpXTtcbiAgICBmb3IgKHNpemUrKzsgaWRlbnQgPj0gMHg4MDsgaWRlbnQgPj49IDcpXG4gICAgICBzaXplKys7XG4gIH1cblxuICB2YXIgb2JqaWQgPSBuZXcgQnVmZmVyKHNpemUpO1xuICB2YXIgb2Zmc2V0ID0gb2JqaWQubGVuZ3RoIC0gMTtcbiAgZm9yICh2YXIgaSA9IGlkLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgdmFyIGlkZW50ID0gaWRbaV07XG4gICAgb2JqaWRbb2Zmc2V0LS1dID0gaWRlbnQgJiAweDdmO1xuICAgIHdoaWxlICgoaWRlbnQgPj49IDcpID4gMClcbiAgICAgIG9iamlkW29mZnNldC0tXSA9IDB4ODAgfCAoaWRlbnQgJiAweDdmKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKG9iamlkKTtcbn07XG5cbmZ1bmN0aW9uIHR3byhudW0pIHtcbiAgaWYgKG51bSA8IDEwKVxuICAgIHJldHVybiAnMCcgKyBudW07XG4gIGVsc2VcbiAgICByZXR1cm4gbnVtO1xufVxuXG5ERVJOb2RlLnByb3RvdHlwZS5fZW5jb2RlVGltZSA9IGZ1bmN0aW9uIGVuY29kZVRpbWUodGltZSwgdGFnKSB7XG4gIHZhciBzdHI7XG4gIHZhciBkYXRlID0gbmV3IERhdGUodGltZSk7XG5cbiAgaWYgKHRhZyA9PT0gJ2dlbnRpbWUnKSB7XG4gICAgc3RyID0gW1xuICAgICAgdHdvKGRhdGUuZ2V0RnVsbFllYXIoKSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENNb250aCgpICsgMSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENEYXRlKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDSG91cnMoKSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENNaW51dGVzKCkpLFxuICAgICAgdHdvKGRhdGUuZ2V0VVRDU2Vjb25kcygpKSxcbiAgICAgICdaJ1xuICAgIF0uam9pbignJyk7XG4gIH0gZWxzZSBpZiAodGFnID09PSAndXRjdGltZScpIHtcbiAgICBzdHIgPSBbXG4gICAgICB0d28oZGF0ZS5nZXRGdWxsWWVhcigpICUgMTAwKSxcbiAgICAgIHR3byhkYXRlLmdldFVUQ01vbnRoKCkgKyAxKSxcbiAgICAgIHR3byhkYXRlLmdldFVUQ0RhdGUoKSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENIb3VycygpKSxcbiAgICAgIHR3byhkYXRlLmdldFVUQ01pbnV0ZXMoKSksXG4gICAgICB0d28oZGF0ZS5nZXRVVENTZWNvbmRzKCkpLFxuICAgICAgJ1onXG4gICAgXS5qb2luKCcnKTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnJlcG9ydGVyLmVycm9yKCdFbmNvZGluZyAnICsgdGFnICsgJyB0aW1lIGlzIG5vdCBzdXBwb3J0ZWQgeWV0Jyk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5fZW5jb2RlU3RyKHN0ciwgJ29jdHN0cicpO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZU51bGwgPSBmdW5jdGlvbiBlbmNvZGVOdWxsKCkge1xuICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcignJyk7XG59O1xuXG5ERVJOb2RlLnByb3RvdHlwZS5fZW5jb2RlSW50ID0gZnVuY3Rpb24gZW5jb2RlSW50KG51bSwgdmFsdWVzKSB7XG4gIGlmICh0eXBlb2YgbnVtID09PSAnc3RyaW5nJykge1xuICAgIGlmICghdmFsdWVzKVxuICAgICAgcmV0dXJuIHRoaXMucmVwb3J0ZXIuZXJyb3IoJ1N0cmluZyBpbnQgb3IgZW51bSBnaXZlbiwgYnV0IG5vIHZhbHVlcyBtYXAnKTtcbiAgICBpZiAoIXZhbHVlcy5oYXNPd25Qcm9wZXJ0eShudW0pKSB7XG4gICAgICByZXR1cm4gdGhpcy5yZXBvcnRlci5lcnJvcignVmFsdWVzIG1hcCBkb2VzblxcJ3QgY29udGFpbjogJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBKU09OLnN0cmluZ2lmeShudW0pKTtcbiAgICB9XG4gICAgbnVtID0gdmFsdWVzW251bV07XG4gIH1cblxuICAvLyBCaWdudW0sIGFzc3VtZSBiaWcgZW5kaWFuXG4gIGlmICh0eXBlb2YgbnVtICE9PSAnbnVtYmVyJyAmJiAhQnVmZmVyLmlzQnVmZmVyKG51bSkpIHtcbiAgICB2YXIgbnVtQXJyYXkgPSBudW0udG9BcnJheSgpO1xuICAgIGlmICghbnVtLnNpZ24gJiYgbnVtQXJyYXlbMF0gJiAweDgwKSB7XG4gICAgICBudW1BcnJheS51bnNoaWZ0KDApO1xuICAgIH1cbiAgICBudW0gPSBuZXcgQnVmZmVyKG51bUFycmF5KTtcbiAgfVxuXG4gIGlmIChCdWZmZXIuaXNCdWZmZXIobnVtKSkge1xuICAgIHZhciBzaXplID0gbnVtLmxlbmd0aDtcbiAgICBpZiAobnVtLmxlbmd0aCA9PT0gMClcbiAgICAgIHNpemUrKztcblxuICAgIHZhciBvdXQgPSBuZXcgQnVmZmVyKHNpemUpO1xuICAgIG51bS5jb3B5KG91dCk7XG4gICAgaWYgKG51bS5sZW5ndGggPT09IDApXG4gICAgICBvdXRbMF0gPSAwXG4gICAgcmV0dXJuIHRoaXMuX2NyZWF0ZUVuY29kZXJCdWZmZXIob3V0KTtcbiAgfVxuXG4gIGlmIChudW0gPCAweDgwKVxuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKG51bSk7XG5cbiAgaWYgKG51bSA8IDB4MTAwKVxuICAgIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKFswLCBudW1dKTtcblxuICB2YXIgc2l6ZSA9IDE7XG4gIGZvciAodmFyIGkgPSBudW07IGkgPj0gMHgxMDA7IGkgPj49IDgpXG4gICAgc2l6ZSsrO1xuXG4gIHZhciBvdXQgPSBuZXcgQXJyYXkoc2l6ZSk7XG4gIGZvciAodmFyIGkgPSBvdXQubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICBvdXRbaV0gPSBudW0gJiAweGZmO1xuICAgIG51bSA+Pj0gODtcbiAgfVxuICBpZihvdXRbMF0gJiAweDgwKSB7XG4gICAgb3V0LnVuc2hpZnQoMCk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5fY3JlYXRlRW5jb2RlckJ1ZmZlcihuZXcgQnVmZmVyKG91dCkpO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX2VuY29kZUJvb2wgPSBmdW5jdGlvbiBlbmNvZGVCb29sKHZhbHVlKSB7XG4gIHJldHVybiB0aGlzLl9jcmVhdGVFbmNvZGVyQnVmZmVyKHZhbHVlID8gMHhmZiA6IDApO1xufTtcblxuREVSTm9kZS5wcm90b3R5cGUuX3VzZSA9IGZ1bmN0aW9uIHVzZShlbnRpdHksIG9iaikge1xuICBpZiAodHlwZW9mIGVudGl0eSA9PT0gJ2Z1bmN0aW9uJylcbiAgICBlbnRpdHkgPSBlbnRpdHkob2JqKTtcbiAgcmV0dXJuIGVudGl0eS5fZ2V0RW5jb2RlcignZGVyJykudHJlZTtcbn07XG5cbkRFUk5vZGUucHJvdG90eXBlLl9za2lwRGVmYXVsdCA9IGZ1bmN0aW9uIHNraXBEZWZhdWx0KGRhdGFCdWZmZXIsIHJlcG9ydGVyLCBwYXJlbnQpIHtcbiAgdmFyIHN0YXRlID0gdGhpcy5fYmFzZVN0YXRlO1xuICB2YXIgaTtcbiAgaWYgKHN0YXRlWydkZWZhdWx0J10gPT09IG51bGwpXG4gICAgcmV0dXJuIGZhbHNlO1xuXG4gIHZhciBkYXRhID0gZGF0YUJ1ZmZlci5qb2luKCk7XG4gIGlmIChzdGF0ZS5kZWZhdWx0QnVmZmVyID09PSB1bmRlZmluZWQpXG4gICAgc3RhdGUuZGVmYXVsdEJ1ZmZlciA9IHRoaXMuX2VuY29kZVZhbHVlKHN0YXRlWydkZWZhdWx0J10sIHJlcG9ydGVyLCBwYXJlbnQpLmpvaW4oKTtcblxuICBpZiAoZGF0YS5sZW5ndGggIT09IHN0YXRlLmRlZmF1bHRCdWZmZXIubGVuZ3RoKVxuICAgIHJldHVybiBmYWxzZTtcblxuICBmb3IgKGk9MDsgaSA8IGRhdGEubGVuZ3RoOyBpKyspXG4gICAgaWYgKGRhdGFbaV0gIT09IHN0YXRlLmRlZmF1bHRCdWZmZXJbaV0pXG4gICAgICByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIHRydWU7XG59O1xuXG4vLyBVdGlsaXR5IG1ldGhvZHNcblxuZnVuY3Rpb24gZW5jb2RlVGFnKHRhZywgcHJpbWl0aXZlLCBjbHMsIHJlcG9ydGVyKSB7XG4gIHZhciByZXM7XG5cbiAgaWYgKHRhZyA9PT0gJ3NlcW9mJylcbiAgICB0YWcgPSAnc2VxJztcbiAgZWxzZSBpZiAodGFnID09PSAnc2V0b2YnKVxuICAgIHRhZyA9ICdzZXQnO1xuXG4gIGlmIChkZXIudGFnQnlOYW1lLmhhc093blByb3BlcnR5KHRhZykpXG4gICAgcmVzID0gZGVyLnRhZ0J5TmFtZVt0YWddO1xuICBlbHNlIGlmICh0eXBlb2YgdGFnID09PSAnbnVtYmVyJyAmJiAodGFnIHwgMCkgPT09IHRhZylcbiAgICByZXMgPSB0YWc7XG4gIGVsc2VcbiAgICByZXR1cm4gcmVwb3J0ZXIuZXJyb3IoJ1Vua25vd24gdGFnOiAnICsgdGFnKTtcblxuICBpZiAocmVzID49IDB4MWYpXG4gICAgcmV0dXJuIHJlcG9ydGVyLmVycm9yKCdNdWx0aS1vY3RldCB0YWcgZW5jb2RpbmcgdW5zdXBwb3J0ZWQnKTtcblxuICBpZiAoIXByaW1pdGl2ZSlcbiAgICByZXMgfD0gMHgyMDtcblxuICByZXMgfD0gKGRlci50YWdDbGFzc0J5TmFtZVtjbHMgfHwgJ3VuaXZlcnNhbCddIDw8IDYpO1xuXG4gIHJldHVybiByZXM7XG59XG4iLCJ2YXIgZW5jb2RlcnMgPSBleHBvcnRzO1xuXG5lbmNvZGVycy5kZXIgPSByZXF1aXJlKCcuL2RlcicpO1xuZW5jb2RlcnMucGVtID0gcmVxdWlyZSgnLi9wZW0nKTtcbiIsInZhciBpbmhlcml0cyA9IHJlcXVpcmUoJ2luaGVyaXRzJyk7XG5cbnZhciBERVJFbmNvZGVyID0gcmVxdWlyZSgnLi9kZXInKTtcblxuZnVuY3Rpb24gUEVNRW5jb2RlcihlbnRpdHkpIHtcbiAgREVSRW5jb2Rlci5jYWxsKHRoaXMsIGVudGl0eSk7XG4gIHRoaXMuZW5jID0gJ3BlbSc7XG59O1xuaW5oZXJpdHMoUEVNRW5jb2RlciwgREVSRW5jb2Rlcik7XG5tb2R1bGUuZXhwb3J0cyA9IFBFTUVuY29kZXI7XG5cblBFTUVuY29kZXIucHJvdG90eXBlLmVuY29kZSA9IGZ1bmN0aW9uIGVuY29kZShkYXRhLCBvcHRpb25zKSB7XG4gIHZhciBidWYgPSBERVJFbmNvZGVyLnByb3RvdHlwZS5lbmNvZGUuY2FsbCh0aGlzLCBkYXRhKTtcblxuICB2YXIgcCA9IGJ1Zi50b1N0cmluZygnYmFzZTY0Jyk7XG4gIHZhciBvdXQgPSBbICctLS0tLUJFR0lOICcgKyBvcHRpb25zLmxhYmVsICsgJy0tLS0tJyBdO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHAubGVuZ3RoOyBpICs9IDY0KVxuICAgIG91dC5wdXNoKHAuc2xpY2UoaSwgaSArIDY0KSk7XG4gIG91dC5wdXNoKCctLS0tLUVORCAnICsgb3B0aW9ucy5sYWJlbCArICctLS0tLScpO1xuICByZXR1cm4gb3V0LmpvaW4oJ1xcbicpO1xufTtcbiIsIid1c2Ugc3RyaWN0J1xuXG5leHBvcnRzLnRvQnl0ZUFycmF5ID0gdG9CeXRlQXJyYXlcbmV4cG9ydHMuZnJvbUJ5dGVBcnJheSA9IGZyb21CeXRlQXJyYXlcblxudmFyIGxvb2t1cCA9IFtdXG52YXIgcmV2TG9va3VwID0gW11cbnZhciBBcnIgPSB0eXBlb2YgVWludDhBcnJheSAhPT0gJ3VuZGVmaW5lZCcgPyBVaW50OEFycmF5IDogQXJyYXlcblxuZnVuY3Rpb24gaW5pdCAoKSB7XG4gIHZhciBjb2RlID0gJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nXG4gIGZvciAodmFyIGkgPSAwLCBsZW4gPSBjb2RlLmxlbmd0aDsgaSA8IGxlbjsgKytpKSB7XG4gICAgbG9va3VwW2ldID0gY29kZVtpXVxuICAgIHJldkxvb2t1cFtjb2RlLmNoYXJDb2RlQXQoaSldID0gaVxuICB9XG5cbiAgcmV2TG9va3VwWyctJy5jaGFyQ29kZUF0KDApXSA9IDYyXG4gIHJldkxvb2t1cFsnXycuY2hhckNvZGVBdCgwKV0gPSA2M1xufVxuXG5pbml0KClcblxuZnVuY3Rpb24gdG9CeXRlQXJyYXkgKGI2NCkge1xuICB2YXIgaSwgaiwgbCwgdG1wLCBwbGFjZUhvbGRlcnMsIGFyclxuICB2YXIgbGVuID0gYjY0Lmxlbmd0aFxuXG4gIGlmIChsZW4gJSA0ID4gMCkge1xuICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBzdHJpbmcuIExlbmd0aCBtdXN0IGJlIGEgbXVsdGlwbGUgb2YgNCcpXG4gIH1cblxuICAvLyB0aGUgbnVtYmVyIG9mIGVxdWFsIHNpZ25zIChwbGFjZSBob2xkZXJzKVxuICAvLyBpZiB0aGVyZSBhcmUgdHdvIHBsYWNlaG9sZGVycywgdGhhbiB0aGUgdHdvIGNoYXJhY3RlcnMgYmVmb3JlIGl0XG4gIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAvLyBpZiB0aGVyZSBpcyBvbmx5IG9uZSwgdGhlbiB0aGUgdGhyZWUgY2hhcmFjdGVycyBiZWZvcmUgaXQgcmVwcmVzZW50IDIgYnl0ZXNcbiAgLy8gdGhpcyBpcyBqdXN0IGEgY2hlYXAgaGFjayB0byBub3QgZG8gaW5kZXhPZiB0d2ljZVxuICBwbGFjZUhvbGRlcnMgPSBiNjRbbGVuIC0gMl0gPT09ICc9JyA/IDIgOiBiNjRbbGVuIC0gMV0gPT09ICc9JyA/IDEgOiAwXG5cbiAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gIGFyciA9IG5ldyBBcnIobGVuICogMyAvIDQgLSBwbGFjZUhvbGRlcnMpXG5cbiAgLy8gaWYgdGhlcmUgYXJlIHBsYWNlaG9sZGVycywgb25seSBnZXQgdXAgdG8gdGhlIGxhc3QgY29tcGxldGUgNCBjaGFyc1xuICBsID0gcGxhY2VIb2xkZXJzID4gMCA/IGxlbiAtIDQgOiBsZW5cblxuICB2YXIgTCA9IDBcblxuICBmb3IgKGkgPSAwLCBqID0gMDsgaSA8IGw7IGkgKz0gNCwgaiArPSAzKSB7XG4gICAgdG1wID0gKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpKV0gPDwgMTgpIHwgKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpICsgMSldIDw8IDEyKSB8IChyZXZMb29rdXBbYjY0LmNoYXJDb2RlQXQoaSArIDIpXSA8PCA2KSB8IHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpICsgMyldXG4gICAgYXJyW0wrK10gPSAodG1wID4+IDE2KSAmIDB4RkZcbiAgICBhcnJbTCsrXSA9ICh0bXAgPj4gOCkgJiAweEZGXG4gICAgYXJyW0wrK10gPSB0bXAgJiAweEZGXG4gIH1cblxuICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgdG1wID0gKHJldkxvb2t1cFtiNjQuY2hhckNvZGVBdChpKV0gPDwgMikgfCAocmV2TG9va3VwW2I2NC5jaGFyQ29kZUF0KGkgKyAxKV0gPj4gNClcbiAgICBhcnJbTCsrXSA9IHRtcCAmIDB4RkZcbiAgfSBlbHNlIGlmIChwbGFjZUhvbGRlcnMgPT09IDEpIHtcbiAgICB0bXAgPSAocmV2TG9va3VwW2I2NC5jaGFyQ29kZUF0KGkpXSA8PCAxMCkgfCAocmV2TG9va3VwW2I2NC5jaGFyQ29kZUF0KGkgKyAxKV0gPDwgNCkgfCAocmV2TG9va3VwW2I2NC5jaGFyQ29kZUF0KGkgKyAyKV0gPj4gMilcbiAgICBhcnJbTCsrXSA9ICh0bXAgPj4gOCkgJiAweEZGXG4gICAgYXJyW0wrK10gPSB0bXAgJiAweEZGXG4gIH1cblxuICByZXR1cm4gYXJyXG59XG5cbmZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCAobnVtKSB7XG4gIHJldHVybiBsb29rdXBbbnVtID4+IDE4ICYgMHgzRl0gKyBsb29rdXBbbnVtID4+IDEyICYgMHgzRl0gKyBsb29rdXBbbnVtID4+IDYgJiAweDNGXSArIGxvb2t1cFtudW0gJiAweDNGXVxufVxuXG5mdW5jdGlvbiBlbmNvZGVDaHVuayAodWludDgsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIHRtcFxuICB2YXIgb3V0cHV0ID0gW11cbiAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyBpICs9IDMpIHtcbiAgICB0bXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pXG4gICAgb3V0cHV0LnB1c2godHJpcGxldFRvQmFzZTY0KHRtcCkpXG4gIH1cbiAgcmV0dXJuIG91dHB1dC5qb2luKCcnKVxufVxuXG5mdW5jdGlvbiBmcm9tQnl0ZUFycmF5ICh1aW50OCkge1xuICB2YXIgdG1wXG4gIHZhciBsZW4gPSB1aW50OC5sZW5ndGhcbiAgdmFyIGV4dHJhQnl0ZXMgPSBsZW4gJSAzIC8vIGlmIHdlIGhhdmUgMSBieXRlIGxlZnQsIHBhZCAyIGJ5dGVzXG4gIHZhciBvdXRwdXQgPSAnJ1xuICB2YXIgcGFydHMgPSBbXVxuICB2YXIgbWF4Q2h1bmtMZW5ndGggPSAxNjM4MyAvLyBtdXN0IGJlIG11bHRpcGxlIG9mIDNcblxuICAvLyBnbyB0aHJvdWdoIHRoZSBhcnJheSBldmVyeSB0aHJlZSBieXRlcywgd2UnbGwgZGVhbCB3aXRoIHRyYWlsaW5nIHN0dWZmIGxhdGVyXG4gIGZvciAodmFyIGkgPSAwLCBsZW4yID0gbGVuIC0gZXh0cmFCeXRlczsgaSA8IGxlbjI7IGkgKz0gbWF4Q2h1bmtMZW5ndGgpIHtcbiAgICBwYXJ0cy5wdXNoKGVuY29kZUNodW5rKHVpbnQ4LCBpLCAoaSArIG1heENodW5rTGVuZ3RoKSA+IGxlbjIgPyBsZW4yIDogKGkgKyBtYXhDaHVua0xlbmd0aCkpKVxuICB9XG5cbiAgLy8gcGFkIHRoZSBlbmQgd2l0aCB6ZXJvcywgYnV0IG1ha2Ugc3VyZSB0byBub3QgZm9yZ2V0IHRoZSBleHRyYSBieXRlc1xuICBpZiAoZXh0cmFCeXRlcyA9PT0gMSkge1xuICAgIHRtcCA9IHVpbnQ4W2xlbiAtIDFdXG4gICAgb3V0cHV0ICs9IGxvb2t1cFt0bXAgPj4gMl1cbiAgICBvdXRwdXQgKz0gbG9va3VwWyh0bXAgPDwgNCkgJiAweDNGXVxuICAgIG91dHB1dCArPSAnPT0nXG4gIH0gZWxzZSBpZiAoZXh0cmFCeXRlcyA9PT0gMikge1xuICAgIHRtcCA9ICh1aW50OFtsZW4gLSAyXSA8PCA4KSArICh1aW50OFtsZW4gLSAxXSlcbiAgICBvdXRwdXQgKz0gbG9va3VwW3RtcCA+PiAxMF1cbiAgICBvdXRwdXQgKz0gbG9va3VwWyh0bXAgPj4gNCkgJiAweDNGXVxuICAgIG91dHB1dCArPSBsb29rdXBbKHRtcCA8PCAyKSAmIDB4M0ZdXG4gICAgb3V0cHV0ICs9ICc9J1xuICB9XG5cbiAgcGFydHMucHVzaChvdXRwdXQpXG5cbiAgcmV0dXJuIHBhcnRzLmpvaW4oJycpXG59XG4iLCIoZnVuY3Rpb24gKG1vZHVsZSwgZXhwb3J0cykge1xuICAndXNlIHN0cmljdCc7XG5cbiAgLy8gVXRpbHNcbiAgZnVuY3Rpb24gYXNzZXJ0ICh2YWwsIG1zZykge1xuICAgIGlmICghdmFsKSB0aHJvdyBuZXcgRXJyb3IobXNnIHx8ICdBc3NlcnRpb24gZmFpbGVkJyk7XG4gIH1cblxuICAvLyBDb3VsZCB1c2UgYGluaGVyaXRzYCBtb2R1bGUsIGJ1dCBkb24ndCB3YW50IHRvIG1vdmUgZnJvbSBzaW5nbGUgZmlsZVxuICAvLyBhcmNoaXRlY3R1cmUgeWV0LlxuICBmdW5jdGlvbiBpbmhlcml0cyAoY3Rvciwgc3VwZXJDdG9yKSB7XG4gICAgY3Rvci5zdXBlcl8gPSBzdXBlckN0b3I7XG4gICAgdmFyIFRlbXBDdG9yID0gZnVuY3Rpb24gKCkge307XG4gICAgVGVtcEN0b3IucHJvdG90eXBlID0gc3VwZXJDdG9yLnByb3RvdHlwZTtcbiAgICBjdG9yLnByb3RvdHlwZSA9IG5ldyBUZW1wQ3RvcigpO1xuICAgIGN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gY3RvcjtcbiAgfVxuXG4gIC8vIEJOXG5cbiAgZnVuY3Rpb24gQk4gKG51bWJlciwgYmFzZSwgZW5kaWFuKSB7XG4gICAgaWYgKEJOLmlzQk4obnVtYmVyKSkge1xuICAgICAgcmV0dXJuIG51bWJlcjtcbiAgICB9XG5cbiAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICB0aGlzLndvcmRzID0gbnVsbDtcbiAgICB0aGlzLmxlbmd0aCA9IDA7XG5cbiAgICAvLyBSZWR1Y3Rpb24gY29udGV4dFxuICAgIHRoaXMucmVkID0gbnVsbDtcblxuICAgIGlmIChudW1iZXIgIT09IG51bGwpIHtcbiAgICAgIGlmIChiYXNlID09PSAnbGUnIHx8IGJhc2UgPT09ICdiZScpIHtcbiAgICAgICAgZW5kaWFuID0gYmFzZTtcbiAgICAgICAgYmFzZSA9IDEwO1xuICAgICAgfVxuXG4gICAgICB0aGlzLl9pbml0KG51bWJlciB8fCAwLCBiYXNlIHx8IDEwLCBlbmRpYW4gfHwgJ2JlJyk7XG4gICAgfVxuICB9XG4gIGlmICh0eXBlb2YgbW9kdWxlID09PSAnb2JqZWN0Jykge1xuICAgIG1vZHVsZS5leHBvcnRzID0gQk47XG4gIH0gZWxzZSB7XG4gICAgZXhwb3J0cy5CTiA9IEJOO1xuICB9XG5cbiAgQk4uQk4gPSBCTjtcbiAgQk4ud29yZFNpemUgPSAyNjtcblxuICB2YXIgQnVmZmVyO1xuICB0cnkge1xuICAgIEJ1ZmZlciA9IHJlcXVpcmUoJ2J1ZicgKyAnZmVyJykuQnVmZmVyO1xuICB9IGNhdGNoIChlKSB7XG4gIH1cblxuICBCTi5pc0JOID0gZnVuY3Rpb24gaXNCTiAobnVtKSB7XG4gICAgcmV0dXJuIG51bSAhPT0gbnVsbCAmJiB0eXBlb2YgbnVtID09PSAnb2JqZWN0JyAmJlxuICAgICAgbnVtLmNvbnN0cnVjdG9yLm5hbWUgPT09ICdCTicgJiYgQXJyYXkuaXNBcnJheShudW0ud29yZHMpO1xuICB9O1xuXG4gIEJOLm1heCA9IGZ1bmN0aW9uIG1heCAobGVmdCwgcmlnaHQpIHtcbiAgICBpZiAobGVmdC5jbXAocmlnaHQpID4gMCkgcmV0dXJuIGxlZnQ7XG4gICAgcmV0dXJuIHJpZ2h0O1xuICB9O1xuXG4gIEJOLm1pbiA9IGZ1bmN0aW9uIG1pbiAobGVmdCwgcmlnaHQpIHtcbiAgICBpZiAobGVmdC5jbXAocmlnaHQpIDwgMCkgcmV0dXJuIGxlZnQ7XG4gICAgcmV0dXJuIHJpZ2h0O1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5faW5pdCA9IGZ1bmN0aW9uIGluaXQgKG51bWJlciwgYmFzZSwgZW5kaWFuKSB7XG4gICAgaWYgKHR5cGVvZiBudW1iZXIgPT09ICdudW1iZXInKSB7XG4gICAgICByZXR1cm4gdGhpcy5faW5pdE51bWJlcihudW1iZXIsIGJhc2UsIGVuZGlhbik7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBudW1iZXIgPT09ICdvYmplY3QnKSB7XG4gICAgICByZXR1cm4gdGhpcy5faW5pdEFycmF5KG51bWJlciwgYmFzZSwgZW5kaWFuKTtcbiAgICB9XG5cbiAgICBpZiAoYmFzZSA9PT0gJ2hleCcpIHtcbiAgICAgIGJhc2UgPSAxNjtcbiAgICB9XG4gICAgYXNzZXJ0KGJhc2UgPT09IChiYXNlIHwgMCkgJiYgYmFzZSA+PSAyICYmIGJhc2UgPD0gMzYpO1xuXG4gICAgbnVtYmVyID0gbnVtYmVyLnRvU3RyaW5nKCkucmVwbGFjZSgvXFxzKy9nLCAnJyk7XG4gICAgdmFyIHN0YXJ0ID0gMDtcbiAgICBpZiAobnVtYmVyWzBdID09PSAnLScpIHtcbiAgICAgIHN0YXJ0Kys7XG4gICAgfVxuXG4gICAgaWYgKGJhc2UgPT09IDE2KSB7XG4gICAgICB0aGlzLl9wYXJzZUhleChudW1iZXIsIHN0YXJ0KTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5fcGFyc2VCYXNlKG51bWJlciwgYmFzZSwgc3RhcnQpO1xuICAgIH1cblxuICAgIGlmIChudW1iZXJbMF0gPT09ICctJykge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG4gICAgfVxuXG4gICAgdGhpcy5zdHJpcCgpO1xuXG4gICAgaWYgKGVuZGlhbiAhPT0gJ2xlJykgcmV0dXJuO1xuXG4gICAgdGhpcy5faW5pdEFycmF5KHRoaXMudG9BcnJheSgpLCBiYXNlLCBlbmRpYW4pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5faW5pdE51bWJlciA9IGZ1bmN0aW9uIF9pbml0TnVtYmVyIChudW1iZXIsIGJhc2UsIGVuZGlhbikge1xuICAgIGlmIChudW1iZXIgPCAwKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICAgIG51bWJlciA9IC1udW1iZXI7XG4gICAgfVxuICAgIGlmIChudW1iZXIgPCAweDQwMDAwMDApIHtcbiAgICAgIHRoaXMud29yZHMgPSBbIG51bWJlciAmIDB4M2ZmZmZmZiBdO1xuICAgICAgdGhpcy5sZW5ndGggPSAxO1xuICAgIH0gZWxzZSBpZiAobnVtYmVyIDwgMHgxMDAwMDAwMDAwMDAwMCkge1xuICAgICAgdGhpcy53b3JkcyA9IFtcbiAgICAgICAgbnVtYmVyICYgMHgzZmZmZmZmLFxuICAgICAgICAobnVtYmVyIC8gMHg0MDAwMDAwKSAmIDB4M2ZmZmZmZlxuICAgICAgXTtcbiAgICAgIHRoaXMubGVuZ3RoID0gMjtcbiAgICB9IGVsc2Uge1xuICAgICAgYXNzZXJ0KG51bWJlciA8IDB4MjAwMDAwMDAwMDAwMDApOyAvLyAyIF4gNTMgKHVuc2FmZSlcbiAgICAgIHRoaXMud29yZHMgPSBbXG4gICAgICAgIG51bWJlciAmIDB4M2ZmZmZmZixcbiAgICAgICAgKG51bWJlciAvIDB4NDAwMDAwMCkgJiAweDNmZmZmZmYsXG4gICAgICAgIDFcbiAgICAgIF07XG4gICAgICB0aGlzLmxlbmd0aCA9IDM7XG4gICAgfVxuXG4gICAgaWYgKGVuZGlhbiAhPT0gJ2xlJykgcmV0dXJuO1xuXG4gICAgLy8gUmV2ZXJzZSB0aGUgYnl0ZXNcbiAgICB0aGlzLl9pbml0QXJyYXkodGhpcy50b0FycmF5KCksIGJhc2UsIGVuZGlhbik7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLl9pbml0QXJyYXkgPSBmdW5jdGlvbiBfaW5pdEFycmF5IChudW1iZXIsIGJhc2UsIGVuZGlhbikge1xuICAgIC8vIFBlcmhhcHMgYSBVaW50OEFycmF5XG4gICAgYXNzZXJ0KHR5cGVvZiBudW1iZXIubGVuZ3RoID09PSAnbnVtYmVyJyk7XG4gICAgaWYgKG51bWJlci5sZW5ndGggPD0gMCkge1xuICAgICAgdGhpcy53b3JkcyA9IFsgMCBdO1xuICAgICAgdGhpcy5sZW5ndGggPSAxO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgdGhpcy5sZW5ndGggPSBNYXRoLmNlaWwobnVtYmVyLmxlbmd0aCAvIDMpO1xuICAgIHRoaXMud29yZHMgPSBuZXcgQXJyYXkodGhpcy5sZW5ndGgpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IDA7XG4gICAgfVxuXG4gICAgdmFyIGosIHc7XG4gICAgdmFyIG9mZiA9IDA7XG4gICAgaWYgKGVuZGlhbiA9PT0gJ2JlJykge1xuICAgICAgZm9yIChpID0gbnVtYmVyLmxlbmd0aCAtIDEsIGogPSAwOyBpID49IDA7IGkgLT0gMykge1xuICAgICAgICB3ID0gbnVtYmVyW2ldIHwgKG51bWJlcltpIC0gMV0gPDwgOCkgfCAobnVtYmVyW2kgLSAyXSA8PCAxNik7XG4gICAgICAgIHRoaXMud29yZHNbal0gfD0gKHcgPDwgb2ZmKSAmIDB4M2ZmZmZmZjtcbiAgICAgICAgdGhpcy53b3Jkc1tqICsgMV0gPSAodyA+Pj4gKDI2IC0gb2ZmKSkgJiAweDNmZmZmZmY7XG4gICAgICAgIG9mZiArPSAyNDtcbiAgICAgICAgaWYgKG9mZiA+PSAyNikge1xuICAgICAgICAgIG9mZiAtPSAyNjtcbiAgICAgICAgICBqKys7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKGVuZGlhbiA9PT0gJ2xlJykge1xuICAgICAgZm9yIChpID0gMCwgaiA9IDA7IGkgPCBudW1iZXIubGVuZ3RoOyBpICs9IDMpIHtcbiAgICAgICAgdyA9IG51bWJlcltpXSB8IChudW1iZXJbaSArIDFdIDw8IDgpIHwgKG51bWJlcltpICsgMl0gPDwgMTYpO1xuICAgICAgICB0aGlzLndvcmRzW2pdIHw9ICh3IDw8IG9mZikgJiAweDNmZmZmZmY7XG4gICAgICAgIHRoaXMud29yZHNbaiArIDFdID0gKHcgPj4+ICgyNiAtIG9mZikpICYgMHgzZmZmZmZmO1xuICAgICAgICBvZmYgKz0gMjQ7XG4gICAgICAgIGlmIChvZmYgPj0gMjYpIHtcbiAgICAgICAgICBvZmYgLT0gMjY7XG4gICAgICAgICAgaisrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgZnVuY3Rpb24gcGFyc2VIZXggKHN0ciwgc3RhcnQsIGVuZCkge1xuICAgIHZhciByID0gMDtcbiAgICB2YXIgbGVuID0gTWF0aC5taW4oc3RyLmxlbmd0aCwgZW5kKTtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBsZW47IGkrKykge1xuICAgICAgdmFyIGMgPSBzdHIuY2hhckNvZGVBdChpKSAtIDQ4O1xuXG4gICAgICByIDw8PSA0O1xuXG4gICAgICAvLyAnYScgLSAnZidcbiAgICAgIGlmIChjID49IDQ5ICYmIGMgPD0gNTQpIHtcbiAgICAgICAgciB8PSBjIC0gNDkgKyAweGE7XG5cbiAgICAgIC8vICdBJyAtICdGJ1xuICAgICAgfSBlbHNlIGlmIChjID49IDE3ICYmIGMgPD0gMjIpIHtcbiAgICAgICAgciB8PSBjIC0gMTcgKyAweGE7XG5cbiAgICAgIC8vICcwJyAtICc5J1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgciB8PSBjICYgMHhmO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcjtcbiAgfVxuXG4gIEJOLnByb3RvdHlwZS5fcGFyc2VIZXggPSBmdW5jdGlvbiBfcGFyc2VIZXggKG51bWJlciwgc3RhcnQpIHtcbiAgICAvLyBDcmVhdGUgcG9zc2libHkgYmlnZ2VyIGFycmF5IHRvIGVuc3VyZSB0aGF0IGl0IGZpdHMgdGhlIG51bWJlclxuICAgIHRoaXMubGVuZ3RoID0gTWF0aC5jZWlsKChudW1iZXIubGVuZ3RoIC0gc3RhcnQpIC8gNik7XG4gICAgdGhpcy53b3JkcyA9IG5ldyBBcnJheSh0aGlzLmxlbmd0aCk7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gMDtcbiAgICB9XG5cbiAgICB2YXIgaiwgdztcbiAgICAvLyBTY2FuIDI0LWJpdCBjaHVua3MgYW5kIGFkZCB0aGVtIHRvIHRoZSBudW1iZXJcbiAgICB2YXIgb2ZmID0gMDtcbiAgICBmb3IgKGkgPSBudW1iZXIubGVuZ3RoIC0gNiwgaiA9IDA7IGkgPj0gc3RhcnQ7IGkgLT0gNikge1xuICAgICAgdyA9IHBhcnNlSGV4KG51bWJlciwgaSwgaSArIDYpO1xuICAgICAgdGhpcy53b3Jkc1tqXSB8PSAodyA8PCBvZmYpICYgMHgzZmZmZmZmO1xuICAgICAgLy8gTk9URTogYDB4M2ZmZmZmYCBpcyBpbnRlbnRpb25hbCBoZXJlLCAyNmJpdHMgbWF4IHNoaWZ0ICsgMjRiaXQgaGV4IGxpbWJcbiAgICAgIHRoaXMud29yZHNbaiArIDFdIHw9IHcgPj4+ICgyNiAtIG9mZikgJiAweDNmZmZmZjtcbiAgICAgIG9mZiArPSAyNDtcbiAgICAgIGlmIChvZmYgPj0gMjYpIHtcbiAgICAgICAgb2ZmIC09IDI2O1xuICAgICAgICBqKys7XG4gICAgICB9XG4gICAgfVxuICAgIGlmIChpICsgNiAhPT0gc3RhcnQpIHtcbiAgICAgIHcgPSBwYXJzZUhleChudW1iZXIsIHN0YXJ0LCBpICsgNik7XG4gICAgICB0aGlzLndvcmRzW2pdIHw9ICh3IDw8IG9mZikgJiAweDNmZmZmZmY7XG4gICAgICB0aGlzLndvcmRzW2ogKyAxXSB8PSB3ID4+PiAoMjYgLSBvZmYpICYgMHgzZmZmZmY7XG4gICAgfVxuICAgIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBmdW5jdGlvbiBwYXJzZUJhc2UgKHN0ciwgc3RhcnQsIGVuZCwgbXVsKSB7XG4gICAgdmFyIHIgPSAwO1xuICAgIHZhciBsZW4gPSBNYXRoLm1pbihzdHIubGVuZ3RoLCBlbmQpO1xuICAgIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICB2YXIgYyA9IHN0ci5jaGFyQ29kZUF0KGkpIC0gNDg7XG5cbiAgICAgIHIgKj0gbXVsO1xuXG4gICAgICAvLyAnYSdcbiAgICAgIGlmIChjID49IDQ5KSB7XG4gICAgICAgIHIgKz0gYyAtIDQ5ICsgMHhhO1xuXG4gICAgICAvLyAnQSdcbiAgICAgIH0gZWxzZSBpZiAoYyA+PSAxNykge1xuICAgICAgICByICs9IGMgLSAxNyArIDB4YTtcblxuICAgICAgLy8gJzAnIC0gJzknXG4gICAgICB9IGVsc2Uge1xuICAgICAgICByICs9IGM7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiByO1xuICB9XG5cbiAgQk4ucHJvdG90eXBlLl9wYXJzZUJhc2UgPSBmdW5jdGlvbiBfcGFyc2VCYXNlIChudW1iZXIsIGJhc2UsIHN0YXJ0KSB7XG4gICAgLy8gSW5pdGlhbGl6ZSBhcyB6ZXJvXG4gICAgdGhpcy53b3JkcyA9IFsgMCBdO1xuICAgIHRoaXMubGVuZ3RoID0gMTtcblxuICAgIC8vIEZpbmQgbGVuZ3RoIG9mIGxpbWIgaW4gYmFzZVxuICAgIGZvciAodmFyIGxpbWJMZW4gPSAwLCBsaW1iUG93ID0gMTsgbGltYlBvdyA8PSAweDNmZmZmZmY7IGxpbWJQb3cgKj0gYmFzZSkge1xuICAgICAgbGltYkxlbisrO1xuICAgIH1cbiAgICBsaW1iTGVuLS07XG4gICAgbGltYlBvdyA9IChsaW1iUG93IC8gYmFzZSkgfCAwO1xuXG4gICAgdmFyIHRvdGFsID0gbnVtYmVyLmxlbmd0aCAtIHN0YXJ0O1xuICAgIHZhciBtb2QgPSB0b3RhbCAlIGxpbWJMZW47XG4gICAgdmFyIGVuZCA9IE1hdGgubWluKHRvdGFsLCB0b3RhbCAtIG1vZCkgKyBzdGFydDtcblxuICAgIHZhciB3b3JkID0gMDtcbiAgICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7IGkgKz0gbGltYkxlbikge1xuICAgICAgd29yZCA9IHBhcnNlQmFzZShudW1iZXIsIGksIGkgKyBsaW1iTGVuLCBiYXNlKTtcblxuICAgICAgdGhpcy5pbXVsbihsaW1iUG93KTtcbiAgICAgIGlmICh0aGlzLndvcmRzWzBdICsgd29yZCA8IDB4NDAwMDAwMCkge1xuICAgICAgICB0aGlzLndvcmRzWzBdICs9IHdvcmQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9pYWRkbih3b3JkKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAobW9kICE9PSAwKSB7XG4gICAgICB2YXIgcG93ID0gMTtcbiAgICAgIHdvcmQgPSBwYXJzZUJhc2UobnVtYmVyLCBpLCBudW1iZXIubGVuZ3RoLCBiYXNlKTtcblxuICAgICAgZm9yIChpID0gMDsgaSA8IG1vZDsgaSsrKSB7XG4gICAgICAgIHBvdyAqPSBiYXNlO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmltdWxuKHBvdyk7XG4gICAgICBpZiAodGhpcy53b3Jkc1swXSArIHdvcmQgPCAweDQwMDAwMDApIHtcbiAgICAgICAgdGhpcy53b3Jkc1swXSArPSB3b3JkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5faWFkZG4od29yZCk7XG4gICAgICB9XG4gICAgfVxuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5jb3B5ID0gZnVuY3Rpb24gY29weSAoZGVzdCkge1xuICAgIGRlc3Qud29yZHMgPSBuZXcgQXJyYXkodGhpcy5sZW5ndGgpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgZGVzdC53b3Jkc1tpXSA9IHRoaXMud29yZHNbaV07XG4gICAgfVxuICAgIGRlc3QubGVuZ3RoID0gdGhpcy5sZW5ndGg7XG4gICAgZGVzdC5uZWdhdGl2ZSA9IHRoaXMubmVnYXRpdmU7XG4gICAgZGVzdC5yZWQgPSB0aGlzLnJlZDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuY2xvbmUgPSBmdW5jdGlvbiBjbG9uZSAoKSB7XG4gICAgdmFyIHIgPSBuZXcgQk4obnVsbCk7XG4gICAgdGhpcy5jb3B5KHIpO1xuICAgIHJldHVybiByO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5fZXhwYW5kID0gZnVuY3Rpb24gX2V4cGFuZCAoc2l6ZSkge1xuICAgIHdoaWxlICh0aGlzLmxlbmd0aCA8IHNpemUpIHtcbiAgICAgIHRoaXMud29yZHNbdGhpcy5sZW5ndGgrK10gPSAwO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICAvLyBSZW1vdmUgbGVhZGluZyBgMGAgZnJvbSBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLnN0cmlwID0gZnVuY3Rpb24gc3RyaXAgKCkge1xuICAgIHdoaWxlICh0aGlzLmxlbmd0aCA+IDEgJiYgdGhpcy53b3Jkc1t0aGlzLmxlbmd0aCAtIDFdID09PSAwKSB7XG4gICAgICB0aGlzLmxlbmd0aC0tO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fbm9ybVNpZ24oKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX25vcm1TaWduID0gZnVuY3Rpb24gX25vcm1TaWduICgpIHtcbiAgICAvLyAtMCA9IDBcbiAgICBpZiAodGhpcy5sZW5ndGggPT09IDEgJiYgdGhpcy53b3Jkc1swXSA9PT0gMCkge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgfVxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCAoKSB7XG4gICAgcmV0dXJuICh0aGlzLnJlZCA/ICc8Qk4tUjogJyA6ICc8Qk46ICcpICsgdGhpcy50b1N0cmluZygxNikgKyAnPic7XG4gIH07XG5cbiAgLypcblxuICB2YXIgemVyb3MgPSBbXTtcbiAgdmFyIGdyb3VwU2l6ZXMgPSBbXTtcbiAgdmFyIGdyb3VwQmFzZXMgPSBbXTtcblxuICB2YXIgcyA9ICcnO1xuICB2YXIgaSA9IC0xO1xuICB3aGlsZSAoKytpIDwgQk4ud29yZFNpemUpIHtcbiAgICB6ZXJvc1tpXSA9IHM7XG4gICAgcyArPSAnMCc7XG4gIH1cbiAgZ3JvdXBTaXplc1swXSA9IDA7XG4gIGdyb3VwU2l6ZXNbMV0gPSAwO1xuICBncm91cEJhc2VzWzBdID0gMDtcbiAgZ3JvdXBCYXNlc1sxXSA9IDA7XG4gIHZhciBiYXNlID0gMiAtIDE7XG4gIHdoaWxlICgrK2Jhc2UgPCAzNiArIDEpIHtcbiAgICB2YXIgZ3JvdXBTaXplID0gMDtcbiAgICB2YXIgZ3JvdXBCYXNlID0gMTtcbiAgICB3aGlsZSAoZ3JvdXBCYXNlIDwgKDEgPDwgQk4ud29yZFNpemUpIC8gYmFzZSkge1xuICAgICAgZ3JvdXBCYXNlICo9IGJhc2U7XG4gICAgICBncm91cFNpemUgKz0gMTtcbiAgICB9XG4gICAgZ3JvdXBTaXplc1tiYXNlXSA9IGdyb3VwU2l6ZTtcbiAgICBncm91cEJhc2VzW2Jhc2VdID0gZ3JvdXBCYXNlO1xuICB9XG5cbiAgKi9cblxuICB2YXIgemVyb3MgPSBbXG4gICAgJycsXG4gICAgJzAnLFxuICAgICcwMCcsXG4gICAgJzAwMCcsXG4gICAgJzAwMDAnLFxuICAgICcwMDAwMCcsXG4gICAgJzAwMDAwMCcsXG4gICAgJzAwMDAwMDAnLFxuICAgICcwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAnLFxuICAgICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gICAgJzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAnXG4gIF07XG5cbiAgdmFyIGdyb3VwU2l6ZXMgPSBbXG4gICAgMCwgMCxcbiAgICAyNSwgMTYsIDEyLCAxMSwgMTAsIDksIDgsXG4gICAgOCwgNywgNywgNywgNywgNiwgNixcbiAgICA2LCA2LCA2LCA2LCA2LCA1LCA1LFxuICAgIDUsIDUsIDUsIDUsIDUsIDUsIDUsXG4gICAgNSwgNSwgNSwgNSwgNSwgNSwgNVxuICBdO1xuXG4gIHZhciBncm91cEJhc2VzID0gW1xuICAgIDAsIDAsXG4gICAgMzM1NTQ0MzIsIDQzMDQ2NzIxLCAxNjc3NzIxNiwgNDg4MjgxMjUsIDYwNDY2MTc2LCA0MDM1MzYwNywgMTY3NzcyMTYsXG4gICAgNDMwNDY3MjEsIDEwMDAwMDAwLCAxOTQ4NzE3MSwgMzU4MzE4MDgsIDYyNzQ4NTE3LCA3NTI5NTM2LCAxMTM5MDYyNSxcbiAgICAxNjc3NzIxNiwgMjQxMzc1NjksIDM0MDEyMjI0LCA0NzA0NTg4MSwgNjQwMDAwMDAsIDQwODQxMDEsIDUxNTM2MzIsXG4gICAgNjQzNjM0MywgNzk2MjYyNCwgOTc2NTYyNSwgMTE4ODEzNzYsIDE0MzQ4OTA3LCAxNzIxMDM2OCwgMjA1MTExNDksXG4gICAgMjQzMDAwMDAsIDI4NjI5MTUxLCAzMzU1NDQzMiwgMzkxMzUzOTMsIDQ1NDM1NDI0LCA1MjUyMTg3NSwgNjA0NjYxNzZcbiAgXTtcblxuICBCTi5wcm90b3R5cGUudG9TdHJpbmcgPSBmdW5jdGlvbiB0b1N0cmluZyAoYmFzZSwgcGFkZGluZykge1xuICAgIGJhc2UgPSBiYXNlIHx8IDEwO1xuICAgIHBhZGRpbmcgPSBwYWRkaW5nIHwgMCB8fCAxO1xuXG4gICAgdmFyIG91dDtcbiAgICBpZiAoYmFzZSA9PT0gMTYgfHwgYmFzZSA9PT0gJ2hleCcpIHtcbiAgICAgIG91dCA9ICcnO1xuICAgICAgdmFyIG9mZiA9IDA7XG4gICAgICB2YXIgY2FycnkgPSAwO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciB3ID0gdGhpcy53b3Jkc1tpXTtcbiAgICAgICAgdmFyIHdvcmQgPSAoKCh3IDw8IG9mZikgfCBjYXJyeSkgJiAweGZmZmZmZikudG9TdHJpbmcoMTYpO1xuICAgICAgICBjYXJyeSA9ICh3ID4+PiAoMjQgLSBvZmYpKSAmIDB4ZmZmZmZmO1xuICAgICAgICBpZiAoY2FycnkgIT09IDAgfHwgaSAhPT0gdGhpcy5sZW5ndGggLSAxKSB7XG4gICAgICAgICAgb3V0ID0gemVyb3NbNiAtIHdvcmQubGVuZ3RoXSArIHdvcmQgKyBvdXQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgb3V0ID0gd29yZCArIG91dDtcbiAgICAgICAgfVxuICAgICAgICBvZmYgKz0gMjtcbiAgICAgICAgaWYgKG9mZiA+PSAyNikge1xuICAgICAgICAgIG9mZiAtPSAyNjtcbiAgICAgICAgICBpLS07XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChjYXJyeSAhPT0gMCkge1xuICAgICAgICBvdXQgPSBjYXJyeS50b1N0cmluZygxNikgKyBvdXQ7XG4gICAgICB9XG4gICAgICB3aGlsZSAob3V0Lmxlbmd0aCAlIHBhZGRpbmcgIT09IDApIHtcbiAgICAgICAgb3V0ID0gJzAnICsgb3V0O1xuICAgICAgfVxuICAgICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHtcbiAgICAgICAgb3V0ID0gJy0nICsgb3V0O1xuICAgICAgfVxuICAgICAgcmV0dXJuIG91dDtcbiAgICB9XG5cbiAgICBpZiAoYmFzZSA9PT0gKGJhc2UgfCAwKSAmJiBiYXNlID49IDIgJiYgYmFzZSA8PSAzNikge1xuICAgICAgLy8gdmFyIGdyb3VwU2l6ZSA9IE1hdGguZmxvb3IoQk4ud29yZFNpemUgKiBNYXRoLkxOMiAvIE1hdGgubG9nKGJhc2UpKTtcbiAgICAgIHZhciBncm91cFNpemUgPSBncm91cFNpemVzW2Jhc2VdO1xuICAgICAgLy8gdmFyIGdyb3VwQmFzZSA9IE1hdGgucG93KGJhc2UsIGdyb3VwU2l6ZSk7XG4gICAgICB2YXIgZ3JvdXBCYXNlID0gZ3JvdXBCYXNlc1tiYXNlXTtcbiAgICAgIG91dCA9ICcnO1xuICAgICAgdmFyIGMgPSB0aGlzLmNsb25lKCk7XG4gICAgICBjLm5lZ2F0aXZlID0gMDtcbiAgICAgIHdoaWxlICghYy5pc1plcm8oKSkge1xuICAgICAgICB2YXIgciA9IGMubW9kbihncm91cEJhc2UpLnRvU3RyaW5nKGJhc2UpO1xuICAgICAgICBjID0gYy5pZGl2bihncm91cEJhc2UpO1xuXG4gICAgICAgIGlmICghYy5pc1plcm8oKSkge1xuICAgICAgICAgIG91dCA9IHplcm9zW2dyb3VwU2l6ZSAtIHIubGVuZ3RoXSArIHIgKyBvdXQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgb3V0ID0gciArIG91dDtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKHRoaXMuaXNaZXJvKCkpIHtcbiAgICAgICAgb3V0ID0gJzAnICsgb3V0O1xuICAgICAgfVxuICAgICAgd2hpbGUgKG91dC5sZW5ndGggJSBwYWRkaW5nICE9PSAwKSB7XG4gICAgICAgIG91dCA9ICcwJyArIG91dDtcbiAgICAgIH1cbiAgICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICAgIG91dCA9ICctJyArIG91dDtcbiAgICAgIH1cbiAgICAgIHJldHVybiBvdXQ7XG4gICAgfVxuXG4gICAgYXNzZXJ0KGZhbHNlLCAnQmFzZSBzaG91bGQgYmUgYmV0d2VlbiAyIGFuZCAzNicpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS50b051bWJlciA9IGZ1bmN0aW9uIHRvTnVtYmVyICgpIHtcbiAgICB2YXIgcmV0ID0gdGhpcy53b3Jkc1swXTtcbiAgICBpZiAodGhpcy5sZW5ndGggPT09IDIpIHtcbiAgICAgIHJldCArPSB0aGlzLndvcmRzWzFdICogMHg0MDAwMDAwO1xuICAgIH0gZWxzZSBpZiAodGhpcy5sZW5ndGggPT09IDMgJiYgdGhpcy53b3Jkc1syXSA9PT0gMHgwMSkge1xuICAgICAgLy8gTk9URTogYXQgdGhpcyBzdGFnZSBpdCBpcyBrbm93biB0aGF0IHRoZSB0b3AgYml0IGlzIHNldFxuICAgICAgcmV0ICs9IDB4MTAwMDAwMDAwMDAwMDAgKyAodGhpcy53b3Jkc1sxXSAqIDB4NDAwMDAwMCk7XG4gICAgfSBlbHNlIGlmICh0aGlzLmxlbmd0aCA+IDIpIHtcbiAgICAgIGFzc2VydChmYWxzZSwgJ051bWJlciBjYW4gb25seSBzYWZlbHkgc3RvcmUgdXAgdG8gNTMgYml0cycpO1xuICAgIH1cbiAgICByZXR1cm4gKHRoaXMubmVnYXRpdmUgIT09IDApID8gLXJldCA6IHJldDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24gdG9KU09OICgpIHtcbiAgICByZXR1cm4gdGhpcy50b1N0cmluZygxNik7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnRvQnVmZmVyID0gZnVuY3Rpb24gdG9CdWZmZXIgKGVuZGlhbiwgbGVuZ3RoKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBCdWZmZXIgIT09ICd1bmRlZmluZWQnKTtcbiAgICByZXR1cm4gdGhpcy50b0FycmF5TGlrZShCdWZmZXIsIGVuZGlhbiwgbGVuZ3RoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudG9BcnJheSA9IGZ1bmN0aW9uIHRvQXJyYXkgKGVuZGlhbiwgbGVuZ3RoKSB7XG4gICAgcmV0dXJuIHRoaXMudG9BcnJheUxpa2UoQXJyYXksIGVuZGlhbiwgbGVuZ3RoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudG9BcnJheUxpa2UgPSBmdW5jdGlvbiB0b0FycmF5TGlrZSAoQXJyYXlUeXBlLCBlbmRpYW4sIGxlbmd0aCkge1xuICAgIHZhciBieXRlTGVuZ3RoID0gdGhpcy5ieXRlTGVuZ3RoKCk7XG4gICAgdmFyIHJlcUxlbmd0aCA9IGxlbmd0aCB8fCBNYXRoLm1heCgxLCBieXRlTGVuZ3RoKTtcbiAgICBhc3NlcnQoYnl0ZUxlbmd0aCA8PSByZXFMZW5ndGgsICdieXRlIGFycmF5IGxvbmdlciB0aGFuIGRlc2lyZWQgbGVuZ3RoJyk7XG4gICAgYXNzZXJ0KHJlcUxlbmd0aCA+IDAsICdSZXF1ZXN0ZWQgYXJyYXkgbGVuZ3RoIDw9IDAnKTtcblxuICAgIHRoaXMuc3RyaXAoKTtcbiAgICB2YXIgbGl0dGxlRW5kaWFuID0gZW5kaWFuID09PSAnbGUnO1xuICAgIHZhciByZXMgPSBuZXcgQXJyYXlUeXBlKHJlcUxlbmd0aCk7XG5cbiAgICB2YXIgYiwgaTtcbiAgICB2YXIgcSA9IHRoaXMuY2xvbmUoKTtcbiAgICBpZiAoIWxpdHRsZUVuZGlhbikge1xuICAgICAgLy8gQXNzdW1lIGJpZy1lbmRpYW5cbiAgICAgIGZvciAoaSA9IDA7IGkgPCByZXFMZW5ndGggLSBieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgcmVzW2ldID0gMDtcbiAgICAgIH1cblxuICAgICAgZm9yIChpID0gMDsgIXEuaXNaZXJvKCk7IGkrKykge1xuICAgICAgICBiID0gcS5hbmRsbigweGZmKTtcbiAgICAgICAgcS5pdXNocm4oOCk7XG5cbiAgICAgICAgcmVzW3JlcUxlbmd0aCAtIGkgLSAxXSA9IGI7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGZvciAoaSA9IDA7ICFxLmlzWmVybygpOyBpKyspIHtcbiAgICAgICAgYiA9IHEuYW5kbG4oMHhmZik7XG4gICAgICAgIHEuaXVzaHJuKDgpO1xuXG4gICAgICAgIHJlc1tpXSA9IGI7XG4gICAgICB9XG5cbiAgICAgIGZvciAoOyBpIDwgcmVxTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgcmVzW2ldID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIGlmIChNYXRoLmNsejMyKSB7XG4gICAgQk4ucHJvdG90eXBlLl9jb3VudEJpdHMgPSBmdW5jdGlvbiBfY291bnRCaXRzICh3KSB7XG4gICAgICByZXR1cm4gMzIgLSBNYXRoLmNsejMyKHcpO1xuICAgIH07XG4gIH0gZWxzZSB7XG4gICAgQk4ucHJvdG90eXBlLl9jb3VudEJpdHMgPSBmdW5jdGlvbiBfY291bnRCaXRzICh3KSB7XG4gICAgICB2YXIgdCA9IHc7XG4gICAgICB2YXIgciA9IDA7XG4gICAgICBpZiAodCA+PSAweDEwMDApIHtcbiAgICAgICAgciArPSAxMztcbiAgICAgICAgdCA+Pj49IDEzO1xuICAgICAgfVxuICAgICAgaWYgKHQgPj0gMHg0MCkge1xuICAgICAgICByICs9IDc7XG4gICAgICAgIHQgPj4+PSA3O1xuICAgICAgfVxuICAgICAgaWYgKHQgPj0gMHg4KSB7XG4gICAgICAgIHIgKz0gNDtcbiAgICAgICAgdCA+Pj49IDQ7XG4gICAgICB9XG4gICAgICBpZiAodCA+PSAweDAyKSB7XG4gICAgICAgIHIgKz0gMjtcbiAgICAgICAgdCA+Pj49IDI7XG4gICAgICB9XG4gICAgICByZXR1cm4gciArIHQ7XG4gICAgfTtcbiAgfVxuXG4gIEJOLnByb3RvdHlwZS5femVyb0JpdHMgPSBmdW5jdGlvbiBfemVyb0JpdHMgKHcpIHtcbiAgICAvLyBTaG9ydC1jdXRcbiAgICBpZiAodyA9PT0gMCkgcmV0dXJuIDI2O1xuXG4gICAgdmFyIHQgPSB3O1xuICAgIHZhciByID0gMDtcbiAgICBpZiAoKHQgJiAweDFmZmYpID09PSAwKSB7XG4gICAgICByICs9IDEzO1xuICAgICAgdCA+Pj49IDEzO1xuICAgIH1cbiAgICBpZiAoKHQgJiAweDdmKSA9PT0gMCkge1xuICAgICAgciArPSA3O1xuICAgICAgdCA+Pj49IDc7XG4gICAgfVxuICAgIGlmICgodCAmIDB4ZikgPT09IDApIHtcbiAgICAgIHIgKz0gNDtcbiAgICAgIHQgPj4+PSA0O1xuICAgIH1cbiAgICBpZiAoKHQgJiAweDMpID09PSAwKSB7XG4gICAgICByICs9IDI7XG4gICAgICB0ID4+Pj0gMjtcbiAgICB9XG4gICAgaWYgKCh0ICYgMHgxKSA9PT0gMCkge1xuICAgICAgcisrO1xuICAgIH1cbiAgICByZXR1cm4gcjtcbiAgfTtcblxuICAvLyBSZXR1cm4gbnVtYmVyIG9mIHVzZWQgYml0cyBpbiBhIEJOXG4gIEJOLnByb3RvdHlwZS5iaXRMZW5ndGggPSBmdW5jdGlvbiBiaXRMZW5ndGggKCkge1xuICAgIHZhciB3ID0gdGhpcy53b3Jkc1t0aGlzLmxlbmd0aCAtIDFdO1xuICAgIHZhciBoaSA9IHRoaXMuX2NvdW50Qml0cyh3KTtcbiAgICByZXR1cm4gKHRoaXMubGVuZ3RoIC0gMSkgKiAyNiArIGhpO1xuICB9O1xuXG4gIGZ1bmN0aW9uIHRvQml0QXJyYXkgKG51bSkge1xuICAgIHZhciB3ID0gbmV3IEFycmF5KG51bS5iaXRMZW5ndGgoKSk7XG5cbiAgICBmb3IgKHZhciBiaXQgPSAwOyBiaXQgPCB3Lmxlbmd0aDsgYml0KyspIHtcbiAgICAgIHZhciBvZmYgPSAoYml0IC8gMjYpIHwgMDtcbiAgICAgIHZhciB3Yml0ID0gYml0ICUgMjY7XG5cbiAgICAgIHdbYml0XSA9IChudW0ud29yZHNbb2ZmXSAmICgxIDw8IHdiaXQpKSA+Pj4gd2JpdDtcbiAgICB9XG5cbiAgICByZXR1cm4gdztcbiAgfVxuXG4gIC8vIE51bWJlciBvZiB0cmFpbGluZyB6ZXJvIGJpdHNcbiAgQk4ucHJvdG90eXBlLnplcm9CaXRzID0gZnVuY3Rpb24gemVyb0JpdHMgKCkge1xuICAgIGlmICh0aGlzLmlzWmVybygpKSByZXR1cm4gMDtcblxuICAgIHZhciByID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBiID0gdGhpcy5femVyb0JpdHModGhpcy53b3Jkc1tpXSk7XG4gICAgICByICs9IGI7XG4gICAgICBpZiAoYiAhPT0gMjYpIGJyZWFrO1xuICAgIH1cbiAgICByZXR1cm4gcjtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuYnl0ZUxlbmd0aCA9IGZ1bmN0aW9uIGJ5dGVMZW5ndGggKCkge1xuICAgIHJldHVybiBNYXRoLmNlaWwodGhpcy5iaXRMZW5ndGgoKSAvIDgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS50b1R3b3MgPSBmdW5jdGlvbiB0b1R3b3MgKHdpZHRoKSB7XG4gICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIHJldHVybiB0aGlzLmFicygpLmlub3RuKHdpZHRoKS5pYWRkbigxKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZnJvbVR3b3MgPSBmdW5jdGlvbiBmcm9tVHdvcyAod2lkdGgpIHtcbiAgICBpZiAodGhpcy50ZXN0bih3aWR0aCAtIDEpKSB7XG4gICAgICByZXR1cm4gdGhpcy5ub3RuKHdpZHRoKS5pYWRkbigxKS5pbmVnKCk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmNsb25lKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmlzTmVnID0gZnVuY3Rpb24gaXNOZWcgKCkge1xuICAgIHJldHVybiB0aGlzLm5lZ2F0aXZlICE9PSAwO1xuICB9O1xuXG4gIC8vIFJldHVybiBuZWdhdGl2ZSBjbG9uZSBvZiBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLm5lZyA9IGZ1bmN0aW9uIG5lZyAoKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pbmVnKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmluZWcgPSBmdW5jdGlvbiBpbmVnICgpIHtcbiAgICBpZiAoIXRoaXMuaXNaZXJvKCkpIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgXj0gMTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICAvLyBPciBgbnVtYCB3aXRoIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXVvciA9IGZ1bmN0aW9uIGl1b3IgKG51bSkge1xuICAgIHdoaWxlICh0aGlzLmxlbmd0aCA8IG51bS5sZW5ndGgpIHtcbiAgICAgIHRoaXMud29yZHNbdGhpcy5sZW5ndGgrK10gPSAwO1xuICAgIH1cblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbnVtLmxlbmd0aDsgaSsrKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gdGhpcy53b3Jkc1tpXSB8IG51bS53b3Jkc1tpXTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pb3IgPSBmdW5jdGlvbiBpb3IgKG51bSkge1xuICAgIGFzc2VydCgodGhpcy5uZWdhdGl2ZSB8IG51bS5uZWdhdGl2ZSkgPT09IDApO1xuICAgIHJldHVybiB0aGlzLml1b3IobnVtKTtcbiAgfTtcblxuICAvLyBPciBgbnVtYCB3aXRoIGB0aGlzYFxuICBCTi5wcm90b3R5cGUub3IgPSBmdW5jdGlvbiBvciAobnVtKSB7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkgcmV0dXJuIHRoaXMuY2xvbmUoKS5pb3IobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaW9yKHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS51b3IgPSBmdW5jdGlvbiB1b3IgKG51bSkge1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaXVvcihudW0pO1xuICAgIHJldHVybiBudW0uY2xvbmUoKS5pdW9yKHRoaXMpO1xuICB9O1xuXG4gIC8vIEFuZCBgbnVtYCB3aXRoIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXVhbmQgPSBmdW5jdGlvbiBpdWFuZCAobnVtKSB7XG4gICAgLy8gYiA9IG1pbi1sZW5ndGgobnVtLCB0aGlzKVxuICAgIHZhciBiO1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHtcbiAgICAgIGIgPSBudW07XG4gICAgfSBlbHNlIHtcbiAgICAgIGIgPSB0aGlzO1xuICAgIH1cblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYi5sZW5ndGg7IGkrKykge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IHRoaXMud29yZHNbaV0gJiBudW0ud29yZHNbaV07XG4gICAgfVxuXG4gICAgdGhpcy5sZW5ndGggPSBiLmxlbmd0aDtcblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmlhbmQgPSBmdW5jdGlvbiBpYW5kIChudW0pIHtcbiAgICBhc3NlcnQoKHRoaXMubmVnYXRpdmUgfCBudW0ubmVnYXRpdmUpID09PSAwKTtcbiAgICByZXR1cm4gdGhpcy5pdWFuZChudW0pO1xuICB9O1xuXG4gIC8vIEFuZCBgbnVtYCB3aXRoIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuYW5kID0gZnVuY3Rpb24gYW5kIChudW0pIHtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSByZXR1cm4gdGhpcy5jbG9uZSgpLmlhbmQobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaWFuZCh0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudWFuZCA9IGZ1bmN0aW9uIHVhbmQgKG51bSkge1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaXVhbmQobnVtKTtcbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaXVhbmQodGhpcyk7XG4gIH07XG5cbiAgLy8gWG9yIGBudW1gIHdpdGggYHRoaXNgIGluLXBsYWNlXG4gIEJOLnByb3RvdHlwZS5pdXhvciA9IGZ1bmN0aW9uIGl1eG9yIChudW0pIHtcbiAgICAvLyBhLmxlbmd0aCA+IGIubGVuZ3RoXG4gICAgdmFyIGE7XG4gICAgdmFyIGI7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkge1xuICAgICAgYSA9IHRoaXM7XG4gICAgICBiID0gbnVtO1xuICAgIH0gZWxzZSB7XG4gICAgICBhID0gbnVtO1xuICAgICAgYiA9IHRoaXM7XG4gICAgfVxuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBiLmxlbmd0aDsgaSsrKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gYS53b3Jkc1tpXSBeIGIud29yZHNbaV07XG4gICAgfVxuXG4gICAgaWYgKHRoaXMgIT09IGEpIHtcbiAgICAgIGZvciAoOyBpIDwgYS5sZW5ndGg7IGkrKykge1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gYS53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aGlzLmxlbmd0aCA9IGEubGVuZ3RoO1xuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXhvciA9IGZ1bmN0aW9uIGl4b3IgKG51bSkge1xuICAgIGFzc2VydCgodGhpcy5uZWdhdGl2ZSB8IG51bS5uZWdhdGl2ZSkgPT09IDApO1xuICAgIHJldHVybiB0aGlzLml1eG9yKG51bSk7XG4gIH07XG5cbiAgLy8gWG9yIGBudW1gIHdpdGggYHRoaXNgXG4gIEJOLnByb3RvdHlwZS54b3IgPSBmdW5jdGlvbiB4b3IgKG51bSkge1xuICAgIGlmICh0aGlzLmxlbmd0aCA+IG51bS5sZW5ndGgpIHJldHVybiB0aGlzLmNsb25lKCkuaXhvcihudW0pO1xuICAgIHJldHVybiBudW0uY2xvbmUoKS5peG9yKHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS51eG9yID0gZnVuY3Rpb24gdXhvciAobnVtKSB7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkgcmV0dXJuIHRoaXMuY2xvbmUoKS5pdXhvcihudW0pO1xuICAgIHJldHVybiBudW0uY2xvbmUoKS5pdXhvcih0aGlzKTtcbiAgfTtcblxuICAvLyBOb3QgYGB0aGlzYGAgd2l0aCBgYHdpZHRoYGAgYml0d2lkdGhcbiAgQk4ucHJvdG90eXBlLmlub3RuID0gZnVuY3Rpb24gaW5vdG4gKHdpZHRoKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiB3aWR0aCA9PT0gJ251bWJlcicgJiYgd2lkdGggPj0gMCk7XG5cbiAgICB2YXIgYnl0ZXNOZWVkZWQgPSBNYXRoLmNlaWwod2lkdGggLyAyNikgfCAwO1xuICAgIHZhciBiaXRzTGVmdCA9IHdpZHRoICUgMjY7XG5cbiAgICAvLyBFeHRlbmQgdGhlIGJ1ZmZlciB3aXRoIGxlYWRpbmcgemVyb2VzXG4gICAgdGhpcy5fZXhwYW5kKGJ5dGVzTmVlZGVkKTtcblxuICAgIGlmIChiaXRzTGVmdCA+IDApIHtcbiAgICAgIGJ5dGVzTmVlZGVkLS07XG4gICAgfVxuXG4gICAgLy8gSGFuZGxlIGNvbXBsZXRlIHdvcmRzXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlc05lZWRlZDsgaSsrKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gfnRoaXMud29yZHNbaV0gJiAweDNmZmZmZmY7XG4gICAgfVxuXG4gICAgLy8gSGFuZGxlIHRoZSByZXNpZHVlXG4gICAgaWYgKGJpdHNMZWZ0ID4gMCkge1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IH50aGlzLndvcmRzW2ldICYgKDB4M2ZmZmZmZiA+PiAoMjYgLSBiaXRzTGVmdCkpO1xuICAgIH1cblxuICAgIC8vIEFuZCByZW1vdmUgbGVhZGluZyB6ZXJvZXNcbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5ub3RuID0gZnVuY3Rpb24gbm90biAod2lkdGgpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlub3RuKHdpZHRoKTtcbiAgfTtcblxuICAvLyBTZXQgYGJpdGAgb2YgYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5zZXRuID0gZnVuY3Rpb24gc2V0biAoYml0LCB2YWwpIHtcbiAgICBhc3NlcnQodHlwZW9mIGJpdCA9PT0gJ251bWJlcicgJiYgYml0ID49IDApO1xuXG4gICAgdmFyIG9mZiA9IChiaXQgLyAyNikgfCAwO1xuICAgIHZhciB3Yml0ID0gYml0ICUgMjY7XG5cbiAgICB0aGlzLl9leHBhbmQob2ZmICsgMSk7XG5cbiAgICBpZiAodmFsKSB7XG4gICAgICB0aGlzLndvcmRzW29mZl0gPSB0aGlzLndvcmRzW29mZl0gfCAoMSA8PCB3Yml0KTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy53b3Jkc1tvZmZdID0gdGhpcy53b3Jkc1tvZmZdICYgfigxIDw8IHdiaXQpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgLy8gQWRkIGBudW1gIHRvIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaWFkZCA9IGZ1bmN0aW9uIGlhZGQgKG51bSkge1xuICAgIHZhciByO1xuXG4gICAgLy8gbmVnYXRpdmUgKyBwb3NpdGl2ZVxuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwICYmIG51bS5uZWdhdGl2ZSA9PT0gMCkge1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDA7XG4gICAgICByID0gdGhpcy5pc3ViKG51bSk7XG4gICAgICB0aGlzLm5lZ2F0aXZlIF49IDE7XG4gICAgICByZXR1cm4gdGhpcy5fbm9ybVNpZ24oKTtcblxuICAgIC8vIHBvc2l0aXZlICsgbmVnYXRpdmVcbiAgICB9IGVsc2UgaWYgKHRoaXMubmVnYXRpdmUgPT09IDAgJiYgbnVtLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICBudW0ubmVnYXRpdmUgPSAwO1xuICAgICAgciA9IHRoaXMuaXN1YihudW0pO1xuICAgICAgbnVtLm5lZ2F0aXZlID0gMTtcbiAgICAgIHJldHVybiByLl9ub3JtU2lnbigpO1xuICAgIH1cblxuICAgIC8vIGEubGVuZ3RoID4gYi5sZW5ndGhcbiAgICB2YXIgYSwgYjtcbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSB7XG4gICAgICBhID0gdGhpcztcbiAgICAgIGIgPSBudW07XG4gICAgfSBlbHNlIHtcbiAgICAgIGEgPSBudW07XG4gICAgICBiID0gdGhpcztcbiAgICB9XG5cbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYi5sZW5ndGg7IGkrKykge1xuICAgICAgciA9IChhLndvcmRzW2ldIHwgMCkgKyAoYi53b3Jkc1tpXSB8IDApICsgY2Fycnk7XG4gICAgICB0aGlzLndvcmRzW2ldID0gciAmIDB4M2ZmZmZmZjtcbiAgICAgIGNhcnJ5ID0gciA+Pj4gMjY7XG4gICAgfVxuICAgIGZvciAoOyBjYXJyeSAhPT0gMCAmJiBpIDwgYS5sZW5ndGg7IGkrKykge1xuICAgICAgciA9IChhLndvcmRzW2ldIHwgMCkgKyBjYXJyeTtcbiAgICAgIHRoaXMud29yZHNbaV0gPSByICYgMHgzZmZmZmZmO1xuICAgICAgY2FycnkgPSByID4+PiAyNjtcbiAgICB9XG5cbiAgICB0aGlzLmxlbmd0aCA9IGEubGVuZ3RoO1xuICAgIGlmIChjYXJyeSAhPT0gMCkge1xuICAgICAgdGhpcy53b3Jkc1t0aGlzLmxlbmd0aF0gPSBjYXJyeTtcbiAgICAgIHRoaXMubGVuZ3RoKys7XG4gICAgLy8gQ29weSB0aGUgcmVzdCBvZiB0aGUgd29yZHNcbiAgICB9IGVsc2UgaWYgKGEgIT09IHRoaXMpIHtcbiAgICAgIGZvciAoOyBpIDwgYS5sZW5ndGg7IGkrKykge1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gYS53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICAvLyBBZGQgYG51bWAgdG8gYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5hZGQgPSBmdW5jdGlvbiBhZGQgKG51bSkge1xuICAgIHZhciByZXM7XG4gICAgaWYgKG51bS5uZWdhdGl2ZSAhPT0gMCAmJiB0aGlzLm5lZ2F0aXZlID09PSAwKSB7XG4gICAgICBudW0ubmVnYXRpdmUgPSAwO1xuICAgICAgcmVzID0gdGhpcy5zdWIobnVtKTtcbiAgICAgIG51bS5uZWdhdGl2ZSBePSAxO1xuICAgICAgcmV0dXJuIHJlcztcbiAgICB9IGVsc2UgaWYgKG51bS5uZWdhdGl2ZSA9PT0gMCAmJiB0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgIHJlcyA9IG51bS5zdWIodGhpcyk7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICAgIHJldHVybiByZXM7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubGVuZ3RoID4gbnVtLmxlbmd0aCkgcmV0dXJuIHRoaXMuY2xvbmUoKS5pYWRkKG51bSk7XG5cbiAgICByZXR1cm4gbnVtLmNsb25lKCkuaWFkZCh0aGlzKTtcbiAgfTtcblxuICAvLyBTdWJ0cmFjdCBgbnVtYCBmcm9tIGB0aGlzYCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXN1YiA9IGZ1bmN0aW9uIGlzdWIgKG51bSkge1xuICAgIC8vIHRoaXMgLSAoLW51bSkgPSB0aGlzICsgbnVtXG4gICAgaWYgKG51bS5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgbnVtLm5lZ2F0aXZlID0gMDtcbiAgICAgIHZhciByID0gdGhpcy5pYWRkKG51bSk7XG4gICAgICBudW0ubmVnYXRpdmUgPSAxO1xuICAgICAgcmV0dXJuIHIuX25vcm1TaWduKCk7XG5cbiAgICAvLyAtdGhpcyAtIG51bSA9IC0odGhpcyArIG51bSlcbiAgICB9IGVsc2UgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAwO1xuICAgICAgdGhpcy5pYWRkKG51bSk7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMTtcbiAgICAgIHJldHVybiB0aGlzLl9ub3JtU2lnbigpO1xuICAgIH1cblxuICAgIC8vIEF0IHRoaXMgcG9pbnQgYm90aCBudW1iZXJzIGFyZSBwb3NpdGl2ZVxuICAgIHZhciBjbXAgPSB0aGlzLmNtcChudW0pO1xuXG4gICAgLy8gT3B0aW1pemF0aW9uIC0gemVyb2lmeVxuICAgIGlmIChjbXAgPT09IDApIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAwO1xuICAgICAgdGhpcy5sZW5ndGggPSAxO1xuICAgICAgdGhpcy53b3Jkc1swXSA9IDA7XG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG5cbiAgICAvLyBhID4gYlxuICAgIHZhciBhLCBiO1xuICAgIGlmIChjbXAgPiAwKSB7XG4gICAgICBhID0gdGhpcztcbiAgICAgIGIgPSBudW07XG4gICAgfSBlbHNlIHtcbiAgICAgIGEgPSBudW07XG4gICAgICBiID0gdGhpcztcbiAgICB9XG5cbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYi5sZW5ndGg7IGkrKykge1xuICAgICAgciA9IChhLndvcmRzW2ldIHwgMCkgLSAoYi53b3Jkc1tpXSB8IDApICsgY2Fycnk7XG4gICAgICBjYXJyeSA9IHIgPj4gMjY7XG4gICAgICB0aGlzLndvcmRzW2ldID0gciAmIDB4M2ZmZmZmZjtcbiAgICB9XG4gICAgZm9yICg7IGNhcnJ5ICE9PSAwICYmIGkgPCBhLmxlbmd0aDsgaSsrKSB7XG4gICAgICByID0gKGEud29yZHNbaV0gfCAwKSArIGNhcnJ5O1xuICAgICAgY2FycnkgPSByID4+IDI2O1xuICAgICAgdGhpcy53b3Jkc1tpXSA9IHIgJiAweDNmZmZmZmY7XG4gICAgfVxuXG4gICAgLy8gQ29weSByZXN0IG9mIHRoZSB3b3Jkc1xuICAgIGlmIChjYXJyeSA9PT0gMCAmJiBpIDwgYS5sZW5ndGggJiYgYSAhPT0gdGhpcykge1xuICAgICAgZm9yICg7IGkgPCBhLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHRoaXMud29yZHNbaV0gPSBhLndvcmRzW2ldO1xuICAgICAgfVxuICAgIH1cblxuICAgIHRoaXMubGVuZ3RoID0gTWF0aC5tYXgodGhpcy5sZW5ndGgsIGkpO1xuXG4gICAgaWYgKGEgIT09IHRoaXMpIHtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAxO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgLy8gU3VidHJhY3QgYG51bWAgZnJvbSBgdGhpc2BcbiAgQk4ucHJvdG90eXBlLnN1YiA9IGZ1bmN0aW9uIHN1YiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pc3ViKG51bSk7XG4gIH07XG5cbiAgZnVuY3Rpb24gc21hbGxNdWxUbyAoc2VsZiwgbnVtLCBvdXQpIHtcbiAgICBvdXQubmVnYXRpdmUgPSBudW0ubmVnYXRpdmUgXiBzZWxmLm5lZ2F0aXZlO1xuICAgIHZhciBsZW4gPSAoc2VsZi5sZW5ndGggKyBudW0ubGVuZ3RoKSB8IDA7XG4gICAgb3V0Lmxlbmd0aCA9IGxlbjtcbiAgICBsZW4gPSAobGVuIC0gMSkgfCAwO1xuXG4gICAgLy8gUGVlbCBvbmUgaXRlcmF0aW9uIChjb21waWxlciBjYW4ndCBkbyBpdCwgYmVjYXVzZSBvZiBjb2RlIGNvbXBsZXhpdHkpXG4gICAgdmFyIGEgPSBzZWxmLndvcmRzWzBdIHwgMDtcbiAgICB2YXIgYiA9IG51bS53b3Jkc1swXSB8IDA7XG4gICAgdmFyIHIgPSBhICogYjtcblxuICAgIHZhciBsbyA9IHIgJiAweDNmZmZmZmY7XG4gICAgdmFyIGNhcnJ5ID0gKHIgLyAweDQwMDAwMDApIHwgMDtcbiAgICBvdXQud29yZHNbMF0gPSBsbztcblxuICAgIGZvciAodmFyIGsgPSAxOyBrIDwgbGVuOyBrKyspIHtcbiAgICAgIC8vIFN1bSBhbGwgd29yZHMgd2l0aCB0aGUgc2FtZSBgaSArIGogPSBrYCBhbmQgYWNjdW11bGF0ZSBgbmNhcnJ5YCxcbiAgICAgIC8vIG5vdGUgdGhhdCBuY2FycnkgY291bGQgYmUgPj0gMHgzZmZmZmZmXG4gICAgICB2YXIgbmNhcnJ5ID0gY2FycnkgPj4+IDI2O1xuICAgICAgdmFyIHJ3b3JkID0gY2FycnkgJiAweDNmZmZmZmY7XG4gICAgICB2YXIgbWF4SiA9IE1hdGgubWluKGssIG51bS5sZW5ndGggLSAxKTtcbiAgICAgIGZvciAodmFyIGogPSBNYXRoLm1heCgwLCBrIC0gc2VsZi5sZW5ndGggKyAxKTsgaiA8PSBtYXhKOyBqKyspIHtcbiAgICAgICAgdmFyIGkgPSAoayAtIGopIHwgMDtcbiAgICAgICAgYSA9IHNlbGYud29yZHNbaV0gfCAwO1xuICAgICAgICBiID0gbnVtLndvcmRzW2pdIHwgMDtcbiAgICAgICAgciA9IGEgKiBiICsgcndvcmQ7XG4gICAgICAgIG5jYXJyeSArPSAociAvIDB4NDAwMDAwMCkgfCAwO1xuICAgICAgICByd29yZCA9IHIgJiAweDNmZmZmZmY7XG4gICAgICB9XG4gICAgICBvdXQud29yZHNba10gPSByd29yZCB8IDA7XG4gICAgICBjYXJyeSA9IG5jYXJyeSB8IDA7XG4gICAgfVxuICAgIGlmIChjYXJyeSAhPT0gMCkge1xuICAgICAgb3V0LndvcmRzW2tdID0gY2FycnkgfCAwO1xuICAgIH0gZWxzZSB7XG4gICAgICBvdXQubGVuZ3RoLS07XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dC5zdHJpcCgpO1xuICB9XG5cbiAgLy8gVE9ETyhpbmR1dG55KTogaXQgbWF5IGJlIHJlYXNvbmFibGUgdG8gb21pdCBpdCBmb3IgdXNlcnMgd2hvIGRvbid0IG5lZWRcbiAgLy8gdG8gd29yayB3aXRoIDI1Ni1iaXQgbnVtYmVycywgb3RoZXJ3aXNlIGl0IGdpdmVzIDIwJSBpbXByb3ZlbWVudCBmb3IgMjU2LWJpdFxuICAvLyBtdWx0aXBsaWNhdGlvbiAobGlrZSBlbGxpcHRpYyBzZWNwMjU2azEpLlxuICB2YXIgY29tYjEwTXVsVG8gPSBmdW5jdGlvbiBjb21iMTBNdWxUbyAoc2VsZiwgbnVtLCBvdXQpIHtcbiAgICB2YXIgYSA9IHNlbGYud29yZHM7XG4gICAgdmFyIGIgPSBudW0ud29yZHM7XG4gICAgdmFyIG8gPSBvdXQud29yZHM7XG4gICAgdmFyIGMgPSAwO1xuICAgIHZhciBsbztcbiAgICB2YXIgbWlkO1xuICAgIHZhciBoaTtcbiAgICB2YXIgYTAgPSBhWzBdIHwgMDtcbiAgICB2YXIgYWwwID0gYTAgJiAweDFmZmY7XG4gICAgdmFyIGFoMCA9IGEwID4+PiAxMztcbiAgICB2YXIgYTEgPSBhWzFdIHwgMDtcbiAgICB2YXIgYWwxID0gYTEgJiAweDFmZmY7XG4gICAgdmFyIGFoMSA9IGExID4+PiAxMztcbiAgICB2YXIgYTIgPSBhWzJdIHwgMDtcbiAgICB2YXIgYWwyID0gYTIgJiAweDFmZmY7XG4gICAgdmFyIGFoMiA9IGEyID4+PiAxMztcbiAgICB2YXIgYTMgPSBhWzNdIHwgMDtcbiAgICB2YXIgYWwzID0gYTMgJiAweDFmZmY7XG4gICAgdmFyIGFoMyA9IGEzID4+PiAxMztcbiAgICB2YXIgYTQgPSBhWzRdIHwgMDtcbiAgICB2YXIgYWw0ID0gYTQgJiAweDFmZmY7XG4gICAgdmFyIGFoNCA9IGE0ID4+PiAxMztcbiAgICB2YXIgYTUgPSBhWzVdIHwgMDtcbiAgICB2YXIgYWw1ID0gYTUgJiAweDFmZmY7XG4gICAgdmFyIGFoNSA9IGE1ID4+PiAxMztcbiAgICB2YXIgYTYgPSBhWzZdIHwgMDtcbiAgICB2YXIgYWw2ID0gYTYgJiAweDFmZmY7XG4gICAgdmFyIGFoNiA9IGE2ID4+PiAxMztcbiAgICB2YXIgYTcgPSBhWzddIHwgMDtcbiAgICB2YXIgYWw3ID0gYTcgJiAweDFmZmY7XG4gICAgdmFyIGFoNyA9IGE3ID4+PiAxMztcbiAgICB2YXIgYTggPSBhWzhdIHwgMDtcbiAgICB2YXIgYWw4ID0gYTggJiAweDFmZmY7XG4gICAgdmFyIGFoOCA9IGE4ID4+PiAxMztcbiAgICB2YXIgYTkgPSBhWzldIHwgMDtcbiAgICB2YXIgYWw5ID0gYTkgJiAweDFmZmY7XG4gICAgdmFyIGFoOSA9IGE5ID4+PiAxMztcbiAgICB2YXIgYjAgPSBiWzBdIHwgMDtcbiAgICB2YXIgYmwwID0gYjAgJiAweDFmZmY7XG4gICAgdmFyIGJoMCA9IGIwID4+PiAxMztcbiAgICB2YXIgYjEgPSBiWzFdIHwgMDtcbiAgICB2YXIgYmwxID0gYjEgJiAweDFmZmY7XG4gICAgdmFyIGJoMSA9IGIxID4+PiAxMztcbiAgICB2YXIgYjIgPSBiWzJdIHwgMDtcbiAgICB2YXIgYmwyID0gYjIgJiAweDFmZmY7XG4gICAgdmFyIGJoMiA9IGIyID4+PiAxMztcbiAgICB2YXIgYjMgPSBiWzNdIHwgMDtcbiAgICB2YXIgYmwzID0gYjMgJiAweDFmZmY7XG4gICAgdmFyIGJoMyA9IGIzID4+PiAxMztcbiAgICB2YXIgYjQgPSBiWzRdIHwgMDtcbiAgICB2YXIgYmw0ID0gYjQgJiAweDFmZmY7XG4gICAgdmFyIGJoNCA9IGI0ID4+PiAxMztcbiAgICB2YXIgYjUgPSBiWzVdIHwgMDtcbiAgICB2YXIgYmw1ID0gYjUgJiAweDFmZmY7XG4gICAgdmFyIGJoNSA9IGI1ID4+PiAxMztcbiAgICB2YXIgYjYgPSBiWzZdIHwgMDtcbiAgICB2YXIgYmw2ID0gYjYgJiAweDFmZmY7XG4gICAgdmFyIGJoNiA9IGI2ID4+PiAxMztcbiAgICB2YXIgYjcgPSBiWzddIHwgMDtcbiAgICB2YXIgYmw3ID0gYjcgJiAweDFmZmY7XG4gICAgdmFyIGJoNyA9IGI3ID4+PiAxMztcbiAgICB2YXIgYjggPSBiWzhdIHwgMDtcbiAgICB2YXIgYmw4ID0gYjggJiAweDFmZmY7XG4gICAgdmFyIGJoOCA9IGI4ID4+PiAxMztcbiAgICB2YXIgYjkgPSBiWzldIHwgMDtcbiAgICB2YXIgYmw5ID0gYjkgJiAweDFmZmY7XG4gICAgdmFyIGJoOSA9IGI5ID4+PiAxMztcblxuICAgIG91dC5uZWdhdGl2ZSA9IHNlbGYubmVnYXRpdmUgXiBudW0ubmVnYXRpdmU7XG4gICAgb3V0Lmxlbmd0aCA9IDE5O1xuICAgIC8qIGsgPSAwICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWwwLCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDAsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWgwLCBiaDApO1xuICAgIHZhciB3MCA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHcwID4+PiAyNik7XG4gICAgdzAgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWwxLCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDEsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDEsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWgxLCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmgxKTtcbiAgICB2YXIgdzEgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MSA+Pj4gMjYpO1xuICAgIHcxICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gMiAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsMiwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWwyLCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoMiwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDIpO1xuICAgIHZhciB3MiA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHcyID4+PiAyNik7XG4gICAgdzIgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAzICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWwzLCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDMsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWgzLCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDIsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDIsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDIsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMiwgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDMpO1xuICAgIHZhciB3MyA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHczID4+PiAyNik7XG4gICAgdzMgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSA0ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw0LCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDQsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDQsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg0LCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg0KTtcbiAgICB2YXIgdzQgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3NCA+Pj4gMjYpO1xuICAgIHc0ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gNSAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsNSwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw1LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoNSwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw0LCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw0LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDQsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMywgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMywgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMywgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgzLCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDIsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDIsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDIsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMiwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDUpO1xuICAgIHZhciB3NSA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHc1ID4+PiAyNik7XG4gICAgdzUgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSA2ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw2LCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDYsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg2LCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDUsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDUsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDUsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNSwgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw0LCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw0LCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDQsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMywgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMywgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMywgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgzLCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDIsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDIsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDIsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMiwgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDYpO1xuICAgIHZhciB3NiA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHc2ID4+PiAyNik7XG4gICAgdzYgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSA3ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw3LCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDcsIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDcsIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg3LCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDAsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDAsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDAsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMCwgYmg3KTtcbiAgICB2YXIgdzcgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3NyA+Pj4gMjYpO1xuICAgIHc3ICY9IDB4M2ZmZmZmZjtcbiAgICAvKiBrID0gOCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOCwgYmwwKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw4LCBiaDApO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDApO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOCwgYmgwKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw3LCBibDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw3LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg3LCBibDEpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDcsIGJoMSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNiwgYmwyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNiwgYmgyKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNiwgYmwyKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg2LCBiaDIpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDUsIGJsMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDUsIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDUsIGJsMyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNSwgYmgzKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw0LCBibDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw0LCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDQpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDQsIGJoNCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMywgYmw1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMywgYmg1KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMywgYmw1KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgzLCBiaDUpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDIsIGJsNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDIsIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDIsIGJsNik7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMiwgYmg2KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDcpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoNyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmw4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmg4KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmw4KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDgpO1xuICAgIHZhciB3OCA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHc4ID4+PiAyNik7XG4gICAgdzggJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSA5ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw5LCBibDApO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDksIGJoMCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDksIGJsMCk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg5LCBiaDApO1xuICAgIGxvICs9IE1hdGguaW11bChhbDgsIGJsMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDgsIGJoMSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDgsIGJsMSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoOCwgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw3LCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw3LCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg3LCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDcsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNiwgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNiwgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNiwgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg2LCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDUsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDUsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDUsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNSwgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw0LCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw0LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDQsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMywgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMywgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMywgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgzLCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDIsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDIsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDIsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMiwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwxLCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwxLCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgxLCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDEsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMCwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMCwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMCwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgwLCBiaDkpO1xuICAgIHZhciB3OSA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHc5ID4+PiAyNik7XG4gICAgdzkgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxMCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmwxKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDEpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDEpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmgxKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDIpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoMik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmwzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmgzKTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmwzKTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMSwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMSwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMSwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgxLCBiaDkpO1xuICAgIHZhciB3MTAgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTAgPj4+IDI2KTtcbiAgICB3MTAgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxMSAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmwyKTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDIpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDIpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmgyKTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDMpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDMpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoMyk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg0KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw0KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDQpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoNSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsNSk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg1KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDYpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoNik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw3KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDcpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDMsIGJsOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDMsIGJoOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDMsIGJsOCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoMywgYmg4KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWwyLCBibDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWwyLCBiaDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWgyLCBibDkpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDIsIGJoOSk7XG4gICAgdmFyIHcxMSA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHcxMSA+Pj4gMjYpO1xuICAgIHcxMSAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDEyICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw5LCBibDMpO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDksIGJoMyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDksIGJsMyk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg5LCBiaDMpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDgsIGJsNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDgsIGJoNCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDgsIGJsNCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoOCwgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw3LCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw3LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg3LCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDcsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNiwgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNiwgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNiwgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg2LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDUsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDUsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDUsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNSwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw0LCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw0LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg0LCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDQsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsMywgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsMywgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoMywgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWgzLCBiaDkpO1xuICAgIHZhciB3MTIgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTIgPj4+IDI2KTtcbiAgICB3MTIgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxMyAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw0KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDQpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDQpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg0KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDUpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoNSk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg2KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw2KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNCwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNCwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNCwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg0LCBiaDkpO1xuICAgIHZhciB3MTMgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTMgPj4+IDI2KTtcbiAgICB3MTMgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxNCAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw1KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDUpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDUpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg1KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDYpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDYpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoNik7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg3KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw3KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDcpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDYsIGJsOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDYsIGJoOCk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDYsIGJsOCk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoNiwgYmg4KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw1LCBibDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw1LCBiaDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg1LCBibDkpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDUsIGJoOSk7XG4gICAgdmFyIHcxNCA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHcxNCA+Pj4gMjYpO1xuICAgIHcxNCAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDE1ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw5LCBibDYpO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDksIGJoNik7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDksIGJsNik7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg5LCBiaDYpO1xuICAgIGxvICs9IE1hdGguaW11bChhbDgsIGJsNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhbDgsIGJoNyk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDgsIGJsNyk7XG4gICAgaGkgKz0gTWF0aC5pbXVsKGFoOCwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw3LCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw3LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg3LCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDcsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNiwgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNiwgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNiwgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg2LCBiaDkpO1xuICAgIHZhciB3MTUgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTUgPj4+IDI2KTtcbiAgICB3MTUgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxNiAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw3KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDcpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDcpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg3KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDgpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoOCk7XG4gICAgbG8gKz0gTWF0aC5pbXVsKGFsNywgYmw5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFsNywgYmg5KTtcbiAgICBtaWQgKz0gTWF0aC5pbXVsKGFoNywgYmw5KTtcbiAgICBoaSArPSBNYXRoLmltdWwoYWg3LCBiaDkpO1xuICAgIHZhciB3MTYgPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTYgPj4+IDI2KTtcbiAgICB3MTYgJj0gMHgzZmZmZmZmO1xuICAgIC8qIGsgPSAxNyAqL1xuICAgIGxvID0gTWF0aC5pbXVsKGFsOSwgYmw4KTtcbiAgICBtaWQgPSBNYXRoLmltdWwoYWw5LCBiaDgpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg5LCBibDgpO1xuICAgIGhpID0gTWF0aC5pbXVsKGFoOSwgYmg4KTtcbiAgICBsbyArPSBNYXRoLmltdWwoYWw4LCBibDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWw4LCBiaDkpO1xuICAgIG1pZCArPSBNYXRoLmltdWwoYWg4LCBibDkpO1xuICAgIGhpICs9IE1hdGguaW11bChhaDgsIGJoOSk7XG4gICAgdmFyIHcxNyA9IGMgKyBsbyArICgobWlkICYgMHgxZmZmKSA8PCAxMyk7XG4gICAgYyA9IGhpICsgKG1pZCA+Pj4gMTMpICsgKHcxNyA+Pj4gMjYpO1xuICAgIHcxNyAmPSAweDNmZmZmZmY7XG4gICAgLyogayA9IDE4ICovXG4gICAgbG8gPSBNYXRoLmltdWwoYWw5LCBibDkpO1xuICAgIG1pZCA9IE1hdGguaW11bChhbDksIGJoOSk7XG4gICAgbWlkICs9IE1hdGguaW11bChhaDksIGJsOSk7XG4gICAgaGkgPSBNYXRoLmltdWwoYWg5LCBiaDkpO1xuICAgIHZhciB3MTggPSBjICsgbG8gKyAoKG1pZCAmIDB4MWZmZikgPDwgMTMpO1xuICAgIGMgPSBoaSArIChtaWQgPj4+IDEzKSArICh3MTggPj4+IDI2KTtcbiAgICB3MTggJj0gMHgzZmZmZmZmO1xuICAgIG9bMF0gPSB3MDtcbiAgICBvWzFdID0gdzE7XG4gICAgb1syXSA9IHcyO1xuICAgIG9bM10gPSB3MztcbiAgICBvWzRdID0gdzQ7XG4gICAgb1s1XSA9IHc1O1xuICAgIG9bNl0gPSB3NjtcbiAgICBvWzddID0gdzc7XG4gICAgb1s4XSA9IHc4O1xuICAgIG9bOV0gPSB3OTtcbiAgICBvWzEwXSA9IHcxMDtcbiAgICBvWzExXSA9IHcxMTtcbiAgICBvWzEyXSA9IHcxMjtcbiAgICBvWzEzXSA9IHcxMztcbiAgICBvWzE0XSA9IHcxNDtcbiAgICBvWzE1XSA9IHcxNTtcbiAgICBvWzE2XSA9IHcxNjtcbiAgICBvWzE3XSA9IHcxNztcbiAgICBvWzE4XSA9IHcxODtcbiAgICBpZiAoYyAhPT0gMCkge1xuICAgICAgb1sxOV0gPSBjO1xuICAgICAgb3V0Lmxlbmd0aCsrO1xuICAgIH1cbiAgICByZXR1cm4gb3V0O1xuICB9O1xuXG4gIC8vIFBvbHlmaWxsIGNvbWJcbiAgaWYgKCFNYXRoLmltdWwpIHtcbiAgICBjb21iMTBNdWxUbyA9IHNtYWxsTXVsVG87XG4gIH1cblxuICBmdW5jdGlvbiBiaWdNdWxUbyAoc2VsZiwgbnVtLCBvdXQpIHtcbiAgICBvdXQubmVnYXRpdmUgPSBudW0ubmVnYXRpdmUgXiBzZWxmLm5lZ2F0aXZlO1xuICAgIG91dC5sZW5ndGggPSBzZWxmLmxlbmd0aCArIG51bS5sZW5ndGg7XG5cbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIHZhciBobmNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBrID0gMDsgayA8IG91dC5sZW5ndGggLSAxOyBrKyspIHtcbiAgICAgIC8vIFN1bSBhbGwgd29yZHMgd2l0aCB0aGUgc2FtZSBgaSArIGogPSBrYCBhbmQgYWNjdW11bGF0ZSBgbmNhcnJ5YCxcbiAgICAgIC8vIG5vdGUgdGhhdCBuY2FycnkgY291bGQgYmUgPj0gMHgzZmZmZmZmXG4gICAgICB2YXIgbmNhcnJ5ID0gaG5jYXJyeTtcbiAgICAgIGhuY2FycnkgPSAwO1xuICAgICAgdmFyIHJ3b3JkID0gY2FycnkgJiAweDNmZmZmZmY7XG4gICAgICB2YXIgbWF4SiA9IE1hdGgubWluKGssIG51bS5sZW5ndGggLSAxKTtcbiAgICAgIGZvciAodmFyIGogPSBNYXRoLm1heCgwLCBrIC0gc2VsZi5sZW5ndGggKyAxKTsgaiA8PSBtYXhKOyBqKyspIHtcbiAgICAgICAgdmFyIGkgPSBrIC0gajtcbiAgICAgICAgdmFyIGEgPSBzZWxmLndvcmRzW2ldIHwgMDtcbiAgICAgICAgdmFyIGIgPSBudW0ud29yZHNbal0gfCAwO1xuICAgICAgICB2YXIgciA9IGEgKiBiO1xuXG4gICAgICAgIHZhciBsbyA9IHIgJiAweDNmZmZmZmY7XG4gICAgICAgIG5jYXJyeSA9IChuY2FycnkgKyAoKHIgLyAweDQwMDAwMDApIHwgMCkpIHwgMDtcbiAgICAgICAgbG8gPSAobG8gKyByd29yZCkgfCAwO1xuICAgICAgICByd29yZCA9IGxvICYgMHgzZmZmZmZmO1xuICAgICAgICBuY2FycnkgPSAobmNhcnJ5ICsgKGxvID4+PiAyNikpIHwgMDtcblxuICAgICAgICBobmNhcnJ5ICs9IG5jYXJyeSA+Pj4gMjY7XG4gICAgICAgIG5jYXJyeSAmPSAweDNmZmZmZmY7XG4gICAgICB9XG4gICAgICBvdXQud29yZHNba10gPSByd29yZDtcbiAgICAgIGNhcnJ5ID0gbmNhcnJ5O1xuICAgICAgbmNhcnJ5ID0gaG5jYXJyeTtcbiAgICB9XG4gICAgaWYgKGNhcnJ5ICE9PSAwKSB7XG4gICAgICBvdXQud29yZHNba10gPSBjYXJyeTtcbiAgICB9IGVsc2Uge1xuICAgICAgb3V0Lmxlbmd0aC0tO1xuICAgIH1cblxuICAgIHJldHVybiBvdXQuc3RyaXAoKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGp1bWJvTXVsVG8gKHNlbGYsIG51bSwgb3V0KSB7XG4gICAgdmFyIGZmdG0gPSBuZXcgRkZUTSgpO1xuICAgIHJldHVybiBmZnRtLm11bHAoc2VsZiwgbnVtLCBvdXQpO1xuICB9XG5cbiAgQk4ucHJvdG90eXBlLm11bFRvID0gZnVuY3Rpb24gbXVsVG8gKG51bSwgb3V0KSB7XG4gICAgdmFyIHJlcztcbiAgICB2YXIgbGVuID0gdGhpcy5sZW5ndGggKyBudW0ubGVuZ3RoO1xuICAgIGlmICh0aGlzLmxlbmd0aCA9PT0gMTAgJiYgbnVtLmxlbmd0aCA9PT0gMTApIHtcbiAgICAgIHJlcyA9IGNvbWIxME11bFRvKHRoaXMsIG51bSwgb3V0KTtcbiAgICB9IGVsc2UgaWYgKGxlbiA8IDYzKSB7XG4gICAgICByZXMgPSBzbWFsbE11bFRvKHRoaXMsIG51bSwgb3V0KTtcbiAgICB9IGVsc2UgaWYgKGxlbiA8IDEwMjQpIHtcbiAgICAgIHJlcyA9IGJpZ011bFRvKHRoaXMsIG51bSwgb3V0KTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzID0ganVtYm9NdWxUbyh0aGlzLCBudW0sIG91dCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICAvLyBDb29sZXktVHVrZXkgYWxnb3JpdGhtIGZvciBGRlRcbiAgLy8gc2xpZ2h0bHkgcmV2aXNpdGVkIHRvIHJlbHkgb24gbG9vcGluZyBpbnN0ZWFkIG9mIHJlY3Vyc2lvblxuXG4gIGZ1bmN0aW9uIEZGVE0gKHgsIHkpIHtcbiAgICB0aGlzLnggPSB4O1xuICAgIHRoaXMueSA9IHk7XG4gIH1cblxuICBGRlRNLnByb3RvdHlwZS5tYWtlUkJUID0gZnVuY3Rpb24gbWFrZVJCVCAoTikge1xuICAgIHZhciB0ID0gbmV3IEFycmF5KE4pO1xuICAgIHZhciBsID0gQk4ucHJvdG90eXBlLl9jb3VudEJpdHMoTikgLSAxO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgTjsgaSsrKSB7XG4gICAgICB0W2ldID0gdGhpcy5yZXZCaW4oaSwgbCwgTik7XG4gICAgfVxuXG4gICAgcmV0dXJuIHQ7XG4gIH07XG5cbiAgLy8gUmV0dXJucyBiaW5hcnktcmV2ZXJzZWQgcmVwcmVzZW50YXRpb24gb2YgYHhgXG4gIEZGVE0ucHJvdG90eXBlLnJldkJpbiA9IGZ1bmN0aW9uIHJldkJpbiAoeCwgbCwgTikge1xuICAgIGlmICh4ID09PSAwIHx8IHggPT09IE4gLSAxKSByZXR1cm4geDtcblxuICAgIHZhciByYiA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsOyBpKyspIHtcbiAgICAgIHJiIHw9ICh4ICYgMSkgPDwgKGwgLSBpIC0gMSk7XG4gICAgICB4ID4+PSAxO1xuICAgIH1cblxuICAgIHJldHVybiByYjtcbiAgfTtcblxuICAvLyBQZXJmb3JtcyBcInR3ZWVkbGluZ1wiIHBoYXNlLCB0aGVyZWZvcmUgJ2VtdWxhdGluZydcbiAgLy8gYmVoYXZpb3VyIG9mIHRoZSByZWN1cnNpdmUgYWxnb3JpdGhtXG4gIEZGVE0ucHJvdG90eXBlLnBlcm11dGUgPSBmdW5jdGlvbiBwZXJtdXRlIChyYnQsIHJ3cywgaXdzLCBydHdzLCBpdHdzLCBOKSB7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBOOyBpKyspIHtcbiAgICAgIHJ0d3NbaV0gPSByd3NbcmJ0W2ldXTtcbiAgICAgIGl0d3NbaV0gPSBpd3NbcmJ0W2ldXTtcbiAgICB9XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUudHJhbnNmb3JtID0gZnVuY3Rpb24gdHJhbnNmb3JtIChyd3MsIGl3cywgcnR3cywgaXR3cywgTiwgcmJ0KSB7XG4gICAgdGhpcy5wZXJtdXRlKHJidCwgcndzLCBpd3MsIHJ0d3MsIGl0d3MsIE4pO1xuXG4gICAgZm9yICh2YXIgcyA9IDE7IHMgPCBOOyBzIDw8PSAxKSB7XG4gICAgICB2YXIgbCA9IHMgPDwgMTtcblxuICAgICAgdmFyIHJ0d2RmID0gTWF0aC5jb3MoMiAqIE1hdGguUEkgLyBsKTtcbiAgICAgIHZhciBpdHdkZiA9IE1hdGguc2luKDIgKiBNYXRoLlBJIC8gbCk7XG5cbiAgICAgIGZvciAodmFyIHAgPSAwOyBwIDwgTjsgcCArPSBsKSB7XG4gICAgICAgIHZhciBydHdkZl8gPSBydHdkZjtcbiAgICAgICAgdmFyIGl0d2RmXyA9IGl0d2RmO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgczsgaisrKSB7XG4gICAgICAgICAgdmFyIHJlID0gcnR3c1twICsgal07XG4gICAgICAgICAgdmFyIGllID0gaXR3c1twICsgal07XG5cbiAgICAgICAgICB2YXIgcm8gPSBydHdzW3AgKyBqICsgc107XG4gICAgICAgICAgdmFyIGlvID0gaXR3c1twICsgaiArIHNdO1xuXG4gICAgICAgICAgdmFyIHJ4ID0gcnR3ZGZfICogcm8gLSBpdHdkZl8gKiBpbztcblxuICAgICAgICAgIGlvID0gcnR3ZGZfICogaW8gKyBpdHdkZl8gKiBybztcbiAgICAgICAgICBybyA9IHJ4O1xuXG4gICAgICAgICAgcnR3c1twICsgal0gPSByZSArIHJvO1xuICAgICAgICAgIGl0d3NbcCArIGpdID0gaWUgKyBpbztcblxuICAgICAgICAgIHJ0d3NbcCArIGogKyBzXSA9IHJlIC0gcm87XG4gICAgICAgICAgaXR3c1twICsgaiArIHNdID0gaWUgLSBpbztcblxuICAgICAgICAgIC8qIGpzaGludCBtYXhkZXB0aCA6IGZhbHNlICovXG4gICAgICAgICAgaWYgKGogIT09IGwpIHtcbiAgICAgICAgICAgIHJ4ID0gcnR3ZGYgKiBydHdkZl8gLSBpdHdkZiAqIGl0d2RmXztcblxuICAgICAgICAgICAgaXR3ZGZfID0gcnR3ZGYgKiBpdHdkZl8gKyBpdHdkZiAqIHJ0d2RmXztcbiAgICAgICAgICAgIHJ0d2RmXyA9IHJ4O1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICBGRlRNLnByb3RvdHlwZS5ndWVzc0xlbjEzYiA9IGZ1bmN0aW9uIGd1ZXNzTGVuMTNiIChuLCBtKSB7XG4gICAgdmFyIE4gPSBNYXRoLm1heChtLCBuKSB8IDE7XG4gICAgdmFyIG9kZCA9IE4gJiAxO1xuICAgIHZhciBpID0gMDtcbiAgICBmb3IgKE4gPSBOIC8gMiB8IDA7IE47IE4gPSBOID4+PiAxKSB7XG4gICAgICBpKys7XG4gICAgfVxuXG4gICAgcmV0dXJuIDEgPDwgaSArIDEgKyBvZGQ7XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUuY29uanVnYXRlID0gZnVuY3Rpb24gY29uanVnYXRlIChyd3MsIGl3cywgTikge1xuICAgIGlmIChOIDw9IDEpIHJldHVybjtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgTiAvIDI7IGkrKykge1xuICAgICAgdmFyIHQgPSByd3NbaV07XG5cbiAgICAgIHJ3c1tpXSA9IHJ3c1tOIC0gaSAtIDFdO1xuICAgICAgcndzW04gLSBpIC0gMV0gPSB0O1xuXG4gICAgICB0ID0gaXdzW2ldO1xuXG4gICAgICBpd3NbaV0gPSAtaXdzW04gLSBpIC0gMV07XG4gICAgICBpd3NbTiAtIGkgLSAxXSA9IC10O1xuICAgIH1cbiAgfTtcblxuICBGRlRNLnByb3RvdHlwZS5ub3JtYWxpemUxM2IgPSBmdW5jdGlvbiBub3JtYWxpemUxM2IgKHdzLCBOKSB7XG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IE4gLyAyOyBpKyspIHtcbiAgICAgIHZhciB3ID0gTWF0aC5yb3VuZCh3c1syICogaSArIDFdIC8gTikgKiAweDIwMDAgK1xuICAgICAgICBNYXRoLnJvdW5kKHdzWzIgKiBpXSAvIE4pICtcbiAgICAgICAgY2Fycnk7XG5cbiAgICAgIHdzW2ldID0gdyAmIDB4M2ZmZmZmZjtcblxuICAgICAgaWYgKHcgPCAweDQwMDAwMDApIHtcbiAgICAgICAgY2FycnkgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY2FycnkgPSB3IC8gMHg0MDAwMDAwIHwgMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gd3M7XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUuY29udmVydDEzYiA9IGZ1bmN0aW9uIGNvbnZlcnQxM2IgKHdzLCBsZW4sIHJ3cywgTikge1xuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgICAgY2FycnkgPSBjYXJyeSArICh3c1tpXSB8IDApO1xuXG4gICAgICByd3NbMiAqIGldID0gY2FycnkgJiAweDFmZmY7IGNhcnJ5ID0gY2FycnkgPj4+IDEzO1xuICAgICAgcndzWzIgKiBpICsgMV0gPSBjYXJyeSAmIDB4MWZmZjsgY2FycnkgPSBjYXJyeSA+Pj4gMTM7XG4gICAgfVxuXG4gICAgLy8gUGFkIHdpdGggemVyb2VzXG4gICAgZm9yIChpID0gMiAqIGxlbjsgaSA8IE47ICsraSkge1xuICAgICAgcndzW2ldID0gMDtcbiAgICB9XG5cbiAgICBhc3NlcnQoY2FycnkgPT09IDApO1xuICAgIGFzc2VydCgoY2FycnkgJiB+MHgxZmZmKSA9PT0gMCk7XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUuc3R1YiA9IGZ1bmN0aW9uIHN0dWIgKE4pIHtcbiAgICB2YXIgcGggPSBuZXcgQXJyYXkoTik7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBOOyBpKyspIHtcbiAgICAgIHBoW2ldID0gMDtcbiAgICB9XG5cbiAgICByZXR1cm4gcGg7XG4gIH07XG5cbiAgRkZUTS5wcm90b3R5cGUubXVscCA9IGZ1bmN0aW9uIG11bHAgKHgsIHksIG91dCkge1xuICAgIHZhciBOID0gMiAqIHRoaXMuZ3Vlc3NMZW4xM2IoeC5sZW5ndGgsIHkubGVuZ3RoKTtcblxuICAgIHZhciByYnQgPSB0aGlzLm1ha2VSQlQoTik7XG5cbiAgICB2YXIgXyA9IHRoaXMuc3R1YihOKTtcblxuICAgIHZhciByd3MgPSBuZXcgQXJyYXkoTik7XG4gICAgdmFyIHJ3c3QgPSBuZXcgQXJyYXkoTik7XG4gICAgdmFyIGl3c3QgPSBuZXcgQXJyYXkoTik7XG5cbiAgICB2YXIgbnJ3cyA9IG5ldyBBcnJheShOKTtcbiAgICB2YXIgbnJ3c3QgPSBuZXcgQXJyYXkoTik7XG4gICAgdmFyIG5pd3N0ID0gbmV3IEFycmF5KE4pO1xuXG4gICAgdmFyIHJtd3MgPSBvdXQud29yZHM7XG4gICAgcm13cy5sZW5ndGggPSBOO1xuXG4gICAgdGhpcy5jb252ZXJ0MTNiKHgud29yZHMsIHgubGVuZ3RoLCByd3MsIE4pO1xuICAgIHRoaXMuY29udmVydDEzYih5LndvcmRzLCB5Lmxlbmd0aCwgbnJ3cywgTik7XG5cbiAgICB0aGlzLnRyYW5zZm9ybShyd3MsIF8sIHJ3c3QsIGl3c3QsIE4sIHJidCk7XG4gICAgdGhpcy50cmFuc2Zvcm0obnJ3cywgXywgbnJ3c3QsIG5pd3N0LCBOLCByYnQpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBOOyBpKyspIHtcbiAgICAgIHZhciByeCA9IHJ3c3RbaV0gKiBucndzdFtpXSAtIGl3c3RbaV0gKiBuaXdzdFtpXTtcbiAgICAgIGl3c3RbaV0gPSByd3N0W2ldICogbml3c3RbaV0gKyBpd3N0W2ldICogbnJ3c3RbaV07XG4gICAgICByd3N0W2ldID0gcng7XG4gICAgfVxuXG4gICAgdGhpcy5jb25qdWdhdGUocndzdCwgaXdzdCwgTik7XG4gICAgdGhpcy50cmFuc2Zvcm0ocndzdCwgaXdzdCwgcm13cywgXywgTiwgcmJ0KTtcbiAgICB0aGlzLmNvbmp1Z2F0ZShybXdzLCBfLCBOKTtcbiAgICB0aGlzLm5vcm1hbGl6ZTEzYihybXdzLCBOKTtcblxuICAgIG91dC5uZWdhdGl2ZSA9IHgubmVnYXRpdmUgXiB5Lm5lZ2F0aXZlO1xuICAgIG91dC5sZW5ndGggPSB4Lmxlbmd0aCArIHkubGVuZ3RoO1xuICAgIHJldHVybiBvdXQuc3RyaXAoKTtcbiAgfTtcblxuICAvLyBNdWx0aXBseSBgdGhpc2AgYnkgYG51bWBcbiAgQk4ucHJvdG90eXBlLm11bCA9IGZ1bmN0aW9uIG11bCAobnVtKSB7XG4gICAgdmFyIG91dCA9IG5ldyBCTihudWxsKTtcbiAgICBvdXQud29yZHMgPSBuZXcgQXJyYXkodGhpcy5sZW5ndGggKyBudW0ubGVuZ3RoKTtcbiAgICByZXR1cm4gdGhpcy5tdWxUbyhudW0sIG91dCk7XG4gIH07XG5cbiAgLy8gTXVsdGlwbHkgZW1wbG95aW5nIEZGVFxuICBCTi5wcm90b3R5cGUubXVsZiA9IGZ1bmN0aW9uIG11bGYgKG51bSkge1xuICAgIHZhciBvdXQgPSBuZXcgQk4obnVsbCk7XG4gICAgb3V0LndvcmRzID0gbmV3IEFycmF5KHRoaXMubGVuZ3RoICsgbnVtLmxlbmd0aCk7XG4gICAgcmV0dXJuIGp1bWJvTXVsVG8odGhpcywgbnVtLCBvdXQpO1xuICB9O1xuXG4gIC8vIEluLXBsYWNlIE11bHRpcGxpY2F0aW9uXG4gIEJOLnByb3RvdHlwZS5pbXVsID0gZnVuY3Rpb24gaW11bCAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5tdWxUbyhudW0sIHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pbXVsbiA9IGZ1bmN0aW9uIGltdWxuIChudW0pIHtcbiAgICBhc3NlcnQodHlwZW9mIG51bSA9PT0gJ251bWJlcicpO1xuICAgIGFzc2VydChudW0gPCAweDQwMDAwMDApO1xuXG4gICAgLy8gQ2FycnlcbiAgICB2YXIgY2FycnkgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIHcgPSAodGhpcy53b3Jkc1tpXSB8IDApICogbnVtO1xuICAgICAgdmFyIGxvID0gKHcgJiAweDNmZmZmZmYpICsgKGNhcnJ5ICYgMHgzZmZmZmZmKTtcbiAgICAgIGNhcnJ5ID4+PSAyNjtcbiAgICAgIGNhcnJ5ICs9ICh3IC8gMHg0MDAwMDAwKSB8IDA7XG4gICAgICAvLyBOT1RFOiBsbyBpcyAyN2JpdCBtYXhpbXVtXG4gICAgICBjYXJyeSArPSBsbyA+Pj4gMjY7XG4gICAgICB0aGlzLndvcmRzW2ldID0gbG8gJiAweDNmZmZmZmY7XG4gICAgfVxuXG4gICAgaWYgKGNhcnJ5ICE9PSAwKSB7XG4gICAgICB0aGlzLndvcmRzW2ldID0gY2Fycnk7XG4gICAgICB0aGlzLmxlbmd0aCsrO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5tdWxuID0gZnVuY3Rpb24gbXVsbiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pbXVsbihudW0pO1xuICB9O1xuXG4gIC8vIGB0aGlzYCAqIGB0aGlzYFxuICBCTi5wcm90b3R5cGUuc3FyID0gZnVuY3Rpb24gc3FyICgpIHtcbiAgICByZXR1cm4gdGhpcy5tdWwodGhpcyk7XG4gIH07XG5cbiAgLy8gYHRoaXNgICogYHRoaXNgIGluLXBsYWNlXG4gIEJOLnByb3RvdHlwZS5pc3FyID0gZnVuY3Rpb24gaXNxciAoKSB7XG4gICAgcmV0dXJuIHRoaXMuaW11bCh0aGlzLmNsb25lKCkpO1xuICB9O1xuXG4gIC8vIE1hdGgucG93KGB0aGlzYCwgYG51bWApXG4gIEJOLnByb3RvdHlwZS5wb3cgPSBmdW5jdGlvbiBwb3cgKG51bSkge1xuICAgIHZhciB3ID0gdG9CaXRBcnJheShudW0pO1xuICAgIGlmICh3Lmxlbmd0aCA9PT0gMCkgcmV0dXJuIG5ldyBCTigxKTtcblxuICAgIC8vIFNraXAgbGVhZGluZyB6ZXJvZXNcbiAgICB2YXIgcmVzID0gdGhpcztcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHcubGVuZ3RoOyBpKyssIHJlcyA9IHJlcy5zcXIoKSkge1xuICAgICAgaWYgKHdbaV0gIT09IDApIGJyZWFrO1xuICAgIH1cblxuICAgIGlmICgrK2kgPCB3Lmxlbmd0aCkge1xuICAgICAgZm9yICh2YXIgcSA9IHJlcy5zcXIoKTsgaSA8IHcubGVuZ3RoOyBpKyssIHEgPSBxLnNxcigpKSB7XG4gICAgICAgIGlmICh3W2ldID09PSAwKSBjb250aW51ZTtcblxuICAgICAgICByZXMgPSByZXMubXVsKHEpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgLy8gU2hpZnQtbGVmdCBpbi1wbGFjZVxuICBCTi5wcm90b3R5cGUuaXVzaGxuID0gZnVuY3Rpb24gaXVzaGxuIChiaXRzKSB7XG4gICAgYXNzZXJ0KHR5cGVvZiBiaXRzID09PSAnbnVtYmVyJyAmJiBiaXRzID49IDApO1xuICAgIHZhciByID0gYml0cyAlIDI2O1xuICAgIHZhciBzID0gKGJpdHMgLSByKSAvIDI2O1xuICAgIHZhciBjYXJyeU1hc2sgPSAoMHgzZmZmZmZmID4+PiAoMjYgLSByKSkgPDwgKDI2IC0gcik7XG4gICAgdmFyIGk7XG5cbiAgICBpZiAociAhPT0gMCkge1xuICAgICAgdmFyIGNhcnJ5ID0gMDtcblxuICAgICAgZm9yIChpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdmFyIG5ld0NhcnJ5ID0gdGhpcy53b3Jkc1tpXSAmIGNhcnJ5TWFzaztcbiAgICAgICAgdmFyIGMgPSAoKHRoaXMud29yZHNbaV0gfCAwKSAtIG5ld0NhcnJ5KSA8PCByO1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gYyB8IGNhcnJ5O1xuICAgICAgICBjYXJyeSA9IG5ld0NhcnJ5ID4+PiAoMjYgLSByKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGNhcnJ5KSB7XG4gICAgICAgIHRoaXMud29yZHNbaV0gPSBjYXJyeTtcbiAgICAgICAgdGhpcy5sZW5ndGgrKztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAocyAhPT0gMCkge1xuICAgICAgZm9yIChpID0gdGhpcy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgICAgICB0aGlzLndvcmRzW2kgKyBzXSA9IHRoaXMud29yZHNbaV07XG4gICAgICB9XG5cbiAgICAgIGZvciAoaSA9IDA7IGkgPCBzOyBpKyspIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpXSA9IDA7XG4gICAgICB9XG5cbiAgICAgIHRoaXMubGVuZ3RoICs9IHM7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXNobG4gPSBmdW5jdGlvbiBpc2hsbiAoYml0cykge1xuICAgIC8vIFRPRE8oaW5kdXRueSk6IGltcGxlbWVudCBtZVxuICAgIGFzc2VydCh0aGlzLm5lZ2F0aXZlID09PSAwKTtcbiAgICByZXR1cm4gdGhpcy5pdXNobG4oYml0cyk7XG4gIH07XG5cbiAgLy8gU2hpZnQtcmlnaHQgaW4tcGxhY2VcbiAgLy8gTk9URTogYGhpbnRgIGlzIGEgbG93ZXN0IGJpdCBiZWZvcmUgdHJhaWxpbmcgemVyb2VzXG4gIC8vIE5PVEU6IGlmIGBleHRlbmRlZGAgaXMgcHJlc2VudCAtIGl0IHdpbGwgYmUgZmlsbGVkIHdpdGggZGVzdHJveWVkIGJpdHNcbiAgQk4ucHJvdG90eXBlLml1c2hybiA9IGZ1bmN0aW9uIGl1c2hybiAoYml0cywgaGludCwgZXh0ZW5kZWQpIHtcbiAgICBhc3NlcnQodHlwZW9mIGJpdHMgPT09ICdudW1iZXInICYmIGJpdHMgPj0gMCk7XG4gICAgdmFyIGg7XG4gICAgaWYgKGhpbnQpIHtcbiAgICAgIGggPSAoaGludCAtIChoaW50ICUgMjYpKSAvIDI2O1xuICAgIH0gZWxzZSB7XG4gICAgICBoID0gMDtcbiAgICB9XG5cbiAgICB2YXIgciA9IGJpdHMgJSAyNjtcbiAgICB2YXIgcyA9IE1hdGgubWluKChiaXRzIC0gcikgLyAyNiwgdGhpcy5sZW5ndGgpO1xuICAgIHZhciBtYXNrID0gMHgzZmZmZmZmIF4gKCgweDNmZmZmZmYgPj4+IHIpIDw8IHIpO1xuICAgIHZhciBtYXNrZWRXb3JkcyA9IGV4dGVuZGVkO1xuXG4gICAgaCAtPSBzO1xuICAgIGggPSBNYXRoLm1heCgwLCBoKTtcblxuICAgIC8vIEV4dGVuZGVkIG1vZGUsIGNvcHkgbWFza2VkIHBhcnRcbiAgICBpZiAobWFza2VkV29yZHMpIHtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgczsgaSsrKSB7XG4gICAgICAgIG1hc2tlZFdvcmRzLndvcmRzW2ldID0gdGhpcy53b3Jkc1tpXTtcbiAgICAgIH1cbiAgICAgIG1hc2tlZFdvcmRzLmxlbmd0aCA9IHM7XG4gICAgfVxuXG4gICAgaWYgKHMgPT09IDApIHtcbiAgICAgIC8vIE5vLW9wLCB3ZSBzaG91bGQgbm90IG1vdmUgYW55dGhpbmcgYXQgYWxsXG4gICAgfSBlbHNlIGlmICh0aGlzLmxlbmd0aCA+IHMpIHtcbiAgICAgIHRoaXMubGVuZ3RoIC09IHM7XG4gICAgICBmb3IgKGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7IGkrKykge1xuICAgICAgICB0aGlzLndvcmRzW2ldID0gdGhpcy53b3Jkc1tpICsgc107XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMud29yZHNbMF0gPSAwO1xuICAgICAgdGhpcy5sZW5ndGggPSAxO1xuICAgIH1cblxuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yIChpID0gdGhpcy5sZW5ndGggLSAxOyBpID49IDAgJiYgKGNhcnJ5ICE9PSAwIHx8IGkgPj0gaCk7IGktLSkge1xuICAgICAgdmFyIHdvcmQgPSB0aGlzLndvcmRzW2ldIHwgMDtcbiAgICAgIHRoaXMud29yZHNbaV0gPSAoY2FycnkgPDwgKDI2IC0gcikpIHwgKHdvcmQgPj4+IHIpO1xuICAgICAgY2FycnkgPSB3b3JkICYgbWFzaztcbiAgICB9XG5cbiAgICAvLyBQdXNoIGNhcnJpZWQgYml0cyBhcyBhIG1hc2tcbiAgICBpZiAobWFza2VkV29yZHMgJiYgY2FycnkgIT09IDApIHtcbiAgICAgIG1hc2tlZFdvcmRzLndvcmRzW21hc2tlZFdvcmRzLmxlbmd0aCsrXSA9IGNhcnJ5O1xuICAgIH1cblxuICAgIGlmICh0aGlzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy53b3Jkc1swXSA9IDA7XG4gICAgICB0aGlzLmxlbmd0aCA9IDE7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc3RyaXAoKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuaXNocm4gPSBmdW5jdGlvbiBpc2hybiAoYml0cywgaGludCwgZXh0ZW5kZWQpIHtcbiAgICAvLyBUT0RPKGluZHV0bnkpOiBpbXBsZW1lbnQgbWVcbiAgICBhc3NlcnQodGhpcy5uZWdhdGl2ZSA9PT0gMCk7XG4gICAgcmV0dXJuIHRoaXMuaXVzaHJuKGJpdHMsIGhpbnQsIGV4dGVuZGVkKTtcbiAgfTtcblxuICAvLyBTaGlmdC1sZWZ0XG4gIEJOLnByb3RvdHlwZS5zaGxuID0gZnVuY3Rpb24gc2hsbiAoYml0cykge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaXNobG4oYml0cyk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnVzaGxuID0gZnVuY3Rpb24gdXNobG4gKGJpdHMpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLml1c2hsbihiaXRzKTtcbiAgfTtcblxuICAvLyBTaGlmdC1yaWdodFxuICBCTi5wcm90b3R5cGUuc2hybiA9IGZ1bmN0aW9uIHNocm4gKGJpdHMpIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlzaHJuKGJpdHMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS51c2hybiA9IGZ1bmN0aW9uIHVzaHJuIChiaXRzKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pdXNocm4oYml0cyk7XG4gIH07XG5cbiAgLy8gVGVzdCBpZiBuIGJpdCBpcyBzZXRcbiAgQk4ucHJvdG90eXBlLnRlc3RuID0gZnVuY3Rpb24gdGVzdG4gKGJpdCkge1xuICAgIGFzc2VydCh0eXBlb2YgYml0ID09PSAnbnVtYmVyJyAmJiBiaXQgPj0gMCk7XG4gICAgdmFyIHIgPSBiaXQgJSAyNjtcbiAgICB2YXIgcyA9IChiaXQgLSByKSAvIDI2O1xuICAgIHZhciBxID0gMSA8PCByO1xuXG4gICAgLy8gRmFzdCBjYXNlOiBiaXQgaXMgbXVjaCBoaWdoZXIgdGhhbiBhbGwgZXhpc3Rpbmcgd29yZHNcbiAgICBpZiAodGhpcy5sZW5ndGggPD0gcykgcmV0dXJuIGZhbHNlO1xuXG4gICAgLy8gQ2hlY2sgYml0IGFuZCByZXR1cm5cbiAgICB2YXIgdyA9IHRoaXMud29yZHNbc107XG5cbiAgICByZXR1cm4gISEodyAmIHEpO1xuICB9O1xuXG4gIC8vIFJldHVybiBvbmx5IGxvd2VycyBiaXRzIG9mIG51bWJlciAoaW4tcGxhY2UpXG4gIEJOLnByb3RvdHlwZS5pbWFza24gPSBmdW5jdGlvbiBpbWFza24gKGJpdHMpIHtcbiAgICBhc3NlcnQodHlwZW9mIGJpdHMgPT09ICdudW1iZXInICYmIGJpdHMgPj0gMCk7XG4gICAgdmFyIHIgPSBiaXRzICUgMjY7XG4gICAgdmFyIHMgPSAoYml0cyAtIHIpIC8gMjY7XG5cbiAgICBhc3NlcnQodGhpcy5uZWdhdGl2ZSA9PT0gMCwgJ2ltYXNrbiB3b3JrcyBvbmx5IHdpdGggcG9zaXRpdmUgbnVtYmVycycpO1xuXG4gICAgaWYgKHIgIT09IDApIHtcbiAgICAgIHMrKztcbiAgICB9XG4gICAgdGhpcy5sZW5ndGggPSBNYXRoLm1pbihzLCB0aGlzLmxlbmd0aCk7XG5cbiAgICBpZiAociAhPT0gMCkge1xuICAgICAgdmFyIG1hc2sgPSAweDNmZmZmZmYgXiAoKDB4M2ZmZmZmZiA+Pj4gcikgPDwgcik7XG4gICAgICB0aGlzLndvcmRzW3RoaXMubGVuZ3RoIC0gMV0gJj0gbWFzaztcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIC8vIFJldHVybiBvbmx5IGxvd2VycyBiaXRzIG9mIG51bWJlclxuICBCTi5wcm90b3R5cGUubWFza24gPSBmdW5jdGlvbiBtYXNrbiAoYml0cykge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaW1hc2tuKGJpdHMpO1xuICB9O1xuXG4gIC8vIEFkZCBwbGFpbiBudW1iZXIgYG51bWAgdG8gYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5pYWRkbiA9IGZ1bmN0aW9uIGlhZGRuIChudW0pIHtcbiAgICBhc3NlcnQodHlwZW9mIG51bSA9PT0gJ251bWJlcicpO1xuICAgIGFzc2VydChudW0gPCAweDQwMDAwMDApO1xuICAgIGlmIChudW0gPCAwKSByZXR1cm4gdGhpcy5pc3VibigtbnVtKTtcblxuICAgIC8vIFBvc3NpYmxlIHNpZ24gY2hhbmdlXG4gICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIGlmICh0aGlzLmxlbmd0aCA9PT0gMSAmJiAodGhpcy53b3Jkc1swXSB8IDApIDwgbnVtKSB7XG4gICAgICAgIHRoaXMud29yZHNbMF0gPSBudW0gLSAodGhpcy53b3Jkc1swXSB8IDApO1xuICAgICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgICB9XG5cbiAgICAgIHRoaXMubmVnYXRpdmUgPSAwO1xuICAgICAgdGhpcy5pc3VibihudW0pO1xuICAgICAgdGhpcy5uZWdhdGl2ZSA9IDE7XG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG5cbiAgICAvLyBBZGQgd2l0aG91dCBjaGVja3NcbiAgICByZXR1cm4gdGhpcy5faWFkZG4obnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2lhZGRuID0gZnVuY3Rpb24gX2lhZGRuIChudW0pIHtcbiAgICB0aGlzLndvcmRzWzBdICs9IG51bTtcblxuICAgIC8vIENhcnJ5XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aCAmJiB0aGlzLndvcmRzW2ldID49IDB4NDAwMDAwMDsgaSsrKSB7XG4gICAgICB0aGlzLndvcmRzW2ldIC09IDB4NDAwMDAwMDtcbiAgICAgIGlmIChpID09PSB0aGlzLmxlbmd0aCAtIDEpIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpICsgMV0gPSAxO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy53b3Jkc1tpICsgMV0rKztcbiAgICAgIH1cbiAgICB9XG4gICAgdGhpcy5sZW5ndGggPSBNYXRoLm1heCh0aGlzLmxlbmd0aCwgaSArIDEpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgLy8gU3VidHJhY3QgcGxhaW4gbnVtYmVyIGBudW1gIGZyb20gYHRoaXNgXG4gIEJOLnByb3RvdHlwZS5pc3VibiA9IGZ1bmN0aW9uIGlzdWJuIChudW0pIHtcbiAgICBhc3NlcnQodHlwZW9mIG51bSA9PT0gJ251bWJlcicpO1xuICAgIGFzc2VydChudW0gPCAweDQwMDAwMDApO1xuICAgIGlmIChudW0gPCAwKSByZXR1cm4gdGhpcy5pYWRkbigtbnVtKTtcblxuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICB0aGlzLm5lZ2F0aXZlID0gMDtcbiAgICAgIHRoaXMuaWFkZG4obnVtKTtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAxO1xuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuXG4gICAgdGhpcy53b3Jkc1swXSAtPSBudW07XG5cbiAgICBpZiAodGhpcy5sZW5ndGggPT09IDEgJiYgdGhpcy53b3Jkc1swXSA8IDApIHtcbiAgICAgIHRoaXMud29yZHNbMF0gPSAtdGhpcy53b3Jkc1swXTtcbiAgICAgIHRoaXMubmVnYXRpdmUgPSAxO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBDYXJyeVxuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aCAmJiB0aGlzLndvcmRzW2ldIDwgMDsgaSsrKSB7XG4gICAgICAgIHRoaXMud29yZHNbaV0gKz0gMHg0MDAwMDAwO1xuICAgICAgICB0aGlzLndvcmRzW2kgKyAxXSAtPSAxO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmFkZG4gPSBmdW5jdGlvbiBhZGRuIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlhZGRuKG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnN1Ym4gPSBmdW5jdGlvbiBzdWJuIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbG9uZSgpLmlzdWJuKG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmlhYnMgPSBmdW5jdGlvbiBpYWJzICgpIHtcbiAgICB0aGlzLm5lZ2F0aXZlID0gMDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5hYnMgPSBmdW5jdGlvbiBhYnMgKCkge1xuICAgIHJldHVybiB0aGlzLmNsb25lKCkuaWFicygpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5faXNobG5zdWJtdWwgPSBmdW5jdGlvbiBfaXNobG5zdWJtdWwgKG51bSwgbXVsLCBzaGlmdCkge1xuICAgIHZhciBsZW4gPSBudW0ubGVuZ3RoICsgc2hpZnQ7XG4gICAgdmFyIGk7XG5cbiAgICB0aGlzLl9leHBhbmQobGVuKTtcblxuICAgIHZhciB3O1xuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yIChpID0gMDsgaSA8IG51bS5sZW5ndGg7IGkrKykge1xuICAgICAgdyA9ICh0aGlzLndvcmRzW2kgKyBzaGlmdF0gfCAwKSArIGNhcnJ5O1xuICAgICAgdmFyIHJpZ2h0ID0gKG51bS53b3Jkc1tpXSB8IDApICogbXVsO1xuICAgICAgdyAtPSByaWdodCAmIDB4M2ZmZmZmZjtcbiAgICAgIGNhcnJ5ID0gKHcgPj4gMjYpIC0gKChyaWdodCAvIDB4NDAwMDAwMCkgfCAwKTtcbiAgICAgIHRoaXMud29yZHNbaSArIHNoaWZ0XSA9IHcgJiAweDNmZmZmZmY7XG4gICAgfVxuICAgIGZvciAoOyBpIDwgdGhpcy5sZW5ndGggLSBzaGlmdDsgaSsrKSB7XG4gICAgICB3ID0gKHRoaXMud29yZHNbaSArIHNoaWZ0XSB8IDApICsgY2Fycnk7XG4gICAgICBjYXJyeSA9IHcgPj4gMjY7XG4gICAgICB0aGlzLndvcmRzW2kgKyBzaGlmdF0gPSB3ICYgMHgzZmZmZmZmO1xuICAgIH1cblxuICAgIGlmIChjYXJyeSA9PT0gMCkgcmV0dXJuIHRoaXMuc3RyaXAoKTtcblxuICAgIC8vIFN1YnRyYWN0aW9uIG92ZXJmbG93XG4gICAgYXNzZXJ0KGNhcnJ5ID09PSAtMSk7XG4gICAgY2FycnkgPSAwO1xuICAgIGZvciAoaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB3ID0gLSh0aGlzLndvcmRzW2ldIHwgMCkgKyBjYXJyeTtcbiAgICAgIGNhcnJ5ID0gdyA+PiAyNjtcbiAgICAgIHRoaXMud29yZHNbaV0gPSB3ICYgMHgzZmZmZmZmO1xuICAgIH1cbiAgICB0aGlzLm5lZ2F0aXZlID0gMTtcblxuICAgIHJldHVybiB0aGlzLnN0cmlwKCk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLl93b3JkRGl2ID0gZnVuY3Rpb24gX3dvcmREaXYgKG51bSwgbW9kZSkge1xuICAgIHZhciBzaGlmdCA9IHRoaXMubGVuZ3RoIC0gbnVtLmxlbmd0aDtcblxuICAgIHZhciBhID0gdGhpcy5jbG9uZSgpO1xuICAgIHZhciBiID0gbnVtO1xuXG4gICAgLy8gTm9ybWFsaXplXG4gICAgdmFyIGJoaSA9IGIud29yZHNbYi5sZW5ndGggLSAxXSB8IDA7XG4gICAgdmFyIGJoaUJpdHMgPSB0aGlzLl9jb3VudEJpdHMoYmhpKTtcbiAgICBzaGlmdCA9IDI2IC0gYmhpQml0cztcbiAgICBpZiAoc2hpZnQgIT09IDApIHtcbiAgICAgIGIgPSBiLnVzaGxuKHNoaWZ0KTtcbiAgICAgIGEuaXVzaGxuKHNoaWZ0KTtcbiAgICAgIGJoaSA9IGIud29yZHNbYi5sZW5ndGggLSAxXSB8IDA7XG4gICAgfVxuXG4gICAgLy8gSW5pdGlhbGl6ZSBxdW90aWVudFxuICAgIHZhciBtID0gYS5sZW5ndGggLSBiLmxlbmd0aDtcbiAgICB2YXIgcTtcblxuICAgIGlmIChtb2RlICE9PSAnbW9kJykge1xuICAgICAgcSA9IG5ldyBCTihudWxsKTtcbiAgICAgIHEubGVuZ3RoID0gbSArIDE7XG4gICAgICBxLndvcmRzID0gbmV3IEFycmF5KHEubGVuZ3RoKTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcS5sZW5ndGg7IGkrKykge1xuICAgICAgICBxLndvcmRzW2ldID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB2YXIgZGlmZiA9IGEuY2xvbmUoKS5faXNobG5zdWJtdWwoYiwgMSwgbSk7XG4gICAgaWYgKGRpZmYubmVnYXRpdmUgPT09IDApIHtcbiAgICAgIGEgPSBkaWZmO1xuICAgICAgaWYgKHEpIHtcbiAgICAgICAgcS53b3Jkc1ttXSA9IDE7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZm9yICh2YXIgaiA9IG0gLSAxOyBqID49IDA7IGotLSkge1xuICAgICAgdmFyIHFqID0gKGEud29yZHNbYi5sZW5ndGggKyBqXSB8IDApICogMHg0MDAwMDAwICtcbiAgICAgICAgKGEud29yZHNbYi5sZW5ndGggKyBqIC0gMV0gfCAwKTtcblxuICAgICAgLy8gTk9URTogKHFqIC8gYmhpKSBpcyAoMHgzZmZmZmZmICogMHg0MDAwMDAwICsgMHgzZmZmZmZmKSAvIDB4MjAwMDAwMCBtYXhcbiAgICAgIC8vICgweDdmZmZmZmYpXG4gICAgICBxaiA9IE1hdGgubWluKChxaiAvIGJoaSkgfCAwLCAweDNmZmZmZmYpO1xuXG4gICAgICBhLl9pc2hsbnN1Ym11bChiLCBxaiwgaik7XG4gICAgICB3aGlsZSAoYS5uZWdhdGl2ZSAhPT0gMCkge1xuICAgICAgICBxai0tO1xuICAgICAgICBhLm5lZ2F0aXZlID0gMDtcbiAgICAgICAgYS5faXNobG5zdWJtdWwoYiwgMSwgaik7XG4gICAgICAgIGlmICghYS5pc1plcm8oKSkge1xuICAgICAgICAgIGEubmVnYXRpdmUgXj0gMTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKHEpIHtcbiAgICAgICAgcS53b3Jkc1tqXSA9IHFqO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAocSkge1xuICAgICAgcS5zdHJpcCgpO1xuICAgIH1cbiAgICBhLnN0cmlwKCk7XG5cbiAgICAvLyBEZW5vcm1hbGl6ZVxuICAgIGlmIChtb2RlICE9PSAnZGl2JyAmJiBzaGlmdCAhPT0gMCkge1xuICAgICAgYS5pdXNocm4oc2hpZnQpO1xuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICBkaXY6IHEgfHwgbnVsbCxcbiAgICAgIG1vZDogYVxuICAgIH07XG4gIH07XG5cbiAgLy8gTk9URTogMSkgYG1vZGVgIGNhbiBiZSBzZXQgdG8gYG1vZGAgdG8gcmVxdWVzdCBtb2Qgb25seSxcbiAgLy8gICAgICAgdG8gYGRpdmAgdG8gcmVxdWVzdCBkaXYgb25seSwgb3IgYmUgYWJzZW50IHRvXG4gIC8vICAgICAgIHJlcXVlc3QgYm90aCBkaXYgJiBtb2RcbiAgLy8gICAgICAgMikgYHBvc2l0aXZlYCBpcyB0cnVlIGlmIHVuc2lnbmVkIG1vZCBpcyByZXF1ZXN0ZWRcbiAgQk4ucHJvdG90eXBlLmRpdm1vZCA9IGZ1bmN0aW9uIGRpdm1vZCAobnVtLCBtb2RlLCBwb3NpdGl2ZSkge1xuICAgIGFzc2VydCghbnVtLmlzWmVybygpKTtcblxuICAgIGlmICh0aGlzLmlzWmVybygpKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBkaXY6IG5ldyBCTigwKSxcbiAgICAgICAgbW9kOiBuZXcgQk4oMClcbiAgICAgIH07XG4gICAgfVxuXG4gICAgdmFyIGRpdiwgbW9kLCByZXM7XG4gICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDAgJiYgbnVtLm5lZ2F0aXZlID09PSAwKSB7XG4gICAgICByZXMgPSB0aGlzLm5lZygpLmRpdm1vZChudW0sIG1vZGUpO1xuXG4gICAgICBpZiAobW9kZSAhPT0gJ21vZCcpIHtcbiAgICAgICAgZGl2ID0gcmVzLmRpdi5uZWcoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKG1vZGUgIT09ICdkaXYnKSB7XG4gICAgICAgIG1vZCA9IHJlcy5tb2QubmVnKCk7XG4gICAgICAgIGlmIChwb3NpdGl2ZSAmJiBtb2QubmVnYXRpdmUgIT09IDApIHtcbiAgICAgICAgICBtb2QuaWFkZChudW0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB7XG4gICAgICAgIGRpdjogZGl2LFxuICAgICAgICBtb2Q6IG1vZFxuICAgICAgfTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5uZWdhdGl2ZSA9PT0gMCAmJiBudW0ubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIHJlcyA9IHRoaXMuZGl2bW9kKG51bS5uZWcoKSwgbW9kZSk7XG5cbiAgICAgIGlmIChtb2RlICE9PSAnbW9kJykge1xuICAgICAgICBkaXYgPSByZXMuZGl2Lm5lZygpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBkaXY6IGRpdixcbiAgICAgICAgbW9kOiByZXMubW9kXG4gICAgICB9O1xuICAgIH1cblxuICAgIGlmICgodGhpcy5uZWdhdGl2ZSAmIG51bS5uZWdhdGl2ZSkgIT09IDApIHtcbiAgICAgIHJlcyA9IHRoaXMubmVnKCkuZGl2bW9kKG51bS5uZWcoKSwgbW9kZSk7XG5cbiAgICAgIGlmIChtb2RlICE9PSAnZGl2Jykge1xuICAgICAgICBtb2QgPSByZXMubW9kLm5lZygpO1xuICAgICAgICBpZiAocG9zaXRpdmUgJiYgbW9kLm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICAgICAgbW9kLmlzdWIobnVtKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICByZXR1cm4ge1xuICAgICAgICBkaXY6IHJlcy5kaXYsXG4gICAgICAgIG1vZDogbW9kXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vIEJvdGggbnVtYmVycyBhcmUgcG9zaXRpdmUgYXQgdGhpcyBwb2ludFxuXG4gICAgLy8gU3RyaXAgYm90aCBudW1iZXJzIHRvIGFwcHJveGltYXRlIHNoaWZ0IHZhbHVlXG4gICAgaWYgKG51bS5sZW5ndGggPiB0aGlzLmxlbmd0aCB8fCB0aGlzLmNtcChudW0pIDwgMCkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgZGl2OiBuZXcgQk4oMCksXG4gICAgICAgIG1vZDogdGhpc1xuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBWZXJ5IHNob3J0IHJlZHVjdGlvblxuICAgIGlmIChudW0ubGVuZ3RoID09PSAxKSB7XG4gICAgICBpZiAobW9kZSA9PT0gJ2RpdicpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBkaXY6IHRoaXMuZGl2bihudW0ud29yZHNbMF0pLFxuICAgICAgICAgIG1vZDogbnVsbFxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICBpZiAobW9kZSA9PT0gJ21vZCcpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBkaXY6IG51bGwsXG4gICAgICAgICAgbW9kOiBuZXcgQk4odGhpcy5tb2RuKG51bS53b3Jkc1swXSkpXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB7XG4gICAgICAgIGRpdjogdGhpcy5kaXZuKG51bS53b3Jkc1swXSksXG4gICAgICAgIG1vZDogbmV3IEJOKHRoaXMubW9kbihudW0ud29yZHNbMF0pKVxuICAgICAgfTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5fd29yZERpdihudW0sIG1vZGUpO1xuICB9O1xuXG4gIC8vIEZpbmQgYHRoaXNgIC8gYG51bWBcbiAgQk4ucHJvdG90eXBlLmRpdiA9IGZ1bmN0aW9uIGRpdiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuZGl2bW9kKG51bSwgJ2RpdicsIGZhbHNlKS5kaXY7XG4gIH07XG5cbiAgLy8gRmluZCBgdGhpc2AgJSBgbnVtYFxuICBCTi5wcm90b3R5cGUubW9kID0gZnVuY3Rpb24gbW9kIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5kaXZtb2QobnVtLCAnbW9kJywgZmFsc2UpLm1vZDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUudW1vZCA9IGZ1bmN0aW9uIHVtb2QgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmRpdm1vZChudW0sICdtb2QnLCB0cnVlKS5tb2Q7XG4gIH07XG5cbiAgLy8gRmluZCBSb3VuZChgdGhpc2AgLyBgbnVtYClcbiAgQk4ucHJvdG90eXBlLmRpdlJvdW5kID0gZnVuY3Rpb24gZGl2Um91bmQgKG51bSkge1xuICAgIHZhciBkbSA9IHRoaXMuZGl2bW9kKG51bSk7XG5cbiAgICAvLyBGYXN0IGNhc2UgLSBleGFjdCBkaXZpc2lvblxuICAgIGlmIChkbS5tb2QuaXNaZXJvKCkpIHJldHVybiBkbS5kaXY7XG5cbiAgICB2YXIgbW9kID0gZG0uZGl2Lm5lZ2F0aXZlICE9PSAwID8gZG0ubW9kLmlzdWIobnVtKSA6IGRtLm1vZDtcblxuICAgIHZhciBoYWxmID0gbnVtLnVzaHJuKDEpO1xuICAgIHZhciByMiA9IG51bS5hbmRsbigxKTtcbiAgICB2YXIgY21wID0gbW9kLmNtcChoYWxmKTtcblxuICAgIC8vIFJvdW5kIGRvd25cbiAgICBpZiAoY21wIDwgMCB8fCByMiA9PT0gMSAmJiBjbXAgPT09IDApIHJldHVybiBkbS5kaXY7XG5cbiAgICAvLyBSb3VuZCB1cFxuICAgIHJldHVybiBkbS5kaXYubmVnYXRpdmUgIT09IDAgPyBkbS5kaXYuaXN1Ym4oMSkgOiBkbS5kaXYuaWFkZG4oMSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLm1vZG4gPSBmdW5jdGlvbiBtb2RuIChudW0pIHtcbiAgICBhc3NlcnQobnVtIDw9IDB4M2ZmZmZmZik7XG4gICAgdmFyIHAgPSAoMSA8PCAyNikgJSBudW07XG5cbiAgICB2YXIgYWNjID0gMDtcbiAgICBmb3IgKHZhciBpID0gdGhpcy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgICAgYWNjID0gKHAgKiBhY2MgKyAodGhpcy53b3Jkc1tpXSB8IDApKSAlIG51bTtcbiAgICB9XG5cbiAgICByZXR1cm4gYWNjO1xuICB9O1xuXG4gIC8vIEluLXBsYWNlIGRpdmlzaW9uIGJ5IG51bWJlclxuICBCTi5wcm90b3R5cGUuaWRpdm4gPSBmdW5jdGlvbiBpZGl2biAobnVtKSB7XG4gICAgYXNzZXJ0KG51bSA8PSAweDNmZmZmZmYpO1xuXG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICBmb3IgKHZhciBpID0gdGhpcy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgICAgdmFyIHcgPSAodGhpcy53b3Jkc1tpXSB8IDApICsgY2FycnkgKiAweDQwMDAwMDA7XG4gICAgICB0aGlzLndvcmRzW2ldID0gKHcgLyBudW0pIHwgMDtcbiAgICAgIGNhcnJ5ID0gdyAlIG51bTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zdHJpcCgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5kaXZuID0gZnVuY3Rpb24gZGl2biAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY2xvbmUoKS5pZGl2bihudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5lZ2NkID0gZnVuY3Rpb24gZWdjZCAocCkge1xuICAgIGFzc2VydChwLm5lZ2F0aXZlID09PSAwKTtcbiAgICBhc3NlcnQoIXAuaXNaZXJvKCkpO1xuXG4gICAgdmFyIHggPSB0aGlzO1xuICAgIHZhciB5ID0gcC5jbG9uZSgpO1xuXG4gICAgaWYgKHgubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIHggPSB4LnVtb2QocCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHggPSB4LmNsb25lKCk7XG4gICAgfVxuXG4gICAgLy8gQSAqIHggKyBCICogeSA9IHhcbiAgICB2YXIgQSA9IG5ldyBCTigxKTtcbiAgICB2YXIgQiA9IG5ldyBCTigwKTtcblxuICAgIC8vIEMgKiB4ICsgRCAqIHkgPSB5XG4gICAgdmFyIEMgPSBuZXcgQk4oMCk7XG4gICAgdmFyIEQgPSBuZXcgQk4oMSk7XG5cbiAgICB2YXIgZyA9IDA7XG5cbiAgICB3aGlsZSAoeC5pc0V2ZW4oKSAmJiB5LmlzRXZlbigpKSB7XG4gICAgICB4Lml1c2hybigxKTtcbiAgICAgIHkuaXVzaHJuKDEpO1xuICAgICAgKytnO1xuICAgIH1cblxuICAgIHZhciB5cCA9IHkuY2xvbmUoKTtcbiAgICB2YXIgeHAgPSB4LmNsb25lKCk7XG5cbiAgICB3aGlsZSAoIXguaXNaZXJvKCkpIHtcbiAgICAgIGZvciAodmFyIGkgPSAwLCBpbSA9IDE7ICh4LndvcmRzWzBdICYgaW0pID09PSAwICYmIGkgPCAyNjsgKytpLCBpbSA8PD0gMSk7XG4gICAgICBpZiAoaSA+IDApIHtcbiAgICAgICAgeC5pdXNocm4oaSk7XG4gICAgICAgIHdoaWxlIChpLS0gPiAwKSB7XG4gICAgICAgICAgaWYgKEEuaXNPZGQoKSB8fCBCLmlzT2RkKCkpIHtcbiAgICAgICAgICAgIEEuaWFkZCh5cCk7XG4gICAgICAgICAgICBCLmlzdWIoeHApO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIEEuaXVzaHJuKDEpO1xuICAgICAgICAgIEIuaXVzaHJuKDEpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGZvciAodmFyIGogPSAwLCBqbSA9IDE7ICh5LndvcmRzWzBdICYgam0pID09PSAwICYmIGogPCAyNjsgKytqLCBqbSA8PD0gMSk7XG4gICAgICBpZiAoaiA+IDApIHtcbiAgICAgICAgeS5pdXNocm4oaik7XG4gICAgICAgIHdoaWxlIChqLS0gPiAwKSB7XG4gICAgICAgICAgaWYgKEMuaXNPZGQoKSB8fCBELmlzT2RkKCkpIHtcbiAgICAgICAgICAgIEMuaWFkZCh5cCk7XG4gICAgICAgICAgICBELmlzdWIoeHApO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIEMuaXVzaHJuKDEpO1xuICAgICAgICAgIEQuaXVzaHJuKDEpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICh4LmNtcCh5KSA+PSAwKSB7XG4gICAgICAgIHguaXN1Yih5KTtcbiAgICAgICAgQS5pc3ViKEMpO1xuICAgICAgICBCLmlzdWIoRCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB5LmlzdWIoeCk7XG4gICAgICAgIEMuaXN1YihBKTtcbiAgICAgICAgRC5pc3ViKEIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICBhOiBDLFxuICAgICAgYjogRCxcbiAgICAgIGdjZDogeS5pdXNobG4oZylcbiAgICB9O1xuICB9O1xuXG4gIC8vIFRoaXMgaXMgcmVkdWNlZCBpbmNhcm5hdGlvbiBvZiB0aGUgYmluYXJ5IEVFQVxuICAvLyBhYm92ZSwgZGVzaWduYXRlZCB0byBpbnZlcnQgbWVtYmVycyBvZiB0aGVcbiAgLy8gX3ByaW1lXyBmaWVsZHMgRihwKSBhdCBhIG1heGltYWwgc3BlZWRcbiAgQk4ucHJvdG90eXBlLl9pbnZtcCA9IGZ1bmN0aW9uIF9pbnZtcCAocCkge1xuICAgIGFzc2VydChwLm5lZ2F0aXZlID09PSAwKTtcbiAgICBhc3NlcnQoIXAuaXNaZXJvKCkpO1xuXG4gICAgdmFyIGEgPSB0aGlzO1xuICAgIHZhciBiID0gcC5jbG9uZSgpO1xuXG4gICAgaWYgKGEubmVnYXRpdmUgIT09IDApIHtcbiAgICAgIGEgPSBhLnVtb2QocCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGEgPSBhLmNsb25lKCk7XG4gICAgfVxuXG4gICAgdmFyIHgxID0gbmV3IEJOKDEpO1xuICAgIHZhciB4MiA9IG5ldyBCTigwKTtcblxuICAgIHZhciBkZWx0YSA9IGIuY2xvbmUoKTtcblxuICAgIHdoaWxlIChhLmNtcG4oMSkgPiAwICYmIGIuY21wbigxKSA+IDApIHtcbiAgICAgIGZvciAodmFyIGkgPSAwLCBpbSA9IDE7IChhLndvcmRzWzBdICYgaW0pID09PSAwICYmIGkgPCAyNjsgKytpLCBpbSA8PD0gMSk7XG4gICAgICBpZiAoaSA+IDApIHtcbiAgICAgICAgYS5pdXNocm4oaSk7XG4gICAgICAgIHdoaWxlIChpLS0gPiAwKSB7XG4gICAgICAgICAgaWYgKHgxLmlzT2RkKCkpIHtcbiAgICAgICAgICAgIHgxLmlhZGQoZGVsdGEpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHgxLml1c2hybigxKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBmb3IgKHZhciBqID0gMCwgam0gPSAxOyAoYi53b3Jkc1swXSAmIGptKSA9PT0gMCAmJiBqIDwgMjY7ICsraiwgam0gPDw9IDEpO1xuICAgICAgaWYgKGogPiAwKSB7XG4gICAgICAgIGIuaXVzaHJuKGopO1xuICAgICAgICB3aGlsZSAoai0tID4gMCkge1xuICAgICAgICAgIGlmICh4Mi5pc09kZCgpKSB7XG4gICAgICAgICAgICB4Mi5pYWRkKGRlbHRhKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB4Mi5pdXNocm4oMSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKGEuY21wKGIpID49IDApIHtcbiAgICAgICAgYS5pc3ViKGIpO1xuICAgICAgICB4MS5pc3ViKHgyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGIuaXN1YihhKTtcbiAgICAgICAgeDIuaXN1Yih4MSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdmFyIHJlcztcbiAgICBpZiAoYS5jbXBuKDEpID09PSAwKSB7XG4gICAgICByZXMgPSB4MTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzID0geDI7XG4gICAgfVxuXG4gICAgaWYgKHJlcy5jbXBuKDApIDwgMCkge1xuICAgICAgcmVzLmlhZGQocCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZ2NkID0gZnVuY3Rpb24gZ2NkIChudW0pIHtcbiAgICBpZiAodGhpcy5pc1plcm8oKSkgcmV0dXJuIG51bS5hYnMoKTtcbiAgICBpZiAobnVtLmlzWmVybygpKSByZXR1cm4gdGhpcy5hYnMoKTtcblxuICAgIHZhciBhID0gdGhpcy5jbG9uZSgpO1xuICAgIHZhciBiID0gbnVtLmNsb25lKCk7XG4gICAgYS5uZWdhdGl2ZSA9IDA7XG4gICAgYi5uZWdhdGl2ZSA9IDA7XG5cbiAgICAvLyBSZW1vdmUgY29tbW9uIGZhY3RvciBvZiB0d29cbiAgICBmb3IgKHZhciBzaGlmdCA9IDA7IGEuaXNFdmVuKCkgJiYgYi5pc0V2ZW4oKTsgc2hpZnQrKykge1xuICAgICAgYS5pdXNocm4oMSk7XG4gICAgICBiLml1c2hybigxKTtcbiAgICB9XG5cbiAgICBkbyB7XG4gICAgICB3aGlsZSAoYS5pc0V2ZW4oKSkge1xuICAgICAgICBhLml1c2hybigxKTtcbiAgICAgIH1cbiAgICAgIHdoaWxlIChiLmlzRXZlbigpKSB7XG4gICAgICAgIGIuaXVzaHJuKDEpO1xuICAgICAgfVxuXG4gICAgICB2YXIgciA9IGEuY21wKGIpO1xuICAgICAgaWYgKHIgPCAwKSB7XG4gICAgICAgIC8vIFN3YXAgYGFgIGFuZCBgYmAgdG8gbWFrZSBgYWAgYWx3YXlzIGJpZ2dlciB0aGFuIGBiYFxuICAgICAgICB2YXIgdCA9IGE7XG4gICAgICAgIGEgPSBiO1xuICAgICAgICBiID0gdDtcbiAgICAgIH0gZWxzZSBpZiAociA9PT0gMCB8fCBiLmNtcG4oMSkgPT09IDApIHtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG5cbiAgICAgIGEuaXN1YihiKTtcbiAgICB9IHdoaWxlICh0cnVlKTtcblxuICAgIHJldHVybiBiLml1c2hsbihzaGlmdCk7XG4gIH07XG5cbiAgLy8gSW52ZXJ0IG51bWJlciBpbiB0aGUgZmllbGQgRihudW0pXG4gIEJOLnByb3RvdHlwZS5pbnZtID0gZnVuY3Rpb24gaW52bSAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuZWdjZChudW0pLmEudW1vZChudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pc0V2ZW4gPSBmdW5jdGlvbiBpc0V2ZW4gKCkge1xuICAgIHJldHVybiAodGhpcy53b3Jkc1swXSAmIDEpID09PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pc09kZCA9IGZ1bmN0aW9uIGlzT2RkICgpIHtcbiAgICByZXR1cm4gKHRoaXMud29yZHNbMF0gJiAxKSA9PT0gMTtcbiAgfTtcblxuICAvLyBBbmQgZmlyc3Qgd29yZCBhbmQgbnVtXG4gIEJOLnByb3RvdHlwZS5hbmRsbiA9IGZ1bmN0aW9uIGFuZGxuIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy53b3Jkc1swXSAmIG51bTtcbiAgfTtcblxuICAvLyBJbmNyZW1lbnQgYXQgdGhlIGJpdCBwb3NpdGlvbiBpbi1saW5lXG4gIEJOLnByb3RvdHlwZS5iaW5jbiA9IGZ1bmN0aW9uIGJpbmNuIChiaXQpIHtcbiAgICBhc3NlcnQodHlwZW9mIGJpdCA9PT0gJ251bWJlcicpO1xuICAgIHZhciByID0gYml0ICUgMjY7XG4gICAgdmFyIHMgPSAoYml0IC0gcikgLyAyNjtcbiAgICB2YXIgcSA9IDEgPDwgcjtcblxuICAgIC8vIEZhc3QgY2FzZTogYml0IGlzIG11Y2ggaGlnaGVyIHRoYW4gYWxsIGV4aXN0aW5nIHdvcmRzXG4gICAgaWYgKHRoaXMubGVuZ3RoIDw9IHMpIHtcbiAgICAgIHRoaXMuX2V4cGFuZChzICsgMSk7XG4gICAgICB0aGlzLndvcmRzW3NdIHw9IHE7XG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG5cbiAgICAvLyBBZGQgYml0IGFuZCBwcm9wYWdhdGUsIGlmIG5lZWRlZFxuICAgIHZhciBjYXJyeSA9IHE7XG4gICAgZm9yICh2YXIgaSA9IHM7IGNhcnJ5ICE9PSAwICYmIGkgPCB0aGlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgdyA9IHRoaXMud29yZHNbaV0gfCAwO1xuICAgICAgdyArPSBjYXJyeTtcbiAgICAgIGNhcnJ5ID0gdyA+Pj4gMjY7XG4gICAgICB3ICY9IDB4M2ZmZmZmZjtcbiAgICAgIHRoaXMud29yZHNbaV0gPSB3O1xuICAgIH1cbiAgICBpZiAoY2FycnkgIT09IDApIHtcbiAgICAgIHRoaXMud29yZHNbaV0gPSBjYXJyeTtcbiAgICAgIHRoaXMubGVuZ3RoKys7XG4gICAgfVxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5pc1plcm8gPSBmdW5jdGlvbiBpc1plcm8gKCkge1xuICAgIHJldHVybiB0aGlzLmxlbmd0aCA9PT0gMSAmJiB0aGlzLndvcmRzWzBdID09PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5jbXBuID0gZnVuY3Rpb24gY21wbiAobnVtKSB7XG4gICAgdmFyIG5lZ2F0aXZlID0gbnVtIDwgMDtcblxuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwICYmICFuZWdhdGl2ZSkgcmV0dXJuIC0xO1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlID09PSAwICYmIG5lZ2F0aXZlKSByZXR1cm4gMTtcblxuICAgIHRoaXMuc3RyaXAoKTtcblxuICAgIHZhciByZXM7XG4gICAgaWYgKHRoaXMubGVuZ3RoID4gMSkge1xuICAgICAgcmVzID0gMTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKG5lZ2F0aXZlKSB7XG4gICAgICAgIG51bSA9IC1udW07XG4gICAgICB9XG5cbiAgICAgIGFzc2VydChudW0gPD0gMHgzZmZmZmZmLCAnTnVtYmVyIGlzIHRvbyBiaWcnKTtcblxuICAgICAgdmFyIHcgPSB0aGlzLndvcmRzWzBdIHwgMDtcbiAgICAgIHJlcyA9IHcgPT09IG51bSA/IDAgOiB3IDwgbnVtID8gLTEgOiAxO1xuICAgIH1cbiAgICBpZiAodGhpcy5uZWdhdGl2ZSAhPT0gMCkgcmV0dXJuIC1yZXMgfCAwO1xuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgLy8gQ29tcGFyZSB0d28gbnVtYmVycyBhbmQgcmV0dXJuOlxuICAvLyAxIC0gaWYgYHRoaXNgID4gYG51bWBcbiAgLy8gMCAtIGlmIGB0aGlzYCA9PSBgbnVtYFxuICAvLyAtMSAtIGlmIGB0aGlzYCA8IGBudW1gXG4gIEJOLnByb3RvdHlwZS5jbXAgPSBmdW5jdGlvbiBjbXAgKG51bSkge1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlICE9PSAwICYmIG51bS5uZWdhdGl2ZSA9PT0gMCkgcmV0dXJuIC0xO1xuICAgIGlmICh0aGlzLm5lZ2F0aXZlID09PSAwICYmIG51bS5uZWdhdGl2ZSAhPT0gMCkgcmV0dXJuIDE7XG5cbiAgICB2YXIgcmVzID0gdGhpcy51Y21wKG51bSk7XG4gICAgaWYgKHRoaXMubmVnYXRpdmUgIT09IDApIHJldHVybiAtcmVzIHwgMDtcbiAgICByZXR1cm4gcmVzO1xuICB9O1xuXG4gIC8vIFVuc2lnbmVkIGNvbXBhcmlzb25cbiAgQk4ucHJvdG90eXBlLnVjbXAgPSBmdW5jdGlvbiB1Y21wIChudW0pIHtcbiAgICAvLyBBdCB0aGlzIHBvaW50IGJvdGggbnVtYmVycyBoYXZlIHRoZSBzYW1lIHNpZ25cbiAgICBpZiAodGhpcy5sZW5ndGggPiBudW0ubGVuZ3RoKSByZXR1cm4gMTtcbiAgICBpZiAodGhpcy5sZW5ndGggPCBudW0ubGVuZ3RoKSByZXR1cm4gLTE7XG5cbiAgICB2YXIgcmVzID0gMDtcbiAgICBmb3IgKHZhciBpID0gdGhpcy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkge1xuICAgICAgdmFyIGEgPSB0aGlzLndvcmRzW2ldIHwgMDtcbiAgICAgIHZhciBiID0gbnVtLndvcmRzW2ldIHwgMDtcblxuICAgICAgaWYgKGEgPT09IGIpIGNvbnRpbnVlO1xuICAgICAgaWYgKGEgPCBiKSB7XG4gICAgICAgIHJlcyA9IC0xO1xuICAgICAgfSBlbHNlIGlmIChhID4gYikge1xuICAgICAgICByZXMgPSAxO1xuICAgICAgfVxuICAgICAgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmd0biA9IGZ1bmN0aW9uIGd0biAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wbihudW0pID09PSAxO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5ndCA9IGZ1bmN0aW9uIGd0IChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbXAobnVtKSA9PT0gMTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZ3RlbiA9IGZ1bmN0aW9uIGd0ZW4gKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcG4obnVtKSA+PSAwO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5ndGUgPSBmdW5jdGlvbiBndGUgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcChudW0pID49IDA7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmx0biA9IGZ1bmN0aW9uIGx0biAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wbihudW0pID09PSAtMTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUubHQgPSBmdW5jdGlvbiBsdCAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wKG51bSkgPT09IC0xO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5sdGVuID0gZnVuY3Rpb24gbHRlbiAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wbihudW0pIDw9IDA7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmx0ZSA9IGZ1bmN0aW9uIGx0ZSAobnVtKSB7XG4gICAgcmV0dXJuIHRoaXMuY21wKG51bSkgPD0gMDtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZXFuID0gZnVuY3Rpb24gZXFuIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5jbXBuKG51bSkgPT09IDA7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLmVxID0gZnVuY3Rpb24gZXEgKG51bSkge1xuICAgIHJldHVybiB0aGlzLmNtcChudW0pID09PSAwO1xuICB9O1xuXG4gIC8vXG4gIC8vIEEgcmVkdWNlIGNvbnRleHQsIGNvdWxkIGJlIHVzaW5nIG1vbnRnb21lcnkgb3Igc29tZXRoaW5nIGJldHRlciwgZGVwZW5kaW5nXG4gIC8vIG9uIHRoZSBgbWAgaXRzZWxmLlxuICAvL1xuICBCTi5yZWQgPSBmdW5jdGlvbiByZWQgKG51bSkge1xuICAgIHJldHVybiBuZXcgUmVkKG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnRvUmVkID0gZnVuY3Rpb24gdG9SZWQgKGN0eCkge1xuICAgIGFzc2VydCghdGhpcy5yZWQsICdBbHJlYWR5IGEgbnVtYmVyIGluIHJlZHVjdGlvbiBjb250ZXh0Jyk7XG4gICAgYXNzZXJ0KHRoaXMubmVnYXRpdmUgPT09IDAsICdyZWQgd29ya3Mgb25seSB3aXRoIHBvc2l0aXZlcycpO1xuICAgIHJldHVybiBjdHguY29udmVydFRvKHRoaXMpLl9mb3JjZVJlZChjdHgpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5mcm9tUmVkID0gZnVuY3Rpb24gZnJvbVJlZCAoKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAnZnJvbVJlZCB3b3JrcyBvbmx5IHdpdGggbnVtYmVycyBpbiByZWR1Y3Rpb24gY29udGV4dCcpO1xuICAgIHJldHVybiB0aGlzLnJlZC5jb252ZXJ0RnJvbSh0aGlzKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuX2ZvcmNlUmVkID0gZnVuY3Rpb24gX2ZvcmNlUmVkIChjdHgpIHtcbiAgICB0aGlzLnJlZCA9IGN0eDtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCTi5wcm90b3R5cGUuZm9yY2VSZWQgPSBmdW5jdGlvbiBmb3JjZVJlZCAoY3R4KSB7XG4gICAgYXNzZXJ0KCF0aGlzLnJlZCwgJ0FscmVhZHkgYSBudW1iZXIgaW4gcmVkdWN0aW9uIGNvbnRleHQnKTtcbiAgICByZXR1cm4gdGhpcy5fZm9yY2VSZWQoY3R4KTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkQWRkID0gZnVuY3Rpb24gcmVkQWRkIChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRBZGQgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLmFkZCh0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRJQWRkID0gZnVuY3Rpb24gcmVkSUFkZCAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkSUFkZCB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuaWFkZCh0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRTdWIgPSBmdW5jdGlvbiByZWRTdWIgKG51bSkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZFN1YiB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuc3ViKHRoaXMsIG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnJlZElTdWIgPSBmdW5jdGlvbiByZWRJU3ViIChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRJU3ViIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHJldHVybiB0aGlzLnJlZC5pc3ViKHRoaXMsIG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnJlZFNobCA9IGZ1bmN0aW9uIHJlZFNobCAobnVtKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkU2hsIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHJldHVybiB0aGlzLnJlZC5zaGwodGhpcywgbnVtKTtcbiAgfTtcblxuICBCTi5wcm90b3R5cGUucmVkTXVsID0gZnVuY3Rpb24gcmVkTXVsIChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRNdWwgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTIodGhpcywgbnVtKTtcbiAgICByZXR1cm4gdGhpcy5yZWQubXVsKHRoaXMsIG51bSk7XG4gIH07XG5cbiAgQk4ucHJvdG90eXBlLnJlZElNdWwgPSBmdW5jdGlvbiByZWRJTXVsIChudW0pIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRNdWwgd29ya3Mgb25seSB3aXRoIHJlZCBudW1iZXJzJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTIodGhpcywgbnVtKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuaW11bCh0aGlzLCBudW0pO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRTcXIgPSBmdW5jdGlvbiByZWRTcXIgKCkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZFNxciB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICB0aGlzLnJlZC5fdmVyaWZ5MSh0aGlzKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuc3FyKHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRJU3FyID0gZnVuY3Rpb24gcmVkSVNxciAoKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkSVNxciB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICB0aGlzLnJlZC5fdmVyaWZ5MSh0aGlzKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuaXNxcih0aGlzKTtcbiAgfTtcblxuICAvLyBTcXVhcmUgcm9vdCBvdmVyIHBcbiAgQk4ucHJvdG90eXBlLnJlZFNxcnQgPSBmdW5jdGlvbiByZWRTcXJ0ICgpIHtcbiAgICBhc3NlcnQodGhpcy5yZWQsICdyZWRTcXJ0IHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICAgIHRoaXMucmVkLl92ZXJpZnkxKHRoaXMpO1xuICAgIHJldHVybiB0aGlzLnJlZC5zcXJ0KHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRJbnZtID0gZnVuY3Rpb24gcmVkSW52bSAoKSB7XG4gICAgYXNzZXJ0KHRoaXMucmVkLCAncmVkSW52bSB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICB0aGlzLnJlZC5fdmVyaWZ5MSh0aGlzKTtcbiAgICByZXR1cm4gdGhpcy5yZWQuaW52bSh0aGlzKTtcbiAgfTtcblxuICAvLyBSZXR1cm4gbmVnYXRpdmUgY2xvbmUgb2YgYHRoaXNgICUgYHJlZCBtb2R1bG9gXG4gIEJOLnByb3RvdHlwZS5yZWROZWcgPSBmdW5jdGlvbiByZWROZWcgKCkge1xuICAgIGFzc2VydCh0aGlzLnJlZCwgJ3JlZE5lZyB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgICB0aGlzLnJlZC5fdmVyaWZ5MSh0aGlzKTtcbiAgICByZXR1cm4gdGhpcy5yZWQubmVnKHRoaXMpO1xuICB9O1xuXG4gIEJOLnByb3RvdHlwZS5yZWRQb3cgPSBmdW5jdGlvbiByZWRQb3cgKG51bSkge1xuICAgIGFzc2VydCh0aGlzLnJlZCAmJiAhbnVtLnJlZCwgJ3JlZFBvdyhub3JtYWxOdW0pJyk7XG4gICAgdGhpcy5yZWQuX3ZlcmlmeTEodGhpcyk7XG4gICAgcmV0dXJuIHRoaXMucmVkLnBvdyh0aGlzLCBudW0pO1xuICB9O1xuXG4gIC8vIFByaW1lIG51bWJlcnMgd2l0aCBlZmZpY2llbnQgcmVkdWN0aW9uXG4gIHZhciBwcmltZXMgPSB7XG4gICAgazI1NjogbnVsbCxcbiAgICBwMjI0OiBudWxsLFxuICAgIHAxOTI6IG51bGwsXG4gICAgcDI1NTE5OiBudWxsXG4gIH07XG5cbiAgLy8gUHNldWRvLU1lcnNlbm5lIHByaW1lXG4gIGZ1bmN0aW9uIE1QcmltZSAobmFtZSwgcCkge1xuICAgIC8vIFAgPSAyIF4gTiAtIEtcbiAgICB0aGlzLm5hbWUgPSBuYW1lO1xuICAgIHRoaXMucCA9IG5ldyBCTihwLCAxNik7XG4gICAgdGhpcy5uID0gdGhpcy5wLmJpdExlbmd0aCgpO1xuICAgIHRoaXMuayA9IG5ldyBCTigxKS5pdXNobG4odGhpcy5uKS5pc3ViKHRoaXMucCk7XG5cbiAgICB0aGlzLnRtcCA9IHRoaXMuX3RtcCgpO1xuICB9XG5cbiAgTVByaW1lLnByb3RvdHlwZS5fdG1wID0gZnVuY3Rpb24gX3RtcCAoKSB7XG4gICAgdmFyIHRtcCA9IG5ldyBCTihudWxsKTtcbiAgICB0bXAud29yZHMgPSBuZXcgQXJyYXkoTWF0aC5jZWlsKHRoaXMubiAvIDEzKSk7XG4gICAgcmV0dXJuIHRtcDtcbiAgfTtcblxuICBNUHJpbWUucHJvdG90eXBlLmlyZWR1Y2UgPSBmdW5jdGlvbiBpcmVkdWNlIChudW0pIHtcbiAgICAvLyBBc3N1bWVzIHRoYXQgYG51bWAgaXMgbGVzcyB0aGFuIGBQXjJgXG4gICAgLy8gbnVtID0gSEkgKiAoMiBeIE4gLSBLKSArIEhJICogSyArIExPID0gSEkgKiBLICsgTE8gKG1vZCBQKVxuICAgIHZhciByID0gbnVtO1xuICAgIHZhciBybGVuO1xuXG4gICAgZG8ge1xuICAgICAgdGhpcy5zcGxpdChyLCB0aGlzLnRtcCk7XG4gICAgICByID0gdGhpcy5pbXVsSyhyKTtcbiAgICAgIHIgPSByLmlhZGQodGhpcy50bXApO1xuICAgICAgcmxlbiA9IHIuYml0TGVuZ3RoKCk7XG4gICAgfSB3aGlsZSAocmxlbiA+IHRoaXMubik7XG5cbiAgICB2YXIgY21wID0gcmxlbiA8IHRoaXMubiA/IC0xIDogci51Y21wKHRoaXMucCk7XG4gICAgaWYgKGNtcCA9PT0gMCkge1xuICAgICAgci53b3Jkc1swXSA9IDA7XG4gICAgICByLmxlbmd0aCA9IDE7XG4gICAgfSBlbHNlIGlmIChjbXAgPiAwKSB7XG4gICAgICByLmlzdWIodGhpcy5wKTtcbiAgICB9IGVsc2Uge1xuICAgICAgci5zdHJpcCgpO1xuICAgIH1cblxuICAgIHJldHVybiByO1xuICB9O1xuXG4gIE1QcmltZS5wcm90b3R5cGUuc3BsaXQgPSBmdW5jdGlvbiBzcGxpdCAoaW5wdXQsIG91dCkge1xuICAgIGlucHV0Lml1c2hybih0aGlzLm4sIDAsIG91dCk7XG4gIH07XG5cbiAgTVByaW1lLnByb3RvdHlwZS5pbXVsSyA9IGZ1bmN0aW9uIGltdWxLIChudW0pIHtcbiAgICByZXR1cm4gbnVtLmltdWwodGhpcy5rKTtcbiAgfTtcblxuICBmdW5jdGlvbiBLMjU2ICgpIHtcbiAgICBNUHJpbWUuY2FsbChcbiAgICAgIHRoaXMsXG4gICAgICAnazI1NicsXG4gICAgICAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmUgZmZmZmZjMmYnKTtcbiAgfVxuICBpbmhlcml0cyhLMjU2LCBNUHJpbWUpO1xuXG4gIEsyNTYucHJvdG90eXBlLnNwbGl0ID0gZnVuY3Rpb24gc3BsaXQgKGlucHV0LCBvdXRwdXQpIHtcbiAgICAvLyAyNTYgPSA5ICogMjYgKyAyMlxuICAgIHZhciBtYXNrID0gMHgzZmZmZmY7XG5cbiAgICB2YXIgb3V0TGVuID0gTWF0aC5taW4oaW5wdXQubGVuZ3RoLCA5KTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG91dExlbjsgaSsrKSB7XG4gICAgICBvdXRwdXQud29yZHNbaV0gPSBpbnB1dC53b3Jkc1tpXTtcbiAgICB9XG4gICAgb3V0cHV0Lmxlbmd0aCA9IG91dExlbjtcblxuICAgIGlmIChpbnB1dC5sZW5ndGggPD0gOSkge1xuICAgICAgaW5wdXQud29yZHNbMF0gPSAwO1xuICAgICAgaW5wdXQubGVuZ3RoID0gMTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBTaGlmdCBieSA5IGxpbWJzXG4gICAgdmFyIHByZXYgPSBpbnB1dC53b3Jkc1s5XTtcbiAgICBvdXRwdXQud29yZHNbb3V0cHV0Lmxlbmd0aCsrXSA9IHByZXYgJiBtYXNrO1xuXG4gICAgZm9yIChpID0gMTA7IGkgPCBpbnB1dC5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIG5leHQgPSBpbnB1dC53b3Jkc1tpXSB8IDA7XG4gICAgICBpbnB1dC53b3Jkc1tpIC0gMTBdID0gKChuZXh0ICYgbWFzaykgPDwgNCkgfCAocHJldiA+Pj4gMjIpO1xuICAgICAgcHJldiA9IG5leHQ7XG4gICAgfVxuICAgIHByZXYgPj4+PSAyMjtcbiAgICBpbnB1dC53b3Jkc1tpIC0gMTBdID0gcHJldjtcbiAgICBpZiAocHJldiA9PT0gMCAmJiBpbnB1dC5sZW5ndGggPiAxMCkge1xuICAgICAgaW5wdXQubGVuZ3RoIC09IDEwO1xuICAgIH0gZWxzZSB7XG4gICAgICBpbnB1dC5sZW5ndGggLT0gOTtcbiAgICB9XG4gIH07XG5cbiAgSzI1Ni5wcm90b3R5cGUuaW11bEsgPSBmdW5jdGlvbiBpbXVsSyAobnVtKSB7XG4gICAgLy8gSyA9IDB4MTAwMDAwM2QxID0gWyAweDQwLCAweDNkMSBdXG4gICAgbnVtLndvcmRzW251bS5sZW5ndGhdID0gMDtcbiAgICBudW0ud29yZHNbbnVtLmxlbmd0aCArIDFdID0gMDtcbiAgICBudW0ubGVuZ3RoICs9IDI7XG5cbiAgICAvLyBib3VuZGVkIGF0OiAweDQwICogMHgzZmZmZmZmICsgMHgzZDAgPSAweDEwMDAwMDM5MFxuICAgIHZhciBsbyA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBudW0ubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciB3ID0gbnVtLndvcmRzW2ldIHwgMDtcbiAgICAgIGxvICs9IHcgKiAweDNkMTtcbiAgICAgIG51bS53b3Jkc1tpXSA9IGxvICYgMHgzZmZmZmZmO1xuICAgICAgbG8gPSB3ICogMHg0MCArICgobG8gLyAweDQwMDAwMDApIHwgMCk7XG4gICAgfVxuXG4gICAgLy8gRmFzdCBsZW5ndGggcmVkdWN0aW9uXG4gICAgaWYgKG51bS53b3Jkc1tudW0ubGVuZ3RoIC0gMV0gPT09IDApIHtcbiAgICAgIG51bS5sZW5ndGgtLTtcbiAgICAgIGlmIChudW0ud29yZHNbbnVtLmxlbmd0aCAtIDFdID09PSAwKSB7XG4gICAgICAgIG51bS5sZW5ndGgtLTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG51bTtcbiAgfTtcblxuICBmdW5jdGlvbiBQMjI0ICgpIHtcbiAgICBNUHJpbWUuY2FsbChcbiAgICAgIHRoaXMsXG4gICAgICAncDIyNCcsXG4gICAgICAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDEnKTtcbiAgfVxuICBpbmhlcml0cyhQMjI0LCBNUHJpbWUpO1xuXG4gIGZ1bmN0aW9uIFAxOTIgKCkge1xuICAgIE1QcmltZS5jYWxsKFxuICAgICAgdGhpcyxcbiAgICAgICdwMTkyJyxcbiAgICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmZicpO1xuICB9XG4gIGluaGVyaXRzKFAxOTIsIE1QcmltZSk7XG5cbiAgZnVuY3Rpb24gUDI1NTE5ICgpIHtcbiAgICAvLyAyIF4gMjU1IC0gMTlcbiAgICBNUHJpbWUuY2FsbChcbiAgICAgIHRoaXMsXG4gICAgICAnMjU1MTknLFxuICAgICAgJzdmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZWQnKTtcbiAgfVxuICBpbmhlcml0cyhQMjU1MTksIE1QcmltZSk7XG5cbiAgUDI1NTE5LnByb3RvdHlwZS5pbXVsSyA9IGZ1bmN0aW9uIGltdWxLIChudW0pIHtcbiAgICAvLyBLID0gMHgxM1xuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBudW0ubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoaSA9IChudW0ud29yZHNbaV0gfCAwKSAqIDB4MTMgKyBjYXJyeTtcbiAgICAgIHZhciBsbyA9IGhpICYgMHgzZmZmZmZmO1xuICAgICAgaGkgPj4+PSAyNjtcblxuICAgICAgbnVtLndvcmRzW2ldID0gbG87XG4gICAgICBjYXJyeSA9IGhpO1xuICAgIH1cbiAgICBpZiAoY2FycnkgIT09IDApIHtcbiAgICAgIG51bS53b3Jkc1tudW0ubGVuZ3RoKytdID0gY2Fycnk7XG4gICAgfVxuICAgIHJldHVybiBudW07XG4gIH07XG5cbiAgLy8gRXhwb3J0ZWQgbW9zdGx5IGZvciB0ZXN0aW5nIHB1cnBvc2VzLCB1c2UgcGxhaW4gbmFtZSBpbnN0ZWFkXG4gIEJOLl9wcmltZSA9IGZ1bmN0aW9uIHByaW1lIChuYW1lKSB7XG4gICAgLy8gQ2FjaGVkIHZlcnNpb24gb2YgcHJpbWVcbiAgICBpZiAocHJpbWVzW25hbWVdKSByZXR1cm4gcHJpbWVzW25hbWVdO1xuXG4gICAgdmFyIHByaW1lO1xuICAgIGlmIChuYW1lID09PSAnazI1NicpIHtcbiAgICAgIHByaW1lID0gbmV3IEsyNTYoKTtcbiAgICB9IGVsc2UgaWYgKG5hbWUgPT09ICdwMjI0Jykge1xuICAgICAgcHJpbWUgPSBuZXcgUDIyNCgpO1xuICAgIH0gZWxzZSBpZiAobmFtZSA9PT0gJ3AxOTInKSB7XG4gICAgICBwcmltZSA9IG5ldyBQMTkyKCk7XG4gICAgfSBlbHNlIGlmIChuYW1lID09PSAncDI1NTE5Jykge1xuICAgICAgcHJpbWUgPSBuZXcgUDI1NTE5KCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVW5rbm93biBwcmltZSAnICsgbmFtZSk7XG4gICAgfVxuICAgIHByaW1lc1tuYW1lXSA9IHByaW1lO1xuXG4gICAgcmV0dXJuIHByaW1lO1xuICB9O1xuXG4gIC8vXG4gIC8vIEJhc2UgcmVkdWN0aW9uIGVuZ2luZVxuICAvL1xuICBmdW5jdGlvbiBSZWQgKG0pIHtcbiAgICBpZiAodHlwZW9mIG0gPT09ICdzdHJpbmcnKSB7XG4gICAgICB2YXIgcHJpbWUgPSBCTi5fcHJpbWUobSk7XG4gICAgICB0aGlzLm0gPSBwcmltZS5wO1xuICAgICAgdGhpcy5wcmltZSA9IHByaW1lO1xuICAgIH0gZWxzZSB7XG4gICAgICBhc3NlcnQobS5ndG4oMSksICdtb2R1bHVzIG11c3QgYmUgZ3JlYXRlciB0aGFuIDEnKTtcbiAgICAgIHRoaXMubSA9IG07XG4gICAgICB0aGlzLnByaW1lID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBSZWQucHJvdG90eXBlLl92ZXJpZnkxID0gZnVuY3Rpb24gX3ZlcmlmeTEgKGEpIHtcbiAgICBhc3NlcnQoYS5uZWdhdGl2ZSA9PT0gMCwgJ3JlZCB3b3JrcyBvbmx5IHdpdGggcG9zaXRpdmVzJyk7XG4gICAgYXNzZXJ0KGEucmVkLCAncmVkIHdvcmtzIG9ubHkgd2l0aCByZWQgbnVtYmVycycpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuX3ZlcmlmeTIgPSBmdW5jdGlvbiBfdmVyaWZ5MiAoYSwgYikge1xuICAgIGFzc2VydCgoYS5uZWdhdGl2ZSB8IGIubmVnYXRpdmUpID09PSAwLCAncmVkIHdvcmtzIG9ubHkgd2l0aCBwb3NpdGl2ZXMnKTtcbiAgICBhc3NlcnQoYS5yZWQgJiYgYS5yZWQgPT09IGIucmVkLFxuICAgICAgJ3JlZCB3b3JrcyBvbmx5IHdpdGggcmVkIG51bWJlcnMnKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLmltb2QgPSBmdW5jdGlvbiBpbW9kIChhKSB7XG4gICAgaWYgKHRoaXMucHJpbWUpIHJldHVybiB0aGlzLnByaW1lLmlyZWR1Y2UoYSkuX2ZvcmNlUmVkKHRoaXMpO1xuICAgIHJldHVybiBhLnVtb2QodGhpcy5tKS5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5uZWcgPSBmdW5jdGlvbiBuZWcgKGEpIHtcbiAgICBpZiAoYS5pc1plcm8oKSkge1xuICAgICAgcmV0dXJuIGEuY2xvbmUoKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5tLnN1YihhKS5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5hZGQgPSBmdW5jdGlvbiBhZGQgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuXG4gICAgdmFyIHJlcyA9IGEuYWRkKGIpO1xuICAgIGlmIChyZXMuY21wKHRoaXMubSkgPj0gMCkge1xuICAgICAgcmVzLmlzdWIodGhpcy5tKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcy5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5pYWRkID0gZnVuY3Rpb24gaWFkZCAoYSwgYikge1xuICAgIHRoaXMuX3ZlcmlmeTIoYSwgYik7XG5cbiAgICB2YXIgcmVzID0gYS5pYWRkKGIpO1xuICAgIGlmIChyZXMuY21wKHRoaXMubSkgPj0gMCkge1xuICAgICAgcmVzLmlzdWIodGhpcy5tKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLnN1YiA9IGZ1bmN0aW9uIHN1YiAoYSwgYikge1xuICAgIHRoaXMuX3ZlcmlmeTIoYSwgYik7XG5cbiAgICB2YXIgcmVzID0gYS5zdWIoYik7XG4gICAgaWYgKHJlcy5jbXBuKDApIDwgMCkge1xuICAgICAgcmVzLmlhZGQodGhpcy5tKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcy5fZm9yY2VSZWQodGhpcyk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5pc3ViID0gZnVuY3Rpb24gaXN1YiAoYSwgYikge1xuICAgIHRoaXMuX3ZlcmlmeTIoYSwgYik7XG5cbiAgICB2YXIgcmVzID0gYS5pc3ViKGIpO1xuICAgIGlmIChyZXMuY21wbigwKSA8IDApIHtcbiAgICAgIHJlcy5pYWRkKHRoaXMubSk7XG4gICAgfVxuICAgIHJldHVybiByZXM7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5zaGwgPSBmdW5jdGlvbiBzaGwgKGEsIG51bSkge1xuICAgIHRoaXMuX3ZlcmlmeTEoYSk7XG4gICAgcmV0dXJuIHRoaXMuaW1vZChhLnVzaGxuKG51bSkpO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuaW11bCA9IGZ1bmN0aW9uIGltdWwgKGEsIGIpIHtcbiAgICB0aGlzLl92ZXJpZnkyKGEsIGIpO1xuICAgIHJldHVybiB0aGlzLmltb2QoYS5pbXVsKGIpKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLm11bCA9IGZ1bmN0aW9uIG11bCAoYSwgYikge1xuICAgIHRoaXMuX3ZlcmlmeTIoYSwgYik7XG4gICAgcmV0dXJuIHRoaXMuaW1vZChhLm11bChiKSk7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5pc3FyID0gZnVuY3Rpb24gaXNxciAoYSkge1xuICAgIHJldHVybiB0aGlzLmltdWwoYSwgYS5jbG9uZSgpKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLnNxciA9IGZ1bmN0aW9uIHNxciAoYSkge1xuICAgIHJldHVybiB0aGlzLm11bChhLCBhKTtcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLnNxcnQgPSBmdW5jdGlvbiBzcXJ0IChhKSB7XG4gICAgaWYgKGEuaXNaZXJvKCkpIHJldHVybiBhLmNsb25lKCk7XG5cbiAgICB2YXIgbW9kMyA9IHRoaXMubS5hbmRsbigzKTtcbiAgICBhc3NlcnQobW9kMyAlIDIgPT09IDEpO1xuXG4gICAgLy8gRmFzdCBjYXNlXG4gICAgaWYgKG1vZDMgPT09IDMpIHtcbiAgICAgIHZhciBwb3cgPSB0aGlzLm0uYWRkKG5ldyBCTigxKSkuaXVzaHJuKDIpO1xuICAgICAgcmV0dXJuIHRoaXMucG93KGEsIHBvdyk7XG4gICAgfVxuXG4gICAgLy8gVG9uZWxsaS1TaGFua3MgYWxnb3JpdGhtIChUb3RhbGx5IHVub3B0aW1pemVkIGFuZCBzbG93KVxuICAgIC8vXG4gICAgLy8gRmluZCBRIGFuZCBTLCB0aGF0IFEgKiAyIF4gUyA9IChQIC0gMSlcbiAgICB2YXIgcSA9IHRoaXMubS5zdWJuKDEpO1xuICAgIHZhciBzID0gMDtcbiAgICB3aGlsZSAoIXEuaXNaZXJvKCkgJiYgcS5hbmRsbigxKSA9PT0gMCkge1xuICAgICAgcysrO1xuICAgICAgcS5pdXNocm4oMSk7XG4gICAgfVxuICAgIGFzc2VydCghcS5pc1plcm8oKSk7XG5cbiAgICB2YXIgb25lID0gbmV3IEJOKDEpLnRvUmVkKHRoaXMpO1xuICAgIHZhciBuT25lID0gb25lLnJlZE5lZygpO1xuXG4gICAgLy8gRmluZCBxdWFkcmF0aWMgbm9uLXJlc2lkdWVcbiAgICAvLyBOT1RFOiBNYXggaXMgc3VjaCBiZWNhdXNlIG9mIGdlbmVyYWxpemVkIFJpZW1hbm4gaHlwb3RoZXNpcy5cbiAgICB2YXIgbHBvdyA9IHRoaXMubS5zdWJuKDEpLml1c2hybigxKTtcbiAgICB2YXIgeiA9IHRoaXMubS5iaXRMZW5ndGgoKTtcbiAgICB6ID0gbmV3IEJOKDIgKiB6ICogeikudG9SZWQodGhpcyk7XG5cbiAgICB3aGlsZSAodGhpcy5wb3coeiwgbHBvdykuY21wKG5PbmUpICE9PSAwKSB7XG4gICAgICB6LnJlZElBZGQobk9uZSk7XG4gICAgfVxuXG4gICAgdmFyIGMgPSB0aGlzLnBvdyh6LCBxKTtcbiAgICB2YXIgciA9IHRoaXMucG93KGEsIHEuYWRkbigxKS5pdXNocm4oMSkpO1xuICAgIHZhciB0ID0gdGhpcy5wb3coYSwgcSk7XG4gICAgdmFyIG0gPSBzO1xuICAgIHdoaWxlICh0LmNtcChvbmUpICE9PSAwKSB7XG4gICAgICB2YXIgdG1wID0gdDtcbiAgICAgIGZvciAodmFyIGkgPSAwOyB0bXAuY21wKG9uZSkgIT09IDA7IGkrKykge1xuICAgICAgICB0bXAgPSB0bXAucmVkU3FyKCk7XG4gICAgICB9XG4gICAgICBhc3NlcnQoaSA8IG0pO1xuICAgICAgdmFyIGIgPSB0aGlzLnBvdyhjLCBuZXcgQk4oMSkuaXVzaGxuKG0gLSBpIC0gMSkpO1xuXG4gICAgICByID0gci5yZWRNdWwoYik7XG4gICAgICBjID0gYi5yZWRTcXIoKTtcbiAgICAgIHQgPSB0LnJlZE11bChjKTtcbiAgICAgIG0gPSBpO1xuICAgIH1cblxuICAgIHJldHVybiByO1xuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUuaW52bSA9IGZ1bmN0aW9uIGludm0gKGEpIHtcbiAgICB2YXIgaW52ID0gYS5faW52bXAodGhpcy5tKTtcbiAgICBpZiAoaW52Lm5lZ2F0aXZlICE9PSAwKSB7XG4gICAgICBpbnYubmVnYXRpdmUgPSAwO1xuICAgICAgcmV0dXJuIHRoaXMuaW1vZChpbnYpLnJlZE5lZygpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5pbW9kKGludik7XG4gICAgfVxuICB9O1xuXG4gIFJlZC5wcm90b3R5cGUucG93ID0gZnVuY3Rpb24gcG93IChhLCBudW0pIHtcbiAgICBpZiAobnVtLmlzWmVybygpKSByZXR1cm4gbmV3IEJOKDEpO1xuICAgIGlmIChudW0uY21wbigxKSA9PT0gMCkgcmV0dXJuIGEuY2xvbmUoKTtcblxuICAgIHZhciB3aW5kb3dTaXplID0gNDtcbiAgICB2YXIgd25kID0gbmV3IEFycmF5KDEgPDwgd2luZG93U2l6ZSk7XG4gICAgd25kWzBdID0gbmV3IEJOKDEpLnRvUmVkKHRoaXMpO1xuICAgIHduZFsxXSA9IGE7XG4gICAgZm9yICh2YXIgaSA9IDI7IGkgPCB3bmQubGVuZ3RoOyBpKyspIHtcbiAgICAgIHduZFtpXSA9IHRoaXMubXVsKHduZFtpIC0gMV0sIGEpO1xuICAgIH1cblxuICAgIHZhciByZXMgPSB3bmRbMF07XG4gICAgdmFyIGN1cnJlbnQgPSAwO1xuICAgIHZhciBjdXJyZW50TGVuID0gMDtcbiAgICB2YXIgc3RhcnQgPSBudW0uYml0TGVuZ3RoKCkgJSAyNjtcbiAgICBpZiAoc3RhcnQgPT09IDApIHtcbiAgICAgIHN0YXJ0ID0gMjY7XG4gICAgfVxuXG4gICAgZm9yIChpID0gbnVtLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgICB2YXIgd29yZCA9IG51bS53b3Jkc1tpXTtcbiAgICAgIGZvciAodmFyIGogPSBzdGFydCAtIDE7IGogPj0gMDsgai0tKSB7XG4gICAgICAgIHZhciBiaXQgPSAod29yZCA+PiBqKSAmIDE7XG4gICAgICAgIGlmIChyZXMgIT09IHduZFswXSkge1xuICAgICAgICAgIHJlcyA9IHRoaXMuc3FyKHJlcyk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoYml0ID09PSAwICYmIGN1cnJlbnQgPT09IDApIHtcbiAgICAgICAgICBjdXJyZW50TGVuID0gMDtcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGN1cnJlbnQgPDw9IDE7XG4gICAgICAgIGN1cnJlbnQgfD0gYml0O1xuICAgICAgICBjdXJyZW50TGVuKys7XG4gICAgICAgIGlmIChjdXJyZW50TGVuICE9PSB3aW5kb3dTaXplICYmIChpICE9PSAwIHx8IGogIT09IDApKSBjb250aW51ZTtcblxuICAgICAgICByZXMgPSB0aGlzLm11bChyZXMsIHduZFtjdXJyZW50XSk7XG4gICAgICAgIGN1cnJlbnRMZW4gPSAwO1xuICAgICAgICBjdXJyZW50ID0gMDtcbiAgICAgIH1cbiAgICAgIHN0YXJ0ID0gMjY7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICBSZWQucHJvdG90eXBlLmNvbnZlcnRUbyA9IGZ1bmN0aW9uIGNvbnZlcnRUbyAobnVtKSB7XG4gICAgdmFyIHIgPSBudW0udW1vZCh0aGlzLm0pO1xuXG4gICAgcmV0dXJuIHIgPT09IG51bSA/IHIuY2xvbmUoKSA6IHI7XG4gIH07XG5cbiAgUmVkLnByb3RvdHlwZS5jb252ZXJ0RnJvbSA9IGZ1bmN0aW9uIGNvbnZlcnRGcm9tIChudW0pIHtcbiAgICB2YXIgcmVzID0gbnVtLmNsb25lKCk7XG4gICAgcmVzLnJlZCA9IG51bGw7XG4gICAgcmV0dXJuIHJlcztcbiAgfTtcblxuICAvL1xuICAvLyBNb250Z29tZXJ5IG1ldGhvZCBlbmdpbmVcbiAgLy9cblxuICBCTi5tb250ID0gZnVuY3Rpb24gbW9udCAobnVtKSB7XG4gICAgcmV0dXJuIG5ldyBNb250KG51bSk7XG4gIH07XG5cbiAgZnVuY3Rpb24gTW9udCAobSkge1xuICAgIFJlZC5jYWxsKHRoaXMsIG0pO1xuXG4gICAgdGhpcy5zaGlmdCA9IHRoaXMubS5iaXRMZW5ndGgoKTtcbiAgICBpZiAodGhpcy5zaGlmdCAlIDI2ICE9PSAwKSB7XG4gICAgICB0aGlzLnNoaWZ0ICs9IDI2IC0gKHRoaXMuc2hpZnQgJSAyNik7XG4gICAgfVxuXG4gICAgdGhpcy5yID0gbmV3IEJOKDEpLml1c2hsbih0aGlzLnNoaWZ0KTtcbiAgICB0aGlzLnIyID0gdGhpcy5pbW9kKHRoaXMuci5zcXIoKSk7XG4gICAgdGhpcy5yaW52ID0gdGhpcy5yLl9pbnZtcCh0aGlzLm0pO1xuXG4gICAgdGhpcy5taW52ID0gdGhpcy5yaW52Lm11bCh0aGlzLnIpLmlzdWJuKDEpLmRpdih0aGlzLm0pO1xuICAgIHRoaXMubWludiA9IHRoaXMubWludi51bW9kKHRoaXMucik7XG4gICAgdGhpcy5taW52ID0gdGhpcy5yLnN1Yih0aGlzLm1pbnYpO1xuICB9XG4gIGluaGVyaXRzKE1vbnQsIFJlZCk7XG5cbiAgTW9udC5wcm90b3R5cGUuY29udmVydFRvID0gZnVuY3Rpb24gY29udmVydFRvIChudW0pIHtcbiAgICByZXR1cm4gdGhpcy5pbW9kKG51bS51c2hsbih0aGlzLnNoaWZ0KSk7XG4gIH07XG5cbiAgTW9udC5wcm90b3R5cGUuY29udmVydEZyb20gPSBmdW5jdGlvbiBjb252ZXJ0RnJvbSAobnVtKSB7XG4gICAgdmFyIHIgPSB0aGlzLmltb2QobnVtLm11bCh0aGlzLnJpbnYpKTtcbiAgICByLnJlZCA9IG51bGw7XG4gICAgcmV0dXJuIHI7XG4gIH07XG5cbiAgTW9udC5wcm90b3R5cGUuaW11bCA9IGZ1bmN0aW9uIGltdWwgKGEsIGIpIHtcbiAgICBpZiAoYS5pc1plcm8oKSB8fCBiLmlzWmVybygpKSB7XG4gICAgICBhLndvcmRzWzBdID0gMDtcbiAgICAgIGEubGVuZ3RoID0gMTtcbiAgICAgIHJldHVybiBhO1xuICAgIH1cblxuICAgIHZhciB0ID0gYS5pbXVsKGIpO1xuICAgIHZhciBjID0gdC5tYXNrbih0aGlzLnNoaWZ0KS5tdWwodGhpcy5taW52KS5pbWFza24odGhpcy5zaGlmdCkubXVsKHRoaXMubSk7XG4gICAgdmFyIHUgPSB0LmlzdWIoYykuaXVzaHJuKHRoaXMuc2hpZnQpO1xuICAgIHZhciByZXMgPSB1O1xuXG4gICAgaWYgKHUuY21wKHRoaXMubSkgPj0gMCkge1xuICAgICAgcmVzID0gdS5pc3ViKHRoaXMubSk7XG4gICAgfSBlbHNlIGlmICh1LmNtcG4oMCkgPCAwKSB7XG4gICAgICByZXMgPSB1LmlhZGQodGhpcy5tKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmVzLl9mb3JjZVJlZCh0aGlzKTtcbiAgfTtcblxuICBNb250LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwgKGEsIGIpIHtcbiAgICBpZiAoYS5pc1plcm8oKSB8fCBiLmlzWmVybygpKSByZXR1cm4gbmV3IEJOKDApLl9mb3JjZVJlZCh0aGlzKTtcblxuICAgIHZhciB0ID0gYS5tdWwoYik7XG4gICAgdmFyIGMgPSB0Lm1hc2tuKHRoaXMuc2hpZnQpLm11bCh0aGlzLm1pbnYpLmltYXNrbih0aGlzLnNoaWZ0KS5tdWwodGhpcy5tKTtcbiAgICB2YXIgdSA9IHQuaXN1YihjKS5pdXNocm4odGhpcy5zaGlmdCk7XG4gICAgdmFyIHJlcyA9IHU7XG4gICAgaWYgKHUuY21wKHRoaXMubSkgPj0gMCkge1xuICAgICAgcmVzID0gdS5pc3ViKHRoaXMubSk7XG4gICAgfSBlbHNlIGlmICh1LmNtcG4oMCkgPCAwKSB7XG4gICAgICByZXMgPSB1LmlhZGQodGhpcy5tKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmVzLl9mb3JjZVJlZCh0aGlzKTtcbiAgfTtcblxuICBNb250LnByb3RvdHlwZS5pbnZtID0gZnVuY3Rpb24gaW52bSAoYSkge1xuICAgIC8vIChBUileLTEgKiBSXjIgPSAoQV4tMSAqIFJeLTEpICogUl4yID0gQV4tMSAqIFJcbiAgICB2YXIgcmVzID0gdGhpcy5pbW9kKGEuX2ludm1wKHRoaXMubSkubXVsKHRoaXMucjIpKTtcbiAgICByZXR1cm4gcmVzLl9mb3JjZVJlZCh0aGlzKTtcbiAgfTtcbn0pKHR5cGVvZiBtb2R1bGUgPT09ICd1bmRlZmluZWQnIHx8IG1vZHVsZSwgdGhpcyk7XG4iLCJ2YXIgcjtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiByYW5kKGxlbikge1xuICBpZiAoIXIpXG4gICAgciA9IG5ldyBSYW5kKG51bGwpO1xuXG4gIHJldHVybiByLmdlbmVyYXRlKGxlbik7XG59O1xuXG5mdW5jdGlvbiBSYW5kKHJhbmQpIHtcbiAgdGhpcy5yYW5kID0gcmFuZDtcbn1cbm1vZHVsZS5leHBvcnRzLlJhbmQgPSBSYW5kO1xuXG5SYW5kLnByb3RvdHlwZS5nZW5lcmF0ZSA9IGZ1bmN0aW9uIGdlbmVyYXRlKGxlbikge1xuICByZXR1cm4gdGhpcy5fcmFuZChsZW4pO1xufTtcblxuaWYgKHR5cGVvZiB3aW5kb3cgPT09ICdvYmplY3QnKSB7XG4gIGlmICh3aW5kb3cuY3J5cHRvICYmIHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKSB7XG4gICAgLy8gTW9kZXJuIGJyb3dzZXJzXG4gICAgUmFuZC5wcm90b3R5cGUuX3JhbmQgPSBmdW5jdGlvbiBfcmFuZChuKSB7XG4gICAgICB2YXIgYXJyID0gbmV3IFVpbnQ4QXJyYXkobik7XG4gICAgICB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhhcnIpO1xuICAgICAgcmV0dXJuIGFycjtcbiAgICB9O1xuICB9IGVsc2UgaWYgKHdpbmRvdy5tc0NyeXB0byAmJiB3aW5kb3cubXNDcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKSB7XG4gICAgLy8gSUVcbiAgICBSYW5kLnByb3RvdHlwZS5fcmFuZCA9IGZ1bmN0aW9uIF9yYW5kKG4pIHtcbiAgICAgIHZhciBhcnIgPSBuZXcgVWludDhBcnJheShuKTtcbiAgICAgIHdpbmRvdy5tc0NyeXB0by5nZXRSYW5kb21WYWx1ZXMoYXJyKTtcbiAgICAgIHJldHVybiBhcnI7XG4gICAgfTtcbiAgfSBlbHNlIHtcbiAgICAvLyBPbGQganVua1xuICAgIFJhbmQucHJvdG90eXBlLl9yYW5kID0gZnVuY3Rpb24oKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCB5ZXQnKTtcbiAgICB9O1xuICB9XG59IGVsc2Uge1xuICAvLyBOb2RlLmpzIG9yIFdlYiB3b3JrZXJcbiAgdHJ5IHtcbiAgICB2YXIgY3J5cHRvID0gcmVxdWlyZSgnY3J5JyArICdwdG8nKTtcblxuICAgIFJhbmQucHJvdG90eXBlLl9yYW5kID0gZnVuY3Rpb24gX3JhbmQobikge1xuICAgICAgcmV0dXJuIGNyeXB0by5yYW5kb21CeXRlcyhuKTtcbiAgICB9O1xuICB9IGNhdGNoIChlKSB7XG4gICAgLy8gRW11bGF0ZSBjcnlwdG8gQVBJIHVzaW5nIHJhbmR5XG4gICAgUmFuZC5wcm90b3R5cGUuX3JhbmQgPSBmdW5jdGlvbiBfcmFuZChuKSB7XG4gICAgICB2YXIgcmVzID0gbmV3IFVpbnQ4QXJyYXkobik7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHJlcy5sZW5ndGg7IGkrKylcbiAgICAgICAgcmVzW2ldID0gdGhpcy5yYW5kLmdldEJ5dGUoKTtcbiAgICAgIHJldHVybiByZXM7XG4gICAgfTtcbiAgfVxufVxuIiwiLyohXG4gKiBUaGUgYnVmZmVyIG1vZHVsZSBmcm9tIG5vZGUuanMsIGZvciB0aGUgYnJvd3Nlci5cbiAqXG4gKiBAYXV0aG9yICAgRmVyb3NzIEFib3VraGFkaWplaCA8ZmVyb3NzQGZlcm9zcy5vcmc+IDxodHRwOi8vZmVyb3NzLm9yZz5cbiAqIEBsaWNlbnNlICBNSVRcbiAqL1xuLyogZXNsaW50LWRpc2FibGUgbm8tcHJvdG8gKi9cblxuJ3VzZSBzdHJpY3QnXG5cbnZhciBiYXNlNjQgPSByZXF1aXJlKCdiYXNlNjQtanMnKVxudmFyIGllZWU3NTQgPSByZXF1aXJlKCdpZWVlNzU0JylcbnZhciBpc0FycmF5ID0gcmVxdWlyZSgnaXNhcnJheScpXG5cbmV4cG9ydHMuQnVmZmVyID0gQnVmZmVyXG5leHBvcnRzLlNsb3dCdWZmZXIgPSBTbG93QnVmZmVyXG5leHBvcnRzLklOU1BFQ1RfTUFYX0JZVEVTID0gNTBcblxuLyoqXG4gKiBJZiBgQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlRgOlxuICogICA9PT0gdHJ1ZSAgICBVc2UgVWludDhBcnJheSBpbXBsZW1lbnRhdGlvbiAoZmFzdGVzdClcbiAqICAgPT09IGZhbHNlICAgVXNlIE9iamVjdCBpbXBsZW1lbnRhdGlvbiAobW9zdCBjb21wYXRpYmxlLCBldmVuIElFNilcbiAqXG4gKiBCcm93c2VycyB0aGF0IHN1cHBvcnQgdHlwZWQgYXJyYXlzIGFyZSBJRSAxMCssIEZpcmVmb3ggNCssIENocm9tZSA3KywgU2FmYXJpIDUuMSssXG4gKiBPcGVyYSAxMS42KywgaU9TIDQuMisuXG4gKlxuICogRHVlIHRvIHZhcmlvdXMgYnJvd3NlciBidWdzLCBzb21ldGltZXMgdGhlIE9iamVjdCBpbXBsZW1lbnRhdGlvbiB3aWxsIGJlIHVzZWQgZXZlblxuICogd2hlbiB0aGUgYnJvd3NlciBzdXBwb3J0cyB0eXBlZCBhcnJheXMuXG4gKlxuICogTm90ZTpcbiAqXG4gKiAgIC0gRmlyZWZveCA0LTI5IGxhY2tzIHN1cHBvcnQgZm9yIGFkZGluZyBuZXcgcHJvcGVydGllcyB0byBgVWludDhBcnJheWAgaW5zdGFuY2VzLFxuICogICAgIFNlZTogaHR0cHM6Ly9idWd6aWxsYS5tb3ppbGxhLm9yZy9zaG93X2J1Zy5jZ2k/aWQ9Njk1NDM4LlxuICpcbiAqICAgLSBDaHJvbWUgOS0xMCBpcyBtaXNzaW5nIHRoZSBgVHlwZWRBcnJheS5wcm90b3R5cGUuc3ViYXJyYXlgIGZ1bmN0aW9uLlxuICpcbiAqICAgLSBJRTEwIGhhcyBhIGJyb2tlbiBgVHlwZWRBcnJheS5wcm90b3R5cGUuc3ViYXJyYXlgIGZ1bmN0aW9uIHdoaWNoIHJldHVybnMgYXJyYXlzIG9mXG4gKiAgICAgaW5jb3JyZWN0IGxlbmd0aCBpbiBzb21lIHNpdHVhdGlvbnMuXG5cbiAqIFdlIGRldGVjdCB0aGVzZSBidWdneSBicm93c2VycyBhbmQgc2V0IGBCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVGAgdG8gYGZhbHNlYCBzbyB0aGV5XG4gKiBnZXQgdGhlIE9iamVjdCBpbXBsZW1lbnRhdGlvbiwgd2hpY2ggaXMgc2xvd2VyIGJ1dCBiZWhhdmVzIGNvcnJlY3RseS5cbiAqL1xuQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQgPSBnbG9iYWwuVFlQRURfQVJSQVlfU1VQUE9SVCAhPT0gdW5kZWZpbmVkXG4gID8gZ2xvYmFsLlRZUEVEX0FSUkFZX1NVUFBPUlRcbiAgOiB0eXBlZEFycmF5U3VwcG9ydCgpXG5cbi8qXG4gKiBFeHBvcnQga01heExlbmd0aCBhZnRlciB0eXBlZCBhcnJheSBzdXBwb3J0IGlzIGRldGVybWluZWQuXG4gKi9cbmV4cG9ydHMua01heExlbmd0aCA9IGtNYXhMZW5ndGgoKVxuXG5mdW5jdGlvbiB0eXBlZEFycmF5U3VwcG9ydCAoKSB7XG4gIHRyeSB7XG4gICAgdmFyIGFyciA9IG5ldyBVaW50OEFycmF5KDEpXG4gICAgYXJyLmZvbyA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIDQyIH1cbiAgICByZXR1cm4gYXJyLmZvbygpID09PSA0MiAmJiAvLyB0eXBlZCBhcnJheSBpbnN0YW5jZXMgY2FuIGJlIGF1Z21lbnRlZFxuICAgICAgICB0eXBlb2YgYXJyLnN1YmFycmF5ID09PSAnZnVuY3Rpb24nICYmIC8vIGNocm9tZSA5LTEwIGxhY2sgYHN1YmFycmF5YFxuICAgICAgICBhcnIuc3ViYXJyYXkoMSwgMSkuYnl0ZUxlbmd0aCA9PT0gMCAvLyBpZTEwIGhhcyBicm9rZW4gYHN1YmFycmF5YFxuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuIGZhbHNlXG4gIH1cbn1cblxuZnVuY3Rpb24ga01heExlbmd0aCAoKSB7XG4gIHJldHVybiBCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVFxuICAgID8gMHg3ZmZmZmZmZlxuICAgIDogMHgzZmZmZmZmZlxufVxuXG5mdW5jdGlvbiBjcmVhdGVCdWZmZXIgKHRoYXQsIGxlbmd0aCkge1xuICBpZiAoa01heExlbmd0aCgpIDwgbGVuZ3RoKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0ludmFsaWQgdHlwZWQgYXJyYXkgbGVuZ3RoJylcbiAgfVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICAvLyBSZXR1cm4gYW4gYXVnbWVudGVkIGBVaW50OEFycmF5YCBpbnN0YW5jZSwgZm9yIGJlc3QgcGVyZm9ybWFuY2VcbiAgICB0aGF0ID0gbmV3IFVpbnQ4QXJyYXkobGVuZ3RoKVxuICAgIHRoYXQuX19wcm90b19fID0gQnVmZmVyLnByb3RvdHlwZVxuICB9IGVsc2Uge1xuICAgIC8vIEZhbGxiYWNrOiBSZXR1cm4gYW4gb2JqZWN0IGluc3RhbmNlIG9mIHRoZSBCdWZmZXIgY2xhc3NcbiAgICBpZiAodGhhdCA9PT0gbnVsbCkge1xuICAgICAgdGhhdCA9IG5ldyBCdWZmZXIobGVuZ3RoKVxuICAgIH1cbiAgICB0aGF0Lmxlbmd0aCA9IGxlbmd0aFxuICB9XG5cbiAgcmV0dXJuIHRoYXRcbn1cblxuLyoqXG4gKiBUaGUgQnVmZmVyIGNvbnN0cnVjdG9yIHJldHVybnMgaW5zdGFuY2VzIG9mIGBVaW50OEFycmF5YCB0aGF0IGhhdmUgdGhlaXJcbiAqIHByb3RvdHlwZSBjaGFuZ2VkIHRvIGBCdWZmZXIucHJvdG90eXBlYC4gRnVydGhlcm1vcmUsIGBCdWZmZXJgIGlzIGEgc3ViY2xhc3Mgb2ZcbiAqIGBVaW50OEFycmF5YCwgc28gdGhlIHJldHVybmVkIGluc3RhbmNlcyB3aWxsIGhhdmUgYWxsIHRoZSBub2RlIGBCdWZmZXJgIG1ldGhvZHNcbiAqIGFuZCB0aGUgYFVpbnQ4QXJyYXlgIG1ldGhvZHMuIFNxdWFyZSBicmFja2V0IG5vdGF0aW9uIHdvcmtzIGFzIGV4cGVjdGVkIC0tIGl0XG4gKiByZXR1cm5zIGEgc2luZ2xlIG9jdGV0LlxuICpcbiAqIFRoZSBgVWludDhBcnJheWAgcHJvdG90eXBlIHJlbWFpbnMgdW5tb2RpZmllZC5cbiAqL1xuXG5mdW5jdGlvbiBCdWZmZXIgKGFyZywgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKSB7XG4gIGlmICghQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQgJiYgISh0aGlzIGluc3RhbmNlb2YgQnVmZmVyKSkge1xuICAgIHJldHVybiBuZXcgQnVmZmVyKGFyZywgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKVxuICB9XG5cbiAgLy8gQ29tbW9uIGNhc2UuXG4gIGlmICh0eXBlb2YgYXJnID09PSAnbnVtYmVyJykge1xuICAgIGlmICh0eXBlb2YgZW5jb2RpbmdPck9mZnNldCA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgJ0lmIGVuY29kaW5nIGlzIHNwZWNpZmllZCB0aGVuIHRoZSBmaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgc3RyaW5nJ1xuICAgICAgKVxuICAgIH1cbiAgICByZXR1cm4gYWxsb2NVbnNhZmUodGhpcywgYXJnKVxuICB9XG4gIHJldHVybiBmcm9tKHRoaXMsIGFyZywgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKVxufVxuXG5CdWZmZXIucG9vbFNpemUgPSA4MTkyIC8vIG5vdCB1c2VkIGJ5IHRoaXMgaW1wbGVtZW50YXRpb25cblxuLy8gVE9ETzogTGVnYWN5LCBub3QgbmVlZGVkIGFueW1vcmUuIFJlbW92ZSBpbiBuZXh0IG1ham9yIHZlcnNpb24uXG5CdWZmZXIuX2F1Z21lbnQgPSBmdW5jdGlvbiAoYXJyKSB7XG4gIGFyci5fX3Byb3RvX18gPSBCdWZmZXIucHJvdG90eXBlXG4gIHJldHVybiBhcnJcbn1cblxuZnVuY3Rpb24gZnJvbSAodGhhdCwgdmFsdWUsIGVuY29kaW5nT3JPZmZzZXQsIGxlbmd0aCkge1xuICBpZiAodHlwZW9mIHZhbHVlID09PSAnbnVtYmVyJykge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1widmFsdWVcIiBhcmd1bWVudCBtdXN0IG5vdCBiZSBhIG51bWJlcicpXG4gIH1cblxuICBpZiAodHlwZW9mIEFycmF5QnVmZmVyICE9PSAndW5kZWZpbmVkJyAmJiB2YWx1ZSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSB7XG4gICAgcmV0dXJuIGZyb21BcnJheUJ1ZmZlcih0aGF0LCB2YWx1ZSwgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKVxuICB9XG5cbiAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICByZXR1cm4gZnJvbVN0cmluZyh0aGF0LCB2YWx1ZSwgZW5jb2RpbmdPck9mZnNldClcbiAgfVxuXG4gIHJldHVybiBmcm9tT2JqZWN0KHRoYXQsIHZhbHVlKVxufVxuXG4vKipcbiAqIEZ1bmN0aW9uYWxseSBlcXVpdmFsZW50IHRvIEJ1ZmZlcihhcmcsIGVuY29kaW5nKSBidXQgdGhyb3dzIGEgVHlwZUVycm9yXG4gKiBpZiB2YWx1ZSBpcyBhIG51bWJlci5cbiAqIEJ1ZmZlci5mcm9tKHN0clssIGVuY29kaW5nXSlcbiAqIEJ1ZmZlci5mcm9tKGFycmF5KVxuICogQnVmZmVyLmZyb20oYnVmZmVyKVxuICogQnVmZmVyLmZyb20oYXJyYXlCdWZmZXJbLCBieXRlT2Zmc2V0WywgbGVuZ3RoXV0pXG4gKiovXG5CdWZmZXIuZnJvbSA9IGZ1bmN0aW9uICh2YWx1ZSwgZW5jb2RpbmdPck9mZnNldCwgbGVuZ3RoKSB7XG4gIHJldHVybiBmcm9tKG51bGwsIHZhbHVlLCBlbmNvZGluZ09yT2Zmc2V0LCBsZW5ndGgpXG59XG5cbmlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICBCdWZmZXIucHJvdG90eXBlLl9fcHJvdG9fXyA9IFVpbnQ4QXJyYXkucHJvdG90eXBlXG4gIEJ1ZmZlci5fX3Byb3RvX18gPSBVaW50OEFycmF5XG4gIGlmICh0eXBlb2YgU3ltYm9sICE9PSAndW5kZWZpbmVkJyAmJiBTeW1ib2wuc3BlY2llcyAmJlxuICAgICAgQnVmZmVyW1N5bWJvbC5zcGVjaWVzXSA9PT0gQnVmZmVyKSB7XG4gICAgLy8gRml4IHN1YmFycmF5KCkgaW4gRVMyMDE2LiBTZWU6IGh0dHBzOi8vZ2l0aHViLmNvbS9mZXJvc3MvYnVmZmVyL3B1bGwvOTdcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoQnVmZmVyLCBTeW1ib2wuc3BlY2llcywge1xuICAgICAgdmFsdWU6IG51bGwsXG4gICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KVxuICB9XG59XG5cbmZ1bmN0aW9uIGFzc2VydFNpemUgKHNpemUpIHtcbiAgaWYgKHR5cGVvZiBzaXplICE9PSAnbnVtYmVyJykge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wic2l6ZVwiIGFyZ3VtZW50IG11c3QgYmUgYSBudW1iZXInKVxuICB9XG59XG5cbmZ1bmN0aW9uIGFsbG9jICh0aGF0LCBzaXplLCBmaWxsLCBlbmNvZGluZykge1xuICBhc3NlcnRTaXplKHNpemUpXG4gIGlmIChzaXplIDw9IDApIHtcbiAgICByZXR1cm4gY3JlYXRlQnVmZmVyKHRoYXQsIHNpemUpXG4gIH1cbiAgaWYgKGZpbGwgIT09IHVuZGVmaW5lZCkge1xuICAgIC8vIE9ubHkgcGF5IGF0dGVudGlvbiB0byBlbmNvZGluZyBpZiBpdCdzIGEgc3RyaW5nLiBUaGlzXG4gICAgLy8gcHJldmVudHMgYWNjaWRlbnRhbGx5IHNlbmRpbmcgaW4gYSBudW1iZXIgdGhhdCB3b3VsZFxuICAgIC8vIGJlIGludGVycHJldHRlZCBhcyBhIHN0YXJ0IG9mZnNldC5cbiAgICByZXR1cm4gdHlwZW9mIGVuY29kaW5nID09PSAnc3RyaW5nJ1xuICAgICAgPyBjcmVhdGVCdWZmZXIodGhhdCwgc2l6ZSkuZmlsbChmaWxsLCBlbmNvZGluZylcbiAgICAgIDogY3JlYXRlQnVmZmVyKHRoYXQsIHNpemUpLmZpbGwoZmlsbClcbiAgfVxuICByZXR1cm4gY3JlYXRlQnVmZmVyKHRoYXQsIHNpemUpXG59XG5cbi8qKlxuICogQ3JlYXRlcyBhIG5ldyBmaWxsZWQgQnVmZmVyIGluc3RhbmNlLlxuICogYWxsb2Moc2l6ZVssIGZpbGxbLCBlbmNvZGluZ11dKVxuICoqL1xuQnVmZmVyLmFsbG9jID0gZnVuY3Rpb24gKHNpemUsIGZpbGwsIGVuY29kaW5nKSB7XG4gIHJldHVybiBhbGxvYyhudWxsLCBzaXplLCBmaWxsLCBlbmNvZGluZylcbn1cblxuZnVuY3Rpb24gYWxsb2NVbnNhZmUgKHRoYXQsIHNpemUpIHtcbiAgYXNzZXJ0U2l6ZShzaXplKVxuICB0aGF0ID0gY3JlYXRlQnVmZmVyKHRoYXQsIHNpemUgPCAwID8gMCA6IGNoZWNrZWQoc2l6ZSkgfCAwKVxuICBpZiAoIUJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaXplOyBpKyspIHtcbiAgICAgIHRoYXRbaV0gPSAwXG4gICAgfVxuICB9XG4gIHJldHVybiB0aGF0XG59XG5cbi8qKlxuICogRXF1aXZhbGVudCB0byBCdWZmZXIobnVtKSwgYnkgZGVmYXVsdCBjcmVhdGVzIGEgbm9uLXplcm8tZmlsbGVkIEJ1ZmZlciBpbnN0YW5jZS5cbiAqICovXG5CdWZmZXIuYWxsb2NVbnNhZmUgPSBmdW5jdGlvbiAoc2l6ZSkge1xuICByZXR1cm4gYWxsb2NVbnNhZmUobnVsbCwgc2l6ZSlcbn1cbi8qKlxuICogRXF1aXZhbGVudCB0byBTbG93QnVmZmVyKG51bSksIGJ5IGRlZmF1bHQgY3JlYXRlcyBhIG5vbi16ZXJvLWZpbGxlZCBCdWZmZXIgaW5zdGFuY2UuXG4gKi9cbkJ1ZmZlci5hbGxvY1Vuc2FmZVNsb3cgPSBmdW5jdGlvbiAoc2l6ZSkge1xuICByZXR1cm4gYWxsb2NVbnNhZmUobnVsbCwgc2l6ZSlcbn1cblxuZnVuY3Rpb24gZnJvbVN0cmluZyAodGhhdCwgc3RyaW5nLCBlbmNvZGluZykge1xuICBpZiAodHlwZW9mIGVuY29kaW5nICE9PSAnc3RyaW5nJyB8fCBlbmNvZGluZyA9PT0gJycpIHtcbiAgICBlbmNvZGluZyA9ICd1dGY4J1xuICB9XG5cbiAgaWYgKCFCdWZmZXIuaXNFbmNvZGluZyhlbmNvZGluZykpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcImVuY29kaW5nXCIgbXVzdCBiZSBhIHZhbGlkIHN0cmluZyBlbmNvZGluZycpXG4gIH1cblxuICB2YXIgbGVuZ3RoID0gYnl0ZUxlbmd0aChzdHJpbmcsIGVuY29kaW5nKSB8IDBcbiAgdGhhdCA9IGNyZWF0ZUJ1ZmZlcih0aGF0LCBsZW5ndGgpXG5cbiAgdGhhdC53cml0ZShzdHJpbmcsIGVuY29kaW5nKVxuICByZXR1cm4gdGhhdFxufVxuXG5mdW5jdGlvbiBmcm9tQXJyYXlMaWtlICh0aGF0LCBhcnJheSkge1xuICB2YXIgbGVuZ3RoID0gY2hlY2tlZChhcnJheS5sZW5ndGgpIHwgMFxuICB0aGF0ID0gY3JlYXRlQnVmZmVyKHRoYXQsIGxlbmd0aClcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMSkge1xuICAgIHRoYXRbaV0gPSBhcnJheVtpXSAmIDI1NVxuICB9XG4gIHJldHVybiB0aGF0XG59XG5cbmZ1bmN0aW9uIGZyb21BcnJheUJ1ZmZlciAodGhhdCwgYXJyYXksIGJ5dGVPZmZzZXQsIGxlbmd0aCkge1xuICBhcnJheS5ieXRlTGVuZ3RoIC8vIHRoaXMgdGhyb3dzIGlmIGBhcnJheWAgaXMgbm90IGEgdmFsaWQgQXJyYXlCdWZmZXJcblxuICBpZiAoYnl0ZU9mZnNldCA8IDAgfHwgYXJyYXkuYnl0ZUxlbmd0aCA8IGJ5dGVPZmZzZXQpIHtcbiAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcignXFwnb2Zmc2V0XFwnIGlzIG91dCBvZiBib3VuZHMnKVxuICB9XG5cbiAgaWYgKGFycmF5LmJ5dGVMZW5ndGggPCBieXRlT2Zmc2V0ICsgKGxlbmd0aCB8fCAwKSkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdcXCdsZW5ndGhcXCcgaXMgb3V0IG9mIGJvdW5kcycpXG4gIH1cblxuICBpZiAobGVuZ3RoID09PSB1bmRlZmluZWQpIHtcbiAgICBhcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5LCBieXRlT2Zmc2V0KVxuICB9IGVsc2Uge1xuICAgIGFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXksIGJ5dGVPZmZzZXQsIGxlbmd0aClcbiAgfVxuXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIC8vIFJldHVybiBhbiBhdWdtZW50ZWQgYFVpbnQ4QXJyYXlgIGluc3RhbmNlLCBmb3IgYmVzdCBwZXJmb3JtYW5jZVxuICAgIHRoYXQgPSBhcnJheVxuICAgIHRoYXQuX19wcm90b19fID0gQnVmZmVyLnByb3RvdHlwZVxuICB9IGVsc2Uge1xuICAgIC8vIEZhbGxiYWNrOiBSZXR1cm4gYW4gb2JqZWN0IGluc3RhbmNlIG9mIHRoZSBCdWZmZXIgY2xhc3NcbiAgICB0aGF0ID0gZnJvbUFycmF5TGlrZSh0aGF0LCBhcnJheSlcbiAgfVxuICByZXR1cm4gdGhhdFxufVxuXG5mdW5jdGlvbiBmcm9tT2JqZWN0ICh0aGF0LCBvYmopIHtcbiAgaWYgKEJ1ZmZlci5pc0J1ZmZlcihvYmopKSB7XG4gICAgdmFyIGxlbiA9IGNoZWNrZWQob2JqLmxlbmd0aCkgfCAwXG4gICAgdGhhdCA9IGNyZWF0ZUJ1ZmZlcih0aGF0LCBsZW4pXG5cbiAgICBpZiAodGhhdC5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB0aGF0XG4gICAgfVxuXG4gICAgb2JqLmNvcHkodGhhdCwgMCwgMCwgbGVuKVxuICAgIHJldHVybiB0aGF0XG4gIH1cblxuICBpZiAob2JqKSB7XG4gICAgaWYgKCh0eXBlb2YgQXJyYXlCdWZmZXIgIT09ICd1bmRlZmluZWQnICYmXG4gICAgICAgIG9iai5idWZmZXIgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikgfHwgJ2xlbmd0aCcgaW4gb2JqKSB7XG4gICAgICBpZiAodHlwZW9mIG9iai5sZW5ndGggIT09ICdudW1iZXInIHx8IGlzbmFuKG9iai5sZW5ndGgpKSB7XG4gICAgICAgIHJldHVybiBjcmVhdGVCdWZmZXIodGhhdCwgMClcbiAgICAgIH1cbiAgICAgIHJldHVybiBmcm9tQXJyYXlMaWtlKHRoYXQsIG9iailcbiAgICB9XG5cbiAgICBpZiAob2JqLnR5cGUgPT09ICdCdWZmZXInICYmIGlzQXJyYXkob2JqLmRhdGEpKSB7XG4gICAgICByZXR1cm4gZnJvbUFycmF5TGlrZSh0aGF0LCBvYmouZGF0YSlcbiAgICB9XG4gIH1cblxuICB0aHJvdyBuZXcgVHlwZUVycm9yKCdGaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgc3RyaW5nLCBCdWZmZXIsIEFycmF5QnVmZmVyLCBBcnJheSwgb3IgYXJyYXktbGlrZSBvYmplY3QuJylcbn1cblxuZnVuY3Rpb24gY2hlY2tlZCAobGVuZ3RoKSB7XG4gIC8vIE5vdGU6IGNhbm5vdCB1c2UgYGxlbmd0aCA8IGtNYXhMZW5ndGhgIGhlcmUgYmVjYXVzZSB0aGF0IGZhaWxzIHdoZW5cbiAgLy8gbGVuZ3RoIGlzIE5hTiAod2hpY2ggaXMgb3RoZXJ3aXNlIGNvZXJjZWQgdG8gemVyby4pXG4gIGlmIChsZW5ndGggPj0ga01heExlbmd0aCgpKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0F0dGVtcHQgdG8gYWxsb2NhdGUgQnVmZmVyIGxhcmdlciB0aGFuIG1heGltdW0gJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgJ3NpemU6IDB4JyArIGtNYXhMZW5ndGgoKS50b1N0cmluZygxNikgKyAnIGJ5dGVzJylcbiAgfVxuICByZXR1cm4gbGVuZ3RoIHwgMFxufVxuXG5mdW5jdGlvbiBTbG93QnVmZmVyIChsZW5ndGgpIHtcbiAgaWYgKCtsZW5ndGggIT0gbGVuZ3RoKSB7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgZXFlcWVxXG4gICAgbGVuZ3RoID0gMFxuICB9XG4gIHJldHVybiBCdWZmZXIuYWxsb2MoK2xlbmd0aClcbn1cblxuQnVmZmVyLmlzQnVmZmVyID0gZnVuY3Rpb24gaXNCdWZmZXIgKGIpIHtcbiAgcmV0dXJuICEhKGIgIT0gbnVsbCAmJiBiLl9pc0J1ZmZlcilcbn1cblxuQnVmZmVyLmNvbXBhcmUgPSBmdW5jdGlvbiBjb21wYXJlIChhLCBiKSB7XG4gIGlmICghQnVmZmVyLmlzQnVmZmVyKGEpIHx8ICFCdWZmZXIuaXNCdWZmZXIoYikpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdBcmd1bWVudHMgbXVzdCBiZSBCdWZmZXJzJylcbiAgfVxuXG4gIGlmIChhID09PSBiKSByZXR1cm4gMFxuXG4gIHZhciB4ID0gYS5sZW5ndGhcbiAgdmFyIHkgPSBiLmxlbmd0aFxuXG4gIGZvciAodmFyIGkgPSAwLCBsZW4gPSBNYXRoLm1pbih4LCB5KTsgaSA8IGxlbjsgKytpKSB7XG4gICAgaWYgKGFbaV0gIT09IGJbaV0pIHtcbiAgICAgIHggPSBhW2ldXG4gICAgICB5ID0gYltpXVxuICAgICAgYnJlYWtcbiAgICB9XG4gIH1cblxuICBpZiAoeCA8IHkpIHJldHVybiAtMVxuICBpZiAoeSA8IHgpIHJldHVybiAxXG4gIHJldHVybiAwXG59XG5cbkJ1ZmZlci5pc0VuY29kaW5nID0gZnVuY3Rpb24gaXNFbmNvZGluZyAoZW5jb2RpbmcpIHtcbiAgc3dpdGNoIChTdHJpbmcoZW5jb2RpbmcpLnRvTG93ZXJDYXNlKCkpIHtcbiAgICBjYXNlICdoZXgnOlxuICAgIGNhc2UgJ3V0ZjgnOlxuICAgIGNhc2UgJ3V0Zi04JzpcbiAgICBjYXNlICdhc2NpaSc6XG4gICAgY2FzZSAnYmluYXJ5JzpcbiAgICBjYXNlICdiYXNlNjQnOlxuICAgIGNhc2UgJ3Jhdyc6XG4gICAgY2FzZSAndWNzMic6XG4gICAgY2FzZSAndWNzLTInOlxuICAgIGNhc2UgJ3V0ZjE2bGUnOlxuICAgIGNhc2UgJ3V0Zi0xNmxlJzpcbiAgICAgIHJldHVybiB0cnVlXG4gICAgZGVmYXVsdDpcbiAgICAgIHJldHVybiBmYWxzZVxuICB9XG59XG5cbkJ1ZmZlci5jb25jYXQgPSBmdW5jdGlvbiBjb25jYXQgKGxpc3QsIGxlbmd0aCkge1xuICBpZiAoIWlzQXJyYXkobGlzdCkpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcImxpc3RcIiBhcmd1bWVudCBtdXN0IGJlIGFuIEFycmF5IG9mIEJ1ZmZlcnMnKVxuICB9XG5cbiAgaWYgKGxpc3QubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIEJ1ZmZlci5hbGxvYygwKVxuICB9XG5cbiAgdmFyIGlcbiAgaWYgKGxlbmd0aCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgbGVuZ3RoID0gMFxuICAgIGZvciAoaSA9IDA7IGkgPCBsaXN0Lmxlbmd0aDsgaSsrKSB7XG4gICAgICBsZW5ndGggKz0gbGlzdFtpXS5sZW5ndGhcbiAgICB9XG4gIH1cblxuICB2YXIgYnVmZmVyID0gQnVmZmVyLmFsbG9jVW5zYWZlKGxlbmd0aClcbiAgdmFyIHBvcyA9IDBcbiAgZm9yIChpID0gMDsgaSA8IGxpc3QubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgYnVmID0gbGlzdFtpXVxuICAgIGlmICghQnVmZmVyLmlzQnVmZmVyKGJ1ZikpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wibGlzdFwiIGFyZ3VtZW50IG11c3QgYmUgYW4gQXJyYXkgb2YgQnVmZmVycycpXG4gICAgfVxuICAgIGJ1Zi5jb3B5KGJ1ZmZlciwgcG9zKVxuICAgIHBvcyArPSBidWYubGVuZ3RoXG4gIH1cbiAgcmV0dXJuIGJ1ZmZlclxufVxuXG5mdW5jdGlvbiBieXRlTGVuZ3RoIChzdHJpbmcsIGVuY29kaW5nKSB7XG4gIGlmIChCdWZmZXIuaXNCdWZmZXIoc3RyaW5nKSkge1xuICAgIHJldHVybiBzdHJpbmcubGVuZ3RoXG4gIH1cbiAgaWYgKHR5cGVvZiBBcnJheUJ1ZmZlciAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIEFycmF5QnVmZmVyLmlzVmlldyA9PT0gJ2Z1bmN0aW9uJyAmJlxuICAgICAgKEFycmF5QnVmZmVyLmlzVmlldyhzdHJpbmcpIHx8IHN0cmluZyBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSkge1xuICAgIHJldHVybiBzdHJpbmcuYnl0ZUxlbmd0aFxuICB9XG4gIGlmICh0eXBlb2Ygc3RyaW5nICE9PSAnc3RyaW5nJykge1xuICAgIHN0cmluZyA9ICcnICsgc3RyaW5nXG4gIH1cblxuICB2YXIgbGVuID0gc3RyaW5nLmxlbmd0aFxuICBpZiAobGVuID09PSAwKSByZXR1cm4gMFxuXG4gIC8vIFVzZSBhIGZvciBsb29wIHRvIGF2b2lkIHJlY3Vyc2lvblxuICB2YXIgbG93ZXJlZENhc2UgPSBmYWxzZVxuICBmb3IgKDs7KSB7XG4gICAgc3dpdGNoIChlbmNvZGluZykge1xuICAgICAgY2FzZSAnYXNjaWknOlxuICAgICAgY2FzZSAnYmluYXJ5JzpcbiAgICAgIC8vIERlcHJlY2F0ZWRcbiAgICAgIGNhc2UgJ3Jhdyc6XG4gICAgICBjYXNlICdyYXdzJzpcbiAgICAgICAgcmV0dXJuIGxlblxuICAgICAgY2FzZSAndXRmOCc6XG4gICAgICBjYXNlICd1dGYtOCc6XG4gICAgICBjYXNlIHVuZGVmaW5lZDpcbiAgICAgICAgcmV0dXJuIHV0ZjhUb0J5dGVzKHN0cmluZykubGVuZ3RoXG4gICAgICBjYXNlICd1Y3MyJzpcbiAgICAgIGNhc2UgJ3Vjcy0yJzpcbiAgICAgIGNhc2UgJ3V0ZjE2bGUnOlxuICAgICAgY2FzZSAndXRmLTE2bGUnOlxuICAgICAgICByZXR1cm4gbGVuICogMlxuICAgICAgY2FzZSAnaGV4JzpcbiAgICAgICAgcmV0dXJuIGxlbiA+Pj4gMVxuICAgICAgY2FzZSAnYmFzZTY0JzpcbiAgICAgICAgcmV0dXJuIGJhc2U2NFRvQnl0ZXMoc3RyaW5nKS5sZW5ndGhcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIGlmIChsb3dlcmVkQ2FzZSkgcmV0dXJuIHV0ZjhUb0J5dGVzKHN0cmluZykubGVuZ3RoIC8vIGFzc3VtZSB1dGY4XG4gICAgICAgIGVuY29kaW5nID0gKCcnICsgZW5jb2RpbmcpLnRvTG93ZXJDYXNlKClcbiAgICAgICAgbG93ZXJlZENhc2UgPSB0cnVlXG4gICAgfVxuICB9XG59XG5CdWZmZXIuYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGhcblxuZnVuY3Rpb24gc2xvd1RvU3RyaW5nIChlbmNvZGluZywgc3RhcnQsIGVuZCkge1xuICB2YXIgbG93ZXJlZENhc2UgPSBmYWxzZVxuXG4gIC8vIE5vIG5lZWQgdG8gdmVyaWZ5IHRoYXQgXCJ0aGlzLmxlbmd0aCA8PSBNQVhfVUlOVDMyXCIgc2luY2UgaXQncyBhIHJlYWQtb25seVxuICAvLyBwcm9wZXJ0eSBvZiBhIHR5cGVkIGFycmF5LlxuXG4gIC8vIFRoaXMgYmVoYXZlcyBuZWl0aGVyIGxpa2UgU3RyaW5nIG5vciBVaW50OEFycmF5IGluIHRoYXQgd2Ugc2V0IHN0YXJ0L2VuZFxuICAvLyB0byB0aGVpciB1cHBlci9sb3dlciBib3VuZHMgaWYgdGhlIHZhbHVlIHBhc3NlZCBpcyBvdXQgb2YgcmFuZ2UuXG4gIC8vIHVuZGVmaW5lZCBpcyBoYW5kbGVkIHNwZWNpYWxseSBhcyBwZXIgRUNNQS0yNjIgNnRoIEVkaXRpb24sXG4gIC8vIFNlY3Rpb24gMTMuMy4zLjcgUnVudGltZSBTZW1hbnRpY3M6IEtleWVkQmluZGluZ0luaXRpYWxpemF0aW9uLlxuICBpZiAoc3RhcnQgPT09IHVuZGVmaW5lZCB8fCBzdGFydCA8IDApIHtcbiAgICBzdGFydCA9IDBcbiAgfVxuICAvLyBSZXR1cm4gZWFybHkgaWYgc3RhcnQgPiB0aGlzLmxlbmd0aC4gRG9uZSBoZXJlIHRvIHByZXZlbnQgcG90ZW50aWFsIHVpbnQzMlxuICAvLyBjb2VyY2lvbiBmYWlsIGJlbG93LlxuICBpZiAoc3RhcnQgPiB0aGlzLmxlbmd0aCkge1xuICAgIHJldHVybiAnJ1xuICB9XG5cbiAgaWYgKGVuZCA9PT0gdW5kZWZpbmVkIHx8IGVuZCA+IHRoaXMubGVuZ3RoKSB7XG4gICAgZW5kID0gdGhpcy5sZW5ndGhcbiAgfVxuXG4gIGlmIChlbmQgPD0gMCkge1xuICAgIHJldHVybiAnJ1xuICB9XG5cbiAgLy8gRm9yY2UgY29lcnNpb24gdG8gdWludDMyLiBUaGlzIHdpbGwgYWxzbyBjb2VyY2UgZmFsc2V5L05hTiB2YWx1ZXMgdG8gMC5cbiAgZW5kID4+Pj0gMFxuICBzdGFydCA+Pj49IDBcblxuICBpZiAoZW5kIDw9IHN0YXJ0KSB7XG4gICAgcmV0dXJuICcnXG4gIH1cblxuICBpZiAoIWVuY29kaW5nKSBlbmNvZGluZyA9ICd1dGY4J1xuXG4gIHdoaWxlICh0cnVlKSB7XG4gICAgc3dpdGNoIChlbmNvZGluZykge1xuICAgICAgY2FzZSAnaGV4JzpcbiAgICAgICAgcmV0dXJuIGhleFNsaWNlKHRoaXMsIHN0YXJ0LCBlbmQpXG5cbiAgICAgIGNhc2UgJ3V0ZjgnOlxuICAgICAgY2FzZSAndXRmLTgnOlxuICAgICAgICByZXR1cm4gdXRmOFNsaWNlKHRoaXMsIHN0YXJ0LCBlbmQpXG5cbiAgICAgIGNhc2UgJ2FzY2lpJzpcbiAgICAgICAgcmV0dXJuIGFzY2lpU2xpY2UodGhpcywgc3RhcnQsIGVuZClcblxuICAgICAgY2FzZSAnYmluYXJ5JzpcbiAgICAgICAgcmV0dXJuIGJpbmFyeVNsaWNlKHRoaXMsIHN0YXJ0LCBlbmQpXG5cbiAgICAgIGNhc2UgJ2Jhc2U2NCc6XG4gICAgICAgIHJldHVybiBiYXNlNjRTbGljZSh0aGlzLCBzdGFydCwgZW5kKVxuXG4gICAgICBjYXNlICd1Y3MyJzpcbiAgICAgIGNhc2UgJ3Vjcy0yJzpcbiAgICAgIGNhc2UgJ3V0ZjE2bGUnOlxuICAgICAgY2FzZSAndXRmLTE2bGUnOlxuICAgICAgICByZXR1cm4gdXRmMTZsZVNsaWNlKHRoaXMsIHN0YXJ0LCBlbmQpXG5cbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIGlmIChsb3dlcmVkQ2FzZSkgdGhyb3cgbmV3IFR5cGVFcnJvcignVW5rbm93biBlbmNvZGluZzogJyArIGVuY29kaW5nKVxuICAgICAgICBlbmNvZGluZyA9IChlbmNvZGluZyArICcnKS50b0xvd2VyQ2FzZSgpXG4gICAgICAgIGxvd2VyZWRDYXNlID0gdHJ1ZVxuICAgIH1cbiAgfVxufVxuXG4vLyBUaGUgcHJvcGVydHkgaXMgdXNlZCBieSBgQnVmZmVyLmlzQnVmZmVyYCBhbmQgYGlzLWJ1ZmZlcmAgKGluIFNhZmFyaSA1LTcpIHRvIGRldGVjdFxuLy8gQnVmZmVyIGluc3RhbmNlcy5cbkJ1ZmZlci5wcm90b3R5cGUuX2lzQnVmZmVyID0gdHJ1ZVxuXG5mdW5jdGlvbiBzd2FwIChiLCBuLCBtKSB7XG4gIHZhciBpID0gYltuXVxuICBiW25dID0gYlttXVxuICBiW21dID0gaVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnN3YXAxNiA9IGZ1bmN0aW9uIHN3YXAxNiAoKSB7XG4gIHZhciBsZW4gPSB0aGlzLmxlbmd0aFxuICBpZiAobGVuICUgMiAhPT0gMCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdCdWZmZXIgc2l6ZSBtdXN0IGJlIGEgbXVsdGlwbGUgb2YgMTYtYml0cycpXG4gIH1cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47IGkgKz0gMikge1xuICAgIHN3YXAodGhpcywgaSwgaSArIDEpXG4gIH1cbiAgcmV0dXJuIHRoaXNcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5zd2FwMzIgPSBmdW5jdGlvbiBzd2FwMzIgKCkge1xuICB2YXIgbGVuID0gdGhpcy5sZW5ndGhcbiAgaWYgKGxlbiAlIDQgIT09IDApIHtcbiAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcignQnVmZmVyIHNpemUgbXVzdCBiZSBhIG11bHRpcGxlIG9mIDMyLWJpdHMnKVxuICB9XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpICs9IDQpIHtcbiAgICBzd2FwKHRoaXMsIGksIGkgKyAzKVxuICAgIHN3YXAodGhpcywgaSArIDEsIGkgKyAyKVxuICB9XG4gIHJldHVybiB0aGlzXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUudG9TdHJpbmcgPSBmdW5jdGlvbiB0b1N0cmluZyAoKSB7XG4gIHZhciBsZW5ndGggPSB0aGlzLmxlbmd0aCB8IDBcbiAgaWYgKGxlbmd0aCA9PT0gMCkgcmV0dXJuICcnXG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAwKSByZXR1cm4gdXRmOFNsaWNlKHRoaXMsIDAsIGxlbmd0aClcbiAgcmV0dXJuIHNsb3dUb1N0cmluZy5hcHBseSh0aGlzLCBhcmd1bWVudHMpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUuZXF1YWxzID0gZnVuY3Rpb24gZXF1YWxzIChiKSB7XG4gIGlmICghQnVmZmVyLmlzQnVmZmVyKGIpKSB0aHJvdyBuZXcgVHlwZUVycm9yKCdBcmd1bWVudCBtdXN0IGJlIGEgQnVmZmVyJylcbiAgaWYgKHRoaXMgPT09IGIpIHJldHVybiB0cnVlXG4gIHJldHVybiBCdWZmZXIuY29tcGFyZSh0aGlzLCBiKSA9PT0gMFxufVxuXG5CdWZmZXIucHJvdG90eXBlLmluc3BlY3QgPSBmdW5jdGlvbiBpbnNwZWN0ICgpIHtcbiAgdmFyIHN0ciA9ICcnXG4gIHZhciBtYXggPSBleHBvcnRzLklOU1BFQ1RfTUFYX0JZVEVTXG4gIGlmICh0aGlzLmxlbmd0aCA+IDApIHtcbiAgICBzdHIgPSB0aGlzLnRvU3RyaW5nKCdoZXgnLCAwLCBtYXgpLm1hdGNoKC8uezJ9L2cpLmpvaW4oJyAnKVxuICAgIGlmICh0aGlzLmxlbmd0aCA+IG1heCkgc3RyICs9ICcgLi4uICdcbiAgfVxuICByZXR1cm4gJzxCdWZmZXIgJyArIHN0ciArICc+J1xufVxuXG5CdWZmZXIucHJvdG90eXBlLmNvbXBhcmUgPSBmdW5jdGlvbiBjb21wYXJlICh0YXJnZXQsIHN0YXJ0LCBlbmQsIHRoaXNTdGFydCwgdGhpc0VuZCkge1xuICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcih0YXJnZXQpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQXJndW1lbnQgbXVzdCBiZSBhIEJ1ZmZlcicpXG4gIH1cblxuICBpZiAoc3RhcnQgPT09IHVuZGVmaW5lZCkge1xuICAgIHN0YXJ0ID0gMFxuICB9XG4gIGlmIChlbmQgPT09IHVuZGVmaW5lZCkge1xuICAgIGVuZCA9IHRhcmdldCA/IHRhcmdldC5sZW5ndGggOiAwXG4gIH1cbiAgaWYgKHRoaXNTdGFydCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgdGhpc1N0YXJ0ID0gMFxuICB9XG4gIGlmICh0aGlzRW5kID09PSB1bmRlZmluZWQpIHtcbiAgICB0aGlzRW5kID0gdGhpcy5sZW5ndGhcbiAgfVxuXG4gIGlmIChzdGFydCA8IDAgfHwgZW5kID4gdGFyZ2V0Lmxlbmd0aCB8fCB0aGlzU3RhcnQgPCAwIHx8IHRoaXNFbmQgPiB0aGlzLmxlbmd0aCkge1xuICAgIHRocm93IG5ldyBSYW5nZUVycm9yKCdvdXQgb2YgcmFuZ2UgaW5kZXgnKVxuICB9XG5cbiAgaWYgKHRoaXNTdGFydCA+PSB0aGlzRW5kICYmIHN0YXJ0ID49IGVuZCkge1xuICAgIHJldHVybiAwXG4gIH1cbiAgaWYgKHRoaXNTdGFydCA+PSB0aGlzRW5kKSB7XG4gICAgcmV0dXJuIC0xXG4gIH1cbiAgaWYgKHN0YXJ0ID49IGVuZCkge1xuICAgIHJldHVybiAxXG4gIH1cblxuICBzdGFydCA+Pj49IDBcbiAgZW5kID4+Pj0gMFxuICB0aGlzU3RhcnQgPj4+PSAwXG4gIHRoaXNFbmQgPj4+PSAwXG5cbiAgaWYgKHRoaXMgPT09IHRhcmdldCkgcmV0dXJuIDBcblxuICB2YXIgeCA9IHRoaXNFbmQgLSB0aGlzU3RhcnRcbiAgdmFyIHkgPSBlbmQgLSBzdGFydFxuICB2YXIgbGVuID0gTWF0aC5taW4oeCwgeSlcblxuICB2YXIgdGhpc0NvcHkgPSB0aGlzLnNsaWNlKHRoaXNTdGFydCwgdGhpc0VuZClcbiAgdmFyIHRhcmdldENvcHkgPSB0YXJnZXQuc2xpY2Uoc3RhcnQsIGVuZClcblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbjsgKytpKSB7XG4gICAgaWYgKHRoaXNDb3B5W2ldICE9PSB0YXJnZXRDb3B5W2ldKSB7XG4gICAgICB4ID0gdGhpc0NvcHlbaV1cbiAgICAgIHkgPSB0YXJnZXRDb3B5W2ldXG4gICAgICBicmVha1xuICAgIH1cbiAgfVxuXG4gIGlmICh4IDwgeSkgcmV0dXJuIC0xXG4gIGlmICh5IDwgeCkgcmV0dXJuIDFcbiAgcmV0dXJuIDBcbn1cblxuZnVuY3Rpb24gYXJyYXlJbmRleE9mIChhcnIsIHZhbCwgYnl0ZU9mZnNldCwgZW5jb2RpbmcpIHtcbiAgdmFyIGluZGV4U2l6ZSA9IDFcbiAgdmFyIGFyckxlbmd0aCA9IGFyci5sZW5ndGhcbiAgdmFyIHZhbExlbmd0aCA9IHZhbC5sZW5ndGhcblxuICBpZiAoZW5jb2RpbmcgIT09IHVuZGVmaW5lZCkge1xuICAgIGVuY29kaW5nID0gU3RyaW5nKGVuY29kaW5nKS50b0xvd2VyQ2FzZSgpXG4gICAgaWYgKGVuY29kaW5nID09PSAndWNzMicgfHwgZW5jb2RpbmcgPT09ICd1Y3MtMicgfHxcbiAgICAgICAgZW5jb2RpbmcgPT09ICd1dGYxNmxlJyB8fCBlbmNvZGluZyA9PT0gJ3V0Zi0xNmxlJykge1xuICAgICAgaWYgKGFyci5sZW5ndGggPCAyIHx8IHZhbC5sZW5ndGggPCAyKSB7XG4gICAgICAgIHJldHVybiAtMVxuICAgICAgfVxuICAgICAgaW5kZXhTaXplID0gMlxuICAgICAgYXJyTGVuZ3RoIC89IDJcbiAgICAgIHZhbExlbmd0aCAvPSAyXG4gICAgICBieXRlT2Zmc2V0IC89IDJcbiAgICB9XG4gIH1cblxuICBmdW5jdGlvbiByZWFkIChidWYsIGkpIHtcbiAgICBpZiAoaW5kZXhTaXplID09PSAxKSB7XG4gICAgICByZXR1cm4gYnVmW2ldXG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBidWYucmVhZFVJbnQxNkJFKGkgKiBpbmRleFNpemUpXG4gICAgfVxuICB9XG5cbiAgdmFyIGZvdW5kSW5kZXggPSAtMVxuICBmb3IgKHZhciBpID0gMDsgYnl0ZU9mZnNldCArIGkgPCBhcnJMZW5ndGg7IGkrKykge1xuICAgIGlmIChyZWFkKGFyciwgYnl0ZU9mZnNldCArIGkpID09PSByZWFkKHZhbCwgZm91bmRJbmRleCA9PT0gLTEgPyAwIDogaSAtIGZvdW5kSW5kZXgpKSB7XG4gICAgICBpZiAoZm91bmRJbmRleCA9PT0gLTEpIGZvdW5kSW5kZXggPSBpXG4gICAgICBpZiAoaSAtIGZvdW5kSW5kZXggKyAxID09PSB2YWxMZW5ndGgpIHJldHVybiAoYnl0ZU9mZnNldCArIGZvdW5kSW5kZXgpICogaW5kZXhTaXplXG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChmb3VuZEluZGV4ICE9PSAtMSkgaSAtPSBpIC0gZm91bmRJbmRleFxuICAgICAgZm91bmRJbmRleCA9IC0xXG4gICAgfVxuICB9XG4gIHJldHVybiAtMVxufVxuXG5CdWZmZXIucHJvdG90eXBlLmluZGV4T2YgPSBmdW5jdGlvbiBpbmRleE9mICh2YWwsIGJ5dGVPZmZzZXQsIGVuY29kaW5nKSB7XG4gIGlmICh0eXBlb2YgYnl0ZU9mZnNldCA9PT0gJ3N0cmluZycpIHtcbiAgICBlbmNvZGluZyA9IGJ5dGVPZmZzZXRcbiAgICBieXRlT2Zmc2V0ID0gMFxuICB9IGVsc2UgaWYgKGJ5dGVPZmZzZXQgPiAweDdmZmZmZmZmKSB7XG4gICAgYnl0ZU9mZnNldCA9IDB4N2ZmZmZmZmZcbiAgfSBlbHNlIGlmIChieXRlT2Zmc2V0IDwgLTB4ODAwMDAwMDApIHtcbiAgICBieXRlT2Zmc2V0ID0gLTB4ODAwMDAwMDBcbiAgfVxuICBieXRlT2Zmc2V0ID4+PSAwXG5cbiAgaWYgKHRoaXMubGVuZ3RoID09PSAwKSByZXR1cm4gLTFcbiAgaWYgKGJ5dGVPZmZzZXQgPj0gdGhpcy5sZW5ndGgpIHJldHVybiAtMVxuXG4gIC8vIE5lZ2F0aXZlIG9mZnNldHMgc3RhcnQgZnJvbSB0aGUgZW5kIG9mIHRoZSBidWZmZXJcbiAgaWYgKGJ5dGVPZmZzZXQgPCAwKSBieXRlT2Zmc2V0ID0gTWF0aC5tYXgodGhpcy5sZW5ndGggKyBieXRlT2Zmc2V0LCAwKVxuXG4gIGlmICh0eXBlb2YgdmFsID09PSAnc3RyaW5nJykge1xuICAgIHZhbCA9IEJ1ZmZlci5mcm9tKHZhbCwgZW5jb2RpbmcpXG4gIH1cblxuICBpZiAoQnVmZmVyLmlzQnVmZmVyKHZhbCkpIHtcbiAgICAvLyBzcGVjaWFsIGNhc2U6IGxvb2tpbmcgZm9yIGVtcHR5IHN0cmluZy9idWZmZXIgYWx3YXlzIGZhaWxzXG4gICAgaWYgKHZhbC5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiAtMVxuICAgIH1cbiAgICByZXR1cm4gYXJyYXlJbmRleE9mKHRoaXMsIHZhbCwgYnl0ZU9mZnNldCwgZW5jb2RpbmcpXG4gIH1cbiAgaWYgKHR5cGVvZiB2YWwgPT09ICdudW1iZXInKSB7XG4gICAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUICYmIFVpbnQ4QXJyYXkucHJvdG90eXBlLmluZGV4T2YgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHJldHVybiBVaW50OEFycmF5LnByb3RvdHlwZS5pbmRleE9mLmNhbGwodGhpcywgdmFsLCBieXRlT2Zmc2V0KVxuICAgIH1cbiAgICByZXR1cm4gYXJyYXlJbmRleE9mKHRoaXMsIFsgdmFsIF0sIGJ5dGVPZmZzZXQsIGVuY29kaW5nKVxuICB9XG5cbiAgdGhyb3cgbmV3IFR5cGVFcnJvcigndmFsIG11c3QgYmUgc3RyaW5nLCBudW1iZXIgb3IgQnVmZmVyJylcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5pbmNsdWRlcyA9IGZ1bmN0aW9uIGluY2x1ZGVzICh2YWwsIGJ5dGVPZmZzZXQsIGVuY29kaW5nKSB7XG4gIHJldHVybiB0aGlzLmluZGV4T2YodmFsLCBieXRlT2Zmc2V0LCBlbmNvZGluZykgIT09IC0xXG59XG5cbmZ1bmN0aW9uIGhleFdyaXRlIChidWYsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgb2Zmc2V0ID0gTnVtYmVyKG9mZnNldCkgfHwgMFxuICB2YXIgcmVtYWluaW5nID0gYnVmLmxlbmd0aCAtIG9mZnNldFxuICBpZiAoIWxlbmd0aCkge1xuICAgIGxlbmd0aCA9IHJlbWFpbmluZ1xuICB9IGVsc2Uge1xuICAgIGxlbmd0aCA9IE51bWJlcihsZW5ndGgpXG4gICAgaWYgKGxlbmd0aCA+IHJlbWFpbmluZykge1xuICAgICAgbGVuZ3RoID0gcmVtYWluaW5nXG4gICAgfVxuICB9XG5cbiAgLy8gbXVzdCBiZSBhbiBldmVuIG51bWJlciBvZiBkaWdpdHNcbiAgdmFyIHN0ckxlbiA9IHN0cmluZy5sZW5ndGhcbiAgaWYgKHN0ckxlbiAlIDIgIT09IDApIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBoZXggc3RyaW5nJylcblxuICBpZiAobGVuZ3RoID4gc3RyTGVuIC8gMikge1xuICAgIGxlbmd0aCA9IHN0ckxlbiAvIDJcbiAgfVxuICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIHBhcnNlZCA9IHBhcnNlSW50KHN0cmluZy5zdWJzdHIoaSAqIDIsIDIpLCAxNilcbiAgICBpZiAoaXNOYU4ocGFyc2VkKSkgcmV0dXJuIGlcbiAgICBidWZbb2Zmc2V0ICsgaV0gPSBwYXJzZWRcbiAgfVxuICByZXR1cm4gaVxufVxuXG5mdW5jdGlvbiB1dGY4V3JpdGUgKGJ1Ziwgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aCkge1xuICByZXR1cm4gYmxpdEJ1ZmZlcih1dGY4VG9CeXRlcyhzdHJpbmcsIGJ1Zi5sZW5ndGggLSBvZmZzZXQpLCBidWYsIG9mZnNldCwgbGVuZ3RoKVxufVxuXG5mdW5jdGlvbiBhc2NpaVdyaXRlIChidWYsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgcmV0dXJuIGJsaXRCdWZmZXIoYXNjaWlUb0J5dGVzKHN0cmluZyksIGJ1Ziwgb2Zmc2V0LCBsZW5ndGgpXG59XG5cbmZ1bmN0aW9uIGJpbmFyeVdyaXRlIChidWYsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgcmV0dXJuIGFzY2lpV3JpdGUoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxufVxuXG5mdW5jdGlvbiBiYXNlNjRXcml0ZSAoYnVmLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKSB7XG4gIHJldHVybiBibGl0QnVmZmVyKGJhc2U2NFRvQnl0ZXMoc3RyaW5nKSwgYnVmLCBvZmZzZXQsIGxlbmd0aClcbn1cblxuZnVuY3Rpb24gdWNzMldyaXRlIChidWYsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgcmV0dXJuIGJsaXRCdWZmZXIodXRmMTZsZVRvQnl0ZXMoc3RyaW5nLCBidWYubGVuZ3RoIC0gb2Zmc2V0KSwgYnVmLCBvZmZzZXQsIGxlbmd0aClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZSA9IGZ1bmN0aW9uIHdyaXRlIChzdHJpbmcsIG9mZnNldCwgbGVuZ3RoLCBlbmNvZGluZykge1xuICAvLyBCdWZmZXIjd3JpdGUoc3RyaW5nKVxuICBpZiAob2Zmc2V0ID09PSB1bmRlZmluZWQpIHtcbiAgICBlbmNvZGluZyA9ICd1dGY4J1xuICAgIGxlbmd0aCA9IHRoaXMubGVuZ3RoXG4gICAgb2Zmc2V0ID0gMFxuICAvLyBCdWZmZXIjd3JpdGUoc3RyaW5nLCBlbmNvZGluZylcbiAgfSBlbHNlIGlmIChsZW5ndGggPT09IHVuZGVmaW5lZCAmJiB0eXBlb2Ygb2Zmc2V0ID09PSAnc3RyaW5nJykge1xuICAgIGVuY29kaW5nID0gb2Zmc2V0XG4gICAgbGVuZ3RoID0gdGhpcy5sZW5ndGhcbiAgICBvZmZzZXQgPSAwXG4gIC8vIEJ1ZmZlciN3cml0ZShzdHJpbmcsIG9mZnNldFssIGxlbmd0aF1bLCBlbmNvZGluZ10pXG4gIH0gZWxzZSBpZiAoaXNGaW5pdGUob2Zmc2V0KSkge1xuICAgIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgICBpZiAoaXNGaW5pdGUobGVuZ3RoKSkge1xuICAgICAgbGVuZ3RoID0gbGVuZ3RoIHwgMFxuICAgICAgaWYgKGVuY29kaW5nID09PSB1bmRlZmluZWQpIGVuY29kaW5nID0gJ3V0ZjgnXG4gICAgfSBlbHNlIHtcbiAgICAgIGVuY29kaW5nID0gbGVuZ3RoXG4gICAgICBsZW5ndGggPSB1bmRlZmluZWRcbiAgICB9XG4gIC8vIGxlZ2FjeSB3cml0ZShzdHJpbmcsIGVuY29kaW5nLCBvZmZzZXQsIGxlbmd0aCkgLSByZW1vdmUgaW4gdjAuMTNcbiAgfSBlbHNlIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAnQnVmZmVyLndyaXRlKHN0cmluZywgZW5jb2RpbmcsIG9mZnNldFssIGxlbmd0aF0pIGlzIG5vIGxvbmdlciBzdXBwb3J0ZWQnXG4gICAgKVxuICB9XG5cbiAgdmFyIHJlbWFpbmluZyA9IHRoaXMubGVuZ3RoIC0gb2Zmc2V0XG4gIGlmIChsZW5ndGggPT09IHVuZGVmaW5lZCB8fCBsZW5ndGggPiByZW1haW5pbmcpIGxlbmd0aCA9IHJlbWFpbmluZ1xuXG4gIGlmICgoc3RyaW5nLmxlbmd0aCA+IDAgJiYgKGxlbmd0aCA8IDAgfHwgb2Zmc2V0IDwgMCkpIHx8IG9mZnNldCA+IHRoaXMubGVuZ3RoKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0F0dGVtcHQgdG8gd3JpdGUgb3V0c2lkZSBidWZmZXIgYm91bmRzJylcbiAgfVxuXG4gIGlmICghZW5jb2RpbmcpIGVuY29kaW5nID0gJ3V0ZjgnXG5cbiAgdmFyIGxvd2VyZWRDYXNlID0gZmFsc2VcbiAgZm9yICg7Oykge1xuICAgIHN3aXRjaCAoZW5jb2RpbmcpIHtcbiAgICAgIGNhc2UgJ2hleCc6XG4gICAgICAgIHJldHVybiBoZXhXcml0ZSh0aGlzLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxuXG4gICAgICBjYXNlICd1dGY4JzpcbiAgICAgIGNhc2UgJ3V0Zi04JzpcbiAgICAgICAgcmV0dXJuIHV0ZjhXcml0ZSh0aGlzLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxuXG4gICAgICBjYXNlICdhc2NpaSc6XG4gICAgICAgIHJldHVybiBhc2NpaVdyaXRlKHRoaXMsIHN0cmluZywgb2Zmc2V0LCBsZW5ndGgpXG5cbiAgICAgIGNhc2UgJ2JpbmFyeSc6XG4gICAgICAgIHJldHVybiBiaW5hcnlXcml0ZSh0aGlzLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxuXG4gICAgICBjYXNlICdiYXNlNjQnOlxuICAgICAgICAvLyBXYXJuaW5nOiBtYXhMZW5ndGggbm90IHRha2VuIGludG8gYWNjb3VudCBpbiBiYXNlNjRXcml0ZVxuICAgICAgICByZXR1cm4gYmFzZTY0V3JpdGUodGhpcywgc3RyaW5nLCBvZmZzZXQsIGxlbmd0aClcblxuICAgICAgY2FzZSAndWNzMic6XG4gICAgICBjYXNlICd1Y3MtMic6XG4gICAgICBjYXNlICd1dGYxNmxlJzpcbiAgICAgIGNhc2UgJ3V0Zi0xNmxlJzpcbiAgICAgICAgcmV0dXJuIHVjczJXcml0ZSh0aGlzLCBzdHJpbmcsIG9mZnNldCwgbGVuZ3RoKVxuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBpZiAobG93ZXJlZENhc2UpIHRocm93IG5ldyBUeXBlRXJyb3IoJ1Vua25vd24gZW5jb2Rpbmc6ICcgKyBlbmNvZGluZylcbiAgICAgICAgZW5jb2RpbmcgPSAoJycgKyBlbmNvZGluZykudG9Mb3dlckNhc2UoKVxuICAgICAgICBsb3dlcmVkQ2FzZSA9IHRydWVcbiAgICB9XG4gIH1cbn1cblxuQnVmZmVyLnByb3RvdHlwZS50b0pTT04gPSBmdW5jdGlvbiB0b0pTT04gKCkge1xuICByZXR1cm4ge1xuICAgIHR5cGU6ICdCdWZmZXInLFxuICAgIGRhdGE6IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKHRoaXMuX2FyciB8fCB0aGlzLCAwKVxuICB9XG59XG5cbmZ1bmN0aW9uIGJhc2U2NFNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgaWYgKHN0YXJ0ID09PSAwICYmIGVuZCA9PT0gYnVmLmxlbmd0aCkge1xuICAgIHJldHVybiBiYXNlNjQuZnJvbUJ5dGVBcnJheShidWYpXG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIGJhc2U2NC5mcm9tQnl0ZUFycmF5KGJ1Zi5zbGljZShzdGFydCwgZW5kKSlcbiAgfVxufVxuXG5mdW5jdGlvbiB1dGY4U2xpY2UgKGJ1Ziwgc3RhcnQsIGVuZCkge1xuICBlbmQgPSBNYXRoLm1pbihidWYubGVuZ3RoLCBlbmQpXG4gIHZhciByZXMgPSBbXVxuXG4gIHZhciBpID0gc3RhcnRcbiAgd2hpbGUgKGkgPCBlbmQpIHtcbiAgICB2YXIgZmlyc3RCeXRlID0gYnVmW2ldXG4gICAgdmFyIGNvZGVQb2ludCA9IG51bGxcbiAgICB2YXIgYnl0ZXNQZXJTZXF1ZW5jZSA9IChmaXJzdEJ5dGUgPiAweEVGKSA/IDRcbiAgICAgIDogKGZpcnN0Qnl0ZSA+IDB4REYpID8gM1xuICAgICAgOiAoZmlyc3RCeXRlID4gMHhCRikgPyAyXG4gICAgICA6IDFcblxuICAgIGlmIChpICsgYnl0ZXNQZXJTZXF1ZW5jZSA8PSBlbmQpIHtcbiAgICAgIHZhciBzZWNvbmRCeXRlLCB0aGlyZEJ5dGUsIGZvdXJ0aEJ5dGUsIHRlbXBDb2RlUG9pbnRcblxuICAgICAgc3dpdGNoIChieXRlc1BlclNlcXVlbmNlKSB7XG4gICAgICAgIGNhc2UgMTpcbiAgICAgICAgICBpZiAoZmlyc3RCeXRlIDwgMHg4MCkge1xuICAgICAgICAgICAgY29kZVBvaW50ID0gZmlyc3RCeXRlXG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIGNhc2UgMjpcbiAgICAgICAgICBzZWNvbmRCeXRlID0gYnVmW2kgKyAxXVxuICAgICAgICAgIGlmICgoc2Vjb25kQnl0ZSAmIDB4QzApID09PSAweDgwKSB7XG4gICAgICAgICAgICB0ZW1wQ29kZVBvaW50ID0gKGZpcnN0Qnl0ZSAmIDB4MUYpIDw8IDB4NiB8IChzZWNvbmRCeXRlICYgMHgzRilcbiAgICAgICAgICAgIGlmICh0ZW1wQ29kZVBvaW50ID4gMHg3Rikge1xuICAgICAgICAgICAgICBjb2RlUG9pbnQgPSB0ZW1wQ29kZVBvaW50XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIGNhc2UgMzpcbiAgICAgICAgICBzZWNvbmRCeXRlID0gYnVmW2kgKyAxXVxuICAgICAgICAgIHRoaXJkQnl0ZSA9IGJ1ZltpICsgMl1cbiAgICAgICAgICBpZiAoKHNlY29uZEJ5dGUgJiAweEMwKSA9PT0gMHg4MCAmJiAodGhpcmRCeXRlICYgMHhDMCkgPT09IDB4ODApIHtcbiAgICAgICAgICAgIHRlbXBDb2RlUG9pbnQgPSAoZmlyc3RCeXRlICYgMHhGKSA8PCAweEMgfCAoc2Vjb25kQnl0ZSAmIDB4M0YpIDw8IDB4NiB8ICh0aGlyZEJ5dGUgJiAweDNGKVxuICAgICAgICAgICAgaWYgKHRlbXBDb2RlUG9pbnQgPiAweDdGRiAmJiAodGVtcENvZGVQb2ludCA8IDB4RDgwMCB8fCB0ZW1wQ29kZVBvaW50ID4gMHhERkZGKSkge1xuICAgICAgICAgICAgICBjb2RlUG9pbnQgPSB0ZW1wQ29kZVBvaW50XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIGNhc2UgNDpcbiAgICAgICAgICBzZWNvbmRCeXRlID0gYnVmW2kgKyAxXVxuICAgICAgICAgIHRoaXJkQnl0ZSA9IGJ1ZltpICsgMl1cbiAgICAgICAgICBmb3VydGhCeXRlID0gYnVmW2kgKyAzXVxuICAgICAgICAgIGlmICgoc2Vjb25kQnl0ZSAmIDB4QzApID09PSAweDgwICYmICh0aGlyZEJ5dGUgJiAweEMwKSA9PT0gMHg4MCAmJiAoZm91cnRoQnl0ZSAmIDB4QzApID09PSAweDgwKSB7XG4gICAgICAgICAgICB0ZW1wQ29kZVBvaW50ID0gKGZpcnN0Qnl0ZSAmIDB4RikgPDwgMHgxMiB8IChzZWNvbmRCeXRlICYgMHgzRikgPDwgMHhDIHwgKHRoaXJkQnl0ZSAmIDB4M0YpIDw8IDB4NiB8IChmb3VydGhCeXRlICYgMHgzRilcbiAgICAgICAgICAgIGlmICh0ZW1wQ29kZVBvaW50ID4gMHhGRkZGICYmIHRlbXBDb2RlUG9pbnQgPCAweDExMDAwMCkge1xuICAgICAgICAgICAgICBjb2RlUG9pbnQgPSB0ZW1wQ29kZVBvaW50XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjb2RlUG9pbnQgPT09IG51bGwpIHtcbiAgICAgIC8vIHdlIGRpZCBub3QgZ2VuZXJhdGUgYSB2YWxpZCBjb2RlUG9pbnQgc28gaW5zZXJ0IGFcbiAgICAgIC8vIHJlcGxhY2VtZW50IGNoYXIgKFUrRkZGRCkgYW5kIGFkdmFuY2Ugb25seSAxIGJ5dGVcbiAgICAgIGNvZGVQb2ludCA9IDB4RkZGRFxuICAgICAgYnl0ZXNQZXJTZXF1ZW5jZSA9IDFcbiAgICB9IGVsc2UgaWYgKGNvZGVQb2ludCA+IDB4RkZGRikge1xuICAgICAgLy8gZW5jb2RlIHRvIHV0ZjE2IChzdXJyb2dhdGUgcGFpciBkYW5jZSlcbiAgICAgIGNvZGVQb2ludCAtPSAweDEwMDAwXG4gICAgICByZXMucHVzaChjb2RlUG9pbnQgPj4+IDEwICYgMHgzRkYgfCAweEQ4MDApXG4gICAgICBjb2RlUG9pbnQgPSAweERDMDAgfCBjb2RlUG9pbnQgJiAweDNGRlxuICAgIH1cblxuICAgIHJlcy5wdXNoKGNvZGVQb2ludClcbiAgICBpICs9IGJ5dGVzUGVyU2VxdWVuY2VcbiAgfVxuXG4gIHJldHVybiBkZWNvZGVDb2RlUG9pbnRzQXJyYXkocmVzKVxufVxuXG4vLyBCYXNlZCBvbiBodHRwOi8vc3RhY2tvdmVyZmxvdy5jb20vYS8yMjc0NzI3Mi82ODA3NDIsIHRoZSBicm93c2VyIHdpdGhcbi8vIHRoZSBsb3dlc3QgbGltaXQgaXMgQ2hyb21lLCB3aXRoIDB4MTAwMDAgYXJncy5cbi8vIFdlIGdvIDEgbWFnbml0dWRlIGxlc3MsIGZvciBzYWZldHlcbnZhciBNQVhfQVJHVU1FTlRTX0xFTkdUSCA9IDB4MTAwMFxuXG5mdW5jdGlvbiBkZWNvZGVDb2RlUG9pbnRzQXJyYXkgKGNvZGVQb2ludHMpIHtcbiAgdmFyIGxlbiA9IGNvZGVQb2ludHMubGVuZ3RoXG4gIGlmIChsZW4gPD0gTUFYX0FSR1VNRU5UU19MRU5HVEgpIHtcbiAgICByZXR1cm4gU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShTdHJpbmcsIGNvZGVQb2ludHMpIC8vIGF2b2lkIGV4dHJhIHNsaWNlKClcbiAgfVxuXG4gIC8vIERlY29kZSBpbiBjaHVua3MgdG8gYXZvaWQgXCJjYWxsIHN0YWNrIHNpemUgZXhjZWVkZWRcIi5cbiAgdmFyIHJlcyA9ICcnXG4gIHZhciBpID0gMFxuICB3aGlsZSAoaSA8IGxlbikge1xuICAgIHJlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KFxuICAgICAgU3RyaW5nLFxuICAgICAgY29kZVBvaW50cy5zbGljZShpLCBpICs9IE1BWF9BUkdVTUVOVFNfTEVOR1RIKVxuICAgIClcbiAgfVxuICByZXR1cm4gcmVzXG59XG5cbmZ1bmN0aW9uIGFzY2lpU2xpY2UgKGJ1Ziwgc3RhcnQsIGVuZCkge1xuICB2YXIgcmV0ID0gJydcbiAgZW5kID0gTWF0aC5taW4oYnVmLmxlbmd0aCwgZW5kKVxuXG4gIGZvciAodmFyIGkgPSBzdGFydDsgaSA8IGVuZDsgaSsrKSB7XG4gICAgcmV0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnVmW2ldICYgMHg3RilcbiAgfVxuICByZXR1cm4gcmV0XG59XG5cbmZ1bmN0aW9uIGJpbmFyeVNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIHJldCA9ICcnXG4gIGVuZCA9IE1hdGgubWluKGJ1Zi5sZW5ndGgsIGVuZClcblxuICBmb3IgKHZhciBpID0gc3RhcnQ7IGkgPCBlbmQ7IGkrKykge1xuICAgIHJldCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ1ZltpXSlcbiAgfVxuICByZXR1cm4gcmV0XG59XG5cbmZ1bmN0aW9uIGhleFNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIGxlbiA9IGJ1Zi5sZW5ndGhcblxuICBpZiAoIXN0YXJ0IHx8IHN0YXJ0IDwgMCkgc3RhcnQgPSAwXG4gIGlmICghZW5kIHx8IGVuZCA8IDAgfHwgZW5kID4gbGVuKSBlbmQgPSBsZW5cblxuICB2YXIgb3V0ID0gJydcbiAgZm9yICh2YXIgaSA9IHN0YXJ0OyBpIDwgZW5kOyBpKyspIHtcbiAgICBvdXQgKz0gdG9IZXgoYnVmW2ldKVxuICB9XG4gIHJldHVybiBvdXRcbn1cblxuZnVuY3Rpb24gdXRmMTZsZVNsaWNlIChidWYsIHN0YXJ0LCBlbmQpIHtcbiAgdmFyIGJ5dGVzID0gYnVmLnNsaWNlKHN0YXJ0LCBlbmQpXG4gIHZhciByZXMgPSAnJ1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVzLmxlbmd0aDsgaSArPSAyKSB7XG4gICAgcmVzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZXNbaV0gKyBieXRlc1tpICsgMV0gKiAyNTYpXG4gIH1cbiAgcmV0dXJuIHJlc1xufVxuXG5CdWZmZXIucHJvdG90eXBlLnNsaWNlID0gZnVuY3Rpb24gc2xpY2UgKHN0YXJ0LCBlbmQpIHtcbiAgdmFyIGxlbiA9IHRoaXMubGVuZ3RoXG4gIHN0YXJ0ID0gfn5zdGFydFxuICBlbmQgPSBlbmQgPT09IHVuZGVmaW5lZCA/IGxlbiA6IH5+ZW5kXG5cbiAgaWYgKHN0YXJ0IDwgMCkge1xuICAgIHN0YXJ0ICs9IGxlblxuICAgIGlmIChzdGFydCA8IDApIHN0YXJ0ID0gMFxuICB9IGVsc2UgaWYgKHN0YXJ0ID4gbGVuKSB7XG4gICAgc3RhcnQgPSBsZW5cbiAgfVxuXG4gIGlmIChlbmQgPCAwKSB7XG4gICAgZW5kICs9IGxlblxuICAgIGlmIChlbmQgPCAwKSBlbmQgPSAwXG4gIH0gZWxzZSBpZiAoZW5kID4gbGVuKSB7XG4gICAgZW5kID0gbGVuXG4gIH1cblxuICBpZiAoZW5kIDwgc3RhcnQpIGVuZCA9IHN0YXJ0XG5cbiAgdmFyIG5ld0J1ZlxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICBuZXdCdWYgPSB0aGlzLnN1YmFycmF5KHN0YXJ0LCBlbmQpXG4gICAgbmV3QnVmLl9fcHJvdG9fXyA9IEJ1ZmZlci5wcm90b3R5cGVcbiAgfSBlbHNlIHtcbiAgICB2YXIgc2xpY2VMZW4gPSBlbmQgLSBzdGFydFxuICAgIG5ld0J1ZiA9IG5ldyBCdWZmZXIoc2xpY2VMZW4sIHVuZGVmaW5lZClcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNsaWNlTGVuOyBpKyspIHtcbiAgICAgIG5ld0J1ZltpXSA9IHRoaXNbaSArIHN0YXJ0XVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBuZXdCdWZcbn1cblxuLypcbiAqIE5lZWQgdG8gbWFrZSBzdXJlIHRoYXQgYnVmZmVyIGlzbid0IHRyeWluZyB0byB3cml0ZSBvdXQgb2YgYm91bmRzLlxuICovXG5mdW5jdGlvbiBjaGVja09mZnNldCAob2Zmc2V0LCBleHQsIGxlbmd0aCkge1xuICBpZiAoKG9mZnNldCAlIDEpICE9PSAwIHx8IG9mZnNldCA8IDApIHRocm93IG5ldyBSYW5nZUVycm9yKCdvZmZzZXQgaXMgbm90IHVpbnQnKVxuICBpZiAob2Zmc2V0ICsgZXh0ID4gbGVuZ3RoKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignVHJ5aW5nIHRvIGFjY2VzcyBiZXlvbmQgYnVmZmVyIGxlbmd0aCcpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZFVJbnRMRSA9IGZ1bmN0aW9uIHJlYWRVSW50TEUgKG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBieXRlTGVuZ3RoID0gYnl0ZUxlbmd0aCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCBieXRlTGVuZ3RoLCB0aGlzLmxlbmd0aClcblxuICB2YXIgdmFsID0gdGhpc1tvZmZzZXRdXG4gIHZhciBtdWwgPSAxXG4gIHZhciBpID0gMFxuICB3aGlsZSAoKytpIDwgYnl0ZUxlbmd0aCAmJiAobXVsICo9IDB4MTAwKSkge1xuICAgIHZhbCArPSB0aGlzW29mZnNldCArIGldICogbXVsXG4gIH1cblxuICByZXR1cm4gdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZFVJbnRCRSA9IGZ1bmN0aW9uIHJlYWRVSW50QkUgKG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBieXRlTGVuZ3RoID0gYnl0ZUxlbmd0aCB8IDBcbiAgaWYgKCFub0Fzc2VydCkge1xuICAgIGNoZWNrT2Zmc2V0KG9mZnNldCwgYnl0ZUxlbmd0aCwgdGhpcy5sZW5ndGgpXG4gIH1cblxuICB2YXIgdmFsID0gdGhpc1tvZmZzZXQgKyAtLWJ5dGVMZW5ndGhdXG4gIHZhciBtdWwgPSAxXG4gIHdoaWxlIChieXRlTGVuZ3RoID4gMCAmJiAobXVsICo9IDB4MTAwKSkge1xuICAgIHZhbCArPSB0aGlzW29mZnNldCArIC0tYnl0ZUxlbmd0aF0gKiBtdWxcbiAgfVxuXG4gIHJldHVybiB2YWxcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkVUludDggPSBmdW5jdGlvbiByZWFkVUludDggKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCAxLCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuIHRoaXNbb2Zmc2V0XVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRVSW50MTZMRSA9IGZ1bmN0aW9uIHJlYWRVSW50MTZMRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDIsIHRoaXMubGVuZ3RoKVxuICByZXR1cm4gdGhpc1tvZmZzZXRdIHwgKHRoaXNbb2Zmc2V0ICsgMV0gPDwgOClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkVUludDE2QkUgPSBmdW5jdGlvbiByZWFkVUludDE2QkUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCAyLCB0aGlzLmxlbmd0aClcbiAgcmV0dXJuICh0aGlzW29mZnNldF0gPDwgOCkgfCB0aGlzW29mZnNldCArIDFdXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZFVJbnQzMkxFID0gZnVuY3Rpb24gcmVhZFVJbnQzMkxFIChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgNCwgdGhpcy5sZW5ndGgpXG5cbiAgcmV0dXJuICgodGhpc1tvZmZzZXRdKSB8XG4gICAgICAodGhpc1tvZmZzZXQgKyAxXSA8PCA4KSB8XG4gICAgICAodGhpc1tvZmZzZXQgKyAyXSA8PCAxNikpICtcbiAgICAgICh0aGlzW29mZnNldCArIDNdICogMHgxMDAwMDAwKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRVSW50MzJCRSA9IGZ1bmN0aW9uIHJlYWRVSW50MzJCRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuXG4gIHJldHVybiAodGhpc1tvZmZzZXRdICogMHgxMDAwMDAwKSArXG4gICAgKCh0aGlzW29mZnNldCArIDFdIDw8IDE2KSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgMl0gPDwgOCkgfFxuICAgIHRoaXNbb2Zmc2V0ICsgM10pXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludExFID0gZnVuY3Rpb24gcmVhZEludExFIChvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgYnl0ZUxlbmd0aCwgdGhpcy5sZW5ndGgpXG5cbiAgdmFyIHZhbCA9IHRoaXNbb2Zmc2V0XVxuICB2YXIgbXVsID0gMVxuICB2YXIgaSA9IDBcbiAgd2hpbGUgKCsraSA8IGJ5dGVMZW5ndGggJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICB2YWwgKz0gdGhpc1tvZmZzZXQgKyBpXSAqIG11bFxuICB9XG4gIG11bCAqPSAweDgwXG5cbiAgaWYgKHZhbCA+PSBtdWwpIHZhbCAtPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aClcblxuICByZXR1cm4gdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludEJFID0gZnVuY3Rpb24gcmVhZEludEJFIChvZmZzZXQsIGJ5dGVMZW5ndGgsIG5vQXNzZXJ0KSB7XG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgYnl0ZUxlbmd0aCA9IGJ5dGVMZW5ndGggfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgYnl0ZUxlbmd0aCwgdGhpcy5sZW5ndGgpXG5cbiAgdmFyIGkgPSBieXRlTGVuZ3RoXG4gIHZhciBtdWwgPSAxXG4gIHZhciB2YWwgPSB0aGlzW29mZnNldCArIC0taV1cbiAgd2hpbGUgKGkgPiAwICYmIChtdWwgKj0gMHgxMDApKSB7XG4gICAgdmFsICs9IHRoaXNbb2Zmc2V0ICsgLS1pXSAqIG11bFxuICB9XG4gIG11bCAqPSAweDgwXG5cbiAgaWYgKHZhbCA+PSBtdWwpIHZhbCAtPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aClcblxuICByZXR1cm4gdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludDggPSBmdW5jdGlvbiByZWFkSW50OCAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDEsIHRoaXMubGVuZ3RoKVxuICBpZiAoISh0aGlzW29mZnNldF0gJiAweDgwKSkgcmV0dXJuICh0aGlzW29mZnNldF0pXG4gIHJldHVybiAoKDB4ZmYgLSB0aGlzW29mZnNldF0gKyAxKSAqIC0xKVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWRJbnQxNkxFID0gZnVuY3Rpb24gcmVhZEludDE2TEUgKG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tPZmZzZXQob2Zmc2V0LCAyLCB0aGlzLmxlbmd0aClcbiAgdmFyIHZhbCA9IHRoaXNbb2Zmc2V0XSB8ICh0aGlzW29mZnNldCArIDFdIDw8IDgpXG4gIHJldHVybiAodmFsICYgMHg4MDAwKSA/IHZhbCB8IDB4RkZGRjAwMDAgOiB2YWxcbn1cblxuQnVmZmVyLnByb3RvdHlwZS5yZWFkSW50MTZCRSA9IGZ1bmN0aW9uIHJlYWRJbnQxNkJFIChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgMiwgdGhpcy5sZW5ndGgpXG4gIHZhciB2YWwgPSB0aGlzW29mZnNldCArIDFdIHwgKHRoaXNbb2Zmc2V0XSA8PCA4KVxuICByZXR1cm4gKHZhbCAmIDB4ODAwMCkgPyB2YWwgfCAweEZGRkYwMDAwIDogdmFsXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludDMyTEUgPSBmdW5jdGlvbiByZWFkSW50MzJMRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuXG4gIHJldHVybiAodGhpc1tvZmZzZXRdKSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgMV0gPDwgOCkgfFxuICAgICh0aGlzW29mZnNldCArIDJdIDw8IDE2KSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgM10gPDwgMjQpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEludDMyQkUgPSBmdW5jdGlvbiByZWFkSW50MzJCRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuXG4gIHJldHVybiAodGhpc1tvZmZzZXRdIDw8IDI0KSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgMV0gPDwgMTYpIHxcbiAgICAodGhpc1tvZmZzZXQgKyAyXSA8PCA4KSB8XG4gICAgKHRoaXNbb2Zmc2V0ICsgM10pXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEZsb2F0TEUgPSBmdW5jdGlvbiByZWFkRmxvYXRMRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuICByZXR1cm4gaWVlZTc1NC5yZWFkKHRoaXMsIG9mZnNldCwgdHJ1ZSwgMjMsIDQpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZEZsb2F0QkUgPSBmdW5jdGlvbiByZWFkRmxvYXRCRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDQsIHRoaXMubGVuZ3RoKVxuICByZXR1cm4gaWVlZTc1NC5yZWFkKHRoaXMsIG9mZnNldCwgZmFsc2UsIDIzLCA0KVxufVxuXG5CdWZmZXIucHJvdG90eXBlLnJlYWREb3VibGVMRSA9IGZ1bmN0aW9uIHJlYWREb3VibGVMRSAob2Zmc2V0LCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSBjaGVja09mZnNldChvZmZzZXQsIDgsIHRoaXMubGVuZ3RoKVxuICByZXR1cm4gaWVlZTc1NC5yZWFkKHRoaXMsIG9mZnNldCwgdHJ1ZSwgNTIsIDgpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUucmVhZERvdWJsZUJFID0gZnVuY3Rpb24gcmVhZERvdWJsZUJFIChvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrT2Zmc2V0KG9mZnNldCwgOCwgdGhpcy5sZW5ndGgpXG4gIHJldHVybiBpZWVlNzU0LnJlYWQodGhpcywgb2Zmc2V0LCBmYWxzZSwgNTIsIDgpXG59XG5cbmZ1bmN0aW9uIGNoZWNrSW50IChidWYsIHZhbHVlLCBvZmZzZXQsIGV4dCwgbWF4LCBtaW4pIHtcbiAgaWYgKCFCdWZmZXIuaXNCdWZmZXIoYnVmKSkgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJidWZmZXJcIiBhcmd1bWVudCBtdXN0IGJlIGEgQnVmZmVyIGluc3RhbmNlJylcbiAgaWYgKHZhbHVlID4gbWF4IHx8IHZhbHVlIDwgbWluKSB0aHJvdyBuZXcgUmFuZ2VFcnJvcignXCJ2YWx1ZVwiIGFyZ3VtZW50IGlzIG91dCBvZiBib3VuZHMnKVxuICBpZiAob2Zmc2V0ICsgZXh0ID4gYnVmLmxlbmd0aCkgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0luZGV4IG91dCBvZiByYW5nZScpXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVVSW50TEUgPSBmdW5jdGlvbiB3cml0ZVVJbnRMRSAodmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBieXRlTGVuZ3RoID0gYnl0ZUxlbmd0aCB8IDBcbiAgaWYgKCFub0Fzc2VydCkge1xuICAgIHZhciBtYXhCeXRlcyA9IE1hdGgucG93KDIsIDggKiBieXRlTGVuZ3RoKSAtIDFcbiAgICBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBtYXhCeXRlcywgMClcbiAgfVxuXG4gIHZhciBtdWwgPSAxXG4gIHZhciBpID0gMFxuICB0aGlzW29mZnNldF0gPSB2YWx1ZSAmIDB4RkZcbiAgd2hpbGUgKCsraSA8IGJ5dGVMZW5ndGggJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICB0aGlzW29mZnNldCArIGldID0gKHZhbHVlIC8gbXVsKSAmIDB4RkZcbiAgfVxuXG4gIHJldHVybiBvZmZzZXQgKyBieXRlTGVuZ3RoXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVVSW50QkUgPSBmdW5jdGlvbiB3cml0ZVVJbnRCRSAodmFsdWUsIG9mZnNldCwgYnl0ZUxlbmd0aCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBieXRlTGVuZ3RoID0gYnl0ZUxlbmd0aCB8IDBcbiAgaWYgKCFub0Fzc2VydCkge1xuICAgIHZhciBtYXhCeXRlcyA9IE1hdGgucG93KDIsIDggKiBieXRlTGVuZ3RoKSAtIDFcbiAgICBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBtYXhCeXRlcywgMClcbiAgfVxuXG4gIHZhciBpID0gYnl0ZUxlbmd0aCAtIDFcbiAgdmFyIG11bCA9IDFcbiAgdGhpc1tvZmZzZXQgKyBpXSA9IHZhbHVlICYgMHhGRlxuICB3aGlsZSAoLS1pID49IDAgJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICB0aGlzW29mZnNldCArIGldID0gKHZhbHVlIC8gbXVsKSAmIDB4RkZcbiAgfVxuXG4gIHJldHVybiBvZmZzZXQgKyBieXRlTGVuZ3RoXG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVVSW50OCA9IGZ1bmN0aW9uIHdyaXRlVUludDggKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgMSwgMHhmZiwgMClcbiAgaWYgKCFCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkgdmFsdWUgPSBNYXRoLmZsb29yKHZhbHVlKVxuICB0aGlzW29mZnNldF0gPSAodmFsdWUgJiAweGZmKVxuICByZXR1cm4gb2Zmc2V0ICsgMVxufVxuXG5mdW5jdGlvbiBvYmplY3RXcml0ZVVJbnQxNiAoYnVmLCB2YWx1ZSwgb2Zmc2V0LCBsaXR0bGVFbmRpYW4pIHtcbiAgaWYgKHZhbHVlIDwgMCkgdmFsdWUgPSAweGZmZmYgKyB2YWx1ZSArIDFcbiAgZm9yICh2YXIgaSA9IDAsIGogPSBNYXRoLm1pbihidWYubGVuZ3RoIC0gb2Zmc2V0LCAyKTsgaSA8IGo7IGkrKykge1xuICAgIGJ1ZltvZmZzZXQgKyBpXSA9ICh2YWx1ZSAmICgweGZmIDw8ICg4ICogKGxpdHRsZUVuZGlhbiA/IGkgOiAxIC0gaSkpKSkgPj4+XG4gICAgICAobGl0dGxlRW5kaWFuID8gaSA6IDEgLSBpKSAqIDhcbiAgfVxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlVUludDE2TEUgPSBmdW5jdGlvbiB3cml0ZVVJbnQxNkxFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrSW50KHRoaXMsIHZhbHVlLCBvZmZzZXQsIDIsIDB4ZmZmZiwgMClcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgdGhpc1tvZmZzZXRdID0gKHZhbHVlICYgMHhmZilcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlID4+PiA4KVxuICB9IGVsc2Uge1xuICAgIG9iamVjdFdyaXRlVUludDE2KHRoaXMsIHZhbHVlLCBvZmZzZXQsIHRydWUpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDJcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZVVJbnQxNkJFID0gZnVuY3Rpb24gd3JpdGVVSW50MTZCRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCAyLCAweGZmZmYsIDApXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSA+Pj4gOClcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlICYgMHhmZilcbiAgfSBlbHNlIHtcbiAgICBvYmplY3RXcml0ZVVJbnQxNih0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBmYWxzZSlcbiAgfVxuICByZXR1cm4gb2Zmc2V0ICsgMlxufVxuXG5mdW5jdGlvbiBvYmplY3RXcml0ZVVJbnQzMiAoYnVmLCB2YWx1ZSwgb2Zmc2V0LCBsaXR0bGVFbmRpYW4pIHtcbiAgaWYgKHZhbHVlIDwgMCkgdmFsdWUgPSAweGZmZmZmZmZmICsgdmFsdWUgKyAxXG4gIGZvciAodmFyIGkgPSAwLCBqID0gTWF0aC5taW4oYnVmLmxlbmd0aCAtIG9mZnNldCwgNCk7IGkgPCBqOyBpKyspIHtcbiAgICBidWZbb2Zmc2V0ICsgaV0gPSAodmFsdWUgPj4+IChsaXR0bGVFbmRpYW4gPyBpIDogMyAtIGkpICogOCkgJiAweGZmXG4gIH1cbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZVVJbnQzMkxFID0gZnVuY3Rpb24gd3JpdGVVSW50MzJMRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCA0LCAweGZmZmZmZmZmLCAwKVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldCArIDNdID0gKHZhbHVlID4+PiAyNClcbiAgICB0aGlzW29mZnNldCArIDJdID0gKHZhbHVlID4+PiAxNilcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlID4+PiA4KVxuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MzIodGhpcywgdmFsdWUsIG9mZnNldCwgdHJ1ZSlcbiAgfVxuICByZXR1cm4gb2Zmc2V0ICsgNFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlVUludDMyQkUgPSBmdW5jdGlvbiB3cml0ZVVJbnQzMkJFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIGNoZWNrSW50KHRoaXMsIHZhbHVlLCBvZmZzZXQsIDQsIDB4ZmZmZmZmZmYsIDApXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSA+Pj4gMjQpXG4gICAgdGhpc1tvZmZzZXQgKyAxXSA9ICh2YWx1ZSA+Pj4gMTYpXG4gICAgdGhpc1tvZmZzZXQgKyAyXSA9ICh2YWx1ZSA+Pj4gOClcbiAgICB0aGlzW29mZnNldCArIDNdID0gKHZhbHVlICYgMHhmZilcbiAgfSBlbHNlIHtcbiAgICBvYmplY3RXcml0ZVVJbnQzMih0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBmYWxzZSlcbiAgfVxuICByZXR1cm4gb2Zmc2V0ICsgNFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlSW50TEUgPSBmdW5jdGlvbiB3cml0ZUludExFICh2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIHtcbiAgICB2YXIgbGltaXQgPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aCAtIDEpXG5cbiAgICBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBsaW1pdCAtIDEsIC1saW1pdClcbiAgfVxuXG4gIHZhciBpID0gMFxuICB2YXIgbXVsID0gMVxuICB2YXIgc3ViID0gMFxuICB0aGlzW29mZnNldF0gPSB2YWx1ZSAmIDB4RkZcbiAgd2hpbGUgKCsraSA8IGJ5dGVMZW5ndGggJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICBpZiAodmFsdWUgPCAwICYmIHN1YiA9PT0gMCAmJiB0aGlzW29mZnNldCArIGkgLSAxXSAhPT0gMCkge1xuICAgICAgc3ViID0gMVxuICAgIH1cbiAgICB0aGlzW29mZnNldCArIGldID0gKCh2YWx1ZSAvIG11bCkgPj4gMCkgLSBzdWIgJiAweEZGXG4gIH1cblxuICByZXR1cm4gb2Zmc2V0ICsgYnl0ZUxlbmd0aFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlSW50QkUgPSBmdW5jdGlvbiB3cml0ZUludEJFICh2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBub0Fzc2VydCkge1xuICB2YWx1ZSA9ICt2YWx1ZVxuICBvZmZzZXQgPSBvZmZzZXQgfCAwXG4gIGlmICghbm9Bc3NlcnQpIHtcbiAgICB2YXIgbGltaXQgPSBNYXRoLnBvdygyLCA4ICogYnl0ZUxlbmd0aCAtIDEpXG5cbiAgICBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBieXRlTGVuZ3RoLCBsaW1pdCAtIDEsIC1saW1pdClcbiAgfVxuXG4gIHZhciBpID0gYnl0ZUxlbmd0aCAtIDFcbiAgdmFyIG11bCA9IDFcbiAgdmFyIHN1YiA9IDBcbiAgdGhpc1tvZmZzZXQgKyBpXSA9IHZhbHVlICYgMHhGRlxuICB3aGlsZSAoLS1pID49IDAgJiYgKG11bCAqPSAweDEwMCkpIHtcbiAgICBpZiAodmFsdWUgPCAwICYmIHN1YiA9PT0gMCAmJiB0aGlzW29mZnNldCArIGkgKyAxXSAhPT0gMCkge1xuICAgICAgc3ViID0gMVxuICAgIH1cbiAgICB0aGlzW29mZnNldCArIGldID0gKCh2YWx1ZSAvIG11bCkgPj4gMCkgLSBzdWIgJiAweEZGXG4gIH1cblxuICByZXR1cm4gb2Zmc2V0ICsgYnl0ZUxlbmd0aFxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlSW50OCA9IGZ1bmN0aW9uIHdyaXRlSW50OCAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCAxLCAweDdmLCAtMHg4MClcbiAgaWYgKCFCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkgdmFsdWUgPSBNYXRoLmZsb29yKHZhbHVlKVxuICBpZiAodmFsdWUgPCAwKSB2YWx1ZSA9IDB4ZmYgKyB2YWx1ZSArIDFcbiAgdGhpc1tvZmZzZXRdID0gKHZhbHVlICYgMHhmZilcbiAgcmV0dXJuIG9mZnNldCArIDFcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludDE2TEUgPSBmdW5jdGlvbiB3cml0ZUludDE2TEUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgMiwgMHg3ZmZmLCAtMHg4MDAwKVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgJiAweGZmKVxuICAgIHRoaXNbb2Zmc2V0ICsgMV0gPSAodmFsdWUgPj4+IDgpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MTYodGhpcywgdmFsdWUsIG9mZnNldCwgdHJ1ZSlcbiAgfVxuICByZXR1cm4gb2Zmc2V0ICsgMlxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlSW50MTZCRSA9IGZ1bmN0aW9uIHdyaXRlSW50MTZCRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCAyLCAweDdmZmYsIC0weDgwMDApXG4gIGlmIChCdWZmZXIuVFlQRURfQVJSQVlfU1VQUE9SVCkge1xuICAgIHRoaXNbb2Zmc2V0XSA9ICh2YWx1ZSA+Pj4gOClcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlICYgMHhmZilcbiAgfSBlbHNlIHtcbiAgICBvYmplY3RXcml0ZVVJbnQxNih0aGlzLCB2YWx1ZSwgb2Zmc2V0LCBmYWxzZSlcbiAgfVxuICByZXR1cm4gb2Zmc2V0ICsgMlxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlSW50MzJMRSA9IGZ1bmN0aW9uIHdyaXRlSW50MzJMRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgdmFsdWUgPSArdmFsdWVcbiAgb2Zmc2V0ID0gb2Zmc2V0IHwgMFxuICBpZiAoIW5vQXNzZXJ0KSBjaGVja0ludCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCA0LCAweDdmZmZmZmZmLCAtMHg4MDAwMDAwMClcbiAgaWYgKEJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgdGhpc1tvZmZzZXRdID0gKHZhbHVlICYgMHhmZilcbiAgICB0aGlzW29mZnNldCArIDFdID0gKHZhbHVlID4+PiA4KVxuICAgIHRoaXNbb2Zmc2V0ICsgMl0gPSAodmFsdWUgPj4+IDE2KVxuICAgIHRoaXNbb2Zmc2V0ICsgM10gPSAodmFsdWUgPj4+IDI0KVxuICB9IGVsc2Uge1xuICAgIG9iamVjdFdyaXRlVUludDMyKHRoaXMsIHZhbHVlLCBvZmZzZXQsIHRydWUpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDRcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUludDMyQkUgPSBmdW5jdGlvbiB3cml0ZUludDMyQkUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHZhbHVlID0gK3ZhbHVlXG4gIG9mZnNldCA9IG9mZnNldCB8IDBcbiAgaWYgKCFub0Fzc2VydCkgY2hlY2tJbnQodGhpcywgdmFsdWUsIG9mZnNldCwgNCwgMHg3ZmZmZmZmZiwgLTB4ODAwMDAwMDApXG4gIGlmICh2YWx1ZSA8IDApIHZhbHVlID0gMHhmZmZmZmZmZiArIHZhbHVlICsgMVxuICBpZiAoQnVmZmVyLlRZUEVEX0FSUkFZX1NVUFBPUlQpIHtcbiAgICB0aGlzW29mZnNldF0gPSAodmFsdWUgPj4+IDI0KVxuICAgIHRoaXNbb2Zmc2V0ICsgMV0gPSAodmFsdWUgPj4+IDE2KVxuICAgIHRoaXNbb2Zmc2V0ICsgMl0gPSAodmFsdWUgPj4+IDgpXG4gICAgdGhpc1tvZmZzZXQgKyAzXSA9ICh2YWx1ZSAmIDB4ZmYpXG4gIH0gZWxzZSB7XG4gICAgb2JqZWN0V3JpdGVVSW50MzIodGhpcywgdmFsdWUsIG9mZnNldCwgZmFsc2UpXG4gIH1cbiAgcmV0dXJuIG9mZnNldCArIDRcbn1cblxuZnVuY3Rpb24gY2hlY2tJRUVFNzU0IChidWYsIHZhbHVlLCBvZmZzZXQsIGV4dCwgbWF4LCBtaW4pIHtcbiAgaWYgKG9mZnNldCArIGV4dCA+IGJ1Zi5sZW5ndGgpIHRocm93IG5ldyBSYW5nZUVycm9yKCdJbmRleCBvdXQgb2YgcmFuZ2UnKVxuICBpZiAob2Zmc2V0IDwgMCkgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ0luZGV4IG91dCBvZiByYW5nZScpXG59XG5cbmZ1bmN0aW9uIHdyaXRlRmxvYXQgKGJ1ZiwgdmFsdWUsIG9mZnNldCwgbGl0dGxlRW5kaWFuLCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSB7XG4gICAgY2hlY2tJRUVFNzU0KGJ1ZiwgdmFsdWUsIG9mZnNldCwgNCwgMy40MDI4MjM0NjYzODUyODg2ZSszOCwgLTMuNDAyODIzNDY2Mzg1Mjg4NmUrMzgpXG4gIH1cbiAgaWVlZTc1NC53cml0ZShidWYsIHZhbHVlLCBvZmZzZXQsIGxpdHRsZUVuZGlhbiwgMjMsIDQpXG4gIHJldHVybiBvZmZzZXQgKyA0XG59XG5cbkJ1ZmZlci5wcm90b3R5cGUud3JpdGVGbG9hdExFID0gZnVuY3Rpb24gd3JpdGVGbG9hdExFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICByZXR1cm4gd3JpdGVGbG9hdCh0aGlzLCB2YWx1ZSwgb2Zmc2V0LCB0cnVlLCBub0Fzc2VydClcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZUZsb2F0QkUgPSBmdW5jdGlvbiB3cml0ZUZsb2F0QkUgKHZhbHVlLCBvZmZzZXQsIG5vQXNzZXJ0KSB7XG4gIHJldHVybiB3cml0ZUZsb2F0KHRoaXMsIHZhbHVlLCBvZmZzZXQsIGZhbHNlLCBub0Fzc2VydClcbn1cblxuZnVuY3Rpb24gd3JpdGVEb3VibGUgKGJ1ZiwgdmFsdWUsIG9mZnNldCwgbGl0dGxlRW5kaWFuLCBub0Fzc2VydCkge1xuICBpZiAoIW5vQXNzZXJ0KSB7XG4gICAgY2hlY2tJRUVFNzU0KGJ1ZiwgdmFsdWUsIG9mZnNldCwgOCwgMS43OTc2OTMxMzQ4NjIzMTU3RSszMDgsIC0xLjc5NzY5MzEzNDg2MjMxNTdFKzMwOClcbiAgfVxuICBpZWVlNzU0LndyaXRlKGJ1ZiwgdmFsdWUsIG9mZnNldCwgbGl0dGxlRW5kaWFuLCA1MiwgOClcbiAgcmV0dXJuIG9mZnNldCArIDhcbn1cblxuQnVmZmVyLnByb3RvdHlwZS53cml0ZURvdWJsZUxFID0gZnVuY3Rpb24gd3JpdGVEb3VibGVMRSAodmFsdWUsIG9mZnNldCwgbm9Bc3NlcnQpIHtcbiAgcmV0dXJuIHdyaXRlRG91YmxlKHRoaXMsIHZhbHVlLCBvZmZzZXQsIHRydWUsIG5vQXNzZXJ0KVxufVxuXG5CdWZmZXIucHJvdG90eXBlLndyaXRlRG91YmxlQkUgPSBmdW5jdGlvbiB3cml0ZURvdWJsZUJFICh2YWx1ZSwgb2Zmc2V0LCBub0Fzc2VydCkge1xuICByZXR1cm4gd3JpdGVEb3VibGUodGhpcywgdmFsdWUsIG9mZnNldCwgZmFsc2UsIG5vQXNzZXJ0KVxufVxuXG4vLyBjb3B5KHRhcmdldEJ1ZmZlciwgdGFyZ2V0U3RhcnQ9MCwgc291cmNlU3RhcnQ9MCwgc291cmNlRW5kPWJ1ZmZlci5sZW5ndGgpXG5CdWZmZXIucHJvdG90eXBlLmNvcHkgPSBmdW5jdGlvbiBjb3B5ICh0YXJnZXQsIHRhcmdldFN0YXJ0LCBzdGFydCwgZW5kKSB7XG4gIGlmICghc3RhcnQpIHN0YXJ0ID0gMFxuICBpZiAoIWVuZCAmJiBlbmQgIT09IDApIGVuZCA9IHRoaXMubGVuZ3RoXG4gIGlmICh0YXJnZXRTdGFydCA+PSB0YXJnZXQubGVuZ3RoKSB0YXJnZXRTdGFydCA9IHRhcmdldC5sZW5ndGhcbiAgaWYgKCF0YXJnZXRTdGFydCkgdGFyZ2V0U3RhcnQgPSAwXG4gIGlmIChlbmQgPiAwICYmIGVuZCA8IHN0YXJ0KSBlbmQgPSBzdGFydFxuXG4gIC8vIENvcHkgMCBieXRlczsgd2UncmUgZG9uZVxuICBpZiAoZW5kID09PSBzdGFydCkgcmV0dXJuIDBcbiAgaWYgKHRhcmdldC5sZW5ndGggPT09IDAgfHwgdGhpcy5sZW5ndGggPT09IDApIHJldHVybiAwXG5cbiAgLy8gRmF0YWwgZXJyb3IgY29uZGl0aW9uc1xuICBpZiAodGFyZ2V0U3RhcnQgPCAwKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ3RhcmdldFN0YXJ0IG91dCBvZiBib3VuZHMnKVxuICB9XG4gIGlmIChzdGFydCA8IDAgfHwgc3RhcnQgPj0gdGhpcy5sZW5ndGgpIHRocm93IG5ldyBSYW5nZUVycm9yKCdzb3VyY2VTdGFydCBvdXQgb2YgYm91bmRzJylcbiAgaWYgKGVuZCA8IDApIHRocm93IG5ldyBSYW5nZUVycm9yKCdzb3VyY2VFbmQgb3V0IG9mIGJvdW5kcycpXG5cbiAgLy8gQXJlIHdlIG9vYj9cbiAgaWYgKGVuZCA+IHRoaXMubGVuZ3RoKSBlbmQgPSB0aGlzLmxlbmd0aFxuICBpZiAodGFyZ2V0Lmxlbmd0aCAtIHRhcmdldFN0YXJ0IDwgZW5kIC0gc3RhcnQpIHtcbiAgICBlbmQgPSB0YXJnZXQubGVuZ3RoIC0gdGFyZ2V0U3RhcnQgKyBzdGFydFxuICB9XG5cbiAgdmFyIGxlbiA9IGVuZCAtIHN0YXJ0XG4gIHZhciBpXG5cbiAgaWYgKHRoaXMgPT09IHRhcmdldCAmJiBzdGFydCA8IHRhcmdldFN0YXJ0ICYmIHRhcmdldFN0YXJ0IDwgZW5kKSB7XG4gICAgLy8gZGVzY2VuZGluZyBjb3B5IGZyb20gZW5kXG4gICAgZm9yIChpID0gbGVuIC0gMTsgaSA+PSAwOyBpLS0pIHtcbiAgICAgIHRhcmdldFtpICsgdGFyZ2V0U3RhcnRdID0gdGhpc1tpICsgc3RhcnRdXG4gICAgfVxuICB9IGVsc2UgaWYgKGxlbiA8IDEwMDAgfHwgIUJ1ZmZlci5UWVBFRF9BUlJBWV9TVVBQT1JUKSB7XG4gICAgLy8gYXNjZW5kaW5nIGNvcHkgZnJvbSBzdGFydFxuICAgIGZvciAoaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgICAgdGFyZ2V0W2kgKyB0YXJnZXRTdGFydF0gPSB0aGlzW2kgKyBzdGFydF1cbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgVWludDhBcnJheS5wcm90b3R5cGUuc2V0LmNhbGwoXG4gICAgICB0YXJnZXQsXG4gICAgICB0aGlzLnN1YmFycmF5KHN0YXJ0LCBzdGFydCArIGxlbiksXG4gICAgICB0YXJnZXRTdGFydFxuICAgIClcbiAgfVxuXG4gIHJldHVybiBsZW5cbn1cblxuLy8gVXNhZ2U6XG4vLyAgICBidWZmZXIuZmlsbChudW1iZXJbLCBvZmZzZXRbLCBlbmRdXSlcbi8vICAgIGJ1ZmZlci5maWxsKGJ1ZmZlclssIG9mZnNldFssIGVuZF1dKVxuLy8gICAgYnVmZmVyLmZpbGwoc3RyaW5nWywgb2Zmc2V0WywgZW5kXV1bLCBlbmNvZGluZ10pXG5CdWZmZXIucHJvdG90eXBlLmZpbGwgPSBmdW5jdGlvbiBmaWxsICh2YWwsIHN0YXJ0LCBlbmQsIGVuY29kaW5nKSB7XG4gIC8vIEhhbmRsZSBzdHJpbmcgY2FzZXM6XG4gIGlmICh0eXBlb2YgdmFsID09PSAnc3RyaW5nJykge1xuICAgIGlmICh0eXBlb2Ygc3RhcnQgPT09ICdzdHJpbmcnKSB7XG4gICAgICBlbmNvZGluZyA9IHN0YXJ0XG4gICAgICBzdGFydCA9IDBcbiAgICAgIGVuZCA9IHRoaXMubGVuZ3RoXG4gICAgfSBlbHNlIGlmICh0eXBlb2YgZW5kID09PSAnc3RyaW5nJykge1xuICAgICAgZW5jb2RpbmcgPSBlbmRcbiAgICAgIGVuZCA9IHRoaXMubGVuZ3RoXG4gICAgfVxuICAgIGlmICh2YWwubGVuZ3RoID09PSAxKSB7XG4gICAgICB2YXIgY29kZSA9IHZhbC5jaGFyQ29kZUF0KDApXG4gICAgICBpZiAoY29kZSA8IDI1Nikge1xuICAgICAgICB2YWwgPSBjb2RlXG4gICAgICB9XG4gICAgfVxuICAgIGlmIChlbmNvZGluZyAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBlbmNvZGluZyAhPT0gJ3N0cmluZycpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2VuY29kaW5nIG11c3QgYmUgYSBzdHJpbmcnKVxuICAgIH1cbiAgICBpZiAodHlwZW9mIGVuY29kaW5nID09PSAnc3RyaW5nJyAmJiAhQnVmZmVyLmlzRW5jb2RpbmcoZW5jb2RpbmcpKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdVbmtub3duIGVuY29kaW5nOiAnICsgZW5jb2RpbmcpXG4gICAgfVxuICB9IGVsc2UgaWYgKHR5cGVvZiB2YWwgPT09ICdudW1iZXInKSB7XG4gICAgdmFsID0gdmFsICYgMjU1XG4gIH1cblxuICAvLyBJbnZhbGlkIHJhbmdlcyBhcmUgbm90IHNldCB0byBhIGRlZmF1bHQsIHNvIGNhbiByYW5nZSBjaGVjayBlYXJseS5cbiAgaWYgKHN0YXJ0IDwgMCB8fCB0aGlzLmxlbmd0aCA8IHN0YXJ0IHx8IHRoaXMubGVuZ3RoIDwgZW5kKSB7XG4gICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoJ091dCBvZiByYW5nZSBpbmRleCcpXG4gIH1cblxuICBpZiAoZW5kIDw9IHN0YXJ0KSB7XG4gICAgcmV0dXJuIHRoaXNcbiAgfVxuXG4gIHN0YXJ0ID0gc3RhcnQgPj4+IDBcbiAgZW5kID0gZW5kID09PSB1bmRlZmluZWQgPyB0aGlzLmxlbmd0aCA6IGVuZCA+Pj4gMFxuXG4gIGlmICghdmFsKSB2YWwgPSAwXG5cbiAgdmFyIGlcbiAgaWYgKHR5cGVvZiB2YWwgPT09ICdudW1iZXInKSB7XG4gICAgZm9yIChpID0gc3RhcnQ7IGkgPCBlbmQ7IGkrKykge1xuICAgICAgdGhpc1tpXSA9IHZhbFxuICAgIH1cbiAgfSBlbHNlIHtcbiAgICB2YXIgYnl0ZXMgPSBCdWZmZXIuaXNCdWZmZXIodmFsKVxuICAgICAgPyB2YWxcbiAgICAgIDogdXRmOFRvQnl0ZXMobmV3IEJ1ZmZlcih2YWwsIGVuY29kaW5nKS50b1N0cmluZygpKVxuICAgIHZhciBsZW4gPSBieXRlcy5sZW5ndGhcbiAgICBmb3IgKGkgPSAwOyBpIDwgZW5kIC0gc3RhcnQ7IGkrKykge1xuICAgICAgdGhpc1tpICsgc3RhcnRdID0gYnl0ZXNbaSAlIGxlbl1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gdGhpc1xufVxuXG4vLyBIRUxQRVIgRlVOQ1RJT05TXG4vLyA9PT09PT09PT09PT09PT09XG5cbnZhciBJTlZBTElEX0JBU0U2NF9SRSA9IC9bXitcXC8wLTlBLVphLXotX10vZ1xuXG5mdW5jdGlvbiBiYXNlNjRjbGVhbiAoc3RyKSB7XG4gIC8vIE5vZGUgc3RyaXBzIG91dCBpbnZhbGlkIGNoYXJhY3RlcnMgbGlrZSBcXG4gYW5kIFxcdCBmcm9tIHRoZSBzdHJpbmcsIGJhc2U2NC1qcyBkb2VzIG5vdFxuICBzdHIgPSBzdHJpbmd0cmltKHN0cikucmVwbGFjZShJTlZBTElEX0JBU0U2NF9SRSwgJycpXG4gIC8vIE5vZGUgY29udmVydHMgc3RyaW5ncyB3aXRoIGxlbmd0aCA8IDIgdG8gJydcbiAgaWYgKHN0ci5sZW5ndGggPCAyKSByZXR1cm4gJydcbiAgLy8gTm9kZSBhbGxvd3MgZm9yIG5vbi1wYWRkZWQgYmFzZTY0IHN0cmluZ3MgKG1pc3NpbmcgdHJhaWxpbmcgPT09KSwgYmFzZTY0LWpzIGRvZXMgbm90XG4gIHdoaWxlIChzdHIubGVuZ3RoICUgNCAhPT0gMCkge1xuICAgIHN0ciA9IHN0ciArICc9J1xuICB9XG4gIHJldHVybiBzdHJcbn1cblxuZnVuY3Rpb24gc3RyaW5ndHJpbSAoc3RyKSB7XG4gIGlmIChzdHIudHJpbSkgcmV0dXJuIHN0ci50cmltKClcbiAgcmV0dXJuIHN0ci5yZXBsYWNlKC9eXFxzK3xcXHMrJC9nLCAnJylcbn1cblxuZnVuY3Rpb24gdG9IZXggKG4pIHtcbiAgaWYgKG4gPCAxNikgcmV0dXJuICcwJyArIG4udG9TdHJpbmcoMTYpXG4gIHJldHVybiBuLnRvU3RyaW5nKDE2KVxufVxuXG5mdW5jdGlvbiB1dGY4VG9CeXRlcyAoc3RyaW5nLCB1bml0cykge1xuICB1bml0cyA9IHVuaXRzIHx8IEluZmluaXR5XG4gIHZhciBjb2RlUG9pbnRcbiAgdmFyIGxlbmd0aCA9IHN0cmluZy5sZW5ndGhcbiAgdmFyIGxlYWRTdXJyb2dhdGUgPSBudWxsXG4gIHZhciBieXRlcyA9IFtdXG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW5ndGg7IGkrKykge1xuICAgIGNvZGVQb2ludCA9IHN0cmluZy5jaGFyQ29kZUF0KGkpXG5cbiAgICAvLyBpcyBzdXJyb2dhdGUgY29tcG9uZW50XG4gICAgaWYgKGNvZGVQb2ludCA+IDB4RDdGRiAmJiBjb2RlUG9pbnQgPCAweEUwMDApIHtcbiAgICAgIC8vIGxhc3QgY2hhciB3YXMgYSBsZWFkXG4gICAgICBpZiAoIWxlYWRTdXJyb2dhdGUpIHtcbiAgICAgICAgLy8gbm8gbGVhZCB5ZXRcbiAgICAgICAgaWYgKGNvZGVQb2ludCA+IDB4REJGRikge1xuICAgICAgICAgIC8vIHVuZXhwZWN0ZWQgdHJhaWxcbiAgICAgICAgICBpZiAoKHVuaXRzIC09IDMpID4gLTEpIGJ5dGVzLnB1c2goMHhFRiwgMHhCRiwgMHhCRClcbiAgICAgICAgICBjb250aW51ZVxuICAgICAgICB9IGVsc2UgaWYgKGkgKyAxID09PSBsZW5ndGgpIHtcbiAgICAgICAgICAvLyB1bnBhaXJlZCBsZWFkXG4gICAgICAgICAgaWYgKCh1bml0cyAtPSAzKSA+IC0xKSBieXRlcy5wdXNoKDB4RUYsIDB4QkYsIDB4QkQpXG4gICAgICAgICAgY29udGludWVcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIHZhbGlkIGxlYWRcbiAgICAgICAgbGVhZFN1cnJvZ2F0ZSA9IGNvZGVQb2ludFxuXG4gICAgICAgIGNvbnRpbnVlXG4gICAgICB9XG5cbiAgICAgIC8vIDIgbGVhZHMgaW4gYSByb3dcbiAgICAgIGlmIChjb2RlUG9pbnQgPCAweERDMDApIHtcbiAgICAgICAgaWYgKCh1bml0cyAtPSAzKSA+IC0xKSBieXRlcy5wdXNoKDB4RUYsIDB4QkYsIDB4QkQpXG4gICAgICAgIGxlYWRTdXJyb2dhdGUgPSBjb2RlUG9pbnRcbiAgICAgICAgY29udGludWVcbiAgICAgIH1cblxuICAgICAgLy8gdmFsaWQgc3Vycm9nYXRlIHBhaXJcbiAgICAgIGNvZGVQb2ludCA9IChsZWFkU3Vycm9nYXRlIC0gMHhEODAwIDw8IDEwIHwgY29kZVBvaW50IC0gMHhEQzAwKSArIDB4MTAwMDBcbiAgICB9IGVsc2UgaWYgKGxlYWRTdXJyb2dhdGUpIHtcbiAgICAgIC8vIHZhbGlkIGJtcCBjaGFyLCBidXQgbGFzdCBjaGFyIHdhcyBhIGxlYWRcbiAgICAgIGlmICgodW5pdHMgLT0gMykgPiAtMSkgYnl0ZXMucHVzaCgweEVGLCAweEJGLCAweEJEKVxuICAgIH1cblxuICAgIGxlYWRTdXJyb2dhdGUgPSBudWxsXG5cbiAgICAvLyBlbmNvZGUgdXRmOFxuICAgIGlmIChjb2RlUG9pbnQgPCAweDgwKSB7XG4gICAgICBpZiAoKHVuaXRzIC09IDEpIDwgMCkgYnJlYWtcbiAgICAgIGJ5dGVzLnB1c2goY29kZVBvaW50KVxuICAgIH0gZWxzZSBpZiAoY29kZVBvaW50IDwgMHg4MDApIHtcbiAgICAgIGlmICgodW5pdHMgLT0gMikgPCAwKSBicmVha1xuICAgICAgYnl0ZXMucHVzaChcbiAgICAgICAgY29kZVBvaW50ID4+IDB4NiB8IDB4QzAsXG4gICAgICAgIGNvZGVQb2ludCAmIDB4M0YgfCAweDgwXG4gICAgICApXG4gICAgfSBlbHNlIGlmIChjb2RlUG9pbnQgPCAweDEwMDAwKSB7XG4gICAgICBpZiAoKHVuaXRzIC09IDMpIDwgMCkgYnJlYWtcbiAgICAgIGJ5dGVzLnB1c2goXG4gICAgICAgIGNvZGVQb2ludCA+PiAweEMgfCAweEUwLFxuICAgICAgICBjb2RlUG9pbnQgPj4gMHg2ICYgMHgzRiB8IDB4ODAsXG4gICAgICAgIGNvZGVQb2ludCAmIDB4M0YgfCAweDgwXG4gICAgICApXG4gICAgfSBlbHNlIGlmIChjb2RlUG9pbnQgPCAweDExMDAwMCkge1xuICAgICAgaWYgKCh1bml0cyAtPSA0KSA8IDApIGJyZWFrXG4gICAgICBieXRlcy5wdXNoKFxuICAgICAgICBjb2RlUG9pbnQgPj4gMHgxMiB8IDB4RjAsXG4gICAgICAgIGNvZGVQb2ludCA+PiAweEMgJiAweDNGIHwgMHg4MCxcbiAgICAgICAgY29kZVBvaW50ID4+IDB4NiAmIDB4M0YgfCAweDgwLFxuICAgICAgICBjb2RlUG9pbnQgJiAweDNGIHwgMHg4MFxuICAgICAgKVxuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgY29kZSBwb2ludCcpXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGJ5dGVzXG59XG5cbmZ1bmN0aW9uIGFzY2lpVG9CeXRlcyAoc3RyKSB7XG4gIHZhciBieXRlQXJyYXkgPSBbXVxuICBmb3IgKHZhciBpID0gMDsgaSA8IHN0ci5sZW5ndGg7IGkrKykge1xuICAgIC8vIE5vZGUncyBjb2RlIHNlZW1zIHRvIGJlIGRvaW5nIHRoaXMgYW5kIG5vdCAmIDB4N0YuLlxuICAgIGJ5dGVBcnJheS5wdXNoKHN0ci5jaGFyQ29kZUF0KGkpICYgMHhGRilcbiAgfVxuICByZXR1cm4gYnl0ZUFycmF5XG59XG5cbmZ1bmN0aW9uIHV0ZjE2bGVUb0J5dGVzIChzdHIsIHVuaXRzKSB7XG4gIHZhciBjLCBoaSwgbG9cbiAgdmFyIGJ5dGVBcnJheSA9IFtdXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgc3RyLmxlbmd0aDsgaSsrKSB7XG4gICAgaWYgKCh1bml0cyAtPSAyKSA8IDApIGJyZWFrXG5cbiAgICBjID0gc3RyLmNoYXJDb2RlQXQoaSlcbiAgICBoaSA9IGMgPj4gOFxuICAgIGxvID0gYyAlIDI1NlxuICAgIGJ5dGVBcnJheS5wdXNoKGxvKVxuICAgIGJ5dGVBcnJheS5wdXNoKGhpKVxuICB9XG5cbiAgcmV0dXJuIGJ5dGVBcnJheVxufVxuXG5mdW5jdGlvbiBiYXNlNjRUb0J5dGVzIChzdHIpIHtcbiAgcmV0dXJuIGJhc2U2NC50b0J5dGVBcnJheShiYXNlNjRjbGVhbihzdHIpKVxufVxuXG5mdW5jdGlvbiBibGl0QnVmZmVyIChzcmMsIGRzdCwgb2Zmc2V0LCBsZW5ndGgpIHtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW5ndGg7IGkrKykge1xuICAgIGlmICgoaSArIG9mZnNldCA+PSBkc3QubGVuZ3RoKSB8fCAoaSA+PSBzcmMubGVuZ3RoKSkgYnJlYWtcbiAgICBkc3RbaSArIG9mZnNldF0gPSBzcmNbaV1cbiAgfVxuICByZXR1cm4gaVxufVxuXG5mdW5jdGlvbiBpc25hbiAodmFsKSB7XG4gIHJldHVybiB2YWwgIT09IHZhbCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG5vLXNlbGYtY29tcGFyZVxufVxuIiwiJ3VzZSBzdHJpY3QnO1xudmFyIGFzc2VydCA9IHJlcXVpcmUoJ21pbmltYWxpc3RpYy1hc3NlcnQnKTtcblxuZXhwb3J0cy5mcm9tRGVyID0gZnJvbURlcjtcbmV4cG9ydHMudG9EZXIgPSB0b0RFUjtcblxuZnVuY3Rpb24gdG9ERVIgKGlucHV0KSB7XG4gIGlmIChpbnB1dC5sZW5ndGggJSAyKSB7XG4gICAgaW5wdXQgPSBCdWZmZXIuY29uY2F0KFtuZXcgQnVmZmVyKFswXSksIGlucHV0XSk7XG4gIH1cbiAgdmFyIHNsaWNlTGVuID0gTWF0aC5mbG9vcihpbnB1dC5sZW5ndGggLyAyKTtcbiAgdmFyIHIgPSBpbnB1dC5zbGljZSgwLCBzbGljZUxlbik7XG4gIHZhciBzID0gaW5wdXQuc2xpY2Uoc2xpY2VMZW4pO1xuXG4gIC8vIFBhZCB2YWx1ZXNcblxuICBpZiAoclswXSAmIDB4ODApIHtcbiAgICByID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihbMF0pLCByXSk7XG4gIH1cbiAgLy8gUGFkIHZhbHVlc1xuICBpZiAoc1swXSAmIDB4ODApIHtcbiAgICBzID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihbMF0pLCBzXSk7XG4gIH1cbiAgaWYgKCFyWzBdICYmICEoclsxXSAmIDB4ODApKSB7XG4gICAgciA9IHIuc2xpY2UoMSk7XG4gIH1cbiAgaWYgKCFzWzBdICYmICEoc1sxXSAmIDB4ODApKSB7XG4gICAgcyA9IHMuc2xpY2UoMSk7XG4gIH1cbiAgdmFyIHJhcnIgPSBbMHgwMl07XG4gIGNvbnN0cnVjdExlbmd0aChyYXJyLCByLmxlbmd0aCk7XG4gIHZhciBzYXJyID0gWzB4MDJdO1xuICBjb25zdHJ1Y3RMZW5ndGgoc2Fyciwgcy5sZW5ndGgpO1xuICB2YXIgYmFja0hhbGYgPSBCdWZmZXIuY29uY2F0KFtuZXcgQnVmZmVyKHJhcnIpLCByLCBuZXcgQnVmZmVyKHNhcnIpLCBzXSk7XG4gIHZhciBoZWFkID0gWzB4MzBdO1xuICBjb25zdHJ1Y3RMZW5ndGgoaGVhZCwgYmFja0hhbGYubGVuZ3RoKTtcbiAgcmV0dXJuIEJ1ZmZlci5jb25jYXQoW25ldyBCdWZmZXIoaGVhZCksIGJhY2tIYWxmXSk7XG59XG5mdW5jdGlvbiBjb25zdHJ1Y3RMZW5ndGgoYXJyLCBsZW4pIHtcbiAgaWYgKGxlbiA8IDB4ODApIHtcbiAgICBhcnIucHVzaChsZW4pO1xuICAgIHJldHVybjtcbiAgfVxuICB2YXIgb2N0ZXRzID0gMSArIChNYXRoLmxvZzIobGVuKSA+PiAzKTtcbiAgYXJyLnB1c2gob2N0ZXRzIF4gMHg4MCk7XG4gIHdoaWxlICh0cnVlKSB7XG4gICAgaWYgKG9jdGV0cyA9PT0gMSkge1xuICAgICAgYXJyLnB1c2gobGVuICYgMHhmZik7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIG9jdGV0cy0tO1xuICAgIGFyci5wdXNoKGxlbiA+PiAob2N0ZXRzIDw8IDMpKTtcbiAgfVxufVxudmFyIGxlbnMgPSB7XG4gICdwLTI1Nic6IDMyLFxuICAncDI1Nic6IDMyLFxuICAncC0zODQnOiA0OCxcbiAgJ3AzODQnOiA0OCxcbiAgJ3AtNTIxJzogNjYsXG4gICdwNTIxJzogNjZcbn07XG5mdW5jdGlvbiBmcm9tRGVyKGlucHV0LCBjdXJ2ZSkge1xuICBhc3NlcnQodHlwZW9mIGN1cnZlID09PSAnc3RyaW5nJyk7XG4gIHZhciBsZW4gPSBsZW5zW2N1cnZlLnRvTG93ZXJDYXNlKCldO1xuICB2YXIgcCA9IHt9O1xuICBwLnBsYWNlID0gMDtcbiAgYXNzZXJ0LmVxdWFsKGlucHV0W3AucGxhY2UrK10sIDB4MzApO1xuICBnZXRMZW5ndGgoaW5wdXQsIHApO1xuICBhc3NlcnQuZXF1YWwoaW5wdXRbcC5wbGFjZSsrXSwgMHgwMik7XG4gIHZhciBybGVuID0gZ2V0TGVuZ3RoKGlucHV0LCBwKTtcbiAgdmFyIHIgPSBpbnB1dC5zbGljZShwLnBsYWNlLCBybGVuICsgcC5wbGFjZSk7XG4gIHAucGxhY2UgKz0gcmxlbjtcbiAgYXNzZXJ0LmVxdWFsKGlucHV0W3AucGxhY2UrK10sIDB4MDIpO1xuICB2YXIgc2xlbiA9IGdldExlbmd0aChpbnB1dCwgcCk7XG4gIGFzc2VydC5lcXVhbChpbnB1dC5sZW5ndGgsIHNsZW4gKyBwLnBsYWNlKTtcbiAgdmFyIHMgPSBpbnB1dC5zbGljZShwLnBsYWNlLCBzbGVuICsgcC5wbGFjZSk7XG4gIGlmICghclswXSAmJiAoclsxXSAmIDB4ODApKSB7XG4gICAgciA9IHIuc2xpY2UoMSk7XG4gIH1cbiAgaWYgKCFzWzBdICYmIChzWzFdICYgMHg4MCkpIHtcbiAgICBzID0gcy5zbGljZSgxKTtcbiAgfVxuICB3aGlsZSAoci5sZW5ndGggPCBsZW4pIHtcbiAgICByID0gQnVmZmVyLmNvbmNhdChbbmV3IEJ1ZmZlcihbMF0pLCByXSk7XG4gIH1cbiAgd2hpbGUgKHMubGVuZ3RoIDwgbGVuKSB7XG4gICAgcyA9IEJ1ZmZlci5jb25jYXQoW25ldyBCdWZmZXIoWzBdKSwgc10pO1xuICB9XG4gIHJldHVybiBCdWZmZXIuY29uY2F0KFtyLCBzXSk7XG59XG5mdW5jdGlvbiBnZXRMZW5ndGgoYnVmLCBwKSB7XG4gIHZhciBpbml0aWFsID0gYnVmW3AucGxhY2UrK107XG4gIGlmICghKGluaXRpYWwgJiAweDgwKSkge1xuICAgIHJldHVybiBpbml0aWFsO1xuICB9XG4gIHZhciBvY3RldExlbiA9IGluaXRpYWwgJiAweGY7XG4gIHZhciBkYXRhID0gYnVmLnJlYWRVSW50QkUocC5wbGFjZSwgb2N0ZXRMZW4pO1xuICBwLnBsYWNlICs9IG9jdGV0TGVuO1xuICByZXR1cm4gZGF0YTtcbn1cbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGVsbGlwdGljID0gZXhwb3J0cztcblxuZWxsaXB0aWMudmVyc2lvbiA9IHJlcXVpcmUoJy4uL3BhY2thZ2UuanNvbicpLnZlcnNpb247XG5lbGxpcHRpYy51dGlscyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvdXRpbHMnKTtcbmVsbGlwdGljLnJhbmQgPSByZXF1aXJlKCdicm9yYW5kJyk7XG5lbGxpcHRpYy5obWFjRFJCRyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvaG1hYy1kcmJnJyk7XG5lbGxpcHRpYy5jdXJ2ZSA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvY3VydmUnKTtcbmVsbGlwdGljLmN1cnZlcyA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvY3VydmVzJyk7XG5cbi8vIFByb3RvY29sc1xuZWxsaXB0aWMuZWMgPSByZXF1aXJlKCcuL2VsbGlwdGljL2VjJyk7XG5lbGxpcHRpYy5lZGRzYSA9IHJlcXVpcmUoJy4vZWxsaXB0aWMvZWRkc2EnKTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBnZXROQUYgPSB1dGlscy5nZXROQUY7XG52YXIgZ2V0SlNGID0gdXRpbHMuZ2V0SlNGO1xudmFyIGFzc2VydCA9IHV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gQmFzZUN1cnZlKHR5cGUsIGNvbmYpIHtcbiAgdGhpcy50eXBlID0gdHlwZTtcbiAgdGhpcy5wID0gbmV3IEJOKGNvbmYucCwgMTYpO1xuXG4gIC8vIFVzZSBNb250Z29tZXJ5LCB3aGVuIHRoZXJlIGlzIG5vIGZhc3QgcmVkdWN0aW9uIGZvciB0aGUgcHJpbWVcbiAgdGhpcy5yZWQgPSBjb25mLnByaW1lID8gQk4ucmVkKGNvbmYucHJpbWUpIDogQk4ubW9udCh0aGlzLnApO1xuXG4gIC8vIFVzZWZ1bCBmb3IgbWFueSBjdXJ2ZXNcbiAgdGhpcy56ZXJvID0gbmV3IEJOKDApLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5vbmUgPSBuZXcgQk4oMSkudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLnR3byA9IG5ldyBCTigyKS50b1JlZCh0aGlzLnJlZCk7XG5cbiAgLy8gQ3VydmUgY29uZmlndXJhdGlvbiwgb3B0aW9uYWxcbiAgdGhpcy5uID0gY29uZi5uICYmIG5ldyBCTihjb25mLm4sIDE2KTtcbiAgdGhpcy5nID0gY29uZi5nICYmIHRoaXMucG9pbnRGcm9tSlNPTihjb25mLmcsIGNvbmYuZ1JlZCk7XG5cbiAgLy8gVGVtcG9yYXJ5IGFycmF5c1xuICB0aGlzLl93bmFmVDEgPSBuZXcgQXJyYXkoNCk7XG4gIHRoaXMuX3duYWZUMiA9IG5ldyBBcnJheSg0KTtcbiAgdGhpcy5fd25hZlQzID0gbmV3IEFycmF5KDQpO1xuICB0aGlzLl93bmFmVDQgPSBuZXcgQXJyYXkoNCk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEJhc2VDdXJ2ZTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5wb2ludCA9IGZ1bmN0aW9uIHBvaW50KCkge1xuICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCcpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKCkge1xuICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCcpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5fZml4ZWROYWZNdWwgPSBmdW5jdGlvbiBfZml4ZWROYWZNdWwocCwgaykge1xuICBhc3NlcnQocC5wcmVjb21wdXRlZCk7XG4gIHZhciBkb3VibGVzID0gcC5fZ2V0RG91YmxlcygpO1xuXG4gIHZhciBuYWYgPSBnZXROQUYoaywgMSk7XG4gIHZhciBJID0gKDEgPDwgKGRvdWJsZXMuc3RlcCArIDEpKSAtIChkb3VibGVzLnN0ZXAgJSAyID09PSAwID8gMiA6IDEpO1xuICBJIC89IDM7XG5cbiAgLy8gVHJhbnNsYXRlIGludG8gbW9yZSB3aW5kb3dlZCBmb3JtXG4gIHZhciByZXByID0gW107XG4gIGZvciAodmFyIGogPSAwOyBqIDwgbmFmLmxlbmd0aDsgaiArPSBkb3VibGVzLnN0ZXApIHtcbiAgICB2YXIgbmFmVyA9IDA7XG4gICAgZm9yICh2YXIgayA9IGogKyBkb3VibGVzLnN0ZXAgLSAxOyBrID49IGo7IGstLSlcbiAgICAgIG5hZlcgPSAobmFmVyA8PCAxKSArIG5hZltrXTtcbiAgICByZXByLnB1c2gobmFmVyk7XG4gIH1cblxuICB2YXIgYSA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICB2YXIgYiA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICBmb3IgKHZhciBpID0gSTsgaSA+IDA7IGktLSkge1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgcmVwci5sZW5ndGg7IGorKykge1xuICAgICAgdmFyIG5hZlcgPSByZXByW2pdO1xuICAgICAgaWYgKG5hZlcgPT09IGkpXG4gICAgICAgIGIgPSBiLm1peGVkQWRkKGRvdWJsZXMucG9pbnRzW2pdKTtcbiAgICAgIGVsc2UgaWYgKG5hZlcgPT09IC1pKVxuICAgICAgICBiID0gYi5taXhlZEFkZChkb3VibGVzLnBvaW50c1tqXS5uZWcoKSk7XG4gICAgfVxuICAgIGEgPSBhLmFkZChiKTtcbiAgfVxuICByZXR1cm4gYS50b1AoKTtcbn07XG5cbkJhc2VDdXJ2ZS5wcm90b3R5cGUuX3duYWZNdWwgPSBmdW5jdGlvbiBfd25hZk11bChwLCBrKSB7XG4gIHZhciB3ID0gNDtcblxuICAvLyBQcmVjb21wdXRlIHdpbmRvd1xuICB2YXIgbmFmUG9pbnRzID0gcC5fZ2V0TkFGUG9pbnRzKHcpO1xuICB3ID0gbmFmUG9pbnRzLnduZDtcbiAgdmFyIHduZCA9IG5hZlBvaW50cy5wb2ludHM7XG5cbiAgLy8gR2V0IE5BRiBmb3JtXG4gIHZhciBuYWYgPSBnZXROQUYoaywgdyk7XG5cbiAgLy8gQWRkIGB0aGlzYCooTisxKSBmb3IgZXZlcnkgdy1OQUYgaW5kZXhcbiAgdmFyIGFjYyA9IHRoaXMuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuICBmb3IgKHZhciBpID0gbmFmLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgLy8gQ291bnQgemVyb2VzXG4gICAgZm9yICh2YXIgayA9IDA7IGkgPj0gMCAmJiBuYWZbaV0gPT09IDA7IGktLSlcbiAgICAgIGsrKztcbiAgICBpZiAoaSA+PSAwKVxuICAgICAgaysrO1xuICAgIGFjYyA9IGFjYy5kYmxwKGspO1xuXG4gICAgaWYgKGkgPCAwKVxuICAgICAgYnJlYWs7XG4gICAgdmFyIHogPSBuYWZbaV07XG4gICAgYXNzZXJ0KHogIT09IDApO1xuICAgIGlmIChwLnR5cGUgPT09ICdhZmZpbmUnKSB7XG4gICAgICAvLyBKICstIFBcbiAgICAgIGlmICh6ID4gMClcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHduZFsoeiAtIDEpID4+IDFdKTtcbiAgICAgIGVsc2VcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHduZFsoLXogLSAxKSA+PiAxXS5uZWcoKSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEogKy0gSlxuICAgICAgaWYgKHogPiAwKVxuICAgICAgICBhY2MgPSBhY2MuYWRkKHduZFsoeiAtIDEpID4+IDFdKTtcbiAgICAgIGVsc2VcbiAgICAgICAgYWNjID0gYWNjLmFkZCh3bmRbKC16IC0gMSkgPj4gMV0ubmVnKCkpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcC50eXBlID09PSAnYWZmaW5lJyA/IGFjYy50b1AoKSA6IGFjYztcbn07XG5cbkJhc2VDdXJ2ZS5wcm90b3R5cGUuX3duYWZNdWxBZGQgPSBmdW5jdGlvbiBfd25hZk11bEFkZChkZWZXLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvaW50cyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2VmZnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGVuKSB7XG4gIHZhciB3bmRXaWR0aCA9IHRoaXMuX3duYWZUMTtcbiAgdmFyIHduZCA9IHRoaXMuX3duYWZUMjtcbiAgdmFyIG5hZiA9IHRoaXMuX3duYWZUMztcblxuICAvLyBGaWxsIGFsbCBhcnJheXNcbiAgdmFyIG1heCA9IDA7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICB2YXIgcCA9IHBvaW50c1tpXTtcbiAgICB2YXIgbmFmUG9pbnRzID0gcC5fZ2V0TkFGUG9pbnRzKGRlZlcpO1xuICAgIHduZFdpZHRoW2ldID0gbmFmUG9pbnRzLnduZDtcbiAgICB3bmRbaV0gPSBuYWZQb2ludHMucG9pbnRzO1xuICB9XG5cbiAgLy8gQ29tYiBzbWFsbCB3aW5kb3cgTkFGc1xuICBmb3IgKHZhciBpID0gbGVuIC0gMTsgaSA+PSAxOyBpIC09IDIpIHtcbiAgICB2YXIgYSA9IGkgLSAxO1xuICAgIHZhciBiID0gaTtcbiAgICBpZiAod25kV2lkdGhbYV0gIT09IDEgfHwgd25kV2lkdGhbYl0gIT09IDEpIHtcbiAgICAgIG5hZlthXSA9IGdldE5BRihjb2VmZnNbYV0sIHduZFdpZHRoW2FdKTtcbiAgICAgIG5hZltiXSA9IGdldE5BRihjb2VmZnNbYl0sIHduZFdpZHRoW2JdKTtcbiAgICAgIG1heCA9IE1hdGgubWF4KG5hZlthXS5sZW5ndGgsIG1heCk7XG4gICAgICBtYXggPSBNYXRoLm1heChuYWZbYl0ubGVuZ3RoLCBtYXgpO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgdmFyIGNvbWIgPSBbXG4gICAgICBwb2ludHNbYV0sIC8qIDEgKi9cbiAgICAgIG51bGwsIC8qIDMgKi9cbiAgICAgIG51bGwsIC8qIDUgKi9cbiAgICAgIHBvaW50c1tiXSAvKiA3ICovXG4gICAgXTtcblxuICAgIC8vIFRyeSB0byBhdm9pZCBQcm9qZWN0aXZlIHBvaW50cywgaWYgcG9zc2libGVcbiAgICBpZiAocG9pbnRzW2FdLnkuY21wKHBvaW50c1tiXS55KSA9PT0gMCkge1xuICAgICAgY29tYlsxXSA9IHBvaW50c1thXS5hZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdLm5lZygpKTtcbiAgICB9IGVsc2UgaWYgKHBvaW50c1thXS55LmNtcChwb2ludHNbYl0ueS5yZWROZWcoKSkgPT09IDApIHtcbiAgICAgIGNvbWJbMV0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0uYWRkKHBvaW50c1tiXS5uZWcoKSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbWJbMV0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdKTtcbiAgICAgIGNvbWJbMl0gPSBwb2ludHNbYV0udG9KKCkubWl4ZWRBZGQocG9pbnRzW2JdLm5lZygpKTtcbiAgICB9XG5cbiAgICB2YXIgaW5kZXggPSBbXG4gICAgICAtMywgLyogLTEgLTEgKi9cbiAgICAgIC0xLCAvKiAtMSAwICovXG4gICAgICAtNSwgLyogLTEgMSAqL1xuICAgICAgLTcsIC8qIDAgLTEgKi9cbiAgICAgIDAsIC8qIDAgMCAqL1xuICAgICAgNywgLyogMCAxICovXG4gICAgICA1LCAvKiAxIC0xICovXG4gICAgICAxLCAvKiAxIDAgKi9cbiAgICAgIDMgIC8qIDEgMSAqL1xuICAgIF07XG5cbiAgICB2YXIganNmID0gZ2V0SlNGKGNvZWZmc1thXSwgY29lZmZzW2JdKTtcbiAgICBtYXggPSBNYXRoLm1heChqc2ZbMF0ubGVuZ3RoLCBtYXgpO1xuICAgIG5hZlthXSA9IG5ldyBBcnJheShtYXgpO1xuICAgIG5hZltiXSA9IG5ldyBBcnJheShtYXgpO1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgbWF4OyBqKyspIHtcbiAgICAgIHZhciBqYSA9IGpzZlswXVtqXSB8IDA7XG4gICAgICB2YXIgamIgPSBqc2ZbMV1bal0gfCAwO1xuXG4gICAgICBuYWZbYV1bal0gPSBpbmRleFsoamEgKyAxKSAqIDMgKyAoamIgKyAxKV07XG4gICAgICBuYWZbYl1bal0gPSAwO1xuICAgICAgd25kW2FdID0gY29tYjtcbiAgICB9XG4gIH1cblxuICB2YXIgYWNjID0gdGhpcy5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gIHZhciB0bXAgPSB0aGlzLl93bmFmVDQ7XG4gIGZvciAodmFyIGkgPSBtYXg7IGkgPj0gMDsgaS0tKSB7XG4gICAgdmFyIGsgPSAwO1xuXG4gICAgd2hpbGUgKGkgPj0gMCkge1xuICAgICAgdmFyIHplcm8gPSB0cnVlO1xuICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCBsZW47IGorKykge1xuICAgICAgICB0bXBbal0gPSBuYWZbal1baV0gfCAwO1xuICAgICAgICBpZiAodG1wW2pdICE9PSAwKVxuICAgICAgICAgIHplcm8gPSBmYWxzZTtcbiAgICAgIH1cbiAgICAgIGlmICghemVybylcbiAgICAgICAgYnJlYWs7XG4gICAgICBrKys7XG4gICAgICBpLS07XG4gICAgfVxuICAgIGlmIChpID49IDApXG4gICAgICBrKys7XG4gICAgYWNjID0gYWNjLmRibHAoayk7XG4gICAgaWYgKGkgPCAwKVxuICAgICAgYnJlYWs7XG5cbiAgICBmb3IgKHZhciBqID0gMDsgaiA8IGxlbjsgaisrKSB7XG4gICAgICB2YXIgeiA9IHRtcFtqXTtcbiAgICAgIHZhciBwO1xuICAgICAgaWYgKHogPT09IDApXG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgZWxzZSBpZiAoeiA+IDApXG4gICAgICAgIHAgPSB3bmRbal1bKHogLSAxKSA+PiAxXTtcbiAgICAgIGVsc2UgaWYgKHogPCAwKVxuICAgICAgICBwID0gd25kW2pdWygteiAtIDEpID4+IDFdLm5lZygpO1xuXG4gICAgICBpZiAocC50eXBlID09PSAnYWZmaW5lJylcbiAgICAgICAgYWNjID0gYWNjLm1peGVkQWRkKHApO1xuICAgICAgZWxzZVxuICAgICAgICBhY2MgPSBhY2MuYWRkKHApO1xuICAgIH1cbiAgfVxuICAvLyBaZXJvaWZ5IHJlZmVyZW5jZXNcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47IGkrKylcbiAgICB3bmRbaV0gPSBudWxsO1xuICByZXR1cm4gYWNjLnRvUCgpO1xufTtcblxuZnVuY3Rpb24gQmFzZVBvaW50KGN1cnZlLCB0eXBlKSB7XG4gIHRoaXMuY3VydmUgPSBjdXJ2ZTtcbiAgdGhpcy50eXBlID0gdHlwZTtcbiAgdGhpcy5wcmVjb21wdXRlZCA9IG51bGw7XG59XG5CYXNlQ3VydmUuQmFzZVBvaW50ID0gQmFzZVBvaW50O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLmVxID0gZnVuY3Rpb24gZXEoLypvdGhlciovKSB7XG4gIHRocm93IG5ldyBFcnJvcignTm90IGltcGxlbWVudGVkJyk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLnZhbGlkYXRlID0gZnVuY3Rpb24gdmFsaWRhdGUoKSB7XG4gIHJldHVybiB0aGlzLmN1cnZlLnZhbGlkYXRlKHRoaXMpO1xufTtcblxuQmFzZUN1cnZlLnByb3RvdHlwZS5kZWNvZGVQb2ludCA9IGZ1bmN0aW9uIGRlY29kZVBvaW50KGJ5dGVzLCBlbmMpIHtcbiAgYnl0ZXMgPSB1dGlscy50b0FycmF5KGJ5dGVzLCBlbmMpO1xuXG4gIHZhciBsZW4gPSB0aGlzLnAuYnl0ZUxlbmd0aCgpO1xuICBpZiAoYnl0ZXNbMF0gPT09IDB4MDQgJiYgYnl0ZXMubGVuZ3RoIC0gMSA9PT0gMiAqIGxlbikge1xuICAgIHJldHVybiB0aGlzLnBvaW50KGJ5dGVzLnNsaWNlKDEsIDEgKyBsZW4pLFxuICAgICAgICAgICAgICAgICAgICAgIGJ5dGVzLnNsaWNlKDEgKyBsZW4sIDEgKyAyICogbGVuKSk7XG4gIH0gZWxzZSBpZiAoKGJ5dGVzWzBdID09PSAweDAyIHx8IGJ5dGVzWzBdID09PSAweDAzKSAmJlxuICAgICAgICAgICAgICBieXRlcy5sZW5ndGggLSAxID09PSBsZW4pIHtcbiAgICByZXR1cm4gdGhpcy5wb2ludEZyb21YKGJ5dGVzLnNsaWNlKDEsIDEgKyBsZW4pLCBieXRlc1swXSA9PT0gMHgwMyk7XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKCdVbmtub3duIHBvaW50IGZvcm1hdCcpO1xufTtcblxuQmFzZVBvaW50LnByb3RvdHlwZS5lbmNvZGVDb21wcmVzc2VkID0gZnVuY3Rpb24gZW5jb2RlQ29tcHJlc3NlZChlbmMpIHtcbiAgcmV0dXJuIHRoaXMuZW5jb2RlKGVuYywgdHJ1ZSk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLl9lbmNvZGUgPSBmdW5jdGlvbiBfZW5jb2RlKGNvbXBhY3QpIHtcbiAgdmFyIGxlbiA9IHRoaXMuY3VydmUucC5ieXRlTGVuZ3RoKCk7XG4gIHZhciB4ID0gdGhpcy5nZXRYKCkudG9BcnJheSgnYmUnLCBsZW4pO1xuXG4gIGlmIChjb21wYWN0KVxuICAgIHJldHVybiBbIHRoaXMuZ2V0WSgpLmlzRXZlbigpID8gMHgwMiA6IDB4MDMgXS5jb25jYXQoeCk7XG5cbiAgcmV0dXJuIFsgMHgwNCBdLmNvbmNhdCh4LCB0aGlzLmdldFkoKS50b0FycmF5KCdiZScsIGxlbikpIDtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuZW5jb2RlID0gZnVuY3Rpb24gZW5jb2RlKGVuYywgY29tcGFjdCkge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMuX2VuY29kZShjb21wYWN0KSwgZW5jKTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUucHJlY29tcHV0ZSA9IGZ1bmN0aW9uIHByZWNvbXB1dGUocG93ZXIpIHtcbiAgaWYgKHRoaXMucHJlY29tcHV0ZWQpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgdmFyIHByZWNvbXB1dGVkID0ge1xuICAgIGRvdWJsZXM6IG51bGwsXG4gICAgbmFmOiBudWxsLFxuICAgIGJldGE6IG51bGxcbiAgfTtcbiAgcHJlY29tcHV0ZWQubmFmID0gdGhpcy5fZ2V0TkFGUG9pbnRzKDgpO1xuICBwcmVjb21wdXRlZC5kb3VibGVzID0gdGhpcy5fZ2V0RG91Ymxlcyg0LCBwb3dlcik7XG4gIHByZWNvbXB1dGVkLmJldGEgPSB0aGlzLl9nZXRCZXRhKCk7XG4gIHRoaXMucHJlY29tcHV0ZWQgPSBwcmVjb21wdXRlZDtcblxuICByZXR1cm4gdGhpcztcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2hhc0RvdWJsZXMgPSBmdW5jdGlvbiBfaGFzRG91YmxlcyhrKSB7XG4gIGlmICghdGhpcy5wcmVjb21wdXRlZClcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgdmFyIGRvdWJsZXMgPSB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXM7XG4gIGlmICghZG91YmxlcylcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIGRvdWJsZXMucG9pbnRzLmxlbmd0aCA+PSBNYXRoLmNlaWwoKGsuYml0TGVuZ3RoKCkgKyAxKSAvIGRvdWJsZXMuc3RlcCk7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLl9nZXREb3VibGVzID0gZnVuY3Rpb24gX2dldERvdWJsZXMoc3RlcCwgcG93ZXIpIHtcbiAgaWYgKHRoaXMucHJlY29tcHV0ZWQgJiYgdGhpcy5wcmVjb21wdXRlZC5kb3VibGVzKVxuICAgIHJldHVybiB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXM7XG5cbiAgdmFyIGRvdWJsZXMgPSBbIHRoaXMgXTtcbiAgdmFyIGFjYyA9IHRoaXM7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgcG93ZXI7IGkgKz0gc3RlcCkge1xuICAgIGZvciAodmFyIGogPSAwOyBqIDwgc3RlcDsgaisrKVxuICAgICAgYWNjID0gYWNjLmRibCgpO1xuICAgIGRvdWJsZXMucHVzaChhY2MpO1xuICB9XG4gIHJldHVybiB7XG4gICAgc3RlcDogc3RlcCxcbiAgICBwb2ludHM6IGRvdWJsZXNcbiAgfTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2dldE5BRlBvaW50cyA9IGZ1bmN0aW9uIF9nZXROQUZQb2ludHMod25kKSB7XG4gIGlmICh0aGlzLnByZWNvbXB1dGVkICYmIHRoaXMucHJlY29tcHV0ZWQubmFmKVxuICAgIHJldHVybiB0aGlzLnByZWNvbXB1dGVkLm5hZjtcblxuICB2YXIgcmVzID0gWyB0aGlzIF07XG4gIHZhciBtYXggPSAoMSA8PCB3bmQpIC0gMTtcbiAgdmFyIGRibCA9IG1heCA9PT0gMSA/IG51bGwgOiB0aGlzLmRibCgpO1xuICBmb3IgKHZhciBpID0gMTsgaSA8IG1heDsgaSsrKVxuICAgIHJlc1tpXSA9IHJlc1tpIC0gMV0uYWRkKGRibCk7XG4gIHJldHVybiB7XG4gICAgd25kOiB3bmQsXG4gICAgcG9pbnRzOiByZXNcbiAgfTtcbn07XG5cbkJhc2VQb2ludC5wcm90b3R5cGUuX2dldEJldGEgPSBmdW5jdGlvbiBfZ2V0QmV0YSgpIHtcbiAgcmV0dXJuIG51bGw7XG59O1xuXG5CYXNlUG9pbnQucHJvdG90eXBlLmRibHAgPSBmdW5jdGlvbiBkYmxwKGspIHtcbiAgdmFyIHIgPSB0aGlzO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGs7IGkrKylcbiAgICByID0gci5kYmwoKTtcbiAgcmV0dXJuIHI7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgY3VydmUgPSByZXF1aXJlKCcuLi9jdXJ2ZScpO1xudmFyIGVsbGlwdGljID0gcmVxdWlyZSgnLi4vLi4vZWxsaXB0aWMnKTtcbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIEJhc2UgPSBjdXJ2ZS5iYXNlO1xuXG52YXIgYXNzZXJ0ID0gZWxsaXB0aWMudXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBFZHdhcmRzQ3VydmUoY29uZikge1xuICAvLyBOT1RFOiBJbXBvcnRhbnQgYXMgd2UgYXJlIGNyZWF0aW5nIHBvaW50IGluIEJhc2UuY2FsbCgpXG4gIHRoaXMudHdpc3RlZCA9IChjb25mLmEgfCAwKSAhPT0gMTtcbiAgdGhpcy5tT25lQSA9IHRoaXMudHdpc3RlZCAmJiAoY29uZi5hIHwgMCkgPT09IC0xO1xuICB0aGlzLmV4dGVuZGVkID0gdGhpcy5tT25lQTtcblxuICBCYXNlLmNhbGwodGhpcywgJ2Vkd2FyZHMnLCBjb25mKTtcblxuICB0aGlzLmEgPSBuZXcgQk4oY29uZi5hLCAxNikudW1vZCh0aGlzLnJlZC5tKTtcbiAgdGhpcy5hID0gdGhpcy5hLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5jID0gbmV3IEJOKGNvbmYuYywgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5jMiA9IHRoaXMuYy5yZWRTcXIoKTtcbiAgdGhpcy5kID0gbmV3IEJOKGNvbmYuZCwgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgdGhpcy5kZCA9IHRoaXMuZC5yZWRBZGQodGhpcy5kKTtcblxuICBhc3NlcnQoIXRoaXMudHdpc3RlZCB8fCB0aGlzLmMuZnJvbVJlZCgpLmNtcG4oMSkgPT09IDApO1xuICB0aGlzLm9uZUMgPSAoY29uZi5jIHwgMCkgPT09IDE7XG59XG5pbmhlcml0cyhFZHdhcmRzQ3VydmUsIEJhc2UpO1xubW9kdWxlLmV4cG9ydHMgPSBFZHdhcmRzQ3VydmU7XG5cbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUuX211bEEgPSBmdW5jdGlvbiBfbXVsQShudW0pIHtcbiAgaWYgKHRoaXMubU9uZUEpXG4gICAgcmV0dXJuIG51bS5yZWROZWcoKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmEucmVkTXVsKG51bSk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLl9tdWxDID0gZnVuY3Rpb24gX211bEMobnVtKSB7XG4gIGlmICh0aGlzLm9uZUMpXG4gICAgcmV0dXJuIG51bTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmMucmVkTXVsKG51bSk7XG59O1xuXG4vLyBKdXN0IGZvciBjb21wYXRpYmlsaXR5IHdpdGggU2hvcnQgY3VydmVcbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUuanBvaW50ID0gZnVuY3Rpb24ganBvaW50KHgsIHksIHosIHQpIHtcbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSwgeiwgdCk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbVggPSBmdW5jdGlvbiBwb2ludEZyb21YKHgsIG9kZCkge1xuICB4ID0gbmV3IEJOKHgsIDE2KTtcbiAgaWYgKCF4LnJlZClcbiAgICB4ID0geC50b1JlZCh0aGlzLnJlZCk7XG5cbiAgdmFyIHgyID0geC5yZWRTcXIoKTtcbiAgdmFyIHJocyA9IHRoaXMuYzIucmVkU3ViKHRoaXMuYS5yZWRNdWwoeDIpKTtcbiAgdmFyIGxocyA9IHRoaXMub25lLnJlZFN1Yih0aGlzLmMyLnJlZE11bCh0aGlzLmQpLnJlZE11bCh4MikpO1xuXG4gIHZhciB5MiA9IHJocy5yZWRNdWwobGhzLnJlZEludm0oKSk7XG4gIHZhciB5ID0geTIucmVkU3FydCgpO1xuICBpZiAoeS5yZWRTcXIoKS5yZWRTdWIoeTIpLmNtcCh0aGlzLnplcm8pICE9PSAwKVxuICAgIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBwb2ludCcpO1xuXG4gIHZhciBpc09kZCA9IHkuZnJvbVJlZCgpLmlzT2RkKCk7XG4gIGlmIChvZGQgJiYgIWlzT2RkIHx8ICFvZGQgJiYgaXNPZGQpXG4gICAgeSA9IHkucmVkTmVnKCk7XG5cbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSk7XG59O1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbVkgPSBmdW5jdGlvbiBwb2ludEZyb21ZKHksIG9kZCkge1xuICB5ID0gbmV3IEJOKHksIDE2KTtcbiAgaWYgKCF5LnJlZClcbiAgICB5ID0geS50b1JlZCh0aGlzLnJlZCk7XG5cbiAgLy8geF4yID0gKHleMiAtIDEpIC8gKGQgeV4yICsgMSlcbiAgdmFyIHkyID0geS5yZWRTcXIoKTtcbiAgdmFyIGxocyA9IHkyLnJlZFN1Yih0aGlzLm9uZSk7XG4gIHZhciByaHMgPSB5Mi5yZWRNdWwodGhpcy5kKS5yZWRBZGQodGhpcy5vbmUpO1xuICB2YXIgeDIgPSBsaHMucmVkTXVsKHJocy5yZWRJbnZtKCkpO1xuXG4gIGlmICh4Mi5jbXAodGhpcy56ZXJvKSA9PT0gMCkge1xuICAgIGlmIChvZGQpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcG9pbnQnKTtcbiAgICBlbHNlXG4gICAgICByZXR1cm4gdGhpcy5wb2ludCh0aGlzLnplcm8sIHkpO1xuICB9XG5cbiAgdmFyIHggPSB4Mi5yZWRTcXJ0KCk7XG4gIGlmICh4LnJlZFNxcigpLnJlZFN1Yih4MikuY21wKHRoaXMuemVybykgIT09IDApXG4gICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHBvaW50Jyk7XG5cbiAgaWYgKHguaXNPZGQoKSAhPT0gb2RkKVxuICAgIHggPSB4LnJlZE5lZygpO1xuXG4gIHJldHVybiB0aGlzLnBvaW50KHgsIHkpO1xufTtcblxuRWR3YXJkc0N1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIGlmIChwb2ludC5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgLy8gQ3VydmU6IEEgKiBYXjIgKyBZXjIgPSBDXjIgKiAoMSArIEQgKiBYXjIgKiBZXjIpXG4gIHBvaW50Lm5vcm1hbGl6ZSgpO1xuXG4gIHZhciB4MiA9IHBvaW50LngucmVkU3FyKCk7XG4gIHZhciB5MiA9IHBvaW50LnkucmVkU3FyKCk7XG4gIHZhciBsaHMgPSB4Mi5yZWRNdWwodGhpcy5hKS5yZWRBZGQoeTIpO1xuICB2YXIgcmhzID0gdGhpcy5jMi5yZWRNdWwodGhpcy5vbmUucmVkQWRkKHRoaXMuZC5yZWRNdWwoeDIpLnJlZE11bCh5MikpKTtcblxuICByZXR1cm4gbGhzLmNtcChyaHMpID09PSAwO1xufTtcblxuZnVuY3Rpb24gUG9pbnQoY3VydmUsIHgsIHksIHosIHQpIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ3Byb2plY3RpdmUnKTtcbiAgaWYgKHggPT09IG51bGwgJiYgeSA9PT0gbnVsbCAmJiB6ID09PSBudWxsKSB7XG4gICAgdGhpcy54ID0gdGhpcy5jdXJ2ZS56ZXJvO1xuICAgIHRoaXMueSA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMueiA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMudCA9IHRoaXMuY3VydmUuemVybztcbiAgICB0aGlzLnpPbmUgPSB0cnVlO1xuICB9IGVsc2Uge1xuICAgIHRoaXMueCA9IG5ldyBCTih4LCAxNik7XG4gICAgdGhpcy55ID0gbmV3IEJOKHksIDE2KTtcbiAgICB0aGlzLnogPSB6ID8gbmV3IEJOKHosIDE2KSA6IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMudCA9IHQgJiYgbmV3IEJOKHQsIDE2KTtcbiAgICBpZiAoIXRoaXMueC5yZWQpXG4gICAgICB0aGlzLnggPSB0aGlzLngudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIGlmICghdGhpcy55LnJlZClcbiAgICAgIHRoaXMueSA9IHRoaXMueS50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgaWYgKCF0aGlzLnoucmVkKVxuICAgICAgdGhpcy56ID0gdGhpcy56LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICBpZiAodGhpcy50ICYmICF0aGlzLnQucmVkKVxuICAgICAgdGhpcy50ID0gdGhpcy50LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICB0aGlzLnpPbmUgPSB0aGlzLnogPT09IHRoaXMuY3VydmUub25lO1xuXG4gICAgLy8gVXNlIGV4dGVuZGVkIGNvb3JkaW5hdGVzXG4gICAgaWYgKHRoaXMuY3VydmUuZXh0ZW5kZWQgJiYgIXRoaXMudCkge1xuICAgICAgdGhpcy50ID0gdGhpcy54LnJlZE11bCh0aGlzLnkpO1xuICAgICAgaWYgKCF0aGlzLnpPbmUpXG4gICAgICAgIHRoaXMudCA9IHRoaXMudC5yZWRNdWwodGhpcy56LnJlZEludm0oKSk7XG4gICAgfVxuICB9XG59XG5pbmhlcml0cyhQb2ludCwgQmFzZS5CYXNlUG9pbnQpO1xuXG5FZHdhcmRzQ3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaikge1xuICByZXR1cm4gUG9pbnQuZnJvbUpTT04odGhpcywgb2JqKTtcbn07XG5cbkVkd2FyZHNDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB5LCB6LCB0KSB7XG4gIHJldHVybiBuZXcgUG9pbnQodGhpcywgeCwgeSwgeiwgdCk7XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmopIHtcbiAgcmV0dXJuIG5ldyBQb2ludChjdXJ2ZSwgb2JqWzBdLCBvYmpbMV0sIG9ialsyXSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaW5zcGVjdCA9IGZ1bmN0aW9uIGluc3BlY3QoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gJzxFQyBQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBQb2ludCB4OiAnICsgdGhpcy54LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB6OiAnICsgdGhpcy56LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgKyAnPic7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaXNJbmZpbml0eSA9IGZ1bmN0aW9uIGlzSW5maW5pdHkoKSB7XG4gIC8vIFhYWCBUaGlzIGNvZGUgYXNzdW1lcyB0aGF0IHplcm8gaXMgYWx3YXlzIHplcm8gaW4gcmVkXG4gIHJldHVybiB0aGlzLnguY21wbigwKSA9PT0gMCAmJlxuICAgICAgICAgdGhpcy55LmNtcCh0aGlzLnopID09PSAwO1xufTtcblxuUG9pbnQucHJvdG90eXBlLl9leHREYmwgPSBmdW5jdGlvbiBfZXh0RGJsKCkge1xuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tdHdpc3RlZC1leHRlbmRlZC0xLmh0bWxcbiAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwOC1od2NkXG4gIC8vIDRNICsgNFNcblxuICAvLyBBID0gWDFeMlxuICB2YXIgYSA9IHRoaXMueC5yZWRTcXIoKTtcbiAgLy8gQiA9IFkxXjJcbiAgdmFyIGIgPSB0aGlzLnkucmVkU3FyKCk7XG4gIC8vIEMgPSAyICogWjFeMlxuICB2YXIgYyA9IHRoaXMuei5yZWRTcXIoKTtcbiAgYyA9IGMucmVkSUFkZChjKTtcbiAgLy8gRCA9IGEgKiBBXG4gIHZhciBkID0gdGhpcy5jdXJ2ZS5fbXVsQShhKTtcbiAgLy8gRSA9IChYMSArIFkxKV4yIC0gQSAtIEJcbiAgdmFyIGUgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkU3FyKCkucmVkSVN1YihhKS5yZWRJU3ViKGIpO1xuICAvLyBHID0gRCArIEJcbiAgdmFyIGcgPSBkLnJlZEFkZChiKTtcbiAgLy8gRiA9IEcgLSBDXG4gIHZhciBmID0gZy5yZWRTdWIoYyk7XG4gIC8vIEggPSBEIC0gQlxuICB2YXIgaCA9IGQucmVkU3ViKGIpO1xuICAvLyBYMyA9IEUgKiBGXG4gIHZhciBueCA9IGUucmVkTXVsKGYpO1xuICAvLyBZMyA9IEcgKiBIXG4gIHZhciBueSA9IGcucmVkTXVsKGgpO1xuICAvLyBUMyA9IEUgKiBIXG4gIHZhciBudCA9IGUucmVkTXVsKGgpO1xuICAvLyBaMyA9IEYgKiBHXG4gIHZhciBueiA9IGYucmVkTXVsKGcpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnksIG56LCBudCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX3Byb2pEYmwgPSBmdW5jdGlvbiBfcHJvakRibCgpIHtcbiAgLy8gaHlwZXJlbGxpcHRpYy5vcmcvRUZEL2cxcC9hdXRvLXR3aXN0ZWQtcHJvamVjdGl2ZS5odG1sXG4gIC8vICAgICAjZG91YmxpbmctZGJsLTIwMDgtYmJqbHBcbiAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwNy1ibFxuICAvLyBhbmQgb3RoZXJzXG4gIC8vIEdlbmVyYWxseSAzTSArIDRTIG9yIDJNICsgNFNcblxuICAvLyBCID0gKFgxICsgWTEpXjJcbiAgdmFyIGIgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkU3FyKCk7XG4gIC8vIEMgPSBYMV4yXG4gIHZhciBjID0gdGhpcy54LnJlZFNxcigpO1xuICAvLyBEID0gWTFeMlxuICB2YXIgZCA9IHRoaXMueS5yZWRTcXIoKTtcblxuICB2YXIgbng7XG4gIHZhciBueTtcbiAgdmFyIG56O1xuICBpZiAodGhpcy5jdXJ2ZS50d2lzdGVkKSB7XG4gICAgLy8gRSA9IGEgKiBDXG4gICAgdmFyIGUgPSB0aGlzLmN1cnZlLl9tdWxBKGMpO1xuICAgIC8vIEYgPSBFICsgRFxuICAgIHZhciBmID0gZS5yZWRBZGQoZCk7XG4gICAgaWYgKHRoaXMuek9uZSkge1xuICAgICAgLy8gWDMgPSAoQiAtIEMgLSBEKSAqIChGIC0gMilcbiAgICAgIG54ID0gYi5yZWRTdWIoYykucmVkU3ViKGQpLnJlZE11bChmLnJlZFN1Yih0aGlzLmN1cnZlLnR3bykpO1xuICAgICAgLy8gWTMgPSBGICogKEUgLSBEKVxuICAgICAgbnkgPSBmLnJlZE11bChlLnJlZFN1YihkKSk7XG4gICAgICAvLyBaMyA9IEZeMiAtIDIgKiBGXG4gICAgICBueiA9IGYucmVkU3FyKCkucmVkU3ViKGYpLnJlZFN1YihmKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gSCA9IFoxXjJcbiAgICAgIHZhciBoID0gdGhpcy56LnJlZFNxcigpO1xuICAgICAgLy8gSiA9IEYgLSAyICogSFxuICAgICAgdmFyIGogPSBmLnJlZFN1YihoKS5yZWRJU3ViKGgpO1xuICAgICAgLy8gWDMgPSAoQi1DLUQpKkpcbiAgICAgIG54ID0gYi5yZWRTdWIoYykucmVkSVN1YihkKS5yZWRNdWwoaik7XG4gICAgICAvLyBZMyA9IEYgKiAoRSAtIEQpXG4gICAgICBueSA9IGYucmVkTXVsKGUucmVkU3ViKGQpKTtcbiAgICAgIC8vIFozID0gRiAqIEpcbiAgICAgIG56ID0gZi5yZWRNdWwoaik7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIC8vIEUgPSBDICsgRFxuICAgIHZhciBlID0gYy5yZWRBZGQoZCk7XG4gICAgLy8gSCA9IChjICogWjEpXjJcbiAgICB2YXIgaCA9IHRoaXMuY3VydmUuX211bEModGhpcy5jLnJlZE11bCh0aGlzLnopKS5yZWRTcXIoKTtcbiAgICAvLyBKID0gRSAtIDIgKiBIXG4gICAgdmFyIGogPSBlLnJlZFN1YihoKS5yZWRTdWIoaCk7XG4gICAgLy8gWDMgPSBjICogKEIgLSBFKSAqIEpcbiAgICBueCA9IHRoaXMuY3VydmUuX211bEMoYi5yZWRJU3ViKGUpKS5yZWRNdWwoaik7XG4gICAgLy8gWTMgPSBjICogRSAqIChDIC0gRClcbiAgICBueSA9IHRoaXMuY3VydmUuX211bEMoZSkucmVkTXVsKGMucmVkSVN1YihkKSk7XG4gICAgLy8gWjMgPSBFICogSlxuICAgIG56ID0gZS5yZWRNdWwoaik7XG4gIH1cbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobngsIG55LCBueik7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gRG91YmxlIGluIGV4dGVuZGVkIGNvb3JkaW5hdGVzXG4gIGlmICh0aGlzLmN1cnZlLmV4dGVuZGVkKVxuICAgIHJldHVybiB0aGlzLl9leHREYmwoKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLl9wcm9qRGJsKCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX2V4dEFkZCA9IGZ1bmN0aW9uIF9leHRBZGQocCkge1xuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tdHdpc3RlZC1leHRlbmRlZC0xLmh0bWxcbiAgLy8gICAgICNhZGRpdGlvbi1hZGQtMjAwOC1od2NkLTNcbiAgLy8gOE1cblxuICAvLyBBID0gKFkxIC0gWDEpICogKFkyIC0gWDIpXG4gIHZhciBhID0gdGhpcy55LnJlZFN1Yih0aGlzLngpLnJlZE11bChwLnkucmVkU3ViKHAueCkpO1xuICAvLyBCID0gKFkxICsgWDEpICogKFkyICsgWDIpXG4gIHZhciBiID0gdGhpcy55LnJlZEFkZCh0aGlzLngpLnJlZE11bChwLnkucmVkQWRkKHAueCkpO1xuICAvLyBDID0gVDEgKiBrICogVDJcbiAgdmFyIGMgPSB0aGlzLnQucmVkTXVsKHRoaXMuY3VydmUuZGQpLnJlZE11bChwLnQpO1xuICAvLyBEID0gWjEgKiAyICogWjJcbiAgdmFyIGQgPSB0aGlzLnoucmVkTXVsKHAuei5yZWRBZGQocC56KSk7XG4gIC8vIEUgPSBCIC0gQVxuICB2YXIgZSA9IGIucmVkU3ViKGEpO1xuICAvLyBGID0gRCAtIENcbiAgdmFyIGYgPSBkLnJlZFN1YihjKTtcbiAgLy8gRyA9IEQgKyBDXG4gIHZhciBnID0gZC5yZWRBZGQoYyk7XG4gIC8vIEggPSBCICsgQVxuICB2YXIgaCA9IGIucmVkQWRkKGEpO1xuICAvLyBYMyA9IEUgKiBGXG4gIHZhciBueCA9IGUucmVkTXVsKGYpO1xuICAvLyBZMyA9IEcgKiBIXG4gIHZhciBueSA9IGcucmVkTXVsKGgpO1xuICAvLyBUMyA9IEUgKiBIXG4gIHZhciBudCA9IGUucmVkTXVsKGgpO1xuICAvLyBaMyA9IEYgKiBHXG4gIHZhciBueiA9IGYucmVkTXVsKGcpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnksIG56LCBudCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX3Byb2pBZGQgPSBmdW5jdGlvbiBfcHJvakFkZChwKSB7XG4gIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by10d2lzdGVkLXByb2plY3RpdmUuaHRtbFxuICAvLyAgICAgI2FkZGl0aW9uLWFkZC0yMDA4LWJiamxwXG4gIC8vICAgICAjYWRkaXRpb24tYWRkLTIwMDctYmxcbiAgLy8gMTBNICsgMVNcblxuICAvLyBBID0gWjEgKiBaMlxuICB2YXIgYSA9IHRoaXMuei5yZWRNdWwocC56KTtcbiAgLy8gQiA9IEFeMlxuICB2YXIgYiA9IGEucmVkU3FyKCk7XG4gIC8vIEMgPSBYMSAqIFgyXG4gIHZhciBjID0gdGhpcy54LnJlZE11bChwLngpO1xuICAvLyBEID0gWTEgKiBZMlxuICB2YXIgZCA9IHRoaXMueS5yZWRNdWwocC55KTtcbiAgLy8gRSA9IGQgKiBDICogRFxuICB2YXIgZSA9IHRoaXMuY3VydmUuZC5yZWRNdWwoYykucmVkTXVsKGQpO1xuICAvLyBGID0gQiAtIEVcbiAgdmFyIGYgPSBiLnJlZFN1YihlKTtcbiAgLy8gRyA9IEIgKyBFXG4gIHZhciBnID0gYi5yZWRBZGQoZSk7XG4gIC8vIFgzID0gQSAqIEYgKiAoKFgxICsgWTEpICogKFgyICsgWTIpIC0gQyAtIEQpXG4gIHZhciB0bXAgPSB0aGlzLngucmVkQWRkKHRoaXMueSkucmVkTXVsKHAueC5yZWRBZGQocC55KSkucmVkSVN1YihjKS5yZWRJU3ViKGQpO1xuICB2YXIgbnggPSBhLnJlZE11bChmKS5yZWRNdWwodG1wKTtcbiAgdmFyIG55O1xuICB2YXIgbno7XG4gIGlmICh0aGlzLmN1cnZlLnR3aXN0ZWQpIHtcbiAgICAvLyBZMyA9IEEgKiBHICogKEQgLSBhICogQylcbiAgICBueSA9IGEucmVkTXVsKGcpLnJlZE11bChkLnJlZFN1Yih0aGlzLmN1cnZlLl9tdWxBKGMpKSk7XG4gICAgLy8gWjMgPSBGICogR1xuICAgIG56ID0gZi5yZWRNdWwoZyk7XG4gIH0gZWxzZSB7XG4gICAgLy8gWTMgPSBBICogRyAqIChEIC0gQylcbiAgICBueSA9IGEucmVkTXVsKGcpLnJlZE11bChkLnJlZFN1YihjKSk7XG4gICAgLy8gWjMgPSBjICogRiAqIEdcbiAgICBueiA9IHRoaXMuY3VydmUuX211bEMoZikucmVkTXVsKGcpO1xuICB9XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSwgbnopO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZChwKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gcDtcbiAgaWYgKHAuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiB0aGlzO1xuXG4gIGlmICh0aGlzLmN1cnZlLmV4dGVuZGVkKVxuICAgIHJldHVybiB0aGlzLl9leHRBZGQocCk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5fcHJvakFkZChwKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICBpZiAodGhpcy5faGFzRG91YmxlcyhrKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZml4ZWROYWZNdWwodGhpcywgayk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fd25hZk11bCh0aGlzLCBrKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWxBZGQgPSBmdW5jdGlvbiBtdWxBZGQoazEsIHAsIGsyKSB7XG4gIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsQWRkKDEsIFsgdGhpcywgcCBdLCBbIGsxLCBrMiBdLCAyKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5ub3JtYWxpemUgPSBmdW5jdGlvbiBub3JtYWxpemUoKSB7XG4gIGlmICh0aGlzLnpPbmUpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gTm9ybWFsaXplIGNvb3JkaW5hdGVzXG4gIHZhciB6aSA9IHRoaXMuei5yZWRJbnZtKCk7XG4gIHRoaXMueCA9IHRoaXMueC5yZWRNdWwoemkpO1xuICB0aGlzLnkgPSB0aGlzLnkucmVkTXVsKHppKTtcbiAgaWYgKHRoaXMudClcbiAgICB0aGlzLnQgPSB0aGlzLnQucmVkTXVsKHppKTtcbiAgdGhpcy56ID0gdGhpcy5jdXJ2ZS5vbmU7XG4gIHRoaXMuek9uZSA9IHRydWU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuUG9pbnQucHJvdG90eXBlLm5lZyA9IGZ1bmN0aW9uIG5lZygpIHtcbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQodGhpcy54LnJlZE5lZygpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnksXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMueixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy50ICYmIHRoaXMudC5yZWROZWcoKSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIHRoaXMubm9ybWFsaXplKCk7XG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmdldFkgPSBmdW5jdGlvbiBnZXRZKCkge1xuICB0aGlzLm5vcm1hbGl6ZSgpO1xuICByZXR1cm4gdGhpcy55LmZyb21SZWQoKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5lcSA9IGZ1bmN0aW9uIGVxKG90aGVyKSB7XG4gIHJldHVybiB0aGlzID09PSBvdGhlciB8fFxuICAgICAgICAgdGhpcy5nZXRYKCkuY21wKG90aGVyLmdldFgoKSkgPT09IDAgJiZcbiAgICAgICAgIHRoaXMuZ2V0WSgpLmNtcChvdGhlci5nZXRZKCkpID09PSAwO1xufTtcblxuLy8gQ29tcGF0aWJpbGl0eSB3aXRoIEJhc2VDdXJ2ZVxuUG9pbnQucHJvdG90eXBlLnRvUCA9IFBvaW50LnByb3RvdHlwZS5ub3JtYWxpemU7XG5Qb2ludC5wcm90b3R5cGUubWl4ZWRBZGQgPSBQb2ludC5wcm90b3R5cGUuYWRkO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgY3VydmUgPSBleHBvcnRzO1xuXG5jdXJ2ZS5iYXNlID0gcmVxdWlyZSgnLi9iYXNlJyk7XG5jdXJ2ZS5zaG9ydCA9IHJlcXVpcmUoJy4vc2hvcnQnKTtcbmN1cnZlLm1vbnQgPSByZXF1aXJlKCcuL21vbnQnKTtcbmN1cnZlLmVkd2FyZHMgPSByZXF1aXJlKCcuL2Vkd2FyZHMnKTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlID0gcmVxdWlyZSgnLi4vY3VydmUnKTtcbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xudmFyIEJhc2UgPSBjdXJ2ZS5iYXNlO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG5cbmZ1bmN0aW9uIE1vbnRDdXJ2ZShjb25mKSB7XG4gIEJhc2UuY2FsbCh0aGlzLCAnbW9udCcsIGNvbmYpO1xuXG4gIHRoaXMuYSA9IG5ldyBCTihjb25mLmEsIDE2KS50b1JlZCh0aGlzLnJlZCk7XG4gIHRoaXMuYiA9IG5ldyBCTihjb25mLmIsIDE2KS50b1JlZCh0aGlzLnJlZCk7XG4gIHRoaXMuaTQgPSBuZXcgQk4oNCkudG9SZWQodGhpcy5yZWQpLnJlZEludm0oKTtcbiAgdGhpcy50d28gPSBuZXcgQk4oMikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLmEyNCA9IHRoaXMuaTQucmVkTXVsKHRoaXMuYS5yZWRBZGQodGhpcy50d28pKTtcbn1cbmluaGVyaXRzKE1vbnRDdXJ2ZSwgQmFzZSk7XG5tb2R1bGUuZXhwb3J0cyA9IE1vbnRDdXJ2ZTtcblxuTW9udEN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIHZhciB4ID0gcG9pbnQubm9ybWFsaXplKCkueDtcbiAgdmFyIHgyID0geC5yZWRTcXIoKTtcbiAgdmFyIHJocyA9IHgyLnJlZE11bCh4KS5yZWRBZGQoeDIucmVkTXVsKHRoaXMuYSkpLnJlZEFkZCh4KTtcbiAgdmFyIHkgPSByaHMucmVkU3FydCgpO1xuXG4gIHJldHVybiB5LnJlZFNxcigpLmNtcChyaHMpID09PSAwO1xufTtcblxuZnVuY3Rpb24gUG9pbnQoY3VydmUsIHgsIHopIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ3Byb2plY3RpdmUnKTtcbiAgaWYgKHggPT09IG51bGwgJiYgeiA9PT0gbnVsbCkge1xuICAgIHRoaXMueCA9IHRoaXMuY3VydmUub25lO1xuICAgIHRoaXMueiA9IHRoaXMuY3VydmUuemVybztcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnggPSBuZXcgQk4oeCwgMTYpO1xuICAgIHRoaXMueiA9IG5ldyBCTih6LCAxNik7XG4gICAgaWYgKCF0aGlzLngucmVkKVxuICAgICAgdGhpcy54ID0gdGhpcy54LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcbiAgICBpZiAoIXRoaXMuei5yZWQpXG4gICAgICB0aGlzLnogPSB0aGlzLnoudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICB9XG59XG5pbmhlcml0cyhQb2ludCwgQmFzZS5CYXNlUG9pbnQpO1xuXG5Nb250Q3VydmUucHJvdG90eXBlLmRlY29kZVBvaW50ID0gZnVuY3Rpb24gZGVjb2RlUG9pbnQoYnl0ZXMsIGVuYykge1xuICByZXR1cm4gdGhpcy5wb2ludCh1dGlscy50b0FycmF5KGJ5dGVzLCBlbmMpLCAxKTtcbn07XG5cbk1vbnRDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB6KSB7XG4gIHJldHVybiBuZXcgUG9pbnQodGhpcywgeCwgeik7XG59O1xuXG5Nb250Q3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaikge1xuICByZXR1cm4gUG9pbnQuZnJvbUpTT04odGhpcywgb2JqKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5wcmVjb21wdXRlID0gZnVuY3Rpb24gcHJlY29tcHV0ZSgpIHtcbiAgLy8gTm8tb3Bcbn07XG5cblBvaW50LnByb3RvdHlwZS5fZW5jb2RlID0gZnVuY3Rpb24gX2VuY29kZSgpIHtcbiAgcmV0dXJuIHRoaXMuZ2V0WCgpLnRvQXJyYXkoJ2JlJywgdGhpcy5jdXJ2ZS5wLmJ5dGVMZW5ndGgoKSk7XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmopIHtcbiAgcmV0dXJuIG5ldyBQb2ludChjdXJ2ZSwgb2JqWzBdLCBvYmpbMV0gfHwgY3VydmUub25lKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCgpIHtcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiAnPEVDIFBvaW50IEluZmluaXR5Pic7XG4gIHJldHVybiAnPEVDIFBvaW50IHg6ICcgKyB0aGlzLnguZnJvbVJlZCgpLnRvU3RyaW5nKDE2LCAyKSArXG4gICAgICAnIHo6ICcgKyB0aGlzLnouZnJvbVJlZCgpLnRvU3RyaW5nKDE2LCAyKSArICc+Jztcbn07XG5cblBvaW50LnByb3RvdHlwZS5pc0luZmluaXR5ID0gZnVuY3Rpb24gaXNJbmZpbml0eSgpIHtcbiAgLy8gWFhYIFRoaXMgY29kZSBhc3N1bWVzIHRoYXQgemVybyBpcyBhbHdheXMgemVybyBpbiByZWRcbiAgcmV0dXJuIHRoaXMuei5jbXBuKDApID09PSAwO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmRibCA9IGZ1bmN0aW9uIGRibCgpIHtcbiAgLy8gaHR0cDovL2h5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1tb250Z29tLXh6Lmh0bWwjZG91YmxpbmctZGJsLTE5ODctbS0zXG4gIC8vIDJNICsgMlMgKyA0QVxuXG4gIC8vIEEgPSBYMSArIFoxXG4gIHZhciBhID0gdGhpcy54LnJlZEFkZCh0aGlzLnopO1xuICAvLyBBQSA9IEFeMlxuICB2YXIgYWEgPSBhLnJlZFNxcigpO1xuICAvLyBCID0gWDEgLSBaMVxuICB2YXIgYiA9IHRoaXMueC5yZWRTdWIodGhpcy56KTtcbiAgLy8gQkIgPSBCXjJcbiAgdmFyIGJiID0gYi5yZWRTcXIoKTtcbiAgLy8gQyA9IEFBIC0gQkJcbiAgdmFyIGMgPSBhYS5yZWRTdWIoYmIpO1xuICAvLyBYMyA9IEFBICogQkJcbiAgdmFyIG54ID0gYWEucmVkTXVsKGJiKTtcbiAgLy8gWjMgPSBDICogKEJCICsgQTI0ICogQylcbiAgdmFyIG56ID0gYy5yZWRNdWwoYmIucmVkQWRkKHRoaXMuY3VydmUuYTI0LnJlZE11bChjKSkpO1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChueCwgbnopO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZCgpIHtcbiAgdGhyb3cgbmV3IEVycm9yKCdOb3Qgc3VwcG9ydGVkIG9uIE1vbnRnb21lcnkgY3VydmUnKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5kaWZmQWRkID0gZnVuY3Rpb24gZGlmZkFkZChwLCBkaWZmKSB7XG4gIC8vIGh0dHA6Ly9oeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tbW9udGdvbS14ei5odG1sI2RpZmZhZGQtZGFkZC0xOTg3LW0tM1xuICAvLyA0TSArIDJTICsgNkFcblxuICAvLyBBID0gWDIgKyBaMlxuICB2YXIgYSA9IHRoaXMueC5yZWRBZGQodGhpcy56KTtcbiAgLy8gQiA9IFgyIC0gWjJcbiAgdmFyIGIgPSB0aGlzLngucmVkU3ViKHRoaXMueik7XG4gIC8vIEMgPSBYMyArIFozXG4gIHZhciBjID0gcC54LnJlZEFkZChwLnopO1xuICAvLyBEID0gWDMgLSBaM1xuICB2YXIgZCA9IHAueC5yZWRTdWIocC56KTtcbiAgLy8gREEgPSBEICogQVxuICB2YXIgZGEgPSBkLnJlZE11bChhKTtcbiAgLy8gQ0IgPSBDICogQlxuICB2YXIgY2IgPSBjLnJlZE11bChiKTtcbiAgLy8gWDUgPSBaMSAqIChEQSArIENCKV4yXG4gIHZhciBueCA9IGRpZmYuei5yZWRNdWwoZGEucmVkQWRkKGNiKS5yZWRTcXIoKSk7XG4gIC8vIFo1ID0gWDEgKiAoREEgLSBDQileMlxuICB2YXIgbnogPSBkaWZmLngucmVkTXVsKGRhLnJlZElTdWIoY2IpLnJlZFNxcigpKTtcbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobngsIG56KTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICB2YXIgdCA9IGsuY2xvbmUoKTtcbiAgdmFyIGEgPSB0aGlzOyAvLyAoTiAvIDIpICogUSArIFFcbiAgdmFyIGIgPSB0aGlzLmN1cnZlLnBvaW50KG51bGwsIG51bGwpOyAvLyAoTiAvIDIpICogUVxuICB2YXIgYyA9IHRoaXM7IC8vIFFcblxuICBmb3IgKHZhciBiaXRzID0gW107IHQuY21wbigwKSAhPT0gMDsgdC5pdXNocm4oMSkpXG4gICAgYml0cy5wdXNoKHQuYW5kbG4oMSkpO1xuXG4gIGZvciAodmFyIGkgPSBiaXRzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSB7XG4gICAgaWYgKGJpdHNbaV0gPT09IDApIHtcbiAgICAgIC8vIE4gKiBRICsgUSA9ICgoTiAvIDIpICogUSArIFEpKSArIChOIC8gMikgKiBRXG4gICAgICBhID0gYS5kaWZmQWRkKGIsIGMpO1xuICAgICAgLy8gTiAqIFEgPSAyICogKChOIC8gMikgKiBRICsgUSkpXG4gICAgICBiID0gYi5kYmwoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gTiAqIFEgPSAoKE4gLyAyKSAqIFEgKyBRKSArICgoTiAvIDIpICogUSlcbiAgICAgIGIgPSBhLmRpZmZBZGQoYiwgYyk7XG4gICAgICAvLyBOICogUSArIFEgPSAyICogKChOIC8gMikgKiBRICsgUSlcbiAgICAgIGEgPSBhLmRibCgpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gYjtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWxBZGQgPSBmdW5jdGlvbiBtdWxBZGQoKSB7XG4gIHRocm93IG5ldyBFcnJvcignTm90IHN1cHBvcnRlZCBvbiBNb250Z29tZXJ5IGN1cnZlJyk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZXEgPSBmdW5jdGlvbiBlcShvdGhlcikge1xuICByZXR1cm4gdGhpcy5nZXRYKCkuY21wKG90aGVyLmdldFgoKSkgPT09IDA7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUubm9ybWFsaXplID0gZnVuY3Rpb24gbm9ybWFsaXplKCkge1xuICB0aGlzLnggPSB0aGlzLngucmVkTXVsKHRoaXMuei5yZWRJbnZtKCkpO1xuICB0aGlzLnogPSB0aGlzLmN1cnZlLm9uZTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIC8vIE5vcm1hbGl6ZSBjb29yZGluYXRlc1xuICB0aGlzLm5vcm1hbGl6ZSgpO1xuXG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlID0gcmVxdWlyZSgnLi4vY3VydmUnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgQk4gPSByZXF1aXJlKCdibi5qcycpO1xudmFyIGluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcbnZhciBCYXNlID0gY3VydmUuYmFzZTtcblxudmFyIGFzc2VydCA9IGVsbGlwdGljLnV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gU2hvcnRDdXJ2ZShjb25mKSB7XG4gIEJhc2UuY2FsbCh0aGlzLCAnc2hvcnQnLCBjb25mKTtcblxuICB0aGlzLmEgPSBuZXcgQk4oY29uZi5hLCAxNikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLmIgPSBuZXcgQk4oY29uZi5iLCAxNikudG9SZWQodGhpcy5yZWQpO1xuICB0aGlzLnRpbnYgPSB0aGlzLnR3by5yZWRJbnZtKCk7XG5cbiAgdGhpcy56ZXJvQSA9IHRoaXMuYS5mcm9tUmVkKCkuY21wbigwKSA9PT0gMDtcbiAgdGhpcy50aHJlZUEgPSB0aGlzLmEuZnJvbVJlZCgpLnN1Yih0aGlzLnApLmNtcG4oLTMpID09PSAwO1xuXG4gIC8vIElmIHRoZSBjdXJ2ZSBpcyBlbmRvbW9ycGhpYywgcHJlY2FsY3VsYXRlIGJldGEgYW5kIGxhbWJkYVxuICB0aGlzLmVuZG8gPSB0aGlzLl9nZXRFbmRvbW9ycGhpc20oY29uZik7XG4gIHRoaXMuX2VuZG9XbmFmVDEgPSBuZXcgQXJyYXkoNCk7XG4gIHRoaXMuX2VuZG9XbmFmVDIgPSBuZXcgQXJyYXkoNCk7XG59XG5pbmhlcml0cyhTaG9ydEN1cnZlLCBCYXNlKTtcbm1vZHVsZS5leHBvcnRzID0gU2hvcnRDdXJ2ZTtcblxuU2hvcnRDdXJ2ZS5wcm90b3R5cGUuX2dldEVuZG9tb3JwaGlzbSA9IGZ1bmN0aW9uIF9nZXRFbmRvbW9ycGhpc20oY29uZikge1xuICAvLyBObyBlZmZpY2llbnQgZW5kb21vcnBoaXNtXG4gIGlmICghdGhpcy56ZXJvQSB8fCAhdGhpcy5nIHx8ICF0aGlzLm4gfHwgdGhpcy5wLm1vZG4oMykgIT09IDEpXG4gICAgcmV0dXJuO1xuXG4gIC8vIENvbXB1dGUgYmV0YSBhbmQgbGFtYmRhLCB0aGF0IGxhbWJkYSAqIFAgPSAoYmV0YSAqIFB4OyBQeSlcbiAgdmFyIGJldGE7XG4gIHZhciBsYW1iZGE7XG4gIGlmIChjb25mLmJldGEpIHtcbiAgICBiZXRhID0gbmV3IEJOKGNvbmYuYmV0YSwgMTYpLnRvUmVkKHRoaXMucmVkKTtcbiAgfSBlbHNlIHtcbiAgICB2YXIgYmV0YXMgPSB0aGlzLl9nZXRFbmRvUm9vdHModGhpcy5wKTtcbiAgICAvLyBDaG9vc2UgdGhlIHNtYWxsZXN0IGJldGFcbiAgICBiZXRhID0gYmV0YXNbMF0uY21wKGJldGFzWzFdKSA8IDAgPyBiZXRhc1swXSA6IGJldGFzWzFdO1xuICAgIGJldGEgPSBiZXRhLnRvUmVkKHRoaXMucmVkKTtcbiAgfVxuICBpZiAoY29uZi5sYW1iZGEpIHtcbiAgICBsYW1iZGEgPSBuZXcgQk4oY29uZi5sYW1iZGEsIDE2KTtcbiAgfSBlbHNlIHtcbiAgICAvLyBDaG9vc2UgdGhlIGxhbWJkYSB0aGF0IGlzIG1hdGNoaW5nIHNlbGVjdGVkIGJldGFcbiAgICB2YXIgbGFtYmRhcyA9IHRoaXMuX2dldEVuZG9Sb290cyh0aGlzLm4pO1xuICAgIGlmICh0aGlzLmcubXVsKGxhbWJkYXNbMF0pLnguY21wKHRoaXMuZy54LnJlZE11bChiZXRhKSkgPT09IDApIHtcbiAgICAgIGxhbWJkYSA9IGxhbWJkYXNbMF07XG4gICAgfSBlbHNlIHtcbiAgICAgIGxhbWJkYSA9IGxhbWJkYXNbMV07XG4gICAgICBhc3NlcnQodGhpcy5nLm11bChsYW1iZGEpLnguY21wKHRoaXMuZy54LnJlZE11bChiZXRhKSkgPT09IDApO1xuICAgIH1cbiAgfVxuXG4gIC8vIEdldCBiYXNpcyB2ZWN0b3JzLCB1c2VkIGZvciBiYWxhbmNlZCBsZW5ndGgtdHdvIHJlcHJlc2VudGF0aW9uXG4gIHZhciBiYXNpcztcbiAgaWYgKGNvbmYuYmFzaXMpIHtcbiAgICBiYXNpcyA9IGNvbmYuYmFzaXMubWFwKGZ1bmN0aW9uKHZlYykge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgYTogbmV3IEJOKHZlYy5hLCAxNiksXG4gICAgICAgIGI6IG5ldyBCTih2ZWMuYiwgMTYpXG4gICAgICB9O1xuICAgIH0pO1xuICB9IGVsc2Uge1xuICAgIGJhc2lzID0gdGhpcy5fZ2V0RW5kb0Jhc2lzKGxhbWJkYSk7XG4gIH1cblxuICByZXR1cm4ge1xuICAgIGJldGE6IGJldGEsXG4gICAgbGFtYmRhOiBsYW1iZGEsXG4gICAgYmFzaXM6IGJhc2lzXG4gIH07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZ2V0RW5kb1Jvb3RzID0gZnVuY3Rpb24gX2dldEVuZG9Sb290cyhudW0pIHtcbiAgLy8gRmluZCByb290cyBvZiBmb3IgeF4yICsgeCArIDEgaW4gRlxuICAvLyBSb290ID0gKC0xICstIFNxcnQoLTMpKSAvIDJcbiAgLy9cbiAgdmFyIHJlZCA9IG51bSA9PT0gdGhpcy5wID8gdGhpcy5yZWQgOiBCTi5tb250KG51bSk7XG4gIHZhciB0aW52ID0gbmV3IEJOKDIpLnRvUmVkKHJlZCkucmVkSW52bSgpO1xuICB2YXIgbnRpbnYgPSB0aW52LnJlZE5lZygpO1xuXG4gIHZhciBzID0gbmV3IEJOKDMpLnRvUmVkKHJlZCkucmVkTmVnKCkucmVkU3FydCgpLnJlZE11bCh0aW52KTtcblxuICB2YXIgbDEgPSBudGludi5yZWRBZGQocykuZnJvbVJlZCgpO1xuICB2YXIgbDIgPSBudGludi5yZWRTdWIocykuZnJvbVJlZCgpO1xuICByZXR1cm4gWyBsMSwgbDIgXTtcbn07XG5cblNob3J0Q3VydmUucHJvdG90eXBlLl9nZXRFbmRvQmFzaXMgPSBmdW5jdGlvbiBfZ2V0RW5kb0Jhc2lzKGxhbWJkYSkge1xuICAvLyBhcHJ4U3FydCA+PSBzcXJ0KHRoaXMubilcbiAgdmFyIGFwcnhTcXJ0ID0gdGhpcy5uLnVzaHJuKE1hdGguZmxvb3IodGhpcy5uLmJpdExlbmd0aCgpIC8gMikpO1xuXG4gIC8vIDMuNzRcbiAgLy8gUnVuIEVHQ0QsIHVudGlsIHIoTCArIDEpIDwgYXByeFNxcnRcbiAgdmFyIHUgPSBsYW1iZGE7XG4gIHZhciB2ID0gdGhpcy5uLmNsb25lKCk7XG4gIHZhciB4MSA9IG5ldyBCTigxKTtcbiAgdmFyIHkxID0gbmV3IEJOKDApO1xuICB2YXIgeDIgPSBuZXcgQk4oMCk7XG4gIHZhciB5MiA9IG5ldyBCTigxKTtcblxuICAvLyBOT1RFOiBhbGwgdmVjdG9ycyBhcmUgcm9vdHMgb2Y6IGEgKyBiICogbGFtYmRhID0gMCAobW9kIG4pXG4gIHZhciBhMDtcbiAgdmFyIGIwO1xuICAvLyBGaXJzdCB2ZWN0b3JcbiAgdmFyIGExO1xuICB2YXIgYjE7XG4gIC8vIFNlY29uZCB2ZWN0b3JcbiAgdmFyIGEyO1xuICB2YXIgYjI7XG5cbiAgdmFyIHByZXZSO1xuICB2YXIgaSA9IDA7XG4gIHZhciByO1xuICB2YXIgeDtcbiAgd2hpbGUgKHUuY21wbigwKSAhPT0gMCkge1xuICAgIHZhciBxID0gdi5kaXYodSk7XG4gICAgciA9IHYuc3ViKHEubXVsKHUpKTtcbiAgICB4ID0geDIuc3ViKHEubXVsKHgxKSk7XG4gICAgdmFyIHkgPSB5Mi5zdWIocS5tdWwoeTEpKTtcblxuICAgIGlmICghYTEgJiYgci5jbXAoYXByeFNxcnQpIDwgMCkge1xuICAgICAgYTAgPSBwcmV2Ui5uZWcoKTtcbiAgICAgIGIwID0geDE7XG4gICAgICBhMSA9IHIubmVnKCk7XG4gICAgICBiMSA9IHg7XG4gICAgfSBlbHNlIGlmIChhMSAmJiArK2kgPT09IDIpIHtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgICBwcmV2UiA9IHI7XG5cbiAgICB2ID0gdTtcbiAgICB1ID0gcjtcbiAgICB4MiA9IHgxO1xuICAgIHgxID0geDtcbiAgICB5MiA9IHkxO1xuICAgIHkxID0geTtcbiAgfVxuICBhMiA9IHIubmVnKCk7XG4gIGIyID0geDtcblxuICB2YXIgbGVuMSA9IGExLnNxcigpLmFkZChiMS5zcXIoKSk7XG4gIHZhciBsZW4yID0gYTIuc3FyKCkuYWRkKGIyLnNxcigpKTtcbiAgaWYgKGxlbjIuY21wKGxlbjEpID49IDApIHtcbiAgICBhMiA9IGEwO1xuICAgIGIyID0gYjA7XG4gIH1cblxuICAvLyBOb3JtYWxpemUgc2lnbnNcbiAgaWYgKGExLm5lZ2F0aXZlKSB7XG4gICAgYTEgPSBhMS5uZWcoKTtcbiAgICBiMSA9IGIxLm5lZygpO1xuICB9XG4gIGlmIChhMi5uZWdhdGl2ZSkge1xuICAgIGEyID0gYTIubmVnKCk7XG4gICAgYjIgPSBiMi5uZWcoKTtcbiAgfVxuXG4gIHJldHVybiBbXG4gICAgeyBhOiBhMSwgYjogYjEgfSxcbiAgICB7IGE6IGEyLCBiOiBiMiB9XG4gIF07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZW5kb1NwbGl0ID0gZnVuY3Rpb24gX2VuZG9TcGxpdChrKSB7XG4gIHZhciBiYXNpcyA9IHRoaXMuZW5kby5iYXNpcztcbiAgdmFyIHYxID0gYmFzaXNbMF07XG4gIHZhciB2MiA9IGJhc2lzWzFdO1xuXG4gIHZhciBjMSA9IHYyLmIubXVsKGspLmRpdlJvdW5kKHRoaXMubik7XG4gIHZhciBjMiA9IHYxLmIubmVnKCkubXVsKGspLmRpdlJvdW5kKHRoaXMubik7XG5cbiAgdmFyIHAxID0gYzEubXVsKHYxLmEpO1xuICB2YXIgcDIgPSBjMi5tdWwodjIuYSk7XG4gIHZhciBxMSA9IGMxLm11bCh2MS5iKTtcbiAgdmFyIHEyID0gYzIubXVsKHYyLmIpO1xuXG4gIC8vIENhbGN1bGF0ZSBhbnN3ZXJcbiAgdmFyIGsxID0gay5zdWIocDEpLnN1YihwMik7XG4gIHZhciBrMiA9IHExLmFkZChxMikubmVnKCk7XG4gIHJldHVybiB7IGsxOiBrMSwgazI6IGsyIH07XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5wb2ludEZyb21YID0gZnVuY3Rpb24gcG9pbnRGcm9tWCh4LCBvZGQpIHtcbiAgeCA9IG5ldyBCTih4LCAxNik7XG4gIGlmICgheC5yZWQpXG4gICAgeCA9IHgudG9SZWQodGhpcy5yZWQpO1xuXG4gIHZhciB5MiA9IHgucmVkU3FyKCkucmVkTXVsKHgpLnJlZElBZGQoeC5yZWRNdWwodGhpcy5hKSkucmVkSUFkZCh0aGlzLmIpO1xuICB2YXIgeSA9IHkyLnJlZFNxcnQoKTtcbiAgaWYgKHkucmVkU3FyKCkucmVkU3ViKHkyKS5jbXAodGhpcy56ZXJvKSAhPT0gMClcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcG9pbnQnKTtcblxuICAvLyBYWFggSXMgdGhlcmUgYW55IHdheSB0byB0ZWxsIGlmIHRoZSBudW1iZXIgaXMgb2RkIHdpdGhvdXQgY29udmVydGluZyBpdFxuICAvLyB0byBub24tcmVkIGZvcm0/XG4gIHZhciBpc09kZCA9IHkuZnJvbVJlZCgpLmlzT2RkKCk7XG4gIGlmIChvZGQgJiYgIWlzT2RkIHx8ICFvZGQgJiYgaXNPZGQpXG4gICAgeSA9IHkucmVkTmVnKCk7XG5cbiAgcmV0dXJuIHRoaXMucG9pbnQoeCwgeSk7XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS52YWxpZGF0ZSA9IGZ1bmN0aW9uIHZhbGlkYXRlKHBvaW50KSB7XG4gIGlmIChwb2ludC5pbmYpXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgdmFyIHggPSBwb2ludC54O1xuICB2YXIgeSA9IHBvaW50Lnk7XG5cbiAgdmFyIGF4ID0gdGhpcy5hLnJlZE11bCh4KTtcbiAgdmFyIHJocyA9IHgucmVkU3FyKCkucmVkTXVsKHgpLnJlZElBZGQoYXgpLnJlZElBZGQodGhpcy5iKTtcbiAgcmV0dXJuIHkucmVkU3FyKCkucmVkSVN1YihyaHMpLmNtcG4oMCkgPT09IDA7XG59O1xuXG5TaG9ydEN1cnZlLnByb3RvdHlwZS5fZW5kb1duYWZNdWxBZGQgPVxuICAgIGZ1bmN0aW9uIF9lbmRvV25hZk11bEFkZChwb2ludHMsIGNvZWZmcykge1xuICB2YXIgbnBvaW50cyA9IHRoaXMuX2VuZG9XbmFmVDE7XG4gIHZhciBuY29lZmZzID0gdGhpcy5fZW5kb1duYWZUMjtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBwb2ludHMubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgc3BsaXQgPSB0aGlzLl9lbmRvU3BsaXQoY29lZmZzW2ldKTtcbiAgICB2YXIgcCA9IHBvaW50c1tpXTtcbiAgICB2YXIgYmV0YSA9IHAuX2dldEJldGEoKTtcblxuICAgIGlmIChzcGxpdC5rMS5uZWdhdGl2ZSkge1xuICAgICAgc3BsaXQuazEuaW5lZygpO1xuICAgICAgcCA9IHAubmVnKHRydWUpO1xuICAgIH1cbiAgICBpZiAoc3BsaXQuazIubmVnYXRpdmUpIHtcbiAgICAgIHNwbGl0LmsyLmluZWcoKTtcbiAgICAgIGJldGEgPSBiZXRhLm5lZyh0cnVlKTtcbiAgICB9XG5cbiAgICBucG9pbnRzW2kgKiAyXSA9IHA7XG4gICAgbnBvaW50c1tpICogMiArIDFdID0gYmV0YTtcbiAgICBuY29lZmZzW2kgKiAyXSA9IHNwbGl0LmsxO1xuICAgIG5jb2VmZnNbaSAqIDIgKyAxXSA9IHNwbGl0LmsyO1xuICB9XG4gIHZhciByZXMgPSB0aGlzLl93bmFmTXVsQWRkKDEsIG5wb2ludHMsIG5jb2VmZnMsIGkgKiAyKTtcblxuICAvLyBDbGVhbi11cCByZWZlcmVuY2VzIHRvIHBvaW50cyBhbmQgY29lZmZpY2llbnRzXG4gIGZvciAodmFyIGogPSAwOyBqIDwgaSAqIDI7IGorKykge1xuICAgIG5wb2ludHNbal0gPSBudWxsO1xuICAgIG5jb2VmZnNbal0gPSBudWxsO1xuICB9XG4gIHJldHVybiByZXM7XG59O1xuXG5mdW5jdGlvbiBQb2ludChjdXJ2ZSwgeCwgeSwgaXNSZWQpIHtcbiAgQmFzZS5CYXNlUG9pbnQuY2FsbCh0aGlzLCBjdXJ2ZSwgJ2FmZmluZScpO1xuICBpZiAoeCA9PT0gbnVsbCAmJiB5ID09PSBudWxsKSB7XG4gICAgdGhpcy54ID0gbnVsbDtcbiAgICB0aGlzLnkgPSBudWxsO1xuICAgIHRoaXMuaW5mID0gdHJ1ZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnggPSBuZXcgQk4oeCwgMTYpO1xuICAgIHRoaXMueSA9IG5ldyBCTih5LCAxNik7XG4gICAgLy8gRm9yY2UgcmVkZ29tZXJ5IHJlcHJlc2VudGF0aW9uIHdoZW4gbG9hZGluZyBmcm9tIEpTT05cbiAgICBpZiAoaXNSZWQpIHtcbiAgICAgIHRoaXMueC5mb3JjZVJlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgICB0aGlzLnkuZm9yY2VSZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIH1cbiAgICBpZiAoIXRoaXMueC5yZWQpXG4gICAgICB0aGlzLnggPSB0aGlzLngudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICAgIGlmICghdGhpcy55LnJlZClcbiAgICAgIHRoaXMueSA9IHRoaXMueS50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gICAgdGhpcy5pbmYgPSBmYWxzZTtcbiAgfVxufVxuaW5oZXJpdHMoUG9pbnQsIEJhc2UuQmFzZVBvaW50KTtcblxuU2hvcnRDdXJ2ZS5wcm90b3R5cGUucG9pbnQgPSBmdW5jdGlvbiBwb2ludCh4LCB5LCBpc1JlZCkge1xuICByZXR1cm4gbmV3IFBvaW50KHRoaXMsIHgsIHksIGlzUmVkKTtcbn07XG5cblNob3J0Q3VydmUucHJvdG90eXBlLnBvaW50RnJvbUpTT04gPSBmdW5jdGlvbiBwb2ludEZyb21KU09OKG9iaiwgcmVkKSB7XG4gIHJldHVybiBQb2ludC5mcm9tSlNPTih0aGlzLCBvYmosIHJlZCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuX2dldEJldGEgPSBmdW5jdGlvbiBfZ2V0QmV0YSgpIHtcbiAgaWYgKCF0aGlzLmN1cnZlLmVuZG8pXG4gICAgcmV0dXJuO1xuXG4gIHZhciBwcmUgPSB0aGlzLnByZWNvbXB1dGVkO1xuICBpZiAocHJlICYmIHByZS5iZXRhKVxuICAgIHJldHVybiBwcmUuYmV0YTtcblxuICB2YXIgYmV0YSA9IHRoaXMuY3VydmUucG9pbnQodGhpcy54LnJlZE11bCh0aGlzLmN1cnZlLmVuZG8uYmV0YSksIHRoaXMueSk7XG4gIGlmIChwcmUpIHtcbiAgICB2YXIgY3VydmUgPSB0aGlzLmN1cnZlO1xuICAgIHZhciBlbmRvTXVsID0gZnVuY3Rpb24ocCkge1xuICAgICAgcmV0dXJuIGN1cnZlLnBvaW50KHAueC5yZWRNdWwoY3VydmUuZW5kby5iZXRhKSwgcC55KTtcbiAgICB9O1xuICAgIHByZS5iZXRhID0gYmV0YTtcbiAgICBiZXRhLnByZWNvbXB1dGVkID0ge1xuICAgICAgYmV0YTogbnVsbCxcbiAgICAgIG5hZjogcHJlLm5hZiAmJiB7XG4gICAgICAgIHduZDogcHJlLm5hZi53bmQsXG4gICAgICAgIHBvaW50czogcHJlLm5hZi5wb2ludHMubWFwKGVuZG9NdWwpXG4gICAgICB9LFxuICAgICAgZG91YmxlczogcHJlLmRvdWJsZXMgJiYge1xuICAgICAgICBzdGVwOiBwcmUuZG91Ymxlcy5zdGVwLFxuICAgICAgICBwb2ludHM6IHByZS5kb3VibGVzLnBvaW50cy5tYXAoZW5kb011bClcbiAgICAgIH1cbiAgICB9O1xuICB9XG4gIHJldHVybiBiZXRhO1xufTtcblxuUG9pbnQucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uIHRvSlNPTigpIHtcbiAgaWYgKCF0aGlzLnByZWNvbXB1dGVkKVxuICAgIHJldHVybiBbIHRoaXMueCwgdGhpcy55IF07XG5cbiAgcmV0dXJuIFsgdGhpcy54LCB0aGlzLnksIHRoaXMucHJlY29tcHV0ZWQgJiYge1xuICAgIGRvdWJsZXM6IHRoaXMucHJlY29tcHV0ZWQuZG91YmxlcyAmJiB7XG4gICAgICBzdGVwOiB0aGlzLnByZWNvbXB1dGVkLmRvdWJsZXMuc3RlcCxcbiAgICAgIHBvaW50czogdGhpcy5wcmVjb21wdXRlZC5kb3VibGVzLnBvaW50cy5zbGljZSgxKVxuICAgIH0sXG4gICAgbmFmOiB0aGlzLnByZWNvbXB1dGVkLm5hZiAmJiB7XG4gICAgICB3bmQ6IHRoaXMucHJlY29tcHV0ZWQubmFmLnduZCxcbiAgICAgIHBvaW50czogdGhpcy5wcmVjb21wdXRlZC5uYWYucG9pbnRzLnNsaWNlKDEpXG4gICAgfVxuICB9IF07XG59O1xuXG5Qb2ludC5mcm9tSlNPTiA9IGZ1bmN0aW9uIGZyb21KU09OKGN1cnZlLCBvYmosIHJlZCkge1xuICBpZiAodHlwZW9mIG9iaiA9PT0gJ3N0cmluZycpXG4gICAgb2JqID0gSlNPTi5wYXJzZShvYmopO1xuICB2YXIgcmVzID0gY3VydmUucG9pbnQob2JqWzBdLCBvYmpbMV0sIHJlZCk7XG4gIGlmICghb2JqWzJdKVxuICAgIHJldHVybiByZXM7XG5cbiAgZnVuY3Rpb24gb2JqMnBvaW50KG9iaikge1xuICAgIHJldHVybiBjdXJ2ZS5wb2ludChvYmpbMF0sIG9ialsxXSwgcmVkKTtcbiAgfVxuXG4gIHZhciBwcmUgPSBvYmpbMl07XG4gIHJlcy5wcmVjb21wdXRlZCA9IHtcbiAgICBiZXRhOiBudWxsLFxuICAgIGRvdWJsZXM6IHByZS5kb3VibGVzICYmIHtcbiAgICAgIHN0ZXA6IHByZS5kb3VibGVzLnN0ZXAsXG4gICAgICBwb2ludHM6IFsgcmVzIF0uY29uY2F0KHByZS5kb3VibGVzLnBvaW50cy5tYXAob2JqMnBvaW50KSlcbiAgICB9LFxuICAgIG5hZjogcHJlLm5hZiAmJiB7XG4gICAgICB3bmQ6IHByZS5uYWYud25kLFxuICAgICAgcG9pbnRzOiBbIHJlcyBdLmNvbmNhdChwcmUubmFmLnBvaW50cy5tYXAob2JqMnBvaW50KSlcbiAgICB9XG4gIH07XG4gIHJldHVybiByZXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaW5zcGVjdCA9IGZ1bmN0aW9uIGluc3BlY3QoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gJzxFQyBQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBQb2ludCB4OiAnICsgdGhpcy54LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LmZyb21SZWQoKS50b1N0cmluZygxNiwgMikgKyAnPic7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuaXNJbmZpbml0eSA9IGZ1bmN0aW9uIGlzSW5maW5pdHkoKSB7XG4gIHJldHVybiB0aGlzLmluZjtcbn07XG5cblBvaW50LnByb3RvdHlwZS5hZGQgPSBmdW5jdGlvbiBhZGQocCkge1xuICAvLyBPICsgUCA9IFBcbiAgaWYgKHRoaXMuaW5mKVxuICAgIHJldHVybiBwO1xuXG4gIC8vIFAgKyBPID0gUFxuICBpZiAocC5pbmYpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gUCArIFAgPSAyUFxuICBpZiAodGhpcy5lcShwKSlcbiAgICByZXR1cm4gdGhpcy5kYmwoKTtcblxuICAvLyBQICsgKC1QKSA9IE9cbiAgaWYgKHRoaXMubmVnKCkuZXEocCkpXG4gICAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobnVsbCwgbnVsbCk7XG5cbiAgLy8gUCArIFEgPSBPXG4gIGlmICh0aGlzLnguY21wKHAueCkgPT09IDApXG4gICAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQobnVsbCwgbnVsbCk7XG5cbiAgdmFyIGMgPSB0aGlzLnkucmVkU3ViKHAueSk7XG4gIGlmIChjLmNtcG4oMCkgIT09IDApXG4gICAgYyA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIocC54KS5yZWRJbnZtKCkpO1xuICB2YXIgbnggPSBjLnJlZFNxcigpLnJlZElTdWIodGhpcy54KS5yZWRJU3ViKHAueCk7XG4gIHZhciBueSA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIobngpKS5yZWRJU3ViKHRoaXMueSk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pbmYpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gMlAgPSBPXG4gIHZhciB5czEgPSB0aGlzLnkucmVkQWRkKHRoaXMueSk7XG4gIGlmICh5czEuY21wbigwKSA9PT0gMClcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChudWxsLCBudWxsKTtcblxuICB2YXIgYSA9IHRoaXMuY3VydmUuYTtcblxuICB2YXIgeDIgPSB0aGlzLngucmVkU3FyKCk7XG4gIHZhciBkeWludiA9IHlzMS5yZWRJbnZtKCk7XG4gIHZhciBjID0geDIucmVkQWRkKHgyKS5yZWRJQWRkKHgyKS5yZWRJQWRkKGEpLnJlZE11bChkeWludik7XG5cbiAgdmFyIG54ID0gYy5yZWRTcXIoKS5yZWRJU3ViKHRoaXMueC5yZWRBZGQodGhpcy54KSk7XG4gIHZhciBueSA9IGMucmVkTXVsKHRoaXMueC5yZWRTdWIobngpKS5yZWRJU3ViKHRoaXMueSk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50KG54LCBueSk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZ2V0WCA9IGZ1bmN0aW9uIGdldFgoKSB7XG4gIHJldHVybiB0aGlzLnguZnJvbVJlZCgpO1xufTtcblxuUG9pbnQucHJvdG90eXBlLmdldFkgPSBmdW5jdGlvbiBnZXRZKCkge1xuICByZXR1cm4gdGhpcy55LmZyb21SZWQoKTtcbn07XG5cblBvaW50LnByb3RvdHlwZS5tdWwgPSBmdW5jdGlvbiBtdWwoaykge1xuICBrID0gbmV3IEJOKGssIDE2KTtcblxuICBpZiAodGhpcy5faGFzRG91YmxlcyhrKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZml4ZWROYWZNdWwodGhpcywgayk7XG4gIGVsc2UgaWYgKHRoaXMuY3VydmUuZW5kbylcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fZW5kb1duYWZNdWxBZGQoWyB0aGlzIF0sIFsgayBdKTtcbiAgZWxzZVxuICAgIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsKHRoaXMsIGspO1xufTtcblxuUG9pbnQucHJvdG90eXBlLm11bEFkZCA9IGZ1bmN0aW9uIG11bEFkZChrMSwgcDIsIGsyKSB7XG4gIHZhciBwb2ludHMgPSBbIHRoaXMsIHAyIF07XG4gIHZhciBjb2VmZnMgPSBbIGsxLCBrMiBdO1xuICBpZiAodGhpcy5jdXJ2ZS5lbmRvKVxuICAgIHJldHVybiB0aGlzLmN1cnZlLl9lbmRvV25hZk11bEFkZChwb2ludHMsIGNvZWZmcyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5fd25hZk11bEFkZCgxLCBwb2ludHMsIGNvZWZmcywgMik7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUuZXEgPSBmdW5jdGlvbiBlcShwKSB7XG4gIHJldHVybiB0aGlzID09PSBwIHx8XG4gICAgICAgICB0aGlzLmluZiA9PT0gcC5pbmYgJiZcbiAgICAgICAgICAgICAodGhpcy5pbmYgfHwgdGhpcy54LmNtcChwLngpID09PSAwICYmIHRoaXMueS5jbXAocC55KSA9PT0gMCk7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUubmVnID0gZnVuY3Rpb24gbmVnKF9wcmVjb21wdXRlKSB7XG4gIGlmICh0aGlzLmluZilcbiAgICByZXR1cm4gdGhpcztcblxuICB2YXIgcmVzID0gdGhpcy5jdXJ2ZS5wb2ludCh0aGlzLngsIHRoaXMueS5yZWROZWcoKSk7XG4gIGlmIChfcHJlY29tcHV0ZSAmJiB0aGlzLnByZWNvbXB1dGVkKSB7XG4gICAgdmFyIHByZSA9IHRoaXMucHJlY29tcHV0ZWQ7XG4gICAgdmFyIG5lZ2F0ZSA9IGZ1bmN0aW9uKHApIHtcbiAgICAgIHJldHVybiBwLm5lZygpO1xuICAgIH07XG4gICAgcmVzLnByZWNvbXB1dGVkID0ge1xuICAgICAgbmFmOiBwcmUubmFmICYmIHtcbiAgICAgICAgd25kOiBwcmUubmFmLnduZCxcbiAgICAgICAgcG9pbnRzOiBwcmUubmFmLnBvaW50cy5tYXAobmVnYXRlKVxuICAgICAgfSxcbiAgICAgIGRvdWJsZXM6IHByZS5kb3VibGVzICYmIHtcbiAgICAgICAgc3RlcDogcHJlLmRvdWJsZXMuc3RlcCxcbiAgICAgICAgcG9pbnRzOiBwcmUuZG91Ymxlcy5wb2ludHMubWFwKG5lZ2F0ZSlcbiAgICAgIH1cbiAgICB9O1xuICB9XG4gIHJldHVybiByZXM7XG59O1xuXG5Qb2ludC5wcm90b3R5cGUudG9KID0gZnVuY3Rpb24gdG9KKCkge1xuICBpZiAodGhpcy5pbmYpXG4gICAgcmV0dXJuIHRoaXMuY3VydmUuanBvaW50KG51bGwsIG51bGwsIG51bGwpO1xuXG4gIHZhciByZXMgPSB0aGlzLmN1cnZlLmpwb2ludCh0aGlzLngsIHRoaXMueSwgdGhpcy5jdXJ2ZS5vbmUpO1xuICByZXR1cm4gcmVzO1xufTtcblxuZnVuY3Rpb24gSlBvaW50KGN1cnZlLCB4LCB5LCB6KSB7XG4gIEJhc2UuQmFzZVBvaW50LmNhbGwodGhpcywgY3VydmUsICdqYWNvYmlhbicpO1xuICBpZiAoeCA9PT0gbnVsbCAmJiB5ID09PSBudWxsICYmIHogPT09IG51bGwpIHtcbiAgICB0aGlzLnggPSB0aGlzLmN1cnZlLm9uZTtcbiAgICB0aGlzLnkgPSB0aGlzLmN1cnZlLm9uZTtcbiAgICB0aGlzLnogPSBuZXcgQk4oMCk7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy54ID0gbmV3IEJOKHgsIDE2KTtcbiAgICB0aGlzLnkgPSBuZXcgQk4oeSwgMTYpO1xuICAgIHRoaXMueiA9IG5ldyBCTih6LCAxNik7XG4gIH1cbiAgaWYgKCF0aGlzLngucmVkKVxuICAgIHRoaXMueCA9IHRoaXMueC50b1JlZCh0aGlzLmN1cnZlLnJlZCk7XG4gIGlmICghdGhpcy55LnJlZClcbiAgICB0aGlzLnkgPSB0aGlzLnkudG9SZWQodGhpcy5jdXJ2ZS5yZWQpO1xuICBpZiAoIXRoaXMuei5yZWQpXG4gICAgdGhpcy56ID0gdGhpcy56LnRvUmVkKHRoaXMuY3VydmUucmVkKTtcblxuICB0aGlzLnpPbmUgPSB0aGlzLnogPT09IHRoaXMuY3VydmUub25lO1xufVxuaW5oZXJpdHMoSlBvaW50LCBCYXNlLkJhc2VQb2ludCk7XG5cblNob3J0Q3VydmUucHJvdG90eXBlLmpwb2ludCA9IGZ1bmN0aW9uIGpwb2ludCh4LCB5LCB6KSB7XG4gIHJldHVybiBuZXcgSlBvaW50KHRoaXMsIHgsIHksIHopO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS50b1AgPSBmdW5jdGlvbiB0b1AoKSB7XG4gIGlmICh0aGlzLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gdGhpcy5jdXJ2ZS5wb2ludChudWxsLCBudWxsKTtcblxuICB2YXIgemludiA9IHRoaXMuei5yZWRJbnZtKCk7XG4gIHZhciB6aW52MiA9IHppbnYucmVkU3FyKCk7XG4gIHZhciBheCA9IHRoaXMueC5yZWRNdWwoemludjIpO1xuICB2YXIgYXkgPSB0aGlzLnkucmVkTXVsKHppbnYyKS5yZWRNdWwoemludik7XG5cbiAgcmV0dXJuIHRoaXMuY3VydmUucG9pbnQoYXgsIGF5KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUubmVnID0gZnVuY3Rpb24gbmVnKCkge1xuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQodGhpcy54LCB0aGlzLnkucmVkTmVnKCksIHRoaXMueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLmFkZCA9IGZ1bmN0aW9uIGFkZChwKSB7XG4gIC8vIE8gKyBQID0gUFxuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHA7XG5cbiAgLy8gUCArIE8gPSBQXG4gIGlmIChwLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gdGhpcztcblxuICAvLyAxMk0gKyA0UyArIDdBXG4gIHZhciBwejIgPSBwLnoucmVkU3FyKCk7XG4gIHZhciB6MiA9IHRoaXMuei5yZWRTcXIoKTtcbiAgdmFyIHUxID0gdGhpcy54LnJlZE11bChwejIpO1xuICB2YXIgdTIgPSBwLngucmVkTXVsKHoyKTtcbiAgdmFyIHMxID0gdGhpcy55LnJlZE11bChwejIucmVkTXVsKHAueikpO1xuICB2YXIgczIgPSBwLnkucmVkTXVsKHoyLnJlZE11bCh0aGlzLnopKTtcblxuICB2YXIgaCA9IHUxLnJlZFN1Yih1Mik7XG4gIHZhciByID0gczEucmVkU3ViKHMyKTtcbiAgaWYgKGguY21wbigwKSA9PT0gMCkge1xuICAgIGlmIChyLmNtcG4oMCkgIT09IDApXG4gICAgICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIHRoaXMuZGJsKCk7XG4gIH1cblxuICB2YXIgaDIgPSBoLnJlZFNxcigpO1xuICB2YXIgaDMgPSBoMi5yZWRNdWwoaCk7XG4gIHZhciB2ID0gdTEucmVkTXVsKGgyKTtcblxuICB2YXIgbnggPSByLnJlZFNxcigpLnJlZElBZGQoaDMpLnJlZElTdWIodikucmVkSVN1Yih2KTtcbiAgdmFyIG55ID0gci5yZWRNdWwodi5yZWRJU3ViKG54KSkucmVkSVN1YihzMS5yZWRNdWwoaDMpKTtcbiAgdmFyIG56ID0gdGhpcy56LnJlZE11bChwLnopLnJlZE11bChoKTtcblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLm1peGVkQWRkID0gZnVuY3Rpb24gbWl4ZWRBZGQocCkge1xuICAvLyBPICsgUCA9IFBcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiBwLnRvSigpO1xuXG4gIC8vIFAgKyBPID0gUFxuICBpZiAocC5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgLy8gOE0gKyAzUyArIDdBXG4gIHZhciB6MiA9IHRoaXMuei5yZWRTcXIoKTtcbiAgdmFyIHUxID0gdGhpcy54O1xuICB2YXIgdTIgPSBwLngucmVkTXVsKHoyKTtcbiAgdmFyIHMxID0gdGhpcy55O1xuICB2YXIgczIgPSBwLnkucmVkTXVsKHoyKS5yZWRNdWwodGhpcy56KTtcblxuICB2YXIgaCA9IHUxLnJlZFN1Yih1Mik7XG4gIHZhciByID0gczEucmVkU3ViKHMyKTtcbiAgaWYgKGguY21wbigwKSA9PT0gMCkge1xuICAgIGlmIChyLmNtcG4oMCkgIT09IDApXG4gICAgICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobnVsbCwgbnVsbCwgbnVsbCk7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIHRoaXMuZGJsKCk7XG4gIH1cblxuICB2YXIgaDIgPSBoLnJlZFNxcigpO1xuICB2YXIgaDMgPSBoMi5yZWRNdWwoaCk7XG4gIHZhciB2ID0gdTEucmVkTXVsKGgyKTtcblxuICB2YXIgbnggPSByLnJlZFNxcigpLnJlZElBZGQoaDMpLnJlZElTdWIodikucmVkSVN1Yih2KTtcbiAgdmFyIG55ID0gci5yZWRNdWwodi5yZWRJU3ViKG54KSkucmVkSVN1YihzMS5yZWRNdWwoaDMpKTtcbiAgdmFyIG56ID0gdGhpcy56LnJlZE11bChoKTtcblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLmRibHAgPSBmdW5jdGlvbiBkYmxwKHBvdykge1xuICBpZiAocG93ID09PSAwKVxuICAgIHJldHVybiB0aGlzO1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG4gIGlmICghcG93KVxuICAgIHJldHVybiB0aGlzLmRibCgpO1xuXG4gIGlmICh0aGlzLmN1cnZlLnplcm9BIHx8IHRoaXMuY3VydmUudGhyZWVBKSB7XG4gICAgdmFyIHIgPSB0aGlzO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgcG93OyBpKyspXG4gICAgICByID0gci5kYmwoKTtcbiAgICByZXR1cm4gcjtcbiAgfVxuXG4gIC8vIDFNICsgMlMgKyAxQSArIE4gKiAoNFMgKyA1TSArIDhBKVxuICAvLyBOID0gMSA9PiA2TSArIDZTICsgOUFcbiAgdmFyIGEgPSB0aGlzLmN1cnZlLmE7XG4gIHZhciB0aW52ID0gdGhpcy5jdXJ2ZS50aW52O1xuXG4gIHZhciBqeCA9IHRoaXMueDtcbiAgdmFyIGp5ID0gdGhpcy55O1xuICB2YXIganogPSB0aGlzLno7XG4gIHZhciBqejQgPSBqei5yZWRTcXIoKS5yZWRTcXIoKTtcblxuICAvLyBSZXVzZSByZXN1bHRzXG4gIHZhciBqeWQgPSBqeS5yZWRBZGQoankpO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHBvdzsgaSsrKSB7XG4gICAgdmFyIGp4MiA9IGp4LnJlZFNxcigpO1xuICAgIHZhciBqeWQyID0ganlkLnJlZFNxcigpO1xuICAgIHZhciBqeWQ0ID0ganlkMi5yZWRTcXIoKTtcbiAgICB2YXIgYyA9IGp4Mi5yZWRBZGQoangyKS5yZWRJQWRkKGp4MikucmVkSUFkZChhLnJlZE11bChqejQpKTtcblxuICAgIHZhciB0MSA9IGp4LnJlZE11bChqeWQyKTtcbiAgICB2YXIgbnggPSBjLnJlZFNxcigpLnJlZElTdWIodDEucmVkQWRkKHQxKSk7XG4gICAgdmFyIHQyID0gdDEucmVkSVN1YihueCk7XG4gICAgdmFyIGRueSA9IGMucmVkTXVsKHQyKTtcbiAgICBkbnkgPSBkbnkucmVkSUFkZChkbnkpLnJlZElTdWIoanlkNCk7XG4gICAgdmFyIG56ID0ganlkLnJlZE11bChqeik7XG4gICAgaWYgKGkgKyAxIDwgcG93KVxuICAgICAgano0ID0gano0LnJlZE11bChqeWQ0KTtcblxuICAgIGp4ID0gbng7XG4gICAganogPSBuejtcbiAgICBqeWQgPSBkbnk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQoangsIGp5ZC5yZWRNdWwodGludiksIGp6KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUuZGJsID0gZnVuY3Rpb24gZGJsKCkge1xuICBpZiAodGhpcy5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHRoaXM7XG5cbiAgaWYgKHRoaXMuY3VydmUuemVyb0EpXG4gICAgcmV0dXJuIHRoaXMuX3plcm9EYmwoKTtcbiAgZWxzZSBpZiAodGhpcy5jdXJ2ZS50aHJlZUEpXG4gICAgcmV0dXJuIHRoaXMuX3RocmVlRGJsKCk7XG4gIGVsc2VcbiAgICByZXR1cm4gdGhpcy5fZGJsKCk7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLl96ZXJvRGJsID0gZnVuY3Rpb24gX3plcm9EYmwoKSB7XG4gIHZhciBueDtcbiAgdmFyIG55O1xuICB2YXIgbno7XG4gIC8vIFogPSAxXG4gIGlmICh0aGlzLnpPbmUpIHtcbiAgICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tc2hvcnR3LWphY29iaWFuLTAuaHRtbFxuICAgIC8vICAgICAjZG91YmxpbmctbWRibC0yMDA3LWJsXG4gICAgLy8gMU0gKyA1UyArIDE0QVxuXG4gICAgLy8gWFggPSBYMV4yXG4gICAgdmFyIHh4ID0gdGhpcy54LnJlZFNxcigpO1xuICAgIC8vIFlZID0gWTFeMlxuICAgIHZhciB5eSA9IHRoaXMueS5yZWRTcXIoKTtcbiAgICAvLyBZWVlZID0gWVleMlxuICAgIHZhciB5eXl5ID0geXkucmVkU3FyKCk7XG4gICAgLy8gUyA9IDIgKiAoKFgxICsgWVkpXjIgLSBYWCAtIFlZWVkpXG4gICAgdmFyIHMgPSB0aGlzLngucmVkQWRkKHl5KS5yZWRTcXIoKS5yZWRJU3ViKHh4KS5yZWRJU3ViKHl5eXkpO1xuICAgIHMgPSBzLnJlZElBZGQocyk7XG4gICAgLy8gTSA9IDMgKiBYWCArIGE7IGEgPSAwXG4gICAgdmFyIG0gPSB4eC5yZWRBZGQoeHgpLnJlZElBZGQoeHgpO1xuICAgIC8vIFQgPSBNIF4gMiAtIDIqU1xuICAgIHZhciB0ID0gbS5yZWRTcXIoKS5yZWRJU3ViKHMpLnJlZElTdWIocyk7XG5cbiAgICAvLyA4ICogWVlZWVxuICAgIHZhciB5eXl5OCA9IHl5eXkucmVkSUFkZCh5eXl5KTtcbiAgICB5eXl5OCA9IHl5eXk4LnJlZElBZGQoeXl5eTgpO1xuICAgIHl5eXk4ID0geXl5eTgucmVkSUFkZCh5eXl5OCk7XG5cbiAgICAvLyBYMyA9IFRcbiAgICBueCA9IHQ7XG4gICAgLy8gWTMgPSBNICogKFMgLSBUKSAtIDggKiBZWVlZXG4gICAgbnkgPSBtLnJlZE11bChzLnJlZElTdWIodCkpLnJlZElTdWIoeXl5eTgpO1xuICAgIC8vIFozID0gMipZMVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnkpO1xuICB9IGVsc2Uge1xuICAgIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1zaG9ydHctamFjb2JpYW4tMC5odG1sXG4gICAgLy8gICAgICNkb3VibGluZy1kYmwtMjAwOS1sXG4gICAgLy8gMk0gKyA1UyArIDEzQVxuXG4gICAgLy8gQSA9IFgxXjJcbiAgICB2YXIgYSA9IHRoaXMueC5yZWRTcXIoKTtcbiAgICAvLyBCID0gWTFeMlxuICAgIHZhciBiID0gdGhpcy55LnJlZFNxcigpO1xuICAgIC8vIEMgPSBCXjJcbiAgICB2YXIgYyA9IGIucmVkU3FyKCk7XG4gICAgLy8gRCA9IDIgKiAoKFgxICsgQileMiAtIEEgLSBDKVxuICAgIHZhciBkID0gdGhpcy54LnJlZEFkZChiKS5yZWRTcXIoKS5yZWRJU3ViKGEpLnJlZElTdWIoYyk7XG4gICAgZCA9IGQucmVkSUFkZChkKTtcbiAgICAvLyBFID0gMyAqIEFcbiAgICB2YXIgZSA9IGEucmVkQWRkKGEpLnJlZElBZGQoYSk7XG4gICAgLy8gRiA9IEVeMlxuICAgIHZhciBmID0gZS5yZWRTcXIoKTtcblxuICAgIC8vIDggKiBDXG4gICAgdmFyIGM4ID0gYy5yZWRJQWRkKGMpO1xuICAgIGM4ID0gYzgucmVkSUFkZChjOCk7XG4gICAgYzggPSBjOC5yZWRJQWRkKGM4KTtcblxuICAgIC8vIFgzID0gRiAtIDIgKiBEXG4gICAgbnggPSBmLnJlZElTdWIoZCkucmVkSVN1YihkKTtcbiAgICAvLyBZMyA9IEUgKiAoRCAtIFgzKSAtIDggKiBDXG4gICAgbnkgPSBlLnJlZE11bChkLnJlZElTdWIobngpKS5yZWRJU3ViKGM4KTtcbiAgICAvLyBaMyA9IDIgKiBZMSAqIFoxXG4gICAgbnogPSB0aGlzLnkucmVkTXVsKHRoaXMueik7XG4gICAgbnogPSBuei5yZWRJQWRkKG56KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLmN1cnZlLmpwb2ludChueCwgbnksIG56KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUuX3RocmVlRGJsID0gZnVuY3Rpb24gX3RocmVlRGJsKCkge1xuICB2YXIgbng7XG4gIHZhciBueTtcbiAgdmFyIG56O1xuICAvLyBaID0gMVxuICBpZiAodGhpcy56T25lKSB7XG4gICAgLy8gaHlwZXJlbGxpcHRpYy5vcmcvRUZEL2cxcC9hdXRvLXNob3J0dy1qYWNvYmlhbi0zLmh0bWxcbiAgICAvLyAgICAgI2RvdWJsaW5nLW1kYmwtMjAwNy1ibFxuICAgIC8vIDFNICsgNVMgKyAxNUFcblxuICAgIC8vIFhYID0gWDFeMlxuICAgIHZhciB4eCA9IHRoaXMueC5yZWRTcXIoKTtcbiAgICAvLyBZWSA9IFkxXjJcbiAgICB2YXIgeXkgPSB0aGlzLnkucmVkU3FyKCk7XG4gICAgLy8gWVlZWSA9IFlZXjJcbiAgICB2YXIgeXl5eSA9IHl5LnJlZFNxcigpO1xuICAgIC8vIFMgPSAyICogKChYMSArIFlZKV4yIC0gWFggLSBZWVlZKVxuICAgIHZhciBzID0gdGhpcy54LnJlZEFkZCh5eSkucmVkU3FyKCkucmVkSVN1Yih4eCkucmVkSVN1Yih5eXl5KTtcbiAgICBzID0gcy5yZWRJQWRkKHMpO1xuICAgIC8vIE0gPSAzICogWFggKyBhXG4gICAgdmFyIG0gPSB4eC5yZWRBZGQoeHgpLnJlZElBZGQoeHgpLnJlZElBZGQodGhpcy5jdXJ2ZS5hKTtcbiAgICAvLyBUID0gTV4yIC0gMiAqIFNcbiAgICB2YXIgdCA9IG0ucmVkU3FyKCkucmVkSVN1YihzKS5yZWRJU3ViKHMpO1xuICAgIC8vIFgzID0gVFxuICAgIG54ID0gdDtcbiAgICAvLyBZMyA9IE0gKiAoUyAtIFQpIC0gOCAqIFlZWVlcbiAgICB2YXIgeXl5eTggPSB5eXl5LnJlZElBZGQoeXl5eSk7XG4gICAgeXl5eTggPSB5eXl5OC5yZWRJQWRkKHl5eXk4KTtcbiAgICB5eXl5OCA9IHl5eXk4LnJlZElBZGQoeXl5eTgpO1xuICAgIG55ID0gbS5yZWRNdWwocy5yZWRJU3ViKHQpKS5yZWRJU3ViKHl5eXk4KTtcbiAgICAvLyBaMyA9IDIgKiBZMVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnkpO1xuICB9IGVsc2Uge1xuICAgIC8vIGh5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by1zaG9ydHctamFjb2JpYW4tMy5odG1sI2RvdWJsaW5nLWRibC0yMDAxLWJcbiAgICAvLyAzTSArIDVTXG5cbiAgICAvLyBkZWx0YSA9IFoxXjJcbiAgICB2YXIgZGVsdGEgPSB0aGlzLnoucmVkU3FyKCk7XG4gICAgLy8gZ2FtbWEgPSBZMV4yXG4gICAgdmFyIGdhbW1hID0gdGhpcy55LnJlZFNxcigpO1xuICAgIC8vIGJldGEgPSBYMSAqIGdhbW1hXG4gICAgdmFyIGJldGEgPSB0aGlzLngucmVkTXVsKGdhbW1hKTtcbiAgICAvLyBhbHBoYSA9IDMgKiAoWDEgLSBkZWx0YSkgKiAoWDEgKyBkZWx0YSlcbiAgICB2YXIgYWxwaGEgPSB0aGlzLngucmVkU3ViKGRlbHRhKS5yZWRNdWwodGhpcy54LnJlZEFkZChkZWx0YSkpO1xuICAgIGFscGhhID0gYWxwaGEucmVkQWRkKGFscGhhKS5yZWRJQWRkKGFscGhhKTtcbiAgICAvLyBYMyA9IGFscGhhXjIgLSA4ICogYmV0YVxuICAgIHZhciBiZXRhNCA9IGJldGEucmVkSUFkZChiZXRhKTtcbiAgICBiZXRhNCA9IGJldGE0LnJlZElBZGQoYmV0YTQpO1xuICAgIHZhciBiZXRhOCA9IGJldGE0LnJlZEFkZChiZXRhNCk7XG4gICAgbnggPSBhbHBoYS5yZWRTcXIoKS5yZWRJU3ViKGJldGE4KTtcbiAgICAvLyBaMyA9IChZMSArIFoxKV4yIC0gZ2FtbWEgLSBkZWx0YVxuICAgIG56ID0gdGhpcy55LnJlZEFkZCh0aGlzLnopLnJlZFNxcigpLnJlZElTdWIoZ2FtbWEpLnJlZElTdWIoZGVsdGEpO1xuICAgIC8vIFkzID0gYWxwaGEgKiAoNCAqIGJldGEgLSBYMykgLSA4ICogZ2FtbWFeMlxuICAgIHZhciBnZ2FtbWE4ID0gZ2FtbWEucmVkU3FyKCk7XG4gICAgZ2dhbW1hOCA9IGdnYW1tYTgucmVkSUFkZChnZ2FtbWE4KTtcbiAgICBnZ2FtbWE4ID0gZ2dhbW1hOC5yZWRJQWRkKGdnYW1tYTgpO1xuICAgIGdnYW1tYTggPSBnZ2FtbWE4LnJlZElBZGQoZ2dhbW1hOCk7XG4gICAgbnkgPSBhbHBoYS5yZWRNdWwoYmV0YTQucmVkSVN1YihueCkpLnJlZElTdWIoZ2dhbW1hOCk7XG4gIH1cblxuICByZXR1cm4gdGhpcy5jdXJ2ZS5qcG9pbnQobngsIG55LCBueik7XG59O1xuXG5KUG9pbnQucHJvdG90eXBlLl9kYmwgPSBmdW5jdGlvbiBfZGJsKCkge1xuICB2YXIgYSA9IHRoaXMuY3VydmUuYTtcblxuICAvLyA0TSArIDZTICsgMTBBXG4gIHZhciBqeCA9IHRoaXMueDtcbiAgdmFyIGp5ID0gdGhpcy55O1xuICB2YXIganogPSB0aGlzLno7XG4gIHZhciBqejQgPSBqei5yZWRTcXIoKS5yZWRTcXIoKTtcblxuICB2YXIgangyID0gangucmVkU3FyKCk7XG4gIHZhciBqeTIgPSBqeS5yZWRTcXIoKTtcblxuICB2YXIgYyA9IGp4Mi5yZWRBZGQoangyKS5yZWRJQWRkKGp4MikucmVkSUFkZChhLnJlZE11bChqejQpKTtcblxuICB2YXIganhkNCA9IGp4LnJlZEFkZChqeCk7XG4gIGp4ZDQgPSBqeGQ0LnJlZElBZGQoanhkNCk7XG4gIHZhciB0MSA9IGp4ZDQucmVkTXVsKGp5Mik7XG4gIHZhciBueCA9IGMucmVkU3FyKCkucmVkSVN1Yih0MS5yZWRBZGQodDEpKTtcbiAgdmFyIHQyID0gdDEucmVkSVN1YihueCk7XG5cbiAgdmFyIGp5ZDggPSBqeTIucmVkU3FyKCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIGp5ZDggPSBqeWQ4LnJlZElBZGQoanlkOCk7XG4gIHZhciBueSA9IGMucmVkTXVsKHQyKS5yZWRJU3ViKGp5ZDgpO1xuICB2YXIgbnogPSBqeS5yZWRBZGQoankpLnJlZE11bChqeik7XG5cbiAgcmV0dXJuIHRoaXMuY3VydmUuanBvaW50KG54LCBueSwgbnopO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS50cnBsID0gZnVuY3Rpb24gdHJwbCgpIHtcbiAgaWYgKCF0aGlzLmN1cnZlLnplcm9BKVxuICAgIHJldHVybiB0aGlzLmRibCgpLmFkZCh0aGlzKTtcblxuICAvLyBoeXBlcmVsbGlwdGljLm9yZy9FRkQvZzFwL2F1dG8tc2hvcnR3LWphY29iaWFuLTAuaHRtbCN0cmlwbGluZy10cGwtMjAwNy1ibFxuICAvLyA1TSArIDEwUyArIC4uLlxuXG4gIC8vIFhYID0gWDFeMlxuICB2YXIgeHggPSB0aGlzLngucmVkU3FyKCk7XG4gIC8vIFlZID0gWTFeMlxuICB2YXIgeXkgPSB0aGlzLnkucmVkU3FyKCk7XG4gIC8vIFpaID0gWjFeMlxuICB2YXIgenogPSB0aGlzLnoucmVkU3FyKCk7XG4gIC8vIFlZWVkgPSBZWV4yXG4gIHZhciB5eXl5ID0geXkucmVkU3FyKCk7XG4gIC8vIE0gPSAzICogWFggKyBhICogWloyOyBhID0gMFxuICB2YXIgbSA9IHh4LnJlZEFkZCh4eCkucmVkSUFkZCh4eCk7XG4gIC8vIE1NID0gTV4yXG4gIHZhciBtbSA9IG0ucmVkU3FyKCk7XG4gIC8vIEUgPSA2ICogKChYMSArIFlZKV4yIC0gWFggLSBZWVlZKSAtIE1NXG4gIHZhciBlID0gdGhpcy54LnJlZEFkZCh5eSkucmVkU3FyKCkucmVkSVN1Yih4eCkucmVkSVN1Yih5eXl5KTtcbiAgZSA9IGUucmVkSUFkZChlKTtcbiAgZSA9IGUucmVkQWRkKGUpLnJlZElBZGQoZSk7XG4gIGUgPSBlLnJlZElTdWIobW0pO1xuICAvLyBFRSA9IEVeMlxuICB2YXIgZWUgPSBlLnJlZFNxcigpO1xuICAvLyBUID0gMTYqWVlZWVxuICB2YXIgdCA9IHl5eXkucmVkSUFkZCh5eXl5KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgdCA9IHQucmVkSUFkZCh0KTtcbiAgLy8gVSA9IChNICsgRSleMiAtIE1NIC0gRUUgLSBUXG4gIHZhciB1ID0gbS5yZWRJQWRkKGUpLnJlZFNxcigpLnJlZElTdWIobW0pLnJlZElTdWIoZWUpLnJlZElTdWIodCk7XG4gIC8vIFgzID0gNCAqIChYMSAqIEVFIC0gNCAqIFlZICogVSlcbiAgdmFyIHl5dTQgPSB5eS5yZWRNdWwodSk7XG4gIHl5dTQgPSB5eXU0LnJlZElBZGQoeXl1NCk7XG4gIHl5dTQgPSB5eXU0LnJlZElBZGQoeXl1NCk7XG4gIHZhciBueCA9IHRoaXMueC5yZWRNdWwoZWUpLnJlZElTdWIoeXl1NCk7XG4gIG54ID0gbngucmVkSUFkZChueCk7XG4gIG54ID0gbngucmVkSUFkZChueCk7XG4gIC8vIFkzID0gOCAqIFkxICogKFUgKiAoVCAtIFUpIC0gRSAqIEVFKVxuICB2YXIgbnkgPSB0aGlzLnkucmVkTXVsKHUucmVkTXVsKHQucmVkSVN1Yih1KSkucmVkSVN1YihlLnJlZE11bChlZSkpKTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgbnkgPSBueS5yZWRJQWRkKG55KTtcbiAgLy8gWjMgPSAoWjEgKyBFKV4yIC0gWlogLSBFRVxuICB2YXIgbnogPSB0aGlzLnoucmVkQWRkKGUpLnJlZFNxcigpLnJlZElTdWIoenopLnJlZElTdWIoZWUpO1xuXG4gIHJldHVybiB0aGlzLmN1cnZlLmpwb2ludChueCwgbnksIG56KTtcbn07XG5cbkpQb2ludC5wcm90b3R5cGUubXVsID0gZnVuY3Rpb24gbXVsKGssIGtiYXNlKSB7XG4gIGsgPSBuZXcgQk4oaywga2Jhc2UpO1xuXG4gIHJldHVybiB0aGlzLmN1cnZlLl93bmFmTXVsKHRoaXMsIGspO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5lcSA9IGZ1bmN0aW9uIGVxKHApIHtcbiAgaWYgKHAudHlwZSA9PT0gJ2FmZmluZScpXG4gICAgcmV0dXJuIHRoaXMuZXEocC50b0ooKSk7XG5cbiAgaWYgKHRoaXMgPT09IHApXG4gICAgcmV0dXJuIHRydWU7XG5cbiAgLy8geDEgKiB6Ml4yID09IHgyICogejFeMlxuICB2YXIgejIgPSB0aGlzLnoucmVkU3FyKCk7XG4gIHZhciBwejIgPSBwLnoucmVkU3FyKCk7XG4gIGlmICh0aGlzLngucmVkTXVsKHB6MikucmVkSVN1YihwLngucmVkTXVsKHoyKSkuY21wbigwKSAhPT0gMClcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgLy8geTEgKiB6Ml4zID09IHkyICogejFeM1xuICB2YXIgejMgPSB6Mi5yZWRNdWwodGhpcy56KTtcbiAgdmFyIHB6MyA9IHB6Mi5yZWRNdWwocC56KTtcbiAgcmV0dXJuIHRoaXMueS5yZWRNdWwocHozKS5yZWRJU3ViKHAueS5yZWRNdWwoejMpKS5jbXBuKDApID09PSAwO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5pbnNwZWN0ID0gZnVuY3Rpb24gaW5zcGVjdCgpIHtcbiAgaWYgKHRoaXMuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiAnPEVDIEpQb2ludCBJbmZpbml0eT4nO1xuICByZXR1cm4gJzxFQyBKUG9pbnQgeDogJyArIHRoaXMueC50b1N0cmluZygxNiwgMikgK1xuICAgICAgJyB5OiAnICsgdGhpcy55LnRvU3RyaW5nKDE2LCAyKSArXG4gICAgICAnIHo6ICcgKyB0aGlzLnoudG9TdHJpbmcoMTYsIDIpICsgJz4nO1xufTtcblxuSlBvaW50LnByb3RvdHlwZS5pc0luZmluaXR5ID0gZnVuY3Rpb24gaXNJbmZpbml0eSgpIHtcbiAgLy8gWFhYIFRoaXMgY29kZSBhc3N1bWVzIHRoYXQgemVybyBpcyBhbHdheXMgemVybyBpbiByZWRcbiAgcmV0dXJuIHRoaXMuei5jbXBuKDApID09PSAwO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGN1cnZlcyA9IGV4cG9ydHM7XG5cbnZhciBoYXNoID0gcmVxdWlyZSgnaGFzaC5qcycpO1xudmFyIGVsbGlwdGljID0gcmVxdWlyZSgnLi4vZWxsaXB0aWMnKTtcblxudmFyIGFzc2VydCA9IGVsbGlwdGljLnV0aWxzLmFzc2VydDtcblxuZnVuY3Rpb24gUHJlc2V0Q3VydmUob3B0aW9ucykge1xuICBpZiAob3B0aW9ucy50eXBlID09PSAnc2hvcnQnKVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUuc2hvcnQob3B0aW9ucyk7XG4gIGVsc2UgaWYgKG9wdGlvbnMudHlwZSA9PT0gJ2Vkd2FyZHMnKVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUuZWR3YXJkcyhvcHRpb25zKTtcbiAgZWxzZVxuICAgIHRoaXMuY3VydmUgPSBuZXcgZWxsaXB0aWMuY3VydmUubW9udChvcHRpb25zKTtcbiAgdGhpcy5nID0gdGhpcy5jdXJ2ZS5nO1xuICB0aGlzLm4gPSB0aGlzLmN1cnZlLm47XG4gIHRoaXMuaGFzaCA9IG9wdGlvbnMuaGFzaDtcblxuICBhc3NlcnQodGhpcy5nLnZhbGlkYXRlKCksICdJbnZhbGlkIGN1cnZlJyk7XG4gIGFzc2VydCh0aGlzLmcubXVsKHRoaXMubikuaXNJbmZpbml0eSgpLCAnSW52YWxpZCBjdXJ2ZSwgRypOICE9IE8nKTtcbn1cbmN1cnZlcy5QcmVzZXRDdXJ2ZSA9IFByZXNldEN1cnZlO1xuXG5mdW5jdGlvbiBkZWZpbmVDdXJ2ZShuYW1lLCBvcHRpb25zKSB7XG4gIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjdXJ2ZXMsIG5hbWUsIHtcbiAgICBjb25maWd1cmFibGU6IHRydWUsXG4gICAgZW51bWVyYWJsZTogdHJ1ZSxcbiAgICBnZXQ6IGZ1bmN0aW9uKCkge1xuICAgICAgdmFyIGN1cnZlID0gbmV3IFByZXNldEN1cnZlKG9wdGlvbnMpO1xuICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGN1cnZlcywgbmFtZSwge1xuICAgICAgICBjb25maWd1cmFibGU6IHRydWUsXG4gICAgICAgIGVudW1lcmFibGU6IHRydWUsXG4gICAgICAgIHZhbHVlOiBjdXJ2ZVxuICAgICAgfSk7XG4gICAgICByZXR1cm4gY3VydmU7XG4gICAgfVxuICB9KTtcbn1cblxuZGVmaW5lQ3VydmUoJ3AxOTInLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiAncDE5MicsXG4gIHA6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmZicsXG4gIGE6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmYycsXG4gIGI6ICc2NDIxMDUxOSBlNTljODBlNyAwZmE3ZTlhYiA3MjI0MzA0OSBmZWI4ZGVlYyBjMTQ2YjliMScsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiA5OWRlZjgzNiAxNDZiYzliMSBiNGQyMjgzMScsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICcxODhkYTgwZSBiMDMwOTBmNiA3Y2JmMjBlYiA0M2ExODgwMCBmNGZmMGFmZCA4MmZmMTAxMicsXG4gICAgJzA3MTkyYjk1IGZmYzhkYTc4IDYzMTAxMWVkIDZiMjRjZGQ1IDczZjk3N2ExIDFlNzk0ODExJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3AyMjQnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiAncDIyNCcsXG4gIHA6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiAwMDAwMDAwMCAwMDAwMDAwMCAwMDAwMDAwMScsXG4gIGE6ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZScsXG4gIGI6ICdiNDA1MGE4NSAwYzA0YjNhYiBmNTQxMzI1NiA1MDQ0YjBiNyBkN2JmZDhiYSAyNzBiMzk0MyAyMzU1ZmZiNCcsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmMTZhMiBlMGI4ZjAzZSAxM2RkMjk0NSA1YzVjMmEzZCcsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICdiNzBlMGNiZCA2YmI0YmY3ZiAzMjEzOTBiOSA0YTAzYzFkMyA1NmMyMTEyMiAzNDMyODBkNiAxMTVjMWQyMScsXG4gICAgJ2JkMzc2Mzg4IGI1ZjcyM2ZiIDRjMjJkZmU2IGNkNDM3NWEwIDVhMDc0NzY0IDQ0ZDU4MTk5IDg1MDA3ZTM0J1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3AyNTYnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiBudWxsLFxuICBwOiAnZmZmZmZmZmYgMDAwMDAwMDEgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYnLFxuICBhOiAnZmZmZmZmZmYgMDAwMDAwMDEgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmMnLFxuICBiOiAnNWFjNjM1ZDggYWEzYTkzZTcgYjNlYmJkNTUgNzY5ODg2YmMgNjUxZDA2YjAgY2M1M2IwZjYgM2JjZTNjM2UgMjdkMjYwNGInLFxuICBuOiAnZmZmZmZmZmYgMDAwMDAwMDAgZmZmZmZmZmYgZmZmZmZmZmYgYmNlNmZhYWQgYTcxNzllODQgZjNiOWNhYzIgZmM2MzI1NTEnLFxuICBoYXNoOiBoYXNoLnNoYTI1NixcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnNmIxN2QxZjIgZTEyYzQyNDcgZjhiY2U2ZTUgNjNhNDQwZjIgNzcwMzdkODEgMmRlYjMzYTAgZjRhMTM5NDUgZDg5OGMyOTYnLFxuICAgICc0ZmUzNDJlMiBmZTFhN2Y5YiA4ZWU3ZWI0YSA3YzBmOWUxNiAyYmNlMzM1NyA2YjMxNWVjZSBjYmI2NDA2OCAzN2JmNTFmNSdcbiAgXVxufSk7XG5cbmRlZmluZUN1cnZlKCdwMzg0Jywge1xuICB0eXBlOiAnc2hvcnQnLFxuICBwcmltZTogbnVsbCxcbiAgcDogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmICcgK1xuICAgICAnZmZmZmZmZmUgZmZmZmZmZmYgMDAwMDAwMDAgMDAwMDAwMDAgZmZmZmZmZmYnLFxuICBhOiAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZSBmZmZmZmZmZiAwMDAwMDAwMCAwMDAwMDAwMCBmZmZmZmZmYycsXG4gIGI6ICdiMzMxMmZhNyBlMjNlZTdlNCA5ODhlMDU2YiBlM2Y4MmQxOSAxODFkOWM2ZSBmZTgxNDExMiAwMzE0MDg4ZiAnICtcbiAgICAgJzUwMTM4NzVhIGM2NTYzOThkIDhhMmVkMTlkIDJhODVjOGVkIGQzZWMyYWVmJyxcbiAgbjogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGM3NjM0ZDgxICcgK1xuICAgICAnZjQzNzJkZGYgNTgxYTBkYjIgNDhiMGE3N2EgZWNlYzE5NmEgY2NjNTI5NzMnLFxuICBoYXNoOiBoYXNoLnNoYTM4NCxcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnYWE4N2NhMjIgYmU4YjA1MzcgOGViMWM3MWUgZjMyMGFkNzQgNmUxZDNiNjIgOGJhNzliOTggNTlmNzQxZTAgODI1NDJhMzggJyArXG4gICAgJzU1MDJmMjVkIGJmNTUyOTZjIDNhNTQ1ZTM4IDcyNzYwYWI3JyxcbiAgICAnMzYxN2RlNGEgOTYyNjJjNmYgNWQ5ZTk4YmYgOTI5MmRjMjkgZjhmNDFkYmQgMjg5YTE0N2MgZTlkYTMxMTMgYjVmMGI4YzAgJyArXG4gICAgJzBhNjBiMWNlIDFkN2U4MTlkIDdhNDMxZDdjIDkwZWEwZTVmJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ3A1MjEnLCB7XG4gIHR5cGU6ICdzaG9ydCcsXG4gIHByaW1lOiBudWxsLFxuICBwOiAnMDAwMDAxZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiAnICtcbiAgICAgJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmJyxcbiAgYTogJzAwMDAwMWZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmICcgK1xuICAgICAnZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmYycsXG4gIGI6ICcwMDAwMDA1MSA5NTNlYjk2MSA4ZTFjOWExZiA5MjlhMjFhMCBiNjg1NDBlZSBhMmRhNzI1YiAnICtcbiAgICAgJzk5YjMxNWYzIGI4YjQ4OTkxIDhlZjEwOWUxIDU2MTkzOTUxIGVjN2U5MzdiIDE2NTJjMGJkICcgK1xuICAgICAnM2JiMWJmMDcgMzU3M2RmODggM2QyYzM0ZjEgZWY0NTFmZDQgNmI1MDNmMDAnLFxuICBuOiAnMDAwMDAxZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgZmZmZmZmZmYgJyArXG4gICAgICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmYSA1MTg2ODc4MyBiZjJmOTY2YiA3ZmNjMDE0OCAnICtcbiAgICAgJ2Y3MDlhNWQwIDNiYjVjOWI4IDg5OWM0N2FlIGJiNmZiNzFlIDkxMzg2NDA5JyxcbiAgaGFzaDogaGFzaC5zaGE1MTIsXG4gIGdSZWQ6IGZhbHNlLFxuICBnOiBbXG4gICAgJzAwMDAwMGM2IDg1OGUwNmI3IDA0MDRlOWNkIDllM2VjYjY2IDIzOTViNDQyIDljNjQ4MTM5ICcgK1xuICAgICcwNTNmYjUyMSBmODI4YWY2MCA2YjRkM2RiYSBhMTRiNWU3NyBlZmU3NTkyOCBmZTFkYzEyNyAnICtcbiAgICAnYTJmZmE4ZGUgMzM0OGIzYzEgODU2YTQyOWIgZjk3ZTdlMzEgYzJlNWJkNjYnLFxuICAgICcwMDAwMDExOCAzOTI5NmE3OCA5YTNiYzAwNCA1YzhhNWZiNCAyYzdkMWJkOSA5OGY1NDQ0OSAnICtcbiAgICAnNTc5YjQ0NjggMTdhZmJkMTcgMjczZTY2MmMgOTdlZTcyOTkgNWVmNDI2NDAgYzU1MGI5MDEgJyArXG4gICAgJzNmYWQwNzYxIDM1M2M3MDg2IGEyNzJjMjQwIDg4YmU5NDc2IDlmZDE2NjUwJ1xuICBdXG59KTtcblxuZGVmaW5lQ3VydmUoJ2N1cnZlMjU1MTknLCB7XG4gIHR5cGU6ICdtb250JyxcbiAgcHJpbWU6ICdwMjU1MTknLFxuICBwOiAnN2ZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZlZCcsXG4gIGE6ICc3NmQwNicsXG4gIGI6ICcwJyxcbiAgbjogJzEwMDAwMDAwMDAwMDAwMDAgMDAwMDAwMDAwMDAwMDAwMCAxNGRlZjlkZWEyZjc5Y2Q2IDU4MTI2MzFhNWNmNWQzZWQnLFxuICBoYXNoOiBoYXNoLnNoYTI1NixcbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnOSdcbiAgXVxufSk7XG5cbmRlZmluZUN1cnZlKCdlZDI1NTE5Jywge1xuICB0eXBlOiAnZWR3YXJkcycsXG4gIHByaW1lOiAncDI1NTE5JyxcbiAgcDogJzdmZmZmZmZmZmZmZmZmZmYgZmZmZmZmZmZmZmZmZmZmZiBmZmZmZmZmZmZmZmZmZmZmIGZmZmZmZmZmZmZmZmZmZWQnLFxuICBhOiAnLTEnLFxuICBjOiAnMScsXG4gIC8vIC0xMjE2NjUgKiAoMTIxNjY2XigtMSkpIChtb2QgUClcbiAgZDogJzUyMDM2Y2VlMmI2ZmZlNzMgOGNjNzQwNzk3Nzc5ZTg5OCAwMDcwMGE0ZDQxNDFkOGFiIDc1ZWI0ZGNhMTM1OTc4YTMnLFxuICBuOiAnMTAwMDAwMDAwMDAwMDAwMCAwMDAwMDAwMDAwMDAwMDAwIDE0ZGVmOWRlYTJmNzljZDYgNTgxMjYzMWE1Y2Y1ZDNlZCcsXG4gIGhhc2g6IGhhc2guc2hhMjU2LFxuICBnUmVkOiBmYWxzZSxcbiAgZzogW1xuICAgICcyMTY5MzZkM2NkNmU1M2ZlYzBhNGUyMzFmZGQ2ZGM1YzY5MmNjNzYwOTUyNWE3YjJjOTU2MmQ2MDhmMjVkNTFhJyxcblxuICAgIC8vIDQvNVxuICAgICc2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjU4J1xuICBdXG59KTtcblxudmFyIHByZTtcbnRyeSB7XG4gIHByZSA9IHJlcXVpcmUoJy4vcHJlY29tcHV0ZWQvc2VjcDI1NmsxJyk7XG59IGNhdGNoIChlKSB7XG4gIHByZSA9IHVuZGVmaW5lZDtcbn1cblxuZGVmaW5lQ3VydmUoJ3NlY3AyNTZrMScsIHtcbiAgdHlwZTogJ3Nob3J0JyxcbiAgcHJpbWU6ICdrMjU2JyxcbiAgcDogJ2ZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZmIGZmZmZmZmZlIGZmZmZmYzJmJyxcbiAgYTogJzAnLFxuICBiOiAnNycsXG4gIG46ICdmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZiBmZmZmZmZmZSBiYWFlZGNlNiBhZjQ4YTAzYiBiZmQyNWU4YyBkMDM2NDE0MScsXG4gIGg6ICcxJyxcbiAgaGFzaDogaGFzaC5zaGEyNTYsXG5cbiAgLy8gUHJlY29tcHV0ZWQgZW5kb21vcnBoaXNtXG4gIGJldGE6ICc3YWU5NmEyYjY1N2MwNzEwNmU2NDQ3OWVhYzM0MzRlOTljZjA0OTc1MTJmNTg5OTVjMTM5NmMyODcxOTUwMWVlJyxcbiAgbGFtYmRhOiAnNTM2M2FkNGNjMDVjMzBlMGE1MjYxYzAyODgxMjY0NWExMjJlMjJlYTIwODE2Njc4ZGYwMjk2N2MxYjIzYmQ3MicsXG4gIGJhc2lzOiBbXG4gICAge1xuICAgICAgYTogJzMwODZkMjIxYTdkNDZiY2RlODZjOTBlNDkyODRlYjE1JyxcbiAgICAgIGI6ICctZTQ0MzdlZDYwMTBlODgyODZmNTQ3ZmE5MGFiZmU0YzMnXG4gICAgfSxcbiAgICB7XG4gICAgICBhOiAnMTE0Y2E1MGY3YThlMmYzZjY1N2MxMTA4ZDlkNDRjZmQ4JyxcbiAgICAgIGI6ICczMDg2ZDIyMWE3ZDQ2YmNkZTg2YzkwZTQ5Mjg0ZWIxNSdcbiAgICB9XG4gIF0sXG5cbiAgZ1JlZDogZmFsc2UsXG4gIGc6IFtcbiAgICAnNzliZTY2N2VmOWRjYmJhYzU1YTA2Mjk1Y2U4NzBiMDcwMjliZmNkYjJkY2UyOGQ5NTlmMjgxNWIxNmY4MTc5OCcsXG4gICAgJzQ4M2FkYTc3MjZhM2M0NjU1ZGE0ZmJmYzBlMTEwOGE4ZmQxN2I0NDhhNjg1NTQxOTljNDdkMDhmZmIxMGQ0YjgnLFxuICAgIHByZVxuICBdXG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbnZhciBLZXlQYWlyID0gcmVxdWlyZSgnLi9rZXknKTtcbnZhciBTaWduYXR1cmUgPSByZXF1aXJlKCcuL3NpZ25hdHVyZScpO1xuXG5mdW5jdGlvbiBFQyhvcHRpb25zKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBFQykpXG4gICAgcmV0dXJuIG5ldyBFQyhvcHRpb25zKTtcblxuICAvLyBTaG9ydGN1dCBgZWxsaXB0aWMuZWMoY3VydmUtbmFtZSlgXG4gIGlmICh0eXBlb2Ygb3B0aW9ucyA9PT0gJ3N0cmluZycpIHtcbiAgICBhc3NlcnQoZWxsaXB0aWMuY3VydmVzLmhhc093blByb3BlcnR5KG9wdGlvbnMpLCAnVW5rbm93biBjdXJ2ZSAnICsgb3B0aW9ucyk7XG5cbiAgICBvcHRpb25zID0gZWxsaXB0aWMuY3VydmVzW29wdGlvbnNdO1xuICB9XG5cbiAgLy8gU2hvcnRjdXQgZm9yIGBlbGxpcHRpYy5lYyhlbGxpcHRpYy5jdXJ2ZXMuY3VydmVOYW1lKWBcbiAgaWYgKG9wdGlvbnMgaW5zdGFuY2VvZiBlbGxpcHRpYy5jdXJ2ZXMuUHJlc2V0Q3VydmUpXG4gICAgb3B0aW9ucyA9IHsgY3VydmU6IG9wdGlvbnMgfTtcblxuICB0aGlzLmN1cnZlID0gb3B0aW9ucy5jdXJ2ZS5jdXJ2ZTtcbiAgdGhpcy5uID0gdGhpcy5jdXJ2ZS5uO1xuICB0aGlzLm5oID0gdGhpcy5uLnVzaHJuKDEpO1xuICB0aGlzLmcgPSB0aGlzLmN1cnZlLmc7XG5cbiAgLy8gUG9pbnQgb24gY3VydmVcbiAgdGhpcy5nID0gb3B0aW9ucy5jdXJ2ZS5nO1xuICB0aGlzLmcucHJlY29tcHV0ZShvcHRpb25zLmN1cnZlLm4uYml0TGVuZ3RoKCkgKyAxKTtcblxuICAvLyBIYXNoIGZvciBmdW5jdGlvbiBmb3IgRFJCR1xuICB0aGlzLmhhc2ggPSBvcHRpb25zLmhhc2ggfHwgb3B0aW9ucy5jdXJ2ZS5oYXNoO1xufVxubW9kdWxlLmV4cG9ydHMgPSBFQztcblxuRUMucHJvdG90eXBlLmtleVBhaXIgPSBmdW5jdGlvbiBrZXlQYWlyKG9wdGlvbnMpIHtcbiAgcmV0dXJuIG5ldyBLZXlQYWlyKHRoaXMsIG9wdGlvbnMpO1xufTtcblxuRUMucHJvdG90eXBlLmtleUZyb21Qcml2YXRlID0gZnVuY3Rpb24ga2V5RnJvbVByaXZhdGUocHJpdiwgZW5jKSB7XG4gIHJldHVybiBLZXlQYWlyLmZyb21Qcml2YXRlKHRoaXMsIHByaXYsIGVuYyk7XG59O1xuXG5FQy5wcm90b3R5cGUua2V5RnJvbVB1YmxpYyA9IGZ1bmN0aW9uIGtleUZyb21QdWJsaWMocHViLCBlbmMpIHtcbiAgcmV0dXJuIEtleVBhaXIuZnJvbVB1YmxpYyh0aGlzLCBwdWIsIGVuYyk7XG59O1xuXG5FQy5wcm90b3R5cGUuZ2VuS2V5UGFpciA9IGZ1bmN0aW9uIGdlbktleVBhaXIob3B0aW9ucykge1xuICBpZiAoIW9wdGlvbnMpXG4gICAgb3B0aW9ucyA9IHt9O1xuXG4gIC8vIEluc3RhbnRpYXRlIEhtYWNfRFJCR1xuICB2YXIgZHJiZyA9IG5ldyBlbGxpcHRpYy5obWFjRFJCRyh7XG4gICAgaGFzaDogdGhpcy5oYXNoLFxuICAgIHBlcnM6IG9wdGlvbnMucGVycyxcbiAgICBlbnRyb3B5OiBvcHRpb25zLmVudHJvcHkgfHwgZWxsaXB0aWMucmFuZCh0aGlzLmhhc2guaG1hY1N0cmVuZ3RoKSxcbiAgICBub25jZTogdGhpcy5uLnRvQXJyYXkoKVxuICB9KTtcblxuICB2YXIgYnl0ZXMgPSB0aGlzLm4uYnl0ZUxlbmd0aCgpO1xuICB2YXIgbnMyID0gdGhpcy5uLnN1YihuZXcgQk4oMikpO1xuICBkbyB7XG4gICAgdmFyIHByaXYgPSBuZXcgQk4oZHJiZy5nZW5lcmF0ZShieXRlcykpO1xuICAgIGlmIChwcml2LmNtcChuczIpID4gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgcHJpdi5pYWRkbigxKTtcbiAgICByZXR1cm4gdGhpcy5rZXlGcm9tUHJpdmF0ZShwcml2KTtcbiAgfSB3aGlsZSAodHJ1ZSk7XG59O1xuXG5FQy5wcm90b3R5cGUuX3RydW5jYXRlVG9OID0gZnVuY3Rpb24gdHJ1bmNhdGVUb04obXNnLCB0cnVuY09ubHkpIHtcbiAgdmFyIGRlbHRhID0gbXNnLmJ5dGVMZW5ndGgoKSAqIDggLSB0aGlzLm4uYml0TGVuZ3RoKCk7XG4gIGlmIChkZWx0YSA+IDApXG4gICAgbXNnID0gbXNnLnVzaHJuKGRlbHRhKTtcbiAgaWYgKCF0cnVuY09ubHkgJiYgbXNnLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIG1zZy5zdWIodGhpcy5uKTtcbiAgZWxzZVxuICAgIHJldHVybiBtc2c7XG59O1xuXG5FQy5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obXNnLCBrZXksIGVuYywgb3B0aW9ucykge1xuICBpZiAodHlwZW9mIGVuYyA9PT0gJ29iamVjdCcpIHtcbiAgICBvcHRpb25zID0gZW5jO1xuICAgIGVuYyA9IG51bGw7XG4gIH1cbiAgaWYgKCFvcHRpb25zKVxuICAgIG9wdGlvbnMgPSB7fTtcblxuICBrZXkgPSB0aGlzLmtleUZyb21Qcml2YXRlKGtleSwgZW5jKTtcbiAgbXNnID0gdGhpcy5fdHJ1bmNhdGVUb04obmV3IEJOKG1zZywgMTYpKTtcblxuICAvLyBaZXJvLWV4dGVuZCBrZXkgdG8gcHJvdmlkZSBlbm91Z2ggZW50cm9weVxuICB2YXIgYnl0ZXMgPSB0aGlzLm4uYnl0ZUxlbmd0aCgpO1xuICB2YXIgYmtleSA9IGtleS5nZXRQcml2YXRlKCkudG9BcnJheSgnYmUnLCBieXRlcyk7XG5cbiAgLy8gWmVyby1leHRlbmQgbm9uY2UgdG8gaGF2ZSB0aGUgc2FtZSBieXRlIHNpemUgYXMgTlxuICB2YXIgbm9uY2UgPSBtc2cudG9BcnJheSgnYmUnLCBieXRlcyk7XG5cbiAgLy8gSW5zdGFudGlhdGUgSG1hY19EUkJHXG4gIHZhciBkcmJnID0gbmV3IGVsbGlwdGljLmhtYWNEUkJHKHtcbiAgICBoYXNoOiB0aGlzLmhhc2gsXG4gICAgZW50cm9weTogYmtleSxcbiAgICBub25jZTogbm9uY2UsXG4gICAgcGVyczogb3B0aW9ucy5wZXJzLFxuICAgIHBlcnNFbmM6IG9wdGlvbnMucGVyc0VuY1xuICB9KTtcblxuICAvLyBOdW1iZXIgb2YgYnl0ZXMgdG8gZ2VuZXJhdGVcbiAgdmFyIG5zMSA9IHRoaXMubi5zdWIobmV3IEJOKDEpKTtcblxuICBmb3IgKHZhciBpdGVyID0gMDsgdHJ1ZTsgaXRlcisrKSB7XG4gICAgdmFyIGsgPSBvcHRpb25zLmsgP1xuICAgICAgICBvcHRpb25zLmsoaXRlcikgOlxuICAgICAgICBuZXcgQk4oZHJiZy5nZW5lcmF0ZSh0aGlzLm4uYnl0ZUxlbmd0aCgpKSk7XG4gICAgayA9IHRoaXMuX3RydW5jYXRlVG9OKGssIHRydWUpO1xuICAgIGlmIChrLmNtcG4oMSkgPD0gMCB8fCBrLmNtcChuczEpID49IDApXG4gICAgICBjb250aW51ZTtcblxuICAgIHZhciBrcCA9IHRoaXMuZy5tdWwoayk7XG4gICAgaWYgKGtwLmlzSW5maW5pdHkoKSlcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIGtwWCA9IGtwLmdldFgoKTtcbiAgICB2YXIgciA9IGtwWC51bW9kKHRoaXMubik7XG4gICAgaWYgKHIuY21wbigwKSA9PT0gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIHMgPSBrLmludm0odGhpcy5uKS5tdWwoci5tdWwoa2V5LmdldFByaXZhdGUoKSkuaWFkZChtc2cpKTtcbiAgICBzID0gcy51bW9kKHRoaXMubik7XG4gICAgaWYgKHMuY21wbigwKSA9PT0gMClcbiAgICAgIGNvbnRpbnVlO1xuXG4gICAgdmFyIHJlY292ZXJ5UGFyYW0gPSAoa3AuZ2V0WSgpLmlzT2RkKCkgPyAxIDogMCkgfFxuICAgICAgICAgICAgICAgICAgICAgICAgKGtwWC5jbXAocikgIT09IDAgPyAyIDogMCk7XG5cbiAgICAvLyBVc2UgY29tcGxlbWVudCBvZiBgc2AsIGlmIGl0IGlzID4gYG4gLyAyYFxuICAgIGlmIChvcHRpb25zLmNhbm9uaWNhbCAmJiBzLmNtcCh0aGlzLm5oKSA+IDApIHtcbiAgICAgIHMgPSB0aGlzLm4uc3ViKHMpO1xuICAgICAgcmVjb3ZlcnlQYXJhbSBePSAxO1xuICAgIH1cblxuICAgIHJldHVybiBuZXcgU2lnbmF0dXJlKHsgcjogciwgczogcywgcmVjb3ZlcnlQYXJhbTogcmVjb3ZlcnlQYXJhbSB9KTtcbiAgfVxufTtcblxuRUMucHJvdG90eXBlLnZlcmlmeSA9IGZ1bmN0aW9uIHZlcmlmeShtc2csIHNpZ25hdHVyZSwga2V5LCBlbmMpIHtcbiAgbXNnID0gdGhpcy5fdHJ1bmNhdGVUb04obmV3IEJOKG1zZywgMTYpKTtcbiAga2V5ID0gdGhpcy5rZXlGcm9tUHVibGljKGtleSwgZW5jKTtcbiAgc2lnbmF0dXJlID0gbmV3IFNpZ25hdHVyZShzaWduYXR1cmUsICdoZXgnKTtcblxuICAvLyBQZXJmb3JtIHByaW1pdGl2ZSB2YWx1ZXMgdmFsaWRhdGlvblxuICB2YXIgciA9IHNpZ25hdHVyZS5yO1xuICB2YXIgcyA9IHNpZ25hdHVyZS5zO1xuICBpZiAoci5jbXBuKDEpIDwgMCB8fCByLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIGZhbHNlO1xuICBpZiAocy5jbXBuKDEpIDwgMCB8fCBzLmNtcCh0aGlzLm4pID49IDApXG4gICAgcmV0dXJuIGZhbHNlO1xuXG4gIC8vIFZhbGlkYXRlIHNpZ25hdHVyZVxuICB2YXIgc2ludiA9IHMuaW52bSh0aGlzLm4pO1xuICB2YXIgdTEgPSBzaW52Lm11bChtc2cpLnVtb2QodGhpcy5uKTtcbiAgdmFyIHUyID0gc2ludi5tdWwocikudW1vZCh0aGlzLm4pO1xuXG4gIHZhciBwID0gdGhpcy5nLm11bEFkZCh1MSwga2V5LmdldFB1YmxpYygpLCB1Mik7XG4gIGlmIChwLmlzSW5maW5pdHkoKSlcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIHAuZ2V0WCgpLnVtb2QodGhpcy5uKS5jbXAocikgPT09IDA7XG59O1xuXG5FQy5wcm90b3R5cGUucmVjb3ZlclB1YktleSA9IGZ1bmN0aW9uKG1zZywgc2lnbmF0dXJlLCBqLCBlbmMpIHtcbiAgYXNzZXJ0KCgzICYgaikgPT09IGosICdUaGUgcmVjb3ZlcnkgcGFyYW0gaXMgbW9yZSB0aGFuIHR3byBiaXRzJyk7XG4gIHNpZ25hdHVyZSA9IG5ldyBTaWduYXR1cmUoc2lnbmF0dXJlLCBlbmMpO1xuXG4gIHZhciBuID0gdGhpcy5uO1xuICB2YXIgZSA9IG5ldyBCTihtc2cpO1xuICB2YXIgciA9IHNpZ25hdHVyZS5yO1xuICB2YXIgcyA9IHNpZ25hdHVyZS5zO1xuXG4gIC8vIEEgc2V0IExTQiBzaWduaWZpZXMgdGhhdCB0aGUgeS1jb29yZGluYXRlIGlzIG9kZFxuICB2YXIgaXNZT2RkID0gaiAmIDE7XG4gIHZhciBpc1NlY29uZEtleSA9IGogPj4gMTtcbiAgaWYgKHIuY21wKHRoaXMuY3VydmUucC51bW9kKHRoaXMuY3VydmUubikpID49IDAgJiYgaXNTZWNvbmRLZXkpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gZmluZCBzZW5jb25kIGtleSBjYW5kaW5hdGUnKTtcblxuICAvLyAxLjEuIExldCB4ID0gciArIGpuLlxuICBpZiAoaXNTZWNvbmRLZXkpXG4gICAgciA9IHRoaXMuY3VydmUucG9pbnRGcm9tWChyLmFkZCh0aGlzLmN1cnZlLm4pLCBpc1lPZGQpO1xuICBlbHNlXG4gICAgciA9IHRoaXMuY3VydmUucG9pbnRGcm9tWChyLCBpc1lPZGQpO1xuXG4gIHZhciBlTmVnID0gbi5zdWIoZSk7XG5cbiAgLy8gMS42LjEgQ29tcHV0ZSBRID0gcl4tMSAoc1IgLSAgZUcpXG4gIC8vICAgICAgICAgICAgICAgUSA9IHJeLTEgKHNSICsgLWVHKVxuICB2YXIgckludiA9IHNpZ25hdHVyZS5yLmludm0obik7XG4gIHJldHVybiB0aGlzLmcubXVsQWRkKGVOZWcsIHIsIHMpLm11bChySW52KTtcbn07XG5cbkVDLnByb3RvdHlwZS5nZXRLZXlSZWNvdmVyeVBhcmFtID0gZnVuY3Rpb24oZSwgc2lnbmF0dXJlLCBRLCBlbmMpIHtcbiAgc2lnbmF0dXJlID0gbmV3IFNpZ25hdHVyZShzaWduYXR1cmUsIGVuYyk7XG4gIGlmIChzaWduYXR1cmUucmVjb3ZlcnlQYXJhbSAhPT0gbnVsbClcbiAgICByZXR1cm4gc2lnbmF0dXJlLnJlY292ZXJ5UGFyYW07XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcbiAgICB2YXIgUXByaW1lO1xuICAgIHRyeSB7XG4gICAgICBRcHJpbWUgPSB0aGlzLnJlY292ZXJQdWJLZXkoZSwgc2lnbmF0dXJlLCBpKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICBpZiAoUXByaW1lLmVxKFEpKVxuICAgICAgcmV0dXJuIGk7XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKCdVbmFibGUgdG8gZmluZCB2YWxpZCByZWNvdmVyeSBmYWN0b3InKTtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBCTiA9IHJlcXVpcmUoJ2JuLmpzJyk7XG5cbmZ1bmN0aW9uIEtleVBhaXIoZWMsIG9wdGlvbnMpIHtcbiAgdGhpcy5lYyA9IGVjO1xuICB0aGlzLnByaXYgPSBudWxsO1xuICB0aGlzLnB1YiA9IG51bGw7XG5cbiAgLy8gS2V5UGFpcihlYywgeyBwcml2OiAuLi4sIHB1YjogLi4uIH0pXG4gIGlmIChvcHRpb25zLnByaXYpXG4gICAgdGhpcy5faW1wb3J0UHJpdmF0ZShvcHRpb25zLnByaXYsIG9wdGlvbnMucHJpdkVuYyk7XG4gIGlmIChvcHRpb25zLnB1YilcbiAgICB0aGlzLl9pbXBvcnRQdWJsaWMob3B0aW9ucy5wdWIsIG9wdGlvbnMucHViRW5jKTtcbn1cbm1vZHVsZS5leHBvcnRzID0gS2V5UGFpcjtcblxuS2V5UGFpci5mcm9tUHVibGljID0gZnVuY3Rpb24gZnJvbVB1YmxpYyhlYywgcHViLCBlbmMpIHtcbiAgaWYgKHB1YiBpbnN0YW5jZW9mIEtleVBhaXIpXG4gICAgcmV0dXJuIHB1YjtcblxuICByZXR1cm4gbmV3IEtleVBhaXIoZWMsIHtcbiAgICBwdWI6IHB1YixcbiAgICBwdWJFbmM6IGVuY1xuICB9KTtcbn07XG5cbktleVBhaXIuZnJvbVByaXZhdGUgPSBmdW5jdGlvbiBmcm9tUHJpdmF0ZShlYywgcHJpdiwgZW5jKSB7XG4gIGlmIChwcml2IGluc3RhbmNlb2YgS2V5UGFpcilcbiAgICByZXR1cm4gcHJpdjtcblxuICByZXR1cm4gbmV3IEtleVBhaXIoZWMsIHtcbiAgICBwcml2OiBwcml2LFxuICAgIHByaXZFbmM6IGVuY1xuICB9KTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLnZhbGlkYXRlID0gZnVuY3Rpb24gdmFsaWRhdGUoKSB7XG4gIHZhciBwdWIgPSB0aGlzLmdldFB1YmxpYygpO1xuXG4gIGlmIChwdWIuaXNJbmZpbml0eSgpKVxuICAgIHJldHVybiB7IHJlc3VsdDogZmFsc2UsIHJlYXNvbjogJ0ludmFsaWQgcHVibGljIGtleScgfTtcbiAgaWYgKCFwdWIudmFsaWRhdGUoKSlcbiAgICByZXR1cm4geyByZXN1bHQ6IGZhbHNlLCByZWFzb246ICdQdWJsaWMga2V5IGlzIG5vdCBhIHBvaW50JyB9O1xuICBpZiAoIXB1Yi5tdWwodGhpcy5lYy5jdXJ2ZS5uKS5pc0luZmluaXR5KCkpXG4gICAgcmV0dXJuIHsgcmVzdWx0OiBmYWxzZSwgcmVhc29uOiAnUHVibGljIGtleSAqIE4gIT0gTycgfTtcblxuICByZXR1cm4geyByZXN1bHQ6IHRydWUsIHJlYXNvbjogbnVsbCB9O1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHVibGljID0gZnVuY3Rpb24gZ2V0UHVibGljKGNvbXBhY3QsIGVuYykge1xuICAvLyBjb21wYWN0IGlzIG9wdGlvbmFsIGFyZ3VtZW50XG4gIGlmICh0eXBlb2YgY29tcGFjdCA9PT0gJ3N0cmluZycpIHtcbiAgICBlbmMgPSBjb21wYWN0O1xuICAgIGNvbXBhY3QgPSBudWxsO1xuICB9XG5cbiAgaWYgKCF0aGlzLnB1YilcbiAgICB0aGlzLnB1YiA9IHRoaXMuZWMuZy5tdWwodGhpcy5wcml2KTtcblxuICBpZiAoIWVuYylcbiAgICByZXR1cm4gdGhpcy5wdWI7XG5cbiAgcmV0dXJuIHRoaXMucHViLmVuY29kZShlbmMsIGNvbXBhY3QpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHJpdmF0ZSA9IGZ1bmN0aW9uIGdldFByaXZhdGUoZW5jKSB7XG4gIGlmIChlbmMgPT09ICdoZXgnKVxuICAgIHJldHVybiB0aGlzLnByaXYudG9TdHJpbmcoMTYsIDIpO1xuICBlbHNlXG4gICAgcmV0dXJuIHRoaXMucHJpdjtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLl9pbXBvcnRQcml2YXRlID0gZnVuY3Rpb24gX2ltcG9ydFByaXZhdGUoa2V5LCBlbmMpIHtcbiAgdGhpcy5wcml2ID0gbmV3IEJOKGtleSwgZW5jIHx8IDE2KTtcblxuICAvLyBFbnN1cmUgdGhhdCB0aGUgcHJpdiB3b24ndCBiZSBiaWdnZXIgdGhhbiBuLCBvdGhlcndpc2Ugd2UgbWF5IGZhaWxcbiAgLy8gaW4gZml4ZWQgbXVsdGlwbGljYXRpb24gbWV0aG9kXG4gIHRoaXMucHJpdiA9IHRoaXMucHJpdi51bW9kKHRoaXMuZWMuY3VydmUubik7XG59O1xuXG5LZXlQYWlyLnByb3RvdHlwZS5faW1wb3J0UHVibGljID0gZnVuY3Rpb24gX2ltcG9ydFB1YmxpYyhrZXksIGVuYykge1xuICBpZiAoa2V5LnggfHwga2V5LnkpIHtcbiAgICB0aGlzLnB1YiA9IHRoaXMuZWMuY3VydmUucG9pbnQoa2V5LngsIGtleS55KTtcbiAgICByZXR1cm47XG4gIH1cbiAgdGhpcy5wdWIgPSB0aGlzLmVjLmN1cnZlLmRlY29kZVBvaW50KGtleSwgZW5jKTtcbn07XG5cbi8vIEVDREhcbktleVBhaXIucHJvdG90eXBlLmRlcml2ZSA9IGZ1bmN0aW9uIGRlcml2ZShwdWIpIHtcbiAgcmV0dXJuIHB1Yi5tdWwodGhpcy5wcml2KS5nZXRYKCk7XG59O1xuXG4vLyBFQ0RTQVxuS2V5UGFpci5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obXNnLCBlbmMsIG9wdGlvbnMpIHtcbiAgcmV0dXJuIHRoaXMuZWMuc2lnbihtc2csIHRoaXMsIGVuYywgb3B0aW9ucyk7XG59O1xuXG5LZXlQYWlyLnByb3RvdHlwZS52ZXJpZnkgPSBmdW5jdGlvbiB2ZXJpZnkobXNnLCBzaWduYXR1cmUpIHtcbiAgcmV0dXJuIHRoaXMuZWMudmVyaWZ5KG1zZywgc2lnbmF0dXJlLCB0aGlzKTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLmluc3BlY3QgPSBmdW5jdGlvbiBpbnNwZWN0KCkge1xuICByZXR1cm4gJzxLZXkgcHJpdjogJyArICh0aGlzLnByaXYgJiYgdGhpcy5wcml2LnRvU3RyaW5nKDE2LCAyKSkgK1xuICAgICAgICAgJyBwdWI6ICcgKyAodGhpcy5wdWIgJiYgdGhpcy5wdWIuaW5zcGVjdCgpKSArICcgPic7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgQk4gPSByZXF1aXJlKCdibi5qcycpO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBTaWduYXR1cmUob3B0aW9ucywgZW5jKSB7XG4gIGlmIChvcHRpb25zIGluc3RhbmNlb2YgU2lnbmF0dXJlKVxuICAgIHJldHVybiBvcHRpb25zO1xuXG4gIGlmICh0aGlzLl9pbXBvcnRERVIob3B0aW9ucywgZW5jKSlcbiAgICByZXR1cm47XG5cbiAgYXNzZXJ0KG9wdGlvbnMuciAmJiBvcHRpb25zLnMsICdTaWduYXR1cmUgd2l0aG91dCByIG9yIHMnKTtcbiAgdGhpcy5yID0gbmV3IEJOKG9wdGlvbnMuciwgMTYpO1xuICB0aGlzLnMgPSBuZXcgQk4ob3B0aW9ucy5zLCAxNik7XG4gIGlmIChvcHRpb25zLnJlY292ZXJ5UGFyYW0gPT09IHVuZGVmaW5lZClcbiAgICB0aGlzLnJlY292ZXJ5UGFyYW0gPSBudWxsO1xuICBlbHNlXG4gICAgdGhpcy5yZWNvdmVyeVBhcmFtID0gb3B0aW9ucy5yZWNvdmVyeVBhcmFtO1xufVxubW9kdWxlLmV4cG9ydHMgPSBTaWduYXR1cmU7XG5cbmZ1bmN0aW9uIFBvc2l0aW9uKCkge1xuICB0aGlzLnBsYWNlID0gMDtcbn1cblxuZnVuY3Rpb24gZ2V0TGVuZ3RoKGJ1ZiwgcCkge1xuICB2YXIgaW5pdGlhbCA9IGJ1ZltwLnBsYWNlKytdO1xuICBpZiAoIShpbml0aWFsICYgMHg4MCkpIHtcbiAgICByZXR1cm4gaW5pdGlhbDtcbiAgfVxuICB2YXIgb2N0ZXRMZW4gPSBpbml0aWFsICYgMHhmO1xuICB2YXIgdmFsID0gMDtcbiAgZm9yICh2YXIgaSA9IDAsIG9mZiA9IHAucGxhY2U7IGkgPCBvY3RldExlbjsgaSsrLCBvZmYrKykge1xuICAgIHZhbCA8PD0gODtcbiAgICB2YWwgfD0gYnVmW29mZl07XG4gIH1cbiAgcC5wbGFjZSA9IG9mZjtcbiAgcmV0dXJuIHZhbDtcbn1cblxuZnVuY3Rpb24gcm1QYWRkaW5nKGJ1Zikge1xuICB2YXIgaSA9IDA7XG4gIHZhciBsZW4gPSBidWYubGVuZ3RoIC0gMTtcbiAgd2hpbGUgKCFidWZbaV0gJiYgIShidWZbaSArIDFdICYgMHg4MCkgJiYgaSA8IGxlbikge1xuICAgIGkrKztcbiAgfVxuICBpZiAoaSA9PT0gMCkge1xuICAgIHJldHVybiBidWY7XG4gIH1cbiAgcmV0dXJuIGJ1Zi5zbGljZShpKTtcbn1cblxuU2lnbmF0dXJlLnByb3RvdHlwZS5faW1wb3J0REVSID0gZnVuY3Rpb24gX2ltcG9ydERFUihkYXRhLCBlbmMpIHtcbiAgZGF0YSA9IHV0aWxzLnRvQXJyYXkoZGF0YSwgZW5jKTtcbiAgdmFyIHAgPSBuZXcgUG9zaXRpb24oKTtcbiAgaWYgKGRhdGFbcC5wbGFjZSsrXSAhPT0gMHgzMCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICB2YXIgbGVuID0gZ2V0TGVuZ3RoKGRhdGEsIHApO1xuICBpZiAoKGxlbiArIHAucGxhY2UpICE9PSBkYXRhLmxlbmd0aCkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICBpZiAoZGF0YVtwLnBsYWNlKytdICE9PSAweDAyKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIHZhciBybGVuID0gZ2V0TGVuZ3RoKGRhdGEsIHApO1xuICB2YXIgciA9IGRhdGEuc2xpY2UocC5wbGFjZSwgcmxlbiArIHAucGxhY2UpO1xuICBwLnBsYWNlICs9IHJsZW47XG4gIGlmIChkYXRhW3AucGxhY2UrK10gIT09IDB4MDIpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgdmFyIHNsZW4gPSBnZXRMZW5ndGgoZGF0YSwgcCk7XG4gIGlmIChkYXRhLmxlbmd0aCAhPT0gc2xlbiArIHAucGxhY2UpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgdmFyIHMgPSBkYXRhLnNsaWNlKHAucGxhY2UsIHNsZW4gKyBwLnBsYWNlKTtcbiAgaWYgKHJbMF0gPT09IDAgJiYgKHJbMV0gJiAweDgwKSkge1xuICAgIHIgPSByLnNsaWNlKDEpO1xuICB9XG4gIGlmIChzWzBdID09PSAwICYmIChzWzFdICYgMHg4MCkpIHtcbiAgICBzID0gcy5zbGljZSgxKTtcbiAgfVxuXG4gIHRoaXMuciA9IG5ldyBCTihyKTtcbiAgdGhpcy5zID0gbmV3IEJOKHMpO1xuICB0aGlzLnJlY292ZXJ5UGFyYW0gPSBudWxsO1xuXG4gIHJldHVybiB0cnVlO1xufTtcblxuZnVuY3Rpb24gY29uc3RydWN0TGVuZ3RoKGFyciwgbGVuKSB7XG4gIGlmIChsZW4gPCAweDgwKSB7XG4gICAgYXJyLnB1c2gobGVuKTtcbiAgICByZXR1cm47XG4gIH1cbiAgdmFyIG9jdGV0cyA9IDEgKyAoTWF0aC5sb2cobGVuKSAvIE1hdGguTE4yID4+PiAzKTtcbiAgYXJyLnB1c2gob2N0ZXRzIHwgMHg4MCk7XG4gIHdoaWxlICgtLW9jdGV0cykge1xuICAgIGFyci5wdXNoKChsZW4gPj4+IChvY3RldHMgPDwgMykpICYgMHhmZik7XG4gIH1cbiAgYXJyLnB1c2gobGVuKTtcbn1cblxuU2lnbmF0dXJlLnByb3RvdHlwZS50b0RFUiA9IGZ1bmN0aW9uIHRvREVSKGVuYykge1xuICB2YXIgciA9IHRoaXMuci50b0FycmF5KCk7XG4gIHZhciBzID0gdGhpcy5zLnRvQXJyYXkoKTtcblxuICAvLyBQYWQgdmFsdWVzXG4gIGlmIChyWzBdICYgMHg4MClcbiAgICByID0gWyAwIF0uY29uY2F0KHIpO1xuICAvLyBQYWQgdmFsdWVzXG4gIGlmIChzWzBdICYgMHg4MClcbiAgICBzID0gWyAwIF0uY29uY2F0KHMpO1xuXG4gIHIgPSBybVBhZGRpbmcocik7XG4gIHMgPSBybVBhZGRpbmcocyk7XG5cbiAgd2hpbGUgKCFzWzBdICYmICEoc1sxXSAmIDB4ODApKSB7XG4gICAgcyA9IHMuc2xpY2UoMSk7XG4gIH1cbiAgdmFyIGFyciA9IFsgMHgwMiBdO1xuICBjb25zdHJ1Y3RMZW5ndGgoYXJyLCByLmxlbmd0aCk7XG4gIGFyciA9IGFyci5jb25jYXQocik7XG4gIGFyci5wdXNoKDB4MDIpO1xuICBjb25zdHJ1Y3RMZW5ndGgoYXJyLCBzLmxlbmd0aCk7XG4gIHZhciBiYWNrSGFsZiA9IGFyci5jb25jYXQocyk7XG4gIHZhciByZXMgPSBbIDB4MzAgXTtcbiAgY29uc3RydWN0TGVuZ3RoKHJlcywgYmFja0hhbGYubGVuZ3RoKTtcbiAgcmVzID0gcmVzLmNvbmNhdChiYWNrSGFsZik7XG4gIHJldHVybiB1dGlscy5lbmNvZGUocmVzLCBlbmMpO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGhhc2ggPSByZXF1aXJlKCdoYXNoLmpzJyk7XG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xudmFyIHBhcnNlQnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzO1xudmFyIEtleVBhaXIgPSByZXF1aXJlKCcuL2tleScpO1xudmFyIFNpZ25hdHVyZSA9IHJlcXVpcmUoJy4vc2lnbmF0dXJlJyk7XG5cbmZ1bmN0aW9uIEVERFNBKGN1cnZlKSB7XG4gIGFzc2VydChjdXJ2ZSA9PT0gJ2VkMjU1MTknLCAnb25seSB0ZXN0ZWQgd2l0aCBlZDI1NTE5IHNvIGZhcicpO1xuXG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBFRERTQSkpXG4gICAgcmV0dXJuIG5ldyBFRERTQShjdXJ2ZSk7XG5cbiAgdmFyIGN1cnZlID0gZWxsaXB0aWMuY3VydmVzW2N1cnZlXS5jdXJ2ZTtcbiAgdGhpcy5jdXJ2ZSA9IGN1cnZlO1xuICB0aGlzLmcgPSBjdXJ2ZS5nO1xuICB0aGlzLmcucHJlY29tcHV0ZShjdXJ2ZS5uLmJpdExlbmd0aCgpICsgMSk7XG5cbiAgdGhpcy5wb2ludENsYXNzID0gY3VydmUucG9pbnQoKS5jb25zdHJ1Y3RvcjtcbiAgdGhpcy5lbmNvZGluZ0xlbmd0aCA9IE1hdGguY2VpbChjdXJ2ZS5uLmJpdExlbmd0aCgpIC8gOCk7XG4gIHRoaXMuaGFzaCA9IGhhc2guc2hhNTEyO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IEVERFNBO1xuXG4vKipcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd9IG1lc3NhZ2UgLSBtZXNzYWdlIGJ5dGVzXG4qIEBwYXJhbSB7QXJyYXl8U3RyaW5nfEtleVBhaXJ9IHNlY3JldCAtIHNlY3JldCBieXRlcyBvciBhIGtleXBhaXJcbiogQHJldHVybnMge1NpZ25hdHVyZX0gLSBzaWduYXR1cmVcbiovXG5FRERTQS5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIHNpZ24obWVzc2FnZSwgc2VjcmV0KSB7XG4gIG1lc3NhZ2UgPSBwYXJzZUJ5dGVzKG1lc3NhZ2UpO1xuICB2YXIga2V5ID0gdGhpcy5rZXlGcm9tU2VjcmV0KHNlY3JldCk7XG4gIHZhciByID0gdGhpcy5oYXNoSW50KGtleS5tZXNzYWdlUHJlZml4KCksIG1lc3NhZ2UpO1xuICB2YXIgUiA9IHRoaXMuZy5tdWwocik7XG4gIHZhciBSZW5jb2RlZCA9IHRoaXMuZW5jb2RlUG9pbnQoUik7XG4gIHZhciBzXyA9IHRoaXMuaGFzaEludChSZW5jb2RlZCwga2V5LnB1YkJ5dGVzKCksIG1lc3NhZ2UpXG4gICAgICAgICAgICAgICAubXVsKGtleS5wcml2KCkpO1xuICB2YXIgUyA9IHIuYWRkKHNfKS51bW9kKHRoaXMuY3VydmUubik7XG4gIHJldHVybiB0aGlzLm1ha2VTaWduYXR1cmUoeyBSOiBSLCBTOiBTLCBSZW5jb2RlZDogUmVuY29kZWQgfSk7XG59O1xuXG4vKipcbiogQHBhcmFtIHtBcnJheX0gbWVzc2FnZSAtIG1lc3NhZ2UgYnl0ZXNcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd8U2lnbmF0dXJlfSBzaWcgLSBzaWcgYnl0ZXNcbiogQHBhcmFtIHtBcnJheXxTdHJpbmd8UG9pbnR8S2V5UGFpcn0gcHViIC0gcHVibGljIGtleVxuKiBAcmV0dXJucyB7Qm9vbGVhbn0gLSB0cnVlIGlmIHB1YmxpYyBrZXkgbWF0Y2hlcyBzaWcgb2YgbWVzc2FnZVxuKi9cbkVERFNBLnByb3RvdHlwZS52ZXJpZnkgPSBmdW5jdGlvbiB2ZXJpZnkobWVzc2FnZSwgc2lnLCBwdWIpIHtcbiAgbWVzc2FnZSA9IHBhcnNlQnl0ZXMobWVzc2FnZSk7XG4gIHNpZyA9IHRoaXMubWFrZVNpZ25hdHVyZShzaWcpO1xuICB2YXIga2V5ID0gdGhpcy5rZXlGcm9tUHVibGljKHB1Yik7XG4gIHZhciBoID0gdGhpcy5oYXNoSW50KHNpZy5SZW5jb2RlZCgpLCBrZXkucHViQnl0ZXMoKSwgbWVzc2FnZSk7XG4gIHZhciBTRyA9IHRoaXMuZy5tdWwoc2lnLlMoKSk7XG4gIHZhciBScGx1c0FoID0gc2lnLlIoKS5hZGQoa2V5LnB1YigpLm11bChoKSk7XG4gIHJldHVybiBScGx1c0FoLmVxKFNHKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5oYXNoSW50ID0gZnVuY3Rpb24gaGFzaEludCgpIHtcbiAgdmFyIGhhc2ggPSB0aGlzLmhhc2goKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXG4gICAgaGFzaC51cGRhdGUoYXJndW1lbnRzW2ldKTtcbiAgcmV0dXJuIHV0aWxzLmludEZyb21MRShoYXNoLmRpZ2VzdCgpKS51bW9kKHRoaXMuY3VydmUubik7XG59O1xuXG5FRERTQS5wcm90b3R5cGUua2V5RnJvbVB1YmxpYyA9IGZ1bmN0aW9uIGtleUZyb21QdWJsaWMocHViKSB7XG4gIHJldHVybiBLZXlQYWlyLmZyb21QdWJsaWModGhpcywgcHViKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5rZXlGcm9tU2VjcmV0ID0gZnVuY3Rpb24ga2V5RnJvbVNlY3JldChzZWNyZXQpIHtcbiAgcmV0dXJuIEtleVBhaXIuZnJvbVNlY3JldCh0aGlzLCBzZWNyZXQpO1xufTtcblxuRUREU0EucHJvdG90eXBlLm1ha2VTaWduYXR1cmUgPSBmdW5jdGlvbiBtYWtlU2lnbmF0dXJlKHNpZykge1xuICBpZiAoc2lnIGluc3RhbmNlb2YgU2lnbmF0dXJlKVxuICAgIHJldHVybiBzaWc7XG4gIHJldHVybiBuZXcgU2lnbmF0dXJlKHRoaXMsIHNpZyk7XG59O1xuXG4vKipcbiogKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvZHJhZnQtam9zZWZzc29uLWVkZHNhLWVkMjU1MTktMDMjc2VjdGlvbi01LjJcbipcbiogRUREU0EgZGVmaW5lcyBtZXRob2RzIGZvciBlbmNvZGluZyBhbmQgZGVjb2RpbmcgcG9pbnRzIGFuZCBpbnRlZ2Vycy4gVGhlc2UgYXJlXG4qIGhlbHBlciBjb252ZW5pZW5jZSBtZXRob2RzLCB0aGF0IHBhc3MgYWxvbmcgdG8gdXRpbGl0eSBmdW5jdGlvbnMgaW1wbGllZFxuKiBwYXJhbWV0ZXJzLlxuKlxuKi9cbkVERFNBLnByb3RvdHlwZS5lbmNvZGVQb2ludCA9IGZ1bmN0aW9uIGVuY29kZVBvaW50KHBvaW50KSB7XG4gIHZhciBlbmMgPSBwb2ludC5nZXRZKCkudG9BcnJheSgnbGUnLCB0aGlzLmVuY29kaW5nTGVuZ3RoKTtcbiAgZW5jW3RoaXMuZW5jb2RpbmdMZW5ndGggLSAxXSB8PSBwb2ludC5nZXRYKCkuaXNPZGQoKSA/IDB4ODAgOiAwO1xuICByZXR1cm4gZW5jO1xufTtcblxuRUREU0EucHJvdG90eXBlLmRlY29kZVBvaW50ID0gZnVuY3Rpb24gZGVjb2RlUG9pbnQoYnl0ZXMpIHtcbiAgYnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzKGJ5dGVzKTtcblxuICB2YXIgbGFzdEl4ID0gYnl0ZXMubGVuZ3RoIC0gMTtcbiAgdmFyIG5vcm1lZCA9IGJ5dGVzLnNsaWNlKDAsIGxhc3RJeCkuY29uY2F0KGJ5dGVzW2xhc3RJeF0gJiB+MHg4MCk7XG4gIHZhciB4SXNPZGQgPSAoYnl0ZXNbbGFzdEl4XSAmIDB4ODApICE9PSAwO1xuXG4gIHZhciB5ID0gdXRpbHMuaW50RnJvbUxFKG5vcm1lZCk7XG4gIHJldHVybiB0aGlzLmN1cnZlLnBvaW50RnJvbVkoeSwgeElzT2RkKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5lbmNvZGVJbnQgPSBmdW5jdGlvbiBlbmNvZGVJbnQobnVtKSB7XG4gIHJldHVybiBudW0udG9BcnJheSgnbGUnLCB0aGlzLmVuY29kaW5nTGVuZ3RoKTtcbn07XG5cbkVERFNBLnByb3RvdHlwZS5kZWNvZGVJbnQgPSBmdW5jdGlvbiBkZWNvZGVJbnQoYnl0ZXMpIHtcbiAgcmV0dXJuIHV0aWxzLmludEZyb21MRShieXRlcyk7XG59O1xuXG5FRERTQS5wcm90b3R5cGUuaXNQb2ludCA9IGZ1bmN0aW9uIGlzUG9pbnQodmFsKSB7XG4gIHJldHVybiB2YWwgaW5zdGFuY2VvZiB0aGlzLnBvaW50Q2xhc3M7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgZWxsaXB0aWMgPSByZXF1aXJlKCcuLi8uLi9lbGxpcHRpYycpO1xudmFyIHV0aWxzID0gZWxsaXB0aWMudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xudmFyIHBhcnNlQnl0ZXMgPSB1dGlscy5wYXJzZUJ5dGVzO1xudmFyIGNhY2hlZFByb3BlcnR5ID0gdXRpbHMuY2FjaGVkUHJvcGVydHk7XG5cbi8qKlxuKiBAcGFyYW0ge0VERFNBfSBlZGRzYSAtIGluc3RhbmNlXG4qIEBwYXJhbSB7T2JqZWN0fSBwYXJhbXMgLSBwdWJsaWMvcHJpdmF0ZSBrZXkgcGFyYW1ldGVyc1xuKlxuKiBAcGFyYW0ge0FycmF5PEJ5dGU+fSBbcGFyYW1zLnNlY3JldF0gLSBzZWNyZXQgc2VlZCBieXRlc1xuKiBAcGFyYW0ge1BvaW50fSBbcGFyYW1zLnB1Yl0gLSBwdWJsaWMga2V5IHBvaW50IChha2EgYEFgIGluIGVkZHNhIHRlcm1zKVxuKiBAcGFyYW0ge0FycmF5PEJ5dGU+fSBbcGFyYW1zLnB1Yl0gLSBwdWJsaWMga2V5IHBvaW50IGVuY29kZWQgYXMgYnl0ZXNcbipcbiovXG5mdW5jdGlvbiBLZXlQYWlyKGVkZHNhLCBwYXJhbXMpIHtcbiAgdGhpcy5lZGRzYSA9IGVkZHNhO1xuICB0aGlzLl9zZWNyZXQgPSBwYXJzZUJ5dGVzKHBhcmFtcy5zZWNyZXQpO1xuICBpZiAoZWRkc2EuaXNQb2ludChwYXJhbXMucHViKSlcbiAgICB0aGlzLl9wdWIgPSBwYXJhbXMucHViO1xuICBlbHNlXG4gICAgdGhpcy5fcHViQnl0ZXMgPSBwYXJzZUJ5dGVzKHBhcmFtcy5wdWIpO1xufVxuXG5LZXlQYWlyLmZyb21QdWJsaWMgPSBmdW5jdGlvbiBmcm9tUHVibGljKGVkZHNhLCBwdWIpIHtcbiAgaWYgKHB1YiBpbnN0YW5jZW9mIEtleVBhaXIpXG4gICAgcmV0dXJuIHB1YjtcbiAgcmV0dXJuIG5ldyBLZXlQYWlyKGVkZHNhLCB7IHB1YjogcHViIH0pO1xufTtcblxuS2V5UGFpci5mcm9tU2VjcmV0ID0gZnVuY3Rpb24gZnJvbVNlY3JldChlZGRzYSwgc2VjcmV0KSB7XG4gIGlmIChzZWNyZXQgaW5zdGFuY2VvZiBLZXlQYWlyKVxuICAgIHJldHVybiBzZWNyZXQ7XG4gIHJldHVybiBuZXcgS2V5UGFpcihlZGRzYSwgeyBzZWNyZXQ6IHNlY3JldCB9KTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLnNlY3JldCA9IGZ1bmN0aW9uIHNlY3JldCgpIHtcbiAgcmV0dXJuIHRoaXMuX3NlY3JldDtcbn07XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdwdWJCeXRlcycsIGZ1bmN0aW9uIHB1YkJ5dGVzKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5lbmNvZGVQb2ludCh0aGlzLnB1YigpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShLZXlQYWlyLCAncHViJywgZnVuY3Rpb24gcHViKCkge1xuICBpZiAodGhpcy5fcHViQnl0ZXMpXG4gICAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlUG9pbnQodGhpcy5fcHViQnl0ZXMpO1xuICByZXR1cm4gdGhpcy5lZGRzYS5nLm11bCh0aGlzLnByaXYoKSk7XG59KTtcblxuY2FjaGVkUHJvcGVydHkoS2V5UGFpciwgJ3ByaXZCeXRlcycsIGZ1bmN0aW9uIHByaXZCeXRlcygpIHtcbiAgdmFyIGVkZHNhID0gdGhpcy5lZGRzYTtcbiAgdmFyIGhhc2ggPSB0aGlzLmhhc2goKTtcbiAgdmFyIGxhc3RJeCA9IGVkZHNhLmVuY29kaW5nTGVuZ3RoIC0gMTtcblxuICB2YXIgYSA9IGhhc2guc2xpY2UoMCwgZWRkc2EuZW5jb2RpbmdMZW5ndGgpO1xuICBhWzBdICY9IDI0ODtcbiAgYVtsYXN0SXhdICY9IDEyNztcbiAgYVtsYXN0SXhdIHw9IDY0O1xuXG4gIHJldHVybiBhO1xufSk7XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdwcml2JywgZnVuY3Rpb24gcHJpdigpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlSW50KHRoaXMucHJpdkJ5dGVzKCkpO1xufSk7XG5cbmNhY2hlZFByb3BlcnR5KEtleVBhaXIsICdoYXNoJywgZnVuY3Rpb24gaGFzaCgpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuaGFzaCgpLnVwZGF0ZSh0aGlzLnNlY3JldCgpKS5kaWdlc3QoKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShLZXlQYWlyLCAnbWVzc2FnZVByZWZpeCcsIGZ1bmN0aW9uIG1lc3NhZ2VQcmVmaXgoKSB7XG4gIHJldHVybiB0aGlzLmhhc2goKS5zbGljZSh0aGlzLmVkZHNhLmVuY29kaW5nTGVuZ3RoKTtcbn0pO1xuXG5LZXlQYWlyLnByb3RvdHlwZS5zaWduID0gZnVuY3Rpb24gc2lnbihtZXNzYWdlKSB7XG4gIGFzc2VydCh0aGlzLl9zZWNyZXQsICdLZXlQYWlyIGNhbiBvbmx5IHZlcmlmeScpO1xuICByZXR1cm4gdGhpcy5lZGRzYS5zaWduKG1lc3NhZ2UsIHRoaXMpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUudmVyaWZ5ID0gZnVuY3Rpb24gdmVyaWZ5KG1lc3NhZ2UsIHNpZykge1xuICByZXR1cm4gdGhpcy5lZGRzYS52ZXJpZnkobWVzc2FnZSwgc2lnLCB0aGlzKTtcbn07XG5cbktleVBhaXIucHJvdG90eXBlLmdldFNlY3JldCA9IGZ1bmN0aW9uIGdldFNlY3JldChlbmMpIHtcbiAgYXNzZXJ0KHRoaXMuX3NlY3JldCwgJ0tleVBhaXIgaXMgcHVibGljIG9ubHknKTtcbiAgcmV0dXJuIHV0aWxzLmVuY29kZSh0aGlzLnNlY3JldCgpLCBlbmMpO1xufTtcblxuS2V5UGFpci5wcm90b3R5cGUuZ2V0UHVibGljID0gZnVuY3Rpb24gZ2V0UHVibGljKGVuYykge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMucHViQnl0ZXMoKSwgZW5jKTtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gS2V5UGFpcjtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uLy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG52YXIgY2FjaGVkUHJvcGVydHkgPSB1dGlscy5jYWNoZWRQcm9wZXJ0eTtcbnZhciBwYXJzZUJ5dGVzID0gdXRpbHMucGFyc2VCeXRlcztcblxuLyoqXG4qIEBwYXJhbSB7RUREU0F9IGVkZHNhIC0gZWRkc2EgaW5zdGFuY2VcbiogQHBhcmFtIHtBcnJheTxCeXRlcz58T2JqZWN0fSBzaWcgLVxuKiBAcGFyYW0ge0FycmF5PEJ5dGVzPnxQb2ludH0gW3NpZy5SXSAtIFIgcG9pbnQgYXMgUG9pbnQgb3IgYnl0ZXNcbiogQHBhcmFtIHtBcnJheTxCeXRlcz58Ym59IFtzaWcuU10gLSBTIHNjYWxhciBhcyBibiBvciBieXRlc1xuKiBAcGFyYW0ge0FycmF5PEJ5dGVzPn0gW3NpZy5SZW5jb2RlZF0gLSBSIHBvaW50IGVuY29kZWRcbiogQHBhcmFtIHtBcnJheTxCeXRlcz59IFtzaWcuU2VuY29kZWRdIC0gUyBzY2FsYXIgZW5jb2RlZFxuKi9cbmZ1bmN0aW9uIFNpZ25hdHVyZShlZGRzYSwgc2lnKSB7XG4gIHRoaXMuZWRkc2EgPSBlZGRzYTtcblxuICBpZiAodHlwZW9mIHNpZyAhPT0gJ29iamVjdCcpXG4gICAgc2lnID0gcGFyc2VCeXRlcyhzaWcpO1xuXG4gIGlmIChBcnJheS5pc0FycmF5KHNpZykpIHtcbiAgICBzaWcgPSB7XG4gICAgICBSOiBzaWcuc2xpY2UoMCwgZWRkc2EuZW5jb2RpbmdMZW5ndGgpLFxuICAgICAgUzogc2lnLnNsaWNlKGVkZHNhLmVuY29kaW5nTGVuZ3RoKVxuICAgIH07XG4gIH1cblxuICBhc3NlcnQoc2lnLlIgJiYgc2lnLlMsICdTaWduYXR1cmUgd2l0aG91dCBSIG9yIFMnKTtcblxuICBpZiAoZWRkc2EuaXNQb2ludChzaWcuUikpXG4gICAgdGhpcy5fUiA9IHNpZy5SO1xuICBpZiAoc2lnLlMgaW5zdGFuY2VvZiBCTilcbiAgICB0aGlzLl9TID0gc2lnLlM7XG5cbiAgdGhpcy5fUmVuY29kZWQgPSBBcnJheS5pc0FycmF5KHNpZy5SKSA/IHNpZy5SIDogc2lnLlJlbmNvZGVkO1xuICB0aGlzLl9TZW5jb2RlZCA9IEFycmF5LmlzQXJyYXkoc2lnLlMpID8gc2lnLlMgOiBzaWcuU2VuY29kZWQ7XG59XG5cbmNhY2hlZFByb3BlcnR5KFNpZ25hdHVyZSwgJ1MnLCBmdW5jdGlvbiBTKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5kZWNvZGVJbnQodGhpcy5TZW5jb2RlZCgpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShTaWduYXR1cmUsICdSJywgZnVuY3Rpb24gUigpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZGVjb2RlUG9pbnQodGhpcy5SZW5jb2RlZCgpKTtcbn0pO1xuXG5jYWNoZWRQcm9wZXJ0eShTaWduYXR1cmUsICdSZW5jb2RlZCcsIGZ1bmN0aW9uIFJlbmNvZGVkKCkge1xuICByZXR1cm4gdGhpcy5lZGRzYS5lbmNvZGVQb2ludCh0aGlzLlIoKSk7XG59KTtcblxuY2FjaGVkUHJvcGVydHkoU2lnbmF0dXJlLCAnU2VuY29kZWQnLCBmdW5jdGlvbiBTZW5jb2RlZCgpIHtcbiAgcmV0dXJuIHRoaXMuZWRkc2EuZW5jb2RlSW50KHRoaXMuUygpKTtcbn0pO1xuXG5TaWduYXR1cmUucHJvdG90eXBlLnRvQnl0ZXMgPSBmdW5jdGlvbiB0b0J5dGVzKCkge1xuICByZXR1cm4gdGhpcy5SZW5jb2RlZCgpLmNvbmNhdCh0aGlzLlNlbmNvZGVkKCkpO1xufTtcblxuU2lnbmF0dXJlLnByb3RvdHlwZS50b0hleCA9IGZ1bmN0aW9uIHRvSGV4KCkge1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHRoaXMudG9CeXRlcygpLCAnaGV4JykudG9VcHBlckNhc2UoKTtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gU2lnbmF0dXJlO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgaGFzaCA9IHJlcXVpcmUoJ2hhc2guanMnKTtcbnZhciBlbGxpcHRpYyA9IHJlcXVpcmUoJy4uL2VsbGlwdGljJyk7XG52YXIgdXRpbHMgPSBlbGxpcHRpYy51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbmZ1bmN0aW9uIEhtYWNEUkJHKG9wdGlvbnMpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIEhtYWNEUkJHKSlcbiAgICByZXR1cm4gbmV3IEhtYWNEUkJHKG9wdGlvbnMpO1xuICB0aGlzLmhhc2ggPSBvcHRpb25zLmhhc2g7XG4gIHRoaXMucHJlZFJlc2lzdCA9ICEhb3B0aW9ucy5wcmVkUmVzaXN0O1xuXG4gIHRoaXMub3V0TGVuID0gdGhpcy5oYXNoLm91dFNpemU7XG4gIHRoaXMubWluRW50cm9weSA9IG9wdGlvbnMubWluRW50cm9weSB8fCB0aGlzLmhhc2guaG1hY1N0cmVuZ3RoO1xuXG4gIHRoaXMucmVzZWVkID0gbnVsbDtcbiAgdGhpcy5yZXNlZWRJbnRlcnZhbCA9IG51bGw7XG4gIHRoaXMuSyA9IG51bGw7XG4gIHRoaXMuViA9IG51bGw7XG5cbiAgdmFyIGVudHJvcHkgPSB1dGlscy50b0FycmF5KG9wdGlvbnMuZW50cm9weSwgb3B0aW9ucy5lbnRyb3B5RW5jKTtcbiAgdmFyIG5vbmNlID0gdXRpbHMudG9BcnJheShvcHRpb25zLm5vbmNlLCBvcHRpb25zLm5vbmNlRW5jKTtcbiAgdmFyIHBlcnMgPSB1dGlscy50b0FycmF5KG9wdGlvbnMucGVycywgb3B0aW9ucy5wZXJzRW5jKTtcbiAgYXNzZXJ0KGVudHJvcHkubGVuZ3RoID49ICh0aGlzLm1pbkVudHJvcHkgLyA4KSxcbiAgICAgICAgICdOb3QgZW5vdWdoIGVudHJvcHkuIE1pbmltdW0gaXM6ICcgKyB0aGlzLm1pbkVudHJvcHkgKyAnIGJpdHMnKTtcbiAgdGhpcy5faW5pdChlbnRyb3B5LCBub25jZSwgcGVycyk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEhtYWNEUkJHO1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX2luaXQgPSBmdW5jdGlvbiBpbml0KGVudHJvcHksIG5vbmNlLCBwZXJzKSB7XG4gIHZhciBzZWVkID0gZW50cm9weS5jb25jYXQobm9uY2UpLmNvbmNhdChwZXJzKTtcblxuICB0aGlzLksgPSBuZXcgQXJyYXkodGhpcy5vdXRMZW4gLyA4KTtcbiAgdGhpcy5WID0gbmV3IEFycmF5KHRoaXMub3V0TGVuIC8gOCk7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5WLmxlbmd0aDsgaSsrKSB7XG4gICAgdGhpcy5LW2ldID0gMHgwMDtcbiAgICB0aGlzLlZbaV0gPSAweDAxO1xuICB9XG5cbiAgdGhpcy5fdXBkYXRlKHNlZWQpO1xuICB0aGlzLnJlc2VlZCA9IDE7XG4gIHRoaXMucmVzZWVkSW50ZXJ2YWwgPSAweDEwMDAwMDAwMDAwMDA7ICAvLyAyXjQ4XG59O1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX2htYWMgPSBmdW5jdGlvbiBobWFjKCkge1xuICByZXR1cm4gbmV3IGhhc2guaG1hYyh0aGlzLmhhc2gsIHRoaXMuSyk7XG59O1xuXG5IbWFjRFJCRy5wcm90b3R5cGUuX3VwZGF0ZSA9IGZ1bmN0aW9uIHVwZGF0ZShzZWVkKSB7XG4gIHZhciBrbWFjID0gdGhpcy5faG1hYygpXG4gICAgICAgICAgICAgICAgIC51cGRhdGUodGhpcy5WKVxuICAgICAgICAgICAgICAgICAudXBkYXRlKFsgMHgwMCBdKTtcbiAgaWYgKHNlZWQpXG4gICAga21hYyA9IGttYWMudXBkYXRlKHNlZWQpO1xuICB0aGlzLksgPSBrbWFjLmRpZ2VzdCgpO1xuICB0aGlzLlYgPSB0aGlzLl9obWFjKCkudXBkYXRlKHRoaXMuVikuZGlnZXN0KCk7XG4gIGlmICghc2VlZClcbiAgICByZXR1cm47XG5cbiAgdGhpcy5LID0gdGhpcy5faG1hYygpXG4gICAgICAgICAgICAgICAudXBkYXRlKHRoaXMuVilcbiAgICAgICAgICAgICAgIC51cGRhdGUoWyAweDAxIF0pXG4gICAgICAgICAgICAgICAudXBkYXRlKHNlZWQpXG4gICAgICAgICAgICAgICAuZGlnZXN0KCk7XG4gIHRoaXMuViA9IHRoaXMuX2htYWMoKS51cGRhdGUodGhpcy5WKS5kaWdlc3QoKTtcbn07XG5cbkhtYWNEUkJHLnByb3RvdHlwZS5yZXNlZWQgPSBmdW5jdGlvbiByZXNlZWQoZW50cm9weSwgZW50cm9weUVuYywgYWRkLCBhZGRFbmMpIHtcbiAgLy8gT3B0aW9uYWwgZW50cm9weSBlbmNcbiAgaWYgKHR5cGVvZiBlbnRyb3B5RW5jICE9PSAnc3RyaW5nJykge1xuICAgIGFkZEVuYyA9IGFkZDtcbiAgICBhZGQgPSBlbnRyb3B5RW5jO1xuICAgIGVudHJvcHlFbmMgPSBudWxsO1xuICB9XG5cbiAgZW50cm9weSA9IHV0aWxzLnRvQnVmZmVyKGVudHJvcHksIGVudHJvcHlFbmMpO1xuICBhZGQgPSB1dGlscy50b0J1ZmZlcihhZGQsIGFkZEVuYyk7XG5cbiAgYXNzZXJ0KGVudHJvcHkubGVuZ3RoID49ICh0aGlzLm1pbkVudHJvcHkgLyA4KSxcbiAgICAgICAgICdOb3QgZW5vdWdoIGVudHJvcHkuIE1pbmltdW0gaXM6ICcgKyB0aGlzLm1pbkVudHJvcHkgKyAnIGJpdHMnKTtcblxuICB0aGlzLl91cGRhdGUoZW50cm9weS5jb25jYXQoYWRkIHx8IFtdKSk7XG4gIHRoaXMucmVzZWVkID0gMTtcbn07XG5cbkhtYWNEUkJHLnByb3RvdHlwZS5nZW5lcmF0ZSA9IGZ1bmN0aW9uIGdlbmVyYXRlKGxlbiwgZW5jLCBhZGQsIGFkZEVuYykge1xuICBpZiAodGhpcy5yZXNlZWQgPiB0aGlzLnJlc2VlZEludGVydmFsKVxuICAgIHRocm93IG5ldyBFcnJvcignUmVzZWVkIGlzIHJlcXVpcmVkJyk7XG5cbiAgLy8gT3B0aW9uYWwgZW5jb2RpbmdcbiAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnKSB7XG4gICAgYWRkRW5jID0gYWRkO1xuICAgIGFkZCA9IGVuYztcbiAgICBlbmMgPSBudWxsO1xuICB9XG5cbiAgLy8gT3B0aW9uYWwgYWRkaXRpb25hbCBkYXRhXG4gIGlmIChhZGQpIHtcbiAgICBhZGQgPSB1dGlscy50b0FycmF5KGFkZCwgYWRkRW5jKTtcbiAgICB0aGlzLl91cGRhdGUoYWRkKTtcbiAgfVxuXG4gIHZhciB0ZW1wID0gW107XG4gIHdoaWxlICh0ZW1wLmxlbmd0aCA8IGxlbikge1xuICAgIHRoaXMuViA9IHRoaXMuX2htYWMoKS51cGRhdGUodGhpcy5WKS5kaWdlc3QoKTtcbiAgICB0ZW1wID0gdGVtcC5jb25jYXQodGhpcy5WKTtcbiAgfVxuXG4gIHZhciByZXMgPSB0ZW1wLnNsaWNlKDAsIGxlbik7XG4gIHRoaXMuX3VwZGF0ZShhZGQpO1xuICB0aGlzLnJlc2VlZCsrO1xuICByZXR1cm4gdXRpbHMuZW5jb2RlKHJlcywgZW5jKTtcbn07XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHtcbiAgZG91Ymxlczoge1xuICAgIHN0ZXA6IDQsXG4gICAgcG9pbnRzOiBbXG4gICAgICBbXG4gICAgICAgICdlNjBmY2U5M2I1OWU5ZWM1MzAxMWFhYmMyMWMyM2U5N2IyYTMxMzY5Yjg3YTVhZTljNDRlZTg5ZTJhNmRlYzBhJyxcbiAgICAgICAgJ2Y3ZTM1MDczOTllNTk1OTI5ZGI5OWYzNGY1NzkzNzEwMTI5Njg5MWU0NGQyM2YwYmUxZjMyY2NlNjk2MTY4MjEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnODI4MjI2MzIxMmM2MDlkOWVhMmE2ZTNlMTcyZGUyMzhkOGMzOWNhYmQ1YWMxY2ExMDY0NmUyM2ZkNWY1MTUwOCcsXG4gICAgICAgICcxMWY4YTgwOTg1NTdkZmU0NWU4MjU2ZTgzMGI2MGFjZTYyZDYxM2FjMmY3YjE3YmVkMzFiNmVhZmY2ZTI2Y2FmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzE3NWUxNTlmNzI4Yjg2NWE3MmY5OWNjNmM2ZmM4NDZkZTBiOTM4MzNmZDIyMjJlZDczZmNlNWI1NTFlNWI3MzknLFxuICAgICAgICAnZDM1MDZlMGQ5ZTNjNzllYmE0ZWY5N2E1MWZmNzFmNWVhY2I1OTU1YWRkMjQzNDVjNmVmYTZmZmVlOWZlZDY5NSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNjNkOTBkNDQ3YjAwYzljOTljZWFjMDViNjI2MmVlMDUzNDQxYzdlNTU1NTJmZmU1MjZiYWQ4ZjgzZmY0NjQwJyxcbiAgICAgICAgJzRlMjczYWRmYzczMjIyMTk1M2I0NDUzOTdmMzM2MzE0NWI5YTg5MDA4MTk5ZWNiNjIwMDNjN2YzYmVlOWRlOSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4YjRiNWYxNjVkZjNjMmJlOGM2MjQ0YjViNzQ1NjM4ODQzZTRhNzgxYTE1YmNkMWI2OWY3OWE1NWRmZmRmODBjJyxcbiAgICAgICAgJzRhYWQwYTZmNjhkMzA4YjRiM2ZiZDc4MTNhYjBkYTA0ZjllMzM2NTQ2MTYyZWU1NmIzZWZmMGM2NWZkNGZkMzYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzIzY2JhYTZlNWRiOTk2ZDZiZjc3MWMwMGJkNTQ4YzdiNzAwZGJmZmE2YzBlNzdiY2I2MTE1OTI1MjMyZmNkYScsXG4gICAgICAgICc5NmU4NjdiNTU5NWNjNDk4YTkyMTEzNzQ4ODgyNGQ2ZTI2NjBhMDY1Mzc3OTQ5NDgwMWRjMDY5ZDllYjM5ZjVmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2VlYmZhNGQ0OTNiZWJmOThiYTVmZWVjODEyYzJkM2I1MDk0Nzk2MTIzN2E5MTk4MzlhNTMzZWNhMGU3ZGQ3ZmEnLFxuICAgICAgICAnNWQ5YThjYTM5NzBlZjBmMjY5ZWU3ZWRhZjE3ODA4OWQ5YWU0Y2RjM2E3MTFmNzEyZGRmZDRmZGFlMWRlODk5OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxMDBmNDRkYTY5NmU3MTY3Mjc5MWQwYTA5YjdiZGU0NTlmMTIxNWEyOWIzYzAzYmZlZmQ3ODM1YjM5YTQ4ZGIwJyxcbiAgICAgICAgJ2NkZDllMTMxOTJhMDBiNzcyZWM4ZjMzMDBjMDkwNjY2YjdmZjRhMThmZjUxOTVhYzBmYmQ1Y2Q2MmJjNjVhMDknXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTEwMzFiZTI2MmM3ZWQxYjFkYzkyMjdhNGEwNGMwMTdhNzdmOGQ0NDY0ZjNiMzg1MmM4YWNkZTZlNTM0ZmQyZCcsXG4gICAgICAgICc5ZDcwNjE5Mjg5NDA0MDVlNmJiNmE0MTc2NTk3NTM1YWYyOTJkZDQxOWUxY2VkNzlhNDRmMThmMjk0NTZhMDBkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2ZlZWE2Y2FlNDZkNTViNTMwYWMyODM5ZjE0M2JkN2VjNWNmOGIyNjZhNDFkNmFmNTJkNWU2ODhkOTA5NDY5NmQnLFxuICAgICAgICAnZTU3YzZiNmM5N2RjZTFiYWIwNmU0ZTEyYmYzZWNkNWM5ODFjODk1N2NjNDE0NDJkMzE1NWRlYmYxODA5MDA4OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkYTY3YTkxZDkxMDQ5Y2RjYjM2N2JlNGJlNmZmY2EzY2ZlZWQ2NTdkODA4NTgzZGUzM2ZhOTc4YmMxZWM2Y2IxJyxcbiAgICAgICAgJzliYWNhYTM1NDgxNjQyYmM0MWY0NjNmN2VjOTc4MGU1ZGVjN2FkYzUwOGY3NDBhMTdlOWVhOGUyN2E2OGJlMWQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNTM5MDRmYWEwYjMzNGNkZGE2ZTAwMDkzNWVmMjIxNTFlYzA4ZDBmN2JiMTEwNjlmNTc1NDVjY2MxYTM3YjdjMCcsXG4gICAgICAgICc1YmMwODdkMGJjODAxMDZkODhjOWVjY2FjMjBkM2MxYzEzOTk5OTgxZTE0NDM0Njk5ZGNiMDk2YjAyMjc3MWM4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhlN2JjZDBiZDM1OTgzYTc3MTljY2E3NzY0Y2E5MDY3NzliNTNhMDQzYTliOGJjYWVmZjk1OWY0M2FkODYwNDcnLFxuICAgICAgICAnMTBiNzc3MGIyYTNkYTRiMzk0MDMxMDQyMGNhOTUxNDU3OWU4OGUyZTQ3ZmQ2OGIzZWExMDA0N2U4NDYwMzcyYSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczODVlZWQzNGMxY2RmZjIxZTZkMDgxODY4OWI4MWJkZTcxYTdmNGYxODM5N2U2NjkwYTg0MWUxNTk5YzQzODYyJyxcbiAgICAgICAgJzI4M2JlYmMzZThlYTIzZjU2NzAxZGUxOWU5ZWJmNDU3NmIzMDRlZWMyMDg2ZGM4Y2MwNDU4ZmU1NTQyZTU0NTMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNmY5ZDliODAzZWNmMTkxNjM3YzczYTQ0MTNkZmExODBmZGRmODRhNTk0N2ZiYzljNjA2ZWQ4NmMzZmFjM2E3JyxcbiAgICAgICAgJzdjODBjNjhlNjAzMDU5YmE2OWI4ZTJhMzBlNDVjNGQ0N2VhNGRkMmY1YzI4MTAwMmQ4Njg5MDYwM2E4NDIxNjAnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzMyMmQ0MDEyNDNjNGUyNTgyYTIxNDdjMTA0ZDZlY2JmNzc0ZDE2M2RiMGY1ZTUzMTNiN2UwZTc0MmQwZTZiZCcsXG4gICAgICAgICc1NmU3MDc5N2U5NjY0ZWY1YmZiMDE5YmM0ZGRhZjliNzI4MDVmNjNlYTI4NzNhZjYyNGYzYTJlOTZjMjhiMmEwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzg1NjcyYzdkMmRlMGI3ZGEyYmQxNzcwZDg5NjY1ODY4NzQxYjNmOWFmNzY0MzM5NzcyMWQ3NGQyODEzNGFiODMnLFxuICAgICAgICAnN2M0ODFiOWI1YjQzYjJlYjYzNzQwNDliZmE2MmMyZTVlNzdmMTdmY2M1Mjk4ZjQ0YzhlMzA5NGY3OTAzMTNhNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5NDhiZjgwOWIxOTg4YTQ2YjA2YzlmMTkxOTQxM2IxMGY5MjI2YzYwZjY2ODgzMmZmZDk1OWFmNjBjODJhMGEnLFxuICAgICAgICAnNTNhNTYyODU2ZGNiNjY0NmRjNmI3NGM1ZDFjMzQxOGM2ZDRkZmYwOGM5N2NkMmJlZDRjYjdmODhkOGM4ZTU4OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2MjYwY2U3ZjQ2MTgwMWMzNGYwNjdjZTBmMDI4NzNhOGYxYjBlNDRkZmM2OTc1MmFjY2VjZDgxOWYzOGZkOGU4JyxcbiAgICAgICAgJ2JjMmRhODJiNmZhNWI1NzFhN2YwOTA0OTc3NmExZWY3ZWNkMjkyMjM4MDUxYzE5OGMxYTg0ZTk1YjJiNGFlMTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTUwMzdkZTBhZmMxZDhkNDNkODM0ODQxNGJiZjQxMDMwNDNlYzhmNTc1YmZkYzQzMjk1M2NjOGQyMDM3ZmEyZCcsXG4gICAgICAgICc0NTcxNTM0YmFhOTRkM2I1ZjlmOThkMDlmYjk5MGJkZGJkNWY1YjAzZWM0ODFmMTBlMGU1ZGM4NDFkNzU1YmRhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UwNjM3MmIwZjRhMjA3YWRmNWVhOTA1ZThmMTc3MWI0ZTdlOGRiZDFjNmE2YzViNzI1ODY2YTBhZTRmY2U3MjUnLFxuICAgICAgICAnN2E5MDg5NzRiY2UxOGNmZTEyYTI3YmIyYWQ1YTQ4OGNkNzQ4NGE3Nzg3MTA0ODcwYjI3MDM0Zjk0ZWVlMzFkZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyMTNjN2E3MTVjZDVkNDUzNThkMGJiZjlkYzBjZTAyMjA0YjEwYmRkZTJhM2Y1ODU0MGFkNjkwOGQwNTU5NzU0JyxcbiAgICAgICAgJzRiNmRhZDBiNWFlNDYyNTA3MDEzYWQwNjI0NWJhMTkwYmI0ODUwZjVmMzZhN2VlZGRmZjJjMjc1MzRiNDU4ZjInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNGU3YzI3MmE3YWY0YjM0ZThkYmI5MzUyYTU0MTlhODdlMjgzOGM3MGFkYzYyY2RkZjBjYzNhM2IwOGZiZDUzYycsXG4gICAgICAgICcxNzc0OWM3NjZjOWQwYjE4ZTE2ZmQwOWY2ZGVmNjgxYjUzMGI5NjE0YmZmN2RkMzNlMGIzOTQxODE3ZGNhYWU2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2ZlYTc0ZTNkYmU3NzhiMWIxMGYyMzhhZDYxNjg2YWE1Yzc2ZTNkYjJiZTQzMDU3NjMyNDI3ZTI4NDBmYjI3YjYnLFxuICAgICAgICAnNmUwNTY4ZGI5YjBiMTMyOTdjZjY3NGRlY2NiNmFmOTMxMjZiNTk2Yjk3M2Y3Yjc3NzAxZDNkYjdmMjNjYjk2ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3NmU2NDExM2Y2NzdjZjBlMTBhMjU3MGQ1OTk5NjhkMzE1NDRlMTc5Yjc2MDQzMjk1MmMwMmE0NDE3YmRkZTM5JyxcbiAgICAgICAgJ2M5MGRkZjhkZWU0ZTk1Y2Y1NzcwNjZkNzA2ODFmMGQzNWUyYTMzZDJiNTZkMjAzMmI0YjE3NTJkMTkwMWFjMDEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYzczOGM1NmIwM2IyYWJlMWU4MjgxYmFhNzQzZjhmOWE4ZjdjYzY0M2RmMjZjYmVlM2FiMTUwMjQyYmNiYjg5MScsXG4gICAgICAgICc4OTNmYjU3ODk1MWFkMjUzN2Y3MThmMmVhY2JmYmJiYjgyMzE0ZWVmNzg4MGNmZTkxN2U3MzVkOTY5OWE4NGMzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2Q4OTU2MjY1NDhiNjViODFlMjY0Yzc2MzdjOTcyODc3ZDFkNzJlNWYzYTkyNTAxNDM3MmU5ZjY1ODhmNmMxNGInLFxuICAgICAgICAnZmViZmFhMzhmMmJjN2VhZTcyOGVjNjA4MThjMzQwZWIwMzQyOGQ2MzJiYjA2N2UxNzkzNjNlZDc1ZDdkOTkxZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiOGRhOTQwMzJhOTU3NTE4ZWIwZjY0MzM1NzFlODc2MWNlZmZjNzM2OTNlODRlZGQ0OTE1MGE1NjRmNjc2ZTAzJyxcbiAgICAgICAgJzI4MDRkZmE0NDgwNWExZTRkN2M5OWNjOTc2MjgwOGIwOTJjYzU4NGQ5NWZmM2I1MTE0ODhlNGU3NGVmZGY2ZTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTgwZmVhMTQ0NDFmYjMzYTdkOGFkYWI5NDc1ZDdmYWIyMDE5ZWZmYjUxNTZhNzkyZjFhMTE3NzhlM2MwZGY1ZCcsXG4gICAgICAgICdlZWQxZGU3ZjYzOGUwMDc3MWU4OTc2OGNhM2NhOTQ0NzJkMTU1ZTgwYWYzMjJlYTlmY2I0MjkxYjZhYzllYzc4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2EzMDE2OTdiZGZjZDcwNDMxM2JhNDhlNTFkNTY3NTQzZjJhMTgyMDMxZWZkNjkxNWRkYzA3YmJjYzRlMTYwNzAnLFxuICAgICAgICAnNzM3MGY5MWNmYjY3ZTRmNTA4MTgwOWZhMjVkNDBmOWIxNzM1ZGJmN2MwYTExYTEzMGMwZDFhMDQxZTE3N2VhMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5MGFkODViMzg5ZDZiOTM2NDYzZjlkMDUxMjY3OGRlMjA4Y2MzMzBiMTEzMDdmZmZhYjdhYzYzZTNmYjA0ZWQ0JyxcbiAgICAgICAgJ2U1MDdhMzYyMGEzODI2MWFmZmRjYmQ5NDI3MjIyYjgzOWFlZmFiZTE1ODI4OTRkOTkxZDRkNDhjYjZlZjE1MCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4ZjY4YjlkMmY2M2I1ZjMzOTIzOWMxYWQ5ODFmMTYyZWU4OGM1Njc4NzIzZWEzMzUxYjdiNDQ0YzllYzRjMGRhJyxcbiAgICAgICAgJzY2MmE5ZjJkYmEwNjM5ODZkZTFkOTBjMmI2YmUyMTVkYmJlYTJjZmU5NTUxMGJmZGYyM2NiZjc5NTAxZmZmODInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTRmM2ZiMDE3NmFmODVkNjVmZjk5ZmY5MTk4YzM2MDkxZjQ4ZTg2NTAzNjgxZTNlNjY4NmZkNTA1MzIzMWUxMScsXG4gICAgICAgICcxZTYzNjMzYWQwZWY0ZjFjMTY2MWE2ZDBlYTAyYjcyODZjYzdlNzRlYzk1MWQxYzk4MjJjMzg1NzZmZWI3M2JjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhjMDBmYTliMThlYmYzMzFlYjk2MTUzN2E0NWE0MjY2YzcwMzRmMmYwZDRlMWQwNzE2ZmI2ZWFlMjBlYWUyOWUnLFxuICAgICAgICAnZWZhNDcyNjdmZWE1MjFhMWE5ZGMzNDNhMzczNmM5NzRjMmZhZGFmYTgxZTM2YzU0ZTdkMmE0YzY2NzAyNDE0YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlN2EyNmNlNjlkZDQ4MjlmM2UxMGNlYzBhOWU5OGVkMzE0M2QwODRmMzA4YjkyYzA5OTdmZGRmYzYwY2IzZTQxJyxcbiAgICAgICAgJzJhNzU4ZTMwMGZhNzk4NGI0NzFiMDA2YTFhYWZiYjE4ZDBhNmIyYzA0MjBlODNlMjBlOGE5NDIxY2YyY2ZkNTEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYjY0NTllMGVlMzY2MmVjOGQyMzU0MGMyMjNiY2JkYzU3MWNiY2I5NjdkNzk0MjRmM2NmMjllYjNkZTZiODBlZicsXG4gICAgICAgICc2N2M4NzZkMDZmM2UwNmRlMWRhZGYxNmU1NjYxZGIzYzRiM2FlNmQ0OGUzNWIyZmYzMGJmMGI2MWE3MWJhNDUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDY4YTgwYzgyODBiYjg0MDc5MzIzNGFhMTE4ZjA2MjMxZDZmMWZjNjdlNzNjNWE1ZGVkYTBmNWI0OTY5NDNlOCcsXG4gICAgICAgICdkYjhiYTlmZmY0YjU4NmQwMGM0YjFmOTE3N2IwZTI4YjViMGU3YjhmNzg0NTI5NWEyOTRjODQyNjZiMTMzMTIwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyNGFlZDdkZjY1YzgwNDI1MmRjMDI3MDkwN2EzMGIwOTYxMmFlYjk3MzQ0OWNlYTQwOTU5ODBmYzI4ZDNkNWQnLFxuICAgICAgICAnNjQ4YTM2NTc3NGI2MWYyZmYxMzBjMGMzNWFlYzFmNGYxOTIxM2IwYzdlMzMyODQzOTY3MjI0YWY5NmFiN2M4NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc0ZGY5YzE0OTE5Y2RlNjFmNmQ1MWRmZGJlNWZlZTVkY2VlYzQxNDNiYThkMWNhODg4ZThiZDM3M2ZkMDU0Yzk2JyxcbiAgICAgICAgJzM1ZWM1MTA5MmQ4NzI4MDUwOTc0YzIzYTFkODVkNGI1ZDUwNmNkYzI4ODQ5MDE5MmViYWMwNmNhZDEwZDVkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzljMzkxOWE4NGE0NzQ4NzBmYWVkOGE5YzFjYzY2MDIxNTIzNDg5MDU0ZDdmMDMwOGNiZmM5OWM4YWMxZjk4Y2QnLFxuICAgICAgICAnZGRiODRmMGY0YTRkZGQ1NzU4NGYwNDRiZjI2MGU2NDE5MDUzMjZmNzZjNjRjOGU2YmU3ZTVlMDNkNGZjNTk5ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2MDU3MTcwYjFkZDEyZmRmOGRlMDVmMjgxZDhlMDZiYjkxZTE0OTNhOGI5MWQ0Y2M1YTIxMzgyMTIwYTk1OWU1JyxcbiAgICAgICAgJzlhMWFmMGIyNmE2YTQ4MDdhZGQ5YTJkYWY3MWRmMjYyNDY1MTUyYmMzZWUyNGM2NWU4OTliZTkzMjM4NWEyYTgnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTU3NmRmOGUyM2EwODQxMTQyMTQzOWE0NTE4ZGEzMTg4MGNlZjBmYmE3ZDRkZjEyYjFhNjk3M2VlY2I5NDI2NicsXG4gICAgICAgICc0MGE2YmYyMGU3NjY0MGIyYzkyYjk3YWZlNThjZDgyYzQzMmUxMGE3ZjUxNGQ5ZjNlZThiZTExYWUxYjI4ZWM4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3NzhhNzhjMjhkZWMzZTMwYTA1ZmU5NjI5ZGU4YzM4YmIzMGQxZjVjZjlhM2EyMDhmNzYzODg5YmU1OGFkNzEnLFxuICAgICAgICAnMzQ2MjZkOWFiNWE1YjIyZmY3MDk4ZTEyZjJmZjU4MDA4N2IzODQxMWZmMjRhYzU2M2I1MTNmYzFmZDlmNDNhYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5Mjg5NTVlZTYzN2E4NDQ2MzcyOWZkMzBlN2FmZDJlZDVmOTYyNzRlNWFkN2U1Y2IwOWVkYTljMDZkOTAzYWMnLFxuICAgICAgICAnYzI1NjIxMDAzZDNmNDJhODI3Yjc4YTEzMDkzYTk1ZWVhYzNkMjZlZmE4YThkODNmYzUxODBlOTM1YmNkMDkxZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NWQwZmVmM2VjNmRiMTA5Mzk5MDY0ZjNhMGUzYjI4NTU2NDViNGE5MDdhZDM1NDUyN2FhZTc1MTYzZDgyNzUxJyxcbiAgICAgICAgJzFmMDM2NDg0MTNhMzhjMGJlMjlkNDk2ZTU4MmNmNTY2M2U4NzUxZTk2ODc3MzMxNTgyYzIzN2EyNGViMWY5NjInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmYyYjBkY2U5N2VlY2U5N2MxYzliNjA0MTc5OGI4NWRmZGZiNmQ4ODgyZGEyMDMwOGY1NDA0ODI0NTI2MDg3ZScsXG4gICAgICAgICc0OTNkMTNmZWY1MjRiYTE4OGFmNGM0ZGM1NGQwNzkzNmM3YjdlZDZmYjkwZTJjZWIyYzk1MWUwMWYwYzI5OTA3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzgyN2ZiYmU0YjFlODgwZWE5ZWQyYjJlNjMwMWIyMTJiNTdmMWVlMTQ4Y2Q2ZGQyODc4MGU1ZTJjZjg1NmUyNDEnLFxuICAgICAgICAnYzYwZjljOTIzYzcyN2IwYjcxYmVmMmM2N2QxZDEyNjg3ZmY3YTYzMTg2OTAzMTY2ZDYwNWI2OGJhZWMyOTNlYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYWE2NDlmMjFmNTFiZGJhZTdiZTRhZTM0Y2U2ZTUyMTdhNThmZGNlN2Y0N2Y5YWE3ZjNiNThmYTIxMjBlMmIzJyxcbiAgICAgICAgJ2JlMzI3OWVkNWJiYmIwM2FjNjlhODBmODk4NzlhYTVhMDFhNmI5NjVmMTNmN2U1OWQ0N2E1MzA1YmE1YWQ5M2QnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZTRhNDJkNDNjNWNmMTY5ZDkzOTFkZjZkZWNmNDJlZTU0MWI2ZDhmMGM5YTEzNzQwMWUyMzYzMmRkYTM0ZDI0ZicsXG4gICAgICAgICc0ZDlmOTJlNzE2ZDFjNzM1MjZmYzk5Y2NmYjhhZDM0Y2U4ODZlZWRmYThkOGU0ZjEzYTdmNzEzMWRlYmE5NDE0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzFlYzgwZmVmMzYwY2JkZDk1NDE2MGZhZGFiMzUyYjZiOTJiNTM1NzZhODhmZWE0OTQ3MTczYjlkNDMwMGJmMTknLFxuICAgICAgICAnYWVlZmU5Mzc1NmI1MzQwZDJmM2E0OTU4YTdhYmJmNWUwMTQ2ZTc3ZjYyOTVhMDdiNjcxY2RjMWNjMTA3Y2VmZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNDZhNzc4YzA0NjcwYzJmOTFiMDBhZjQ2ODBkZmE4YmNlMzQ5MDcxN2Q1OGJhODg5ZGRiNTkyODM2NjY0MmJlJyxcbiAgICAgICAgJ2IzMThlMGVjMzM1NDAyOGFkZDY2OTgyN2Y5ZDRiMjg3MGFhYTk3MWQyZjdlNWVkMWQwYjI5NzQ4M2Q4M2VmZDAnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmE1MGMwZjYxZDIyZTVmMDdlM2FjZWJiMWFhMDdiMTI4ZDAwMTIyMDlhMjhiOTc3NmQ3NmE4NzkzMTgwZWVmOScsXG4gICAgICAgICc2Yjg0YzY5MjIzOTdlYmE5YjcyY2QyODcyMjgxYTY4YTVlNjgzMjkzYTU3YTIxM2IzOGNkOGQ3ZDNmNGYyODExJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2RhMWQ2MWQwY2E3MjFhMTFiMWE1YmY2YjdkODhlODQyMWEyODhhYjVkNWJiYTUyMjBlNTNkMzJiNWYwNjdlYzInLFxuICAgICAgICAnODE1N2Y1NWE3Yzk5MzA2Yzc5YzA3NjYxNjFjOTFlMjk2NmE3Mzg5OWQyNzliNDhhNjU1ZmJhMGYxYWQ4MzZmMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhOGUyODJmZjBjOTcwNjkwNzIxNWZmOThlOGZkNDE2NjE1MzExZGUwNDQ2ZjFlMDYyYTczYjA2MTBkMDY0ZTEzJyxcbiAgICAgICAgJzdmOTczNTViOGRiODFjMDlhYmZiN2YzYzViMjUxNTg4OGI2NzlhM2U1MGRkNmJkNmNlZjdjNzMxMTFmNGNjMGMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTc0YTUzYjljOWEyODU4NzJkMzllNTZlNjkxM2NhYjE1ZDU5YjFmYTUxMjUwOGMwMjJmMzgyZGU4MzE5NDk3YycsXG4gICAgICAgICdjY2M5ZGMzN2FiZmM5YzE2NTdiNDE1NWYyYzQ3ZjllNjY0NmIzYTFkOGNiOTg1NDM4M2RhMTNhYzA3OWFmYTczJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzk1OTM5Njk4MTk0Mzc4NWMzZDNlNTdlZGY1MDE4Y2RiZTAzOWU3MzBlNDkxOGIzZDg4NGZkZmYwOTQ3NWI3YmEnLFxuICAgICAgICAnMmU3ZTU1Mjg4OGMzMzFkZDhiYTAzODZhNGI5Y2Q2ODQ5YzY1M2Y2NGM4NzA5Mzg1ZTliOGFiZjg3NTI0ZjJmZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkMmE2M2E1MGFlNDAxZTU2ZDY0NWExMTUzYjEwOWE4ZmNjYTBhNDNkNTYxZmJhMmRiYjUxMzQwYzlkODJiMTUxJyxcbiAgICAgICAgJ2U4MmQ4NmZiNjQ0M2ZjYjc1NjVhZWU1OGIyOTQ4MjIwYTcwZjc1MGFmNDg0Y2E1MmQ0MTQyMTc0ZGNmODk0MDUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNjQ1ODdlMjMzNTQ3MWViODkwZWU3ODk2ZDdjZmRjODY2YmFjYmRiZDM4MzkzMTdiMzQzNmY5YjQ1NjE3ZTA3MycsXG4gICAgICAgICdkOTlmY2RkNWJmNjkwMmUyYWU5NmRkNjQ0N2MyOTlhMTg1YjkwYTM5MTMzYWVhYjM1ODI5OWU1ZTlmYWY2NTg5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzg0ODFiZGUwZTRlNGQ4ODViM2E1NDZkM2U1NDlkZTA0MmYwYWE2Y2VhMjUwZTdmZDM1OGQ2Yzg2ZGQ0NWU0NTgnLFxuICAgICAgICAnMzhlZTdiOGNiYTU0MDRkZDg0YTI1YmYzOWNlY2IyY2E5MDBhNzljNDJiMjYyZTU1NmQ2NGIxYjU5Nzc5MDU3ZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxMzQ2NGE1N2E3ODEwMmFhNjJiNjk3OWFlODE3ZjQ2MzdmZmNmZWQzYzRiMWNlMzBiY2Q2MzAzZjZjYWY2NjZiJyxcbiAgICAgICAgJzY5YmUxNTkwMDQ2MTQ1ODBlZjdlNDMzNDUzY2NiMGNhNDhmMzAwYTgxZDA5NDJlMTNmNDk1YTkwN2Y2ZWNjMjcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYmM0YTlkZjViNzEzZmUyZTlhZWY0MzBiY2MxZGM5N2EwY2Q5Y2NlZGUyZjI4NTg4Y2FkYTNhMGQyZDgzZjM2NicsXG4gICAgICAgICdkM2E4MWNhNmU3ODVjMDYzODM5MzdhZGY0Yjc5OGNhYTZlOGE5ZmJmYTU0N2IxNmQ3NThkNjY2NTgxZjMzYzEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnOGMyOGE5N2JmODI5OGJjMGQyM2Q4Yzc0OTQ1MmEzMmU2OTRiNjVlMzBhOTQ3MmEzOTU0YWIzMGZlNTMyNGNhYScsXG4gICAgICAgICc0MGEzMDQ2M2EzMzA1MTkzMzc4ZmVkZjMxZjdjYzBlYjdhZTc4NGYwNDUxY2I5NDU5ZTcxZGM3M2NiZWY5NDgyJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhlYTk2NjYxMzk1MjdhOGMxZGQ5NGNlNGYwNzFmZDIzYzhiMzUwYzVhNGJiMzM3NDhjNGJhMTExZmFjY2FlMCcsXG4gICAgICAgICc2MjBlZmFiYmM4ZWUyNzgyZTI0ZTdjMGNmYjk1YzVkNzM1Yjc4M2JlOWNmMGY4ZTk1NWFmMzRhMzBlNjJiOTQ1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2RkMzYyNWZhZWY1YmEwNjA3NDY2OTcxNmJiZDM3ODhkODliZGRlODE1OTU5OTY4MDkyZjc2Y2M0ZWI5YTk3ODcnLFxuICAgICAgICAnN2ExODhmYTM1MjBlMzBkNDYxZGEyNTAxMDQ1NzMxY2E5NDE0NjE5ODI4ODMzOTU5MzdmNjhkMDBjNjQ0YTU3MydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmNzEwZDc5ZDllYjk2MjI5N2U0ZjYyMzJiNDBlOGY3ZmViMmJjNjM4MTQ2MTRkNjkyYzEyZGU3NTI0MDgyMjFlJyxcbiAgICAgICAgJ2VhOThlNjcyMzJkM2IzMjk1ZDNiNTM1NTMyMTE1Y2NhYzg2MTJjNzIxODUxNjE3NTI2YWU0N2E5Yzc3YmZjODInXG4gICAgICBdXG4gICAgXVxuICB9LFxuICBuYWY6IHtcbiAgICB3bmQ6IDcsXG4gICAgcG9pbnRzOiBbXG4gICAgICBbXG4gICAgICAgICdmOTMwOGEwMTkyNThjMzEwNDkzNDRmODVmODlkNTIyOWI1MzFjODQ1ODM2Zjk5YjA4NjAxZjExM2JjZTAzNmY5JyxcbiAgICAgICAgJzM4OGY3YjBmNjMyZGU4MTQwZmUzMzdlNjJhMzdmMzU2NjUwMGE5OTkzNGMyMjMxYjZjYjlmZDc1ODRiOGU2NzInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMmY4YmRlNGQxYTA3MjA5MzU1YjRhNzI1MGE1YzUxMjhlODhiODRiZGRjNjE5YWI3Y2JhOGQ1NjliMjQwZWZlNCcsXG4gICAgICAgICdkOGFjMjIyNjM2ZTVlM2Q2ZDRkYmE5ZGRhNmM5YzQyNmY3ODgyNzFiYWIwZDY4NDBkY2E4N2QzYWE2YWM2MmQ2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzVjYmRmMDY0NmU1ZGI0ZWFhMzk4ZjM2NWYyZWE3YTBlM2Q0MTliN2UwMzMwZTM5Y2U5MmJkZGVkY2FjNGY5YmMnLFxuICAgICAgICAnNmFlYmNhNDBiYTI1NTk2MGEzMTc4ZDZkODYxYTU0ZGJhODEzZDBiODEzZmRlN2I1YTUwODI2MjgwODcyNjRkYSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhY2Q0ODRlMmYwYzdmNjUzMDlhZDE3OGE5ZjU1OWFiZGUwOTc5Njk3NGM1N2U3MTRjMzVmMTEwZGZjMjdjY2JlJyxcbiAgICAgICAgJ2NjMzM4OTIxYjBhN2Q5ZmQ2NDM4MDk3MTc2M2I2MWU5YWRkODg4YTQzNzVmOGUwZjA1Y2MyNjJhYzY0ZjljMzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzc0YWU3Zjg1OGE5NDExZTVlZjQyNDZiNzBjNjVhYWM1NjQ5OTgwYmU1YzE3ODkxYmJlYzE3ODk1ZGEwMDhjYicsXG4gICAgICAgICdkOTg0YTAzMmViNmI1ZTE5MDI0M2RkNTZkN2I3YjM2NTM3MmRiMWUyZGZmOWQ2YTgzMDFkNzRjOWM5NTNjNjFiJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2YyODc3M2MyZDk3NTI4OGJjN2QxZDIwNWMzNzQ4NjUxYjA3NWZiYzY2MTBlNThjZGRlZWRkZjhmMTk0MDVhYTgnLFxuICAgICAgICAnYWIwOTAyZThkODgwYTg5NzU4MjEyZWI2NWNkYWY0NzNhMWEwNmRhNTIxZmE5MWYyOWI1Y2I1MmRiMDNlZDgxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2Q3OTI0ZDRmN2Q0M2VhOTY1YTQ2NWFlMzA5NWZmNDExMzFlNTk0NmYzYzg1Zjc5ZTQ0YWRiY2Y4ZTI3ZTA4MGUnLFxuICAgICAgICAnNTgxZTI4NzJhODZjNzJhNjgzODQyZWMyMjhjYzZkZWZlYTQwYWYyYmQ4OTZkM2E1YzUwNGRjOWZmNmEyNmI1OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkZWZkZWE0Y2RiNjc3NzUwYTQyMGZlZTgwN2VhY2YyMWViOTg5OGFlNzliOTc2ODc2NmU0ZmFhMDRhMmQ0YTM0JyxcbiAgICAgICAgJzQyMTFhYjA2OTQ2MzUxNjhlOTk3YjBlYWQyYTkzZGFlY2VkMWY0YTA0YTk1YzBmNmNmYjE5OWY2OWU1NmViNzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMmI0ZWEwYTc5N2E0NDNkMjkzZWY1Y2ZmNDQ0ZjQ5NzlmMDZhY2ZlYmQ3ZTg2ZDI3NzQ3NTY1NjEzODM4NWI2YycsXG4gICAgICAgICc4NWU4OWJjMDM3OTQ1ZDkzYjM0MzA4M2I1YTFjODYxMzFhMDFmNjBjNTAyNjk3NjNiNTcwYzg1NGU1YzA5YjdhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzM1MmJiZjRhNGNkZDEyNTY0ZjkzZmEzMzJjZTMzMzMwMWQ5YWQ0MDI3MWY4MTA3MTgxMzQwYWVmMjViZTU5ZDUnLFxuICAgICAgICAnMzIxZWI0MDc1MzQ4ZjUzNGQ1OWMxODI1OWRkYTNlMWY0YTFiM2IyZTcxYjEwMzljNjdiZDNkOGJjZjgxOTk4YydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyZmEyMTA0ZDZiMzhkMTFiMDIzMDAxMDU1OTg3OTEyNGU0MmFiOGRmZWZmNWZmMjlkYzljZGFkZDRlY2FjYzNmJyxcbiAgICAgICAgJzJkZTEwNjgyOTVkZDg2NWI2NDU2OTMzNWJkNWRkODAxODFkNzBlY2ZjODgyNjQ4NDIzYmE3NmI1MzJiN2Q2NydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5MjQ4Mjc5YjA5YjRkNjhkYWIyMWE5YjA2NmVkZGE4MzI2M2MzZDg0ZTA5NTcyZTI2OWNhMGNkN2Y1NDUzNzE0JyxcbiAgICAgICAgJzczMDE2ZjdiZjIzNGFhZGU1ZDFhYTcxYmRlYTJiMWZmM2ZjMGRlMmE4ODc5MTJmZmU1NGEzMmNlOTdjYjM0MDInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGFlZDRmMmJlM2E4YmYyNzhlNzAxMzJmYjBiZWI3NTIyZjU3MGUxNDRiZjYxNWMwN2U5OTZkNDQzZGVlODcyOScsXG4gICAgICAgICdhNjlkY2U0YTdkNmM5OGU4ZDRhMWFjYTg3ZWY4ZDcwMDNmODNjMjMwZjNhZmE3MjZhYjQwZTUyMjkwYmUxYzU1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M0NGQxMmM3MDY1ZDgxMmU4YWNmMjhkN2NiYjE5ZjkwMTFlY2Q5ZTlmZGYyODFiMGU2YTNiNWU4N2QyMmU3ZGInLFxuICAgICAgICAnMjExOWE0NjBjZTMyNmNkYzc2YzQ1OTI2Yzk4MmZkYWMwZTEwNmU4NjFlZGY2MWM1YTAzOTA2M2YwZTBlNjQ4MidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2YTI0NWJmNmRjNjk4NTA0Yzg5YTIwY2ZkZWQ2MDg1MzE1MmI2OTUzMzZjMjgwNjNiNjFjNjVjYmQyNjllNmI0JyxcbiAgICAgICAgJ2UwMjJjZjQyYzJiZDRhNzA4YjNmNTEyNmYxNmEyNGFkOGIzM2JhNDhkMDQyM2I2ZWZkNWU2MzQ4MTAwZDhhODInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTY5N2ZmYTZmZDlkZTYyN2MwNzdlM2QyZmU1NDEwODRjZTEzMzAwYjBiZWMxMTQ2Zjk1YWU1N2YwZDBiZDZhNScsXG4gICAgICAgICdiOWMzOThmMTg2ODA2ZjVkMjc1NjE1MDZlNDU1NzQzM2EyY2YxNTAwOWU0OThhZTdhZGVlOWQ2M2QwMWIyMzk2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzYwNWJkYjAxOTk4MTcxOGI5ODZkMGYwN2U4MzRjYjBkOWRlYjgzNjBmZmI3ZjYxZGY5ODIzNDVlZjI3YTc0NzknLFxuICAgICAgICAnMjk3MmQyZGU0ZjhkMjA2ODFhNzhkOTNlYzk2ZmUyM2MyNmJmYWU4NGZiMTRkYjQzYjAxZTFlOTA1NmI4YzQ5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzYyZDE0ZGFiNDE1MGJmNDk3NDAyZmRjNDVhMjE1ZTEwZGNiMDFjMzU0OTU5YjEwY2ZlMzFjN2U5ZDg3ZmYzM2QnLFxuICAgICAgICAnODBmYzA2YmQ4Y2M1YjAxMDk4MDg4YTE5NTBlZWQwZGIwMWFhMTMyOTY3YWI0NzIyMzVmNTY0MjQ4M2IyNWVhZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4MGM2MGFkMDA0MGYyN2RhZGU1YjRiMDZjNDA4ZTU2YjJjNTBlOWY1NmI5YjhiNDI1ZTU1NWMyZjg2MzA4YjZmJyxcbiAgICAgICAgJzFjMzgzMDNmMWNjNWMzMGYyNmU2NmJhZDdmZTcyZjcwYTY1ZWVkNGNiZTcwMjRlYjFhYTAxZjU2NDMwYmQ1N2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnN2E5Mzc1YWQ2MTY3YWQ1NGFhNzRjNjM0OGNjNTRkMzQ0Y2M1ZGM5NDg3ZDg0NzA0OWQ1ZWFiYjBmYTAzYzhmYicsXG4gICAgICAgICdkMGUzZmE5ZWNhODcyNjkwOTU1OWUwZDc5MjY5MDQ2YmRjNTllYTEwYzcwY2UyYjAyZDQ5OWVjMjI0ZGM3ZjcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDUyOGVjZDliNjk2YjU0YzkwN2E5ZWQwNDU0NDdhNzliYjQwOGVjMzliNjhkZjUwNGJiNTFmNDU5YmMzZmZjOScsXG4gICAgICAgICdlZWNmNDEyNTMxMzZlNWY5OTk2NmYyMTg4MWZkNjU2ZWJjNDM0NTQwNWM1MjBkYmMwNjM0NjViNTIxNDA5OTMzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ5MzcwYTRiNWY0MzQxMmVhMjVmNTE0ZThlY2RhZDA1MjY2MTE1ZTRhN2VjYjEzODcyMzE4MDhmOGI0NTk2MycsXG4gICAgICAgICc3NThmM2Y0MWFmZDZlZDQyOGIzMDgxYjA1MTJmZDYyYTU0YzNmM2FmYmI1YjY3NjRiNjUzMDUyYTEyOTQ5YzlhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3ZjIzMDkzNmVlODhjYmJkNzNkZjkzMGQ2NDcwMmVmODgxZDgxMWUwZTE0OThlMmYxYzEzZWIxZmMzNDVkNzQnLFxuICAgICAgICAnOTU4ZWY0MmE3ODg2YjY0MDBhMDgyNjZlOWJhMWIzNzg5NmM5NTMzMGQ5NzA3N2NiYmU4ZWIzYzc2NzFjNjBkNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmMmRhYzk5MWNjNGNlNGI5ZWE0NDg4N2U1YzdjMGJjZTU4YzgwMDc0YWI5ZDRkYmFlYjI4NTMxYjc3MzlmNTMwJyxcbiAgICAgICAgJ2UwZGVkYzliM2IyZjhkYWQ0ZGExZjMyZGVjMjUzMWRmOWViNWZiZWIwNTk4ZTRmZDFhMTE3ZGJhNzAzYTNjMzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNDYzYjNkOWY2NjI2MjFmYjFiNGJlOGZiYmUyNTIwMTI1YTIxNmNkZmM5ZGFlM2RlYmNiYTQ4NTBjNjkwZDQ1YicsXG4gICAgICAgICc1ZWQ0MzBkNzhjMjk2YzM1NDMxMTQzMDZkZDg2MjJkN2M2MjJlMjdjOTcwYTFkZTMxY2IzNzdiMDFhZjczMDdlJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2YxNmY4MDQyNDRlNDZlMmEwOTIzMmQ0YWZmM2I1OTk3NmI5OGZhYzE0MzI4YTJkMWEzMjQ5NmI0OTk5OGYyNDcnLFxuICAgICAgICAnY2VkYWJkOWI4MjIwM2Y3ZTEzZDIwNmZjZGY0ZTMzZDkyYTZjNTNjMjZlNWNjZTI2ZDY1Nzk5NjJjNGUzMWRmNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjYWY3NTQyNzJkYzg0NTYzYjAzNTJiN2ExNDMxMWFmNTVkMjQ1MzE1YWNlMjdjNjUzNjllMTVmNzE1MWQ0MWQxJyxcbiAgICAgICAgJ2NiNDc0NjYwZWYzNWY1ZjJhNDFiNjQzZmE1ZTQ2MDU3NWY0ZmE5Yjc5NjIyMzJhNWMzMmY5MDgzMThhMDQ0NzYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMjYwMGNhNGIyODJjYjk4NmY4NWQwZjE3MDk5NzlkOGI0NGEwOWMwN2NiODZkN2MxMjQ0OTdiYzg2ZjA4MjEyMCcsXG4gICAgICAgICc0MTE5Yjg4NzUzYzE1YmQ2YTY5M2IwM2ZjZGRiYjQ1ZDVhYzZiZTc0YWI1ZjBlZjQ0YjBiZTk0NzVhN2U0YjQwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc2MzVjYTcyZDdlODQzMmMzMzhlYzUzY2QxMjIyMGJjMDFjNDg2ODVlMjRmN2RjOGM2MDJhNzc0Njk5OGU0MzUnLFxuICAgICAgICAnOTFiNjQ5NjA5NDg5ZDYxM2QxZDVlNTkwZjc4ZTZkNzRlY2ZjMDYxZDU3MDQ4YmFkOWU3NmYzMDJjNWI5YzYxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc1NGUzMjM5ZjMyNTU3MGNkYmJmNGE4N2RlZWU4YTY2YjdmMmIzMzQ3OWQ0NjhmYmMxYTUwNzQzYmY1NmNjMTgnLFxuICAgICAgICAnNjczZmI4NmU1YmRhMzBmYjNjZDBlZDMwNGVhNDlhMDIzZWUzM2QwMTk3YTY5NWQwYzVkOTgwOTNjNTM2NjgzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UzZTZiZDEwNzFhMWU5NmFmZjU3ODU5YzgyZDU3MGYwMzMwODAwNjYxZDFjOTUyZjlmZTI2OTQ2OTFkOWI5ZTgnLFxuICAgICAgICAnNTljOWUwYmJhMzk0ZTc2ZjQwYzBhYTU4Mzc5YTNjYjZhNWEyMjgzOTkzZTkwYzQxNjcwMDJhZjQ5MjBlMzdmNSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxODZiNDgzZDA1NmEwMzM4MjZhZTczZDg4ZjczMjk4NWM0Y2NiMWYzMmJhMzVmNGI0Y2M0N2ZkY2YwNGFhNmViJyxcbiAgICAgICAgJzNiOTUyZDMyYzY3Y2Y3N2UyZTE3NDQ2ZTIwNDE4MGFiMjFmYjgwOTA4OTUxMzhiNGE0YTc5N2Y4NmU4MDg4OGInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGY5ZDcwYTZiOTg3NmNlNTQ0Yzk4NTYxZjRiZTRmNzI1NDQyZTZkMmI3MzdkOWM5MWE4MzIxNzI0Y2UwOTYzZicsXG4gICAgICAgICc1NWViMmRhZmQ4NGQ2Y2NkNWY4NjJiNzg1ZGMzOWQ0YWIxNTcyMjI3MjBlZjlkYTIxN2I4YzQ1Y2YyYmEyNDE3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzVlZGQ1Y2MyM2M1MWU4N2E0OTdjYTgxNWQ1ZGNlMGY4YWI1MjU1NGY4NDllZDg5OTVkZTY0YzVmMzRjZTcxNDMnLFxuICAgICAgICAnZWZhZTljOGRiYzE0MTMwNjYxZThjZWMwMzBjODlhZDBjMTNjNjZjMGQxN2EyOTA1Y2RjNzA2YWI3Mzk5YTg2OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcyOTA3OThjMmI2NDc2ODMwZGExMmZlMDIyODdlOWU3NzdhYTNmYmExYzM1NWIxN2E3MjJkMzYyZjg0NjE0ZmJhJyxcbiAgICAgICAgJ2UzOGRhNzZkY2Q0NDA2MjE5ODhkMDBiY2Y3OWFmMjVkNWIyOWMwOTRkYjJhMjMxNDZkMDAzYWZkNDE5NDNlN2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYWYzYzQyM2E5NWQ5ZjViMzA1NDc1NGVmYTE1MGFjMzljZDI5NTUyZmUzNjAyNTczNjJkZmRlY2VmNDA1M2I0NScsXG4gICAgICAgICdmOThhM2ZkODMxZWIyYjc0OWE5M2IwZTZmMzVjZmI0MGM4Y2Q1YWE2NjdhMTU1ODFiYzJmZWRlZDQ5OGZkOWM2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc2NmRiYjI0ZDEzNGU3NDVjY2NhYTI4Yzk5YmYyNzQ5MDZiYjY2YjI2ZGNmOThkZjhkMmZlZDUwZDg4NDI0OWEnLFxuICAgICAgICAnNzQ0YjExNTJlYWNiZTVlMzhkY2M4ODc5ODBkYTM4Yjg5NzU4NGE2NWZhMDZjZWRkMmM5MjRmOTdjYmFjNTk5NidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1OWRiZjQ2ZjhjOTQ3NTliYTIxMjc3YzMzNzg0ZjQxNjQ1ZjdiNDRmNmM1OTZhNThjZTkyZTY2NjE5MWFiZTNlJyxcbiAgICAgICAgJ2M1MzRhZDQ0MTc1ZmJjMzAwZjRlYTZjZTY0ODMwOWEwNDJjZTczOWE3OTE5Nzk4Y2Q4NWUyMTZjNGEzMDdmNmUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZjEzYWRhOTUxMDNjNDUzNzMwNWU2OTFlNzRlOWE0YThkZDY0N2U3MTFhOTVlNzNjYjYyZGM2MDE4Y2ZkODdiOCcsXG4gICAgICAgICdlMTM4MTdiNDRlZTE0ZGU2NjNiZjRiYzgwODM0MWYzMjY5NDllMjFhNmE3NWMyNTcwNzc4NDE5YmRhZjU3MzNkJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzc3NTRiNGZhMGU4YWNlZDA2ZDQxNjdhMmM1OWNjYTRjZGExODY5YzA2ZWJhZGZiNjQ4ODU1MDAxNWE4ODUyMmMnLFxuICAgICAgICAnMzBlOTNlODY0ZTY2OWQ4MjIyNGI5NjdjMzAyMGI4ZmE4ZDFlNGUzNTBiNmNiY2M1MzdhNDhiNTc4NDExNjNhMidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5NDhkY2FkZjU5OTBlMDQ4YWEzODc0ZDQ2YWJlZjlkNzAxODU4Zjk1ZGU4MDQxZDJhNjgyOGM5OWUyMjYyNTE5JyxcbiAgICAgICAgJ2U0OTFhNDI1MzdmNmU1OTdkNWQyOGEzMjI0YjFiYzI1ZGY5MTU0ZWZiZDJlZjFkMmNiYmEyY2FlNTM0N2Q1N2UnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzk2MjQxNDQ1MGM3NmMxNjg5YzdiNDhmODIwMmVjMzdmYjIyNGNmNWFjMGJmYTE1NzAzMjhhOGEzZDdjNzdhYicsXG4gICAgICAgICcxMDBiNjEwZWM0ZmZiNDc2MGQ1YzFmYzEzM2VmNmY2YjEyNTA3YTA1MWYwNGFjNTc2MGFmYTViMjlkYjgzNDM3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzM1MTQwODc4MzQ5NjRiNTRiMTViMTYwNjQ0ZDkxNTQ4NWExNjk3NzIyNWI4ODQ3YmIwZGQwODUxMzdlYzQ3Y2EnLFxuICAgICAgICAnZWYwYWZiYjIwNTYyMDU0NDhlMTY1MmM0OGU4MTI3ZmM2MDM5ZTc3YzE1YzIzNzhiN2U3ZDE1YTBkZTI5MzMxMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkM2NjMzBhZDZiNDgzZTRiYzc5Y2UyYzlkZDhiYzU0OTkzZTk0N2ViOGRmNzg3YjQ0Mjk0M2QzZjdiNTI3ZWFmJyxcbiAgICAgICAgJzhiMzc4YTIyZDgyNzI3OGQ4OWM1ZTliZThmOTUwOGFlM2MyYWQ0NjI5MDM1ODYzMGFmYjM0ZGIwNGVlZGUwYTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTYyNGQ4NDc4MDczMjg2MGNlMWM3OGZjYmZlZmUwOGIyYjI5ODIzZGI5MTNmNjQ5Mzk3NWJhMGZmNDg0NzYxMCcsXG4gICAgICAgICc2ODY1MWNmOWI2ZGE5MDNlMDkxNDQ0OGM2Y2Q5ZDRjYTg5Njg3OGY1MjgyYmU0YzhjYzA2ZTJhNDA0MDc4NTc1J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzczM2NlODBkYTk1NWE4YTI2OTAyYzk1NjMzZTYyYTk4NTE5MjQ3NGI1YWYyMDdkYTZkZjdiNGZkNWZjNjFjZDQnLFxuICAgICAgICAnZjU0MzVhMmJkMmJhZGY3ZDQ4NWE0ZDhiOGRiOWZjY2UzZTFlZjhlMDIwMWU0NTc4YzU0NjczYmMxZGM1ZWExZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNWQ5NDQxMjU0OTQ1MDY0Y2YxYTFjMzNiYmQzYjQ5Zjg5NjZjNTA5MjE3MWU2OTllZjI1OGRmYWI4MWMwNDVjJyxcbiAgICAgICAgJ2Q1NmViMzBiNjk0NjNlNzIzNGY1MTM3YjczYjg0MTc3NDM0ODAwYmFjZWJmYzY4NWZjMzdiYmU5ZWZlNDA3MGQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTFkMGZjZjJlYzlkZTY3NWI2MTIxMzZlNWNlNzBkMjcxYzIxNDE3YzlkMmI4YWFhYWMxMzg1OTlkMDcxNzk0MCcsXG4gICAgICAgICdlZGQ3N2Y1MGJjYjVhM2NhYjJlOTA3MzczMDk2NjdmMjY0MTQ2MmE1NDA3MGYzZDUxOTIxMmQzOWMxOTdhNjI5J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UyMmZiZTE1YzBhZjhjY2M1NzgwYzA3MzVmODRkYmU5YTc5MGJhZGVlODI0NWMwNmM3Y2EzNzMzMWNiMzY5ODAnLFxuICAgICAgICAnYTg1NWJhYmFkNWNkNjBjODhiNDMwYTY5ZjUzYTFhN2EzODI4OTE1NDk2NDc5OWJlNDNkMDZkNzdkMzFkYTA2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMxMTA5MWRkOTg2MGU4ZTIwZWUxMzQ3M2MxMTU1ZjVmNjk2MzVlMzk0NzA0ZWFhNzQwMDk0NTIyNDZjZmE5YjMnLFxuICAgICAgICAnNjZkYjY1NmY4N2QxZjA0ZmZmZDFmMDQ3ODhjMDY4MzA4NzFlYzVhNjRmZWVlNjg1YmQ4MGYwYjEyODZkODM3NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNGMxZmQwNGQzMDFiZTg5YjMxYzA0NDJkM2U2YWMyNDg4MzkyOGI0NWE5MzQwNzgxODY3ZDQyMzJlYzJkYmRmJyxcbiAgICAgICAgJzk0MTQ2ODVlOTdiMWI1OTU0YmQ0NmY3MzAxNzQxMzZkNTdmMWNlZWI0ODc0NDNkYzUzMjE4NTdiYTczYWJlZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdmMjE5ZWE1ZDZiNTQ3MDFjMWMxNGRlNWI1NTdlYjQyYThkMTNmM2FiYmNkMDhhZmZjYzJhNWU2YjA0OWI4ZDYzJyxcbiAgICAgICAgJzRjYjk1OTU3ZTgzZDQwYjBmNzNhZjQ1NDRjY2NmNmIxZjRiMDhkM2MwN2IyN2ZiOGQ4YzI5NjJhNDAwNzY2ZDEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDdiODc0MGY3NGE4ZmJhYWIxZjY4M2RiOGY0NWRlMjY1NDNhNTQ5MGJjYTYyNzA4NzIzNjkxMjQ2OWEwYjQ0OCcsXG4gICAgICAgICdmYTc3OTY4MTI4ZDljOTJlZTEwMTBmMzM3YWQ0NzE3ZWZmMTVkYjVlZDNjMDQ5YjM0MTFlMDMxNWVhYTQ1OTNiJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyZDMxYzIyMmY4ZjZmMGVmODZmN2M5OGQzYTMzMzVlYWQ1YmNkMzJhYmRkOTQyODlmZTRkMzA5MWFhODI0YmYnLFxuICAgICAgICAnNWYzMDMyZjU4OTIxNTZlMzljY2QzZDc5MTViOWUxZGEyZTZkYWM5ZTZmMjZlOTYxMTE4ZDE0Yjg0NjJlMTY2MSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3NDYxZjM3MTkxNGFiMzI2NzEwNDVhMTU1ZDk4MzFlYTg3OTNkNzdjZDU5NTkyYzQzNDBmODZjYmMxODM0N2I1JyxcbiAgICAgICAgJzhlYzBiYTIzOGI5NmJlYzBjYmRkZGNhZTBhYTQ0MjU0MmVlZTFmZjUwYzk4NmVhNmIzOTg0N2IzY2MwOTJmZjYnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZWUwNzlhZGIxZGYxODYwMDc0MzU2YTI1YWEzODIwNmE2ZDcxNmIyYzNlNjc0NTNkMjg3Njk4YmFkN2IyYjJkNicsXG4gICAgICAgICc4ZGMyNDEyYWFmZTNiZTVjNGM1ZjM3ZTBlY2M1ZjlmNmE0NDY5ODlhZjA0YzRlMjVlYmFhYzQ3OWVjMWM4YzFlJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzE2ZWM5M2U0NDdlYzgzZjA0NjdiMTgzMDJlZTYyMGY3ZTY1ZGUzMzE4NzRjOWRjNzJiZmQ4NjE2YmE5ZGE2YjUnLFxuICAgICAgICAnNWU0NjMxMTUwZTYyZmI0MGQwZThjMmE3Y2E1ODA0YTM5ZDU4MTg2YTUwZTQ5NzEzOTYyNjc3OGUyNWIwNjc0ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYWE1Zjk4MGMyNDVmNmYwMzg5NzgyOTBhZmE3MGI2YmQ4ODU1ODk3Zjk4YjZhYTQ4NWI5NjA2NWQ1MzdiZDk5JyxcbiAgICAgICAgJ2Y2NWY1ZDNlMjkyYzJlMDgxOWE1MjgzOTFjOTk0NjI0ZDc4NDg2OWQ3ZTZlYTY3ZmIxODA0MTAyNGVkYzA3ZGMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzhjOTQwNzU0NGFjMTMyNjkyZWUxOTEwYTAyNDM5OTU4YWUwNDg3NzE1MTM0MmVhOTZjNGI2YjM1YTQ5ZjUxJyxcbiAgICAgICAgJ2YzZTAzMTkxNjllYjliODVkNTQwNDc5NTUzOWE1ZTY4ZmExZmJkNTgzYzA2NGQyNDYyYjY3NWYxOTRhM2RkYjQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNDk0ZjRiZTIxOWExYTc3MDE2ZGNkODM4NDMxYWVhMDAwMWNkYzhhZTdhNmZjNjg4NzI2NTc4ZDk3MDI4NTdhNScsXG4gICAgICAgICc0MjI0MmE5NjkyODNhNWYzMzliYTdmMDc1ZTM2YmEyYWY5MjVjZTMwZDc2N2VkNmU1NWY0YjAzMTg4MGQ1NjJjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2E1OThhODAzMGRhNmQ4NmM2YmM3ZjJmNTE0NGVhNTQ5ZDI4MjExZWE1OGZhYTcwZWJmNGMxZTY2NWMxZmU5YjUnLFxuICAgICAgICAnMjA0YjVkNmY4NDgyMmMzMDdlNGI0YTcxNDA3MzdhZWMyM2ZjNjNiNjViMzVmODZhMTAwMjZkYmQyZDg2NGU2YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjNDE5MTYzNjVhYmIyYjVkMDkxOTJmNWYyZGJlYWZlYzIwOGYwMjBmMTI1NzBhMTg0ZGJhZGMzZTU4NTk1OTk3JyxcbiAgICAgICAgJzRmMTQzNTFkMDA4N2VmYTQ5ZDI0NWIzMjg5ODQ5ODlkNWNhZjk0NTBmMzRiZmMwZWQxNmU5NmI1OGZhOTkxMydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NDFkNjA2M2E1ODZmYTQ3NWE3MjQ2MDRkYTAzYmM1YjkyYTJlMGQyZTBhMzZhY2ZlNGM3M2E1NTE0NzQyODgxJyxcbiAgICAgICAgJzczODY3ZjU5YzA2NTllODE5MDRmOWExYzc1NDM2OThlNjI1NjJkNjc0NGMxNjljZTdhMzZkZTAxYThkNjE1NCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1ZTk1YmIzOTlhNjk3MWQzNzYwMjY5NDdmODliZGUyZjI4MmIzMzgxMDkyOGJlNGRlZDExMmFjNGQ3MGUyMGQ1JyxcbiAgICAgICAgJzM5ZjIzZjM2NjgwOTA4NWJlZWJmYzcxMTgxMzEzNzc1YTk5YzlhZWQ3ZDhiYTM4YjE2MTM4NGM3NDYwMTI4NjUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzZlNDY0MWE1Mzk0OGZkNDc2YzM5ZjhhOTlmZDk3NGU1ZWMwNzU2NGI1MzE1ZDhiZjk5NDcxYmNhMGVmMmY2NicsXG4gICAgICAgICdkMjQyNGIxYjFhYmU0ZWI4MTY0MjI3YjA4NWM5YWE5NDU2ZWExMzQ5M2ZkNTYzZTA2ZmQ1MWNmNTY5NGM3OGZjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMzNjU4MWVhN2JmYmJiMjkwYzE5MWEyZjUwN2E0MWNmNTY0Mzg0MjE3MGU5MTRmYWVhYjI3YzJjNTc5ZjcyNicsXG4gICAgICAgICdlYWQxMjE2ODU5NWZlMWJlOTkyNTIxMjliNmU1NmIzMzkxZjdhYjE0MTBjZDFlMGVmM2RjZGNhYmQyZmRhMjI0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhhYjg5ODE2ZGFkZmQ2YjZhMWYyNjM0ZmNmMDBlYzg0MDM3ODEwMjVlZDY4OTBjNDg0OTc0MjcwNmJkNDNlZGUnLFxuICAgICAgICAnNmZkY2VmMDlmMmY2ZDBhMDQ0ZTY1NGFlZjYyNDEzNmY1MDNkNDU5YzNlODk4NDU4NThhNDdhOTEyOWNkZDI0ZSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxZTMzZjFhNzQ2YzljNTc3ODEzMzM0NGQ5Mjk5ZmNhYTIwYjA5MzhlOGFjZmYyNTQ0YmI0MDI4NGI4YzVmYjk0JyxcbiAgICAgICAgJzYwNjYwMjU3ZGQxMWIzYWE5YzhlZDYxOGQyNGVkZmYyMzA2ZDMyMGYxZDAzMDEwZTMzYTdkMjA1N2YzYjNiNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc4NWI3YzFkY2IzY2VjMWI3ZWU3ZjMwZGVkNzlkZDIwYTBlZDFmNGNjMThjYmNmY2ZhNDEwMzYxZmQ4ZjA4ZjMxJyxcbiAgICAgICAgJzNkOThhOWNkZDAyNmRkNDNmMzkwNDhmMjVhODg0N2Y0ZmNhZmFkMTg5NWQ3YTYzM2M2ZmVkM2MzNWU5OTk1MTEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMjlkZjlmYmQ4ZDllNDY1MDkyNzVmNGIxMjVkNmQ0NWQ3ZmJlOWEzYjg3OGE3YWY4NzJhMjgwMDY2MWFjNWY1MScsXG4gICAgICAgICdiNGM0ZmU5OWM3NzVhNjA2ZTJkODg2MjE3OTEzOWZmZGE2MWRjODYxYzAxOWU1NWNkMjg3NmViMmEyN2Q4NGInXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYTBiMWNhZTA2YjBhODQ3YTNmZWE2ZTY3MWFhZjhhZGZkZmU1OGNhMmY3NjgxMDVjODA4MmIyZTQ0OWZjZTI1MicsXG4gICAgICAgICdhZTQzNDEwMmVkZGUwOTU4ZWM0YjE5ZDkxN2E2YTI4ZTZiNzJkYTE4MzRhZmYwZTY1MGYwNDk1MDNhMjk2Y2YyJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzRlOGNlYWZiOWIzZTlhMTM2ZGM3ZmY2N2U4NDAyOTViNDk5ZGZiM2IyMTMzZTRiYTExM2YyZTRjMGUxMjFlNScsXG4gICAgICAgICdjZjIxNzQxMThjOGI2ZDdhNGI0OGY2ZDUzNGNlNWM3OTQyMmMwODZhNjM0NjA1MDJiODI3Y2U2MmEzMjY2ODNjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2QyNGE0NGUwNDdlMTliNmY1YWZiODFjN2NhMmY2OTA4MGE1MDc2Njg5YTAxMDkxOWY0MjcyNWMyYjc4OWEzM2InLFxuICAgICAgICAnNmZiOGQ1NTkxYjQ2NmY4ZmM2M2RiNTBmMWMwZjFjNjkwMTNmOTk2ODg3YjgyNDRkMmNkZWM0MTdhZmVhOGZhMydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYTAxNjA2YTdhNmM5Y2RkMjQ5ZmRmY2ZhY2I5OTU4NDAwMWVkZDI4YWJiYWI3N2I1MTA0ZTk4ZThlM2IzNWQ0JyxcbiAgICAgICAgJzMyMmFmNDkwOGM3MzEyYjBjZmJmZTM2OWY3YTdiM2NkYjdkNDQ5NGJjMjgyMzcwMGNmZDY1MjE4OGEzZWE5OGQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnYWY4YWRkYmYyYjY2MWM4YTZjNjMyODY1NWViOTY2NTEyNTIwMDdkOGM1ZWEzMWJlNGFkMTk2ZGU4Y2UyMTMxZicsXG4gICAgICAgICc2NzQ5ZTY3YzAyOWI4NWY1MmEwMzRlYWZkMDk2ODM2YjI1MjA4MTg2ODBlMjZhYzhmM2RmYmNkYjcxNzQ5NzAwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2UzYWUxOTc0NTY2Y2EwNmNjNTE2ZDQ3ZTBmYjE2NWE2NzRhM2RhYmNmY2ExNWU3MjJmMGUzNDUwZjQ1ODg5JyxcbiAgICAgICAgJzJhZWFiZTdlNDUzMTUxMDExNjIxN2YwN2JmNGQwNzMwMGRlOTdlNDg3NGY4MWY1MzM0MjBhNzJlZWIwYmQ2YTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNTkxZWUzNTUzMTNkOTk3MjFjZjY5OTNmZmVkMWUzZTMwMTk5M2ZmM2VkMjU4ODAyMDc1ZWE4Y2VkMzk3ZTI0NicsXG4gICAgICAgICdiMGVhNTU4YTExM2MzMGJlYTYwZmM0Nzc1NDYwYzc5MDFmZjBiMDUzZDI1Y2EyYmRlZWU5OGYxYTRiZTVkMTk2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzExMzk2ZDU1ZmRhNTRjNDlmMTlhYTk3MzE4ZDhkYTYxZmE4NTg0ZTQ3YjA4NDk0NTA3N2NmMDMyNTViNTI5ODQnLFxuICAgICAgICAnOTk4Yzc0YThjZDQ1YWMwMTI4OWQ1ODMzYTdiZWI0NzQ0ZmY1MzZiMDFiMjU3YmU0YzU3NjdiZWE5M2VhNTdhNCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczYzVkMmExYmEzOWM1YTE3OTAwMDA3MzhjOWUwYzQwYjhkY2RmZDU0Njg3NTRiNjQwNTU0MDE1N2UwMTdhYTdhJyxcbiAgICAgICAgJ2IyMjg0Mjc5OTk1YTM0ZTJmOWQ0ZGU3Mzk2ZmMxOGI4MGY5YjhiOWZkZDI3MGY2NjYxZjc5Y2E0YzgxYmQyNTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnY2M4NzA0YjhhNjBhMGRlZmEzYTk5YTcyOTlmMmU5YzNmYmMzOTVhZmIwNGFjMDc4NDI1ZWY4YTE3OTNjYzAzMCcsXG4gICAgICAgICdiZGQ0NjAzOWZlZWQxNzg4MWQxZTA4NjJkYjM0N2Y4Y2YzOTViNzRmYzRiY2RjNGU5NDBiNzRlM2FjMWYxYjEzJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M1MzNlNGY3ZWE4NTU1YWFjZDk3NzdhYzVjYWQyOWI5N2RkNGRlZmNjYzUzZWU3ZWEyMDQxMTliMjg4OWIxOTcnLFxuICAgICAgICAnNmYwYTI1NmJjNWVmZGY0MjlhMmZiNjI0MmYxYTQzYTJkOWI5MjViYjRhNGIzYTI2YmI4ZTBmNDVlYjU5NjA5NidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdjMTRmOGYyY2NiMjdkNmYxMDlmNmQwOGQwM2NjOTZhNjliYThjMzRlZWMwN2JiY2Y1NjZkNDhlMzNkYTY1OTMnLFxuICAgICAgICAnYzM1OWQ2OTIzYmIzOThmN2ZkNDQ3M2UxNmZlMWMyODQ3NWI3NDBkZDA5ODA3NWU2YzBlODY0OTExM2RjM2EzOCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdhNmNiYzMwNDZiYzZhNDUwYmFjMjQ3ODlmYTE3MTE1YTRjOTczOWVkNzVmOGYyMWNlNDQxZjcyZTBiOTBlNmVmJyxcbiAgICAgICAgJzIxYWU3ZjQ2ODBlODg5YmIxMzA2MTllMmMwZjk1YTM2MGNlYjU3M2M3MDYwMzEzOTg2MmFmZDYxN2ZhOWI5ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczNDdkNmQ5YTAyYzQ4OTI3ZWJmYjg2YzEzNTliMWNhZjEzMGEzYzAyNjdkMTFjZTYzNDRiMzlmOTlkNDNjYzM4JyxcbiAgICAgICAgJzYwZWE3ZjYxYTM1MzUyNGQxYzk4N2Y2ZWNlYzkyZjA4NmQ1NjVhYjY4Nzg3MGNiMTI2ODlmZjFlMzFjNzQ0NDgnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZGE2NTQ1ZDIxODFkYjhkOTgzZjdkY2IzNzVlZjU4NjZkNDdjNjdiMWJmMzFjOGNmODU1ZWY3NDM3YjcyNjU2YScsXG4gICAgICAgICc0OWI5NjcxNWFiNjg3OGE3OWU3OGYwN2NlNTY4MGM1ZDY2NzMwNTFiNDkzNWJkODk3ZmVhODI0Yjc3ZGMyMDhhJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2M0MDc0N2NjOWQwMTJjYjFhMTNiODE0ODMwOWM2ZGU3ZWMyNWQ2OTQ1ZDY1NzE0NmI5ZDU5OTRiOGZlYjExMTEnLFxuICAgICAgICAnNWNhNTYwNzUzYmUyYTEyZmM2ZGU2Y2FmMmNiNDg5NTY1ZGI5MzYxNTZiOTUxNGUxYmI1ZTgzMDM3ZTBmYTJkNCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc0ZTQyYzhlYzgyYzk5Nzk4Y2NmM2E2MTBiZTg3MGU3ODMzOGM3ZjcxMzM0OGJkMzRjODIwM2VmNDAzN2YzNTAyJyxcbiAgICAgICAgJzc1NzFkNzRlZTVlMGZiOTJhN2E4YjMzYTA3NzgzMzQxYTU0OTIxNDRjYzU0YmNjNDBhOTQ0NzM2OTM2MDY0MzcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMzc3NWFiNzA4OWJjNmFmODIzYWJhMmUxYWY3MGIyMzZkMjUxY2FkYjBjODY3NDMyODc1MjJhMWIzYjBkZWRlYScsXG4gICAgICAgICdiZTUyZDEwN2JjZmEwOWQ4YmNiOTczNmE4MjhjZmE3ZmFjOGRiMTdiZjdhNzZhMmM0MmFkOTYxNDA5MDE4Y2Y3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2NlZTMxY2JmN2UzNGVjMzc5ZDk0ZmI4MTRkM2Q3NzVhZDk1NDU5NWQxMzE0YmE4ODQ2OTU5ZTNlODJmNzRlMjYnLFxuICAgICAgICAnOGZkNjRhMTRjMDZiNTg5YzI2Yjk0N2FlMmJjZjZiZmEwMTQ5ZWYwYmUxNGVkNGQ4MGY0NDhhMDFjNDNiMWM2ZCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiNGY5ZWFlYTA5YjY5MTc2MTlmNmVhNmE0ZWI1NDY0ZWZkZGI1OGZkNDViMWViZWZjZGMxYTAxZDA4YjQ3OTg2JyxcbiAgICAgICAgJzM5ZTVjOTkyNWI1YTU0YjA3NDMzYTRmMThjNjE3MjZmOGJiMTMxYzAxMmNhNTQyZWIyNGE4YWMwNzIwMDY4MmEnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDQyNjNkZmMzZDJkZjkyM2EwMTc5YTQ4OTY2ZDMwY2U4NGUyNTE1YWZjM2RjY2MxYjc3OTA3NzkyZWJjYzYwZScsXG4gICAgICAgICc2MmRmYWYwN2EwZjc4ZmViMzBlMzBkNjI5NTg1M2NlMTg5ZTEyNzc2MGFkNmNmN2ZhZTE2NGUxMjJhMjA4ZDU0J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ4NDU3NTI0ODIwZmE2NWE0ZjhkMzVlYjY5MzA4NTdjMDAzMmFjYzBhNGEyZGU0MjIyMzNlZWRhODk3NjEyYzQnLFxuICAgICAgICAnMjVhNzQ4YWIzNjc5NzlkOTg3MzNjMzhhMWZhMWMyZTdkYzZjYzA3ZGIyZDYwYTlhZTdhNzZhYWE0OWJkMGY3NydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkZmVlZWYxODgxMTAxZjJjYjExNjQ0ZjNhMmFmZGZjMjA0NWUxOTkxOTE1MjkyM2YzNjdhMTc2N2MxMWNjZWRhJyxcbiAgICAgICAgJ2VjZmI3MDU2Y2YxZGUwNDJmOTQyMGJhYjM5Njc5M2MwYzM5MGJkZTc0YjRiYmRmZjE2YTgzYWUwOWE5YTc1MTcnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNmQ3ZWY2YjE3NTQzZjgzNzNjNTczZjQ0ZTFmMzg5ODM1ZDg5YmNiYzYwNjJjZWQzNmM4MmRmODNiOGZhZTg1OScsXG4gICAgICAgICdjZDQ1MGVjMzM1NDM4OTg2ZGZlZmExMGM1N2ZlYTliY2M1MjFhMDk1OWIyZDgwYmJmNzRiMTkwZGNhNzEyZDEwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2U3NTYwNWQ1OTEwMmE1YTI2ODQ1MDBkM2I5OTFmMmUzZjNjODhiOTMyMjU1NDcwMzVhZjI1YWY2NmUwNDU0MWYnLFxuICAgICAgICAnZjVjNTQ3NTRhOGY3MWVlNTQwYjliNDg3Mjg0NzNlMzE0ZjcyOWFjNTMwOGIwNjkzODM2MDk5MGUyYmZhZDEyNSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlYjk4NjYwZjRjNGRmYWEwNmEyYmU0NTNkNTAyMGJjOTlhMGMyZTYwYWJlMzg4NDU3ZGQ0M2ZlZmIxZWQ2MjBjJyxcbiAgICAgICAgJzZjYjlhODg3NmQ5Y2I4NTIwNjA5YWYzYWRkMjZjZDIwYTBhN2NkOGE5NDExMTMxY2U4NWY0NDEwMDA5OTIyM2UnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnMTNlODdiMDI3ZDg1MTRkMzU5MzlmMmU2ODkyYjE5OTIyMTU0NTk2OTQxODg4MzM2ZGMzNTYzZTNiOGRiYTk0MicsXG4gICAgICAgICdmZWY1YTNjNjgwNTlhNmRlYzVkNjI0MTE0YmYxZTkxYWFjMmI5ZGE1NjhkNmFiZWIyNTcwZDU1NjQ2YjhhZGYxJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2VlMTYzMDI2ZTlmZDZmZTAxN2MzOGYwNmE1YmU2ZmMxMjU0MjRiMzcxY2UyNzA4ZTdiZjQ0OTE2OTFlNTc2NGEnLFxuICAgICAgICAnMWFjYjI1MGYyNTVkZDYxYzQzZDk0Y2NjNjcwZDBmNThmNDlhZTNmYTE1Yjk2NjIzZTU0MzBkYTBhZDZjNjJiMidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiMjY4ZjVlZjlhZDUxZTRkNzhkZTNhNzUwYzJkYzg5YjFlNjI2ZDQzNTA1ODY3OTk5OTMyZTVkYjMzYWYzZDgwJyxcbiAgICAgICAgJzVmMzEwZDRiM2M5OWI5ZWJiMTlmNzdkNDFjMWRlZTAxOGNmMGQzNGZkNDE5MTYxNDAwM2U5NDVhMTIxNmU0MjMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZmYwN2YzMTE4YTlkZjAzNWU5ZmFkODVlYjZjN2JmZTQyYjAyZjAxY2E5OWNlZWEzYmY3ZmZkYmE5M2M0NzUwZCcsXG4gICAgICAgICc0MzgxMzZkNjAzZTg1OGEzYTVjNDQwYzM4ZWNjYmFkZGMxZDI5NDIxMTRlMmVkZGQ0NzQwZDA5OGNlZDFmMGQ4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzhkOGI5ODU1YzdjMDUyYTM0MTQ2ZmQyMGZmYjY1OGJlYTRiOWY2OWUwZDgyNWViZWMxNmU4YzNjZTJiNTI2YTEnLFxuICAgICAgICAnY2RiNTU5ZWVkYzJkNzlmOTI2YmFmNDRmYjg0ZWE0ZDQ0YmNmNTBmZWU1MWQ3Y2ViMzBlMmU3ZjQ2MzAzNjc1OCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc1MmRiMGI1Mzg0ZGZiZjA1YmZhOWQ0NzJkN2FlMjZkZmU0Yjg1MWNlY2E5MWIxZWJhNTQyNjMxODBkYTMyYjYzJyxcbiAgICAgICAgJ2MzYjk5N2QwNTBlZTVkNDIzZWJhZjY2YTZkYjlmNTdiMzE4MGM5MDI4NzU2NzlkZTkyNGI2OWQ4NGE3YjM3NSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlNjJmOTQ5MGQzZDUxZGE2Mzk1ZWZkMjRlODA5MTljYzdkMGYyOWMzZjNmYTQ4YzZmZmY1NDNiZWNiZDQzMzUyJyxcbiAgICAgICAgJzZkODlhZDdiYTQ4NzZiMGIyMmMyY2EyODBjNjgyODYyZjM0MmM4NTkxZjFkYWY1MTcwZTA3YmZkOWNjYWZhN2QnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnN2YzMGVhMjQ3NmIzOTliNDk1NzUwOWM4OGY3N2QwMTkxYWZhMmZmNWNiN2IxNGZkNmQ4ZTdkNjVhYWFiMTE5MycsXG4gICAgICAgICdjYTVlZjdkNGIyMzFjOTRjM2IxNTM4OWE1ZjYzMTFlOWRhZmY3YmI2N2IxMDNlOTg4MGVmNGJmZjYzN2FjYWVjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzUwOThmZjFlMWQ5ZjE0ZmI0NmEyMTBmYWRhNmM5MDNmZWYwZmI3YjRhMWRkMWQ5YWM2MGEwMzYxODAwYjdhMDAnLFxuICAgICAgICAnOTczMTE0MWQ4MWZjOGY4MDg0ZDM3YzZlNzU0MjAwNmIzZWUxYjQwZDYwZGZlNTM2MmE1YjEzMmZkMTdkZGMwJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMyYjc4YzdkZTllZTUxMmE3Mjg5NWJlNmI5Y2JlZmE2ZTJmM2M0Y2NjZTQ0NWM5NmI5ZjJjODFlMjc3OGFkNTgnLFxuICAgICAgICAnZWUxODQ5ZjUxM2RmNzFlMzJlZmMzODk2ZWUyODI2MGM3M2JiODA1NDdhZTIyNzViYTQ5NzIzNzc5NGM4NzUzYydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdlMmNiNzRmZGRjOGU5ZmJjZDA3NmVlZjJhN2M3MmIwY2UzN2Q1MGYwODI2OWRmYzA3NGI1ODE1NTA1NDdhNGY3JyxcbiAgICAgICAgJ2QzYWEyZWQ3MWM5ZGQyMjQ3YTYyZGYwNjI3MzZlYjBiYWRkZWE5ZTM2MTIyZDJiZTg2NDFhYmNiMDA1Y2M0YTQnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnODQzODQ0NzU2NmQ0ZDdiZWRhZGMyOTk0OTZhYjM1NzQyNjAwOWEzNWYyMzVjYjE0MWJlMGQ5OWNkMTBhZTNhOCcsXG4gICAgICAgICdjNGUxMDIwOTE2OTgwYTRkYTVkMDFhYzVlNmFkMzMwNzM0ZWYwZDc5MDY2MzFjNGYyMzkwNDI2YjJlZGQ3OTFmJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQxNjJkNDg4Yjg5NDAyMDM5YjU4NGM2ZmM2YzMwODg3MDU4N2Q5YzQ2ZjY2MGI4NzhhYjY1YzgyYzcxMWQ2N2UnLFxuICAgICAgICAnNjcxNjNlOTAzMjM2Mjg5Zjc3NmYyMmMyNWZiOGEzYWZjMTczMmYyYjg0YjRlOTVkYmRhNDdhZTVhMDg1MjY0OSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICczZmFkM2ZhODRjYWYwZjM0ZjBmODliZmQyZGNmNTRmYzE3NWQ3NjdhZWMzZTUwNjg0ZjNiYTRhNGJmNWY2ODNkJyxcbiAgICAgICAgJ2NkMWJjN2NiNmNjNDA3YmIyZjBjYTY0N2M3MThhNzMwY2Y3MTg3MmU3ZDBkMmE1M2ZhMjBlZmNkZmU2MTgyNidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc2NzRmMjYwMGEzMDA3YTAwNTY4YzFhN2NlMDVkMDgxNmMxZmI4NGJmMTM3MDc5OGYxYzY5NTMyZmFlYjFhODZiJyxcbiAgICAgICAgJzI5OWQyMWY5NDEzZjMzYjNlZGY0M2IyNTcwMDQ1ODBiNzBkYjU3ZGEwYjE4MjI1OWUwOWVlY2M2OWUwZDM4YTUnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDMyZjRkYTU0YWRlNzRhYmI4MWI4MTVhZDFmYjNiMjYzZDgyZDZjNjkyNzE0YmNmZjg3ZDI5YmQ1ZWU5ZjA4ZicsXG4gICAgICAgICdmOTQyOWU3MzhiOGU1M2I5NjhlOTkwMTZjMDU5NzA3NzgyZTE0ZjQ1MzUzNTlkNTgyZmM0MTY5MTBiM2VlYTg3J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMwZTRlNjcwNDM1Mzg1NTU2ZTU5MzY1NzEzNTg0NWQzNmZiYjY5MzFmNzJiMDhjYjFlZDk1NGYxZTNjZTNmZjYnLFxuICAgICAgICAnNDYyZjliY2U2MTk4OTg2Mzg0OTkzNTAxMTNiYmM5YjEwYTg3OGQzNWRhNzA3NDBkYzY5NWE1NTllYjg4ZGI3YidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdiZTIwNjIwMDNjNTFjYzMwMDQ2ODI5MDQzMzBlNGRlZTdmM2RjZDEwYjAxZTU4MGJmMTk3MWIwNGQ0Y2FkMjk3JyxcbiAgICAgICAgJzYyMTg4YmM0OWQ2MWU1NDI4NTczZDQ4YTc0ZTFjNjU1YjFjNjEwOTA5MDU2ODJhMGQ1NTU4ZWQ3MmRjY2I5YmMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnOTMxNDQ0MjNhY2UzNDUxZWQyOWUwZmI5YWMyYWYyMTFjYjZlODRhNjAxZGY1OTkzYzQxOTg1OWZmZjVkZjA0YScsXG4gICAgICAgICc3YzEwZGZiMTY0YzM0MjVmNWM3MWEzZjlkNzk5MjAzOGYxMDY1MjI0ZjcyYmI5ZDFkOTAyYTZkMTMwMzdiNDdjJ1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJ2IwMTVmODA0NGY1ZmNiZGNmMjFjYTI2ZDZjMzRmYjgxOTc4MjkyMDVjN2I3ZDJhN2NiNjY0MThjMTU3YjExMmMnLFxuICAgICAgICAnYWI4YzFlMDg2ZDA0ZTgxMzc0NGE2NTViMmRmOGQ1ZjgzYjNjZGM2ZmFhMzA4OGMxZDNhZWExNDU0ZTNhMWQ1ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICdkNWU5ZTFkYTY0OWQ5N2Q4OWU0ODY4MTE3YTQ2NWEzYTRmOGExOGRlNTdhMTQwZDM2YjNmMmFmMzQxYTIxYjUyJyxcbiAgICAgICAgJzRjYjA0NDM3ZjM5MWVkNzMxMTFhMTNjYzFkNGRkMGRiMTY5MzQ2NWMyMjQwNDgwZDg5NTVlODU5MmYyNzQ0N2EnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnZDNhZTQxMDQ3ZGQ3Y2EwNjVkYmY4ZWQ3N2I5OTI0Mzk5ODMwMDVjZDcyZTE2ZDZmOTk2YTUzMTZkMzY5NjZiYicsXG4gICAgICAgICdiZDFhZWIyMWFkMjJlYmIyMmExMGYwMzAzNDE3YzZkOTY0ZjhjZGQ3ZGYwYWNhNjE0YjEwZGMxNGQxMjVhYzQ2J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzQ2M2UyNzYzZDg4NWY5NThmYzY2Y2RkMjI4MDBmMGE0ODcxOTdkMGE4MmUzNzdiNDlmODBhZjg3Yzg5N2IwNjUnLFxuICAgICAgICAnYmZlZmFjZGIwZTVkMGZkN2RmM2EzMTFhOTRkZTA2MmIyNmI4MGM2MWZiYzk3NTA4Yjc5OTkyNjcxZWY3Y2E3ZidcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc3OTg1ZmRmZDEyN2MwNTY3YzZmNTNlYzFiYjYzZWMzMTU4ZTU5N2M0MGJmZTc0N2M4M2NkZGZjOTEwNjQxOTE3JyxcbiAgICAgICAgJzYwM2MxMmRhZjNkOTg2MmVmMmIyNWZlMWRlMjg5YWVkMjRlZDI5MWUwZWM2NzA4NzAzYTViZDU2N2YzMmVkMDMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzRhMWFkNmI1Zjc2ZTM5ZGIyZGQyNDk0MTBlYWM3Zjk5ZTc0YzU5Y2I4M2QyZDBlZDVmZjE1NDNkYTc3MDNlOScsXG4gICAgICAgICdjYzYxNTdlZjE4YzljNjNjZDYxOTNkODM2MzFiYmVhMDA5M2UwOTY4OTQyZThjMzNkNTczN2ZkNzkwZTBkYjA4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzMwNjgyYTUwNzAzMzc1ZjYwMmQ0MTY2NjRiYTE5YjdmYzliYWI0MmM3Mjc0NzQ2M2E3MWQwODk2YjIyZjZkYTMnLFxuICAgICAgICAnNTUzZTA0ZjZiMDE4YjRmYTZjOGYzOWU3ZjMxMWQzMTc2MjkwZDBlMGYxOWNhNzNmMTc3MTRkOTk3N2EyMmZmOCdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICc5ZTIxNThmMGQ3YzBkNWYyNmMzNzkxZWZlZmE3OTU5NzY1NGU3YTJiMjQ2NGY1MmIxZWU2YzEzNDc3NjllZjU3JyxcbiAgICAgICAgJzcxMmZjZGQxYjkwNTNmMDkwMDNhMzQ4MWZhNzc2MmU5ZmZkN2M4ZWYzNWEzODUwOWUyZmJmMjYyOTAwODM3MydcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxNzZlMjY5ODlhNDNjOWNmZWJhNDAyOWMyMDI1MzhjMjgxNzJlNTY2ZTNjNGZjZTczMjI4NTdmM2JlMzI3ZDY2JyxcbiAgICAgICAgJ2VkOGNjOWQwNGIyOWViODc3ZDI3MGI0ODc4ZGM0M2MxOWFlZmQzMWY0ZWVlMDllZTdiNDc4MzRjMWZhNGIxYzMnXG4gICAgICBdLFxuICAgICAgW1xuICAgICAgICAnNzVkNDZlZmVhMzc3MWU2ZTY4YWJiODlhMTNhZDc0N2VjZjE4OTIzOTNkZmM0ZjFiNzAwNDc4OGM1MDM3NGRhOCcsXG4gICAgICAgICc5ODUyMzkwYTk5NTA3Njc5ZmQwYjg2ZmQyYjM5YTg2OGQ3ZWZjMjIxNTEzNDZlMWEzY2E0NzI2NTg2YTZiZWQ4J1xuICAgICAgXSxcbiAgICAgIFtcbiAgICAgICAgJzgwOWEyMGM2N2Q2NDkwMGZmYjY5OGM0YzgyNWY2ZDVmMjMxMGZiMDQ1MWM4NjkzNDViNzMxOWY2NDU2MDU3MjEnLFxuICAgICAgICAnOWU5OTQ5ODBkOTkxN2UyMmI3NmIwNjE5MjdmYTA0MTQzZDA5NmNjYzU0OTYzZTZhNWViZmE1ZjNmOGUyODZjMSdcbiAgICAgIF0sXG4gICAgICBbXG4gICAgICAgICcxYjM4OTAzYTQzZjdmMTE0ZWQ0NTAwYjRlYWM3MDgzZmRlZmVjZTFjZjI5YzYzNTI4ZDU2MzQ0NmY5NzJjMTgwJyxcbiAgICAgICAgJzQwMzZlZGM5MzFhNjBhZTg4OTM1M2Y3N2ZkNTNkZTRhMjcwOGIyNmI2ZjVkYTcyYWQzMzk0MTE5ZGFmNDA4ZjknXG4gICAgICBdXG4gICAgXVxuICB9XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG52YXIgdXRpbHMgPSBleHBvcnRzO1xudmFyIEJOID0gcmVxdWlyZSgnYm4uanMnKTtcblxudXRpbHMuYXNzZXJ0ID0gZnVuY3Rpb24gYXNzZXJ0KHZhbCwgbXNnKSB7XG4gIGlmICghdmFsKVxuICAgIHRocm93IG5ldyBFcnJvcihtc2cgfHwgJ0Fzc2VydGlvbiBmYWlsZWQnKTtcbn07XG5cbmZ1bmN0aW9uIHRvQXJyYXkobXNnLCBlbmMpIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkobXNnKSlcbiAgICByZXR1cm4gbXNnLnNsaWNlKCk7XG4gIGlmICghbXNnKVxuICAgIHJldHVybiBbXTtcbiAgdmFyIHJlcyA9IFtdO1xuICBpZiAodHlwZW9mIG1zZyAhPT0gJ3N0cmluZycpIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKylcbiAgICAgIHJlc1tpXSA9IG1zZ1tpXSB8IDA7XG4gICAgcmV0dXJuIHJlcztcbiAgfVxuICBpZiAoIWVuYykge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgYyA9IG1zZy5jaGFyQ29kZUF0KGkpO1xuICAgICAgdmFyIGhpID0gYyA+PiA4O1xuICAgICAgdmFyIGxvID0gYyAmIDB4ZmY7XG4gICAgICBpZiAoaGkpXG4gICAgICAgIHJlcy5wdXNoKGhpLCBsbyk7XG4gICAgICBlbHNlXG4gICAgICAgIHJlcy5wdXNoKGxvKTtcbiAgICB9XG4gIH0gZWxzZSBpZiAoZW5jID09PSAnaGV4Jykge1xuICAgIG1zZyA9IG1zZy5yZXBsYWNlKC9bXmEtejAtOV0rL2lnLCAnJyk7XG4gICAgaWYgKG1zZy5sZW5ndGggJSAyICE9PSAwKVxuICAgICAgbXNnID0gJzAnICsgbXNnO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSArPSAyKVxuICAgICAgcmVzLnB1c2gocGFyc2VJbnQobXNnW2ldICsgbXNnW2kgKyAxXSwgMTYpKTtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxudXRpbHMudG9BcnJheSA9IHRvQXJyYXk7XG5cbmZ1bmN0aW9uIHplcm8yKHdvcmQpIHtcbiAgaWYgKHdvcmQubGVuZ3RoID09PSAxKVxuICAgIHJldHVybiAnMCcgKyB3b3JkO1xuICBlbHNlXG4gICAgcmV0dXJuIHdvcmQ7XG59XG51dGlscy56ZXJvMiA9IHplcm8yO1xuXG5mdW5jdGlvbiB0b0hleChtc2cpIHtcbiAgdmFyIHJlcyA9ICcnO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKylcbiAgICByZXMgKz0gemVybzIobXNnW2ldLnRvU3RyaW5nKDE2KSk7XG4gIHJldHVybiByZXM7XG59XG51dGlscy50b0hleCA9IHRvSGV4O1xuXG51dGlscy5lbmNvZGUgPSBmdW5jdGlvbiBlbmNvZGUoYXJyLCBlbmMpIHtcbiAgaWYgKGVuYyA9PT0gJ2hleCcpXG4gICAgcmV0dXJuIHRvSGV4KGFycik7XG4gIGVsc2VcbiAgICByZXR1cm4gYXJyO1xufTtcblxuLy8gUmVwcmVzZW50IG51bSBpbiBhIHctTkFGIGZvcm1cbmZ1bmN0aW9uIGdldE5BRihudW0sIHcpIHtcbiAgdmFyIG5hZiA9IFtdO1xuICB2YXIgd3MgPSAxIDw8ICh3ICsgMSk7XG4gIHZhciBrID0gbnVtLmNsb25lKCk7XG4gIHdoaWxlIChrLmNtcG4oMSkgPj0gMCkge1xuICAgIHZhciB6O1xuICAgIGlmIChrLmlzT2RkKCkpIHtcbiAgICAgIHZhciBtb2QgPSBrLmFuZGxuKHdzIC0gMSk7XG4gICAgICBpZiAobW9kID4gKHdzID4+IDEpIC0gMSlcbiAgICAgICAgeiA9ICh3cyA+PiAxKSAtIG1vZDtcbiAgICAgIGVsc2VcbiAgICAgICAgeiA9IG1vZDtcbiAgICAgIGsuaXN1Ym4oeik7XG4gICAgfSBlbHNlIHtcbiAgICAgIHogPSAwO1xuICAgIH1cbiAgICBuYWYucHVzaCh6KTtcblxuICAgIC8vIE9wdGltaXphdGlvbiwgc2hpZnQgYnkgd29yZCBpZiBwb3NzaWJsZVxuICAgIHZhciBzaGlmdCA9IChrLmNtcG4oMCkgIT09IDAgJiYgay5hbmRsbih3cyAtIDEpID09PSAwKSA/ICh3ICsgMSkgOiAxO1xuICAgIGZvciAodmFyIGkgPSAxOyBpIDwgc2hpZnQ7IGkrKylcbiAgICAgIG5hZi5wdXNoKDApO1xuICAgIGsuaXVzaHJuKHNoaWZ0KTtcbiAgfVxuXG4gIHJldHVybiBuYWY7XG59XG51dGlscy5nZXROQUYgPSBnZXROQUY7XG5cbi8vIFJlcHJlc2VudCBrMSwgazIgaW4gYSBKb2ludCBTcGFyc2UgRm9ybVxuZnVuY3Rpb24gZ2V0SlNGKGsxLCBrMikge1xuICB2YXIganNmID0gW1xuICAgIFtdLFxuICAgIFtdXG4gIF07XG5cbiAgazEgPSBrMS5jbG9uZSgpO1xuICBrMiA9IGsyLmNsb25lKCk7XG4gIHZhciBkMSA9IDA7XG4gIHZhciBkMiA9IDA7XG4gIHdoaWxlIChrMS5jbXBuKC1kMSkgPiAwIHx8IGsyLmNtcG4oLWQyKSA+IDApIHtcblxuICAgIC8vIEZpcnN0IHBoYXNlXG4gICAgdmFyIG0xNCA9IChrMS5hbmRsbigzKSArIGQxKSAmIDM7XG4gICAgdmFyIG0yNCA9IChrMi5hbmRsbigzKSArIGQyKSAmIDM7XG4gICAgaWYgKG0xNCA9PT0gMylcbiAgICAgIG0xNCA9IC0xO1xuICAgIGlmIChtMjQgPT09IDMpXG4gICAgICBtMjQgPSAtMTtcbiAgICB2YXIgdTE7XG4gICAgaWYgKChtMTQgJiAxKSA9PT0gMCkge1xuICAgICAgdTEgPSAwO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbTggPSAoazEuYW5kbG4oNykgKyBkMSkgJiA3O1xuICAgICAgaWYgKChtOCA9PT0gMyB8fCBtOCA9PT0gNSkgJiYgbTI0ID09PSAyKVxuICAgICAgICB1MSA9IC1tMTQ7XG4gICAgICBlbHNlXG4gICAgICAgIHUxID0gbTE0O1xuICAgIH1cbiAgICBqc2ZbMF0ucHVzaCh1MSk7XG5cbiAgICB2YXIgdTI7XG4gICAgaWYgKChtMjQgJiAxKSA9PT0gMCkge1xuICAgICAgdTIgPSAwO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbTggPSAoazIuYW5kbG4oNykgKyBkMikgJiA3O1xuICAgICAgaWYgKChtOCA9PT0gMyB8fCBtOCA9PT0gNSkgJiYgbTE0ID09PSAyKVxuICAgICAgICB1MiA9IC1tMjQ7XG4gICAgICBlbHNlXG4gICAgICAgIHUyID0gbTI0O1xuICAgIH1cbiAgICBqc2ZbMV0ucHVzaCh1Mik7XG5cbiAgICAvLyBTZWNvbmQgcGhhc2VcbiAgICBpZiAoMiAqIGQxID09PSB1MSArIDEpXG4gICAgICBkMSA9IDEgLSBkMTtcbiAgICBpZiAoMiAqIGQyID09PSB1MiArIDEpXG4gICAgICBkMiA9IDEgLSBkMjtcbiAgICBrMS5pdXNocm4oMSk7XG4gICAgazIuaXVzaHJuKDEpO1xuICB9XG5cbiAgcmV0dXJuIGpzZjtcbn1cbnV0aWxzLmdldEpTRiA9IGdldEpTRjtcblxuZnVuY3Rpb24gY2FjaGVkUHJvcGVydHkob2JqLCBuYW1lLCBjb21wdXRlcikge1xuICB2YXIga2V5ID0gJ18nICsgbmFtZTtcbiAgb2JqLnByb3RvdHlwZVtuYW1lXSA9IGZ1bmN0aW9uIGNhY2hlZFByb3BlcnR5KCkge1xuICAgIHJldHVybiB0aGlzW2tleV0gIT09IHVuZGVmaW5lZCA/IHRoaXNba2V5XSA6XG4gICAgICAgICAgIHRoaXNba2V5XSA9IGNvbXB1dGVyLmNhbGwodGhpcyk7XG4gIH07XG59XG51dGlscy5jYWNoZWRQcm9wZXJ0eSA9IGNhY2hlZFByb3BlcnR5O1xuXG5mdW5jdGlvbiBwYXJzZUJ5dGVzKGJ5dGVzKSB7XG4gIHJldHVybiB0eXBlb2YgYnl0ZXMgPT09ICdzdHJpbmcnID8gdXRpbHMudG9BcnJheShieXRlcywgJ2hleCcpIDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBieXRlcztcbn1cbnV0aWxzLnBhcnNlQnl0ZXMgPSBwYXJzZUJ5dGVzO1xuXG5mdW5jdGlvbiBpbnRGcm9tTEUoYnl0ZXMpIHtcbiAgcmV0dXJuIG5ldyBCTihieXRlcywgJ2hleCcsICdsZScpO1xufVxudXRpbHMuaW50RnJvbUxFID0gaW50RnJvbUxFO1xuXG4iLCJtb2R1bGUuZXhwb3J0cz17XG4gIFwiX2FyZ3NcIjogW1xuICAgIFtcbiAgICAgIFwiZWxsaXB0aWNAXjYuMC4wXCIsXG4gICAgICBcIi9Vc2Vycy9jbWV0Y2FsZi9wcm9qZWN0cy9nZW4tY3NyL25vZGVfbW9kdWxlcy9icm93c2VyaWZ5LXNpZ25cIlxuICAgIF1cbiAgXSxcbiAgXCJfZnJvbVwiOiBcImVsbGlwdGljQD49Ni4wLjAgPDcuMC4wXCIsXG4gIFwiX2lkXCI6IFwiZWxsaXB0aWNANi4yLjdcIixcbiAgXCJfaW5DYWNoZVwiOiB0cnVlLFxuICBcIl9pbnN0YWxsYWJsZVwiOiB0cnVlLFxuICBcIl9sb2NhdGlvblwiOiBcIi9lbGxpcHRpY1wiLFxuICBcIl9ub2RlVmVyc2lvblwiOiBcIjYuMC4wXCIsXG4gIFwiX25wbU9wZXJhdGlvbmFsSW50ZXJuYWxcIjoge1xuICAgIFwiaG9zdFwiOiBcInBhY2thZ2VzLTEyLXdlc3QuaW50ZXJuYWwubnBtanMuY29tXCIsXG4gICAgXCJ0bXBcIjogXCJ0bXAvZWxsaXB0aWMtNi4yLjcudGd6XzE0NjQyMDE3OTMyMDJfMC4xMjQ3OTg3ODI4NjgzMTA4MVwiXG4gIH0sXG4gIFwiX25wbVVzZXJcIjoge1xuICAgIFwiZW1haWxcIjogXCJmZWRvckBpbmR1dG55LmNvbVwiLFxuICAgIFwibmFtZVwiOiBcImluZHV0bnlcIlxuICB9LFxuICBcIl9ucG1WZXJzaW9uXCI6IFwiMy44LjZcIixcbiAgXCJfcGhhbnRvbUNoaWxkcmVuXCI6IHt9LFxuICBcIl9yZXF1ZXN0ZWRcIjoge1xuICAgIFwibmFtZVwiOiBcImVsbGlwdGljXCIsXG4gICAgXCJyYXdcIjogXCJlbGxpcHRpY0BeNi4wLjBcIixcbiAgICBcInJhd1NwZWNcIjogXCJeNi4wLjBcIixcbiAgICBcInNjb3BlXCI6IG51bGwsXG4gICAgXCJzcGVjXCI6IFwiPj02LjAuMCA8Ny4wLjBcIixcbiAgICBcInR5cGVcIjogXCJyYW5nZVwiXG4gIH0sXG4gIFwiX3JlcXVpcmVkQnlcIjogW1xuICAgIFwiL2Jyb3dzZXJpZnktc2lnblwiLFxuICAgIFwiL2NyZWF0ZS1lY2RoXCJcbiAgXSxcbiAgXCJfcmVzb2x2ZWRcIjogXCJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZy9lbGxpcHRpYy8tL2VsbGlwdGljLTYuMi43LnRnelwiLFxuICBcIl9zaGFzdW1cIjogXCJkY2U4MmVmYmYxNzZlZWZhNzQ5NWQ0YmUzZThiOWY1YjU2OTRiMjk1XCIsXG4gIFwiX3Nocmlua3dyYXBcIjogbnVsbCxcbiAgXCJfc3BlY1wiOiBcImVsbGlwdGljQF42LjAuMFwiLFxuICBcIl93aGVyZVwiOiBcIi9Vc2Vycy9jbWV0Y2FsZi9wcm9qZWN0cy9nZW4tY3NyL25vZGVfbW9kdWxlcy9icm93c2VyaWZ5LXNpZ25cIixcbiAgXCJhdXRob3JcIjoge1xuICAgIFwiZW1haWxcIjogXCJmZWRvckBpbmR1dG55LmNvbVwiLFxuICAgIFwibmFtZVwiOiBcIkZlZG9yIEluZHV0bnlcIlxuICB9LFxuICBcImJ1Z3NcIjoge1xuICAgIFwidXJsXCI6IFwiaHR0cHM6Ly9naXRodWIuY29tL2luZHV0bnkvZWxsaXB0aWMvaXNzdWVzXCJcbiAgfSxcbiAgXCJkZXBlbmRlbmNpZXNcIjoge1xuICAgIFwiYm4uanNcIjogXCJeNC4wLjBcIixcbiAgICBcImJyb3JhbmRcIjogXCJeMS4wLjFcIixcbiAgICBcImhhc2guanNcIjogXCJeMS4wLjBcIixcbiAgICBcImluaGVyaXRzXCI6IFwiXjIuMC4xXCJcbiAgfSxcbiAgXCJkZXNjcmlwdGlvblwiOiBcIkVDIGNyeXB0b2dyYXBoeVwiLFxuICBcImRldkRlcGVuZGVuY2llc1wiOiB7XG4gICAgXCJicmZzXCI6IFwiXjEuNC4zXCIsXG4gICAgXCJjb3ZlcmFsbHNcIjogXCJeMi4xMS4zXCIsXG4gICAgXCJncnVudFwiOiBcIl4wLjQuNVwiLFxuICAgIFwiZ3J1bnQtYnJvd3NlcmlmeVwiOiBcIl41LjAuMFwiLFxuICAgIFwiZ3J1bnQtY29udHJpYi1jb25uZWN0XCI6IFwiXjEuMC4wXCIsXG4gICAgXCJncnVudC1jb250cmliLWNvcHlcIjogXCJeMS4wLjBcIixcbiAgICBcImdydW50LWNvbnRyaWItdWdsaWZ5XCI6IFwiXjEuMC4xXCIsXG4gICAgXCJncnVudC1tb2NoYS1pc3RhbmJ1bFwiOiBcIl4zLjAuMVwiLFxuICAgIFwiZ3J1bnQtc2F1Y2VsYWJzXCI6IFwiXjguNi4yXCIsXG4gICAgXCJpc3RhbmJ1bFwiOiBcIl4wLjQuMlwiLFxuICAgIFwianNjc1wiOiBcIl4yLjkuMFwiLFxuICAgIFwianNoaW50XCI6IFwiXjIuNi4wXCIsXG4gICAgXCJtb2NoYVwiOiBcIl4yLjEuMFwiXG4gIH0sXG4gIFwiZGlyZWN0b3JpZXNcIjoge30sXG4gIFwiZGlzdFwiOiB7XG4gICAgXCJzaGFzdW1cIjogXCJkY2U4MmVmYmYxNzZlZWZhNzQ5NWQ0YmUzZThiOWY1YjU2OTRiMjk1XCIsXG4gICAgXCJ0YXJiYWxsXCI6IFwiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmcvZWxsaXB0aWMvLS9lbGxpcHRpYy02LjIuNy50Z3pcIlxuICB9LFxuICBcImZpbGVzXCI6IFtcbiAgICBcImxpYlwiXG4gIF0sXG4gIFwiZ2l0SGVhZFwiOiBcIjZhOGVmMTQ1N2JiOGY0NTEwMmQ2Njc4ZmMxMDk1MTY1Zjc3ZDU1ZDNcIixcbiAgXCJob21lcGFnZVwiOiBcImh0dHBzOi8vZ2l0aHViLmNvbS9pbmR1dG55L2VsbGlwdGljXCIsXG4gIFwia2V5d29yZHNcIjogW1xuICAgIFwiRUNcIixcbiAgICBcIkVsbGlwdGljXCIsXG4gICAgXCJjdXJ2ZVwiLFxuICAgIFwiQ3J5cHRvZ3JhcGh5XCJcbiAgXSxcbiAgXCJsaWNlbnNlXCI6IFwiTUlUXCIsXG4gIFwibWFpblwiOiBcImxpYi9lbGxpcHRpYy5qc1wiLFxuICBcIm1haW50YWluZXJzXCI6IFtcbiAgICB7XG4gICAgICBcImVtYWlsXCI6IFwiZmVkb3JAaW5kdXRueS5jb21cIixcbiAgICAgIFwibmFtZVwiOiBcImluZHV0bnlcIlxuICAgIH1cbiAgXSxcbiAgXCJuYW1lXCI6IFwiZWxsaXB0aWNcIixcbiAgXCJvcHRpb25hbERlcGVuZGVuY2llc1wiOiB7fSxcbiAgXCJyZWFkbWVcIjogXCJFUlJPUjogTm8gUkVBRE1FIGRhdGEgZm91bmQhXCIsXG4gIFwicmVwb3NpdG9yeVwiOiB7XG4gICAgXCJ0eXBlXCI6IFwiZ2l0XCIsXG4gICAgXCJ1cmxcIjogXCJnaXQrc3NoOi8vZ2l0QGdpdGh1Yi5jb20vaW5kdXRueS9lbGxpcHRpYy5naXRcIlxuICB9LFxuICBcInNjcmlwdHNcIjoge1xuICAgIFwianNjc1wiOiBcImpzY3MgYmVuY2htYXJrcy8qLmpzIGxpYi8qLmpzIGxpYi8qKi8qLmpzIGxpYi8qKi8qKi8qLmpzIHRlc3QvaW5kZXguanNcIixcbiAgICBcImpzaGludFwiOiBcImpzY3MgYmVuY2htYXJrcy8qLmpzIGxpYi8qLmpzIGxpYi8qKi8qLmpzIGxpYi8qKi8qKi8qLmpzIHRlc3QvaW5kZXguanNcIixcbiAgICBcImxpbnRcIjogXCJucG0gcnVuIGpzY3MgJiYgbnBtIHJ1biBqc2hpbnRcIixcbiAgICBcInRlc3RcIjogXCJucG0gcnVuIGxpbnQgJiYgbnBtIHJ1biB1bml0XCIsXG4gICAgXCJ1bml0XCI6IFwiaXN0YW5idWwgdGVzdCBfbW9jaGEgLS1yZXBvcnRlcj1zcGVjIHRlc3QvaW5kZXguanNcIixcbiAgICBcInZlcnNpb25cIjogXCJncnVudCBkaXN0ICYmIGdpdCBhZGQgZGlzdC9cIlxuICB9LFxuICBcInZlcnNpb25cIjogXCI2LjIuN1wiXG59XG4iLCJ2YXIgaGFzaCA9IGV4cG9ydHM7XG5cbmhhc2gudXRpbHMgPSByZXF1aXJlKCcuL2hhc2gvdXRpbHMnKTtcbmhhc2guY29tbW9uID0gcmVxdWlyZSgnLi9oYXNoL2NvbW1vbicpO1xuaGFzaC5zaGEgPSByZXF1aXJlKCcuL2hhc2gvc2hhJyk7XG5oYXNoLnJpcGVtZCA9IHJlcXVpcmUoJy4vaGFzaC9yaXBlbWQnKTtcbmhhc2guaG1hYyA9IHJlcXVpcmUoJy4vaGFzaC9obWFjJyk7XG5cbi8vIFByb3h5IGhhc2ggZnVuY3Rpb25zIHRvIHRoZSBtYWluIG9iamVjdFxuaGFzaC5zaGExID0gaGFzaC5zaGEuc2hhMTtcbmhhc2guc2hhMjU2ID0gaGFzaC5zaGEuc2hhMjU2O1xuaGFzaC5zaGEyMjQgPSBoYXNoLnNoYS5zaGEyMjQ7XG5oYXNoLnNoYTM4NCA9IGhhc2guc2hhLnNoYTM4NDtcbmhhc2guc2hhNTEyID0gaGFzaC5zaGEuc2hhNTEyO1xuaGFzaC5yaXBlbWQxNjAgPSBoYXNoLnJpcGVtZC5yaXBlbWQxNjA7XG4iLCJ2YXIgaGFzaCA9IHJlcXVpcmUoJy4uL2hhc2gnKTtcbnZhciB1dGlscyA9IGhhc2gudXRpbHM7XG52YXIgYXNzZXJ0ID0gdXRpbHMuYXNzZXJ0O1xuXG5mdW5jdGlvbiBCbG9ja0hhc2goKSB7XG4gIHRoaXMucGVuZGluZyA9IG51bGw7XG4gIHRoaXMucGVuZGluZ1RvdGFsID0gMDtcbiAgdGhpcy5ibG9ja1NpemUgPSB0aGlzLmNvbnN0cnVjdG9yLmJsb2NrU2l6ZTtcbiAgdGhpcy5vdXRTaXplID0gdGhpcy5jb25zdHJ1Y3Rvci5vdXRTaXplO1xuICB0aGlzLmhtYWNTdHJlbmd0aCA9IHRoaXMuY29uc3RydWN0b3IuaG1hY1N0cmVuZ3RoO1xuICB0aGlzLnBhZExlbmd0aCA9IHRoaXMuY29uc3RydWN0b3IucGFkTGVuZ3RoIC8gODtcbiAgdGhpcy5lbmRpYW4gPSAnYmlnJztcblxuICB0aGlzLl9kZWx0YTggPSB0aGlzLmJsb2NrU2l6ZSAvIDg7XG4gIHRoaXMuX2RlbHRhMzIgPSB0aGlzLmJsb2NrU2l6ZSAvIDMyO1xufVxuZXhwb3J0cy5CbG9ja0hhc2ggPSBCbG9ja0hhc2g7XG5cbkJsb2NrSGFzaC5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24gdXBkYXRlKG1zZywgZW5jKSB7XG4gIC8vIENvbnZlcnQgbWVzc2FnZSB0byBhcnJheSwgcGFkIGl0LCBhbmQgam9pbiBpbnRvIDMyYml0IGJsb2Nrc1xuICBtc2cgPSB1dGlscy50b0FycmF5KG1zZywgZW5jKTtcbiAgaWYgKCF0aGlzLnBlbmRpbmcpXG4gICAgdGhpcy5wZW5kaW5nID0gbXNnO1xuICBlbHNlXG4gICAgdGhpcy5wZW5kaW5nID0gdGhpcy5wZW5kaW5nLmNvbmNhdChtc2cpO1xuICB0aGlzLnBlbmRpbmdUb3RhbCArPSBtc2cubGVuZ3RoO1xuXG4gIC8vIEVub3VnaCBkYXRhLCB0cnkgdXBkYXRpbmdcbiAgaWYgKHRoaXMucGVuZGluZy5sZW5ndGggPj0gdGhpcy5fZGVsdGE4KSB7XG4gICAgbXNnID0gdGhpcy5wZW5kaW5nO1xuXG4gICAgLy8gUHJvY2VzcyBwZW5kaW5nIGRhdGEgaW4gYmxvY2tzXG4gICAgdmFyIHIgPSBtc2cubGVuZ3RoICUgdGhpcy5fZGVsdGE4O1xuICAgIHRoaXMucGVuZGluZyA9IG1zZy5zbGljZShtc2cubGVuZ3RoIC0gciwgbXNnLmxlbmd0aCk7XG4gICAgaWYgKHRoaXMucGVuZGluZy5sZW5ndGggPT09IDApXG4gICAgICB0aGlzLnBlbmRpbmcgPSBudWxsO1xuXG4gICAgbXNnID0gdXRpbHMuam9pbjMyKG1zZywgMCwgbXNnLmxlbmd0aCAtIHIsIHRoaXMuZW5kaWFuKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkgKz0gdGhpcy5fZGVsdGEzMilcbiAgICAgIHRoaXMuX3VwZGF0ZShtc2csIGksIGkgKyB0aGlzLl9kZWx0YTMyKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuQmxvY2tIYXNoLnByb3RvdHlwZS5kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIHRoaXMudXBkYXRlKHRoaXMuX3BhZCgpKTtcbiAgYXNzZXJ0KHRoaXMucGVuZGluZyA9PT0gbnVsbCk7XG5cbiAgcmV0dXJuIHRoaXMuX2RpZ2VzdChlbmMpO1xufTtcblxuQmxvY2tIYXNoLnByb3RvdHlwZS5fcGFkID0gZnVuY3Rpb24gcGFkKCkge1xuICB2YXIgbGVuID0gdGhpcy5wZW5kaW5nVG90YWw7XG4gIHZhciBieXRlcyA9IHRoaXMuX2RlbHRhODtcbiAgdmFyIGsgPSBieXRlcyAtICgobGVuICsgdGhpcy5wYWRMZW5ndGgpICUgYnl0ZXMpO1xuICB2YXIgcmVzID0gbmV3IEFycmF5KGsgKyB0aGlzLnBhZExlbmd0aCk7XG4gIHJlc1swXSA9IDB4ODA7XG4gIGZvciAodmFyIGkgPSAxOyBpIDwgazsgaSsrKVxuICAgIHJlc1tpXSA9IDA7XG5cbiAgLy8gQXBwZW5kIGxlbmd0aFxuICBsZW4gPDw9IDM7XG4gIGlmICh0aGlzLmVuZGlhbiA9PT0gJ2JpZycpIHtcbiAgICBmb3IgKHZhciB0ID0gODsgdCA8IHRoaXMucGFkTGVuZ3RoOyB0KyspXG4gICAgICByZXNbaSsrXSA9IDA7XG5cbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAwO1xuICAgIHJlc1tpKytdID0gMDtcbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAobGVuID4+PiAyNCkgJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gMTYpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IChsZW4gPj4+IDgpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IGxlbiAmIDB4ZmY7XG4gIH0gZWxzZSB7XG4gICAgcmVzW2krK10gPSBsZW4gJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gOCkgJiAweGZmO1xuICAgIHJlc1tpKytdID0gKGxlbiA+Pj4gMTYpICYgMHhmZjtcbiAgICByZXNbaSsrXSA9IChsZW4gPj4+IDI0KSAmIDB4ZmY7XG4gICAgcmVzW2krK10gPSAwO1xuICAgIHJlc1tpKytdID0gMDtcbiAgICByZXNbaSsrXSA9IDA7XG4gICAgcmVzW2krK10gPSAwO1xuXG4gICAgZm9yICh2YXIgdCA9IDg7IHQgPCB0aGlzLnBhZExlbmd0aDsgdCsrKVxuICAgICAgcmVzW2krK10gPSAwO1xuICB9XG5cbiAgcmV0dXJuIHJlcztcbn07XG4iLCJ2YXIgaG1hYyA9IGV4cG9ydHM7XG5cbnZhciBoYXNoID0gcmVxdWlyZSgnLi4vaGFzaCcpO1xudmFyIHV0aWxzID0gaGFzaC51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbmZ1bmN0aW9uIEhtYWMoaGFzaCwga2V5LCBlbmMpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIEhtYWMpKVxuICAgIHJldHVybiBuZXcgSG1hYyhoYXNoLCBrZXksIGVuYyk7XG4gIHRoaXMuSGFzaCA9IGhhc2g7XG4gIHRoaXMuYmxvY2tTaXplID0gaGFzaC5ibG9ja1NpemUgLyA4O1xuICB0aGlzLm91dFNpemUgPSBoYXNoLm91dFNpemUgLyA4O1xuICB0aGlzLmlubmVyID0gbnVsbDtcbiAgdGhpcy5vdXRlciA9IG51bGw7XG5cbiAgdGhpcy5faW5pdCh1dGlscy50b0FycmF5KGtleSwgZW5jKSk7XG59XG5tb2R1bGUuZXhwb3J0cyA9IEhtYWM7XG5cbkhtYWMucHJvdG90eXBlLl9pbml0ID0gZnVuY3Rpb24gaW5pdChrZXkpIHtcbiAgLy8gU2hvcnRlbiBrZXksIGlmIG5lZWRlZFxuICBpZiAoa2V5Lmxlbmd0aCA+IHRoaXMuYmxvY2tTaXplKVxuICAgIGtleSA9IG5ldyB0aGlzLkhhc2goKS51cGRhdGUoa2V5KS5kaWdlc3QoKTtcbiAgYXNzZXJ0KGtleS5sZW5ndGggPD0gdGhpcy5ibG9ja1NpemUpO1xuXG4gIC8vIEFkZCBwYWRkaW5nIHRvIGtleVxuICBmb3IgKHZhciBpID0ga2V5Lmxlbmd0aDsgaSA8IHRoaXMuYmxvY2tTaXplOyBpKyspXG4gICAga2V5LnB1c2goMCk7XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBrZXkubGVuZ3RoOyBpKyspXG4gICAga2V5W2ldIF49IDB4MzY7XG4gIHRoaXMuaW5uZXIgPSBuZXcgdGhpcy5IYXNoKCkudXBkYXRlKGtleSk7XG5cbiAgLy8gMHgzNiBeIDB4NWMgPSAweDZhXG4gIGZvciAodmFyIGkgPSAwOyBpIDwga2V5Lmxlbmd0aDsgaSsrKVxuICAgIGtleVtpXSBePSAweDZhO1xuICB0aGlzLm91dGVyID0gbmV3IHRoaXMuSGFzaCgpLnVwZGF0ZShrZXkpO1xufTtcblxuSG1hYy5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24gdXBkYXRlKG1zZywgZW5jKSB7XG4gIHRoaXMuaW5uZXIudXBkYXRlKG1zZywgZW5jKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5IbWFjLnByb3RvdHlwZS5kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIHRoaXMub3V0ZXIudXBkYXRlKHRoaXMuaW5uZXIuZGlnZXN0KCkpO1xuICByZXR1cm4gdGhpcy5vdXRlci5kaWdlc3QoZW5jKTtcbn07XG4iLCJ2YXIgaGFzaCA9IHJlcXVpcmUoJy4uL2hhc2gnKTtcbnZhciB1dGlscyA9IGhhc2gudXRpbHM7XG5cbnZhciByb3RsMzIgPSB1dGlscy5yb3RsMzI7XG52YXIgc3VtMzIgPSB1dGlscy5zdW0zMjtcbnZhciBzdW0zMl8zID0gdXRpbHMuc3VtMzJfMztcbnZhciBzdW0zMl80ID0gdXRpbHMuc3VtMzJfNDtcbnZhciBCbG9ja0hhc2ggPSBoYXNoLmNvbW1vbi5CbG9ja0hhc2g7XG5cbmZ1bmN0aW9uIFJJUEVNRDE2MCgpIHtcbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIFJJUEVNRDE2MCkpXG4gICAgcmV0dXJuIG5ldyBSSVBFTUQxNjAoKTtcblxuICBCbG9ja0hhc2guY2FsbCh0aGlzKTtcblxuICB0aGlzLmggPSBbIDB4Njc0NTIzMDEsIDB4ZWZjZGFiODksIDB4OThiYWRjZmUsIDB4MTAzMjU0NzYsIDB4YzNkMmUxZjAgXTtcbiAgdGhpcy5lbmRpYW4gPSAnbGl0dGxlJztcbn1cbnV0aWxzLmluaGVyaXRzKFJJUEVNRDE2MCwgQmxvY2tIYXNoKTtcbmV4cG9ydHMucmlwZW1kMTYwID0gUklQRU1EMTYwO1xuXG5SSVBFTUQxNjAuYmxvY2tTaXplID0gNTEyO1xuUklQRU1EMTYwLm91dFNpemUgPSAxNjA7XG5SSVBFTUQxNjAuaG1hY1N0cmVuZ3RoID0gMTkyO1xuUklQRU1EMTYwLnBhZExlbmd0aCA9IDY0O1xuXG5SSVBFTUQxNjAucHJvdG90eXBlLl91cGRhdGUgPSBmdW5jdGlvbiB1cGRhdGUobXNnLCBzdGFydCkge1xuICB2YXIgQSA9IHRoaXMuaFswXTtcbiAgdmFyIEIgPSB0aGlzLmhbMV07XG4gIHZhciBDID0gdGhpcy5oWzJdO1xuICB2YXIgRCA9IHRoaXMuaFszXTtcbiAgdmFyIEUgPSB0aGlzLmhbNF07XG4gIHZhciBBaCA9IEE7XG4gIHZhciBCaCA9IEI7XG4gIHZhciBDaCA9IEM7XG4gIHZhciBEaCA9IEQ7XG4gIHZhciBFaCA9IEU7XG4gIGZvciAodmFyIGogPSAwOyBqIDwgODA7IGorKykge1xuICAgIHZhciBUID0gc3VtMzIoXG4gICAgICByb3RsMzIoXG4gICAgICAgIHN1bTMyXzQoQSwgZihqLCBCLCBDLCBEKSwgbXNnW3Jbal0gKyBzdGFydF0sIEsoaikpLFxuICAgICAgICBzW2pdKSxcbiAgICAgIEUpO1xuICAgIEEgPSBFO1xuICAgIEUgPSBEO1xuICAgIEQgPSByb3RsMzIoQywgMTApO1xuICAgIEMgPSBCO1xuICAgIEIgPSBUO1xuICAgIFQgPSBzdW0zMihcbiAgICAgIHJvdGwzMihcbiAgICAgICAgc3VtMzJfNChBaCwgZig3OSAtIGosIEJoLCBDaCwgRGgpLCBtc2dbcmhbal0gKyBzdGFydF0sIEtoKGopKSxcbiAgICAgICAgc2hbal0pLFxuICAgICAgRWgpO1xuICAgIEFoID0gRWg7XG4gICAgRWggPSBEaDtcbiAgICBEaCA9IHJvdGwzMihDaCwgMTApO1xuICAgIENoID0gQmg7XG4gICAgQmggPSBUO1xuICB9XG4gIFQgPSBzdW0zMl8zKHRoaXMuaFsxXSwgQywgRGgpO1xuICB0aGlzLmhbMV0gPSBzdW0zMl8zKHRoaXMuaFsyXSwgRCwgRWgpO1xuICB0aGlzLmhbMl0gPSBzdW0zMl8zKHRoaXMuaFszXSwgRSwgQWgpO1xuICB0aGlzLmhbM10gPSBzdW0zMl8zKHRoaXMuaFs0XSwgQSwgQmgpO1xuICB0aGlzLmhbNF0gPSBzdW0zMl8zKHRoaXMuaFswXSwgQiwgQ2gpO1xuICB0aGlzLmhbMF0gPSBUO1xufTtcblxuUklQRU1EMTYwLnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmgsICdsaXR0bGUnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaCwgJ2xpdHRsZScpO1xufTtcblxuZnVuY3Rpb24gZihqLCB4LCB5LCB6KSB7XG4gIGlmIChqIDw9IDE1KVxuICAgIHJldHVybiB4IF4geSBeIHo7XG4gIGVsc2UgaWYgKGogPD0gMzEpXG4gICAgcmV0dXJuICh4ICYgeSkgfCAoKH54KSAmIHopO1xuICBlbHNlIGlmIChqIDw9IDQ3KVxuICAgIHJldHVybiAoeCB8ICh+eSkpIF4gejtcbiAgZWxzZSBpZiAoaiA8PSA2MylcbiAgICByZXR1cm4gKHggJiB6KSB8ICh5ICYgKH56KSk7XG4gIGVsc2VcbiAgICByZXR1cm4geCBeICh5IHwgKH56KSk7XG59XG5cbmZ1bmN0aW9uIEsoaikge1xuICBpZiAoaiA8PSAxNSlcbiAgICByZXR1cm4gMHgwMDAwMDAwMDtcbiAgZWxzZSBpZiAoaiA8PSAzMSlcbiAgICByZXR1cm4gMHg1YTgyNzk5OTtcbiAgZWxzZSBpZiAoaiA8PSA0NylcbiAgICByZXR1cm4gMHg2ZWQ5ZWJhMTtcbiAgZWxzZSBpZiAoaiA8PSA2MylcbiAgICByZXR1cm4gMHg4ZjFiYmNkYztcbiAgZWxzZVxuICAgIHJldHVybiAweGE5NTNmZDRlO1xufVxuXG5mdW5jdGlvbiBLaChqKSB7XG4gIGlmIChqIDw9IDE1KVxuICAgIHJldHVybiAweDUwYTI4YmU2O1xuICBlbHNlIGlmIChqIDw9IDMxKVxuICAgIHJldHVybiAweDVjNGRkMTI0O1xuICBlbHNlIGlmIChqIDw9IDQ3KVxuICAgIHJldHVybiAweDZkNzAzZWYzO1xuICBlbHNlIGlmIChqIDw9IDYzKVxuICAgIHJldHVybiAweDdhNmQ3NmU5O1xuICBlbHNlXG4gICAgcmV0dXJuIDB4MDAwMDAwMDA7XG59XG5cbnZhciByID0gW1xuICAwLCAxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5LCAxMCwgMTEsIDEyLCAxMywgMTQsIDE1LFxuICA3LCA0LCAxMywgMSwgMTAsIDYsIDE1LCAzLCAxMiwgMCwgOSwgNSwgMiwgMTQsIDExLCA4LFxuICAzLCAxMCwgMTQsIDQsIDksIDE1LCA4LCAxLCAyLCA3LCAwLCA2LCAxMywgMTEsIDUsIDEyLFxuICAxLCA5LCAxMSwgMTAsIDAsIDgsIDEyLCA0LCAxMywgMywgNywgMTUsIDE0LCA1LCA2LCAyLFxuICA0LCAwLCA1LCA5LCA3LCAxMiwgMiwgMTAsIDE0LCAxLCAzLCA4LCAxMSwgNiwgMTUsIDEzXG5dO1xuXG52YXIgcmggPSBbXG4gIDUsIDE0LCA3LCAwLCA5LCAyLCAxMSwgNCwgMTMsIDYsIDE1LCA4LCAxLCAxMCwgMywgMTIsXG4gIDYsIDExLCAzLCA3LCAwLCAxMywgNSwgMTAsIDE0LCAxNSwgOCwgMTIsIDQsIDksIDEsIDIsXG4gIDE1LCA1LCAxLCAzLCA3LCAxNCwgNiwgOSwgMTEsIDgsIDEyLCAyLCAxMCwgMCwgNCwgMTMsXG4gIDgsIDYsIDQsIDEsIDMsIDExLCAxNSwgMCwgNSwgMTIsIDIsIDEzLCA5LCA3LCAxMCwgMTQsXG4gIDEyLCAxNSwgMTAsIDQsIDEsIDUsIDgsIDcsIDYsIDIsIDEzLCAxNCwgMCwgMywgOSwgMTFcbl07XG5cbnZhciBzID0gW1xuICAxMSwgMTQsIDE1LCAxMiwgNSwgOCwgNywgOSwgMTEsIDEzLCAxNCwgMTUsIDYsIDcsIDksIDgsXG4gIDcsIDYsIDgsIDEzLCAxMSwgOSwgNywgMTUsIDcsIDEyLCAxNSwgOSwgMTEsIDcsIDEzLCAxMixcbiAgMTEsIDEzLCA2LCA3LCAxNCwgOSwgMTMsIDE1LCAxNCwgOCwgMTMsIDYsIDUsIDEyLCA3LCA1LFxuICAxMSwgMTIsIDE0LCAxNSwgMTQsIDE1LCA5LCA4LCA5LCAxNCwgNSwgNiwgOCwgNiwgNSwgMTIsXG4gIDksIDE1LCA1LCAxMSwgNiwgOCwgMTMsIDEyLCA1LCAxMiwgMTMsIDE0LCAxMSwgOCwgNSwgNlxuXTtcblxudmFyIHNoID0gW1xuICA4LCA5LCA5LCAxMSwgMTMsIDE1LCAxNSwgNSwgNywgNywgOCwgMTEsIDE0LCAxNCwgMTIsIDYsXG4gIDksIDEzLCAxNSwgNywgMTIsIDgsIDksIDExLCA3LCA3LCAxMiwgNywgNiwgMTUsIDEzLCAxMSxcbiAgOSwgNywgMTUsIDExLCA4LCA2LCA2LCAxNCwgMTIsIDEzLCA1LCAxNCwgMTMsIDEzLCA3LCA1LFxuICAxNSwgNSwgOCwgMTEsIDE0LCAxNCwgNiwgMTQsIDYsIDksIDEyLCA5LCAxMiwgNSwgMTUsIDgsXG4gIDgsIDUsIDEyLCA5LCAxMiwgNSwgMTQsIDYsIDgsIDEzLCA2LCA1LCAxNSwgMTMsIDExLCAxMVxuXTtcbiIsInZhciBoYXNoID0gcmVxdWlyZSgnLi4vaGFzaCcpO1xudmFyIHV0aWxzID0gaGFzaC51dGlscztcbnZhciBhc3NlcnQgPSB1dGlscy5hc3NlcnQ7XG5cbnZhciByb3RyMzIgPSB1dGlscy5yb3RyMzI7XG52YXIgcm90bDMyID0gdXRpbHMucm90bDMyO1xudmFyIHN1bTMyID0gdXRpbHMuc3VtMzI7XG52YXIgc3VtMzJfNCA9IHV0aWxzLnN1bTMyXzQ7XG52YXIgc3VtMzJfNSA9IHV0aWxzLnN1bTMyXzU7XG52YXIgcm90cjY0X2hpID0gdXRpbHMucm90cjY0X2hpO1xudmFyIHJvdHI2NF9sbyA9IHV0aWxzLnJvdHI2NF9sbztcbnZhciBzaHI2NF9oaSA9IHV0aWxzLnNocjY0X2hpO1xudmFyIHNocjY0X2xvID0gdXRpbHMuc2hyNjRfbG87XG52YXIgc3VtNjQgPSB1dGlscy5zdW02NDtcbnZhciBzdW02NF9oaSA9IHV0aWxzLnN1bTY0X2hpO1xudmFyIHN1bTY0X2xvID0gdXRpbHMuc3VtNjRfbG87XG52YXIgc3VtNjRfNF9oaSA9IHV0aWxzLnN1bTY0XzRfaGk7XG52YXIgc3VtNjRfNF9sbyA9IHV0aWxzLnN1bTY0XzRfbG87XG52YXIgc3VtNjRfNV9oaSA9IHV0aWxzLnN1bTY0XzVfaGk7XG52YXIgc3VtNjRfNV9sbyA9IHV0aWxzLnN1bTY0XzVfbG87XG52YXIgQmxvY2tIYXNoID0gaGFzaC5jb21tb24uQmxvY2tIYXNoO1xuXG52YXIgc2hhMjU2X0sgPSBbXG4gIDB4NDI4YTJmOTgsIDB4NzEzNzQ0OTEsIDB4YjVjMGZiY2YsIDB4ZTliNWRiYTUsXG4gIDB4Mzk1NmMyNWIsIDB4NTlmMTExZjEsIDB4OTIzZjgyYTQsIDB4YWIxYzVlZDUsXG4gIDB4ZDgwN2FhOTgsIDB4MTI4MzViMDEsIDB4MjQzMTg1YmUsIDB4NTUwYzdkYzMsXG4gIDB4NzJiZTVkNzQsIDB4ODBkZWIxZmUsIDB4OWJkYzA2YTcsIDB4YzE5YmYxNzQsXG4gIDB4ZTQ5YjY5YzEsIDB4ZWZiZTQ3ODYsIDB4MGZjMTlkYzYsIDB4MjQwY2ExY2MsXG4gIDB4MmRlOTJjNmYsIDB4NGE3NDg0YWEsIDB4NWNiMGE5ZGMsIDB4NzZmOTg4ZGEsXG4gIDB4OTgzZTUxNTIsIDB4YTgzMWM2NmQsIDB4YjAwMzI3YzgsIDB4YmY1OTdmYzcsXG4gIDB4YzZlMDBiZjMsIDB4ZDVhNzkxNDcsIDB4MDZjYTYzNTEsIDB4MTQyOTI5NjcsXG4gIDB4MjdiNzBhODUsIDB4MmUxYjIxMzgsIDB4NGQyYzZkZmMsIDB4NTMzODBkMTMsXG4gIDB4NjUwYTczNTQsIDB4NzY2YTBhYmIsIDB4ODFjMmM5MmUsIDB4OTI3MjJjODUsXG4gIDB4YTJiZmU4YTEsIDB4YTgxYTY2NGIsIDB4YzI0YjhiNzAsIDB4Yzc2YzUxYTMsXG4gIDB4ZDE5MmU4MTksIDB4ZDY5OTA2MjQsIDB4ZjQwZTM1ODUsIDB4MTA2YWEwNzAsXG4gIDB4MTlhNGMxMTYsIDB4MWUzNzZjMDgsIDB4Mjc0ODc3NGMsIDB4MzRiMGJjYjUsXG4gIDB4MzkxYzBjYjMsIDB4NGVkOGFhNGEsIDB4NWI5Y2NhNGYsIDB4NjgyZTZmZjMsXG4gIDB4NzQ4ZjgyZWUsIDB4NzhhNTYzNmYsIDB4ODRjODc4MTQsIDB4OGNjNzAyMDgsXG4gIDB4OTBiZWZmZmEsIDB4YTQ1MDZjZWIsIDB4YmVmOWEzZjcsIDB4YzY3MTc4ZjJcbl07XG5cbnZhciBzaGE1MTJfSyA9IFtcbiAgMHg0MjhhMmY5OCwgMHhkNzI4YWUyMiwgMHg3MTM3NDQ5MSwgMHgyM2VmNjVjZCxcbiAgMHhiNWMwZmJjZiwgMHhlYzRkM2IyZiwgMHhlOWI1ZGJhNSwgMHg4MTg5ZGJiYyxcbiAgMHgzOTU2YzI1YiwgMHhmMzQ4YjUzOCwgMHg1OWYxMTFmMSwgMHhiNjA1ZDAxOSxcbiAgMHg5MjNmODJhNCwgMHhhZjE5NGY5YiwgMHhhYjFjNWVkNSwgMHhkYTZkODExOCxcbiAgMHhkODA3YWE5OCwgMHhhMzAzMDI0MiwgMHgxMjgzNWIwMSwgMHg0NTcwNmZiZSxcbiAgMHgyNDMxODViZSwgMHg0ZWU0YjI4YywgMHg1NTBjN2RjMywgMHhkNWZmYjRlMixcbiAgMHg3MmJlNWQ3NCwgMHhmMjdiODk2ZiwgMHg4MGRlYjFmZSwgMHgzYjE2OTZiMSxcbiAgMHg5YmRjMDZhNywgMHgyNWM3MTIzNSwgMHhjMTliZjE3NCwgMHhjZjY5MjY5NCxcbiAgMHhlNDliNjljMSwgMHg5ZWYxNGFkMiwgMHhlZmJlNDc4NiwgMHgzODRmMjVlMyxcbiAgMHgwZmMxOWRjNiwgMHg4YjhjZDViNSwgMHgyNDBjYTFjYywgMHg3N2FjOWM2NSxcbiAgMHgyZGU5MmM2ZiwgMHg1OTJiMDI3NSwgMHg0YTc0ODRhYSwgMHg2ZWE2ZTQ4MyxcbiAgMHg1Y2IwYTlkYywgMHhiZDQxZmJkNCwgMHg3NmY5ODhkYSwgMHg4MzExNTNiNSxcbiAgMHg5ODNlNTE1MiwgMHhlZTY2ZGZhYiwgMHhhODMxYzY2ZCwgMHgyZGI0MzIxMCxcbiAgMHhiMDAzMjdjOCwgMHg5OGZiMjEzZiwgMHhiZjU5N2ZjNywgMHhiZWVmMGVlNCxcbiAgMHhjNmUwMGJmMywgMHgzZGE4OGZjMiwgMHhkNWE3OTE0NywgMHg5MzBhYTcyNSxcbiAgMHgwNmNhNjM1MSwgMHhlMDAzODI2ZiwgMHgxNDI5Mjk2NywgMHgwYTBlNmU3MCxcbiAgMHgyN2I3MGE4NSwgMHg0NmQyMmZmYywgMHgyZTFiMjEzOCwgMHg1YzI2YzkyNixcbiAgMHg0ZDJjNmRmYywgMHg1YWM0MmFlZCwgMHg1MzM4MGQxMywgMHg5ZDk1YjNkZixcbiAgMHg2NTBhNzM1NCwgMHg4YmFmNjNkZSwgMHg3NjZhMGFiYiwgMHgzYzc3YjJhOCxcbiAgMHg4MWMyYzkyZSwgMHg0N2VkYWVlNiwgMHg5MjcyMmM4NSwgMHgxNDgyMzUzYixcbiAgMHhhMmJmZThhMSwgMHg0Y2YxMDM2NCwgMHhhODFhNjY0YiwgMHhiYzQyMzAwMSxcbiAgMHhjMjRiOGI3MCwgMHhkMGY4OTc5MSwgMHhjNzZjNTFhMywgMHgwNjU0YmUzMCxcbiAgMHhkMTkyZTgxOSwgMHhkNmVmNTIxOCwgMHhkNjk5MDYyNCwgMHg1NTY1YTkxMCxcbiAgMHhmNDBlMzU4NSwgMHg1NzcxMjAyYSwgMHgxMDZhYTA3MCwgMHgzMmJiZDFiOCxcbiAgMHgxOWE0YzExNiwgMHhiOGQyZDBjOCwgMHgxZTM3NmMwOCwgMHg1MTQxYWI1MyxcbiAgMHgyNzQ4Nzc0YywgMHhkZjhlZWI5OSwgMHgzNGIwYmNiNSwgMHhlMTliNDhhOCxcbiAgMHgzOTFjMGNiMywgMHhjNWM5NWE2MywgMHg0ZWQ4YWE0YSwgMHhlMzQxOGFjYixcbiAgMHg1YjljY2E0ZiwgMHg3NzYzZTM3MywgMHg2ODJlNmZmMywgMHhkNmIyYjhhMyxcbiAgMHg3NDhmODJlZSwgMHg1ZGVmYjJmYywgMHg3OGE1NjM2ZiwgMHg0MzE3MmY2MCxcbiAgMHg4NGM4NzgxNCwgMHhhMWYwYWI3MiwgMHg4Y2M3MDIwOCwgMHgxYTY0MzllYyxcbiAgMHg5MGJlZmZmYSwgMHgyMzYzMWUyOCwgMHhhNDUwNmNlYiwgMHhkZTgyYmRlOSxcbiAgMHhiZWY5YTNmNywgMHhiMmM2NzkxNSwgMHhjNjcxNzhmMiwgMHhlMzcyNTMyYixcbiAgMHhjYTI3M2VjZSwgMHhlYTI2NjE5YywgMHhkMTg2YjhjNywgMHgyMWMwYzIwNyxcbiAgMHhlYWRhN2RkNiwgMHhjZGUwZWIxZSwgMHhmNTdkNGY3ZiwgMHhlZTZlZDE3OCxcbiAgMHgwNmYwNjdhYSwgMHg3MjE3NmZiYSwgMHgwYTYzN2RjNSwgMHhhMmM4OThhNixcbiAgMHgxMTNmOTgwNCwgMHhiZWY5MGRhZSwgMHgxYjcxMGIzNSwgMHgxMzFjNDcxYixcbiAgMHgyOGRiNzdmNSwgMHgyMzA0N2Q4NCwgMHgzMmNhYWI3YiwgMHg0MGM3MjQ5MyxcbiAgMHgzYzllYmUwYSwgMHgxNWM5YmViYywgMHg0MzFkNjdjNCwgMHg5YzEwMGQ0YyxcbiAgMHg0Y2M1ZDRiZSwgMHhjYjNlNDJiNiwgMHg1OTdmMjk5YywgMHhmYzY1N2UyYSxcbiAgMHg1ZmNiNmZhYiwgMHgzYWQ2ZmFlYywgMHg2YzQ0MTk4YywgMHg0YTQ3NTgxN1xuXTtcblxudmFyIHNoYTFfSyA9IFtcbiAgMHg1QTgyNzk5OSwgMHg2RUQ5RUJBMSxcbiAgMHg4RjFCQkNEQywgMHhDQTYyQzFENlxuXTtcblxuZnVuY3Rpb24gU0hBMjU2KCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMjU2KSlcbiAgICByZXR1cm4gbmV3IFNIQTI1NigpO1xuXG4gIEJsb2NrSGFzaC5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4NmEwOWU2NjcsIDB4YmI2N2FlODUsIDB4M2M2ZWYzNzIsIDB4YTU0ZmY1M2EsXG4gICAgICAgICAgICAgMHg1MTBlNTI3ZiwgMHg5YjA1Njg4YywgMHgxZjgzZDlhYiwgMHg1YmUwY2QxOSBdO1xuICB0aGlzLmsgPSBzaGEyNTZfSztcbiAgdGhpcy5XID0gbmV3IEFycmF5KDY0KTtcbn1cbnV0aWxzLmluaGVyaXRzKFNIQTI1NiwgQmxvY2tIYXNoKTtcbmV4cG9ydHMuc2hhMjU2ID0gU0hBMjU2O1xuXG5TSEEyNTYuYmxvY2tTaXplID0gNTEyO1xuU0hBMjU2Lm91dFNpemUgPSAyNTY7XG5TSEEyNTYuaG1hY1N0cmVuZ3RoID0gMTkyO1xuU0hBMjU2LnBhZExlbmd0aCA9IDY0O1xuXG5TSEEyNTYucHJvdG90eXBlLl91cGRhdGUgPSBmdW5jdGlvbiBfdXBkYXRlKG1zZywgc3RhcnQpIHtcbiAgdmFyIFcgPSB0aGlzLlc7XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKVxuICAgIFdbaV0gPSBtc2dbc3RhcnQgKyBpXTtcbiAgZm9yICg7IGkgPCBXLmxlbmd0aDsgaSsrKVxuICAgIFdbaV0gPSBzdW0zMl80KGcxXzI1NihXW2kgLSAyXSksIFdbaSAtIDddLCBnMF8yNTYoV1tpIC0gMTVdKSwgV1tpIC0gMTZdKTtcblxuICB2YXIgYSA9IHRoaXMuaFswXTtcbiAgdmFyIGIgPSB0aGlzLmhbMV07XG4gIHZhciBjID0gdGhpcy5oWzJdO1xuICB2YXIgZCA9IHRoaXMuaFszXTtcbiAgdmFyIGUgPSB0aGlzLmhbNF07XG4gIHZhciBmID0gdGhpcy5oWzVdO1xuICB2YXIgZyA9IHRoaXMuaFs2XTtcbiAgdmFyIGggPSB0aGlzLmhbN107XG5cbiAgYXNzZXJ0KHRoaXMuay5sZW5ndGggPT09IFcubGVuZ3RoKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIFQxID0gc3VtMzJfNShoLCBzMV8yNTYoZSksIGNoMzIoZSwgZiwgZyksIHRoaXMua1tpXSwgV1tpXSk7XG4gICAgdmFyIFQyID0gc3VtMzIoczBfMjU2KGEpLCBtYWozMihhLCBiLCBjKSk7XG4gICAgaCA9IGc7XG4gICAgZyA9IGY7XG4gICAgZiA9IGU7XG4gICAgZSA9IHN1bTMyKGQsIFQxKTtcbiAgICBkID0gYztcbiAgICBjID0gYjtcbiAgICBiID0gYTtcbiAgICBhID0gc3VtMzIoVDEsIFQyKTtcbiAgfVxuXG4gIHRoaXMuaFswXSA9IHN1bTMyKHRoaXMuaFswXSwgYSk7XG4gIHRoaXMuaFsxXSA9IHN1bTMyKHRoaXMuaFsxXSwgYik7XG4gIHRoaXMuaFsyXSA9IHN1bTMyKHRoaXMuaFsyXSwgYyk7XG4gIHRoaXMuaFszXSA9IHN1bTMyKHRoaXMuaFszXSwgZCk7XG4gIHRoaXMuaFs0XSA9IHN1bTMyKHRoaXMuaFs0XSwgZSk7XG4gIHRoaXMuaFs1XSA9IHN1bTMyKHRoaXMuaFs1XSwgZik7XG4gIHRoaXMuaFs2XSA9IHN1bTMyKHRoaXMuaFs2XSwgZyk7XG4gIHRoaXMuaFs3XSA9IHN1bTMyKHRoaXMuaFs3XSwgaCk7XG59O1xuXG5TSEEyNTYucHJvdG90eXBlLl9kaWdlc3QgPSBmdW5jdGlvbiBkaWdlc3QoZW5jKSB7XG4gIGlmIChlbmMgPT09ICdoZXgnKVxuICAgIHJldHVybiB1dGlscy50b0hleDMyKHRoaXMuaCwgJ2JpZycpO1xuICBlbHNlXG4gICAgcmV0dXJuIHV0aWxzLnNwbGl0MzIodGhpcy5oLCAnYmlnJyk7XG59O1xuXG5mdW5jdGlvbiBTSEEyMjQoKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBTSEEyMjQpKVxuICAgIHJldHVybiBuZXcgU0hBMjI0KCk7XG5cbiAgU0hBMjU2LmNhbGwodGhpcyk7XG4gIHRoaXMuaCA9IFsgMHhjMTA1OWVkOCwgMHgzNjdjZDUwNywgMHgzMDcwZGQxNywgMHhmNzBlNTkzOSxcbiAgICAgICAgICAgICAweGZmYzAwYjMxLCAweDY4NTgxNTExLCAweDY0Zjk4ZmE3LCAweGJlZmE0ZmE0IF07XG59XG51dGlscy5pbmhlcml0cyhTSEEyMjQsIFNIQTI1Nik7XG5leHBvcnRzLnNoYTIyNCA9IFNIQTIyNDtcblxuU0hBMjI0LmJsb2NrU2l6ZSA9IDUxMjtcblNIQTIyNC5vdXRTaXplID0gMjI0O1xuU0hBMjI0LmhtYWNTdHJlbmd0aCA9IDE5MjtcblNIQTIyNC5wYWRMZW5ndGggPSA2NDtcblxuU0hBMjI0LnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICAvLyBKdXN0IHRydW5jYXRlIG91dHB1dFxuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmguc2xpY2UoMCwgNyksICdiaWcnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaC5zbGljZSgwLCA3KSwgJ2JpZycpO1xufTtcblxuZnVuY3Rpb24gU0hBNTEyKCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBNTEyKSlcbiAgICByZXR1cm4gbmV3IFNIQTUxMigpO1xuXG4gIEJsb2NrSGFzaC5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4NmEwOWU2NjcsIDB4ZjNiY2M5MDgsXG4gICAgICAgICAgICAgMHhiYjY3YWU4NSwgMHg4NGNhYTczYixcbiAgICAgICAgICAgICAweDNjNmVmMzcyLCAweGZlOTRmODJiLFxuICAgICAgICAgICAgIDB4YTU0ZmY1M2EsIDB4NWYxZDM2ZjEsXG4gICAgICAgICAgICAgMHg1MTBlNTI3ZiwgMHhhZGU2ODJkMSxcbiAgICAgICAgICAgICAweDliMDU2ODhjLCAweDJiM2U2YzFmLFxuICAgICAgICAgICAgIDB4MWY4M2Q5YWIsIDB4ZmI0MWJkNmIsXG4gICAgICAgICAgICAgMHg1YmUwY2QxOSwgMHgxMzdlMjE3OSBdO1xuICB0aGlzLmsgPSBzaGE1MTJfSztcbiAgdGhpcy5XID0gbmV3IEFycmF5KDE2MCk7XG59XG51dGlscy5pbmhlcml0cyhTSEE1MTIsIEJsb2NrSGFzaCk7XG5leHBvcnRzLnNoYTUxMiA9IFNIQTUxMjtcblxuU0hBNTEyLmJsb2NrU2l6ZSA9IDEwMjQ7XG5TSEE1MTIub3V0U2l6ZSA9IDUxMjtcblNIQTUxMi5obWFjU3RyZW5ndGggPSAxOTI7XG5TSEE1MTIucGFkTGVuZ3RoID0gMTI4O1xuXG5TSEE1MTIucHJvdG90eXBlLl9wcmVwYXJlQmxvY2sgPSBmdW5jdGlvbiBfcHJlcGFyZUJsb2NrKG1zZywgc3RhcnQpIHtcbiAgdmFyIFcgPSB0aGlzLlc7XG5cbiAgLy8gMzIgeCAzMmJpdCB3b3Jkc1xuICBmb3IgKHZhciBpID0gMDsgaSA8IDMyOyBpKyspXG4gICAgV1tpXSA9IG1zZ1tzdGFydCArIGldO1xuICBmb3IgKDsgaSA8IFcubGVuZ3RoOyBpICs9IDIpIHtcbiAgICB2YXIgYzBfaGkgPSBnMV81MTJfaGkoV1tpIC0gNF0sIFdbaSAtIDNdKTsgIC8vIGkgLSAyXG4gICAgdmFyIGMwX2xvID0gZzFfNTEyX2xvKFdbaSAtIDRdLCBXW2kgLSAzXSk7XG4gICAgdmFyIGMxX2hpID0gV1tpIC0gMTRdOyAgLy8gaSAtIDdcbiAgICB2YXIgYzFfbG8gPSBXW2kgLSAxM107XG4gICAgdmFyIGMyX2hpID0gZzBfNTEyX2hpKFdbaSAtIDMwXSwgV1tpIC0gMjldKTsgIC8vIGkgLSAxNVxuICAgIHZhciBjMl9sbyA9IGcwXzUxMl9sbyhXW2kgLSAzMF0sIFdbaSAtIDI5XSk7XG4gICAgdmFyIGMzX2hpID0gV1tpIC0gMzJdOyAgLy8gaSAtIDE2XG4gICAgdmFyIGMzX2xvID0gV1tpIC0gMzFdO1xuXG4gICAgV1tpXSA9IHN1bTY0XzRfaGkoYzBfaGksIGMwX2xvLFxuICAgICAgICAgICAgICAgICAgICAgIGMxX2hpLCBjMV9sbyxcbiAgICAgICAgICAgICAgICAgICAgICBjMl9oaSwgYzJfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgYzNfaGksIGMzX2xvKTtcbiAgICBXW2kgKyAxXSA9IHN1bTY0XzRfbG8oYzBfaGksIGMwX2xvLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBjMV9oaSwgYzFfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGMyX2hpLCBjMl9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgYzNfaGksIGMzX2xvKTtcbiAgfVxufTtcblxuU0hBNTEyLnByb3RvdHlwZS5fdXBkYXRlID0gZnVuY3Rpb24gX3VwZGF0ZShtc2csIHN0YXJ0KSB7XG4gIHRoaXMuX3ByZXBhcmVCbG9jayhtc2csIHN0YXJ0KTtcblxuICB2YXIgVyA9IHRoaXMuVztcblxuICB2YXIgYWggPSB0aGlzLmhbMF07XG4gIHZhciBhbCA9IHRoaXMuaFsxXTtcbiAgdmFyIGJoID0gdGhpcy5oWzJdO1xuICB2YXIgYmwgPSB0aGlzLmhbM107XG4gIHZhciBjaCA9IHRoaXMuaFs0XTtcbiAgdmFyIGNsID0gdGhpcy5oWzVdO1xuICB2YXIgZGggPSB0aGlzLmhbNl07XG4gIHZhciBkbCA9IHRoaXMuaFs3XTtcbiAgdmFyIGVoID0gdGhpcy5oWzhdO1xuICB2YXIgZWwgPSB0aGlzLmhbOV07XG4gIHZhciBmaCA9IHRoaXMuaFsxMF07XG4gIHZhciBmbCA9IHRoaXMuaFsxMV07XG4gIHZhciBnaCA9IHRoaXMuaFsxMl07XG4gIHZhciBnbCA9IHRoaXMuaFsxM107XG4gIHZhciBoaCA9IHRoaXMuaFsxNF07XG4gIHZhciBobCA9IHRoaXMuaFsxNV07XG5cbiAgYXNzZXJ0KHRoaXMuay5sZW5ndGggPT09IFcubGVuZ3RoKTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSArPSAyKSB7XG4gICAgdmFyIGMwX2hpID0gaGg7XG4gICAgdmFyIGMwX2xvID0gaGw7XG4gICAgdmFyIGMxX2hpID0gczFfNTEyX2hpKGVoLCBlbCk7XG4gICAgdmFyIGMxX2xvID0gczFfNTEyX2xvKGVoLCBlbCk7XG4gICAgdmFyIGMyX2hpID0gY2g2NF9oaShlaCwgZWwsIGZoLCBmbCwgZ2gsIGdsKTtcbiAgICB2YXIgYzJfbG8gPSBjaDY0X2xvKGVoLCBlbCwgZmgsIGZsLCBnaCwgZ2wpO1xuICAgIHZhciBjM19oaSA9IHRoaXMua1tpXTtcbiAgICB2YXIgYzNfbG8gPSB0aGlzLmtbaSArIDFdO1xuICAgIHZhciBjNF9oaSA9IFdbaV07XG4gICAgdmFyIGM0X2xvID0gV1tpICsgMV07XG5cbiAgICB2YXIgVDFfaGkgPSBzdW02NF81X2hpKGMwX2hpLCBjMF9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMxX2hpLCBjMV9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMyX2hpLCBjMl9sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGMzX2hpLCBjM19sbyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGM0X2hpLCBjNF9sbyk7XG4gICAgdmFyIFQxX2xvID0gc3VtNjRfNV9sbyhjMF9oaSwgYzBfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjMV9oaSwgYzFfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjMl9oaSwgYzJfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjM19oaSwgYzNfbG8sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjNF9oaSwgYzRfbG8pO1xuXG4gICAgdmFyIGMwX2hpID0gczBfNTEyX2hpKGFoLCBhbCk7XG4gICAgdmFyIGMwX2xvID0gczBfNTEyX2xvKGFoLCBhbCk7XG4gICAgdmFyIGMxX2hpID0gbWFqNjRfaGkoYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCk7XG4gICAgdmFyIGMxX2xvID0gbWFqNjRfbG8oYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCk7XG5cbiAgICB2YXIgVDJfaGkgPSBzdW02NF9oaShjMF9oaSwgYzBfbG8sIGMxX2hpLCBjMV9sbyk7XG4gICAgdmFyIFQyX2xvID0gc3VtNjRfbG8oYzBfaGksIGMwX2xvLCBjMV9oaSwgYzFfbG8pO1xuXG4gICAgaGggPSBnaDtcbiAgICBobCA9IGdsO1xuXG4gICAgZ2ggPSBmaDtcbiAgICBnbCA9IGZsO1xuXG4gICAgZmggPSBlaDtcbiAgICBmbCA9IGVsO1xuXG4gICAgZWggPSBzdW02NF9oaShkaCwgZGwsIFQxX2hpLCBUMV9sbyk7XG4gICAgZWwgPSBzdW02NF9sbyhkbCwgZGwsIFQxX2hpLCBUMV9sbyk7XG5cbiAgICBkaCA9IGNoO1xuICAgIGRsID0gY2w7XG5cbiAgICBjaCA9IGJoO1xuICAgIGNsID0gYmw7XG5cbiAgICBiaCA9IGFoO1xuICAgIGJsID0gYWw7XG5cbiAgICBhaCA9IHN1bTY0X2hpKFQxX2hpLCBUMV9sbywgVDJfaGksIFQyX2xvKTtcbiAgICBhbCA9IHN1bTY0X2xvKFQxX2hpLCBUMV9sbywgVDJfaGksIFQyX2xvKTtcbiAgfVxuXG4gIHN1bTY0KHRoaXMuaCwgMCwgYWgsIGFsKTtcbiAgc3VtNjQodGhpcy5oLCAyLCBiaCwgYmwpO1xuICBzdW02NCh0aGlzLmgsIDQsIGNoLCBjbCk7XG4gIHN1bTY0KHRoaXMuaCwgNiwgZGgsIGRsKTtcbiAgc3VtNjQodGhpcy5oLCA4LCBlaCwgZWwpO1xuICBzdW02NCh0aGlzLmgsIDEwLCBmaCwgZmwpO1xuICBzdW02NCh0aGlzLmgsIDEyLCBnaCwgZ2wpO1xuICBzdW02NCh0aGlzLmgsIDE0LCBoaCwgaGwpO1xufTtcblxuU0hBNTEyLnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmgsICdiaWcnKTtcbiAgZWxzZVxuICAgIHJldHVybiB1dGlscy5zcGxpdDMyKHRoaXMuaCwgJ2JpZycpO1xufTtcblxuZnVuY3Rpb24gU0hBMzg0KCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMzg0KSlcbiAgICByZXR1cm4gbmV3IFNIQTM4NCgpO1xuXG4gIFNIQTUxMi5jYWxsKHRoaXMpO1xuICB0aGlzLmggPSBbIDB4Y2JiYjlkNWQsIDB4YzEwNTllZDgsXG4gICAgICAgICAgICAgMHg2MjlhMjkyYSwgMHgzNjdjZDUwNyxcbiAgICAgICAgICAgICAweDkxNTkwMTVhLCAweDMwNzBkZDE3LFxuICAgICAgICAgICAgIDB4MTUyZmVjZDgsIDB4ZjcwZTU5MzksXG4gICAgICAgICAgICAgMHg2NzMzMjY2NywgMHhmZmMwMGIzMSxcbiAgICAgICAgICAgICAweDhlYjQ0YTg3LCAweDY4NTgxNTExLFxuICAgICAgICAgICAgIDB4ZGIwYzJlMGQsIDB4NjRmOThmYTcsXG4gICAgICAgICAgICAgMHg0N2I1NDgxZCwgMHhiZWZhNGZhNCBdO1xufVxudXRpbHMuaW5oZXJpdHMoU0hBMzg0LCBTSEE1MTIpO1xuZXhwb3J0cy5zaGEzODQgPSBTSEEzODQ7XG5cblNIQTM4NC5ibG9ja1NpemUgPSAxMDI0O1xuU0hBMzg0Lm91dFNpemUgPSAzODQ7XG5TSEEzODQuaG1hY1N0cmVuZ3RoID0gMTkyO1xuU0hBMzg0LnBhZExlbmd0aCA9IDEyODtcblxuU0hBMzg0LnByb3RvdHlwZS5fZGlnZXN0ID0gZnVuY3Rpb24gZGlnZXN0KGVuYykge1xuICBpZiAoZW5jID09PSAnaGV4JylcbiAgICByZXR1cm4gdXRpbHMudG9IZXgzMih0aGlzLmguc2xpY2UoMCwgMTIpLCAnYmlnJyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdXRpbHMuc3BsaXQzMih0aGlzLmguc2xpY2UoMCwgMTIpLCAnYmlnJyk7XG59O1xuXG5mdW5jdGlvbiBTSEExKCkge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgU0hBMSkpXG4gICAgcmV0dXJuIG5ldyBTSEExKCk7XG5cbiAgQmxvY2tIYXNoLmNhbGwodGhpcyk7XG4gIHRoaXMuaCA9IFsgMHg2NzQ1MjMwMSwgMHhlZmNkYWI4OSwgMHg5OGJhZGNmZSxcbiAgICAgICAgICAgICAweDEwMzI1NDc2LCAweGMzZDJlMWYwIF07XG4gIHRoaXMuVyA9IG5ldyBBcnJheSg4MCk7XG59XG5cbnV0aWxzLmluaGVyaXRzKFNIQTEsIEJsb2NrSGFzaCk7XG5leHBvcnRzLnNoYTEgPSBTSEExO1xuXG5TSEExLmJsb2NrU2l6ZSA9IDUxMjtcblNIQTEub3V0U2l6ZSA9IDE2MDtcblNIQTEuaG1hY1N0cmVuZ3RoID0gODA7XG5TSEExLnBhZExlbmd0aCA9IDY0O1xuXG5TSEExLnByb3RvdHlwZS5fdXBkYXRlID0gZnVuY3Rpb24gX3VwZGF0ZShtc2csIHN0YXJ0KSB7XG4gIHZhciBXID0gdGhpcy5XO1xuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcbiAgICBXW2ldID0gbXNnW3N0YXJ0ICsgaV07XG5cbiAgZm9yKDsgaSA8IFcubGVuZ3RoOyBpKyspXG4gICAgV1tpXSA9IHJvdGwzMihXW2kgLSAzXSBeIFdbaSAtIDhdIF4gV1tpIC0gMTRdIF4gV1tpIC0gMTZdLCAxKTtcblxuICB2YXIgYSA9IHRoaXMuaFswXTtcbiAgdmFyIGIgPSB0aGlzLmhbMV07XG4gIHZhciBjID0gdGhpcy5oWzJdO1xuICB2YXIgZCA9IHRoaXMuaFszXTtcbiAgdmFyIGUgPSB0aGlzLmhbNF07XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBXLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIHMgPSB+fihpIC8gMjApO1xuICAgIHZhciB0ID0gc3VtMzJfNShyb3RsMzIoYSwgNSksIGZ0XzEocywgYiwgYywgZCksIGUsIFdbaV0sIHNoYTFfS1tzXSk7XG4gICAgZSA9IGQ7XG4gICAgZCA9IGM7XG4gICAgYyA9IHJvdGwzMihiLCAzMCk7XG4gICAgYiA9IGE7XG4gICAgYSA9IHQ7XG4gIH1cblxuICB0aGlzLmhbMF0gPSBzdW0zMih0aGlzLmhbMF0sIGEpO1xuICB0aGlzLmhbMV0gPSBzdW0zMih0aGlzLmhbMV0sIGIpO1xuICB0aGlzLmhbMl0gPSBzdW0zMih0aGlzLmhbMl0sIGMpO1xuICB0aGlzLmhbM10gPSBzdW0zMih0aGlzLmhbM10sIGQpO1xuICB0aGlzLmhbNF0gPSBzdW0zMih0aGlzLmhbNF0sIGUpO1xufTtcblxuU0hBMS5wcm90b3R5cGUuX2RpZ2VzdCA9IGZ1bmN0aW9uIGRpZ2VzdChlbmMpIHtcbiAgaWYgKGVuYyA9PT0gJ2hleCcpXG4gICAgcmV0dXJuIHV0aWxzLnRvSGV4MzIodGhpcy5oLCAnYmlnJyk7XG4gIGVsc2VcbiAgICByZXR1cm4gdXRpbHMuc3BsaXQzMih0aGlzLmgsICdiaWcnKTtcbn07XG5cbmZ1bmN0aW9uIGNoMzIoeCwgeSwgeikge1xuICByZXR1cm4gKHggJiB5KSBeICgofngpICYgeik7XG59XG5cbmZ1bmN0aW9uIG1hajMyKHgsIHksIHopIHtcbiAgcmV0dXJuICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KTtcbn1cblxuZnVuY3Rpb24gcDMyKHgsIHksIHopIHtcbiAgcmV0dXJuIHggXiB5IF4gejtcbn1cblxuZnVuY3Rpb24gczBfMjU2KHgpIHtcbiAgcmV0dXJuIHJvdHIzMih4LCAyKSBeIHJvdHIzMih4LCAxMykgXiByb3RyMzIoeCwgMjIpO1xufVxuXG5mdW5jdGlvbiBzMV8yNTYoeCkge1xuICByZXR1cm4gcm90cjMyKHgsIDYpIF4gcm90cjMyKHgsIDExKSBeIHJvdHIzMih4LCAyNSk7XG59XG5cbmZ1bmN0aW9uIGcwXzI1Nih4KSB7XG4gIHJldHVybiByb3RyMzIoeCwgNykgXiByb3RyMzIoeCwgMTgpIF4gKHggPj4+IDMpO1xufVxuXG5mdW5jdGlvbiBnMV8yNTYoeCkge1xuICByZXR1cm4gcm90cjMyKHgsIDE3KSBeIHJvdHIzMih4LCAxOSkgXiAoeCA+Pj4gMTApO1xufVxuXG5mdW5jdGlvbiBmdF8xKHMsIHgsIHksIHopIHtcbiAgaWYgKHMgPT09IDApXG4gICAgcmV0dXJuIGNoMzIoeCwgeSwgeik7XG4gIGlmIChzID09PSAxIHx8IHMgPT09IDMpXG4gICAgcmV0dXJuIHAzMih4LCB5LCB6KTtcbiAgaWYgKHMgPT09IDIpXG4gICAgcmV0dXJuIG1hajMyKHgsIHksIHopO1xufVxuXG5mdW5jdGlvbiBjaDY0X2hpKHhoLCB4bCwgeWgsIHlsLCB6aCwgemwpIHtcbiAgdmFyIHIgPSAoeGggJiB5aCkgXiAoKH54aCkgJiB6aCk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gY2g2NF9sbyh4aCwgeGwsIHloLCB5bCwgemgsIHpsKSB7XG4gIHZhciByID0gKHhsICYgeWwpIF4gKCh+eGwpICYgemwpO1xuICBpZiAociA8IDApXG4gICAgciArPSAweDEwMDAwMDAwMDtcbiAgcmV0dXJuIHI7XG59XG5cbmZ1bmN0aW9uIG1hajY0X2hpKHhoLCB4bCwgeWgsIHlsLCB6aCwgemwpIHtcbiAgdmFyIHIgPSAoeGggJiB5aCkgXiAoeGggJiB6aCkgXiAoeWggJiB6aCk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gbWFqNjRfbG8oeGgsIHhsLCB5aCwgeWwsIHpoLCB6bCkge1xuICB2YXIgciA9ICh4bCAmIHlsKSBeICh4bCAmIHpsKSBeICh5bCAmIHpsKTtcbiAgaWYgKHIgPCAwKVxuICAgIHIgKz0gMHgxMDAwMDAwMDA7XG4gIHJldHVybiByO1xufVxuXG5mdW5jdGlvbiBzMF81MTJfaGkoeGgsIHhsKSB7XG4gIHZhciBjMF9oaSA9IHJvdHI2NF9oaSh4aCwgeGwsIDI4KTtcbiAgdmFyIGMxX2hpID0gcm90cjY0X2hpKHhsLCB4aCwgMik7ICAvLyAzNFxuICB2YXIgYzJfaGkgPSByb3RyNjRfaGkoeGwsIHhoLCA3KTsgIC8vIDM5XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gczBfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAyOCk7XG4gIHZhciBjMV9sbyA9IHJvdHI2NF9sbyh4bCwgeGgsIDIpOyAgLy8gMzRcbiAgdmFyIGMyX2xvID0gcm90cjY0X2xvKHhsLCB4aCwgNyk7ICAvLyAzOVxuXG4gIHZhciByID0gYzBfbG8gXiBjMV9sbyBeIGMyX2xvO1xuICBpZiAociA8IDApXG4gICAgciArPSAweDEwMDAwMDAwMDtcbiAgcmV0dXJuIHI7XG59XG5cbmZ1bmN0aW9uIHMxXzUxMl9oaSh4aCwgeGwpIHtcbiAgdmFyIGMwX2hpID0gcm90cjY0X2hpKHhoLCB4bCwgMTQpO1xuICB2YXIgYzFfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxOCk7XG4gIHZhciBjMl9oaSA9IHJvdHI2NF9oaSh4bCwgeGgsIDkpOyAgLy8gNDFcblxuICB2YXIgciA9IGMwX2hpIF4gYzFfaGkgXiBjMl9oaTtcbiAgaWYgKHIgPCAwKVxuICAgIHIgKz0gMHgxMDAwMDAwMDA7XG4gIHJldHVybiByO1xufVxuXG5mdW5jdGlvbiBzMV81MTJfbG8oeGgsIHhsKSB7XG4gIHZhciBjMF9sbyA9IHJvdHI2NF9sbyh4aCwgeGwsIDE0KTtcbiAgdmFyIGMxX2xvID0gcm90cjY0X2xvKHhoLCB4bCwgMTgpO1xuICB2YXIgYzJfbG8gPSByb3RyNjRfbG8oeGwsIHhoLCA5KTsgIC8vIDQxXG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzBfNTEyX2hpKHhoLCB4bCkge1xuICB2YXIgYzBfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxKTtcbiAgdmFyIGMxX2hpID0gcm90cjY0X2hpKHhoLCB4bCwgOCk7XG4gIHZhciBjMl9oaSA9IHNocjY0X2hpKHhoLCB4bCwgNyk7XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzBfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAxKTtcbiAgdmFyIGMxX2xvID0gcm90cjY0X2xvKHhoLCB4bCwgOCk7XG4gIHZhciBjMl9sbyA9IHNocjY0X2xvKHhoLCB4bCwgNyk7XG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzFfNTEyX2hpKHhoLCB4bCkge1xuICB2YXIgYzBfaGkgPSByb3RyNjRfaGkoeGgsIHhsLCAxOSk7XG4gIHZhciBjMV9oaSA9IHJvdHI2NF9oaSh4bCwgeGgsIDI5KTsgIC8vIDYxXG4gIHZhciBjMl9oaSA9IHNocjY0X2hpKHhoLCB4bCwgNik7XG5cbiAgdmFyIHIgPSBjMF9oaSBeIGMxX2hpIF4gYzJfaGk7XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gZzFfNTEyX2xvKHhoLCB4bCkge1xuICB2YXIgYzBfbG8gPSByb3RyNjRfbG8oeGgsIHhsLCAxOSk7XG4gIHZhciBjMV9sbyA9IHJvdHI2NF9sbyh4bCwgeGgsIDI5KTsgIC8vIDYxXG4gIHZhciBjMl9sbyA9IHNocjY0X2xvKHhoLCB4bCwgNik7XG5cbiAgdmFyIHIgPSBjMF9sbyBeIGMxX2xvIF4gYzJfbG87XG4gIGlmIChyIDwgMClcbiAgICByICs9IDB4MTAwMDAwMDAwO1xuICByZXR1cm4gcjtcbn1cbiIsInZhciB1dGlscyA9IGV4cG9ydHM7XG52YXIgaW5oZXJpdHMgPSByZXF1aXJlKCdpbmhlcml0cycpO1xuXG5mdW5jdGlvbiB0b0FycmF5KG1zZywgZW5jKSB7XG4gIGlmIChBcnJheS5pc0FycmF5KG1zZykpXG4gICAgcmV0dXJuIG1zZy5zbGljZSgpO1xuICBpZiAoIW1zZylcbiAgICByZXR1cm4gW107XG4gIHZhciByZXMgPSBbXTtcbiAgaWYgKHR5cGVvZiBtc2cgPT09ICdzdHJpbmcnKSB7XG4gICAgaWYgKCFlbmMpIHtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciBjID0gbXNnLmNoYXJDb2RlQXQoaSk7XG4gICAgICAgIHZhciBoaSA9IGMgPj4gODtcbiAgICAgICAgdmFyIGxvID0gYyAmIDB4ZmY7XG4gICAgICAgIGlmIChoaSlcbiAgICAgICAgICByZXMucHVzaChoaSwgbG8pO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgcmVzLnB1c2gobG8pO1xuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoZW5jID09PSAnaGV4Jykge1xuICAgICAgbXNnID0gbXNnLnJlcGxhY2UoL1teYS16MC05XSsvaWcsICcnKTtcbiAgICAgIGlmIChtc2cubGVuZ3RoICUgMiAhPT0gMClcbiAgICAgICAgbXNnID0gJzAnICsgbXNnO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBtc2cubGVuZ3RoOyBpICs9IDIpXG4gICAgICAgIHJlcy5wdXNoKHBhcnNlSW50KG1zZ1tpXSArIG1zZ1tpICsgMV0sIDE2KSk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKVxuICAgICAgcmVzW2ldID0gbXNnW2ldIHwgMDtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxudXRpbHMudG9BcnJheSA9IHRvQXJyYXk7XG5cbmZ1bmN0aW9uIHRvSGV4KG1zZykge1xuICB2YXIgcmVzID0gJyc7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrKVxuICAgIHJlcyArPSB6ZXJvMihtc2dbaV0udG9TdHJpbmcoMTYpKTtcbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnRvSGV4ID0gdG9IZXg7XG5cbmZ1bmN0aW9uIGh0b25sKHcpIHtcbiAgdmFyIHJlcyA9ICh3ID4+PiAyNCkgfFxuICAgICAgICAgICAgKCh3ID4+PiA4KSAmIDB4ZmYwMCkgfFxuICAgICAgICAgICAgKCh3IDw8IDgpICYgMHhmZjAwMDApIHxcbiAgICAgICAgICAgICgodyAmIDB4ZmYpIDw8IDI0KTtcbiAgcmV0dXJuIHJlcyA+Pj4gMDtcbn1cbnV0aWxzLmh0b25sID0gaHRvbmw7XG5cbmZ1bmN0aW9uIHRvSGV4MzIobXNnLCBlbmRpYW4pIHtcbiAgdmFyIHJlcyA9ICcnO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKykge1xuICAgIHZhciB3ID0gbXNnW2ldO1xuICAgIGlmIChlbmRpYW4gPT09ICdsaXR0bGUnKVxuICAgICAgdyA9IGh0b25sKHcpO1xuICAgIHJlcyArPSB6ZXJvOCh3LnRvU3RyaW5nKDE2KSk7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnRvSGV4MzIgPSB0b0hleDMyO1xuXG5mdW5jdGlvbiB6ZXJvMih3b3JkKSB7XG4gIGlmICh3b3JkLmxlbmd0aCA9PT0gMSlcbiAgICByZXR1cm4gJzAnICsgd29yZDtcbiAgZWxzZVxuICAgIHJldHVybiB3b3JkO1xufVxudXRpbHMuemVybzIgPSB6ZXJvMjtcblxuZnVuY3Rpb24gemVybzgod29yZCkge1xuICBpZiAod29yZC5sZW5ndGggPT09IDcpXG4gICAgcmV0dXJuICcwJyArIHdvcmQ7XG4gIGVsc2UgaWYgKHdvcmQubGVuZ3RoID09PSA2KVxuICAgIHJldHVybiAnMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDUpXG4gICAgcmV0dXJuICcwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDQpXG4gICAgcmV0dXJuICcwMDAwJyArIHdvcmQ7XG4gIGVsc2UgaWYgKHdvcmQubGVuZ3RoID09PSAzKVxuICAgIHJldHVybiAnMDAwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDIpXG4gICAgcmV0dXJuICcwMDAwMDAnICsgd29yZDtcbiAgZWxzZSBpZiAod29yZC5sZW5ndGggPT09IDEpXG4gICAgcmV0dXJuICcwMDAwMDAwJyArIHdvcmQ7XG4gIGVsc2VcbiAgICByZXR1cm4gd29yZDtcbn1cbnV0aWxzLnplcm84ID0gemVybzg7XG5cbmZ1bmN0aW9uIGpvaW4zMihtc2csIHN0YXJ0LCBlbmQsIGVuZGlhbikge1xuICB2YXIgbGVuID0gZW5kIC0gc3RhcnQ7XG4gIGFzc2VydChsZW4gJSA0ID09PSAwKTtcbiAgdmFyIHJlcyA9IG5ldyBBcnJheShsZW4gLyA0KTtcbiAgZm9yICh2YXIgaSA9IDAsIGsgPSBzdGFydDsgaSA8IHJlcy5sZW5ndGg7IGkrKywgayArPSA0KSB7XG4gICAgdmFyIHc7XG4gICAgaWYgKGVuZGlhbiA9PT0gJ2JpZycpXG4gICAgICB3ID0gKG1zZ1trXSA8PCAyNCkgfCAobXNnW2sgKyAxXSA8PCAxNikgfCAobXNnW2sgKyAyXSA8PCA4KSB8IG1zZ1trICsgM107XG4gICAgZWxzZVxuICAgICAgdyA9IChtc2dbayArIDNdIDw8IDI0KSB8IChtc2dbayArIDJdIDw8IDE2KSB8IChtc2dbayArIDFdIDw8IDgpIHwgbXNnW2tdO1xuICAgIHJlc1tpXSA9IHcgPj4+IDA7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLmpvaW4zMiA9IGpvaW4zMjtcblxuZnVuY3Rpb24gc3BsaXQzMihtc2csIGVuZGlhbikge1xuICB2YXIgcmVzID0gbmV3IEFycmF5KG1zZy5sZW5ndGggKiA0KTtcbiAgZm9yICh2YXIgaSA9IDAsIGsgPSAwOyBpIDwgbXNnLmxlbmd0aDsgaSsrLCBrICs9IDQpIHtcbiAgICB2YXIgbSA9IG1zZ1tpXTtcbiAgICBpZiAoZW5kaWFuID09PSAnYmlnJykge1xuICAgICAgcmVzW2tdID0gbSA+Pj4gMjQ7XG4gICAgICByZXNbayArIDFdID0gKG0gPj4+IDE2KSAmIDB4ZmY7XG4gICAgICByZXNbayArIDJdID0gKG0gPj4+IDgpICYgMHhmZjtcbiAgICAgIHJlc1trICsgM10gPSBtICYgMHhmZjtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzW2sgKyAzXSA9IG0gPj4+IDI0O1xuICAgICAgcmVzW2sgKyAyXSA9IChtID4+PiAxNikgJiAweGZmO1xuICAgICAgcmVzW2sgKyAxXSA9IChtID4+PiA4KSAmIDB4ZmY7XG4gICAgICByZXNba10gPSBtICYgMHhmZjtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cbnV0aWxzLnNwbGl0MzIgPSBzcGxpdDMyO1xuXG5mdW5jdGlvbiByb3RyMzIodywgYikge1xuICByZXR1cm4gKHcgPj4+IGIpIHwgKHcgPDwgKDMyIC0gYikpO1xufVxudXRpbHMucm90cjMyID0gcm90cjMyO1xuXG5mdW5jdGlvbiByb3RsMzIodywgYikge1xuICByZXR1cm4gKHcgPDwgYikgfCAodyA+Pj4gKDMyIC0gYikpO1xufVxudXRpbHMucm90bDMyID0gcm90bDMyO1xuXG5mdW5jdGlvbiBzdW0zMihhLCBiKSB7XG4gIHJldHVybiAoYSArIGIpID4+PiAwO1xufVxudXRpbHMuc3VtMzIgPSBzdW0zMjtcblxuZnVuY3Rpb24gc3VtMzJfMyhhLCBiLCBjKSB7XG4gIHJldHVybiAoYSArIGIgKyBjKSA+Pj4gMDtcbn1cbnV0aWxzLnN1bTMyXzMgPSBzdW0zMl8zO1xuXG5mdW5jdGlvbiBzdW0zMl80KGEsIGIsIGMsIGQpIHtcbiAgcmV0dXJuIChhICsgYiArIGMgKyBkKSA+Pj4gMDtcbn1cbnV0aWxzLnN1bTMyXzQgPSBzdW0zMl80O1xuXG5mdW5jdGlvbiBzdW0zMl81KGEsIGIsIGMsIGQsIGUpIHtcbiAgcmV0dXJuIChhICsgYiArIGMgKyBkICsgZSkgPj4+IDA7XG59XG51dGlscy5zdW0zMl81ID0gc3VtMzJfNTtcblxuZnVuY3Rpb24gYXNzZXJ0KGNvbmQsIG1zZykge1xuICBpZiAoIWNvbmQpXG4gICAgdGhyb3cgbmV3IEVycm9yKG1zZyB8fCAnQXNzZXJ0aW9uIGZhaWxlZCcpO1xufVxudXRpbHMuYXNzZXJ0ID0gYXNzZXJ0O1xuXG51dGlscy5pbmhlcml0cyA9IGluaGVyaXRzO1xuXG5mdW5jdGlvbiBzdW02NChidWYsIHBvcywgYWgsIGFsKSB7XG4gIHZhciBiaCA9IGJ1Zltwb3NdO1xuICB2YXIgYmwgPSBidWZbcG9zICsgMV07XG5cbiAgdmFyIGxvID0gKGFsICsgYmwpID4+PiAwO1xuICB2YXIgaGkgPSAobG8gPCBhbCA/IDEgOiAwKSArIGFoICsgYmg7XG4gIGJ1Zltwb3NdID0gaGkgPj4+IDA7XG4gIGJ1Zltwb3MgKyAxXSA9IGxvO1xufVxuZXhwb3J0cy5zdW02NCA9IHN1bTY0O1xuXG5mdW5jdGlvbiBzdW02NF9oaShhaCwgYWwsIGJoLCBibCkge1xuICB2YXIgbG8gPSAoYWwgKyBibCkgPj4+IDA7XG4gIHZhciBoaSA9IChsbyA8IGFsID8gMSA6IDApICsgYWggKyBiaDtcbiAgcmV0dXJuIGhpID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfaGkgPSBzdW02NF9oaTtcblxuZnVuY3Rpb24gc3VtNjRfbG8oYWgsIGFsLCBiaCwgYmwpIHtcbiAgdmFyIGxvID0gYWwgKyBibDtcbiAgcmV0dXJuIGxvID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfbG8gPSBzdW02NF9sbztcblxuZnVuY3Rpb24gc3VtNjRfNF9oaShhaCwgYWwsIGJoLCBibCwgY2gsIGNsLCBkaCwgZGwpIHtcbiAgdmFyIGNhcnJ5ID0gMDtcbiAgdmFyIGxvID0gYWw7XG4gIGxvID0gKGxvICsgYmwpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGFsID8gMSA6IDA7XG4gIGxvID0gKGxvICsgY2wpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGNsID8gMSA6IDA7XG4gIGxvID0gKGxvICsgZGwpID4+PiAwO1xuICBjYXJyeSArPSBsbyA8IGRsID8gMSA6IDA7XG5cbiAgdmFyIGhpID0gYWggKyBiaCArIGNoICsgZGggKyBjYXJyeTtcbiAgcmV0dXJuIGhpID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfNF9oaSA9IHN1bTY0XzRfaGk7XG5cbmZ1bmN0aW9uIHN1bTY0XzRfbG8oYWgsIGFsLCBiaCwgYmwsIGNoLCBjbCwgZGgsIGRsKSB7XG4gIHZhciBsbyA9IGFsICsgYmwgKyBjbCArIGRsO1xuICByZXR1cm4gbG8gPj4+IDA7XG59O1xuZXhwb3J0cy5zdW02NF80X2xvID0gc3VtNjRfNF9sbztcblxuZnVuY3Rpb24gc3VtNjRfNV9oaShhaCwgYWwsIGJoLCBibCwgY2gsIGNsLCBkaCwgZGwsIGVoLCBlbCkge1xuICB2YXIgY2FycnkgPSAwO1xuICB2YXIgbG8gPSBhbDtcbiAgbG8gPSAobG8gKyBibCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgYWwgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBjbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgY2wgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBkbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgZGwgPyAxIDogMDtcbiAgbG8gPSAobG8gKyBlbCkgPj4+IDA7XG4gIGNhcnJ5ICs9IGxvIDwgZWwgPyAxIDogMDtcblxuICB2YXIgaGkgPSBhaCArIGJoICsgY2ggKyBkaCArIGVoICsgY2Fycnk7XG4gIHJldHVybiBoaSA+Pj4gMDtcbn07XG5leHBvcnRzLnN1bTY0XzVfaGkgPSBzdW02NF81X2hpO1xuXG5mdW5jdGlvbiBzdW02NF81X2xvKGFoLCBhbCwgYmgsIGJsLCBjaCwgY2wsIGRoLCBkbCwgZWgsIGVsKSB7XG4gIHZhciBsbyA9IGFsICsgYmwgKyBjbCArIGRsICsgZWw7XG5cbiAgcmV0dXJuIGxvID4+PiAwO1xufTtcbmV4cG9ydHMuc3VtNjRfNV9sbyA9IHN1bTY0XzVfbG87XG5cbmZ1bmN0aW9uIHJvdHI2NF9oaShhaCwgYWwsIG51bSkge1xuICB2YXIgciA9IChhbCA8PCAoMzIgLSBudW0pKSB8IChhaCA+Pj4gbnVtKTtcbiAgcmV0dXJuIHIgPj4+IDA7XG59O1xuZXhwb3J0cy5yb3RyNjRfaGkgPSByb3RyNjRfaGk7XG5cbmZ1bmN0aW9uIHJvdHI2NF9sbyhhaCwgYWwsIG51bSkge1xuICB2YXIgciA9IChhaCA8PCAoMzIgLSBudW0pKSB8IChhbCA+Pj4gbnVtKTtcbiAgcmV0dXJuIHIgPj4+IDA7XG59O1xuZXhwb3J0cy5yb3RyNjRfbG8gPSByb3RyNjRfbG87XG5cbmZ1bmN0aW9uIHNocjY0X2hpKGFoLCBhbCwgbnVtKSB7XG4gIHJldHVybiBhaCA+Pj4gbnVtO1xufTtcbmV4cG9ydHMuc2hyNjRfaGkgPSBzaHI2NF9oaTtcblxuZnVuY3Rpb24gc2hyNjRfbG8oYWgsIGFsLCBudW0pIHtcbiAgdmFyIHIgPSAoYWggPDwgKDMyIC0gbnVtKSkgfCAoYWwgPj4+IG51bSk7XG4gIHJldHVybiByID4+PiAwO1xufTtcbmV4cG9ydHMuc2hyNjRfbG8gPSBzaHI2NF9sbztcbiIsImV4cG9ydHMucmVhZCA9IGZ1bmN0aW9uIChidWZmZXIsIG9mZnNldCwgaXNMRSwgbUxlbiwgbkJ5dGVzKSB7XG4gIHZhciBlLCBtXG4gIHZhciBlTGVuID0gbkJ5dGVzICogOCAtIG1MZW4gLSAxXG4gIHZhciBlTWF4ID0gKDEgPDwgZUxlbikgLSAxXG4gIHZhciBlQmlhcyA9IGVNYXggPj4gMVxuICB2YXIgbkJpdHMgPSAtN1xuICB2YXIgaSA9IGlzTEUgPyAobkJ5dGVzIC0gMSkgOiAwXG4gIHZhciBkID0gaXNMRSA/IC0xIDogMVxuICB2YXIgcyA9IGJ1ZmZlcltvZmZzZXQgKyBpXVxuXG4gIGkgKz0gZFxuXG4gIGUgPSBzICYgKCgxIDw8ICgtbkJpdHMpKSAtIDEpXG4gIHMgPj49ICgtbkJpdHMpXG4gIG5CaXRzICs9IGVMZW5cbiAgZm9yICg7IG5CaXRzID4gMDsgZSA9IGUgKiAyNTYgKyBidWZmZXJbb2Zmc2V0ICsgaV0sIGkgKz0gZCwgbkJpdHMgLT0gOCkge31cblxuICBtID0gZSAmICgoMSA8PCAoLW5CaXRzKSkgLSAxKVxuICBlID4+PSAoLW5CaXRzKVxuICBuQml0cyArPSBtTGVuXG4gIGZvciAoOyBuQml0cyA+IDA7IG0gPSBtICogMjU2ICsgYnVmZmVyW29mZnNldCArIGldLCBpICs9IGQsIG5CaXRzIC09IDgpIHt9XG5cbiAgaWYgKGUgPT09IDApIHtcbiAgICBlID0gMSAtIGVCaWFzXG4gIH0gZWxzZSBpZiAoZSA9PT0gZU1heCkge1xuICAgIHJldHVybiBtID8gTmFOIDogKChzID8gLTEgOiAxKSAqIEluZmluaXR5KVxuICB9IGVsc2Uge1xuICAgIG0gPSBtICsgTWF0aC5wb3coMiwgbUxlbilcbiAgICBlID0gZSAtIGVCaWFzXG4gIH1cbiAgcmV0dXJuIChzID8gLTEgOiAxKSAqIG0gKiBNYXRoLnBvdygyLCBlIC0gbUxlbilcbn1cblxuZXhwb3J0cy53cml0ZSA9IGZ1bmN0aW9uIChidWZmZXIsIHZhbHVlLCBvZmZzZXQsIGlzTEUsIG1MZW4sIG5CeXRlcykge1xuICB2YXIgZSwgbSwgY1xuICB2YXIgZUxlbiA9IG5CeXRlcyAqIDggLSBtTGVuIC0gMVxuICB2YXIgZU1heCA9ICgxIDw8IGVMZW4pIC0gMVxuICB2YXIgZUJpYXMgPSBlTWF4ID4+IDFcbiAgdmFyIHJ0ID0gKG1MZW4gPT09IDIzID8gTWF0aC5wb3coMiwgLTI0KSAtIE1hdGgucG93KDIsIC03NykgOiAwKVxuICB2YXIgaSA9IGlzTEUgPyAwIDogKG5CeXRlcyAtIDEpXG4gIHZhciBkID0gaXNMRSA/IDEgOiAtMVxuICB2YXIgcyA9IHZhbHVlIDwgMCB8fCAodmFsdWUgPT09IDAgJiYgMSAvIHZhbHVlIDwgMCkgPyAxIDogMFxuXG4gIHZhbHVlID0gTWF0aC5hYnModmFsdWUpXG5cbiAgaWYgKGlzTmFOKHZhbHVlKSB8fCB2YWx1ZSA9PT0gSW5maW5pdHkpIHtcbiAgICBtID0gaXNOYU4odmFsdWUpID8gMSA6IDBcbiAgICBlID0gZU1heFxuICB9IGVsc2Uge1xuICAgIGUgPSBNYXRoLmZsb29yKE1hdGgubG9nKHZhbHVlKSAvIE1hdGguTE4yKVxuICAgIGlmICh2YWx1ZSAqIChjID0gTWF0aC5wb3coMiwgLWUpKSA8IDEpIHtcbiAgICAgIGUtLVxuICAgICAgYyAqPSAyXG4gICAgfVxuICAgIGlmIChlICsgZUJpYXMgPj0gMSkge1xuICAgICAgdmFsdWUgKz0gcnQgLyBjXG4gICAgfSBlbHNlIHtcbiAgICAgIHZhbHVlICs9IHJ0ICogTWF0aC5wb3coMiwgMSAtIGVCaWFzKVxuICAgIH1cbiAgICBpZiAodmFsdWUgKiBjID49IDIpIHtcbiAgICAgIGUrK1xuICAgICAgYyAvPSAyXG4gICAgfVxuXG4gICAgaWYgKGUgKyBlQmlhcyA+PSBlTWF4KSB7XG4gICAgICBtID0gMFxuICAgICAgZSA9IGVNYXhcbiAgICB9IGVsc2UgaWYgKGUgKyBlQmlhcyA+PSAxKSB7XG4gICAgICBtID0gKHZhbHVlICogYyAtIDEpICogTWF0aC5wb3coMiwgbUxlbilcbiAgICAgIGUgPSBlICsgZUJpYXNcbiAgICB9IGVsc2Uge1xuICAgICAgbSA9IHZhbHVlICogTWF0aC5wb3coMiwgZUJpYXMgLSAxKSAqIE1hdGgucG93KDIsIG1MZW4pXG4gICAgICBlID0gMFxuICAgIH1cbiAgfVxuXG4gIGZvciAoOyBtTGVuID49IDg7IGJ1ZmZlcltvZmZzZXQgKyBpXSA9IG0gJiAweGZmLCBpICs9IGQsIG0gLz0gMjU2LCBtTGVuIC09IDgpIHt9XG5cbiAgZSA9IChlIDw8IG1MZW4pIHwgbVxuICBlTGVuICs9IG1MZW5cbiAgZm9yICg7IGVMZW4gPiAwOyBidWZmZXJbb2Zmc2V0ICsgaV0gPSBlICYgMHhmZiwgaSArPSBkLCBlIC89IDI1NiwgZUxlbiAtPSA4KSB7fVxuXG4gIGJ1ZmZlcltvZmZzZXQgKyBpIC0gZF0gfD0gcyAqIDEyOFxufVxuIiwiXG52YXIgaW5kZXhPZiA9IFtdLmluZGV4T2Y7XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24oYXJyLCBvYmope1xuICBpZiAoaW5kZXhPZikgcmV0dXJuIGFyci5pbmRleE9mKG9iaik7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgYXJyLmxlbmd0aDsgKytpKSB7XG4gICAgaWYgKGFycltpXSA9PT0gb2JqKSByZXR1cm4gaTtcbiAgfVxuICByZXR1cm4gLTE7XG59OyIsImlmICh0eXBlb2YgT2JqZWN0LmNyZWF0ZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAvLyBpbXBsZW1lbnRhdGlvbiBmcm9tIHN0YW5kYXJkIG5vZGUuanMgJ3V0aWwnIG1vZHVsZVxuICBtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGluaGVyaXRzKGN0b3IsIHN1cGVyQ3Rvcikge1xuICAgIGN0b3Iuc3VwZXJfID0gc3VwZXJDdG9yXG4gICAgY3Rvci5wcm90b3R5cGUgPSBPYmplY3QuY3JlYXRlKHN1cGVyQ3Rvci5wcm90b3R5cGUsIHtcbiAgICAgIGNvbnN0cnVjdG9yOiB7XG4gICAgICAgIHZhbHVlOiBjdG9yLFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgd3JpdGFibGU6IHRydWUsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgICAgfVxuICAgIH0pO1xuICB9O1xufSBlbHNlIHtcbiAgLy8gb2xkIHNjaG9vbCBzaGltIGZvciBvbGQgYnJvd3NlcnNcbiAgbW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBpbmhlcml0cyhjdG9yLCBzdXBlckN0b3IpIHtcbiAgICBjdG9yLnN1cGVyXyA9IHN1cGVyQ3RvclxuICAgIHZhciBUZW1wQ3RvciA9IGZ1bmN0aW9uICgpIHt9XG4gICAgVGVtcEN0b3IucHJvdG90eXBlID0gc3VwZXJDdG9yLnByb3RvdHlwZVxuICAgIGN0b3IucHJvdG90eXBlID0gbmV3IFRlbXBDdG9yKClcbiAgICBjdG9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IGN0b3JcbiAgfVxufVxuIiwidmFyIHRvU3RyaW5nID0ge30udG9TdHJpbmc7XG5cbm1vZHVsZS5leHBvcnRzID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoYXJyKSB7XG4gIHJldHVybiB0b1N0cmluZy5jYWxsKGFycikgPT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBCTiA9IHJlcXVpcmUoJ2FzbjEuanMnKS5iaWdudW07XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gYmFzZTY0VG9CaWdOdW0odmFsLCB6ZXJvKSB7XG5cdHZhciBidWYgPSBuZXcgQnVmZmVyKHZhbCwgJ2Jhc2U2NCcpO1xuXHR2YXIgYm4gPSB2YWwgPSBuZXcgQk4oYnVmLCAxMCwgJ2JlJykuaWFicygpO1xuXHRpZiAoemVybykge1xuXHRcdGJ1Zi5maWxsKDApO1xuXHR9XG5cdHJldHVybiBibjtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpLFxuXHRFQyA9IHJlcXVpcmUoJ2VsbGlwdGljJykuZWM7XG5cbnZhciBiNjRUb0JuID0gcmVxdWlyZSgnLi9iNjQtdG8tYm4nKTtcblxudmFyIGN1cnZlcyA9IHtcblx0XHQnUC0yNTYnOiAncDI1NicsXG5cdFx0J1AtMzg0JzogJ3AzODQnLFxuXHRcdCdQLTUyMSc6ICdwNTIxJ1xuXHR9LFxuXHRvaWRzID0ge1xuXHRcdCdQLTI1Nic6IFsxLCAyLCA4NDAsIDEwMDQ1LCAzLCAxLCA3XSxcblx0XHQnUC0zODQnOiBbMSwgMywgMTMyLCAwLCAzNF0sXG5cdFx0J1AtNTIxJzogWzEsIDMsIDEzMiwgMCwgMzVdXG5cdH07XG5cbmZ1bmN0aW9uIGVjSndrVG9CdWZmZXIoandrLCBvcHRzKSB7XG5cdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5jcnYpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5jcnZcIiB0byBiZSBhIFN0cmluZycpO1xuXHR9XG5cblx0dmFyIGhhc0QgPSAnc3RyaW5nJyA9PT0gdHlwZW9mIGp3ay5kO1xuXHR2YXIgeHlUeXBlcyA9IGhhc0Rcblx0XHQ/IFsndW5kZWZpbmVkJywgJ3N0cmluZyddXG5cdFx0OiBbJ3N0cmluZyddO1xuXG5cdGlmICgtMSA9PT0geHlUeXBlcy5pbmRleE9mKHR5cGVvZiBqd2sueCkpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay54XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmICgtMSA9PT0geHlUeXBlcy5pbmRleE9mKHR5cGVvZiBqd2sueSkpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay55XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmIChvcHRzLnByaXZhdGUgJiYgIWhhc0QpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdHZhciBjdXJ2ZU5hbWUgPSBjdXJ2ZXNbandrLmNydl07XG5cdGlmICghY3VydmVOYW1lKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKCdVbnN1cHBvcnRlZCBjdXJ2ZSBcIicgKyBqd2suY3J2ICsgJ1wiJyk7XG5cdH1cblxuXHR2YXIgY3VydmUgPSBuZXcgRUMoY3VydmVOYW1lKTtcblxuXHR2YXIga2V5ID0ge307XG5cblx0dmFyIGhhc1B1YiA9IGp3ay54ICYmIGp3ay55O1xuXHRpZiAoaGFzUHViKSB7XG5cdFx0a2V5LnB1YiA9IHtcblx0XHRcdHg6IGI2NFRvQm4oandrLngsIGZhbHNlKSxcblx0XHRcdHk6IGI2NFRvQm4oandrLnksIGZhbHNlKVxuXHRcdH07XG5cdH1cblxuXHRpZiAob3B0cy5wcml2YXRlIHx8ICFoYXNQdWIpIHtcblx0XHRrZXkucHJpdiA9IGI2NFRvQm4oandrLmQsIHRydWUpO1xuXHR9XG5cblx0a2V5ID0gY3VydmUua2V5UGFpcihrZXkpO1xuXG5cdHZhciBrZXlWYWxpZGF0aW9uID0ga2V5LnZhbGlkYXRlKCk7XG5cdGlmICgha2V5VmFsaWRhdGlvbi5yZXN1bHQpIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQga2V5IGZvciBjdXJ2ZTogXCInICsga2V5VmFsaWRhdGlvbi5yZWFzb24gKyAnXCInKTtcblx0fVxuXG5cdHZhciByZXN1bHQgPSBrZXlUb1BlbShqd2suY3J2LCBrZXksIG9wdHMpO1xuXG5cdHJldHVybiByZXN1bHQ7XG59XG5cbmZ1bmN0aW9uIGtleVRvUGVtKGNydiwga2V5LCBvcHRzKSB7XG5cdHZhciBjb21wYWN0ID0gZmFsc2U7XG5cdHZhciBzdWJqZWN0UHVibGljS2V5ID0ga2V5LmdldFB1YmxpYyhjb21wYWN0LCAnaGV4Jyk7XG5cdHN1YmplY3RQdWJsaWNLZXkgPSBuZXcgQnVmZmVyKHN1YmplY3RQdWJsaWNLZXksICdoZXgnKTtcblx0c3ViamVjdFB1YmxpY0tleSA9IHtcblx0XHR1bnVzZWQ6IDAsXG5cdFx0ZGF0YTogc3ViamVjdFB1YmxpY0tleVxuXHR9O1xuXG5cdHZhciBwYXJhbWV0ZXJzID0gRUNQYXJhbWV0ZXJzLmVuY29kZSh7XG5cdFx0dHlwZTogJ25hbWVkQ3VydmUnLFxuXHRcdHZhbHVlOiBvaWRzW2Nydl1cblx0fSwgJ2RlcicpO1xuXG5cdHZhciByZXN1bHQ7XG5cdGlmIChvcHRzLnByaXZhdGUpIHtcblx0XHR2YXIgcHJpdmF0ZUtleSA9IGtleS5nZXRQcml2YXRlKCdoZXgnKTtcblx0XHRwcml2YXRlS2V5ID0gbmV3IEJ1ZmZlcihwcml2YXRlS2V5LCAnaGV4Jyk7XG5cblx0XHRyZXN1bHQgPSBFQ1ByaXZhdGVLZXkuZW5jb2RlKHtcblx0XHRcdHZlcnNpb246IGVjUHJpdmtleVZlcjEsXG5cdFx0XHRwcml2YXRlS2V5OiBwcml2YXRlS2V5LFxuXHRcdFx0cGFyYW1ldGVyczogcGFyYW1ldGVycyxcblx0XHRcdHB1YmxpY0tleTogc3ViamVjdFB1YmxpY0tleVxuXHRcdH0sICdwZW0nLCB7XG5cdFx0XHRsYWJlbDogJ0VDIFBSSVZBVEUgS0VZJ1xuXHRcdH0pO1xuXG5cdFx0cHJpdmF0ZUtleS5maWxsKDApO1xuXHR9IGVsc2Uge1xuXHRcdHJlc3VsdCA9IFN1YmplY3RQdWJsaWNLZXlJbmZvLmVuY29kZSh7XG5cdFx0XHRhbGdvcml0aG06IHtcblx0XHRcdFx0YWxnb3JpdGhtOiBbMSwgMiwgODQwLCAxMDA0NSwgMiwgMV0sXG5cdFx0XHRcdHBhcmFtZXRlcnM6IHBhcmFtZXRlcnNcblx0XHRcdH0sXG5cdFx0XHRzdWJqZWN0UHVibGljS2V5OiBzdWJqZWN0UHVibGljS2V5XG5cdFx0fSwgJ3BlbScsIHtcblx0XHRcdGxhYmVsOiAnUFVCTElDIEtFWSdcblx0XHR9KTtcblx0fVxuXG5cdC8vIFRoaXMgaXMgaW4gYW4gaWYgaW5jYXNlIGFzbjEuanMgYWRkcyBhIHRyYWlsaW5nIFxcblxuXHQvLyBpc3RhbmJ1bCBpZ25vcmUgZWxzZVxuXHRpZiAoJ1xcbicgIT09IHJlc3VsdC5zbGljZSgtMSkpIHtcblx0XHRyZXN1bHQgKz0gJ1xcbic7XG5cdH1cblxuXHRyZXR1cm4gcmVzdWx0O1xufVxuXG52YXIgRUNQYXJhbWV0ZXJzID0gYXNuMS5kZWZpbmUoJ0VDUGFyYW1ldGVycycsIC8qIEB0aGlzICovIGZ1bmN0aW9uKCkge1xuXHR0aGlzLmNob2ljZSh7XG5cdFx0bmFtZWRDdXJ2ZTogdGhpcy5vYmppZCgpXG5cdH0pO1xufSk7XG5cbnZhciBlY1ByaXZrZXlWZXIxID0gMTtcblxudmFyIEVDUHJpdmF0ZUtleSA9IGFzbjEuZGVmaW5lKCdFQ1ByaXZhdGVLZXknLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5zZXEoKS5vYmooXG5cdFx0dGhpcy5rZXkoJ3ZlcnNpb24nKS5pbnQoKSxcblx0XHR0aGlzLmtleSgncHJpdmF0ZUtleScpLm9jdHN0cigpLFxuXHRcdHRoaXMua2V5KCdwYXJhbWV0ZXJzJykuZXhwbGljaXQoMCkub3B0aW9uYWwoKS5hbnkoKSxcblx0XHR0aGlzLmtleSgncHVibGljS2V5JykuZXhwbGljaXQoMSkub3B0aW9uYWwoKS5iaXRzdHIoKVxuXHQpO1xufSk7XG5cbnZhciBBbGdvcml0aG1JZGVudGlmaWVyID0gYXNuMS5kZWZpbmUoJ0FsZ29yaXRobUlkZW50aWZpZXInLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5zZXEoKS5vYmooXG5cdFx0dGhpcy5rZXkoJ2FsZ29yaXRobScpLm9iamlkKCksXG5cdFx0dGhpcy5rZXkoJ3BhcmFtZXRlcnMnKS5vcHRpb25hbCgpLmFueSgpXG5cdCk7XG59KTtcblxudmFyIFN1YmplY3RQdWJsaWNLZXlJbmZvID0gYXNuMS5kZWZpbmUoJ1N1YmplY3RQdWJsaWNLZXlJbmZvJywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCdhbGdvcml0aG0nKS51c2UoQWxnb3JpdGhtSWRlbnRpZmllciksXG5cdFx0dGhpcy5rZXkoJ3N1YmplY3RQdWJsaWNLZXknKS5iaXRzdHIoKVxuXHQpO1xufSk7XG5cbm1vZHVsZS5leHBvcnRzID0gZWNKd2tUb0J1ZmZlcjtcbiIsIid1c2Ugc3RyaWN0JztcblxudmFyIGVjID0gcmVxdWlyZSgnLi9lYycpLFxuXHRyc2EgPSByZXF1aXJlKCcuL3JzYScpO1xuXG5mdW5jdGlvbiBqd2tUb0J1ZmZlcihqd2ssIG9wdHMpIHtcblx0aWYgKCdvYmplY3QnICE9PSB0eXBlb2YgandrIHx8IG51bGwgPT09IGp3aykge1xuXHRcdHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiandrXCIgdG8gYmUgYW4gT2JqZWN0Jyk7XG5cdH1cblxuXHR2YXIga3R5ID0gandrLmt0eTtcblx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2Yga3R5KSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sua3R5XCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdG9wdHMgPSBvcHRzIHx8IHt9O1xuXHRvcHRzLnByaXZhdGUgPSBvcHRzLnByaXZhdGUgPT09IHRydWU7XG5cblx0c3dpdGNoIChrdHkpIHtcblx0XHRjYXNlICdFQyc6IHtcblx0XHRcdHJldHVybiBlYyhqd2ssIG9wdHMpO1xuXHRcdH1cblx0XHRjYXNlICdSU0EnOiB7XG5cdFx0XHRyZXR1cm4gcnNhKGp3aywgb3B0cyk7XG5cdFx0fVxuXHRcdGRlZmF1bHQ6IHtcblx0XHRcdHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQga2V5IHR5cGUgXCInICsga3R5ICsgJ1wiJyk7XG5cdFx0fVxuXHR9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gandrVG9CdWZmZXI7XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBhc24xID0gcmVxdWlyZSgnYXNuMS5qcycpO1xuXG52YXIgYjY0VG9CbiA9IHJlcXVpcmUoJy4vYjY0LXRvLWJuJyk7XG5cbnZhciBWZXJzaW9uID0gYXNuMS5kZWZpbmUoJ1ZlcnNpb24nLCAvKiBAdGhpcyAqLyBmdW5jdGlvbigpIHtcblx0dGhpcy5pbnQoKTtcbn0pO1xuXG52YXIgUlNBUHJpdmF0ZUtleSA9IGFzbjEuZGVmaW5lKCdSU0FQcml2YXRlS2V5JywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCd2ZXJzaW9uJykudXNlKFZlcnNpb24pLFxuXHRcdHRoaXMua2V5KCdtb2R1bHVzJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3B1YmxpY0V4cG9uZW50JykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3ByaXZhdGVFeHBvbmVudCcpLmludCgpLFxuXHRcdHRoaXMua2V5KCdwcmltZTEnKS5pbnQoKSxcblx0XHR0aGlzLmtleSgncHJpbWUyJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ2V4cG9uZW50MScpLmludCgpLFxuXHRcdHRoaXMua2V5KCdleHBvbmVudDInKS5pbnQoKSxcblx0XHR0aGlzLmtleSgnY29lZmZpY2llbnQnKS5pbnQoKVxuXHQpO1xufSk7XG5cbnZhciBSU0FQdWJsaWNLZXkgPSBhc24xLmRlZmluZSgnUlNBUHVibGljS2V5JywgLyogQHRoaXMgKi8gZnVuY3Rpb24oKSB7XG5cdHRoaXMuc2VxKCkub2JqKFxuXHRcdHRoaXMua2V5KCdtb2R1bHVzJykuaW50KCksXG5cdFx0dGhpcy5rZXkoJ3B1YmxpY0V4cG9uZW50JykuaW50KClcblx0KTtcbn0pO1xuXG5mdW5jdGlvbiByc2FKd2tUb0J1ZmZlcihqd2ssIG9wdHMpIHtcblx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmUpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5lXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0fVxuXG5cdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5uKSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sublwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdH1cblxuXHRpZiAob3B0cy5wcml2YXRlKSB7XG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmQpIHtcblx0XHRcdHRocm93IG5ldyBUeXBlRXJyb3IoJ0V4cGVjdGVkIFwiandrLmRcIiB0byBiZSBhIFN0cmluZycpO1xuXHRcdH1cblxuXHRcdGlmICgnc3RyaW5nJyAhPT0gdHlwZW9mIGp3ay5wKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5wXCIgdG8gYmUgYSBTdHJpbmcnKTtcblx0XHR9XG5cblx0XHRpZiAoJ3N0cmluZycgIT09IHR5cGVvZiBqd2sucSkge1xuXHRcdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignRXhwZWN0ZWQgXCJqd2sucVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmRwKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kcFwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLmRxKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5kcVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXG5cdFx0aWYgKCdzdHJpbmcnICE9PSB0eXBlb2YgandrLnFpKSB7XG5cdFx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdFeHBlY3RlZCBcImp3ay5xaVwiIHRvIGJlIGEgU3RyaW5nJyk7XG5cdFx0fVxuXHR9XG5cblx0dmFyIHBlbTtcblx0aWYgKG9wdHMucHJpdmF0ZSkge1xuXHRcdHBlbSA9IFJTQVByaXZhdGVLZXkuZW5jb2RlKHtcblx0XHRcdHZlcnNpb246IDAsXG5cdFx0XHRtb2R1bHVzOiBiNjRUb0JuKGp3ay5uLCBmYWxzZSksXG5cdFx0XHRwdWJsaWNFeHBvbmVudDogYjY0VG9Cbihqd2suZSwgZmFsc2UpLFxuXHRcdFx0cHJpdmF0ZUV4cG9uZW50OiBiNjRUb0JuKGp3ay5kLCB0cnVlKSxcblx0XHRcdHByaW1lMTogYjY0VG9Cbihqd2sucCwgdHJ1ZSksXG5cdFx0XHRwcmltZTI6IGI2NFRvQm4oandrLnEsIHRydWUpLFxuXHRcdFx0ZXhwb25lbnQxOiBiNjRUb0JuKGp3ay5kcCwgdHJ1ZSksXG5cdFx0XHRleHBvbmVudDI6IGI2NFRvQm4oandrLmRxLCB0cnVlKSxcblx0XHRcdGNvZWZmaWNpZW50OiBiNjRUb0JuKGp3ay5xaSwgdHJ1ZSlcblx0XHR9LCAncGVtJywge1xuXHRcdFx0bGFiZWw6ICdSU0EgUFJJVkFURSBLRVknXG5cdFx0fSk7XG5cdH0gZWxzZSB7XG5cdFx0cGVtID0gUlNBUHVibGljS2V5LmVuY29kZSh7XG5cdFx0XHRtb2R1bHVzOiBiNjRUb0JuKGp3ay5uLCBmYWxzZSksXG5cdFx0XHRwdWJsaWNFeHBvbmVudDogYjY0VG9Cbihqd2suZSwgZmFsc2UpXG5cdFx0fSwgJ3BlbScsIHtcblx0XHRcdGxhYmVsOiAnUlNBIFBVQkxJQyBLRVknXG5cdFx0fSk7XG5cdH1cblxuXHQvLyBUaGlzIGlzIGluIGFuIGlmIGluY2FzZSBhc24xLmpzIGFkZHMgYSB0cmFpbGluZyBcXG5cblx0Ly8gaXN0YW5idWwgaWdub3JlIGVsc2Vcblx0aWYgKCdcXG4nICE9PSBwZW0uc2xpY2UoLTEpKSB7XG5cdFx0cGVtICs9ICdcXG4nO1xuXHR9XG5cblx0cmV0dXJuIHBlbTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSByc2FKd2tUb0J1ZmZlcjtcbiIsIm1vZHVsZS5leHBvcnRzID0gYXNzZXJ0O1xuXG5mdW5jdGlvbiBhc3NlcnQodmFsLCBtc2cpIHtcbiAgaWYgKCF2YWwpXG4gICAgdGhyb3cgbmV3IEVycm9yKG1zZyB8fCAnQXNzZXJ0aW9uIGZhaWxlZCcpO1xufVxuXG5hc3NlcnQuZXF1YWwgPSBmdW5jdGlvbiBhc3NlcnRFcXVhbChsLCByLCBtc2cpIHtcbiAgaWYgKGwgIT0gcilcbiAgICB0aHJvdyBuZXcgRXJyb3IobXNnIHx8ICgnQXNzZXJ0aW9uIGZhaWxlZDogJyArIGwgKyAnICE9ICcgKyByKSk7XG59O1xuIiwiLy8gc2hpbSBmb3IgdXNpbmcgcHJvY2VzcyBpbiBicm93c2VyXG5cbnZhciBwcm9jZXNzID0gbW9kdWxlLmV4cG9ydHMgPSB7fTtcbnZhciBxdWV1ZSA9IFtdO1xudmFyIGRyYWluaW5nID0gZmFsc2U7XG52YXIgY3VycmVudFF1ZXVlO1xudmFyIHF1ZXVlSW5kZXggPSAtMTtcblxuZnVuY3Rpb24gY2xlYW5VcE5leHRUaWNrKCkge1xuICAgIGlmICghZHJhaW5pbmcgfHwgIWN1cnJlbnRRdWV1ZSkge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIGRyYWluaW5nID0gZmFsc2U7XG4gICAgaWYgKGN1cnJlbnRRdWV1ZS5sZW5ndGgpIHtcbiAgICAgICAgcXVldWUgPSBjdXJyZW50UXVldWUuY29uY2F0KHF1ZXVlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgICBxdWV1ZUluZGV4ID0gLTE7XG4gICAgfVxuICAgIGlmIChxdWV1ZS5sZW5ndGgpIHtcbiAgICAgICAgZHJhaW5RdWV1ZSgpO1xuICAgIH1cbn1cblxuZnVuY3Rpb24gZHJhaW5RdWV1ZSgpIHtcbiAgICBpZiAoZHJhaW5pbmcpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB2YXIgdGltZW91dCA9IHNldFRpbWVvdXQoY2xlYW5VcE5leHRUaWNrKTtcbiAgICBkcmFpbmluZyA9IHRydWU7XG5cbiAgICB2YXIgbGVuID0gcXVldWUubGVuZ3RoO1xuICAgIHdoaWxlKGxlbikge1xuICAgICAgICBjdXJyZW50UXVldWUgPSBxdWV1ZTtcbiAgICAgICAgcXVldWUgPSBbXTtcbiAgICAgICAgd2hpbGUgKCsrcXVldWVJbmRleCA8IGxlbikge1xuICAgICAgICAgICAgaWYgKGN1cnJlbnRRdWV1ZSkge1xuICAgICAgICAgICAgICAgIGN1cnJlbnRRdWV1ZVtxdWV1ZUluZGV4XS5ydW4oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBxdWV1ZUluZGV4ID0gLTE7XG4gICAgICAgIGxlbiA9IHF1ZXVlLmxlbmd0aDtcbiAgICB9XG4gICAgY3VycmVudFF1ZXVlID0gbnVsbDtcbiAgICBkcmFpbmluZyA9IGZhbHNlO1xuICAgIGNsZWFyVGltZW91dCh0aW1lb3V0KTtcbn1cblxucHJvY2Vzcy5uZXh0VGljayA9IGZ1bmN0aW9uIChmdW4pIHtcbiAgICB2YXIgYXJncyA9IG5ldyBBcnJheShhcmd1bWVudHMubGVuZ3RoIC0gMSk7XG4gICAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPiAxKSB7XG4gICAgICAgIGZvciAodmFyIGkgPSAxOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBhcmdzW2kgLSAxXSA9IGFyZ3VtZW50c1tpXTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBxdWV1ZS5wdXNoKG5ldyBJdGVtKGZ1biwgYXJncykpO1xuICAgIGlmIChxdWV1ZS5sZW5ndGggPT09IDEgJiYgIWRyYWluaW5nKSB7XG4gICAgICAgIHNldFRpbWVvdXQoZHJhaW5RdWV1ZSwgMCk7XG4gICAgfVxufTtcblxuLy8gdjggbGlrZXMgcHJlZGljdGlibGUgb2JqZWN0c1xuZnVuY3Rpb24gSXRlbShmdW4sIGFycmF5KSB7XG4gICAgdGhpcy5mdW4gPSBmdW47XG4gICAgdGhpcy5hcnJheSA9IGFycmF5O1xufVxuSXRlbS5wcm90b3R5cGUucnVuID0gZnVuY3Rpb24gKCkge1xuICAgIHRoaXMuZnVuLmFwcGx5KG51bGwsIHRoaXMuYXJyYXkpO1xufTtcbnByb2Nlc3MudGl0bGUgPSAnYnJvd3Nlcic7XG5wcm9jZXNzLmJyb3dzZXIgPSB0cnVlO1xucHJvY2Vzcy5lbnYgPSB7fTtcbnByb2Nlc3MuYXJndiA9IFtdO1xucHJvY2Vzcy52ZXJzaW9uID0gJyc7IC8vIGVtcHR5IHN0cmluZyB0byBhdm9pZCByZWdleHAgaXNzdWVzXG5wcm9jZXNzLnZlcnNpb25zID0ge307XG5cbmZ1bmN0aW9uIG5vb3AoKSB7fVxuXG5wcm9jZXNzLm9uID0gbm9vcDtcbnByb2Nlc3MuYWRkTGlzdGVuZXIgPSBub29wO1xucHJvY2Vzcy5vbmNlID0gbm9vcDtcbnByb2Nlc3Mub2ZmID0gbm9vcDtcbnByb2Nlc3MucmVtb3ZlTGlzdGVuZXIgPSBub29wO1xucHJvY2Vzcy5yZW1vdmVBbGxMaXN0ZW5lcnMgPSBub29wO1xucHJvY2Vzcy5lbWl0ID0gbm9vcDtcblxucHJvY2Vzcy5iaW5kaW5nID0gZnVuY3Rpb24gKG5hbWUpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3Byb2Nlc3MuYmluZGluZyBpcyBub3Qgc3VwcG9ydGVkJyk7XG59O1xuXG5wcm9jZXNzLmN3ZCA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuICcvJyB9O1xucHJvY2Vzcy5jaGRpciA9IGZ1bmN0aW9uIChkaXIpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3Byb2Nlc3MuY2hkaXIgaXMgbm90IHN1cHBvcnRlZCcpO1xufTtcbnByb2Nlc3MudW1hc2sgPSBmdW5jdGlvbigpIHsgcmV0dXJuIDA7IH07XG4iLCJ2YXIgaW5kZXhPZiA9IHJlcXVpcmUoJ2luZGV4b2YnKTtcblxudmFyIE9iamVjdF9rZXlzID0gZnVuY3Rpb24gKG9iaikge1xuICAgIGlmIChPYmplY3Qua2V5cykgcmV0dXJuIE9iamVjdC5rZXlzKG9iailcbiAgICBlbHNlIHtcbiAgICAgICAgdmFyIHJlcyA9IFtdO1xuICAgICAgICBmb3IgKHZhciBrZXkgaW4gb2JqKSByZXMucHVzaChrZXkpXG4gICAgICAgIHJldHVybiByZXM7XG4gICAgfVxufTtcblxudmFyIGZvckVhY2ggPSBmdW5jdGlvbiAoeHMsIGZuKSB7XG4gICAgaWYgKHhzLmZvckVhY2gpIHJldHVybiB4cy5mb3JFYWNoKGZuKVxuICAgIGVsc2UgZm9yICh2YXIgaSA9IDA7IGkgPCB4cy5sZW5ndGg7IGkrKykge1xuICAgICAgICBmbih4c1tpXSwgaSwgeHMpO1xuICAgIH1cbn07XG5cbnZhciBkZWZpbmVQcm9wID0gKGZ1bmN0aW9uKCkge1xuICAgIHRyeSB7XG4gICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh7fSwgJ18nLCB7fSk7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbihvYmosIG5hbWUsIHZhbHVlKSB7XG4gICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkob2JqLCBuYW1lLCB7XG4gICAgICAgICAgICAgICAgd3JpdGFibGU6IHRydWUsXG4gICAgICAgICAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlLFxuICAgICAgICAgICAgICAgIHZhbHVlOiB2YWx1ZVxuICAgICAgICAgICAgfSlcbiAgICAgICAgfTtcbiAgICB9IGNhdGNoKGUpIHtcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKG9iaiwgbmFtZSwgdmFsdWUpIHtcbiAgICAgICAgICAgIG9ialtuYW1lXSA9IHZhbHVlO1xuICAgICAgICB9O1xuICAgIH1cbn0oKSk7XG5cbnZhciBnbG9iYWxzID0gWydBcnJheScsICdCb29sZWFuJywgJ0RhdGUnLCAnRXJyb3InLCAnRXZhbEVycm9yJywgJ0Z1bmN0aW9uJyxcbidJbmZpbml0eScsICdKU09OJywgJ01hdGgnLCAnTmFOJywgJ051bWJlcicsICdPYmplY3QnLCAnUmFuZ2VFcnJvcicsXG4nUmVmZXJlbmNlRXJyb3InLCAnUmVnRXhwJywgJ1N0cmluZycsICdTeW50YXhFcnJvcicsICdUeXBlRXJyb3InLCAnVVJJRXJyb3InLFxuJ2RlY29kZVVSSScsICdkZWNvZGVVUklDb21wb25lbnQnLCAnZW5jb2RlVVJJJywgJ2VuY29kZVVSSUNvbXBvbmVudCcsICdlc2NhcGUnLFxuJ2V2YWwnLCAnaXNGaW5pdGUnLCAnaXNOYU4nLCAncGFyc2VGbG9hdCcsICdwYXJzZUludCcsICd1bmRlZmluZWQnLCAndW5lc2NhcGUnXTtcblxuZnVuY3Rpb24gQ29udGV4dCgpIHt9XG5Db250ZXh0LnByb3RvdHlwZSA9IHt9O1xuXG52YXIgU2NyaXB0ID0gZXhwb3J0cy5TY3JpcHQgPSBmdW5jdGlvbiBOb2RlU2NyaXB0IChjb2RlKSB7XG4gICAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIFNjcmlwdCkpIHJldHVybiBuZXcgU2NyaXB0KGNvZGUpO1xuICAgIHRoaXMuY29kZSA9IGNvZGU7XG59O1xuXG5TY3JpcHQucHJvdG90eXBlLnJ1bkluQ29udGV4dCA9IGZ1bmN0aW9uIChjb250ZXh0KSB7XG4gICAgaWYgKCEoY29udGV4dCBpbnN0YW5jZW9mIENvbnRleHQpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJuZWVkcyBhICdjb250ZXh0JyBhcmd1bWVudC5cIik7XG4gICAgfVxuICAgIFxuICAgIHZhciBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICBpZiAoIWlmcmFtZS5zdHlsZSkgaWZyYW1lLnN0eWxlID0ge307XG4gICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XG4gICAgXG4gICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuICAgIFxuICAgIHZhciB3aW4gPSBpZnJhbWUuY29udGVudFdpbmRvdztcbiAgICB2YXIgd0V2YWwgPSB3aW4uZXZhbCwgd0V4ZWNTY3JpcHQgPSB3aW4uZXhlY1NjcmlwdDtcblxuICAgIGlmICghd0V2YWwgJiYgd0V4ZWNTY3JpcHQpIHtcbiAgICAgICAgLy8gd2luLmV2YWwoKSBtYWdpY2FsbHkgYXBwZWFycyB3aGVuIHRoaXMgaXMgY2FsbGVkIGluIElFOlxuICAgICAgICB3RXhlY1NjcmlwdC5jYWxsKHdpbiwgJ251bGwnKTtcbiAgICAgICAgd0V2YWwgPSB3aW4uZXZhbDtcbiAgICB9XG4gICAgXG4gICAgZm9yRWFjaChPYmplY3Rfa2V5cyhjb250ZXh0KSwgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB3aW5ba2V5XSA9IGNvbnRleHRba2V5XTtcbiAgICB9KTtcbiAgICBmb3JFYWNoKGdsb2JhbHMsIGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgaWYgKGNvbnRleHRba2V5XSkge1xuICAgICAgICAgICAgd2luW2tleV0gPSBjb250ZXh0W2tleV07XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICBcbiAgICB2YXIgd2luS2V5cyA9IE9iamVjdF9rZXlzKHdpbik7XG5cbiAgICB2YXIgcmVzID0gd0V2YWwuY2FsbCh3aW4sIHRoaXMuY29kZSk7XG4gICAgXG4gICAgZm9yRWFjaChPYmplY3Rfa2V5cyh3aW4pLCBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIC8vIEF2b2lkIGNvcHlpbmcgY2lyY3VsYXIgb2JqZWN0cyBsaWtlIGB0b3BgIGFuZCBgd2luZG93YCBieSBvbmx5XG4gICAgICAgIC8vIHVwZGF0aW5nIGV4aXN0aW5nIGNvbnRleHQgcHJvcGVydGllcyBvciBuZXcgcHJvcGVydGllcyBpbiB0aGUgYHdpbmBcbiAgICAgICAgLy8gdGhhdCB3YXMgb25seSBpbnRyb2R1Y2VkIGFmdGVyIHRoZSBldmFsLlxuICAgICAgICBpZiAoa2V5IGluIGNvbnRleHQgfHwgaW5kZXhPZih3aW5LZXlzLCBrZXkpID09PSAtMSkge1xuICAgICAgICAgICAgY29udGV4dFtrZXldID0gd2luW2tleV07XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgIGZvckVhY2goZ2xvYmFscywgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICBpZiAoIShrZXkgaW4gY29udGV4dCkpIHtcbiAgICAgICAgICAgIGRlZmluZVByb3AoY29udGV4dCwga2V5LCB3aW5ba2V5XSk7XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICBcbiAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGlmcmFtZSk7XG4gICAgXG4gICAgcmV0dXJuIHJlcztcbn07XG5cblNjcmlwdC5wcm90b3R5cGUucnVuSW5UaGlzQ29udGV4dCA9IGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gZXZhbCh0aGlzLmNvZGUpOyAvLyBtYXliZS4uLlxufTtcblxuU2NyaXB0LnByb3RvdHlwZS5ydW5Jbk5ld0NvbnRleHQgPSBmdW5jdGlvbiAoY29udGV4dCkge1xuICAgIHZhciBjdHggPSBTY3JpcHQuY3JlYXRlQ29udGV4dChjb250ZXh0KTtcbiAgICB2YXIgcmVzID0gdGhpcy5ydW5JbkNvbnRleHQoY3R4KTtcblxuICAgIGZvckVhY2goT2JqZWN0X2tleXMoY3R4KSwgZnVuY3Rpb24gKGtleSkge1xuICAgICAgICBjb250ZXh0W2tleV0gPSBjdHhba2V5XTtcbiAgICB9KTtcblxuICAgIHJldHVybiByZXM7XG59O1xuXG5mb3JFYWNoKE9iamVjdF9rZXlzKFNjcmlwdC5wcm90b3R5cGUpLCBmdW5jdGlvbiAobmFtZSkge1xuICAgIGV4cG9ydHNbbmFtZV0gPSBTY3JpcHRbbmFtZV0gPSBmdW5jdGlvbiAoY29kZSkge1xuICAgICAgICB2YXIgcyA9IFNjcmlwdChjb2RlKTtcbiAgICAgICAgcmV0dXJuIHNbbmFtZV0uYXBwbHkocywgW10uc2xpY2UuY2FsbChhcmd1bWVudHMsIDEpKTtcbiAgICB9O1xufSk7XG5cbmV4cG9ydHMuY3JlYXRlU2NyaXB0ID0gZnVuY3Rpb24gKGNvZGUpIHtcbiAgICByZXR1cm4gZXhwb3J0cy5TY3JpcHQoY29kZSk7XG59O1xuXG5leHBvcnRzLmNyZWF0ZUNvbnRleHQgPSBTY3JpcHQuY3JlYXRlQ29udGV4dCA9IGZ1bmN0aW9uIChjb250ZXh0KSB7XG4gICAgdmFyIGNvcHkgPSBuZXcgQ29udGV4dCgpO1xuICAgIGlmKHR5cGVvZiBjb250ZXh0ID09PSAnb2JqZWN0Jykge1xuICAgICAgICBmb3JFYWNoKE9iamVjdF9rZXlzKGNvbnRleHQpLCBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgICAgICBjb3B5W2tleV0gPSBjb250ZXh0W2tleV07XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICByZXR1cm4gY29weTtcbn07XG4iXX0=
