var asn1 = require('asn1.js');
var AlgorithmIdentifier = exports.AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function() {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters').optional().any()
  );
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
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('subjectPublicKey').bitstr()
  );
});

var AttributeValue = asn1.define('AttributeValue', function() {
  this.printstr();
});
var AttributeType = asn1.define('AttributeType', function() {
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
var CertificationRequestInfo = exports.CertificationRequestInfo = asn1.define('CertificationRequestInfo', function() {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('info').use(RelativeDistinguishedName),
    this.key('publicKey').use(SubjectPublicKeyInfo),
    this.key('attributes').implicit(0).optional().seqOf(Int)
  );
});
exports.CertificationRequest = asn1.define('CertificationRequest', function() {
  this.seq().obj(
    this.key('certificationRequestInfo').use(CertificationRequestInfo),
    this.key('signatureAlgorithm').use(AlgorithmIdentifier),
    this.key('signature').bitstr()
  );
});
