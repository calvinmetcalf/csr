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
