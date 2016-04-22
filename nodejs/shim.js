var semver = require('semver');
if (semver.satisfies(process.version, '>= 0.12.0')) {
  return;
}

require('buffer-compare-shim');
require('buffer-io-shim');
var crypto = require('crypto');
crypto.createECDH = require('create-ecdh');
crypto.createCipheriv = require('browserify-aes/encrypter').createCipheriv;
crypto.createDecipheriv = require('browserify-aes/decrypter').createDecipheriv;
