'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');

var count = parseInt(process.argv[2], 10) || 20;
// var log = console.log.bind(console);
var log = function() {};

function encryptDecrypt(length, encryptParams, decryptParams) {
  decryptParams = decryptParams || encryptParams;
  log("Nonce: " + base64.encode(encryptParams.salt));
  var input = crypto.randomBytes(length);
  // var input = new Buffer('I am the walrus');
  log("Input: " + base64.encode(input));
  var encrypted = ece.encrypt(input, encryptParams);
  log("Encrypted: " + base64.encode(encrypted));
  var decrypted = ece.decrypt(encrypted, decryptParams);
  log("Decrypted: " + base64.encode(decrypted));
  assert.equal(Buffer.compare(input, decrypted), 0);
}

function useExplicitKey() {
  var length = crypto.randomBytes(4);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1
  };
  log('Key: ' + base64.encode(params.key));
  encryptDecrypt(length.readUInt16BE(2), params);
}

function useKeyId() {
  var length = crypto.randomBytes(4);
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  ece.saveKey(keyid, key);
  var params = {
    keyid: keyid,
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1
  };
  encryptDecrypt(length.readUInt16BE(2), params);
}

function useDH() {
  // the static key is used by the receiver
  var staticKey = crypto.createECDH('prime256v1');
  staticKey.generateKeys();
  assert.equal(staticKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var staticKeyId = staticKey.getPublicKey().toString('hex')
  ece.saveKey(staticKeyId, staticKey);

  log("Receiver private: " + base64.encode(staticKey.getPrivateKey()));
  log("Receiver public: " + base64.encode(staticKey.getPublicKey()));

  // the ephemeral key is used by the sender
  var ephemeralKey = crypto.createECDH('prime256v1');
  ephemeralKey.generateKeys();
  assert.equal(ephemeralKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var ephemeralKeyId = ephemeralKey.getPublicKey().toString('hex');
  ece.saveKey(ephemeralKeyId, ephemeralKey);

  log("Sender private: " + base64.encode(ephemeralKey.getPrivateKey()));
  log("Sender public: " + base64.encode(ephemeralKey.getPublicKey()));

  var length = crypto.randomBytes(4);
  var encryptParams = {
    keyid: ephemeralKeyId,
    dh: base64.encode(staticKey.getPublicKey()),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1
  };
  var decryptParams = {
    keyid: staticKeyId,
    dh: base64.encode(ephemeralKey.getPublicKey()),
    salt: encryptParams.nonce,
    rs: encryptParams.rs
  };
  encryptDecrypt(length.readUInt16BE(2), encryptParams, decryptParams);
}

var i;
for (i = 0; i < count; ++i) {
  useExplicitKey();
}

for (i = 0; i < count; ++i) {
  useKeyId();
}

for (i = 0; i < count; ++i) {
  useDH();
}
console.log('OK');
