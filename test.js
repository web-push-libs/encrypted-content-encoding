'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');

function encryptDecrypt(length, encryptParams, decryptParams) {
  decryptParams = decryptParams || encryptParams;
  var input = crypto.randomBytes(length);
  // console.log("Input: " + input.toString('hex'));
  var encrypted = ece.encrypt(input, encryptParams);
  // console.log("Encrypted: " + encrypted.toString('hex'));
  var decrypted = ece.decrypt(encrypted, decryptParams);
  // console.log("Decrypted: " + decrypted.toString('hex'));
  assert.equal(Buffer.compare(input, decrypted), 0);
}

function useExplicitKey() {
  var length = crypto.randomBytes(4);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    nonce: base64.encode(crypto.randomBytes(16)),
    bs: length.readUInt16BE(0) + 1
  };
  encryptDecrypt(length.readUInt16BE(2), params);
}

function useKeyId() {
  var length = crypto.randomBytes(4);
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  ece.saveKey(keyid, key);
  var params = {
    keyid: keyid,
    nonce: base64.encode(crypto.randomBytes(16)),
    bs: length.readUInt16BE(0) + 1
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

  // the ephemeral key is used by the sender
  var ephemeralKey = crypto.createECDH('prime256v1');
  ephemeralKey.generateKeys();
  assert.equal(ephemeralKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var ephemeralKeyId = ephemeralKey.getPublicKey().toString('hex');
  ece.saveKey(ephemeralKeyId, ephemeralKey);

  var length = crypto.randomBytes(4);
  var encryptParams = {
    keyid: ephemeralKeyId,
    "p256-dh": base64.encode(staticKey.getPublicKey()),
    nonce: base64.encode(crypto.randomBytes(16)),
    bs: length.readUInt16BE(0) + 1
  };
  var decryptParams = {
    keyid: staticKeyId,
    "p256-dh": base64.encode(ephemeralKey.getPublicKey()),
    nonce: encryptParams.nonce,
    bs: encryptParams.bs
  };
  encryptDecrypt(length.readUInt16BE(2), encryptParams, decryptParams);
}

var i;
for (i = 0; i < 10; ++i) {
  useExplicitKey();
}

for (i = 0; i < 10; ++i) {
  useKeyId();
}

for (i = 0; i < 10; ++i) {
  useDH();
}
console.log('OK');
