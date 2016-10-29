'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');

// Usage: node <this> <iterations> <maxsize|plaintext>
var count = parseInt(process.argv[2], 10) || 20;
var maxLen = 100;
var minLen = 3;
var plaintext = null;
if (process.argv.length >= 4) {
  if (!isNaN(parseInt(process.argv[3], 10))) {
    maxLen = parseInt(process.argv[3], 10);
  } else {
     plaintext = new Buffer(process.argv[3], 'ascii');
  }
}
var log;
if (count === 1) {
  log = console.log.bind(console);
} else {
  log = function() {};
}
function logbuf(msg, buf) {
  if (typeof buf === 'string') {
    buf = base64.decode(buf);
  }
  log(msg + ': [' + buf.length + ']');
  for (i = 0; i < buf.length; i += 48) {
    log('    ' + base64.encode(buf.slice(i, i + 48)));
  }
}

function validate() {
  ['hello', null, 1, NaN, [], {}].forEach(function(v) {
    try {
      encrypt('hello', {});
      throw new Error('should insist on a buffer');
    } catch (e) {}
  });
}

function encryptDecrypt(length, encryptParams, decryptParams, oldVersion) {
  if (oldVersion) {
    decryptParams.salt = base64.encode(crypto.randomBytes(16));
    encryptParams.salt = decryptParams.salt;
    logbuf('Salt', encryptParams.salt);
  }
  var input = plaintext ||
      crypto.randomBytes(Math.max(minLen, Math.min(length, maxLen)));
  // var input = new Buffer('I am the walrus');
  logbuf('Input', input);
  var encrypted = ece.encrypt(input, encryptParams);
  logbuf('Encrypted', encrypted);
  var decrypted = ece.decrypt(encrypted, decryptParams);
  logbuf('Decrypted', decrypted);
  assert.equal(Buffer.compare(input, decrypted), 0);
  log('----- OK');
}

function useExplicitKey(oldVersion) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen
  };
  logbuf('Key', params.key);
  encryptDecrypt(length, params, params, oldVersion);
}

function authenticationSecret(oldVersion) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen,
    authSecret: base64.encode(crypto.randomBytes(16))
  };
  logbuf('Key', params.key);
  logbuf('Context', params.authSecret);
  encryptDecrypt(length, params, params, oldVersion);
}

function exactlyOneRecord(oldVersion) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0) + 1, maxLen);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + 2 // add exactly the padding
  };
  encryptDecrypt(length, params, params, oldVersion);
}

function detectTruncation(oldVersion) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0) + minLen, maxLen);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    rs: length // so we get two records
  };
  var headerLen;
  if (oldVersion) {
    params.salt = base64.encode(crypto.randomBytes(16));
    logbuf('Salt', params.salt);
    headerLen = 0;
  } else {
    headerLen = 21; // no keyid
  }
  var input = crypto.randomBytes(Math.min(length, maxLen));
  logbuf('Input', input);
  var encrypted = ece.encrypt(input, params);
  var chunkLen = headerLen + params.rs + 16;
  assert.ok(chunkLen < encrypted.length);
  encrypted = encrypted.slice(0, chunkLen);
  logbuf('Encrypted', encrypted);
  var ok = false;
  try {
    ece.decrypt(encrypted, params);
  } catch (e) {
    log('----- OK: ' + e);
    ok = true;
  }
  if (!ok) {
    throw new Error('Decryption succeeded, but should not have');
  }
}

function useKeyId(oldVersion) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  ece.saveKey(keyid, key);
  var params = {
    keyid: keyid,
    rs: length + minLen
  };
  encryptDecrypt(length, params, params, oldVersion);
}

function useDH(oldVersion) {
  // the static key is used by the receiver
  var staticKey = crypto.createECDH('prime256v1');
  staticKey.generateKeys();
  assert.equal(staticKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var staticKeyId = staticKey.getPublicKey().toString('hex')
  ece.saveKey(staticKeyId, staticKey, 'P-256');

  logbuf('Receiver private', staticKey.getPrivateKey());
  logbuf('Receiver public', staticKey.getPublicKey());

  // the ephemeral key is used by the sender
  var ephemeralKey = crypto.createECDH('prime256v1');
  ephemeralKey.generateKeys();
  assert.equal(ephemeralKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var ephemeralKeyId = ephemeralKey.getPublicKey().toString('hex');
  ece.saveKey(ephemeralKeyId, ephemeralKey, 'P-256');

  logbuf('Sender private', ephemeralKey.getPrivateKey());
  logbuf('Sender public', ephemeralKey.getPublicKey());

  var length = crypto.randomBytes(4).readUInt16BE(0);
  var encryptParams = {
    keyid: ephemeralKeyId,
    dh: base64.encode(staticKey.getPublicKey()),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen
  };
  var decryptParams = {
    keyid: staticKeyId,
    dh: base64.encode(ephemeralKey.getPublicKey()),
    salt: encryptParams.salt,
    rs: encryptParams.rs
  };
  encryptDecrypt(length, encryptParams, decryptParams, oldVersion);
}

validate();
var i;
for (i = 0; i < count; ++i) {
  [ true, false ].forEach(function(oldVersion) {
    [ useExplicitKey,
      authenticationSecret,
      exactlyOneRecord,
      detectTruncation,
      useKeyId,
      useDH,
    ].forEach(function(f) {
      log((oldVersion ? 'aesgcm' : 'aes128gcm') + ' Test: ' + f.name);
      f(oldVersion);
    });
  });
}

console.log('All tests passed.');
