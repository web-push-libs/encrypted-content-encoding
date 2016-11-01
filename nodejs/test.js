'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');
var fs = require('fs');

var DUMP_FILE = '../encrypt_data.json';
var dump_data = {};

// Usage: node <this> <iterations> <maxsize> <dump>
var count = parseInt(process.argv[2], 10) || 20;
var maxLen = 100;
var plaintext = null;
var dump = false;  // flag to dump encrypt/decrypted values to JSON file for cross library checks.

if (process.argv.length >= 4) {
  if (!isNaN(parseInt(process.argv[3], 10))) {
    maxLen = parseInt(process.argv[3], 10);
  } else {
     plaintext = new Buffer(process.argv[3], 'ascii');
  }
  dump = ( process.argv.indexOf('dump') != -1)
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

// Validate that the encryption function only accepts Buffers
function validate() {
  ['hello', null, 1, NaN, [], {}].forEach(function(v) {
    try {
      ece.encrypt(v, {});
    } catch (e) {
      if (e.toString() != "Error: buffer argument must be a Buffer") {
        throw new Error("encrypt failed to reject " + JSON.stringify(v));
      }
    }
  });
}

function dumpData(data){
  var version = data.version;
  delete(data.version);
  dump_data[version] = data;
}

function encryptDecrypt(length, encryptParams, decryptParams, version, keyData) {
  decryptParams = decryptParams || encryptParams;
  logbuf('Salt', encryptParams.salt);
  var input = plaintext || crypto.randomBytes(Math.min(length, maxLen));
  // var input = new Buffer('I am the walrus');
  logbuf('Input', input);
  var encrypted = ece.encrypt(input, encryptParams);
  logbuf('Encrypted', encrypted);
  var decrypted = ece.decrypt(encrypted, decryptParams);
  logbuf('Decrypted', decrypted);
  if (dump) {
    var data = {
      version: version,
      input: base64.encode(input),
      encrypted: base64.encode(encrypted),
      params: {
        encrypted: encryptParams,
        decrypt: decryptParams,
      }
    };
    if (keyData) {
      data.keys = keyData;
    }
    dumpData(data);
  }
  assert.equal(Buffer.compare(input, decrypted), 0);
  log('----- OK');
}

function useExplicitKey(version) {
  var length = crypto.randomBytes(4);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1
  };
  logbuf('Key', params.key);
  encryptDecrypt(length.readUInt16BE(2), params, params, version);
}

function authenticationSecret(version) {
  var length = crypto.randomBytes(4);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1,
    authSecret: base64.encode(crypto.randomBytes(16))
  };
  logbuf('Key', params.key);
  logbuf('Context', params.authSecret);
  encryptDecrypt(length.readUInt16BE(2), params, params, version);
}

function exactlyOneRecord(version) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0), maxLen);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length + 1
  };
  encryptDecrypt(length, params, params, version);
}

function detectTruncation(version) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0), maxLen);
  var params = {
    key: base64.encode(crypto.randomBytes(16)),
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length + 1
  };
  logbuf('Salt', params.salt);
  var input = crypto.randomBytes(Math.min(length, maxLen));
  logbuf('Input', input);
  var encrypted = ece.encrypt(input, params);
  encrypted = encrypted.slice(0, length + 1 + 16);
  logbuf('Encrypted', encrypted);
  var ok = false;
  try {
    ece.decrypt(encrypted, params, params, version);
  } catch (e) {
    log('----- OK: ' + e);
    ok = true;
  }
  if (!ok) {
    throw new Error('Decryption succeeded, but should not have');
  }
}

function useKeyId(version) {
  var length = crypto.randomBytes(4);
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  ece.saveKey(keyid, key);
  var params = {
    keyid: keyid,
    salt: base64.encode(crypto.randomBytes(16)),
    rs: length.readUInt16BE(0) + 1
  };
  encryptDecrypt(length.readUInt16BE(2), params, params, version);
}

function useDH(version) {
  // the static key is used by the receiver
  var staticKey = crypto.createECDH('prime256v1');
  staticKey.generateKeys();
  assert.equal(staticKey.getPublicKey()[0], 4, 'is an uncompressed point');
  var staticKeyId = staticKey.getPublicKey().toString('hex');
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
    salt: encryptParams.salt,
    rs: encryptParams.rs
  };
  // keyData is used for cross library verification dumps
  var keyData = {
    sender: {
      private: base64.encode(ephemeralKey.getPrivateKey()),
      public: base64.encode(ephemeralKey.getPublicKey())
    },
    receiver: {
      private: base64.encode(staticKey.getPrivateKey()),
      public: base64.encode(staticKey.getPublicKey())
    }
  };
  encryptDecrypt(length.readUInt16BE(2), encryptParams, decryptParams, version, keyData);
}

validate();

for (var version of ['aes128gcm', 'aesgcm', 'aesgcm128']) {
  for (var i = 0; i < count; ++i) {
    [useExplicitKey,
      authenticationSecret,
      exactlyOneRecord,
      detectTruncation,
      useKeyId,
      useDH,
    ].forEach(function (f) {
      log('Test: ' + f.name);
      f(version);
    });
  }
}
console.log('All tests passed.');

if (dump) {
  fs.open(DUMP_FILE, 'w', function (err) {
    if (err) {
      fs.unlink(DUMP_FILE)
    }

    fs.writeFile(DUMP_FILE, JSON.stringify(dump_data, undefined, '  '));
  })
}
