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

function encryptDecrypt(length, encryptParams, decryptParams) {
  // These need to be the same.
  assert.equal(encryptParams.version, decryptParams.version);
  assert.equal(encryptParams.rs, decryptParams.rs);
  assert.equal(encryptParams.authSecret, decryptParams.authSecret);

  // Always fill in the salt so we can log it.
  decryptParams.salt = base64.encode(crypto.randomBytes(16));
  encryptParams.salt = decryptParams.salt;
  logbuf('Salt', encryptParams.salt);

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

function useExplicitKey(version) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen
  };
  logbuf('Key', params.key);
  encryptDecrypt(length, params, params);
}

function authenticationSecret(version) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen,
    authSecret: base64.encode(crypto.randomBytes(16))
  };
  logbuf('Key', params.key);
  logbuf('Context', params.authSecret);
  encryptDecrypt(length, params, params);
}

function exactlyOneRecord(version) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0) + 1, maxLen);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: length + 2 // add exactly the padding
  };
  encryptDecrypt(length, params, params);
}

function detectTruncation(version) {
  var length = Math.min(crypto.randomBytes(2).readUInt16BE(0) + minLen, maxLen);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: length // so we get two records
  };
  var headerLen = (version === 'aes128gcm') ? 21 : 0;
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

function useKeyId(version) {
  var length = crypto.randomBytes(4).readUInt16BE(0);
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  var keymap = {};
  keymap[keyid] = key;
  var params = {
    keyid: keyid,
    rs: length + minLen,
    keymap: keymap
  };
  encryptDecrypt(length, params, params, version);
}

function useDH(version) {
  // the static key is used by the receiver
  var staticKey = crypto.createECDH('prime256v1');
  staticKey.generateKeys();
  assert.equal(staticKey.getPublicKey()[0], 4, 'is an uncompressed point');

  logbuf('Receiver private', staticKey.getPrivateKey());
  logbuf('Receiver public', staticKey.getPublicKey());

  // the ephemeral key is used by the sender
  var ephemeralKey = crypto.createECDH('prime256v1');
  ephemeralKey.generateKeys();
  assert.equal(ephemeralKey.getPublicKey()[0], 4, 'is an uncompressed point');

  logbuf('Sender private', ephemeralKey.getPrivateKey());
  logbuf('Sender public', ephemeralKey.getPublicKey());

  var length = crypto.randomBytes(4).readUInt16BE(0);
  var encryptParams = {
    version: version,
    keyid: 'k',
    dh: base64.encode(ephemeralKey.getPublicKey()),
    authSecret: base64.encode(crypto.randomBytes(16)),
    rs: length + minLen,
    keymap: { k: staticKey },
    keylabels: { k: 'P-256' }
  };
  var decryptParams = {
    version: version,
    keyid: 'k',
    dh: base64.encode(staticKey.getPublicKey()),
    authSecret: encryptParams.authSecret,
    rs: encryptParams.rs,
    keymap: { k: ephemeralKey },
    keylabels: { k: 'P-256' }
  };
  encryptDecrypt(length, encryptParams, decryptParams);
}

// Use the examples from the draft as a sanity check.
function checkExamples() {
  [
    {
      args: {
        version: 'aes128gcm',
        key: base64.decode('6Aqf1aDH8lSxLyCpoCnAqg'),
        keyid: '',
        salt: base64.decode('sJvlboCWzB5jr8hI_q9cOQ'),
        rs: 4096
      },
      plaintext: Buffer.from('I am the walrus'),
      ciphertext: base64.decode('sJvlboCWzB5jr8hI_q9cOQAAEAAANSmx' +
                                'kSVa0-MiNNuF77YHSs-iwaNe_OK0qfmO' +
                                'c7NT5WSW'),
    },
    {
      args: {
        version: 'aes128gcm',
        key: base64.decode('BO3ZVPxUlnLORbVGMpbT1Q'),
        keyid: 'a1',
        salt: base64.decode('uNCkWiNYzKTnBN9ji3-qWA'),
        rs: 10,
        pad: 1
      },
      plaintext: Buffer.from('I am the walrus'),
      ciphertext: base64.decode('uNCkWiNYzKTnBN9ji3-qWAAAAAoCYTGH' +
                                'OqYFz-0in3dpb-VE2GfBngkaPy6bZus_' +
                                'qLF79s6zQyTSsA0iLOKyd3JqVIwprNzV' +
                                'atRCWZGUx_qsFbJBCQu62RqQuR2d')
    }
  ].forEach(function (v, i) {
    log('decrypt ' + v.args.version + ' example ' + (i + 1));
    var decrypted = ece.decrypt(v.ciphertext, v.args);
    logbuf('decrypted', decrypted);
    assert.equal(Buffer.compare(v.plaintext, decrypted), 0);

    log('encrypt ' + v.args.version + ' example ' + (i + 1));
    var encrypted = ece.encrypt(v.plaintext, v.args);
    logbuf('encrypted', encrypted);
    assert.equal(Buffer.compare(v.ciphertext, encrypted), 0);
  });
}

validate();
var i;
for (i = 0; i < count; ++i) {
  [ 'aesgcm128', 'aesgcm', 'aes128gcm' ].forEach(function(version) {
    [ useExplicitKey,
      authenticationSecret,
      exactlyOneRecord,
      detectTruncation,
      useKeyId,
      useDH,
    ].forEach(function(f) {
      log(version + ' Test: ' + f.name);
      f(version);
    });
  });
}
checkExamples();

console.log('All tests passed.');
