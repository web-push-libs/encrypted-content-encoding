'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');

// Usage: node test.js [args]
// If args contains a version (e.g., aes128gcm), filter on versions.
// If args contains a test function, filter on test functions.
// If args contains 'verbose' show logs.
// If args contains 'text=...' set the input string to the UTF-8 encoding of that string.
// If args contains 'max=<n>' set the maximum input size to that value.
// If args contains 'dump[=file]' log info to ../encrypt_data.json or the specified file.
var args = process.argv.slice(2);
var minLen = 3;
var maxLen = 100;
var plaintext;
var dumpFile;
var dumpData = [];
var log = function() {};
args.forEach(function(arg) {
  if (arg === 'verbose') {
    log = console.log.bind(console);
  } else if (arg.substring(0, 5) === 'text=') {
    plaintext = arg.substring(5);
  } else if (arg.substring(0, 4) === 'max=') {
    var v = parseInt(arg.substring(4), 10);
    if (!isNaN(v) && v > minLen) {
      maxLen = v;
    }
  } else if (arg === 'dump') {
    dumpFile = '../encrypt_data.json';
  } else if (arg.substring(0, 5) === 'dump=') {
    dumpFile = arg.substring(5);
  }
});

function filterTests(fullList) {
  var filtered = fullList.filter(function(t) {
    return args.some(function(f) {
      var v = typeof t === 'function' ? t.name : t;
      return f === v;
    });
  });
  if (filtered.length > 0) {
    return filtered;
  }
  return fullList;
}

function logbuf(msg, buf) {
  if (typeof buf === 'string') {
    buf = base64.decode(buf);
  }
  log(msg + ': [' + buf.length + ']');
  for (var i = 0; i < buf.length; i += 48) {
    log('    ' + base64.encode(buf.slice(i, i + 48)));
  }
}

function saveDump(data){
  if (dumpFile && data.version) {
    dumpData.push(data);
  }
}

function validate() {
  ['hello', null, 1, NaN, [], {}].forEach(function(v) {
    try {
      ece.encrypt('hello', {});
      throw new Error('should insist on a buffer');
    } catch (e) {
      if (e.toString() != "Error: buffer argument must be a Buffer") {
        throw new Error("encrypt failed to reject " + JSON.stringify(v));
      }
    }
  });
}

function generateInput(len) {
  var input;
  if (plaintext) {
    if (plaintext.length < minLen) {
      throw new Error('Plaintext is too short');
    }
    input = plaintext;
  } else {
    if (typeof len === 'undefined') {
      len = Math.floor((Math.random() * (maxLen - minLen) + minLen));
    }
    input = crypto.randomBytes(Math.max(minLen, Math.min(len, maxLen)));
  }
  logbuf('Input', input);
  return input;
}

function encryptDecrypt(input, encryptParams, decryptParams, keys) {
  // Fill out a default rs.
  encryptParams.rs = encryptParams.rs || (input.length + minLen);
  if (decryptParams.version === 'aes128gcm') {
    delete decryptParams.rs;
  } else {
    decryptParams.rs = decryptParams.rs || encryptParams.rs;
    assert.equal(encryptParams.rs, decryptParams.rs);
  }

  // These should be in agreement.
  assert.equal(encryptParams.version, decryptParams.version);
  assert.equal(encryptParams.authSecret, decryptParams.authSecret);

  // Always fill in the salt so we can log it.
  decryptParams.salt = base64.encode(crypto.randomBytes(16));
  encryptParams.salt = decryptParams.salt;
  logbuf('Salt', encryptParams.salt);

  var encrypted = ece.encrypt(input, encryptParams);
  logbuf('Encrypted', encrypted);
  var decrypted = ece.decrypt(encrypted, decryptParams);
  logbuf('Decrypted', decrypted);
  assert.equal(Buffer.compare(input, decrypted), 0);
  log('----- OK');

  saveDump({
    version: encryptParams.version,
    input: base64.encode(input),
    encrypted: base64.encode(encrypted),
    params: {
      encrypt: encryptParams,
      decrypt: decryptParams,
    },
    keys: keys
  });
}

function useExplicitKey(version) {
  var input = generateInput();
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16))
  };
  logbuf('Key', params.key);
  encryptDecrypt(input, params, params);
}

function authenticationSecret(version) {
  var input = generateInput();
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    authSecret: base64.encode(crypto.randomBytes(16))
  };
  logbuf('Key', params.key);
  logbuf('Context', params.authSecret);
  encryptDecrypt(input, params, params);
}

function exactlyOneRecord(version) {
  var input = generateInput(1);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: input.length + 2 // add exactly the padding
  };
  encryptDecrypt(input, params, params);
}

function detectTruncation(version) {
  var input = generateInput(2);
  var params = {
    version: version,
    key: base64.encode(crypto.randomBytes(16)),
    rs: input.length + 1 // so we get two records
  };
  var headerLen = (version === 'aes128gcm') ? 21 : 0;
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
  var input = generateInput();
  var keyid = base64.encode(crypto.randomBytes(16));
  var key = crypto.randomBytes(16);
  var keymap = {};
  keymap[keyid] = key;
  var params = {
    keyid: keyid,
    keymap: keymap
  };

  encryptDecrypt(input, params, params);
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

  var input = generateInput();
  var encryptParams = {
    version: version,
    authSecret: base64.encode(crypto.randomBytes(16)),
    dh: base64.encode(staticKey.getPublicKey())
  };
  var decryptParams = {
    version: version,
    authSecret: encryptParams.authSecret
  };
  if (version === 'aes128gcm') {
    encryptParams.privateKey = ephemeralKey;
    decryptParams.privateKey = staticKey;
  } else {
    encryptParams.keyid = 'k';
    encryptParams.keymap = { k: ephemeralKey };
    encryptParams.keylabels = { k: 'P-256' };

    decryptParams.dh = base64.encode(ephemeralKey.getPublicKey());
    decryptParams.keyid = 'k';
    decryptParams.keymap = { k: staticKey };
    decryptParams.keylabels = encryptParams.keylabels;
  }


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
  encryptDecrypt(input, encryptParams, decryptParams, keyData);
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
filterTests([ 'aesgcm128', 'aesgcm', 'aes128gcm' ])
  .forEach(function(version) {
    filterTests([ useExplicitKey,
                  authenticationSecret,
                  exactlyOneRecord,
                  detectTruncation,
                  useKeyId,
                  useDH,
                ])
      .forEach(function(test) {
        log(version + ' Test: ' + test.name);
        test(version);
      });
  });
checkExamples();

log('All tests passed.');


if (dumpFile) {
  require('fs').writeFileSync(dumpFile, JSON.stringify(dumpData, undefined, '  '));
}
