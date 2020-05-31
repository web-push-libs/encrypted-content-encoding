'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');
var base64 = require('urlsafe-base64');
var assert = require('assert');

function usage() {
  console.log('Usage: node test.js [args]');
  console.log('  <version> - test only the specified version(s)');
  console.log('    Supported: [aes128gcm,aesgcm]');
  console.log('  <test function> - test only the specified function(s)');
  console.log('  "verbose" enable logging for tests (export ECE_KEYLOG=1 for more)');
  console.log('  "text=..." sets the input string');
  console.log('  "max=<n>" sets the maximum input size');
  console.log('  "dump[=file]" log info to ../encrypt_data.json or the specified file');
}
var args = process.argv.slice(2);
var minLen = 1;
var maxLen = 100;
var plaintext;
var dumpFile;
var dumpData = [];
var log = function() {};
args.forEach(function(arg) {
  if (arg === 'verbose') {
    log = console.log.bind(console);
  } else if (arg.substring(0, 5) === 'text=') {
    plaintext = Buffer.from(arg.substring(5), 'utf8');
  } else if (arg.substring(0, 4) === 'max=') {
    var v = parseInt(arg.substring(4), 10);
    if (!isNaN(v) && v > minLen) {
      maxLen = v;
    }
  } else if (arg === 'dump') {
    dumpFile = '../encrypt_data.json';
  } else if (arg.substring(0, 5) === 'dump=') {
    dumpFile = arg.substring(5);
  } else if (arg.charAt(0) === '-') {
    usage();
    process.exit(2);
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

function reallySaveDump(data){
  if (dumpFile && data.version) {
    function dumpFix(d) {
      var r = {};
      Object.keys(d).forEach(function(k) {
        if (Buffer.isBuffer(d[k])) {
          r[k] = base64.encode(d[k]);
        } else if (d[k] instanceof Object) {
          r[k] = dumpFix(d[k]);
        } else {
          r[k] = d[k];
        }
      });
      return r;
    }

    dumpData.push(dumpFix(data));
  }
}
var saveDump = reallySaveDump;

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

function generateInput(min) {
  var input;
  min = Math.max(minLen, min || 0);
  if (plaintext) {
    if (plaintext.length < min) {
      throw new Error('Plaintext is too short');
    }
    input = plaintext;
  } else {
    var len = Math.floor((Math.random() * (maxLen - min) + min));
    input = crypto.randomBytes(len);
  }
  logbuf('Input', input);
  return input;
}

function rsoverhead(version) {
  if (version === 'aesgcm') {
    return 2;
  }
  return 18;
}

function encryptDecrypt(input, encryptParams, decryptParams, keys) {
  // Fill out a default rs.
  if (!encryptParams.rs) {
    encryptParams.rs = input.length + rsoverhead(encryptParams.version) + 1;
  }
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
  decryptParams.salt = crypto.randomBytes(16);
  encryptParams.salt = decryptParams.salt;
  logbuf('Salt', encryptParams.salt);

  var encrypted = ece.encrypt(input, encryptParams);
  logbuf('Encrypted', encrypted);
  var decrypted = ece.decrypt(encrypted, decryptParams);
  logbuf('Decrypted', decrypted);
  assert.equal(Buffer.compare(input, decrypted), 0);

  saveDump({
    version: encryptParams.version,
    input: input,
    encrypted: encrypted,
    params: {
      encrypt: encryptParams,
      decrypt: decryptParams
    },
    keys: keys
  });
}

function useExplicitKey(version) {
  var input = generateInput();
  var params = {
    version: version,
    key: crypto.randomBytes(16)
  };
  logbuf('Key', params.key);
  encryptDecrypt(input, params, params);
}

function authenticationSecret(version) {
  var input = generateInput();
  var params = {
    version: version,
    key: crypto.randomBytes(16),
    authSecret: crypto.randomBytes(16)
  };
  logbuf('Key', params.key);
  logbuf('Context', params.authSecret);
  encryptDecrypt(input, params, params);
}

function exactlyOneRecord(version) {
  var input = generateInput(1);
  var params = {
    version: version,
    key: crypto.randomBytes(16),
    rs: input.length + rsoverhead(version)
  };
  encryptDecrypt(input, params, params);
}

// If rs only allows one octet of data in each record AND padding is requested,
// then we need to ensure that padding is added without infinitely looping.
function padTinyRecord(version) {
  var input = generateInput(1);
  var params = {
    version: version,
    key: crypto.randomBytes(16),
    rs: rsoverhead(version) + 1,
    pad: 2
  };
  encryptDecrypt(input, params, params);
}

// The earlier versions had a limit to how much padding they could include in
// each record, which means that they could fail to encrypt if too much padding
// was requested with a large record size.
function tooMuchPadding(version) {
  if (version === 'aes128gcm') {
    return;
  }
  var padSize = rsoverhead(version);
  var rs = Math.pow(256, padSize) + padSize + 1;
  var input = generateInput(1);
  var params = {
    version: version,
    key: crypto.randomBytes(16),
    rs: rs,
    pad: rs
  };
  var ok = false;
  try {
    ece.encrypt(input, params);
  } catch (e) {
    log('----- OK: ' + e);
    ok = true;
  }
  if (!ok) {
    throw new Error('Encryption succeeded, but should not have');
  }
}


function detectTruncation(version) {
  if (version === 'aes128gcm') {
    return;
  }
  var input = generateInput(2);
  var params = {
    version: version,
    key: crypto.randomBytes(16),
    rs: input.length + rsoverhead(version) - 1
  };
  var headerLen = (version === 'aes128gcm') ? 21 : 0;
  var encrypted = ece.encrypt(input, params);
  var chunkLen = headerLen + params.rs;
  if (version != 'aes128gcm') {
    chunkLen += 16;
  }
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
    authSecret: crypto.randomBytes(16),
    dh: staticKey.getPublicKey()
  };
  var decryptParams = {
    version: version,
    authSecret: encryptParams.authSecret
  };
  encryptParams.privateKey = ephemeralKey;
  decryptParams.privateKey = staticKey;
  if (version !== 'aes128gcm') {
    encryptParams.keylabel = 'P-256';

    decryptParams.dh = ephemeralKey.getPublicKey();
    decryptParams.keylabel = 'P-256';
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
function checkExamples(version) {
  [
    {
      args: {
        version: 'aes128gcm',
        key: base64.decode('yqdlZ-tYemfogSmv7Ws5PQ'),
        keyid: '',
        salt: base64.decode('I1BsxtFttlv3u_Oo94xnmw'),
        rs: 4096
      },
      plaintext: Buffer.from('I am the walrus'),
      ciphertext: base64.decode('I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAV' +
                                'ub2qFgBEuQKRapoZu-IxkIva3MEB1PD-' +
                                'ly8Thjg'),
    },
    {
      args: {
        version: 'aes128gcm',
        key: base64.decode('BO3ZVPxUlnLORbVGMpbT1Q'),
        keyid: 'a1',
        salt: base64.decode('uNCkWiNYzKTnBN9ji3-qWA'),
        rs: 25,
        pad: 1
      },
      plaintext: Buffer.from('I am the walrus'),
      ciphertext: base64.decode('uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHO' +
                                'G8chz_gnvgOqdGYovxyjuqRyJFjEDyoF' +
                                '1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_' +
                                'uA')
    }
  ].filter(function(v) {
    return v.args.version === version;
  }).forEach(function (v, i) {
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

function useCustomCallback(version) {
  const customCallback = (keyId) => {
    let keys = [
      {
        keyId: '123456',
        key: '1928375791029'
      },
      {
        keyId: '999',
        key: '9999999999'
      }
    ]
    return keys.find(x => { return x.keyId === keyId.toString() }).key
  }

  let input = generateInput()
  var parameters = {
    keyid: '123456',
  };
  log('Testing custom function')

  var encrypted = ece.encrypt(input, parameters, customCallback);
  logbuf('encrypted', encrypted)

  var decrypted = ece.decrypt(encrypted, parameters, customCallback);
  logbuf('decrypted', decrypted)

  assert.equal(Buffer.compare(decrypted, input), 0)
}

validate();
filterTests([ 'aesgcm', 'aes128gcm' ])
  .forEach(function(version) {
    filterTests([ useExplicitKey,
                  authenticationSecret,
                  exactlyOneRecord,
                  padTinyRecord,
                  detectTruncation,
                  useDH,
                  checkExamples,
                  useCustomCallback
                ])
      .forEach(function(test) {
        log(version + ' Test: ' + test.name);
        saveDump = data => {
          data.test = test.name + ' ' + version;
          reallySaveDump(data);
        };
        test(version);
        log('----- OK');
      });
  });

log('All tests passed.');

if (dumpFile) {
  require('fs').writeFileSync(dumpFile, JSON.stringify(dumpData, undefined, '  '));
}
