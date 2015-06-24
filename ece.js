'use strict';

var crypto = require('crypto');
var base64 = require('urlsafe-base64');

var savedKeys = {};
var AES_GCM = 'id-aes128-GCM';
var TAG_LENGTH = 16;
var KEY_LENGTH = 16;
var NONCE_LENGTH = 12;

function HMAC_hash(key, input) {
  var hmac = crypto.createHmac('sha256', key);
  hmac.update(input);
  return hmac.digest();
}

/* HKDF as defined in RFC5869, using SHA-256 */
function HKDF_extract(salt, ikm) {
  return HMAC_hash(salt, ikm);
}

function HKDF_expand(prk, info, l) {
  var output = new Buffer(0);
  var T = new Buffer(0);
  info = new Buffer(info, 'ascii');
  var counter = 0;
  var cbuf = new Buffer(1);
  while (output.length < l) {
    cbuf.writeUIntBE(++counter, 0, 1);
    T = HMAC_hash(prk, Buffer.concat([T, info, cbuf]));
    output = Buffer.concat([output, T]);
  }

  return output.slice(0, l);
}

function extractKey(params) {
  var secret;
  if (params.key) {
    secret = base64.decode(params.key);
    if (secret.length !== KEY_LENGTH) {
      throw new Error('An explicit key must be ' + KEY_LENGTH + ' bytes');
    }
  } else if (params.dh) { // receiver/decrypt
    var share = base64.decode(params.dh);
    var key = savedKeys[params.keyid];
    secret = key.computeSecret(share);
  } else if (params.keyid) {
    secret = savedKeys[params.keyid];
  }
  if (!secret) {
    throw new Error('Unable to determine key');
  }
  if (!params.salt) {
    throw new Error('A salt is required');
  }

  var salt = base64.decode(params.salt);
  if (salt.length !== KEY_LENGTH) {
    throw new Error('The salt parameter must be ' + KEY_LENGTH + ' bytes');
  }
  var prk = HKDF_extract(salt, secret);
  return {
    key: HKDF_expand(prk, 'Content-Encoding: aesgcm128', KEY_LENGTH),
    nonce: HKDF_expand(prk, 'Content-Encoding: nonce', NONCE_LENGTH)
  };
}

function determineRecordSize(params) {
  var rs = parseInt(params.rs, 10);
  if (isNaN(rs)) {
    return 4096;
  }
  if (rs <= 1) {
    throw new Error('The rs parameter has to be greater than 1');
  }
  return rs;
}

function generateNonce(base, counter) {
  var nonce = new Buffer(base);
  var m = nonce.readUIntBE(nonce.length - 6, 6);
  var x = ((m ^ counter) & 0xffffff) +
      ((((m / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000);
  nonce.writeUIntBE(x, nonce.length - 6, 6);
  return nonce;
}

function decryptRecord(key, counter, buffer) {
  var nonce = generateNonce(key.nonce, counter);
  var gcm = crypto.createDecipheriv(AES_GCM, key.key, nonce);
  gcm.setAuthTag(buffer.slice(buffer.length - TAG_LENGTH));
  var data = gcm.update(buffer.slice(0, buffer.length - TAG_LENGTH));
  data = Buffer.concat([data, gcm.final()]);
  var pad = data.readUInt8(0);
  if (pad + 1 > data.length) {
    throw new Error('padding exceeds block size');
  }
  var padCheck = new Buffer(pad);
  padCheck.fill(0);
  if (padCheck.compare(data.slice(1, 1 + pad)) !== 0) {
    throw new Error('invalid padding');
  }
  return data.slice(1 + pad);
}

// TODO: this really should use the node streams stuff

/**
 * Decrypt some bytes.  This uses the parameters to determine the key and block
 * size, which are described in the draft.  Binary values are base64url encoded.
 * For an explicit key that key is used.  For a keyid on its own, the value of
 * the key is a buffer that is stored with saveKey().  For ECDH, the p256-dh
 * parameter identifies the public share of the recipient and the keyid is
 * anECDH key pair (created by crypto.createECDH()) that is stored using
 * saveKey().
 */
function decrypt(buffer, params) {
  var key = extractKey(params);
  var rs = determineRecordSize(params);
  var start = 0;
  var result = new Buffer(0);

  for (var i = 0; start < buffer.length; ++i) {
    var end = start + rs + TAG_LENGTH;
    if (end === buffer.length) {
      throw new Error('Truncated payload');
    }
    end = Math.min(end, buffer.length);
    if (end - start <= TAG_LENGTH) {
      throw new Error('Invalid block: too small at ' + i);
    }
    var block = decryptRecord(key, i, buffer.slice(start, end));
    result = Buffer.concat([result, block]);
    start = end;
  }
  return result;
}

function encryptRecord(key, counter, buffer, pad) {
  pad = pad || 0;
  var nonce = generateNonce(key.nonce, counter);
  var gcm = crypto.createCipheriv(AES_GCM, key.key, nonce);
  var padding = new Buffer(pad + 1);
  padding.writeUIntBE(pad, 0, 1);
  var epadding = gcm.update(padding);
  var ebuffer = gcm.update(buffer);
  gcm.final();
  var tag = gcm.getAuthTag();
  if (tag.length !== TAG_LENGTH) {
    throw new Error('invalid tag generated');
  }
  return Buffer.concat([epadding, ebuffer, tag]);
}

/**
 * Encrypt some bytes.  This uses the parameters to determine the key and block
 * size, which are described in the draft.  Note that for encryption, the
 * p256-dh parameter identifies the public share of the recipient and the keyid
 * identifies a local ECDH key pair (created by crypto.createECDH()).
 */
function encrypt(buffer, params) {
  var key = extractKey(params);
  var rs = determineRecordSize(params);
  var start = 0;
  var result = new Buffer(0);

  for (var i = 0; start <= buffer.length; ++i) {
    var end = Math.min(start + rs - 1, buffer.length);
    var block = encryptRecord(key, i, buffer.slice(start, end));
    result = Buffer.concat([result, block]);
    start += rs - 1;
  }
  return result;
}

/**
 * This function saves a key under the provided identifier.  This is used to
 * save the keys that are used to decrypt and encrypt blobs that are identified
 * by a 'keyid'.
 */
function saveKey(id, key) {
  savedKeys[id] = key;
}

module.exports = {
  decrypt: decrypt,
  encrypt: encrypt,
  saveKey: saveKey
};
