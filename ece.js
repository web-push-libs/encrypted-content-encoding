'use strict';

var crypto = require('crypto');
var base64 = require('urlsafe-base64');

var savedKeys = {};
var AES_GCM = 'id-aes128-GCM';
var TAG_LENGTH = 16;

function HMAC_hash(secret, data) {
  var hmac = crypto.createHmac('sha256', secret);
  hmac.update(data);
  return hmac.digest();
}

function tlsPRF(secret, label, seed, bytes) {
  seed = Buffer.concat([new Buffer(label, 'ascii'), seed]);
  var a = seed;
  var output = new Buffer(0);
  while (output.length < bytes) {
    a = HMAC_hash(secret, a);
    var stage = HMAC_hash(secret, Buffer.concat([a, seed]));
    output = Buffer.concat([output, stage]);
  }
  return output.slice(0, bytes);
}

function deriveKey(params) {
  var secret;
  if (params.key) {
    secret = base64.decode(params.key);
  } else if (params.ecdh) { // receiver/decrypt
    var share = base64.decode(params.ecdh);
    var key = savedKeys[params.keyid];
    secret = key.computeSecret(share);
  } else if (params.keyid) {
    secret = savedKeys[params.keyid];
  }
  if (!secret) {
    throw new Error('Unable to determine key');
  }
  if (!params.nonce) {
    throw new Error('A nonce is required');
  }

  var nonce = base64.decode(params.nonce);
  return tlsPRF(secret, "encrypted Content-Encoding", nonce, 16);
}

function determineRecordSize(params) {
  var rs = parseInt(params.rs, 10);
  if (isNaN(rs)) {
    return 4096;
  }
  return rs;
}

var aad_;
var context_ = new Buffer('Content-Encoding: aesgcm-128', 'ascii');
function generateAAD(counter) {
  if (!aad_) {
    aad_ = new Buffer(context_.length + 9); // one zero byte, 64-bit counter
    context_.copy(aad_, 0);
    aad_.writeUInt8(0, context_.length);
    aad_.writeUInt32BE(0, context_.length + 1);
  }
  aad_.writeUInt32BE(counter, context_.length + 5);
  return aad_;
}

var iv_;
function generateIV(counter) {
  if (!iv_) {
    iv_ = new Buffer(12);
    iv_.fill(0);
  }
  iv_.writeUInt32BE(counter, iv_.length - 4);
  return iv_;
}

function decryptBlock(key, counter, buffer) {
  var iv = generateIV(counter);
  var gcm = crypto.createDecipheriv(AES_GCM, key, iv);
  gcm.setAAD(generateAAD(counter));
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

// TODO: this really should use the node streams stuff, but I'm more interested
// in working code for now.

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
  var key = deriveKey(params);
  var rs = determineRecordSize(params);
  var start = 0;
  var result = new Buffer(0);

  for (var i = 0; start < buffer.length; ++i) {
    var end = Math.min(start + rs + TAG_LENGTH, buffer.length);
    if (end - start <= TAG_LENGTH) {
      throw new Error('Invalid block: too small at ' + i);
    }
    var block = decryptBlock(key, i, buffer.slice(start, end));
    result = Buffer.concat([result, block]);
    start = end;
  }
  return result;
}

function encryptBlock(key, counter, buffer, pad) {
  pad = pad || 0;
  var iv = generateIV(counter);
  var gcm = crypto.createCipheriv(AES_GCM, key, iv);
  gcm.setAAD(generateAAD(counter));
  var padding = new Buffer(pad + 1);
  padding.writeUInt8(pad, 0);
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
  var key = deriveKey(params);
  var rs = determineRecordSize(params);
  var start = 0;
  var result = new Buffer(0);

  for (var i = 0; start < buffer.length; ++i) {
    var end = Math.min(start + rs - 1, buffer.length);
    var block = encryptBlock(key, i, buffer.slice(start, end));
    result = Buffer.concat([result, block]);
    start = end;
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
