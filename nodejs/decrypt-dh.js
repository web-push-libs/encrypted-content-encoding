'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 6) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <auth-secret> <receiver-private> <receiver-public> <message> [JSON args]');
  process.exit(2);
}

var receiver = crypto.createECDH('prime256v1');
// node crypto is finicky about accessing the public key
// 1. it can't generate the public key from the private key
// 2. it barfs when you try to access the public key, even after you set it
// This hack squelches the complaints at the cost of a few wasted cycles
receiver.generateKeys();
receiver.setPublicKey(Buffer.from(process.argv[4], 'base64url'));
receiver.setPrivateKey(Buffer.from(process.argv[3], 'base64url'));
var keymap = {};

var params = {
  version: 'aes128gcm',
  authSecret: process.argv[2],
  privateKey: receiver
};

if (process.argv.length > 7) {
  var extra = JSON.parse(process.argv[7]);
  Object.keys(extra).forEach(function(k) {
    params[k] = extra[k];
  });
}
keymap[params.keyid] = receiver;

console.log("Params: " + JSON.stringify(params, null, 2));
var result = ece.decrypt(Buffer.from(process.argv[5], 'base64url'), params);

console.log(result.toString('base64url'));
console.log(result.toString('utf-8'));
