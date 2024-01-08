'use strict';

var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 5) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <auth-secret> <receiver-public> <message> [JSON args]');
  process.exit(2);
}


var params = {
  version: 'aes128gcm',
  authSecret: process.argv[2],
  dh: process.argv[3]
};

if (process.argv.length > 5) {
  var extra = JSON.parse(process.argv[5]);
  Object.keys(extra).forEach(function(k) {
    params[k] = extra[k];
  });
}

var sender = crypto.createECDH('prime256v1');
sender.generateKeys();
if (params.senderPrivate) {
  sender.setPrivateKey(Buffer.from(params.senderPrivate, 'base64url'));
} else {
  params.senderPrivate = sender.getPrivateKey().toString('base64url');
}
if (params.senderPublic) {
  sender.setPublicKey(Buffer.from(params.senderPublic, 'base64url'));
} else {
  params.senderPublic = sender.getPublicKey().toString('base64url');
}
params.privateKey = sender;

console.log("Params: " + JSON.stringify(params, null, 2));
var result = ece.encrypt(Buffer.from(process.argv[4], 'base64url'), params);

console.log("Encrypted Message: " + result.toString('base64url'));
