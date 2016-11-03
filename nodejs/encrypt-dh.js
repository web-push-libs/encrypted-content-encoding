'use strict';

var base64 = require('urlsafe-base64');
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
  sender.setPrivateKey(base64.decode(params.senderPrivate));
} else {
  params.senderPrivate = base64.encode(sender.getPrivateKey());
}
if (params.senderPublic) {
  sender.setPublicKey(base64.decode(params.senderPublic));
} else {
  params.senderPublic = base64.encode(sender.getPublicKey());
}
params.privateKey = sender;

console.log("Params: " + JSON.stringify(params, null, 2));
var result = ece.encrypt(base64.decode(process.argv[4]), params);

console.log("Encrypted Message: " + base64.encode(result));
