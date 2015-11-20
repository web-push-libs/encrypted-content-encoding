'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 4) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <receiver-public> <message> [auth-secret]');
  process.exit(2);
}

var sender = crypto.createECDH('prime256v1');
sender.generateKeys();
ece.saveKey('keyid', sender, "P-256");

var salt = base64.encode(crypto.randomBytes(16));

var result = ece.encrypt(base64.decode(process.argv[3]), {
  keyid: 'keyid',
  dh: process.argv[2],
  salt: salt,
  authSecret: process.argv[4]
});

console.log("Salt: " + salt);
console.log("Public Key: " + base64.encode(sender.getPublicKey()));
console.log("Encrypted Message: " + base64.encode(result));
