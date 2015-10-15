'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 6) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <receiver-private> <sender-public> <salt> <message>');
  process.exit(2);
}

var receiver = crypto.createECDH('prime256v1');
receiver.setPrivateKey(base64.decode(process.argv[2]));
ece.saveKey('keyid', receiver);

var result = ece.decrypt(base64.decode(process.argv[5]), {
  keyid: 'keyid',
  dh: process.argv[3],
  salt: process.argv[4]
});

console.log(base64.encode(result));
console.log(result.toString('utf-8'));
