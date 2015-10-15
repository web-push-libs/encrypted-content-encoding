'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 5) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <key> <salt> <message>');
  process.exit(2);
}

var result = ece.encrypt(base64.decode(process.argv[4]), {
  key: process.argv[2],
  salt: process.argv[3]
});

console.log(base64.encode(result));
console.log(result.toString('utf-8'));
