'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 4) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <key> <message> [JSON args]');
  process.exit(2);
}

var params = {
  version: 'aes128gcm',
  key: process.argv[2]
};

if (process.argv.length > 4) {
  var extra = JSON.parse(process.argv[4]);
  Object.keys(extra).forEach(function(k) {
    params[k] = extra[k];
  });
}

console.log("Params: " + JSON.stringify(params, null, 2));
var result = ece.encrypt(base64.decode(process.argv[3]), params);

console.log("Encrypted Message: " + base64.encode(result));
