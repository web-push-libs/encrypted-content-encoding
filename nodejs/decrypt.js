'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');
var ece = require('./ece.js');

if (process.argv.length < 5) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <key> <salt> <message> [JSON args]');
  process.exit(2);
}

var params = {
  key: process.argv[2],
  salt: process.argv[3]
};

if (process.argv.length > 5) {
  var extra = JSON.parse(process.argv[5]);
  Object.keys(extra).forEach(function(k) {
    params[k] = extra[k];
  });
}

console.log("Params: " + JSON.stringify(params, null, 2));
var result = ece.decrypt(base64.decode(process.argv[4]), params);

console.log(base64.encode(result));
console.log(result.toString('utf-8'));
