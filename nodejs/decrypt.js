import crypto from 'node:crypto';
import * as ece from './ece.js';

if (process.argv.length < 4) {
  console.warn('Usage: ' + process.argv.slice(0, 2).join(' ') +
               ' <key> <message> [JSON args]');
  process.exit(2);
}

const params = {
  version: 'aes128gcm',
  key: process.argv[2]
};

if (process.argv.length > 4) {
  const extra = JSON.parse(process.argv[4]);
  Object.keys(extra).forEach(function(k) {
    params[k] = extra[k];
  });
}

console.log("Params: " + JSON.stringify(params, null, 2));
const result = ece.decrypt(Buffer.from(process.argv[3], 'base64url'), params);

console.log(result.toString('base64url'));
console.log(result.toString('utf-8'));
