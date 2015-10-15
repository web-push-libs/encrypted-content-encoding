var base64 = require('urlsafe-base64');
var crypto = require('crypto');

var buffer = base64.decode('HH5QdMESn_mjg-BDyY6xrURjmeHmlesP3l7HopOOMAhtcWkH7KNKlxLlkBoligipE3pr6hoCbzdv1IOBErrrphIWIZIkyt7WZybg4o0PudVQaFoL82x2MpashMq2lqmVM6HY_GdSYyANzpeiXA7T6EoicC1Y');
var gcm = crypto.createDecipheriv('id-aes128-GCM', base64.decode('HUV2cCEaSNAX0FWaZgMlzA'), base64.decode('YJ8P9Oy8k5J7TWoW'));
gcm.setAuthTag(buffer.slice(buffer.length - 16));
var data = Buffer.concat([gcm.update(buffer.slice(0, buffer.length - 16)), gcm.final()]);
console.log(base64.encode(data.slice(1)));
