# encrypted-content-encoding

A simple implementation of the [HTTP encrypted
content-encoding](https://tools.ietf.org/html/rfc8188)

# Use

```js
import assert from 'node:assert';
import crypto from 'node:crypto';
import * as ece from 'http_ece';

const parameters = {
  key: crypto.randomBytes(16).toString('base64url'),
  salt: crypto.randomBytes(16).toString('base64url'),
};

const encrypted = ece.encrypt(data, parameters);
const decrypted = ece.decrypt(encrypted, parameters);

assert.equal(decrypted.compare(data), 0);
```

This also supports the static-ephemeral ECDH mode.  The source explains how.

# TODO

Use the node streams API instead of the legacy APIs.
