encrypted-content-encoding
==========================

A simple implementation of the `HTTP encrypted
content-encoding <https://tools.ietf.org/html/draft-nottingham-http-encryption-encoding>`_

Use
---

.. code-block:: python

    import http_ece
    import os, base64

    key = os.urandom(16)
    salt = os.urandom(16)
    data = os.urandom(100)

    encrypted = http_ece.encrypt(data, salt=salt, key=key)
    decrypted = http_ece.decrypt(encrypted, salt=salt, key=key)
    assert data == decrypted

This also supports the static-ephemeral ECDH mode.

TODO
----

Provide a streaming API
