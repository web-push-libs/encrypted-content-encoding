encrypted-content-encoding
==========================

A simple implementation of the `HTTP encrypted
content-encoding <https://tools.ietf.org/html/rfc8188>`_

Use
---

.. code-block:: python

    import http_ece
    from secrets import token_bytes

    key = token_bytes(16)
    salt = token_bytes(16)
    data = token_bytes(100)

    encrypted = http_ece.encrypt(data, salt=salt, key=key)
    decrypted = http_ece.decrypt(encrypted, salt=salt, key=key)
    assert data == decrypted

This also supports the static-ephemeral ECDH mode.

TODO
----

Provide a streaming API
