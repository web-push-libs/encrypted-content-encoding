import functools
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from pyelliptic import ecc

keys = {}
labels = {}

MAX_RECORD_SIZE = pow(2, 31) - 1
MIN_RECORD_SIZE = 3
KEY_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16

# Valid content types (ordered from newest, to most obsolete)
versions = {
    "aes128gcm": {"pad": 2},
    "aesgcm": {"pad": 2},
    "aesgcm128": {"pad": 1},
}


class ECEException(Exception):
    """Exception for ECE encryption functions"""
    def __init__(self, message):
        self.message = message

# TODO: turn this into a class so that we don't grow/stomp keys.


def derive_key(mode, version, salt=None, key=None,
               private_key=None, dh=None, auth_secret=None,
               keyid=None, keymap=None, keylabels=None):
    """Derive the encryption key

    :param mode: operational mode (encrypt or decrypt)
    :type mode: enumerate('encrypt', 'decrypt)
    :param salt: encryption salt value
    :type salt: str
    :param key: raw key
    :type key: str
    :param private_key: DH private key
    :type key: object
    :param dh: Diffie Helman public key value
    :type dh: str
    :param keyid: key identifier label
    :type keyid: str
    :param keymap: map of keyids to keys
    :type keymap: map
    :param keylabels: map of keyids to labels
    :type keylabels: map
    :param auth_secret: authorization secret
    :type auth_secret: str
    :param version: Content Type identifier
    :type version: enumerate('aes128gcm', 'aesgcm', 'aesgcm128')

    """
    context = b""
    keyinfo = ""
    nonceinfo = ""

    def build_info(base, info_context):
        return b"Content-Encoding: " + base + b"\0" + info_context

    def derive_dh(mode, version, private_key, dh, label):
        def length_prefix(key):
            return struct.pack("!H", len(key)) + key

        if mode == "encrypt":
            sender_pub_key = private_key.get_pubkey()
            receiver_pub_key = dh
        else:
            sender_pub_key = dh
            receiver_pub_key = private_key.get_pubkey()

        if version == "aes128gcm":
            context = b"WebPush: info\x00" + receiver_pub_key + sender_pub_key
        else:
            context = (label + b"\0" + length_prefix(receiver_pub_key) +
                       length_prefix(sender_pub_key))

        return private_key.get_ecdh_key(dh), context

    if version not in versions:
        raise ECEException(u"Invalid version")
    if mode not in ['encrypt', 'decrypt']:
        raise ECEException(u"unknown 'mode' specified: " + mode)
    if salt is None or len(salt) != KEY_LENGTH:
        raise ECEException(u"'salt' must be a 16 octet value")
    if dh is not None or private_key is not None:
        # We need a key in the keymap unless we're decrypting 'aes128gcm', where
        # we can get the key from the keyid.
        if private_key is None:
            raise ECEException(u"DH requires a private_key")
        label = keylabels.get(keyid, 'P-256').encode('utf-8')

        (secret, context) = derive_dh(mode=mode, version=version,
                                      private_key=private_key, dh=dh,
                                      label=label)
    elif keyid in keymap:
        secret = keymap[keyid]
    else:
        secret = key

    if secret is None:
        raise ECEException(u"unable to determine the secret")

    if version == "aesgcm":
        keyinfo = build_info(b"aesgcm", context)
        nonceinfo = build_info(b"nonce", context)
    elif version == "aesgcm128":
        keyinfo = b"Content-Encoding: aesgcm128"
        nonceinfo = b"Content-Encoding: nonce"
    elif version == "aes128gcm":
        keyinfo = b"Content-Encoding: aes128gcm\x00"
        nonceinfo = b"Content-Encoding: nonce\x00"
        if dh is None:
            # Only mix the authentication secret when using DH for aes128gcm
            auth_secret = None

    if auth_secret is not None:
        if version == "aes128gcm":
            info = context
        else:
            info = build_info(b'auth', b'')
        hkdf_auth = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=auth_secret,
            info=info,
            backend=default_backend()
        )
        secret = hkdf_auth.derive(secret)

    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=keyinfo,
        backend=default_backend()
    )
    hkdf_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=NONCE_LENGTH,
        salt=salt,
        info=nonceinfo,
        backend=default_backend()
    )
    return hkdf_key.derive(secret), hkdf_nonce.derive(secret)


def iv(base, counter):
    """Generate an initialization vector.

    """
    if (counter >> 64) != 0:
        raise ECEException(u"Counter too big")
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)


def decrypt(content, salt=None, key=None,
            private_key=None, dh=None, auth_secret=None,
            keyid=None, keymap=None, keylabels=None,
            rs=4096, version="aesgcm", **kwargs):
    """
    Decrypt a data block

    :param content: Data to be decrypted
    :type content: str
    :param salt: Encryption salt
    :type salt: str
    :param key: local public key
    :type key: str
    :param private_key: DH private key
    :type key: object
    :param keyid: Internal key identifier for private key info
    :type keyid: str
    :param dh: Remote Diffie Hellman sequence
    :type dh: str
    :param rs: Record size
    :type rs: int
    :param auth_secret: Authorization secret
    :type auth_secret: str
    :param version: ECE Method version
    :type version: enumerate('aes128gcm', 'aesgcm', 'aesgcm128')
    :return: Decrypted message content
    :rtype str

    """
    def parse_content_header(content):
        """Parse an aes128gcm content body and extract the header values.

        :param content: The encrypted body of the message
        :type content: str

        """
        id_len = struct.unpack("!B", content[20:21])[0]
        return {
            "salt": content[:16],
            "rs": struct.unpack("!L", content[16:20])[0],
            "keyid": content[21:21 + id_len],
            "content": content[21 + id_len:],
        }

    def decrypt_record(key, nonce, counter, content):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter), tag=content[-TAG_LENGTH:]),
            backend=default_backend()
        ).decryptor()
        data = decryptor.update(content[:-TAG_LENGTH]) + decryptor.finalize()
        pad = functools.reduce(
            lambda x, y: x << 8 | y, struct.unpack(
                "!" + ("B" * pad_size), data[0:pad_size])
        )
        if pad_size + pad > len(data) or \
           data[pad_size:pad_size+pad] != (b"\x00" * pad):
            raise ECEException(u"Bad padding")
        data = data[pad_size + pad:]
        return data

    if version not in versions:
        raise ECEException(u"Invalid version")

    # handle old, malformed args
    pad_size = kwargs.get('padSize', versions[version]['pad'])
    auth_secret = kwargs.get('authSecret', auth_secret)
    if keymap is None:
        keymap = keys
    if keylabels is None:
        keylabels = labels
    if keyid is not None and keyid in keymap and isinstance(keymap[keyid], ecc.ECC):
        private_key = keymap[keyid]

    if version == "aes128gcm":
        try:
            content_header = parse_content_header(content)
        except:
            raise ECEException("Could not parse the content header")
        salt = content_header['salt']
        rs = content_header['rs']
        keyid = content_header['keyid']
        if private_key is not None and not dh:
            dh = keyid
        else:
            keyid = keyid.decode('utf-8')
        content = content_header['content']
        overhead = pad_size + 16
    else:
        overhead = pad_size

    (key_, nonce_) = derive_key(mode="decrypt", version=version,
                                salt=salt, key=key,
                                private_key=private_key, dh=dh,
                                auth_secret=auth_secret,
                                keyid=keyid, keymap=keymap, keylabels=keylabels)
    if rs <= overhead:
        raise ECEException(u"Record size too small")
    if version != "aes128gcm":
        chunk = rs + 16  # account for tags in old versions
    else:
        chunk = rs
    if len(content) % chunk == 0:
        raise ECEException(u"Message truncated")

    result = b''
    counter = 0
    try:
        for i in list(range(0, len(content), chunk)):
            result += decrypt_record(key_, nonce_, counter, content[i:i + chunk])
            counter += 1
    except InvalidTag as ex:
        raise ECEException("Decryption error: {}".format(repr(ex)))
    return result


def encrypt(content, salt=None, key=None,
            private_key=None, dh=None, auth_secret=None,
            keyid=None, keymap=None, keylabels=None,
            rs=4096, version="aesgcm", **kwargs):
    """
    Encrypt a data block

    :param content: block of data to encrypt
    :type content: str
    :param salt: Encryption salt
    :type salt: str
    :param key: Encryption key data
    :type key: str
    :param private_key: DH private key
    :type key: object
    :param keyid: Internal key identifier for private key info
    :type keyid: str
    :param dh: Remote Diffie Hellman sequence
    :type dh: str
    :param rs: Record size
    :type rs: int
    :param auth_secret: Authorization secret
    :type auth_secret: str
    :param version: ECE Method version
    :type version: enumerate('aes128gcm', 'aesgcm', 'aesgcm128')
    :return: Encrypted message content
    :rtype str

    """
    def encrypt_record(key, nonce, counter, buf):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter)),
            backend=default_backend()
        ).encryptor()

        data = encryptor.update((b"\0" * pad_size) + buf)
        data += encryptor.finalize()
        data += encryptor.tag
        return data

    def compose_aes128gcm(salt, content, rs, keyid):
        """Compose the header and content of an aes128gcm encrypted
        message body

        :param salt: The sender's salt value
        :type salt: str
        :param content: The encrypted body of the message
        :type content: str
        :param rs: Override for the content length
        :type rs: int
        :param keyid: The keyid to use for this message
        :type keyid: str

        """
        if len(keyid) > 255:
            raise ECEException("keyid is too long")
        header = salt
        if rs > MAX_RECORD_SIZE:
            raise ECEException("Too much content")
        header += struct.pack("!L", rs)
        header += struct.pack("!B", len(keyid))
        header += keyid
        return header + content

    if version not in versions:
        raise ECEException(u"Invalid version")

    # handle the older, ill formatted args.
    pad_size = kwargs.get('padSize', versions[version]['pad'])
    auth_secret = kwargs.get('authSecret', auth_secret)
    if keymap is None:
        keymap = keys
    if keylabels is None:
        keylabels = labels
    if salt is None:
        salt = os.urandom(16)
        version = "aes128gcm"
    if keyid is not None and keyid in keymap and isinstance(keymap[keyid], ecc.ECC):
        private_key = keymap[keyid]

    (key_, nonce_) = derive_key(mode="encrypt", version=version,
                                salt=salt, key=key,
                                private_key=private_key, dh=dh,
                                auth_secret=auth_secret,
                                keyid=keyid, keymap=keymap, keylabels=keylabels)
    overhead = pad_size
    if version == 'aes128gcm':
        overhead += 16
    if rs <= pad_size:
        raise ECEException(u"Record size too small")
    chunk_size = rs - overhead

    result = b""
    counter = 0

    # the extra one on the loop ensures that we produce a padding only
    # record if the data length is an exact multiple of the chunk size
    for i in list(range(0, len(content) + 1, chunk_size)):
        result += encrypt_record(key_, nonce_, counter,
                                 content[i:i + chunk_size])
        counter += 1
    if version == "aes128gcm":
        if keyid is None and private_key is not None:
            kid = private_key.get_pubkey()
        else:
            kid = (keyid or '').encode('utf-8')
        return compose_aes128gcm(salt, result, rs, keyid=kid)
    return result
