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


def derive_key(mode, version, salt=None, key=None, dh=None, auth_secret=None,
               keyid=None, keymap=None, keylabels=None):
    """Derive the encryption key

    :param mode: operational mode (encrypt or decrypt)
    :type mode: enumerate('encrypt', 'decrypt)
    :param salt: encryption salt value
    :type salt: str
    :param key: local public key
    :type key: str
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

    def derive_dh(mode, version, dh, keyid, keymap, keylabels):
        def length_prefix(key):
            return struct.pack("!H", len(key)) + key

        if keyid is None:
            raise ECEException(u"'keyid' is not specified with 'dh'")
        if keyid not in keymap:
            raise ECEException(u"'keyid' doesn't identify a key: " + keyid)
        if mode == "encrypt":
            sender_pub_key = key or keymap[keyid].get_pubkey()
            receiver_pub_key = dh
        else:
            sender_pub_key = dh
            receiver_pub_key = key or keymap[keyid].get_pubkey()
        if version == "aes128gcm":
            context = b"WebPush: info\x00" + receiver_pub_key + sender_pub_key
        else:
            label = keylabels.get(keyid, 'P-256').encode('utf-8')
            context = (label + b"\0" + length_prefix(receiver_pub_key) +
                       length_prefix(sender_pub_key))

        return keymap[keyid].get_ecdh_key(dh), context

    if version not in versions:
        raise ECEException(u"Invalid version")
    if mode not in ['encrypt', 'decrypt']:
        raise ECEException(u"unknown 'mode' specified: " + mode)
    if salt is None or len(salt) != 16:
        raise ECEException(u"'salt' must be a 16 octet value")
    if dh is not None:
        (secret, context) = derive_dh(mode=mode, version=version, dh=dh,
                                      keyid=keyid, keymap=keymap,
                                      keylabels=keylabels)
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
        length=16,
        salt=salt,
        info=keyinfo,
        backend=default_backend()
    )
    hkdf_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=12,
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


def decrypt(content, salt=None, key=None, dh=None, auth_secret=None,
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
            "id_len": id_len,
            "key_id": content[21:21 + id_len],
            "content": content[21 + id_len:],
        }

    def decrypt_record(key, nonce, counter, content):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter), tag=content[-16:]),
            backend=default_backend()
        ).decryptor()
        data = decryptor.update(content[:-16]) + decryptor.finalize()
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

    if version == "aes128gcm":
        try:
            content_header = parse_content_header(content)
        except:
            raise ECEException("Could not parse the content header")
        salt = content_header['salt']
        keyid = content_header['key_id'] or '' if keyid is None else keyid
        content = content_header['content']
        rs = content_header['rs']

    (key_, nonce_) = derive_key(mode="decrypt", version=version,
                                salt=salt, key=key,
                                dh=dh, auth_secret=auth_secret,
                                keyid=keyid, keymap=keymap, keylabels=keylabels)
    if rs <= pad_size:
        raise ECEException(u"Record size too small")
    rs += 16  # account for tags
    if len(content) % rs == 0:
        raise ECEException(u"Message truncated")

    result = b""
    counter = 0
    try:
        for i in list(range(0, len(content), rs)):
            result += decrypt_record(key_, nonce_, counter, content[i:i + rs])
            counter += 1
    except InvalidTag as ex:
        raise ECEException("Decryption error: {}".format(repr(ex)))
    return result


def encrypt(content, salt=None, key=None, dh=None, auth_secret=None,
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

    (key_, nonce_) = derive_key(mode="encrypt", version=version,
                                salt=salt, key=key,
                                dh=dh, auth_secret=auth_secret,
                                keyid=keyid, keymap=keymap, keylabels=keylabels)
    if rs <= pad_size:
        raise ECEException(u"Record size too small")
    chunk_size = rs - pad_size

    result = b""
    counter = 0

    # the extra one on the loop ensures that we produce a padding only
    # record if the data length is an exact multiple of the chunk size
    for i in list(range(0, len(content) + 1, chunk_size)):
        result += encrypt_record(key_, nonce_, counter,
                                 content[i:i + chunk_size])
        counter += 1
    if version == "aes128gcm":
        if keyid == '' and keyid in keymap:
            kid = keymap[keyid].get_pubkey()
        else:
            kid = (keyid or '').encode('utf-8')
        return compose_aes128gcm(salt, result, rs, keyid=kid)
    return result
