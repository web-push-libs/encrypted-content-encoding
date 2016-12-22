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

MAX_BUFFER_SIZE = pow(2, 31) - 1
MIN_BUFFER_SIZE = 3
KEY_LENGTH = 16

# Valid content types (ordered from newest, to most obsolete)
versions = {
    "aes128gcm": {"padding": 2},
    "aesgcm": {"padding": 2},
    "aesgcm128": {"padding": 1}
}


class ECEException(Exception):
    """Exception for ECE encryption functions"""
    def __init__(self, message):
        self.message = message

# TODO: turn this into a class so that we don't grow/stomp keys.


def derive_key(mode, salt=None, key=None, dh=None, keyid=None,
               auth_secret=None, version="aesgcm", **kwargs):
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

    def derive_dh(mode, keyid, dh, version="aesgcm"):

        def length_prefix(key):
            return struct.pack("!H", len(key)) + key

        if keyid is None:
            raise ECEException(u"'keyid' is not specified with 'dh'")
        if keyid not in keys:
            raise ECEException(u"'keyid' doesn't identify a key: " + keyid)
        if mode == "encrypt":
            sender_pub_key = key or keys[keyid].get_pubkey()
            receiver_pub_key = dh
        elif mode == "decrypt":
            sender_pub_key = dh
            receiver_pub_key = key or keys[keyid].get_pubkey()
        else:
            raise ECEException(u"unknown 'mode' specified: " + mode)
        if version == "aes128gcm":
            context = b"WebPush: info\x00" + receiver_pub_key + sender_pub_key
        else:
            label = labels.get(keyid, 'P-256').encode('utf-8')
            context = (label + b"\0" + length_prefix(receiver_pub_key) +
                       length_prefix(sender_pub_key))

        return keys[keyid].get_ecdh_key(dh), context

    # handle the older, ill formatted args.
    pad_size = kwargs.get('padSize', 2)
    auth_secret = kwargs.get('authSecret', auth_secret)
    secret = key

    # handle old cases where version is explicitly None.
    if not version:
        if pad_size == 1:
            version = "aesgcm128"
        else:
            version = "aesgcm"

    if version not in versions:
        raise ECEException(u"invalid version specified")
    if salt is None or len(salt) != 16:
        raise ECEException(u"'salt' must be a 16 octet value")
    if dh is not None:
        (secret, context) = derive_dh(mode=mode, keyid=keyid, dh=dh,
                                      version=version)
    elif keyid in keys:
        if isinstance(keys[keyid], ecc.ECC):
            secret = keys[keyid].get_privkey()
        else:
            secret = keys[keyid]
    if secret is None:
        raise ECEException(u"unable to determine the secret")

    if auth_secret is not None:
        hkdf_auth = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=auth_secret,
            info=build_info(b"auth", b""),
            backend=default_backend()
        )
        secret = hkdf_auth.derive(secret)

    if version == "aesgcm":
        keyinfo = build_info(b"aesgcm", context)
        nonceinfo = build_info(b"nonce", context)
    elif version == "aesgcm128":
        keyinfo = b"Content-Encoding: aesgcm128"
        nonceinfo = b"Content-Encoding: nonce"
    elif version == "aes128gcm":
        keyinfo = b"Content-Encoding: aes128gcm\x00"
        nonceinfo = b"Content-Encoding: nonce\x00"

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


def decrypt(content, salt, key=None, keyid=None, dh=None, rs=4096,
            auth_secret=None, version="aesgcm", **kwargs):
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
        if data[pad_size:pad_size+pad] != (b"\x00" * pad):
            raise ECEException(u"Bad padding")
        data = data[pad_size + pad:]
        return data

    # handle old, malformed args
    pad_size = kwargs.get('padSize', 2)
    auth_secret = kwargs.get('authSecret', auth_secret)

    if version not in versions:
        raise ECEException(u"Invalid version")
    if version == "aes128gcm":
        try:
            content_header = parse_content_header(content)
        except ECEException as ex:
            raise ECEException("Could not parse the content header: " +
                               ex.message)
        salt = content_header['salt']
        keyid = content_header['key_id'] or '' if keyid is None else keyid
        pad_size = 2
        content = content_header['content']

    (key_, nonce_) = derive_key(mode="decrypt", salt=salt,
                                key=key, keyid=keyid, dh=dh,
                                auth_secret=auth_secret,
                                padSize=pad_size,
                                version=version)
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


def encrypt(content, salt=None, key=None, keyid=None, dh=None, rs=4096,
            auth_secret=None, pad_size=2, version="aesgcm", **kwargs):
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
        data = encryptor.update(b"\0\0" + buf)
        data += encryptor.finalize()
        data += encryptor.tag
        return data

    def compose_aes128gcm(salt, content, rs=4096, key_id=""):
        """Compose the header and content of an aes128gcm encrypted
        message body

        :param salt: The sender's salt value
        :type salt: str
        :param content: The encrypted body of the message
        :type content: str
        :param rs: Override for the content length
        :type rs: int
        :param key_id: The optional key_id to use for this message
        :type key_id: str

        """
        if len(salt) != 16:
            raise ECEException("Invalid salt")
        if key_id is None:
            key_id = ''
        if len(key_id) > 255:
            raise ECEException("key_id is too long")
        header = salt
        rs = rs or len(content)
        if rs < MIN_BUFFER_SIZE:
            raise ECEException("Too little content")
        if rs > MAX_BUFFER_SIZE:
            raise ECEException("Too much content")
        header += struct.pack("!L", rs)
        header += struct.pack("!B", len(key_id))
        header += key_id.encode('utf-8')
        return header + content

    # handle the older, ill formatted args.
    pad_size = kwargs.get('padSize', pad_size)
    auth_secret = kwargs.get('authSecret', auth_secret)
    if salt is None:
        salt = os.urandom(16)
        version = "aes128gcm"

    (key_, nonce_) = derive_key(mode="encrypt", salt=salt,
                                key=key, keyid=keyid, dh=dh,
                                auth_secret=auth_secret, padSize=pad_size,
                                version=version)
    if rs <= pad_size:
        raise ECEException(u"Record size too small")
    rs -= pad_size  # account for padding
    
    result = b""
    counter = 0

    # the extra padSize on the loop ensures that we produce a padding only
    # record if the data length is an exact multiple of rs-padSize
    for i in list(range(0, len(content) + pad_size, rs)):
        result += encrypt_record(key_, nonce_, counter, content[i:i + rs])
        counter += 1
    if version == "aes128gcm":
        return compose_aes128gcm(salt, result, rs, key_id=keyid)
    return result
