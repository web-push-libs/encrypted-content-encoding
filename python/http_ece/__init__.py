import os, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import pyelliptic

keys = {}

def deriveKey(salt, key=None, dh=None, keyid=None):
    if salt is None or len(salt) != 16:
        raise Exception(u"'salt' must be a 16 octet value")

    if key is not None:
        secret = key
    elif dh is not None:
        if keyid is None:
            raise Exception(u"'keyid' is not specified with 'dh'")
        if keys[keyid] is None:
            raise Exception(u"'keyid' doesn't identify a key")
        secret = keys[keyid].get_ecdh_key(dh)
    elif keyid is not None:
        secret = keys[keyid]
    if secret is None:
        raise Exception(u"unable to determine the secret")

    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=b"Content-Encoding: aesgcm128",
        backend=default_backend()
    )
    hkdf_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=12,
        salt=salt,
        info=b"Content-Encoding: nonce",
        backend=default_backend()
    )
    return (hkdf_key.derive(secret), hkdf_nonce.derive(secret))

def iv(base, counter):
    if (counter >> 64) != 0:
        raise Exception(u"Counter too big")
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)

def decrypt(buffer, salt, key=None, keyid=None, dh=None, rs=4096):
    def decryptRecord(key, nonce, counter, buffer):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter), tag=buffer[-16:]),
            backend=default_backend()
        ).decryptor()
        data = decryptor.update(buffer[:-16]) + decryptor.finalize()
        (pad,) = struct.unpack("!B", data[0:1]);
        if data[1:1+pad] != (b"\x00" * pad):
            raise Exception(u"Bad padding")
        data = data[1+pad:]
        return data

    (key_, nonce_) = deriveKey(salt=salt, key=key, keyid=keyid, dh=dh)
    if rs < 2:
        raise Exception(u"Record size too small")
    rs += 16 # account for tags
    if len(buffer) % rs == 0:
        raise Exception(u"Message truncated")

    result = b""
    counter = 0
    for i in list(range(0, len(buffer), rs)):
        result += decryptRecord(key_, nonce_, counter, buffer[i:i+rs])
        ++counter
    return result

def encrypt(buffer, salt, key=None, keyid=None, dh=None, rs=4096):
    def encryptRecord(key, nonce, counter, buffer):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter)),
            backend=default_backend()
        ).encryptor()
        data = encryptor.update(b"\x00" + buffer) + encryptor.finalize()
        data += encryptor.tag
        return data

    (key_, nonce_) = deriveKey(salt=salt, key=key, keyid=keyid, dh=dh)
    if rs < 2:
        raise Exception(u"Record size too small")
    rs -= 1 # account for padding

    result = b""
    counter = 0
    # the extra one ensures that we produce a padding only record if the data
    # length is an exact multiple of rs-1
    for i in list(range(0, len(buffer) + 1, rs)):
        result += encryptRecord(key_, nonce_, counter, buffer[i:i+rs])
        ++counter
    return result

if __name__ == "__main__":
    import base64

    salt=base64.urlsafe_b64decode("mUFsKgrmI-i_-HowjX_2XA==")
    key=base64.urlsafe_b64decode("F-hAEGCm7KIGUiSdS4GGtA==")
    m = base64.urlsafe_b64decode("iEPbDBuohQLznv45IlaF1eLRCeu6aWfsq-pDP7OnzgH4A0x5lyIEVAfM39RgeLekW1VgZWIFL_WvuveEhaHj0-iEvxDHw_apYGFYWEY6KmMhXgWPmFZ-2wAMnDsQ-DDVbZHsXw==")
    rs=3300
    print ("message", len(m),  base64.urlsafe_b64encode(m))
    e = encrypt(m, salt=salt, key=key, rs=rs)
    print ("encrypted", len(e), base64.urlsafe_b64encode(e))
    d = decrypt(e, salt=salt, key=key, rs=rs)
    print ("decrypted", len(d), base64.urlsafe_b64encode(d))
    print (m == d)

    salt = os.urandom(16)
    print ("salt", base64.urlsafe_b64encode(salt))
    keys["receiver"] = pyelliptic.ECC(curve="prime256v1")
    print ("receiver", base64.urlsafe_b64encode(keys["receiver"].get_pubkey()),
           base64.urlsafe_b64encode(keys["receiver"].get_privkey()))
    keys["sender"] = pyelliptic.ECC(curve="prime256v1")
    print ("sender", base64.urlsafe_b64encode(keys["sender"].get_pubkey()),
           base64.urlsafe_b64encode(keys["sender"].get_privkey()))

    e = encrypt(m, salt=salt, keyid="sender", dh=keys["receiver"].get_pubkey(), rs=rs)
    print ("encrypted", len(e), base64.urlsafe_b64encode(e))
    d = decrypt(e, salt=salt, keyid="receiver", dh=keys["sender"].get_pubkey(), rs=rs)
    print ("decrypted", len(d), base64.urlsafe_b64encode(d))
    print (m == d)
