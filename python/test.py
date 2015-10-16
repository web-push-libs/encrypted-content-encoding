import http_ece as ece
import os
import struct
import sys
import pyelliptic

count = 20
if len(sys.argv) > 1:
    count = int(sys.argv[1])
maxLen = 100
if len(sys.argv) > 2:
    maxLen = int(sys.argv[2])

def log(arg):
    if (count == 1):
        print(arg)
def b64e(arg):
    import base64
    return base64.urlsafe_b64encode(arg).decode()

def rlen():
    return struct.unpack_from('=H', os.urandom(2))[0]

def encryptDecrypt(length, encryptParams, decryptParams=None):
    if decryptParams is None:
        decryptParams = encryptParams
    log('Salt: ' + b64e(encryptParams['salt']))
    input = os.urandom(min(length, maxLen))
    # input = new Buffer('I am the walrus')
    log('Input: ' + b64e(input))
    encrypted = ece.encrypt(input, salt=encryptParams.get('salt'),
                            key=encryptParams.get('key'),
                            keyid=encryptParams.get('keyid'),
                            dh=encryptParams.get('dh'),
                            rs=encryptParams.get('rs'))
    log('Encrypted: ' + b64e(encrypted))
    decrypted = ece.decrypt(encrypted, salt=decryptParams.get('salt'),
                            key=decryptParams.get('key'),
                            keyid=decryptParams.get('keyid'),
                            dh=decryptParams.get('dh'),
                            rs=decryptParams.get('rs'))
    log('Decrypted: ' + b64e(decrypted))
    assert input == decrypted
    log("----- OK");


def useExplicitKey():
    params = {
        'key': os.urandom(16),
        'salt': os.urandom(16),
        'rs': rlen() + 1
    }
    log('Key: ' + b64e(params['key']))
    encryptDecrypt(rlen() + 1, params)


def exactlyOneRecord():
    length = min(rlen(), maxLen)
    params = {
        'key': os.urandom(16),
        'salt': os.urandom(16),
        'rs': length + 1
    }
    encryptDecrypt(length, params)


def detectTruncation():
    length = min(rlen(), maxLen)
    key = os.urandom(16)
    salt = os.urandom(16)
    rs = length + 1
    input = os.urandom(min(length, maxLen))
    encrypted = ece.encrypt(input, salt=salt, key=key, rs=rs)
    ok = False
    try:
        ece.decrypt(encrypted[0:length + 1 + 16], salt=salt, key=key, rs=rs)
    except Exception as e:
        log('Decryption error: %s' % e.args)
        log('----- OK')
        ok = True

    if not ok:
        raise Exception('Decryption succeeded, but should not have')



def useKeyId():
    keyid = b64e(os.urandom(16))
    key = os.urandom(16)
    ece.keys[keyid] = key
    params = {
        'keyid': keyid,
        'salt': os.urandom(16),
        'rs': rlen() + 1
    }
    encryptDecrypt(rlen(), params)


# This is a complete crap-shoot: the pre-eminent crypto library in python
# doesn't even do ECDH; so this doesn't actually work
def useDH():
    def isUncompressed(k):
        b1 = k.get_pubkey()[0:1]
        assert struct.unpack("B", b1)[0] == 4, 'is an uncompressed point'

    # the static key is used by the receiver
    staticKey = pyelliptic.ECC(curve='prime256v1')
    isUncompressed(staticKey)
    staticKeyId = b64e(staticKey.get_pubkey()[1:])
    ece.keys[staticKeyId] = staticKey

    log('Receiver private: ' + b64e(staticKey.get_privkey()))
    log('Receiver public: ' + b64e(staticKey.get_pubkey()))

    # the ephemeral key is used by the sender
    ephemeralKey = pyelliptic.ECC(curve='prime256v1')
    isUncompressed(ephemeralKey)
    ephemeralKeyId = b64e(ephemeralKey.get_pubkey()[1:])
    ece.keys[ephemeralKeyId] = ephemeralKey

    log('Sender private: ' + b64e(ephemeralKey.get_privkey()))
    log('Sender public: ' + b64e(ephemeralKey.get_pubkey()))

    encryptParams = {
        'keyid': ephemeralKeyId,
        'dh': staticKey.get_pubkey(),
        'salt': os.urandom(16),
        'rs': rlen() + 1
    }
    decryptParams = {
        'keyid': staticKeyId,
        'dh': ephemeralKey.get_pubkey(),
        'salt': encryptParams['salt'],
        'rs': encryptParams['rs']
    }

    encryptDecrypt(rlen(), encryptParams, decryptParams)

if __name__ == '__main__':
    for i in list(range(0,count)):
        useExplicitKey()
        exactlyOneRecord()
        detectTruncation()
        useKeyId()
        useDH()

    print('All tests passed.')
