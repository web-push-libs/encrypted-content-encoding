import http_ece as ece
import base64
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
        print arg

def rlen():
    return struct.unpack_from('=H', os.urandom(2))[0]

def encryptDecrypt(length, encryptParams, decryptParams=None):
    if decryptParams is None:
        decryptParams = encryptParams
    log('Salt: ' + base64.urlsafe_b64encode(encryptParams['salt']))
    input = os.urandom(min(length, maxLen))
    # input = new Buffer('I am the walrus')
    log('Input: ' + base64.urlsafe_b64encode(input))
    encrypted = ece.encrypt(input, salt=encryptParams.get('salt'), key=encryptParams.get('key'), keyid=encryptParams.get('keyid'), dh=encryptParams.get('dh'), rs=encryptParams.get('rs'))
    log('Encrypted: ' + base64.urlsafe_b64encode(encrypted))
    decrypted = ece.decrypt(encrypted, salt=decryptParams.get('salt'), key=decryptParams.get('key'), keyid=decryptParams.get('keyid'), dh=decryptParams.get('dh'), rs=decryptParams.get('rs'))
    log('Decrypted: ' + base64.urlsafe_b64encode(decrypted))
    assert input == decrypted
    log("----- OK");


def useExplicitKey():
    params = {
        'key': os.urandom(16),
        'salt': os.urandom(16),
        'rs': rlen() + 1
    }
    log('Key: ' + base64.urlsafe_b64encode(params['key']))
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
    keyid = base64.urlsafe_b64encode(os.urandom(16))
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
        b1 = k.get_pubkey()[0]
        assert struct.unpack("B", b1)[0] == 4, 'is an uncompressed point'

    # the static key is used by the receiver
    staticKey = pyelliptic.ECC(curve='prime256v1')
    isUncompressed(staticKey)
    staticKeyId = base64.urlsafe_b64encode(staticKey.get_pubkey()[1:])
    ece.keys[staticKeyId] = staticKey

    log('Receiver private: ' + base64.urlsafe_b64encode(staticKey.get_privkey()))
    log('Receiver public: ' + base64.urlsafe_b64encode(staticKey.get_pubkey()))

    # the ephemeral key is used by the sender
    ephemeralKey = pyelliptic.ECC(curve='prime256v1')
    isUncompressed(ephemeralKey)
    ephemeralKeyId = base64.urlsafe_b64encode(ephemeralKey.get_pubkey()[1:])
    ece.keys[ephemeralKeyId] = ephemeralKey

    log('Sender private: ' + base64.urlsafe_b64encode(ephemeralKey.get_privkey()))
    log('Sender public: ' + base64.urlsafe_b64encode(ephemeralKey.get_pubkey()))

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
    for i in range(0,count):
        useExplicitKey()
        exactlyOneRecord()
        detectTruncation()
        useKeyId()
        useDH()

    print 'All tests passed.'
