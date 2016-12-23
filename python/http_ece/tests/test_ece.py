import base64
import json
import os
import pyelliptic
import struct
import unittest

from nose.tools import eq_, assert_raises


import http_ece as ece
from http_ece import ECEException


TEST_VECTORS = os.path.join(os.sep, "..", "encrypt_data.json")[1:]


def logmsg(arg):
    """
    print(arg)
    """
    return


def logbuf(msg, buf):
    """used for debugging test code."""
    if buf is None:
        buf = b''
    logmsg(msg + ': [' + str(len(buf)) + ']')
    for i in list(range(0, len(buf), 48)):
        logmsg('    ' + repr(buf[i:i+48]))
    return


def b64e(arg):
    if arg is None:
        return None
    return base64.urlsafe_b64encode(arg).decode()


def b64d(arg):
    if arg is None:
        return None
    return base64.urlsafe_b64decode(str(arg) + '===='[:len(arg) % 4:])


class TestEce(unittest.TestCase):

    def setUp(self):
        self.keymap = {'valid': pyelliptic.ECC(curve="prime256v1")}
        self.keylabels = {'valid': 'P-256'}
        self.m_key = os.urandom(16)
        self.m_salt = os.urandom(16)

    def tearDown(self):
        self.keymap = None
        self.keylabels = None

    def test_derive_key_no_keyid_dh(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=self.m_salt,
                           dh='bogus',
                           keyid=None,
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "DH requires a private_key")

    def test_derive_key_invalid_keyid_dh(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aesgcm',
                           salt=self.m_salt,
                           dh='bogus',
                           keyid="invalid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "DH requires a private_key")

    def test_derive_key_invalid_mode(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('invalid',
                           version='aes128gcm',
                           salt=self.m_salt,
                           key=self.m_key,
                           keyid="valid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "unknown 'mode' specified: invalid")

    def test_derive_key_invalid_salt(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=None,
                           key=self.m_key,
                           keyid="valid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "'salt' must be a 16 octet value")

    def test_derive_key_invalid_version(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='invalid',
                           salt=self.m_salt,
                           keyid="valid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "Invalid version")

    def test_derive_key_no_secret(self):
        self.keymap['valid'] = None
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=self.m_salt,
                           keyid="valid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "unable to determine the secret")

    def test_derive_key_keyid_from_keys(self):
        self.keymap['valid'] = os.urandom(16)
        ece.derive_key('encrypt',
                       version='aes128gcm',
                       salt=self.m_salt,
                       key=None,
                       keyid="valid",
                       keymap=self.keymap,
                       auth_secret=None,
                       )

    def test_iv_bad_counter(self):
        with assert_raises(ECEException) as ex:
            ece.iv(os.urandom(8), pow(2, 64)+1)
        eq_(ex.exception.message, "Counter too big")


class TestEceChecking(unittest.TestCase):

    def setUp(self):
        self.m_key = os.urandom(16)
        self.m_input = os.urandom(5)
        # This header is specific to the padding tests, but can be used elsewhere
        self.m_header = b'\xaa\xd2\x05}3S\xb7\xff7\xbd\xe4*\xe1\xd5\x0f\xda'
        self.m_header += struct.pack('!L', 4096) + b'\0'

    def test_encrypt_small_rs(self):
        with assert_raises(ECEException) as ex:
            ece.encrypt(
                self.m_input,
                version='aes128gcm',
                key=self.m_key,
                rs=2,
            )
        eq_(ex.exception.message, "Record size too small")

    def test_decrypt_small_rs(self):
        header = os.urandom(16) + struct.pack('!L', 2) + b'\0'
        with assert_raises(ECEException) as ex:
            ece.decrypt(
                header + self.m_input,
                version='aes128gcm',
                key=self.m_key,
                rs=2,
            )
        eq_(ex.exception.message, "Record size too small")

    def test_encrypt_bad_version(self):
        with assert_raises(ECEException) as ex:
            ece.encrypt(
                self.m_input,
                version='bogus',
                key=self.m_key,
            )
        eq_(ex.exception.message, "Invalid version")

    def test_decrypt_bad_version(self):
        with assert_raises(ECEException) as ex:
            ece.decrypt(
                self.m_input,
                version='bogus',
                key=self.m_key,
            )
        eq_(ex.exception.message, "Invalid version")

    def test_decrypt_bad_header(self):
        with assert_raises(ECEException) as ex:
            ece.decrypt(
                os.urandom(4),
                version='aes128gcm',
                key=self.m_key,
            )
        eq_(ex.exception.message, "Could not parse the content header")

    def test_encrypt_long_keyid(self):
        with assert_raises(ECEException) as ex:
            ece.encrypt(
                self.m_input,
                version='aes128gcm',
                key=self.m_key,
                keyid=b64e(os.urandom(192)), # 256 bytes
            )
        eq_(ex.exception.message, "keyid is too long")

    def test_overlong_padding(self):
        with assert_raises(ECEException) as ex:
            ece.decrypt(
                self.m_header + b'\xbb\xc1\xb9ev\x0b\xf0E\xd1u\x11\xac\x82\xae\x96\x96\x98{l\x13\xe2C\xf0',
                version='aes128gcm',
                key=b'd\xc7\x0ed\xa7%U\x14Q\xf2\x08\xdf\xba\xa0\xb9r',
                keyid=b64e(os.urandom(192)), # 256 bytes
            )
        eq_(ex.exception.message, "Bad padding")

    def test_nonzero_padding(self):
        with assert_raises(ECEException) as ex:
            ece.decrypt(
                self.m_header + b'\xbb\xc6\xb1\x1dF:~\x0f\x07+\xbe\xaaD\xe0\xd6.K\xe5\xf9]%\xe3\x86q\xe0~',
                version='aes128gcm',
                key=b'd\xc7\x0ed\xa7%U\x14Q\xf2\x08\xdf\xba\xa0\xb9r',
                keyid=b64e(os.urandom(192)), # 256 bytes
            )
        eq_(ex.exception.message, "Bad padding")


class TestEceIntegration(unittest.TestCase):

    def setUp(self):
        ece.keys = {}
        ece.labels = {}

    def tearDown(self):
        ece.keys = {}
        ece.labels = {}

    def _rsoverhead(self, version):
        if version == 'aesgcm128':
            return 1;
        if version == 'aesgcm':
            return 2;
        return 18;

    def _generate_input(self, minLen=0):
        length = struct.unpack('!B', os.urandom(1))[0] + minLen
        return os.urandom(length);

    def encrypt_decrypt(self, input, encrypt_params, decrypt_params=None,
                        version=None):
        """Run and encrypt/decrypt cycle on some test data

        :param input: data for input
        :type length: bytearray
        :param encrypt_params: Dictionary of encryption parameters
        :type encrypt_params: dict
        :param decrypt_params: Optional dictionary of decryption paramseters
        :type decrypt_params: dict
        :param version: Content-Type of the body, formulating encryption
        :type enumerate("aes128gcm", "aesgcm", "aesgcm128"):
        """
        if decrypt_params is None:
            decrypt_params = encrypt_params
        logbuf("Input", input)
        if "key" in encrypt_params:
            logbuf("Key", encrypt_params["key"])
        if version != "aes128gcm":
            salt = os.urandom(16)
            decrypt_rs_default = 4096
        else:
            salt = None
            decrypt_rs_default = None
        logbuf("Salt", salt)
        if "auth_secret" in encrypt_params:
            logbuf("Auth Secret", encrypt_params["auth_secret"])
        encrypted = ece.encrypt(input,
                                salt=salt,
                                key=encrypt_params.get("key"),
                                keyid=encrypt_params.get("keyid"),
                                keymap=decrypt_params.get("keymap"),
                                dh=encrypt_params.get("dh"),
                                private_key=encrypt_params.get("private_key"),
                                auth_secret=encrypt_params.get("auth_secret"),
                                rs=encrypt_params.get("rs", 4096),
                                version=version)
        logbuf("Encrypted", encrypted)
        decrypted = ece.decrypt(encrypted,
                                salt=salt,
                                key=decrypt_params.get("key"),
                                keyid=decrypt_params.get("keyid"),
                                keymap=decrypt_params.get("keymap"),
                                dh=decrypt_params.get("dh"),
                                private_key=decrypt_params.get("private_key"),
                                auth_secret=decrypt_params.get("auth_secret"),
                                rs=decrypt_params.get("rs", decrypt_rs_default),
                                version=version)
        logbuf("Decrypted", decrypted)
        eq_(input, decrypted)
        return dict(
            version=version,
            source=input,
            salt=b64e(encrypt_params.get("salt")),
            key=repr(encrypt_params.get(
                "key",
                ece.keys.get(encrypt_params.get('keyid')))),
            dh=b64e(encrypt_params.get("dh")),
            rs=encrypt_params.get("rs", 0),
            auth_secret=b64e(encrypt_params.get("auth_secret")),
            encrypted=b64e(encrypted),
        )

    def use_explicit_key(self, version=None):
        params = {
            "key": os.urandom(16),
        }
        self.encrypt_decrypt(self._generate_input(), params, version=version)

    def auth_secret(self, version):
        params = {
            "key": os.urandom(16),
            "auth_secret": os.urandom(16)
        }
        self.encrypt_decrypt(self._generate_input(), params, version=version)

    def exactly_one_record(self, version=None):
        input = self._generate_input(1)
        params = {
            "key": os.urandom(16),
            "rs": len(input) + self._rsoverhead(version)
        }
        self.encrypt_decrypt(input, params, version=version)

    def detect_truncation(self, version):
        input = self._generate_input(2)
        key = os.urandom(16)
        if version != "aes128gcm":
            salt = os.urandom(16)
        else:
            salt = None

        rs = len(input) + self._rsoverhead(version) - 1
        encrypted = ece.encrypt(input, salt=salt, key=key, rs=rs,
                                version=version)
        if version == 'aes128gcm':
            chunk = encrypted[0:21+rs]
        else:
            chunk = encrypted[0:rs+16]
        with assert_raises(ECEException) as ex:
            ece.decrypt(chunk, salt=salt, key=key, rs=rs, version=version)
        eq_(ex.exception.message, "Message truncated")

    def use_key_id(self, version):
        key = os.urandom(16)
        keymap = {'k': key }
        encrypt_params = {
            "keyid": 'k',
            "keymap": keymap,
        }
        # aes128gcm encodes the keyid
        if version != 'aes128gcm':
            decrypt_id = encrypt_params['keyid']
        else:
            decrypt_id = None
        decrypt_params = {
            "keyid": decrypt_id,
            "keymap": keymap,
        }
        self.encrypt_decrypt(self._generate_input(), encrypt_params,
                             decrypt_params, version=version)

    def use_dh(self, version):
        def is_uncompressed(k):
            b1 = k.get_pubkey()[0:1]
            assert struct.unpack("B", b1)[0] == 4, "is an uncompressed point"

        # the static key is used by the receiver
        static_key = pyelliptic.ECC(curve="prime256v1")
        is_uncompressed(static_key)

        logbuf("Receiver private", static_key.get_privkey())
        logbuf("Receiver public", static_key.get_pubkey())

        # the ephemeral key is used by the sender
        ephemeral_key = pyelliptic.ECC(curve="prime256v1")
        is_uncompressed(ephemeral_key)

        logbuf("Sender private", ephemeral_key.get_privkey())
        logbuf("Sender public", ephemeral_key.get_pubkey())

        auth_secret = os.urandom(16)

        if version != "aes128gcm":
            decrypt_dh = ephemeral_key.get_pubkey()
        else:
            decrypt_dh = None

        encrypt_params = {
            "private_key": ephemeral_key,
            "dh": static_key.get_pubkey(),
            "auth_secret": auth_secret,
        }
        decrypt_params = {
            "private_key": static_key,
            "dh": decrypt_dh,
            "auth_secret": auth_secret,
        }

        self.encrypt_decrypt(self._generate_input(), encrypt_params,
                             decrypt_params, version)

    def test_types(self):
        for ver in ["aes128gcm", "aesgcm", "aesgcm128"]:
            for f in (
                    self.use_dh,
                    self.use_explicit_key,
                    self.auth_secret,
                    self.exactly_one_record,
                    self.detect_truncation,
                    self.use_key_id,
                    ):
                ece.keys = {}
                ece.labels = {}
                f(version=ver)


class TestNode(unittest.TestCase):
    """Testing using data from the node.js version.
    """
    def setUp(self):
        if not os.path.exists(TEST_VECTORS):
            self.skipTest("No %s file found" % TEST_VECTORS)
        f = open(TEST_VECTORS, 'r')
        self.legacy_data = json.loads(f.read())
        f.close()

    def _run(self, mode):
        if mode == 'encrypt':
            func = ece.encrypt
            local = 'sender'
            remote = 'receiver'
            inp = 'input'
            outp = 'encrypted'
        else:
            func = ece.decrypt
            local = 'receiver'
            remote = 'sender'
            inp = 'encrypted'
            outp = 'input'

        for data in self.legacy_data:
            print(repr(data))
            p = data['params'][mode]
            if 'keys' in data:
                key = None
                private_key = pyelliptic.ECC(
                    curve='prime256v1',
                    pubkey=b64d(data['keys'][local]['public']),
                    privkey=b64d(data['keys'][local]['private']),
                )
            else:
                key = b64d(p['key'])
                private_key = None

            if 'authSecret' in p:
                auth_secret = b64d(p['authSecret'])
            else:
                auth_secret = None
            if 'dh' in p:
                dh = b64d(p['dh'])
            else:
                dh = None

            result = func(
                b64d(data[inp]),
                salt=b64d(p['salt']),
                key=key,
                dh=dh,
                auth_secret=auth_secret,
                keyid=p.get('keyid'),
                private_key=private_key,
                rs=p.get('rs', 4096),
                version=p['version'],
            )
            eq_(b64d(data[outp]), result)

    def test_decrypt(self):
        self._run('decrypt')

    def test_encrypt(self):
        self._run('encrypt')
