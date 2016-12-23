import base64
import json
import os
import pyelliptic
import struct
import unittest

from nose.tools import eq_, assert_raises


import http_ece as ece
from http_ece import ECEException


TEST_STRING = b"You know my name, look up the number."
TEST_LEN = len(TEST_STRING)
TEST_VECTORS = os.path.join(os.sep, "..", "encrypt_data.json")[1:]


def log(arg):
    """
    print(arg)
    """
    return


def logbuf(msg, buf):
    """used for debugging test code."""
    """
    if buf is None:
        buf = ''
    log(msg + ': [' + str(len(buf)) + ']')
    for i in list(range(0, len(buf), 48)):
        log('    ' + repr(buf[i:i+48]))
    """
    return


def b64e(arg):
    if arg is None:
        return None
    return base64.urlsafe_b64encode(arg).decode()


def b64d(arg):
    if arg is None:
        return None
    return base64.urlsafe_b64decode(str(arg) + '===='[:len(arg) % 4:])


def rlen():
    return struct.unpack_from("=H", os.urandom(2))[0]


class TestEce(unittest.TestCase):

    def setUp(self):
        self.keymap = {'valid': pyelliptic.ECC(curve="prime256v1")}
        self.keylabels = {'valid': 'P-256'}
        self.m_salt = os.urandom(16)
        self.m_dh = os.urandom(16)

    def tearDown(self):
        self.keymap = None
        self.keylabels = None

    def test_derive_key_no_keyid(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=self.m_salt,
                           key=None,
                           dh=self.m_dh,
                           keyid=None,
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "'keyid' is not specified with 'dh'")

    def test_derive_key_invalid_key(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=self.m_salt,
                           key=None,
                           dh=self.m_dh,
                           keyid="invalid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "'keyid' doesn't identify a key: invalid")

    def test_derive_key_invalid_mode(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('invalid',
                           version='aes128gcm',
                           salt=self.m_salt,
                           key=None,
                           dh=self.m_dh,
                           keyid="valid",
                           keymap=self.keymap,
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "unknown 'mode' specified: invalid")

    """
    def test_derive_key_invalid_label(self):
        ece.keys['invalid'] = ece.keys['valid']
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           salt=self.m_salt,
                           key=None,
                           dh=self.m_dh,
                           keyid="invalid",
                           auth_secret=None,
                           )
        eq_(ex.exception.message, "'keyid' doesn't identify a key label: "
                                  "invalid")
    """

    def test_derive_key_invalid_salt(self):
        with assert_raises(ECEException) as ex:
            ece.derive_key('encrypt',
                           version='aes128gcm',
                           salt=None,
                           key=None,
                           dh=self.m_dh,
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
                           key=None,
                           dh=None,
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
                           key=None,
                           dh=None,
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
                       dh=None,
                       keyid="valid",
                       keymap=self.keymap,
                       auth_secret=None,
                       )

    def test_iv_bad_counter(self):
        with assert_raises(ECEException) as ex:
            ece.iv(os.urandom(8), pow(2, 64)+1)
        eq_(ex.exception.message, "Counter too big")


class TestEceIntegration(unittest.TestCase):

    def setUp(self):
        ece.keys = {}
        ece.labels = {}

    def tearDown(self):
        ece.keys = {}
        ece.labels = {}

    def encrypt_decrypt(self, length, encrypt_params, decrypt_params=None,
                        version=None):
        """Run and encrypt/decrypt cycle on some test data

        :param length: Length of data to fake
        :type length: int
        :param encrypt_params: Dictionary of encryption parameters
        :type encrypt_params: dict
        :param decrypt_params: Optional dictionary of decryption paramseters
        :type decrypt_params: dict
        :param version: Content-Type of the body, formulating encryption
        :type enumerate("aes128gcm", "aesgcm", "aesgcm128"):
        """
        if decrypt_params is None:
            decrypt_params = encrypt_params
        if "key" in encrypt_params:
            logbuf("Key", encrypt_params["key"])
        logbuf("Salt", encrypt_params["salt"])
        if "authSecret" in encrypt_params:
            logbuf("Context", encrypt_params["authSecret"])
        # test_string = os.urandom(min(length, maxLen))
        logbuf("Input", TEST_STRING)
        encrypted = ece.encrypt(TEST_STRING,
                                salt=encrypt_params.get("salt"),
                                key=encrypt_params.get("key"),
                                keyid=encrypt_params.get("keyid"),
                                keymap=decrypt_params.get("keymap"),
                                dh=encrypt_params.get("dh"),
                                rs=encrypt_params.get("rs"),
                                auth_secret=encrypt_params.get("authSecret"),
                                version=version)
        logbuf("Encrypted", encrypted)
        decrypted = ece.decrypt(encrypted,
                                salt=decrypt_params.get("salt"),
                                key=decrypt_params.get("key"),
                                keyid=decrypt_params.get("keyid"),
                                keymap=decrypt_params.get("keymap"),
                                dh=decrypt_params.get("dh"),
                                rs=decrypt_params.get("rs"),
                                auth_secret=decrypt_params.get("authSecret"),
                                version=version)
        logbuf("Decrypted", decrypted)
        eq_(TEST_STRING, decrypted)
        return dict(
            version=version,
            source=TEST_STRING,
            salt=b64e(encrypt_params.get("salt")),
            key=repr(encrypt_params.get(
                "key",
                ece.keys.get(encrypt_params.get('keyid')))),
            dh=b64e(encrypt_params.get("dh")),
            rs=encrypt_params.get("rs", 0),
            auth_secret=b64e(encrypt_params.get("authSecret")),
            encrypted=b64e(encrypted),
        )

    def use_explicit_key(self, version=None):
        salt = None
        if version != "aes128gcm":
            salt = os.urandom(16)
        params = {
            "key": os.urandom(16),
            "salt": salt,
            "rs": rlen() + 1
        }
        self.encrypt_decrypt(rlen() + 1, params, version=version)

    def auth_secret(self, version):
        salt = None
        if version != "aes128gcm":
            salt = os.urandom(16)
        params = {
            "key": os.urandom(16),
            "salt": salt,
            "rs": rlen() + 1,
            "authSecret": os.urandom(10)
        }
        self.encrypt_decrypt(rlen() + 1, params, version=version)

    def exactly_one_record(self, version=None):
        length = min(rlen(), TEST_LEN)
        salt = None
        if version != "aes128gcm":
            salt = os.urandom(16)
        params = {
            "key": os.urandom(16),
            "salt": salt,
            "rs": length + 2
        }
        self.encrypt_decrypt(length, params, version=version)

    def detect_truncation(self, version=None):
        key = os.urandom(16)
        salt = None
        ex_msg = 'Decryption error: InvalidTag()'
        if version != "aes128gcm":
            salt = os.urandom(16)
            ex_msg = 'Message truncated'
        if version == "aesgcm128":
            pad_size = 1
        else:
            pad_size = 2

        rs = len(TEST_STRING) + pad_size
        encrypted = ece.encrypt(TEST_STRING, salt=salt, key=key, rs=rs,
                                version=version)
        with assert_raises(ECEException) as ex:
            ece.decrypt(encrypted[0:rs + 16],
                        salt=salt, key=key,
                        rs=rs, version=version)
        eq_(ex.exception.message, ex_msg)

    def use_key_id(self, version=None):
        key = os.urandom(16)
        keymap = {'k': key }
        salt = None
        if version != "aes128gcm":
            salt = os.urandom(16)
        params = {
            "keyid": 'k',
            "keymap": keymap,
            "salt": salt,
            "rs": rlen() + 1
        }
        self.encrypt_decrypt(rlen(), params, params,
                             version=version)

    def use_dh(self, version=None):
        def is_uncompressed(k):
            b1 = k.get_pubkey()[0:1]
            assert struct.unpack("B", b1)[0] == 4, "is an uncompressed point"

        # the static key is used by the receiver
        static_key = pyelliptic.ECC(curve="prime256v1")
        is_uncompressed(static_key)
        salt = None
        if version != "aes128gcm":
            salt = os.urandom(16)

        log("Receiver private: " + repr(static_key.get_privkey()))
        log("Receiver public: " + repr(static_key.get_pubkey()))

        # the ephemeral key is used by the sender
        ephemeral_key = pyelliptic.ECC(curve="prime256v1")
        is_uncompressed(ephemeral_key)

        log("Sender private: " + repr(ephemeral_key.get_privkey()))
        log("Sender public: " + repr(ephemeral_key.get_pubkey()))

        keymap = {'static': static_key, 'ephemeral': ephemeral_key }

        encrypt_params = {
            "keyid": 'ephemeral',
            "keymap": keymap,
            "dh": static_key.get_pubkey(),
            "salt": salt,
            "rs": rlen() + 1,
        }
        decrypt_params = {
            "keyid": 'static',
            "keymap": keymap,
            "dh": ephemeral_key.get_pubkey(),
            "salt": salt,
            "rs": encrypt_params["rs"],
        }

        self.encrypt_decrypt(rlen(), encrypt_params, decrypt_params,
                             version)

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
            print(mode)
            print(repr(data))
            p = data['params'][mode]
            keyid=p.get('keyid', '')
            if 'keys' in data:
                dh = b64d(data['keys'][remote]['public'])
                key = None
                keymap = {
                    keyid: pyelliptic.ECC(
                        curve='prime256v1',
                        pubkey=b64d(data['keys'][local]['public']),
                        privkey=b64d(data['keys'][local]['private']),
                    )
                }
            else:
                dh = None
                key = b64d(p['key'])
                keymap = {}

            if 'authSecret' in p:
                auth_secret = b64d(p['authSecret'])
            else:
                auth_secret = None
            result = func(
                b64d(data[inp]),
                salt=b64d(p['salt']),
                key=key,
                dh=dh,
                auth_secret=auth_secret,
                keyid=keyid,
                keymap=keymap,
                rs=p.get('rs', 4096),
                version=p['version'],
            )
            eq_(b64d(data[outp]), result)

    def test_decrypt(self):
        self._run('decrypt')

    def test_encrypt(self):
        self._run('encrypt')
