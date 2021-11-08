import unittest
from lext import lext, hashfuncs
import hashlib
import os
from random import randint


class MAC:
    """Simulate a server that authenticate a message (MAC)"""

    def __init__(self, method):
        self.method = method
        self.key_len = randint(0, 64)
        self.key = os.urandom(self.key_len)
        self.message = b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo"
        self.sig = self.gen_mac(self.message)

    def gen_mac(self, message):
        return hashlib.new(self.method, self.key + message).hexdigest()

    def is_valid(self, message, signature):
        """Return true if signature is valid"""
        return self.gen_mac(message) == signature


def get_hashlib_ref_sig(data, method):
    ref = hashlib.new(method)
    ref.update(data)
    return ref.hexdigest()


class TestSHA1(unittest.TestCase):
    def test_length_extension_attack(self):
        """Test SHA1 length extension attack (key length is known)"""
        m = MAC("sha1")
        inj, sig = lext(
            data=m.message,
            inject=b"&waffle=liege",
            signature=m.sig,
            secret_length=m.key_len,
            method="sha1",
        )

        self.assertTrue(m.is_valid(inj, sig))

    def test_hexdigest(self):
        """Test SHA1 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0, 9999))

            with self.subTest(data=data):
                self.assertEqual(
                    hashfuncs.new("sha1").hexdigest(data),
                    get_hashlib_ref_sig(data, "sha1"),
                )


class TestSHA256(unittest.TestCase):
    def test_length_extension_attack(self):
        """Test SHA256 length extension attack (key length is known)"""
        m = MAC("sha256")
        inj, sig = lext(
            data=m.message,
            inject=b"&waffle=liege",
            signature=m.sig,
            secret_length=m.key_len,
            method="sha256",
        )

        self.assertTrue(m.is_valid(inj, sig))

    def test_hexdigest(self):
        """Test SHA256 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0, 9999))

            with self.subTest(data=data):
                self.assertEqual(
                    hashfuncs.new("sha256").hexdigest(data),
                    get_hashlib_ref_sig(data, "sha256"),
                )

class TestSHA512(unittest.TestCase):
    def test_length_extension_attack(self):
        """Test SHA512 length extension attack (key length is known)"""
        m = MAC("sha512")
        inj, sig = lext(
            data=m.message,
            inject=b"&waffle=liege",
            signature=m.sig,
            secret_length=m.key_len,
            method="sha512",
        )

        self.assertTrue(m.is_valid(inj, sig))

    def test_hexdigest(self):
        """Test SHA512 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0, 9999))

            with self.subTest(data=data):
                self.assertEqual(
                    hashfuncs.new("sha512").hexdigest(data),
                    get_hashlib_ref_sig(data, "sha512"),
                )


class TestMD5(unittest.TestCase):
    def test_length_extension_attack(self):
        """Test MD5 length extension attack (key length is known)"""
        m = MAC("md5")
        inj, sig = lext(
            data=m.message,
            inject=b"&waffle=liege",
            signature=m.sig,
            secret_length=m.key_len,
            method="md5",
        )

        self.assertTrue(m.is_valid(inj, sig))

    def test_hexdigest(self):
        """Test MD5 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0, 9999))

            with self.subTest(data=data):
                self.assertEqual(
                    hashfuncs.new("md5").hexdigest(data),
                    get_hashlib_ref_sig(data, "md5"),
                )


if __name__ == "__main__":
    unittest.main()
