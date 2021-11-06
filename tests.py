import unittest
from lext import lext, hashfuncs
import hashlib
import os
from random import randint


class TestSHA1(unittest.TestCase):
    def test_length_extension_attack(self):
        """Test SHA1 length extension attack"""
        inj, sig = lext(
            data=b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo",
            inject=b"&waffle=liege",
            signature="6d5f807e23db210bc254a28be2d6759a0f5f5d99",
            secret_length=14,
            method="sha1",
        )

        self.assertEqual(
            inj,
            b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02(&waffle=liege",
        )
        self.assertEqual(sig, "0e41270260895979317fff3898ab85668953aaa2")

    def test_hexdigest(self):
        """Test SHA1 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0,9999))
            ref = hashlib.sha1()
            ref.update(data)
            ref_sig = ref.hexdigest()

            with self.subTest(data=data):
                self.assertEqual(hashfuncs.new("sha1").hexdigest(data), ref_sig)


class TestSHA256(unittest.TestCase):
    def test_hexdigest(self):
        """Test SHA256 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0,9999))
            ref = hashlib.sha256()
            ref.update(data)
            ref_sig = ref.hexdigest()

            with self.subTest(data=data):
                self.assertEqual(hashfuncs.new("sha256").hexdigest(data), ref_sig)


class TestSHA224(unittest.TestCase):
    def test_hexdigest(self):
        """Test SHA224 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0,9999))
            ref = hashlib.sha224()
            ref.update(data)
            ref_sig = ref.hexdigest()

            with self.subTest(data=data):
                self.assertEqual(hashfuncs.new("sha224").hexdigest(data), ref_sig)


class TestMD5(unittest.TestCase):
    def test_hexdigest(self):
        """Test MD5 hexdigest against hashlib as reference"""
        for _ in range(10):
            data = os.urandom(randint(0,9999))
            ref = hashlib.md5()
            ref.update(data)
            ref_sig = ref.hexdigest()

            with self.subTest(data=data):
                self.assertEqual(hashfuncs.new("md5").hexdigest(data), ref_sig)


if __name__ == "__main__":
    unittest.main()
