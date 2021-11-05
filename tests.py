import unittest
import lext
from lext import lext, hashfuncs


class TestSHA1(unittest.TestCase):
    h = [
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
    ]

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
        """Test SHA1 hexdigest"""
        for data, hash in self.h:
            with self.subTest(data=data):
                self.assertEqual(hashfuncs.get("sha1").hexdigest(data), hash)


class TestSHA256(unittest.TestCase):
    h = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ]

    def test_hexdigest(self):
        """Test SHA256 hexdigest"""
        for data, hash in self.h:
            with self.subTest(data=data):
                self.assertEqual(hashfuncs.get("sha256").hexdigest(data), hash)


class TestSHA224(unittest.TestCase):
    h = [
        (b"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
        (b"a", "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        ),
    ]

    def test_hexdigest(self):
        """Test SHA224 hexdigest"""
        for data, hash in self.h:
            with self.subTest(data=data):
                self.assertEqual(hashfuncs.get("sha224").hexdigest(data), hash)


if __name__ == "__main__":
    unittest.main()
