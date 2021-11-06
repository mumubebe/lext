import struct
from . import constants


def rotl(num, shift):
    """Rotate left"""
    return ((num << shift) | (num >> (32 - shift))) & 0xFFFFFFFF


def rotr(num, shift):
    """Rotate right"""
    return ((num >> shift) | (num << (32 - shift))) & 0xFFFFFFFF


def pad(data, extra_length=0, byteorder="big"):
    """Pad message, with the ability to forge"""
    ml = len(data) + extra_length

    padlen = (55 - ml) % 64

    ml_bits = ml * 8

    return (
        data
        + (0x80).to_bytes(1, byteorder=byteorder)
        + (0x00).to_bytes(padlen, byteorder=byteorder)
        + (ml_bits).to_bytes(8, byteorder=byteorder)
    )


class LengthExtender:
    """Methods for SHA-classes"""

    @property
    def extra_length(self):
        return self._extra_length

    @extra_length.setter
    def extra_length(self, value):
        """Appends extra length to data. Using this to forge a padded message.
        (Last byte in pad is the total length of data)
        """
        self._extra_length = value

    @property
    def init_values(self):
        return self._h

    @init_values.setter
    def init_values(self, value):
        """Set init values (h) based on a hash-value"""
        self._h = self._reverse_hash(value)


class sha1(LengthExtender):
    """SHA1"""

    def __init__(self):
        self._h = constants.SHA1_H
        self._extra_length = 0

    def _produce(self, data):
        h = self._h[:]
        data = pad(data, self._extra_length)

        blocks = [data[i * 64 : i * 64 + 64] for i in range(len(data) // 64)]
        for block in blocks:
            w = [struct.unpack(b">I", block[i * 4 : i * 4 + 4])[0] for i in range(16)]

            for i in range(16, 80):
                w.append(rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

            a, b, c, d, e = h[0], h[1], h[2], h[3], h[4]

            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = rotl(b, 30)
                b = a
                a = temp

            h[0] = (h[0] + a) & 0xFFFFFFFF
            h[1] = (h[1] + b) & 0xFFFFFFFF
            h[2] = (h[2] + c) & 0xFFFFFFFF
            h[3] = (h[3] + d) & 0xFFFFFFFF
            h[4] = (h[4] + e) & 0xFFFFFFFF

        return h[0] << 128 | h[1] << 96 | h[2] << 64 | h[3] << 32 | h[4]

    def digest(self, data: bytes) -> bytes:
        """Digest and return bytes hash value"""
        return self._produce(data).to_bytes(20, byteorder="big")

    def hexdigest(self, data: bytes) -> str:
        """Digest and return hex hash value"""
        return self.digest(data).hex()

    def _reverse_hash(self, hsh):
        hsh = int(hsh, 16)
        a = hsh >> 128
        b = (hsh >> 96) & 0xFFFFFFFF
        c = (hsh >> 64) & 0xFFFFFFFF
        d = (hsh >> 32) & 0xFFFFFFFF
        e = hsh & 0xFFFFFFFF
        return [a, b, c, d, e]


class sha2(LengthExtender):
    def __init__(self):
        self.k = constants.SHA2_K
        self._extra_length = 0

    def _produce(self, data):
        _h = self._h[:]
        _k = self.k[:]
        data = pad(data, self._extra_length)

        blocks = [data[i * 64 : i * 64 + 64] for i in range(len(data) // 64)]
        for block in blocks:
            w = [struct.unpack(b">I", block[i * 4 : i * 4 + 4])[0] for i in range(16)]

            for i in range(16, 64):
                s0 = (rotr(w[i - 15], 7)) ^ (rotr(w[i - 15], 18)) ^ (w[i - 15] >> 3)
                s1 = (rotr(w[i - 2], 17)) ^ (rotr(w[i - 2], 19)) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h = _h

            for i in range(64):
                s1 = (rotr(e, 6)) ^ (rotr(e, 11)) ^ (rotr(e, 25))
                ch = (e & f) ^ (~e & g)
                temp1 = (h + s1 + ch + _k[i] + w[i]) & 0xFFFFFFFF
                s0 = (rotr(a, 2)) ^ (rotr(a, 13)) ^ (rotr(a, 22))
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (s0 + maj) & 0xFFFFFFFF

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF

            _h[0] = (_h[0] + a) & 0xFFFFFFFF
            _h[1] = (_h[1] + b) & 0xFFFFFFFF
            _h[2] = (_h[2] + c) & 0xFFFFFFFF
            _h[3] = (_h[3] + d) & 0xFFFFFFFF
            _h[4] = (_h[4] + e) & 0xFFFFFFFF
            _h[5] = (_h[5] + f) & 0xFFFFFFFF
            _h[6] = (_h[6] + g) & 0xFFFFFFFF
            _h[7] = (_h[7] + h) & 0xFFFFFFFF

        return _h

    def _reverse_hash(self, hsh):
        hsh = int(hsh, 16)
        h0 = (hsh >> 224) & 0xFFFFFFFF
        h1 = (hsh >> 192) & 0xFFFFFFFF
        h2 = (hsh >> 160) & 0xFFFFFFFF
        h3 = (hsh >> 128) & 0xFFFFFFFF
        h4 = (hsh >> 96) & 0xFFFFFFFF
        h5 = (hsh >> 64) & 0xFFFFFFFF
        h6 = (hsh >> 32) & 0xFFFFFFFF
        h7 = hsh & 0xFFFFFFFF
        return [h0, h1, h2, h3, h4, h5, h6, h7]

    def hexdigest(self, data: bytes) -> str:
        """Digest and return hex hash value"""
        return self.digest(data).hex()

    def digest(self, data: bytes) -> bytes:
        """Digest and return bytes hash value"""
        return b"".join(x.to_bytes(4, "big") for x in self._produce(data))


class sha256(sha2):
    _h = constants.SHA256_H


class sha224(sha2):
    _h = constants.SHA224_H

    def digest(self, data: bytes) -> bytes:
        """Digest and return bytes hash value
        The return value is identical to SHA-256, except that the output is constructed by omitting h7
        """
        return b"".join(x.to_bytes(4, "big") for x in self._produce(data)[:-1])


class md5(LengthExtender):
    """MD5"""

    k = constants.MD5_K
    s = constants.MD5_S

    def __init__(self):
        self.a0 = 0x67452301
        self.b0 = 0xEFCDAB89
        self.c0 = 0x98BADCFE
        self.d0 = 0x10325476
        self._extra_length = 0

    def _produce(self, data):
        a0, b0, c0, d0 = self.a0, self.b0, self.c0, self.d0
        k = self.k
        s = self.s
        data = pad(data, self._extra_length, byteorder="little")

        blocks = [data[i * 64 : i * 64 + 64] for i in range(len(data) // 64)]

        for block in blocks:
            m = [struct.unpack(b"<I", block[i * 4 : i * 4 + 4])[0] for i in range(16)]
            a = a0
            b = b0
            c = c0
            d = d0

            for i in range(64):
                if 0 <= i <= 15:
                    f = (b & c) | (~b & d)
                    g = i
                elif 16 <= i <= 31:
                    f = (d & b) | (~d & c)
                    g = ((5 * i + 1) % 16) & 0xFFFFFFFF
                elif 32 <= i <= 47:
                    f = b ^ c ^ d
                    g = ((3 * i + 5) % 16) & 0xFFFFFFFF
                elif 48 <= i <= 63:
                    f = c ^ (b | ~d)
                    g = ((7 * i) % 16) & 0xFFFFFFFF

                f = (f + a + k[i] + m[g]) & 0xFFFFFFFF
                a = d
                d = c
                c = b
                b = b + rotl(f, s[i])

            a0 = (a0 + a) & 0xFFFFFFFF
            b0 = (b0 + b) & 0xFFFFFFFF
            c0 = (c0 + c) & 0xFFFFFFFF
            d0 = (d0 + d) & 0xFFFFFFFF

        return [a0, b0, c0, d0]

    def digest(self, data):
        """Digest and return bytes hash value"""
        return b"".join(x.to_bytes(4, "little") for x in self._produce(data))

    def hexdigest(self, data):
        """Digest and return hex hash value"""
        return self.digest(data).hex()


hashclasses = {"sha1": sha1, "sha256": sha256, "sha224": sha224, "md5": md5}


def get(kls: str) -> object:
    kls = kls.lower()
    """Return hash object"""
    if kls in hashclasses:
        return hashclasses[kls]()
    else:
        raise Exception("Could not find hash method name ", kls)
