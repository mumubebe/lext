import struct


def rotl(num, shift):
    """Rotate left"""
    return ((num << shift) | (num >> (32 - shift))) & 0xFFFFFFFF


def rotr(num, shift):
    """Rotate right"""
    return ((num >> shift) | (num << (32 - shift))) & 0xFFFFFFFF


def pad(data, extra_length=0):
    """Pad message, with the ability to forge"""
    ml = len(data) + extra_length

    padlen = (55 - ml) % 64

    ml_bits = ml * 8

    return (
        data
        + bytes([0x80])
        + (0x00).to_bytes(padlen, byteorder="big")
        + (ml_bits).to_bytes(8, byteorder="big")
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

    def add(self, data):
        self._data = data


class sha1(LengthExtender):
    """SHA1"""

    hx = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ]

    def __init__(self):
        self._h = self.hx[:]
        self._extra_length = 0
        self._data = b""

    def _produce(self):
        h = self._h[:]
        data = pad(self._data, self._extra_length)

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

    def digest(self):
        return self._produce().to_bytes(20, byteorder="big")

    def hexdigest(self):
        return self.digest().hex()

    def _reverse_hash(self, hsh):
        hsh = int(hsh, 16)
        a = hsh >> 128
        b = (hsh >> 96) & 0xFFFFFFFF
        c = (hsh >> 64) & 0xFFFFFFFF
        d = (hsh >> 32) & 0xFFFFFFFF
        e = hsh & 0xFFFFFFFF
        return [a, b, c, d, e]


class sha2(LengthExtender):
    hx = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    kx = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]

    def __init__(self):
        self.k = self.kx[:]
        self._h = self.hx[:]
        self._extra_length = 0
        self._data = b""

    def _produce(self):
        _h = self._h[:]
        _k = self.k[:]
        data = pad(self._data, self._extra_length)

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

        self._h = _h
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

    def hexdigest(self):
        return self.digest().hex()

    def digest(self):
        return b"".join(x.to_bytes(4, "big") for x in self._produce())


def get_cls(kls):
    """Return hash class"""
    if kls == "sha1":
        return sha1
    elif kls == "sha256":
        return sha2
    else:
        raise Exception("Could not find hash method name ", kls)
