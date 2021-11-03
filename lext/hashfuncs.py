import struct


def rotl(num, bits):
    num = ((num << bits) | (num >> (32 - bits))) & 0xFFFFFFFF
    return num


class sha1:
    def __init__(self):
        self.h0, self.h1, self.h2, self.h3, self.h4 = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )
        self._extra_length = 0
        self._message = b""

    @property
    def extra_length(self):
        return self._extra_length

    @extra_length.setter
    def extra_length(self, value):
        self._extra_length = value

    @property
    def init_values(self):
        return (self.h0, self.h1, self.h2, self.h3, self.h4)

    @init_values.setter
    def init_values(self, value):
        self.h0, self.h1, self.h2, self.h3, self.h4 = self.reverse_hash(value)

    def add(self, message):
        self._message = message

    def _produce(self, message, h0, h1, h2, h3, h4):
        message = self.pad(self._message, self._extra_length)

        blocks = [message[i * 64 : i * 64 + 64] for i in range(len(message) // 64)]

        for block in blocks:
            w = [struct.unpack(b">I", block[i * 4 : i * 4 + 4])[0] for i in range(16)]

            for i in range(16, 80):
                w.append(rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

            a, b, c, d, e = h0, h1, h2, h3, h4

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

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        return h0 << 128 | h1 << 96 | h2 << 64 | h3 << 32 | h4

    def hex_digest(self):
        return (
            self._produce(self._message, self.h0, self.h1, self.h2, self.h3, self.h4)
            .to_bytes(20, byteorder="big")
            .hex()
        )

    @staticmethod
    def pad(message, extra_length=0):
        """Pad message, with the ability to forge"""
        ml = len(message) + extra_length

        padlen = (55 - ml) % 64

        ml_bits = ml * 8

        return (
            message
            + bytes([0x80])
            + (0x00).to_bytes(padlen, byteorder="big")
            + (ml_bits).to_bytes(8, byteorder="big")
        )

    @staticmethod
    def reverse_hash(hsh):
        hsh = int(hsh, 16)
        a = hsh >> 128
        b = (hsh >> 96) & 0xFFFFFFFF
        c = (hsh >> 64) & 0xFFFFFFFF
        d = (hsh >> 32) & 0xFFFFFFFF
        e = hsh & 0xFFFFFFFF
        return a, b, c, d, e
