from . import hashfuncs


def lext(
    data: bytes, signature: str, inject: bytes, secret_length: int, method: str = "sha1"
) -> tuple:
    if method == "sha1":
        d = hashfuncs.sha1.pad(data, secret_length)

        sha = hashfuncs.sha1()
        sha.extra_length = 128
        sha.init_values = signature
        sha.add(inject)
        return ((d + inject), sha.hex_digest())
