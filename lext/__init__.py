from .hashfuncs import new, pad, pad128
import math


def lext(
    data: bytes, signature: str, inject: bytes, secret_length: int, method: str = "sha1"
) -> tuple:
    """Main lext function

    Return:
        data: byte string
        signature: hex string
    """

    # Get hash class
    hashcls = new(method)

    if method == "sha512":
        d = pad128(data, secret_length, byteorder=hashcls.byteorder)
        extra_length = math.ceil((len(data) + secret_length + 17) / 128) * 128
    else:
        d = pad(data, secret_length, byteorder=hashcls.byteorder)
        extra_length = math.ceil((len(data) + secret_length + 9) / 64) * 64

    return (
        (d + inject),
        hashcls.hexdigest(inject, init_values=signature, extra_length=extra_length),
    )
