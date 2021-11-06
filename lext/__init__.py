from .hashfuncs import new, pad
import math


def lext(
    data: bytes, signature: str, inject: bytes, secret_length: int, method: str = "sha1"
) -> tuple:
    """Main lext function"""

    # Get hash class
    hashcls = new(method)

    # Forge new input data message
    d = pad(data, secret_length, byteorder=hashcls.byteorder)

    # Setup and calculate a new signature
    b = 128 if method == 'sha512' else 64
    extra_length = math.ceil((len(data) + secret_length) / b) * b

    return (
        (d + inject),
        hashcls.hexdigest(inject, init_values=signature, extra_length=extra_length),
    )
