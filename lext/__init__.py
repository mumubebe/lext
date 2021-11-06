from .hashfuncs import new, pad
import math


def lext(
    data: bytes, signature: str, inject: bytes, secret_length: int, method: str = "sha1"
) -> tuple:
    """Main lext function"""

    # Get hash class
    hashcls = new(method)
    # Forge new input data message
    d = pad(data, secret_length)

    # Setup and calculate a new signature
    hashcls.extra_length = math.ceil((len(data) + secret_length) / 64) * 64
    hashcls.init_values = signature

    return ((d + inject), hashcls.hexdigest(inject))
