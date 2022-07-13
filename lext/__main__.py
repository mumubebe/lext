import argparse
import base64
from . import lext

choices = ["sha1", "sha256", "sha512", "md5"]

parser = argparse.ArgumentParser(description="Length Extension Attack-tool")
parser.add_argument(
    "-m",
    "--method",
    type=str,
    help="Hash method",
    choices=choices,
    default=choices[0],
)
parser.add_argument(
    "-d",
    "--data",
    help="""The original data known message from server.\n
    This data is prepend with a hidden secret unknown to client.""",
    required=True,
)
parser.add_argument(
    "-i",
    "--inject",
    help="Additional message to append to the original data",
    required=True,
)

parser.add_argument(
    "-s",
    "--signature",
    help="Signature of original data",
    required=True,
)

parser.add_argument(
    "-l",
    "--secret_length",
    type=int,
    help="Length of the hidden secret that is hidden from client",
    required=True,
)

parser.add_argument(
    "--no-signature",
    dest="no_signature",
    action="store_true",
    help="Ignore output return of signature",
)

parser.add_argument(
    "--no-outputdata",
    dest="no_outputdata",
    action="store_true",
    help="Ignore output return of new data message",
)

parser.add_argument(
    "--base64",
    dest="base64_format",
    action="store_true",
    help="Format output as base64. Note that both signature and data will be converted\
        (default for signature is hex string and byte string for data output)",
)

args = parser.parse_args()
args.data = args.data.encode("utf_8")
args.inject = args.inject.encode("utf_8")

data, sig = lext(
    data=args.data,
    signature=args.signature,
    inject=args.inject,
    secret_length=args.secret_length,
    method=args.method,
)

if args.base64_format:
    data = base64.b64encode(data).decode()
    sig = base64.b64encode(sig.encode()).decode()

if not args.no_outputdata:
    print(data)
if not args.no_signature:
    print(sig)
