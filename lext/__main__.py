import argparse
from . import lext

choices = ["sha1"]

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

args = parser.parse_args()
args.data = args.data.encode("utf_8")
args.inject = args.inject.encode("utf_8")

data, sig = lext(**vars(args))
print("Byte data: ", data)
print("Signature: ", sig)
