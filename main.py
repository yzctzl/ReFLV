import argparse
import logging

from ReFLV import ReFLV
from ReFLV import ReD
from ReFLV import ReN
from ReFLV import ReF

parser = argparse.ArgumentParser(description='Decrypt FLV that encrypted.',
                                 prog='ReFLV', usage='%(prog)s -i INPUT -o OUTPUT')
parser.add_argument('-d', '--debug', action='store_true', help='show debug info')
parser.add_argument('-l', '--log', type=str, help='the log file name, by default log will print to console')
parser.add_argument('-i', '--input', type=str, help='the encrypted flv file path')
parser.add_argument('-o', '--output', type=str, help='the decrypted output flv file path')
parser.add_argument('-p', '--platform', choices=['D', 'N', 'F'], help='select which platform to decrypt')
parser.add_argument('-k', '--key', type=str, help='the decrypt key of N')
args = parser.parse_args()

if args.debug:
    loglevel = logging.DEBUG
else:
    loglevel = logging.INFO
if args.log:
    logging.basicConfig(filename=f"{args.log}.log",
                        format='%(asctime)s - %(levelname)s - %(message)s', level=loglevel)
else:
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=loglevel)


# r = ReF.ReF(r".\Sample\F\enc_hevc.flv", r".\Sample\F\dec_hevc.flv")
# r = ReN.ReN(r".\Sample\N\enc.flv", r".\Sample\N\dec.flv", "5439867")
# r = ReD.ReD(r".\Sample\D\enc.flv", r".\Sample\D\dec.flv")
match args.platform:
    case "D":
        r = ReD.ReD(args.input, args.output)
    case "N":
        r = ReN.ReN(args.input, args.output, args.key)
    case "F":
        r = ReF.ReF(args.input, args.output)
    case _:
        r = ReFLV.ReFLV(args.input, args.output)
r.process()
