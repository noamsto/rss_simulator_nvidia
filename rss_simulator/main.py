from argparse import ArgumentParser

from rss_simulator.arg_parse_types import arg_parse_type_decorator as apt_decorator
from rss_simulator.arg_parse_types import PositiveInt
from rss_simulator.hash_key import HashKey
from rss_simulator.simulator import Simulator


def parse_args():
    # TODO: Help messages, usage.
    parser = ArgumentParser()
    parser.add_argument("--key-file", dest="key", type=apt_decorator(HashKey.from_file), required=True)
    parser.add_argument("--ips-file", required=True)
    parser.add_argument("--hash-table-size", type=PositiveInt.parse, required=True)
    parser.add_argument("--num-of-queues", type=PositiveInt.parse, required=True)
    return parser.parse_args()


def main():

    # h_key = HashKey.from_str(
        # "8a:f5:f2:b1:a3:88:59:94:0a:31:26:a1:cb:54:12:97:d4:fc:05:f7:c9:0a:99:50:22:cd:a4:bb:b5:dc:e8:f5:90:55:54:c0:d2:ea:b5:1b"
    # )
    # h_key = HashKeyOperations.from_str(
        # "3d:48:97:ac:53:4c:33:fe:d1:0e:3c:5e:75:a7:6f:b2:4d:0c:a4:4c:41:0a:3f:68:59:29:47:61:85:b7:60:aa:cd:36:8e:29:22:d1:17:62"
    # )
    args = parse_args()
    rss_sim = Simulator()
    rss_sim.load_ips_from_csv(args.ips_file)
    rss_sim.calc_hash(args.key)
    rss_sim.calc_qpn(32)
    rss_sim.show_histogram()
    # TODO: Add CSV output: count flows per queue number and distribution (full dataframe).

if __name__ == "__main__":
    main()
