from argparse import ArgumentParser
from argparse import ArgumentDefaultsHelpFormatter as ADHFormamtter

from rss_simulator.arg_parse_types import arg_parse_type_decorator as apt_decorator
from rss_simulator.arg_parse_types import PositiveInt
from rss_simulator.hash_key import HashKey
from rss_simulator.simulator import Simulator


def parse_args():
    # TODO: usage.
    parser = ArgumentParser()
    parser.add_argument(
        "--key-file",
        dest="key",
        type=apt_decorator(HashKey.from_file),
        required=True,
        help="File containing 40B hash key.",
    )
    parser.add_argument(
        "--ips-file", required=True, help="csv containing IP TCP/UDP 5 tuple entries."
    )
    parser.add_argument(
        "--hash-table-size",
        type=PositiveInt.parse,
        required=True,
        help="Positive number representing the hash-table size.",
    )
    parser.add_argument(
        "--num-of-queues",
        type=PositiveInt.parse,
        required=True,
        help="Positive number representing number of queues.",
    )
    parser.add_argument(
        "--csv",
        help="Write output to csv file.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    rss_sim = Simulator(args.key, args.hash_table_size, args.num_of_queues)
    rss_sim.load_ips_from_csv(args.ips_file)
    rss_sim.calc_hash()
    rss_sim.calc_qpn()
    if args.csv:
        rss_sim.write_statistics(args.csv)
    else:
        rss_sim.show_histogram()
    # TODO: Add CSV output: count flows per queue number and distribution (full dataframe).


if __name__ == "__main__":
    main()
