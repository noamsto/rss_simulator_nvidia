"""Main module."""
from argparse import ArgumentParser

from rss_simulator.arg_parse_types import arg_parse_type_decorator as apt_decorator
from rss_simulator.arg_parse_types import PositiveInt
from rss_simulator.hash_key import HashKey
from rss_simulator.simulator import Simulator


def parse_args():
    """Parse script arguments.

    Returns:
        argparse.Namespace : Object containing parsed arguments.

    """
    parser = ArgumentParser(
        description=("Simulate Nvidia's NIC RSS queue's distribution for Toeplitz hash function.")
    )
    parser.add_argument(
        "--key-file",
        metavar="PATH",
        dest="key",
        type=apt_decorator(HashKey.from_file),
        required=True,
        help="File containing 40B hash key.",
    )
    parser.add_argument(
        "--ips-file",
        metavar="PATH",
        required=True,
        help="csv containing source/destination IP and source/destination ports 4 tupels entries.",
    )
    parser.add_argument(
        "--htable-size",
        metavar="NUM",
        type=PositiveInt.parse,
        required=True,
        help="Positive number representing the hash-table size.",
    )
    parser.add_argument(
        "--num-queues",
        metavar="NUM",
        type=PositiveInt.parse,
        required=True,
        help="Positive number representing number of queues.",
    )
    parser.add_argument(
        "--csv", metavar="PATH", help="Write output to csv file.",
    )
    return parser.parse_args()


def main():
    """Invoke the RSS simulator."""
    args = parse_args()
    rss_sim = Simulator(args.key, args.htable_size, args.num_queues)
    rss_sim.load_ips_from_csv(args.ips_file)
    rss_sim.calc_hash()
    rss_sim.calc_queue_number()
    if args.csv:
        rss_sim.write_statistics(args.csv)
    else:
        rss_sim.show_histogram()
