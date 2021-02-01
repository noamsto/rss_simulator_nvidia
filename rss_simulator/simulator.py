"""Module containing the RSS simulator logic."""
from __future__ import print_function
import warnings

import matplotlib.cbook
try:
    import matplotlib.pyplot as plt
except ImportError as i_err:
    if "Tkinter" in str(i_err):
        print("Error: Tkinter is not installed, please install using system package manager. i.e.:\n"
              "Redhat: sudo yum install python2/3-tkinter\n"
              "Ubuntu: sudo apt install python2/3-tk.")
        exit(1)
    raise i_err
import pandas as pd
from matplotlib.ticker import MaxNLocator
from pandas.errors import ParserError as pd_ParserError

from rss_simulator.column_names import ColumnNames
from rss_simulator.exceptions import ParseException
from rss_simulator.toeplitz import Toeplitz

warnings.filterwarnings("ignore", category=matplotlib.cbook.mplDeprecation)


class Simulator(object):
    """RSS simulator class."""

    def __init__(self, hash_key, hash_table_size, queue_number):
        """Initialize method.

        Args:
            hash_key (List[int]): List representation of RSS key.
            hash_table_size (int): Hash table size.
            queue_number (int): Number of queues available for RSS.

        """
        self.__ip_df = None
        self.__toeplitz = Toeplitz(hash_key)
        self.__hash_table_size = hash_table_size
        self.__queue_num = queue_number

    def load_ips_from_csv(self, csv_path):
        """Read IPs from a csv file.

        Args:
            csv_path (tr): path to CSV file

        Raises:
            ParseException: CSV file is not in a valid format.
            ParseException: CSV missing information.

        """
        try:
            df = pd.read_csv(csv_path)
        except (UnicodeDecodeError, IOError, pd_ParserError):
            msg = "Couldn't parse '{csv}' file, make sure it's a valid CSV encoded with 'utf-8'"
            raise ParseException(msg)

        columns = df.columns.tolist()
        expected_columns = {
            col.value
            for col in set(ColumnNames) - {ColumnNames.HASH_RESULT, ColumnNames.QUEUE_NUMBER,}
        }
        missing_columns = expected_columns - set(columns)
        if missing_columns:
            raise ParseException(
                "{csv} is missing columns: {cols}".format(
                    csv=csv_path, cols=", ".join(missing_columns)
                )
            )
        self.__ip_df = df

    def calc_hash(self):
        """Calculate hash result for each input entry in CSV file."""
        self.__ip_df[ColumnNames.HASH_RESULT.value] = self.__ip_df.apply(
            self.__calc_entry_hash, axis=1
        )

    def __calc_entry_hash(self, entry):
        """Calc entry hash result.

        Args:
            entry (pandas.Series): Entry containing relevant input for hash calculation.

        Returns:
            int: Hash function result.

        """
        return self.__toeplitz.compute_hash(
            entry.src_ip, entry.dst_ip, entry.src_port, entry.dst_port
        )

    def calc_queue_number(self):
        """Calculate the queue number using the hash result."""
        self.__ip_df[ColumnNames.QUEUE_NUMBER.value] = (
            self.__ip_df.hash_result % self.__hash_table_size % self.__queue_num
        )

    def write_statistics(self, output):
        """Write statistics to csv file.

        Args:
            output (str): Path to output csv file.

        """
        value_counts = (
            self.__ip_df[ColumnNames.QUEUE_NUMBER.value]
            .value_counts()
            .sort_index()
            .rename_axis(ColumnNames.QUEUE_NUMBER.value)
            .to_frame("counts")
        )
        value_counts.to_csv(output)
        self.__ip_df.to_csv(output, mode="a", index=False)
        print("Wrote statistics to {csv}.".format(csv=output))

    def show_histogram(self):
        """Show histogram with information regarding the RSS hash simulation."""
        axes_arr = self.__ip_df.hist(
            column=ColumnNames.QUEUE_NUMBER.value,
            bins=self.__queue_num,
            range=[0, self.__queue_num],
            grid=False,
            figsize=(12, 8),
            color="#86bf91",
            zorder=2,
            rwidth=0.9,
        )
        axes_subplot = axes_arr[0]
        for subplot in axes_subplot:
            # Despine
            subplot.spines["right"].set_visible(False)
            subplot.spines["top"].set_visible(False)
            subplot.spines["left"].set_visible(False)
            # Switch off ticks
            subplot.tick_params(
                axis="both",
                which="both",
                bottom="off",
                top="off",
                labelbottom="on",
                left="off",
                right="off",
                labelleft="on",
            )
            # Draw horizontal axis lines
            values = subplot.get_yticks()
            for tick in values:
                subplot.axhline(y=tick, linestyle="dashed", alpha=0.8, color="#dddddd", zorder=1)
            # Remove title
            subplot.set_title("Number of Unique Flows per Queue", weight="bold", size=16)
            # Set x-axis label
            subplot.set_xlabel("Queue Number", labelpad=20, weight="bold", size=12)
            # Set y-axis label
            subplot.set_ylabel("Number of Flows", labelpad=20, weight="bold", size=12)
            # Set y-axis ticks to integers
            subplot.yaxis.set_major_locator(MaxNLocator(integer=True))

        hash_key = self.__toeplitz.hash_key_str()
        key_str = "Hash Key: {key1}\n{pad}{key2}".format(
            key1=hash_key[:94], pad=" " * 17, key2=hash_key[94:]
        )
        hash_table_str = "Hash Table Size: {size}".format(size=self.__hash_table_size)
        queues_size_str = "Number Queues: {size}".format(size=self.__queue_num)
        unique_queues_str = "Number of Queues Chosen by Hash Function: {num}".format(
            num=self.__ip_df[ColumnNames.QUEUE_NUMBER.value].nunique()
        )
        bottom_txt = "\n".join([key_str, hash_table_str, queues_size_str, unique_queues_str])
        plt.gcf().text(0.04, 0.03, bottom_txt, fontsize=12)
        plt.subplots_adjust(bottom=0.27)
        plt.show()
