import matplotlib.pyplot as plt
import pandas as pd
from pandas.errors import ParserError as pd_ParserError

from rss_simulator.exceptions import ParseException
from rss_simulator.toeplitz import Toeplitz


class Simulator(object):
    def __init__(self):
        self.__ip_df = None
        self.__toeplitz = Toeplitz()

    def load_ips_from_csv(self, csv_path):
        try:
            df = pd.read_csv(csv_path)
        except (UnicodeDecodeError, IOError, pd_ParserError):
            msg = "Couldn't parse '{csv}' file, make sure it's a valid CSV encoded with 'utf-8'"
            raise ParseException(msg)

        self.__ip_df = df

    def calc_hash(self, hash_key=None):
        if hash_key:
            self.__toeplitz.hash_key=hash_key
        self.__ip_df["hash_result"] = self.__ip_df.apply(self.__calc_entry_hash,axis=1)
        print(self.__ip_df)

    def __calc_entry_hash(self, entry):
        return self.__toeplitz.compute_hash(entry.src_ip, entry.dst_ip, entry.src_port, entry.dst_port)

    def calc_qpn(self, number_of_qps):
        self.__ip_df["qp_number"] = self.__ip_df.hash_result % number_of_qps
        print(self.__ip_df)
        print("Number of unique QPs: {num}".format(num=self.__ip_df["qp_number"].nunique()))

    def show_histogram(self):
        self.__ip_df.hist(column="qp_number", bins=128, range=[0,128])
        plt.show()
