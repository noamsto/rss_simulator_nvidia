#!/usr/bin/env python
import re
from random import sample


HASH_KEY_BYTES_LENGTH=40


class HashKey(object):
    @staticmethod
    def __from_str(hash_key):
        hash_key_re = re.compile(
            r"^(?:(?:[0-9a-fA-F]{2}:){39}[0-9a-fA-F]{2})$|"
            r"^(?:(?:[0-9a-fA-F]{2}:){51}[0-9a-fA-F]{2})$"
        )
        if not hash_key_re.match(hash_key):
            raise Exception("Bad hash key")

        return [int(hex_str, 16) for hex_str in hash_key.split(":")]

    @staticmethod
    def from_file(hash_key_file):
        with open(hash_key_file) as _file:
            hash_key = _file.read()
        return HashKey.__from_str(hash_key)

    @staticmethod
    def random_hash_key():
        return sample(range(256), HASH_KEY_BYTES_LENGTH)
