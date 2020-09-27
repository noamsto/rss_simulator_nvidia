"""Hash key related module."""
import re
from random import sample

HASH_KEY_BYTES_LENGTH = 40


class HashKey(object):
    """Hash-key class."""

    @staticmethod
    def __from_str(hash_key):
        """Convert hash-key string to a list.

        Args:
            hash_key (str): hash-key string.

        Raises:
            Exception: Bad hash-key string.

        Returns:
            List[int]: List representation of a hash-key.

        """
        hash_key_re = re.compile(
            r"^(?:(?:[0-9a-fA-F]{2}:){39}[0-9a-fA-F]{2})$|"
            r"^(?:(?:[0-9a-fA-F]{2}:){51}[0-9a-fA-F]{2})$"
        )
        if not hash_key_re.match(hash_key):
            raise Exception("Bad hash key given:\n{hkey}".format(hkey=hash_key))

        return [int(hex_str, 16) for hex_str in hash_key.split(":")]

    @staticmethod
    def from_file(hash_key_file):
        """Read hash-key from a file.

        Args:
            hash_key_file (str): Path to file containing hash-key

        Raises:
            Exception: Bad hash-key string.

        Returns:
            List[int]: List representation of a hash-key.

        """
        with open(hash_key_file) as _file:
            hash_key = _file.read()
        return HashKey.__from_str(hash_key)

    @staticmethod
    def random_hash_key():
        """Return a random 40 bytes length hash-key.

        Returns:
            List[int]: List representation of a hash-key.

        """
        return sample(range(256), HASH_KEY_BYTES_LENGTH)
