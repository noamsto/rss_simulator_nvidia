"""Toeplitz module."""
from rss_simulator.hash_key import HashKey


class Toeplitz(object):
    """Toeplitz RSS-hash related functionality."""

    def __init__(self, hash_key=None):
        """Initialize a Toeplitz instance.

        Args:
            hash_key (List[int], optional): List representation of RSS hash-key. Defaults to None.

        """
        self.__hash_key = hash_key if hash_key else HashKey.random_hash_key()

    @property
    def hash_key(self):
        """Hash-key getter.

        Returns:
            List[int]: List representation of Hash-key.

        """
        return self.__hash_key

    @hash_key.setter
    def hash_key(self, hash_key):
        """Hash-key setter.

        Args:
            hash_key (list[int]): List representation of Hash-key.

        """
        self.__hash_key = hash_key

    def hash_key_str(self):
        """Hash-key string representation.

        Returns:
            str: String representation of hash-key.

        """
        return ":".join("{:02x}".format(_hex) for _hex in self.__hash_key)

    def compute_hash(self, src_ip, dst_ip, src_port, dst_port):
        """Compute hash-result using Toeplitz method.

        Args:
            src_ip (int): int representation of source IP address.
            dst_ip (int): int representation of destination IP address.
            src_port (int): Source port.
            dst_port (int): Destination port.

        Returns:
            int: Hash-result.

        """
        key = list(self.__hash_key)
        input_bytes = self.__prepare_input_bytes(src_ip, dst_ip, src_port, dst_port)
        result = 0
        bitstr = ""
        for b in input_bytes:
            bitstr += bin(b)[2:].zfill(8)  # eliminate prefix "0b" and fill zeros to fit into 8 bits
        for b in bitstr:
            if b == "1":
                result ^= self.__key_left_most_32bits(key)
            self.__shift_key(key)
        return result

    def __key_left_most_32bits(self, key):
        """Extract 32 left most significant bits.

        Args:
            key (List[int]): List reperesentation hash-key.

        Returns:
            int: Int reperesentation of 32 lef most significant bits.

        """
        return key[0] << 24 | key[1] << 16 | key[2] << 8 | key[3]

    def __shift_key(self, key):
        """Shift key left.

        Args:
            key (List[int]): List reperesentation hash-key.

        """
        bitstr = ""
        shifted = ""
        for k in key:
            bitstr += bin(k)[2:].zfill(8)
            shifted = bitstr[1:]
            shifted += bitstr[0]
        for i, k in enumerate(key):
            key[i] = int(shifted[:8], 2)
            shifted = shifted[8:]

    def __ip_to_int(self, ip):
        """Convert IP string to int.

        Args:
            ip (str): String representation of IP address.

        Returns:
            int: String representation of IP address.

        """
        ip_num = ip.split(".")
        return int(ip_num[0]) << 24 | int(ip_num[1]) << 16 | int(ip_num[2]) << 8 | int(ip_num[3])

    def __prepare_input_bytes(self, src_ip, dst_ip, src_port, dst_port):
        """Prepare input bytes for Toeplitz hash input calculation.

        Args:
            src_ip (str): String representation of source IP.
            dst_ip (str): String representation of destination IP.
            src_port (int): Source port.
            dst_port (int): Destination port.

        Returns:
            List[int]: List of bytes, Toeplitz input.

        """
        # See input preparation reference in FlowGenerator.e file line 3920
        src_ip_num = self.__ip_to_int(src_ip)
        dst_ip_num = self.__ip_to_int(dst_ip)
        input_bytes = []
        input_bytes.append((src_ip_num & 0xFF000000) >> 24)
        input_bytes.append((src_ip_num & 0x00FF0000) >> 16)
        input_bytes.append((src_ip_num & 0x0000FF00) >> 8)
        input_bytes.append(src_ip_num & 0x000000FF)
        input_bytes.append((dst_ip_num & 0xFF000000) >> 24)
        input_bytes.append((dst_ip_num & 0x00FF0000) >> 16)
        input_bytes.append((dst_ip_num & 0x0000FF00) >> 8)
        input_bytes.append(dst_ip_num & 0x000000FF)
        input_bytes.append((src_port & 0xFF00) >> 8)
        input_bytes.append(src_port & 0x00FF)
        input_bytes.append((dst_port & 0xFF00) >> 8)
        input_bytes.append(dst_port & 0x00FF)
        return input_bytes
