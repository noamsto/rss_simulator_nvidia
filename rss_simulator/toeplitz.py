
from rss_simulator.hash_key import HashKey

class Toeplitz(object):
    def __init__(self, hash_key=None):
        self.__hash_key = hash_key if hash_key else HashKey.random_hash_key()

    @property
    def hash_key(self):
        return self.__hash_key

    @hash_key.setter
    def hash_key(self, hash_key):
        self.__hash_key=hash_key

    def hash_key_str(self):
        return ":".join("{:x}".format(_hex) for _hex in self.__hash_key)

    def compute_hash(self, src_ip, dst_ip, src_port, dst_port):
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
        return key[0] << 24 | key[1] << 16 | key[2] << 8 | key[3]

    def __shift_key(self, key):
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
        ip_num = ip.split(".")
        return int(ip_num[0]) << 24 | int(ip_num[1]) << 16 | int(ip_num[2]) << 8 | int(ip_num[3])

    def __prepare_input_bytes(self, src_ip, dst_ip, src_port, dst_port):
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
