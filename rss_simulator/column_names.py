from enum import Enum

class ColumnNames(Enum):
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    SRC_PORT = "src_port"
    DST_PORT = "dst_port"
    HASH_RESULT = "hash_result"
    QUEUE_NUMBER = "queue_number"
