from enum import Enum, auto
import socket
import struct
from typing import NamedTuple

SEEDS = [
    0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xABCDEF01, 0xFEDCBA98,
    0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00, 0x0F0F0F0F,
]


class Verdict(Enum):
    ALLOW   = auto()
    DROP_L1 = auto()
    DROP_L2 = auto()


class FiveTuple(NamedTuple):
    src_ip:   int
    dst_ip:   int
    src_port: int
    dst_port: int
    proto:    int


def xor_fold(t: FiveTuple, seed: int, num_bins: int) -> int:
    mixed = (t.src_ip ^ seed) ^ t.dst_ip ^ ((t.src_port << 16) | t.dst_port) ^ t.proto
    mixed ^= mixed >> 16
    return mixed % num_bins


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))
