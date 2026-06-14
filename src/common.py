"""Shared definitions for the AEGIS-ZERO reference pipeline.

This module provides the data types and the hashing primitive shared by
every stage of the pipeline: the network packet representation
(:class:`FiveTuple`), the possible classification outcomes
(:class:`Verdict`), the hash seeds used to derive independent hash
functions, and the XOR-fold hash (:func:`xor_fold`) used by both the
Bloom filter (Layer 1) and the Cuckoo hash tables (Layer 2).
"""

from enum import Enum, auto
import socket
import struct
from typing import NamedTuple

#: Independent 32-bit seeds used to derive multiple hash functions from
#: :func:`xor_fold`. Each seed corresponds to one Bloom filter hash
#: function or one Cuckoo hash bank.
SEEDS = [
    0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xABCDEF01, 0xFEDCBA98,
    0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00, 0x0F0F0F0F,
]


class Verdict(Enum):
    """Final classification result for a packet processed by the pipeline."""

    ALLOW   = auto()  #: Packet matched a rule in Layer 2 and is allowed through.
    DROP_L1 = auto()  #: Packet was rejected by the Layer 1 Bloom filter.
    DROP_L2 = auto()  #: Packet passed Layer 1 but found no match in Layer 2.


class FiveTuple(NamedTuple):
    """Network 5-tuple identifying a packet's flow.

    Attributes:
        src_ip: Source IP address as a 32-bit integer.
        dst_ip: Destination IP address as a 32-bit integer.
        src_port: Source port number.
        dst_port: Destination port number.
        proto: IP protocol number (e.g. 6 for TCP).
    """

    src_ip:   int
    dst_ip:   int
    src_port: int
    dst_port: int
    proto:    int


def xor_fold(t: FiveTuple, seed: int, num_bins: int) -> int:
    """Compute a hash of a 5-tuple using the XOR-fold scheme.

    Mixes all fields of ``t`` with ``seed`` using XOR, folds the result
    by XOR-ing its upper and lower halves, and reduces it to the range
    ``[0, num_bins)``. This is the hardware-friendly hash primitive used
    by both the Bloom filter and the Cuckoo hash tables.

    Args:
        t: The 5-tuple to hash.
        seed: A seed value (typically one of :data:`SEEDS`) used to
            derive an independent hash function.
        num_bins: The number of output bins; the result is taken modulo
            this value.

    Returns:
        An integer in the range ``[0, num_bins)``.
    """
    mixed = (t.src_ip ^ seed) ^ t.dst_ip ^ ((t.src_port << 16) | t.dst_port) ^ t.proto
    mixed ^= mixed >> 16
    return mixed % num_bins


def ip_to_int(ip: str) -> int:
    """Convert a dotted-decimal IPv4 address to a 32-bit integer.

    Args:
        ip: An IPv4 address in dotted-decimal notation, e.g. ``"10.0.0.1"``.

    Returns:
        The address as an unsigned 32-bit integer.
    """
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    """Convert a 32-bit integer to a dotted-decimal IPv4 address.

    Args:
        n: An IPv4 address as an unsigned 32-bit integer.

    Returns:
        The address in dotted-decimal notation, e.g. ``"10.0.0.1"``.
    """
    return socket.inet_ntoa(struct.pack("!I", n))
