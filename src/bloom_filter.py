"""Layer 1: probabilistic pre-filter (Bloom filter).

Implements the Bloom filter used as the AEGIS-ZERO pipeline's first-stage,
probabilistic admission check. A negative result here is a guaranteed
rejection (:data:`~common.Verdict.DROP_L1`); a positive result means the
packet is forwarded to Layer 2 (:mod:`cuckoo_hash`) for an exact check.
"""

from common import FiveTuple, xor_fold, SEEDS

#: Size of the Bloom filter bit array in bits (~144 Kb), sized for
#: n=10^4 elements with a target false-positive rate of ~0.1%.
BLOOM_SIZE_BITS = 147456

#: Number of hash functions (and therefore bits set per element).
BLOOM_K = 10


class BloomFilter:
    """A bit-array Bloom filter using :func:`~common.xor_fold` hashing.

    Args:
        size: Size of the underlying bit array, in bits.
        k: Number of independent hash functions to use.
    """

    def __init__(self, size: int = BLOOM_SIZE_BITS, k: int = BLOOM_K):
        self.size  = size
        self.k     = k
        self._bits = bytearray(size // 8 + 1)

    def _positions(self, t: FiveTuple) -> list[int]:
        """Return the ``k`` bit positions associated with ``t``."""
        return [xor_fold(t, SEEDS[i], self.size) for i in range(self.k)]

    def add(self, t: FiveTuple) -> None:
        """Add a 5-tuple to the filter by setting its ``k`` bits.

        Args:
            t: The 5-tuple to add.
        """
        for pos in self._positions(t):
            self._bits[pos >> 3] |= 1 << (pos & 7)

    def query(self, t: FiveTuple) -> bool:
        """Check whether a 5-tuple may be a member of the filter.

        Args:
            t: The 5-tuple to check.

        Returns:
            ``True`` if all ``k`` bits associated with ``t`` are set
            (possible member, subject to false positives), ``False`` if
            any bit is unset (definitely not a member).
        """
        return all(self._bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(t))

    @property
    def fill_ratio(self) -> float:
        """float: Fraction of bits in the array that are set to 1."""
        ones = sum(bin(b).count("1") for b in self._bits)
        return ones / self.size
