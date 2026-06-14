"""Layer 2: deterministic rule lookup (3-ary Cuckoo hashing).

Implements the Cuckoo hash table used as the AEGIS-ZERO pipeline's
second-stage, exact-match rule lookup. Packets that pass Layer 1
(:mod:`bloom_filter`) are checked here; a miss results in
:data:`~common.Verdict.DROP_L2`, a hit results in
:data:`~common.Verdict.ALLOW`.
"""

from common import FiveTuple, xor_fold, SEEDS

#: Number of independent hash table banks (3-ary Cuckoo hashing).
NUM_BANKS = 3

#: Number of slots per bank.
BANK_SIZE = 16384

#: Maximum number of evictions ("kicks") attempted during
#: :meth:`CuckooHash.insert` before giving up.
MAX_KICKS = 512

_MIX  = [0xbf58476d1ce4e5b9, 0x94d049bb133111eb, 0x6c62272e07bb0142]
_MASK = 0xFFFF_FFFF_FFFF_FFFF


def _hash(t: FiveTuple, bank: int, bank_size: int) -> int:
    """Compute the slot address for ``t`` within a given bank.

    Combines :func:`~common.xor_fold` with a SplitMix64-style avalanche
    mix to produce a well-distributed address.

    Args:
        t: The 5-tuple to hash.
        bank: Index of the bank (selects the seed and mix constant used).
        bank_size: Number of slots in the bank; the result is taken
            modulo this value.

    Returns:
        A slot index in the range ``[0, bank_size)``.
    """
    h = xor_fold(t, SEEDS[bank], 2**32)
    h ^= h >> 30
    h  = (h * _MIX[bank]) & _MASK
    h ^= h >> 27
    h  = (h * 0x94d049bb133111eb) & _MASK
    h ^= h >> 31
    return h % bank_size


class CuckooHash:
    """A 3-ary Cuckoo hash table of :class:`~common.FiveTuple` rules.

    Each tuple can live in one of ``num_banks`` banks, at the slot given
    by :func:`_hash`. On insertion collisions, existing entries are
    evicted ("kicked") to their alternate bank, as in standard Cuckoo
    hashing.

    Args:
        num_banks: Number of hash table banks.
        bank_size: Number of slots per bank.
    """

    def __init__(self, num_banks: int = NUM_BANKS, bank_size: int = BANK_SIZE):
        self.num_banks = num_banks
        self.bank_size = bank_size
        self._banks: list[list[FiveTuple | None]] = [
            [None] * bank_size for _ in range(num_banks)
        ]

    def _addr(self, t: FiveTuple, bank: int) -> int:
        """Return the slot address for ``t`` in the given bank."""
        return _hash(t, bank, self.bank_size)

    def lookup(self, t: FiveTuple) -> bool:
        """Check whether ``t`` is present in any bank.

        Args:
            t: The 5-tuple to look up.

        Returns:
            ``True`` if ``t`` is stored in one of its candidate slots,
            ``False`` otherwise.
        """
        return any(self._banks[b][self._addr(t, b)] == t for b in range(self.num_banks))

    def insert(self, t: FiveTuple) -> bool:
        """Insert ``t`` into the table, evicting entries if necessary.

        If ``t`` is already present, this is a no-op that reports
        success. Otherwise, ``t`` is placed in the first free candidate
        slot; if none is free, an existing entry is evicted to make
        room and the process repeats for the evicted entry, up to
        :data:`MAX_KICKS` times.

        Args:
            t: The 5-tuple to insert.

        Returns:
            ``True`` if ``t`` (and any evicted entries) were
            successfully placed, ``False`` if :data:`MAX_KICKS` was
            exceeded without finding a free slot.
        """
        current = t
        for _ in range(MAX_KICKS):
            for b in range(self.num_banks):
                addr = self._addr(current, b)
                if self._banks[b][addr] is None:
                    self._banks[b][addr] = current
                    return True
                if self._banks[b][addr] == current:
                    return True

            evict_bank = _ % self.num_banks
            addr = self._addr(current, evict_bank)
            current, self._banks[evict_bank][addr] = self._banks[evict_bank][addr], current

        return False

    def delete(self, t: FiveTuple) -> bool:
        """Remove ``t`` from the table if present.

        Args:
            t: The 5-tuple to remove.

        Returns:
            ``True`` if ``t`` was found (in one of its candidate slots)
            and removed, ``False`` if it was not present.
        """
        for b in range(self.num_banks):
            addr = self._addr(t, b)
            if self._banks[b][addr] == t:
                self._banks[b][addr] = None
                return True
        return False

    @property
    def load_factor(self) -> float:
        """float: Fraction of all slots across all banks that are occupied."""
        filled = sum(1 for b in self._banks for slot in b if slot is not None)
        return filled / (self.num_banks * self.bank_size)
