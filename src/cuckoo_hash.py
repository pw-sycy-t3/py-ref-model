from common import FiveTuple, xor_fold, SEEDS

NUM_BANKS = 3
BANK_SIZE = 16384
MAX_KICKS = 512

_MIX  = [0xbf58476d1ce4e5b9, 0x94d049bb133111eb, 0x6c62272e07bb0142]
_MASK = 0xFFFF_FFFF_FFFF_FFFF


def _hash(t: FiveTuple, bank: int, bank_size: int) -> int:
    h = xor_fold(t, SEEDS[bank], 2**32)
    h ^= h >> 30
    h  = (h * _MIX[bank]) & _MASK
    h ^= h >> 27
    h  = (h * 0x94d049bb133111eb) & _MASK
    h ^= h >> 31
    return h % bank_size


class CuckooHash:
    def __init__(self, num_banks: int = NUM_BANKS, bank_size: int = BANK_SIZE):
        self.num_banks = num_banks
        self.bank_size = bank_size
        self._banks: list[list[FiveTuple | None]] = [
            [None] * bank_size for _ in range(num_banks)
        ]

    def _addr(self, t: FiveTuple, bank: int) -> int:
        return _hash(t, bank, self.bank_size)

    def lookup(self, t: FiveTuple) -> bool:
        return any(self._banks[b][self._addr(t, b)] == t for b in range(self.num_banks))

    def insert(self, t: FiveTuple) -> bool:
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
        for b in range(self.num_banks):
            addr = self._addr(t, b)
            if self._banks[b][addr] == t:
                self._banks[b][addr] = None
                return True
        return False

    @property
    def load_factor(self) -> float:
        filled = sum(1 for b in self._banks for slot in b if slot is not None)
        return filled / (self.num_banks * self.bank_size)
