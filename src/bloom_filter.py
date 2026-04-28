from common import FiveTuple, xor_fold, SEEDS

BLOOM_SIZE_BITS = 147456  # ~144 Kb, dla n=10^4 i FP≈0.1%
BLOOM_K = 10


class BloomFilter:
    def __init__(self, size: int = BLOOM_SIZE_BITS, k: int = BLOOM_K):
        self.size  = size
        self.k     = k
        self._bits = bytearray(size // 8 + 1)

    def _positions(self, t: FiveTuple) -> list[int]:
        return [xor_fold(t, SEEDS[i], self.size) for i in range(self.k)]

    def add(self, t: FiveTuple) -> None:
        for pos in self._positions(t):
            self._bits[pos >> 3] |= 1 << (pos & 7)

    def query(self, t: FiveTuple) -> bool:
        return all(self._bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(t))

    @property
    def fill_ratio(self) -> float:
        ones = sum(bin(b).count("1") for b in self._bits)
        return ones / self.size
