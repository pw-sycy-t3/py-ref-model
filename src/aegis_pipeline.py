from common import FiveTuple, Verdict
from bloom_filter import BloomFilter
from cuckoo_hash import CuckooHash


class AegisPipeline:
    def __init__(self):
        self.bloom  = BloomFilter()
        self.cuckoo = CuckooHash()

    def load_rules(self, rules: list[FiveTuple]) -> None:
        for t in rules:
            self.bloom.add(t)
            self.cuckoo.insert(t)

    def process(self, t: FiveTuple) -> Verdict:
        if not self.bloom.query(t):
            return Verdict.DROP_L1
        if not self.cuckoo.lookup(t):
            return Verdict.DROP_L2
        return Verdict.ALLOW
