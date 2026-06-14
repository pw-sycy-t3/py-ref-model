"""Top-level AEGIS-ZERO decision pipeline.

Combines the Layer 1 Bloom filter (:mod:`bloom_filter`) and the Layer 2
Cuckoo hash table (:mod:`cuckoo_hash`) into the two-stage packet
classification pipeline described in the project report.
"""

from common import FiveTuple, Verdict
from bloom_filter import BloomFilter
from cuckoo_hash import CuckooHash


class AegisPipeline:
    """The two-stage AEGIS-ZERO packet classification pipeline.

    Attributes:
        bloom: The Layer 1 Bloom filter pre-filter.
        cuckoo: The Layer 2 Cuckoo hash rule table.
    """

    def __init__(self):
        self.bloom  = BloomFilter()
        self.cuckoo = CuckooHash()

    def load_rules(self, rules: list[FiveTuple]) -> None:
        """Load a set of authorized 5-tuples into both pipeline stages.

        Args:
            rules: The 5-tuples to authorize.
        """
        for t in rules:
            self.bloom.add(t)
            self.cuckoo.insert(t)

    def process(self, t: FiveTuple) -> Verdict:
        """Classify a single packet.

        Args:
            t: The 5-tuple to classify.

        Returns:
            :data:`~common.Verdict.DROP_L1` if rejected by the Bloom
            filter, :data:`~common.Verdict.DROP_L2` if it passes Layer 1
            but is not found in the Cuckoo table, or
            :data:`~common.Verdict.ALLOW` if found.
        """
        if not self.bloom.query(t):
            return Verdict.DROP_L1
        if not self.cuckoo.lookup(t):
            return Verdict.DROP_L2
        return Verdict.ALLOW
