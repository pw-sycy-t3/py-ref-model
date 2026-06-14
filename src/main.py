"""Command-line entry point for the AEGIS-ZERO reference model.

Loads the authorized rule set from ``files/aegis_rules.json``, runs it
through :class:`~aegis_pipeline.AegisPipeline`, and prints summary
statistics about the Bloom filter fill ratio, the Cuckoo hash load
factor, and the classification results for the first 10 rules.
"""

import json
from collections import Counter

from common import FiveTuple, ip_to_int, Verdict
from aegis_pipeline import AegisPipeline

RULES_PATH = "files/aegis_rules.json"


def load_rules(path: str) -> list[FiveTuple]:
    """Load authorized 5-tuples from a JSON rules file.

    Args:
        path: Path to a JSON file containing a list of objects with
            ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port`` and
            ``proto`` keys.

    Returns:
        The corresponding list of :class:`~common.FiveTuple` rules.
    """
    with open(path) as f:
        raw = json.load(f)
    return [
        FiveTuple(
            src_ip   = ip_to_int(r["src_ip"]),
            dst_ip   = ip_to_int(r["dst_ip"]),
            src_port = r["src_port"],
            dst_port = r["dst_port"],
            proto    = r["proto"],
        )
        for r in raw
    ]


def main() -> None:
    """Load the rule set, run a sample of packets through the pipeline,
    and print summary statistics."""
    rules    = load_rules(RULES_PATH)
    pipeline = AegisPipeline()
    pipeline.load_rules(rules)

    stats: Counter[Verdict] = Counter()
    for t in rules[:10]:
        verdict = pipeline.process(t)
        stats[verdict] += 1

    print(f"Załadowano {len(rules)} reguł")
    print(f"Bloom fill ratio:   {pipeline.bloom.fill_ratio:.2%}")
    print(f"Cuckoo load factor: {pipeline.cuckoo.load_factor:.2%}")
    print(f"Statystyki:         {dict(stats)}")


if __name__ == "__main__":
    main()
