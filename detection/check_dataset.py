import os
import sys
from collections import Counter

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))        # the detection/ folder
PATH = os.path.join(HERE, "data", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")


def main():
    if not os.path.exists(PATH):
        print(f"[missing] {PATH}")
        print(__doc__)
        sys.exit(1)

    labels = Counter()
    columns = None
    for chunk in pd.read_csv(PATH, low_memory=False, chunksize=50_000):
        chunk.columns = [c.strip() for c in chunk.columns]
        columns = columns or list(chunk.columns)
        labels.update(chunk["Label"].astype(str).str.strip())

    total = sum(labels.values())
    print(f"[ok] {PATH}")
    print(f"     {total:,} flows, {len(columns)} columns")
    for name, n in labels.most_common():
        print(f"     {name:<10} {n:>9,}  ({100 * n / total:.1f}%)")

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from flow_extractor import FEATURES
    missing = [f for f in FEATURES if f not in columns]
    print(f"     model features present in the file: {len(FEATURES) - len(missing)} of {len(FEATURES)}")
    if missing:
        print(f"     MISSING: {missing}")
        sys.exit(1)


if __name__ == "__main__":
    main()
