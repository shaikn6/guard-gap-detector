#!/usr/bin/env python3
"""
evaluate_detector.py -- measure the precision/recall of detector.py against a
manually-labeled corpus of restricted-interpreter source files.

The manifest is a TSV of ``<label>\t<path>`` lines, label in {1,0}, where 1
means "manual source review found the unguarded method-call dispatch" and 0
means "manual source review found the dispatch is guard-complete (or the file
is not an interpreter)". Comment lines start with '#'.

The corpus itself (third-party source fetched read-only during the study) is
not redistributed, per the paper's disclosure policy; this harness reproduces
the reported confusion matrix from whatever manifest is supplied.

Usage: python3 -I evaluate_detector.py MANIFEST.tsv
"""

from __future__ import annotations

import os
import sys

# Ensure the sibling detector.py is importable even under `python3 -I`, which
# does not add the script's own directory to sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detector


def main(path: str) -> int:
    tp = fp = tn = fn = 0
    rows = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            label_s, _, fpath = line.partition("\t")
            label = int(label_s)
            pred = detector.analyze_file(fpath).vulnerable
            if label == 1 and pred:
                tp += 1
                cell = "TP"
            elif label == 1 and not pred:
                fn += 1
                cell = "FN"
            elif label == 0 and pred:
                fp += 1
                cell = "FP"
            else:
                tn += 1
                cell = "TN"
            rows.append((cell, label, int(pred), fpath))

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision == precision and recall == recall and (precision + recall)
        else float("nan")
    )
    for cell, label, pred, fpath in rows:
        print(f"{cell}  label={label} pred={pred}  {fpath}")
    print("-" * 60)
    print(f"n={len(rows)}  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
