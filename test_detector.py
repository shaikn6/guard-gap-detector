#!/usr/bin/env python3
"""
test_detector.py -- pin detector.py's behaviour on the shipped synthetic corpus.

The synthetic corpus is author-written and label-complete, so the detector must
score it exactly: every vulnerable fixture flagged, every clean fixture left
alone. These tests fail the build on any drift in that confusion matrix, and on
the structural guarantees the README makes about a finding (a line number and
source snippet for a hit, none for a miss).
"""

from __future__ import annotations

import os

import detector

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "corpus_synthetic", "manifest_synthetic.tsv")


def _load_manifest():
    pairs = []
    with open(MANIFEST, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            label_s, _, path = line.partition("\t")
            pairs.append((int(label_s), os.path.join(HERE, path)))
    return pairs


MANIFEST_ROWS = _load_manifest()


def test_manifest_is_balanced_as_documented():
    # README: three vulnerable fixtures, five that must stay clean.
    labels = [label for label, _ in MANIFEST_ROWS]
    assert labels.count(1) == 3
    assert labels.count(0) == 5


def test_each_fixture_matches_its_label():
    for label, path in MANIFEST_ROWS:
        pred = detector.analyze_file(path).vulnerable
        assert pred == bool(label), f"{path}: expected {bool(label)}, got {pred}"


def test_confusion_matrix_is_perfect_on_synthetic_corpus():
    tp = fp = tn = fn = 0
    for label, path in MANIFEST_ROWS:
        pred = detector.analyze_file(path).vulnerable
        if label == 1 and pred:
            tp += 1
        elif label == 1 and not pred:
            fn += 1
        elif label == 0 and pred:
            fp += 1
        else:
            tn += 1
    assert (tp, fp, tn, fn) == (3, 0, 5, 0)


def test_hit_carries_line_and_snippet():
    f = detector.analyze_file(
        os.path.join(HERE, "corpus_synthetic", "vuln_minimal.py")
    )
    assert f.vulnerable
    assert isinstance(f.dispatch_line, int) and f.dispatch_line > 0
    assert f.dispatch_src and "getattr" in f.dispatch_src


def test_clean_file_has_no_dispatch_location():
    f = detector.analyze_file(
        os.path.join(HERE, "corpus_synthetic", "clean_safe_wrapper.py")
    )
    assert not f.vulnerable
    assert f.dispatch_line is None
    assert f.dispatch_src is None
