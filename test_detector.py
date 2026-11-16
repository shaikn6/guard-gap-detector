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

import ast
import json
import os

import detector
import evaluate_detector

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


# ---------------------------------------------------------------------------
# Direct unit tests for analyze_source on inline fixtures (no files on disk).
# ---------------------------------------------------------------------------

_VULN = '''
import ast
def guard(obj, name):
    if name.startswith("__"):
        raise PermissionError(name)
    return getattr(obj, name)
def ev(node, env):
    if isinstance(node, ast.Attribute):
        return guard(ev(node.value, env), node.attr)
    if isinstance(node, ast.Call):
        func = getattr(ev(node.func.value, env), node.func.attr)
        return func(*[ev(a, env) for a in node.args])
    raise ValueError("x")
'''

_CLEAN_WRAPPER = '''
import ast
def safe_getattr(obj, name):
    if name.startswith("__"):
        raise PermissionError(name)
    return getattr(obj, name)
def ev(node, env):
    if isinstance(node, ast.Attribute):
        return safe_getattr(ev(node.value, env), node.attr)
    if isinstance(node, ast.Call):
        func = safe_getattr(ev(node.func.value, env), node.func.attr)
        return func(*[ev(a, env) for a in node.args])
    raise ValueError("x")
'''

_NONINTERP = '''
def dispatch(o, n):
    f = getattr(o, n)
    return f()
'''


def test_analyze_source_flags_inline_vulnerable():
    f = detector.analyze_source(_VULN, "inline")
    assert f.vulnerable is True
    assert isinstance(f.dispatch_line, int) and f.dispatch_line > 0
    assert f.dispatch_src and "getattr" in f.dispatch_src


def test_analyze_source_clears_inline_wrapper():
    f = detector.analyze_source(_CLEAN_WRAPPER, "inline")
    assert f.vulnerable is False
    assert f.dispatch_line is None
    assert f.dispatch_src is None


def test_non_interpreter_is_gated_out():
    f = detector.analyze_source(_NONINTERP, "inline")
    assert f.vulnerable is False
    assert f.reason == "not an AST-walking interpreter"


def test_unparseable_source_is_reported():
    f = detector.analyze_source("def (:\n", "inline")
    assert f.vulnerable is False
    assert f.reason.startswith("unparseable:")


# ---------------------------------------------------------------------------
# Characterization tests: these PIN the detector's known gaps as it is today,
# not an ideal. A change in any of these is a real behaviour change to review.
# Each snippet branches on ast.Attribute so the interpreter gate passes; only
# the method-call arm varies.
# ---------------------------------------------------------------------------

def _interp(call_arm):
    return (
        "import ast\n"
        "def guard(obj, name):\n"
        "    return getattr(obj, name)\n"
        "def ev(node, env):\n"
        "    if isinstance(node, ast.Attribute):\n"
        "        return guard(ev(node.value, env), node.attr)\n"
        "    if isinstance(node, ast.Call):\n"
        + call_arm
        + "    raise ValueError('x')\n"
    )


def test_limit_missed_when_callable_not_assigned():
    # getattr(...)(...) invoked inline, no name binding: missed.
    src = _interp("        return getattr(o, node.func.attr)(env)\n")
    assert detector.analyze_source(src, "inline").vulnerable is False


def test_limit_missed_on_three_arg_getattr():
    # A third `default` argument takes it off the two-arg built-in shape.
    src = _interp(
        "        f = getattr(o, node.func.attr, None)\n"
        "        return f()\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is False


def test_limit_missed_on_attribute_target_assignment():
    # Assigning to self.f (not a plain Name target) is missed.
    src = _interp(
        "        self.f = getattr(o, node.func.attr)\n"
        "        return self.f()\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is False


def test_limit_missed_when_getattr_wrapped_in_helper():
    # The fetch is laundered through a helper, so no getattr-then-call Assign.
    src = (
        "import ast\n"
        "def fetch(o, n):\n"
        "    return getattr(o, n)\n"
        "def ev(node, env):\n"
        "    if isinstance(node, ast.Attribute):\n"
        "        return fetch(ev(node.value, env), node.attr)\n"
        "    if isinstance(node, ast.Call):\n"
        "        f = fetch(o, node.func.attr)\n"
        "        return f()\n"
        "    raise ValueError('x')\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is False


def test_limit_flags_call_path_shape_without_read_guard():
    # The detector never inspects the read path, so it reports the unguarded
    # call-path shape even when reads have no guard. Not a false positive: the
    # call path really is unguarded; the read/call asymmetry is just absent.
    src = (
        "import ast\n"
        "def ev(node, env):\n"
        "    if isinstance(node, ast.Attribute):\n"
        "        return getattr(ev(node.value, env), node.attr)\n"
        "    if isinstance(node, ast.Call):\n"
        "        f = getattr(ev(node.func.value, env), node.func.attr)\n"
        "        return f(*[ev(a, env) for a in node.args])\n"
        "    raise ValueError('x')\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is True


def test_limit_overflags_on_scope_blind_name_match():
    # Name matching is file-wide, not scope-aware: a pure read `x = getattr(...)`
    # in one function plus an unrelated `x()` in another is flagged.
    src = (
        "import ast\n"
        "def reader(node, env):\n"
        "    if isinstance(node, ast.Attribute):\n"
        "        x = getattr(env, node.attr)\n"
        "        return x\n"
        "def other(factory):\n"
        "    x = factory\n"
        "    return x()\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is True


def test_limit_overflags_past_inline_call_path_guard():
    # An inline (non-wrapper) dunder check on the call path is not recognized.
    src = _interp(
        "        nm = node.func.attr\n"
        "        if nm.startswith('__'):\n"
        "            raise ValueError(nm)\n"
        "        f = getattr(o, nm)\n"
        "        return f()\n"
    )
    assert detector.analyze_source(src, "inline").vulnerable is True


# ---------------------------------------------------------------------------
# Helper and file-level behaviour.
# ---------------------------------------------------------------------------

def _call(expr):
    return ast.parse(expr, mode="eval").body


def test_is_builtin_getattr_call_matches_only_two_positional_args():
    assert detector._is_builtin_getattr_call(_call("getattr(a, b)")) is True
    assert detector._is_builtin_getattr_call(_call("getattr(a, b, c)")) is False
    assert detector._is_builtin_getattr_call(_call("getattr(a, b, x=c)")) is False
    assert detector._is_builtin_getattr_call(_call("other(a, b)")) is False


def test_analyze_file_reports_unreadable_path(tmp_path):
    missing = os.path.join(str(tmp_path), "nope.py")
    f = detector.analyze_file(missing)
    assert f.vulnerable is False
    assert f.reason.startswith("unreadable:")


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------

_VULN_FIXTURE = os.path.join(HERE, "corpus_synthetic", "vuln_minimal.py")


def test_cli_no_args_returns_usage_code():
    assert detector.main([]) == 2


def test_cli_text_output_flags_vulnerable(capsys):
    rc = detector.main([_VULN_FIXTURE])
    assert rc == 0
    assert "VULNERABLE" in capsys.readouterr().out


def test_cli_json_output_is_machine_readable(capsys):
    rc = detector.main(["--json", _VULN_FIXTURE])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert data[0]["vulnerable"] is True


# ---------------------------------------------------------------------------
# evaluate_detector harness.
# ---------------------------------------------------------------------------

_CLEAN_FIXTURE = os.path.join(HERE, "corpus_synthetic", "clean_safe_wrapper.py")


def _write_manifest(tmp_path, lines):
    path = os.path.join(str(tmp_path), "m.tsv")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def test_harness_scores_a_manifest(tmp_path, capsys):
    manifest = _write_manifest(
        tmp_path,
        [
            "# a comment",
            "",
            "1\t" + _VULN_FIXTURE,
            "0\t" + _CLEAN_FIXTURE,
        ],
    )
    assert evaluate_detector.main(manifest) == 0
    out = capsys.readouterr().out
    assert "TP=1" in out and "TN=1" in out
    assert "FP=0" in out and "FN=0" in out


def test_harness_fails_loudly_on_unreadable_row(tmp_path, capsys):
    manifest = _write_manifest(
        tmp_path, ["1\t" + os.path.join(str(tmp_path), "missing.py")]
    )
    assert evaluate_detector.main(manifest) == 2
    assert "could not read" in capsys.readouterr().err


def test_harness_prints_nan_without_positives(tmp_path, capsys):
    manifest = _write_manifest(tmp_path, ["0\t" + _CLEAN_FIXTURE])
    assert evaluate_detector.main(manifest) == 0
    out = capsys.readouterr().out
    assert "precision=nan" in out and "recall=nan" in out
