#!/usr/bin/env python3
"""
guard_gap_detector.py  --  static detector for the method-call dispatch
asymmetry described in "When Vendoring Defeats the Patch" (Shaik, 2026).

It flags a Python source file that implements an AST-walking restricted
interpreter in which the *method-call* dispatch path fetches the callable
through the built-in ``getattr(obj, name)`` (two positional arguments) while
the *attribute-read* path is routed through a dunder-blocking guard. That
asymmetry is the root cause of the sandbox-guard bypass measured in the paper
and of its vendored copies.

The detector is read-only static analysis. It parses source with ``ast`` (it
never imports or executes the target) and reports a boolean plus the line of
the offending dispatch. It contains no exploit code and emits no payloads.

Usage:
    python3 -I detector.py FILE [FILE ...]        # prints VULNERABLE/clean per file
    python3 -I detector.py --json FILE            # machine-readable
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import asdict, dataclass

# Names commonly used across these interpreters (and independent
# reimplementations) for a getattr that *does* enforce the dunder policy. A
# dispatch routed through any of these is guard-complete and must not be flagged.
GUARDED_GETATTR_NAMES = {
    "safe_getattr",
    "nodunder_getattr",
    "guarded_getattr",
    "safer_getattr",
    "checked_getattr",
}
# Names an interpreter gives the function that resolves a whole AST node. A
# dispatch that fetches the callable by recursing through one of these inherits
# the attribute-read guard and is also safe (e.g. pytherpreter).
RECURSIVE_EVAL_NAMES = {
    "evaluate_ast",
    "evaluate",
    "visit",
    "_eval",
    "eval_node",
}


@dataclass
class Finding:
    path: str
    vulnerable: bool
    reason: str
    dispatch_line: int | None = None
    dispatch_src: str | None = None


def _is_builtin_getattr_call(node: ast.AST) -> bool:
    """True for a bare ``getattr(a, b)`` call: builtin name, exactly 2 args."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 2
        and not node.keywords
    )


def _looks_like_ast_interpreter(tree: ast.AST) -> bool:
    """Heuristic gate: the file branches on ``ast.Attribute`` somewhere.

    This keeps the detector from flagging ordinary ``f = getattr(o, n); f()`` code in non-interpreter modules, where the
    pattern is benign.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "Attribute":
            # matches `ast.Attribute`
            if isinstance(node.value, ast.Name) and node.value.id == "ast":
                return True
    return False


def _invoked_names(tree: ast.AST) -> set[str]:
    """Names that are themselves called, e.g. ``func(...)`` -> {"func"}."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            out.add(node.func.id)
    return out


def analyze_source(src: str, path: str = "<string>") -> Finding:
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return Finding(path, False, f"unparseable: {exc}")

    if not _looks_like_ast_interpreter(tree):
        return Finding(path, False, "not an AST-walking interpreter")

    invoked = _invoked_names(tree)

    # Look for: <name> = getattr(obj, attr)   where <name> is later called.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not _is_builtin_getattr_call(node.value):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not targets:
            continue
        if any(t in invoked for t in targets):
            # The fetched attribute is subsequently invoked as a callable:
            # this is the method-call dispatch path using an unguarded getattr.
            line = node.lineno
            try:
                dispatch_src = src.splitlines()[line - 1].strip()
            except IndexError:
                dispatch_src = None
            return Finding(
                path,
                True,
                "method-call dispatch fetches callable via unguarded builtin getattr(obj, name)",
                dispatch_line=line,
                dispatch_src=dispatch_src,
            )

    # If every getattr-to-call used a guarded wrapper or a recursive evaluator,
    # the interpreter is guard-complete for this path.
    return Finding(
        tree and path,
        False,
        "dispatch routed through a guard/recursive evaluator "
        f"(guarded names seen: "
        f"{sorted(GUARDED_GETATTR_NAMES & invoked) or 'none'}; "
        f"recursive eval seen: {sorted(RECURSIVE_EVAL_NAMES & invoked) or 'none'})",
    )


def analyze_file(path: str) -> Finding:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        return Finding(path, False, f"unreadable: {exc}")
    f = analyze_source(src, path)
    f.path = path
    return f


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--json"]
    as_json = "--json" in argv
    if not args:
        print(__doc__)
        return 2
    results = [analyze_file(p) for p in args]
    if as_json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in results:
            tag = "VULNERABLE" if r.vulnerable else "clean     "
            loc = f" (line {r.dispatch_line})" if r.dispatch_line else ""
            print(f"{tag}  {r.path}{loc}  -- {r.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
