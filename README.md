# guard-gap-detector

A small, read-only static detector for a **dispatch asymmetry** in AST-walking
restricted Python interpreters: the kind of in-process "sandbox" that some
AI-agent frameworks use to run model-written code without a container or VM.

In a vulnerable interpreter, a bare attribute _read_ (`obj.attr`) is routed
through a guard that rejects dunder names (`__globals__`, `__dict__`, …), but the
callable fetched for a method _call_ (`obj.method(...)`) is fetched with a raw
built-in `getattr` that skips that guard. The read path is protected and the
call path is not — an instance of what the accompanying paper calls a failure of
**guard completeness**: a guard is only as good as the set of dispatch paths it
actually covers.

This tool answers one narrow, auditable question:

> Is the callable for a method dispatch fetched through an **unguarded built-in
> `getattr`**, while attribute reads are guarded?

It is **not** an exploit, a general sandbox-robustness prover, or a
guard-completeness oracle. It parses source with Python's `ast` module and never
imports or executes the file under test. It emits no payloads.

## Install

No dependencies beyond the Python standard library (Python 3.8+).

```bash
git clone https://github.com/shaikn6/guard-gap-detector
cd guard-gap-detector
```

## Use

Scan one or more files:

```bash
python3 -I detector.py path/to/interpreter.py
python3 -I detector.py --json path/to/interpreter.py
```

`-I` runs Python in isolated mode (no implicit `sys.path` entries), which is the
right habit when pointing an analysis tool at files you do not control. Output is
`VULNERABLE`/`clean` per file, with the line of the offending dispatch when found.

## Reproduce the evaluation

The repository ships a **synthetic, author-written** corpus (`corpus_synthetic/`)
of eight fixture files that contain no third-party source and no exploit payload,
only the structural cases the detector must separate:

- three toy AST-walkers carrying the unguarded method-call dispatch (a minimal
  one, one with renamed identifiers, and one in an independent non-lineage style);
- five that must stay clean: a `safe_getattr` wrapper patch, a guard-complete
  recursive evaluator, a hard negative that calls built-in `getattr` only for a
  read whose result is never invoked, and two non-interpreter modules.

Run the harness against the shipped manifest:

```bash
python3 -I evaluate_detector.py corpus_synthetic/manifest_synthetic.tsv
```

Expected result: **precision 1.00, recall 1.00, F1 1.00** (3 true positives,
5 true negatives). The harness also runs against any other
`<label>\t<path>` manifest you supply.

## What the detector does and does not catch

It flags an interpreter when both hold: (i) the file branches on
`ast.Attribute` (the gate that keeps it from flagging ordinary
`f = getattr(o, n); f()` helper code), and (ii) it assigns
`name = getattr(obj, attr)` with the two-argument built-in `getattr` and then
invokes `name` as a callable. A dispatch routed through a guarded wrapper
(`safe_getattr`, `guarded_getattr`, …) or through a recursive evaluator is, by
construction, not flagged.

It will miss a copy that fetches the callable through an aliased or indirect
`getattr`, that uses a non-`ast` parser, or that reaches the same
native-resolution surface through a built-in other than `str.format`. It says
nothing about whether a flagged interpreter is actually reachable by
attacker-controlled input in a given deployment. Treat a hit as a prompt to read
the dispatch path by hand, not as a verdict.

## Proposed fix (for a flagged interpreter)

Route the method-call callable through the **same** dunder-blocking wrapper the
interpreter already uses for attribute reads, instead of a bare `getattr`. That
is a one-call-site change, not new logic.

## Relation to the paper

This is the released artifact for the measurement paper _"When Vendoring Defeats
the Patch: A Cross-Repository Measurement of a Sandbox-Guard Bypass in AI-Agent
Code Interpreters"_ (Shaik, 2026; preprint forthcoming). The paper describes the
mechanism, a cross-repository measurement, and a responsible-disclosure process.
Consistent with that disclosure process, **this repository names no affected
project and ships no third-party source or exploit code.**

## License

MIT — see [LICENSE](LICENSE).
