# SYNTHETIC FIXTURE (author-written). Label: CLEAN (guard-complete by design).
# The callable for a method call is produced by recursing through the same
# evaluate() that guards reads -- never by a builtin getattr. Hard negative:
# the file DOES use getattr elsewhere, but only for an ordinary read, not a
# fetch-then-call dispatch.
import ast

ALLOWED_READ = {"upper", "lower", "strip"}


def evaluate(node, env):
    if isinstance(node, ast.Attribute):
        base = evaluate(node.value, env)
        if node.attr not in ALLOWED_READ:
            raise PermissionError(node.attr)
        return getattr(base, node.attr)          # ordinary read, result not called
    if isinstance(node, ast.Call):
        func = evaluate(node.func, env)           # recursive, inherits the read guard
        return func(*[evaluate(a, env) for a in node.args])
    raise ValueError("unsupported")
