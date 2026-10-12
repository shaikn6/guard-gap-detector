# SYNTHETIC FIXTURE (author-written). Label: CLEAN (patched).
# The method-call dispatch is routed through the SAME guarded wrapper used for
# attribute reads, so there is no unguarded builtin getattr-then-call.
import ast


def safe_getattr(obj, name):
    if name.startswith("__") and name.endswith("__"):
        raise PermissionError(name)
    return getattr(obj, name)


def evaluate(node, env):
    if isinstance(node, ast.Attribute):
        return safe_getattr(evaluate(node.value, env), node.attr)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        obj = evaluate(node.func.value, env)
        func = safe_getattr(obj, node.func.attr)
        return func(*[evaluate(a, env) for a in node.args])
    raise ValueError("unsupported")
