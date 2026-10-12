# SYNTHETIC FIXTURE (author-written). Label: CLEAN. Hard negative.
# An AST interpreter that uses builtin getattr for a guarded read whose result
# is NEVER invoked as a callable, so the dispatch asymmetry is absent.
import ast


def evaluate(node, env):
    if isinstance(node, ast.Attribute):
        base = evaluate(node.value, env)
        attr_val = getattr(base, node.attr)       # read only; attr_val is never called
        return attr_val
    if isinstance(node, ast.Constant):
        return node.value
    raise ValueError("unsupported")
