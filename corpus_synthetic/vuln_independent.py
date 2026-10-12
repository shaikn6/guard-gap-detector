# SYNTHETIC FIXTURE (author-written). Label: VULNERABLE.
# An independently-shaped "safe eval" interpreter (not of the common agent-framework lineage) that
# still fetches the method callable through a raw builtin getattr. Hard positive.
import ast

FORBIDDEN = {"__globals__", "__dict__", "__class__", "__subclasses__", "__bases__"}


def run(node, names):
    if isinstance(node, ast.Attribute):
        if node.attr in FORBIDDEN:
            raise ValueError("blocked")
        return run(node.value, names)
    if isinstance(node, ast.Call):
        base = run(node.func.value, names)
        fn = getattr(base, node.func.attr)
        return fn(*[run(a, names) for a in node.args])
    if isinstance(node, ast.Name):
        return names[node.id]
    raise ValueError("unsupported")
