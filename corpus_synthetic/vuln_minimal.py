# SYNTHETIC FIXTURE (author-written; not third-party source).
# Label: VULNERABLE. A minimal AST-walking evaluator whose attribute READ is
# guarded against dunder names, but whose method-CALL dispatch fetches the
# callable through an unguarded builtin getattr -- the dispatch asymmetry the
# detector targets. Contains no exploit payload; it is a structural fixture.
import ast


def nodunder_getattr(obj, name):
    if name.startswith("__") and name.endswith("__"):
        raise PermissionError(name)
    return getattr(obj, name)


def evaluate(node, env):
    if isinstance(node, ast.Attribute):  # read path: guarded
        return nodunder_getattr(evaluate(node.value, env), node.attr)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):  # call path: UNGUARDED
            obj = evaluate(node.func.value, env)
            func = getattr(obj, node.func.attr)
            return func(*[evaluate(a, env) for a in node.args])
    raise ValueError("unsupported")
