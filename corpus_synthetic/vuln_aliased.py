# SYNTHETIC FIXTURE (author-written). Label: VULNERABLE.
# Same dispatch asymmetry as vuln_minimal but with different identifiers and an
# extra guarded read helper, to show the detector keys on structure, not names.
import ast


def _read_guard(target, attr):
    if attr[:2] == "__" == attr[-2:]:
        raise PermissionError(attr)
    return getattr(target, attr)


class Walker:
    def visit(self, node, scope):
        if isinstance(node, ast.Attribute):
            return _read_guard(self.visit(node.value, scope), node.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = self.visit(node.func.value, scope)
            callee = getattr(owner, node.func.attr)
            return callee(*[self.visit(a, scope) for a in node.args])
        raise ValueError("unsupported")
