# SYNTHETIC FIXTURE (author-written). Label: CLEAN.
# An ordinary helper module that fetches a method by name and calls it. It has
# the getattr-then-call shape but is NOT an AST-walking interpreter (no branch
# on ast.Attribute), so the detector's gate excludes it.
def dispatch(obj, method_name, *args):
    func = getattr(obj, method_name)
    return func(*args)


def apply_all(obj, names):
    return [dispatch(obj, n) for n in names]
