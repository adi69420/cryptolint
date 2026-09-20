"""
Detector 004 v2: insecure random used for a security purpose.

THE BUG: non-cryptographic generators are fast, deterministic and
reconstructable from their outputs. Fine for simulations, sampling and jitter;
catastrophic for keys, tokens, nonces and salts. The fix is `secrets` or
os.urandom.

THE EDGE over a generic linter: this does NOT flag all RNG usage. Flagging
every random/numpy call floods a simulation-heavy codebase. A finding requires
CONTEXT indicating the output feeds a secret.

INSECURE RNG CALLS -- four forms:

  1. stdlib direct        random.randint(...)          attribute on `random`
  2. stdlib from-import   randint(...)  after `from random import randint`
  3. numpy LEGACY direct  np.random.rand() / numpy.random.bytes()
                          -- module-level, treated exactly like stdlib direct
  4. STORED INSTANCE      rng = np.random.default_rng(...); rng.bytes(32)
                          also np.random.Generator / RandomState, and the
                          stdlib r = random.Random() form (one mechanism
                          serves both, deliberately)

  CREATION IS NEVER A FINDING. Building a generator is not insecure; USING it
  for a secret is. A creation assignment TAINTS the variable name; a later
  method call on that name is the candidate.

INSTANCE TRACKING -- same-function, name-matched, SILENT ON ESCAPE. This is
the same boundary discipline as #3's carrier tracking: where the name match
cannot follow the value, the detector goes quiet rather than guessing.
  A tracked name may ONLY be used as `name.method(...)`. Any other load of it
  ends tracking from that point on:
      r2 = rng          alias    -- r2 is NOT tracked, and rng stops being
      f(rng)            passed as an argument
      self.rng = rng    stored on an attribute
      return rng        returned
      rng = other()     reassigned to a non-generator
  A nested function inherits names tainted in an enclosing scope BEFORE its
  `def` line; escapes inside the nested scope do not propagate outward.
  NOT TRACKED, by design: cross-function flow, self.attr generators, aliases.

NO NUMPY EXEMPTION. Unlike stdlib's random.SystemRandom (a CSPRNG, exempt),
numpy has NO cryptographically secure generator -- default_rng, Generator and
RandomState are all non-crypto. The fix for numpy-for-secrets is always
`secrets` / os.urandom, which remain the exempt forms.

THREE CONTEXT AXES, reused UNCHANGED, combined by MAX confidence:
    A  TARGET NAME    the variable assigned, via secret_names.precision_of()
    B  FUNCTION NAME  the enclosing def's own name, same matcher
    C  CALL SHAPE     raw key material only: randbytes / getrandbits (stdlib)
                      and bytes (numpy). integers / random / choice / normal
                      are innocent simulation shapes and carry NO shape signal.

TIERS: HIGH = any axis strong | REVIEW = any axis medium | LOW = shape only |
SILENT = no signal on any axis. Silence is BY DESIGN: rng.normal() for a Monte
Carlo and np.random.rand() for noise are not bugs, and numpy is the most
simulation-heavy library in Python.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import sys

from secret_names import precision_of, name_list, PRECISION_RULE
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse
from tiering import IN_TEST_PAIR, down_tier, is_test_path

# stdlib random module functions
RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices", "shuffle",
    "sample", "getrandbits", "randbytes", "uniform", "gauss",
    "normalvariate", "lognormvariate", "expovariate", "gammavariate",
    "betavariate", "paretovariate", "weibullvariate", "triangular",
    "vonmisesvariate",
}

# numpy legacy module-level functions (np.random.*)
NUMPY_FUNCS = {
    "rand", "randn", "randint", "random", "random_sample", "ranf", "sample",
    "bytes", "choice", "shuffle", "permutation", "permuted", "normal",
    "uniform", "poisson", "binomial", "beta", "gamma", "exponential",
    "standard_normal", "standard_exponential", "laplace", "logistic",
    "lognormal", "pareto", "triangular", "weibull", "chisquare", "f",
    "geometric", "gumbel", "hypergeometric", "multinomial",
    "multivariate_normal", "negative_binomial", "noncentral_chisquare",
    "noncentral_f", "power", "rayleigh", "standard_cauchy", "standard_gamma",
    "standard_t", "vonmises", "wald", "zipf",
}

# Methods on a stored generator instance (numpy Generator/RandomState + stdlib Random)
INSTANCE_METHODS = RANDOM_FUNCS | NUMPY_FUNCS | {"integers", "spawn"}

# Calls that CREATE an insecure generator. Creation is never itself a finding.
NUMPY_CREATORS = {"default_rng", "Generator", "RandomState"}
STDLIB_CREATORS = {"Random"}

# Axis C: raw key material only.
SUSPICIOUS_SHAPES = {"randbytes", "getrandbits", "bytes"}

CSPRNG_WRAPPER = "SystemRandom"
NUMPY_ALIASES = {"np", "numpy"}




def module_aliases(tree):
    """Resolve module-level import aliases for the KNOWN insecure-RNG modules.

    `import random as rnd` -> rnd is the random module.
    `import numpy as npy`  -> npy.random is numpy's RNG namespace.

    Scope is deliberately narrow: module-level aliases for random and numpy
    only. Arbitrary indirection (r = random; r.randint(...)) is variable
    tracking, out of scope, and disclosed in LIMITS.
    """
    randoms = {"random"}
    numpys = set(NUMPY_ALIASES)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == "random":
                randoms.add(alias.asname or alias.name)
            elif alias.name == "numpy":
                numpys.add(alias.asname or alias.name)
    return randoms, numpys


def random_imported_names(tree):
    """`from random import x [as y]` -> {local name: real name}."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "random":
            for alias in node.names:
                names[alias.asname or alias.name] = alias.name
    return names


def is_numpy_random_base(node, numpys=None):
    """np.random / numpy.random (or an aliased numpy) as an attribute base."""
    known = NUMPY_ALIASES if numpys is None else numpys
    return (isinstance(node, ast.Attribute) and node.attr == "random"
            and isinstance(node.value, ast.Name) and node.value.id in known)


def uses_csprng_wrapper(func):
    """True if the callee's base chain contains a SystemRandom() call."""
    node = func
    while True:
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            inner = node.func
            name = getattr(inner, "attr", None) or getattr(inner, "id", None)
            if name == CSPRNG_WRAPPER:
                return True
            node = inner
        else:
            return False


def creation_label(call, aliases=None):
    """Label if this Call CREATES an insecure generator, else None."""
    randoms, numpys = aliases if aliases else ({"random"}, NUMPY_ALIASES)
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if is_numpy_random_base(func.value, numpys) and func.attr in NUMPY_CREATORS:
        return "np.random.%s" % func.attr
    if (isinstance(func.value, ast.Name) and func.value.id in randoms
            and func.attr in STDLIB_CREATORS):
        return "random.%s" % func.attr
    return None


def direct_rng_call(call, imported, aliases=None):
    """(function-name, label) for a direct insecure RNG call, else (None, None)."""
    randoms, numpys = aliases if aliases else ({"random"}, NUMPY_ALIASES)
    func = call.func
    if uses_csprng_wrapper(func):
        return None, None                       # SystemRandom is a CSPRNG
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in randoms:
            if func.attr in RANDOM_FUNCS:
                return func.attr, "random.%s" % func.attr
            return None, None
        if is_numpy_random_base(func.value, numpys) and func.attr in NUMPY_FUNCS:
            return func.attr, "np.random.%s" % func.attr
        return None, None
    if isinstance(func, ast.Name):
        real = imported.get(func.id)            # alias resolved to the real name
        if real in RANDOM_FUNCS:
            return real, real
        return None, None
    return None, None


# ---------------------------------------------------------------- instances

def is_method_call_base(name_node):
    """True when this Name is the base of `name.method(...)` -- the only use
    that does NOT end tracking."""
    parent = getattr(name_node, "_parent", None)
    if not (isinstance(parent, ast.Attribute) and parent.value is name_node):
        return False
    grand = getattr(parent, "_parent", None)
    return isinstance(grand, ast.Call) and grand.func is parent


def own_nodes(scope):
    """Every node inside `scope` without descending into nested scopes.

    Nested defs/classes are yielded themselves (as boundary markers) but their
    bodies belong to their own scope.
    """
    out = []

    def rec(node):
        for child in ast.iter_child_nodes(node):
            out.append(child)
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            rec(child)

    rec(scope)
    return out


def sort_key(node):
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def track_scope(scope, inherited, uses, aliases=None):
    """Simulate this scope in source order; record instance uses.

    `uses` maps id(Call) -> (method-name, label). Nested scopes inherit the
    tainted set as of their `def` line.
    """
    tainted = dict(inherited)
    nodes = sorted(own_nodes(scope), key=sort_key)

    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            track_scope(node, tainted, uses, aliases)  # inherits the state so far
            continue

        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            label = (creation_label(node.value, aliases)
                     if isinstance(node.value, ast.Call) else None)
            if label:
                tainted[target] = label          # creation TAINTS, never flags
                continue
            tainted.pop(target, None)            # reassigned to something else

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) \
                and node.id in tainted:
            if is_method_call_base(node):
                attr = node._parent
                call = attr._parent
                if attr.attr in INSTANCE_METHODS:
                    uses[id(call)] = (attr.attr,
                                      "%s()->.%s" % (tainted[node.id], attr.attr))
            else:
                # aliased, passed, stored, returned -> tracking ENDS. Silent.
                tainted.pop(node.id, None)


def instance_uses(tree, aliases=None):
    uses = {}
    track_scope(tree, {}, uses, aliases)
    return uses


# ---------------------------------------------------------------- classify

def assignment_target(call):
    """The variable this call's result is assigned to, or None."""
    cur = getattr(call, "_parent", None)
    while cur is not None:
        if isinstance(cur, ast.Assign):
            for target in cur.targets:
                if isinstance(target, ast.Name):
                    return target.id
            return None
        if isinstance(cur, ast.AnnAssign) and isinstance(cur.target, ast.Name):
            return cur.target.id
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return None
        cur = getattr(cur, "_parent", None)
    return None


def classify(fn_name, func_name, target):
    """(severity, [axis descriptions]) -- MAX confidence across the three axes."""
    axes = []
    strength = 0

    target_prec = precision_of(target) if target else None
    if target_prec:
        axes.append("target=%s/%s" % (target, target_prec))
        strength = max(strength, 2 if target_prec == "high" else 1)

    func_prec = precision_of(func_name) if func_name != "<module>" else None
    if func_prec:
        axes.append("func=%s/%s" % (func_name, func_prec))
        strength = max(strength, 2 if func_prec == "high" else 1)

    shape = fn_name in SUSPICIOUS_SHAPES
    if shape:
        axes.append("shape=%s" % fn_name)

    if strength == 2:
        return "HIGH", axes
    if strength == 1:
        return "REVIEW", axes
    if shape:
        return "LOW", axes
    return None, axes


def scan(path, tree):
    link_parents(tree)
    in_test = is_test_path(path)
    aliases = module_aliases(tree)
    imported = random_imported_names(tree)
    uses = instance_uses(tree, aliases)

    findings = []
    seen = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn_name, label = direct_rng_call(node, imported, aliases)
        if fn_name is None and id(node) in uses:
            fn_name, label = uses[id(node)]
        if fn_name is None:
            continue
        seen += 1
        func_name = enclosing_function(node)
        severity, axes = classify(fn_name, func_name, assignment_target(node))
        if severity:
            if in_test:
                severity = down_tier(severity)
                axes = axes + ["%s=%s" % IN_TEST_PAIR]
            findings.append((path, func_name, node.lineno, severity, label, axes))

    findings.sort(key=lambda f: f[2])
    return findings, seen


NAME = "weak-random"
SUMMARY = "a non-cryptographic RNG whose output feeds something security-sensitive"
RULES = [
    "forms: random.X(...) | X(...) from `from random import X` | np.random.X(...)",
    "MODULE-LEVEL IMPORT ALIASES are resolved, for random and numpy only:",
    "  `import random as rnd` makes rnd.randint(...) a random call, and",
    "  `from random import randint as ri` makes ri(...) one.",
    "  legacy | a STORED INSTANCE from np.random.default_rng / Generator /",
    "  RandomState / random.Random, used as name.method(...).",
    "CREATION IS NEVER A FINDING -- it taints the name; the USE is the candidate.",
    "three context axes, combined by MAX confidence (highest wins, never summed):",
    "  A target name    the variable assigned  -> high = strong, collision = medium",
    "  B function name  the enclosing def name -> same matcher, same mapping",
    "  C call shape     %s only -> weak signal, never strong"
    % ", ".join(sorted(SUSPICIOUS_SHAPES)),
    "test files DOWN-TIER (shared tiering.down_tier), marked in-test. REASON",
    "  (Principle A, fixture-plausible): a test token or sample drawn from a",
    "  weak RNG is a fixture. Test files are NEVER skipped.",
    "SILENT IS BY DESIGN when no axis fires: rng.normal() for a Monte Carlo and",
    "  np.random.rand() for noise are not bugs.",
    "NO NUMPY EXEMPTION: default_rng / Generator / RandomState are all",
    "  non-cryptographic. Only random.SystemRandom (a CSPRNG), secrets.* and",
    "  os.urandom are exempt -- the last two being the fix.",
]
LIMITS = [
    "instance tracking is same-function name matching. It ENDS -- and further uses go",
    "  SILENT, never guessed -- when the name is aliased (r2 = rng), passed as an",
    "  argument, stored on an attribute (self.rng = rng), returned, or reassigned.",
    "alias resolution covers MODULE-LEVEL imports of random and numpy only.",
    "  ARBITRARY INDIRECTION is still not tracked: `r = random` then",
    "  `r.randint(...)`, a module passed as an argument, or an importlib",
    "  lookup. That is variable tracking, deliberately out of scope.",
]


def collect(paths):
    findings, skipped = [], []
    seen_total = 0
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        rows, seen = scan(path, tree)
        seen_total += seen
        for rpath, func, lineno, severity, label, axes in rows:
            pairs = [("call", label)]
            for axis in axes:
                key, _, value = axis.partition("=")
                pairs.append((key, value))
            findings.append(Finding(NAME, rpath, lineno, func, severity,
                                    "insecure RNG feeds a security-sensitive value",
                                    detail(*pairs)))
    stats = ["insecure RNG calls seen: %d | flagged: %d | silent by design: %d"
             % (seen_total, len(findings), seen_total - len(findings))]
    return findings, skipped, stats


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_weak_random.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
