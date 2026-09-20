"""
Detector 007: a cryptographically weak hash used for security.

THE BUG: MD5, SHA-1 and MD4 are broken -- collisions are practical, so they
cannot carry an integrity or authentication guarantee. But they are perfectly
fine for non-security work: cache keys, dedup ids, file checksums. That makes
this a PRECISION detector rather than a grep. Flagging every md5() in a
codebase floods legitimate use and costs the user's trust in every other
finding, so a weak hash is reported only when CONTEXT says it is security work.

WEAK ALGORITHMS: md5, sha1, md4 (case-insensitive), matched library-agnostically
on the ALGORITHM:
    hashlib.md5(...) / hashlib.sha1(...)
    hashlib.new("md5") / hashlib.new("SHA-1")   -- the string-named form
    cryptography's hashes.MD5() / hashes.SHA1()
SHA-256, SHA-3, BLAKE2 and friends are not weak and are not this detector's
concern.

STRUCTURAL EXEMPTION -- the developer's own declaration:
    hashlib.md5(data, usedforsecurity=False)        (Python 3.9+)
is the developer stating "this is not for security". ALWAYS SILENT. Same
principle as #2 trusting hmac.compare_digest: a structural declaration of safe
intent, recognized rather than second-guessed. usedforsecurity=True, or the
keyword absent, means normal analysis.

THREE CONTEXT AXES, combined by MAX confidence:
  A  SECRET INPUT     what goes INTO the hash -- md5(password), sha1(api_key).
                      Specific to hashing: for this detector the input matters
                      as much as where the output goes. Covers `h.update(x)`
                      on a hash object bound to a variable.
  B  SECURITY TARGET  the variable the digest is assigned to (password_hash,
                      signature), classified by secret_names.precision_of().
  C  SECURITY FUNCTION the enclosing def's own name (hash_password, sign),
                      through the same matcher.

TIERS: a high-precision signal on any axis -> HIGH | a collision-prone signal
-> REVIEW | no signal on any axis -> SILENT.

SILENT-WITHOUT-CONTEXT IS THE POINT, and it is a documented FALSE NEGATIVE: a
context-free `md5(x)` that really is security work will be missed. That is the
deliberate trade -- flooding every checksum in a codebase would make the tool
unusable and would bury the findings that matter.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import sys

from detect_timing_compare import identifiers_in
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from secret_names import matched_component, precision_of, PRECISION_RULE
from source_files import safe_parse

WEAK_ALGORITHMS = {"md5", "sha1", "md4"}
CONSTRUCTOR = "new"                     # hashlib.new("md5")
EXEMPT_KEYWORD = "usedforsecurity"

NAME = "weak-hash"
SUMMARY = "a broken hash (MD5/SHA-1/MD4) used for security work"
RULES = [
    "weak algorithms: md5, sha1, md4 (case-insensitive), matched",
    "  library-agnostically: hashlib.md5(...), hashes.MD5(), and the",
    "  string-named hashlib.new(\"md5\") form. SHA-256 and friends are not weak.",
    "STRUCTURAL EXEMPTION: usedforsecurity=False is the developer declaring this",
    "  is not security work -- ALWAYS SILENT, no further analysis.",
    "three context axes, combined by MAX confidence:",
    "  A secret INPUT      md5(password) / h.update(api_key) -- for hashing,",
    "    what goes in matters as much as where the output goes",
    "  B security TARGET   the variable the digest is assigned to",
    "  C security FUNCTION the enclosing def's name",
    "tiers: high-precision signal -> HIGH | collision-prone signal -> REVIEW |",
    "  NO signal on any axis -> SILENT.",
    "NO test-file down-tier. REASON (Principle A, wrong-regardless): a broken",
    "  hash primitive is broken in a test too, and a test is exactly where a weak",
    "  primitive gets quietly normalized. Contrast the fixture-plausible",
    "  detectors, which DO down-tier in tests.",
    "an UNCONFIRMABLE algorithm -- hashlib.new(<variable>) -- is REVIEW when a",
    "  security context fires, matching how tls-verify and ecb-mode treat a value",
    "  they cannot read. With NO security context it stays SILENT: a checksum",
    "  from a variable algorithm is ordinary, and flagging it would flood.",
]
LIMITS = [
    "SILENT WITHOUT CONTEXT is a deliberate FALSE NEGATIVE: a context-free",
    "  md5(x) that really is security work is missed. Flagging every checksum",
    "  would flood legitimate use and bury the findings that matter.",
    "collision-prone names are a weak discriminator FOR THIS DETECTOR in",
    "  particular: 'hash', 'digest' and 'key' are exactly what an innocent",
    "  checksum variable is called, so a collision-prone target yields REVIEW",
    "  on cache_key/file_hash as readily as on a real one.",
    "h.update(...) inputs are matched by variable name across the whole file,",
    "  not scoped to one function.",
    "the constructor form is recognized only as hashlib.new(...). `from hashlib",
    "  import new` then a bare new(\"md5\") is NOT detected -- the restriction",
    "  exists so AES.new(...) and other .new() factories are not treated as",
    "  hash constructors.",
]




def final_name(func):
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def normalize(text):
    return text.lower().replace("-", "").replace("_", "")


UNCONFIRMABLE = "<variable>"
HASHLIB = "hashlib"


def _is_hashlib_new(func):
    """True only for hashlib.new(...), not any other object's .new() factory."""
    return (isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == HASHLIB)


def weak_algorithm(call):
    """The weak algorithm, UNCONFIRMABLE, or None.

    UNCONFIRMABLE covers hashlib.new(<variable>): the algorithm cannot be read
    from here, so weakness cannot be ruled out. It is gated by context in
    scan() -- surfaced at REVIEW only when a security signal fires.
    """
    name = final_name(call.func)
    if name is None:
        return None
    if normalize(name) in WEAK_ALGORITHMS:
        return normalize(name)
    # The CONSTRUCTOR branch is restricted to hashlib.new specifically. A bare
    # `name == "new"` test would match AES.new(key, ...), Session.new(...) and
    # every other .new() factory -- and with the UNCONFIRMABLE branch below that
    # would turn each of them into a weak-hash candidate.
    if name == CONSTRUCTOR and call.args and _is_hashlib_new(call.func):
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            algo = normalize(first.value)
            return algo if algo in WEAK_ALGORITHMS else None
        return UNCONFIRMABLE              # hashlib.new(<variable>)
    return None


def declared_not_for_security(call):
    """usedforsecurity=False -- the developer's own declaration."""
    for kw in call.keywords:
        if kw.arg == EXEMPT_KEYWORD and isinstance(kw.value, ast.Constant):
            return kw.value.value is False
    return False


def assignment_target(call):
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


def update_inputs(tree, varname):
    """Arguments of `<varname>.update(...)` -- what is fed to a bound hash."""
    if not varname:
        return []
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "update"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == varname):
            out.extend(node.args)
    return out


def best_secret(nodes):
    """(identifier, precision) for the strongest secret name in these subtrees."""
    best = (None, None)
    for node in nodes:
        for ident, _ in identifiers_in(node):
            if not matched_component(ident):
                continue
            prec = precision_of(ident)
            if prec == "high":
                return ident, prec
            if best[0] is None:
                best = (ident, prec)
    return best


def classify(call, tree, func_name, target):
    """(severity, axis descriptions) -- MAX confidence across the three axes."""
    axes = []
    strength = 0

    inputs = [a for a in call.args if not (isinstance(a, ast.Constant)
                                           and isinstance(a.value, str))]
    inputs += [kw.value for kw in call.keywords if kw.arg != EXEMPT_KEYWORD]
    inputs += update_inputs(tree, target)
    ident, prec = best_secret(inputs)
    if prec:
        axes.append(("input", "%s/%s" % (ident, prec)))
        strength = max(strength, 2 if prec == "high" else 1)

    target_prec = precision_of(target) if target else None
    if target_prec:
        axes.append(("target", "%s/%s" % (target, target_prec)))
        strength = max(strength, 2 if target_prec == "high" else 1)

    func_prec = precision_of(func_name) if func_name != "<module>" else None
    if func_prec:
        axes.append(("func", "%s/%s" % (func_name, func_prec)))
        strength = max(strength, 2 if func_prec == "high" else 1)

    if strength == 2:
        return "HIGH", axes
    if strength == 1:
        return "REVIEW", axes
    return None, axes


def scan(path, tree):
    link_parents(tree)
    rows = []
    seen_calls = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        algo = weak_algorithm(node)
        if algo is None:
            continue
        seen_calls += 1
        if declared_not_for_security(node):
            continue                    # structural exemption
        func_name = enclosing_function(node)
        target = assignment_target(node)
        severity, axes = classify(node, tree, func_name, target)
        if not severity:
            continue                    # no security context -> silent, as before
        message = "weak hash used for security work"
        if algo == UNCONFIRMABLE:
            # The algorithm cannot be read from here. A security context fired,
            # so it is surfaced -- but never asserted as weak. This matches how
            # tls-verify and ecb-mode treat a value they cannot resolve.
            severity = "REVIEW"
            message = "hash algorithm from a variable, cannot confirm it is not weak"
        pairs = (("algorithm", algo), ("call", "%s(...)" % ast.unparse(node.func))) \
            + tuple(axes)
        rows.append((path, func_name, node.lineno, severity, message, pairs))
    rows.sort(key=lambda r: r[2])
    return rows, seen_calls


def collect(paths):
    """(findings, skipped, stats) -- the shared interface every detector exposes."""
    findings, skipped = [], []
    seen_total = 0
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        rows, seen = scan(path, tree)
        seen_total += seen
        for rpath, func, lineno, severity, message, pairs in rows:
            findings.append(Finding(NAME, rpath, lineno, func, severity,
                                    message, detail(*pairs)))
    stats = ["weak-hash calls seen: %d | flagged: %d | silent (no security context): %d"
             % (seen_total, len(findings), seen_total - len(findings))] if seen_total else []
    return findings, skipped, stats


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_weak_hash.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)] if stats else []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
