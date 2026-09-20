"""
Detector 002 v4: non-constant-time comparison of secret values.

THE BUG: `if user_token == real_token:` short-circuits at the first mismatched
byte, so the comparison's duration leaks how many leading bytes matched. An
attacker recovers the secret byte-by-byte. The fix is a constant-time compare
(hmac.compare_digest / secrets.compare_digest).

v4 brings this detector up to the standard #3 and #4 already set. v3 was the
only detector with no precision tiering and no test-file awareness, and it
produced 771 findings on Saleor at roughly 98% false positives.

DETERMINISTIC RESOLUTION ORDER (the anti-contradiction rule):

  0. OPERAND EXTRACTION -- a secret-ish operand may be a Name (`token`) OR an
     Attribute, classified on the ATTRIBUTE name (`self.secret_key` -> the
     identifier is "secret_key", never the base "self"). v3 matched only Name
     nodes and MISSED every self.attr comparison -- a false negative, the
     dangerous direction in a security tool.

  1. CONSTANT / LITERAL GATE -- a ==/!= is only a secret-vs-secret timing leak
     if BOTH sides are non-constant secret-ish values.
       operand is None / string / number / True / False
           -> EXEMPT. A presence, mode or config check, not a timing leak.
              (key_derivation == "concat", token == "", x == 0)
       an operand carries an ALL-CAPS constant name (INVALID_TOKEN, PUBLIC_KEY)
           -> base tier LOW, NOT exempt. By convention a module constant, but a
              codebase COULD name a real secret in caps (API_KEY), and exempting
              would risk a FALSE NEGATIVE -- the dangerous direction. Down-tier
              surfaces it quietly and a human can still see it: fail loud on the
              uncertainty.
       otherwise -> step 2.

  2. PRECISION TIER (secret_names.precision_of, the same mechanism #3 uses)
       a HIGH-PRECISION name in the comparison -> HIGH
       only COLLISION-PRONE names              -> REVIEW
     On private/signing specifically: BARE `private` and `signing` are
     COLLISION-PRONE, so private_metadata and is_private tier as REVIEW. They
     were demoted after measurement showed bare occurrences producing false
     HIGHs and no real catches. The catastrophe case is preserved by the
     COMBINATION rule instead: a (private|signing) component together with a
     (key|secret) component -- private_key, signing_key, signing_secret -- is
     HIGH-PRECISION and still tiers HIGH.
     (An earlier version of this docstring claimed private/signing remain
     high-precision. That was stale from before the demotion; every clause
     above was re-verified against precision_of() before being written.)

  3. TEST-FILE DOWN-TIER -- a finding in a test file (path contains /tests/ or
     /test/, or the filename matches test_*.py / *_test.py) drops ONE step
     (HIGH -> REVIEW, REVIEW -> LOW) and is marked "in-test". Test files are
     NOT skipped: a real timing bug can live in a test helper, and skipping
     would be silence -- the thing this project exists to avoid.

PROVEN-SAFE EXEMPTION (unchanged): operands handed to hmac.compare_digest(...)
or secrets.compare_digest(...) are the FIX, never flagged. The module
qualification is REQUIRED -- a look-alike compare_digest (bare call, local def,
other module) is NOT trusted, because it may not be constant-time at all.

KNOWN LIMIT: the literal gate recognizes ast.Constant operands. A container
literal (`x == ['MANAGE_PRODUCTS']`, `x == {...}`) is not a Constant node and
does not exempt; such a comparison falls through to the tiers.

Secret matching and precision come from secret_names.py -- one source of truth.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import os
import sys

from secret_names import matched_component, precision_of, name_list, MATCHING_RULE
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse
from tiering import IN_TEST_PAIR, down_tier, is_test_path

# Only these fully-qualified calls are trusted as constant-time.
CONSTANT_TIME_CALLS = {("hmac", "compare_digest"), ("secrets", "compare_digest")}

EQ_OPS = {ast.Eq: "==", ast.NotEq: "!="}



def is_constant_time_call(call):
    """Exactly hmac.compare_digest(...) or secrets.compare_digest(...)."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return False
    if not isinstance(func.value, ast.Name):
        return False
    return (func.value.id, func.attr) in CONSTANT_TIME_CALLS


def eq_ops(compare):
    """Labels of the ==/!= operators on a Compare node, if any."""
    return [EQ_OPS[type(op)] for op in compare.ops if type(op) in EQ_OPS]


def is_all_caps(identifier):
    """SCREAMING_CASE -- by convention a module constant."""
    return (identifier.isupper()
            and any(c.isalpha() for c in identifier)
            and all(c.isalnum() or c == "_" for c in identifier))


def identifiers_in(node):
    """(identifier, node) for every Name and Attribute in a subtree.

    An Attribute contributes its ATTRIBUTE name, so self.secret_key is
    classified as "secret_key" -- never as the base "self".
    """
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            out.append((sub.attr, sub))
        elif isinstance(sub, ast.Name):
            out.append((sub.id, sub))
    return out


def is_literal_operand(node):
    """None, a string, a number, or True/False -- a presence/mode/config check."""
    return isinstance(node, ast.Constant)


def best_secret(operands, exempt):
    """(identifier, precision) for the strongest secret name across operands."""
    best = (None, None)
    for operand in operands:
        for ident, sub in identifiers_in(operand):
            if id(sub) in exempt or not matched_component(ident):
                continue
            prec = precision_of(ident)
            if prec == "high":
                return ident, prec
            if best[0] is None:
                best = (ident, prec)
    return best


def has_all_caps_constant(operands):
    """Any ALL-CAPS identifier anywhere in the operands."""
    for operand in operands:
        for ident, _ in identifiers_in(operand):
            if is_all_caps(ident):
                return ident
    return None


def scan(path, tree):
    link_parents(tree)
    in_test = is_test_path(path)

    exempt = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and is_constant_time_call(node):
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                for _, sub in identifiers_in(arg):
                    exempt.add(id(sub))

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        ops = eq_ops(node)
        if not ops:
            continue
        operands = [node.left] + list(node.comparators)

        # 1. constant / literal gate
        if any(is_literal_operand(o) for o in operands):
            continue

        ident, prec = best_secret(operands, exempt)
        if ident is None:
            continue

        caps = has_all_caps_constant(operands)
        if caps:
            severity, why = "LOW", "all-caps-constant '%s'" % caps
        else:
            # 2. precision tier
            severity = "HIGH" if prec == "high" else "REVIEW"
            why = "eq-compare-of-secret"

        # 3. test-file down-tier. The in-test marker rides in the DETAIL pair,
        # the same place every other detector puts it.
        extra = ()
        if in_test:
            severity = down_tier(severity)
            extra = (IN_TEST_PAIR,)

        left = ast.unparse(node.left)
        right = " ".join(ast.unparse(c) for c in node.comparators)
        findings.append((path, enclosing_function(node), node.lineno, severity,
                         ident, prec, why, ("/".join(ops), left, right), extra))

    findings.sort(key=lambda f: f[2])
    return findings


NAME = "timing-compare"
SUMMARY = "a secret compared with ==/!=, which short-circuits and leaks bytes by timing"
RULES = [
    "deterministic resolution order:",
    "  0. operands: Name id, or Attribute ATTR name (self.secret_key -> secret_key)",
    "  1. literal operand (None/str/num/bool)  -> EXEMPT, done",
    "     ALL-CAPS constant name in an operand -> base tier LOW (not exempt:",
    "       exempting a caps-named real secret would be a false negative)",
    "  2. precision: high-precision name -> HIGH | collision-prone only -> REVIEW",
    "  3. in a test file -> DOWN-TIER (shared tiering.down_tier), marked with the",
    "     in_test=true detail pair, as every detector does.",
    "     REASON (Principle A, fixture-plausible): a test comparing fixture",
    "     tokens is scaffolding, not a shipped timing leak. Test files are NEVER",
    "     skipped -- down-tiering makes a finding quieter, never absent.",
    "exemption: arguments to %s are never flagged"
    % " / ".join("%s.%s(...)" % c for c in sorted(CONSTANT_TIME_CALLS)),
    "  (that is the fix); the module qualification is REQUIRED -- a look-alike",
    "  compare_digest is not trusted.",
]
LIMITS = [
    "only ast.Constant operands exempt; a container literal (x == ['A']) is not a",
    "  Constant node and falls through to the tiers.",
]


def collect(paths):
    findings, skipped = [], []
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        for row in scan(path, tree):
            rpath, func, lineno, severity, ident, prec, why, operands, extra = row
            op, left, right = operands
            findings.append(Finding(NAME, rpath, lineno, func, severity, why,
                                    detail(("name", ident), ("precision", prec),
                                           ("op", op), ("left", left), ("right", right),
                                           *extra)))
    return findings, skipped, []


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_timing_compare.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)] if stats else []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
