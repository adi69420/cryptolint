"""
Detector 003 v2: secret reaches a sink.

The first FLOW detector. #1 and #2 match local node shapes; this one asks where
a value GOES. A secret-named value passed to a logging/output call, or embedded
in an exception message, leaks the secret into logs and error trackers.

SINKS (v1 -- exactly two categories):
    1. LOGGING / OUTPUT calls: callee `print`, or any call whose final name is
       one of debug, info, warning, warn, error, exception, critical, log --
       as a bare call (log(...)) or an attribute call (logger.error(...),
       logging.info(...), self.log.debug(...)).
    2. EXCEPTION messages: a Raise whose exception is a Call, e.g.
       raise ValueError(...) / raise RuntimeError(...), with a secret in its
       arguments.

SEVERITY -- two axes of confidence, name PRECISION x flow DIRECTNESS:

                      direct-to-sink      indirect (same-variable flow)
    high-precision    HIGH                REVIEW
    collision-prone   REVIEW              LOW

    DIRECT   a secret Name appears anywhere in the sink call's argument
             subtree. An f-string carrying a secret counts as direct.
    INDIRECT a variable RECEIVED a secret value and THAT SAME VARIABLE NAME
             later reaches a sink. The detector cannot prove it is still the
             same value, so it asks for a look rather than asserting.

    password -> log() direct is a confident HIGH. A bare `key` that only
    flowed through a variable is a weak LOW you can filter. Precision never
    silences anything: findings move DOWN a tier, they do not vanish.

    Precision classes come from secret_names.precision_of() -- this detector
    does not classify precision itself.

REVIEW/LOW BOUNDARY -- indirect flow is matched by VARIABLE NAME only. A
rename (x = token; y = x; log(y)) is NOT tracked and stays SILENT,
deliberately: chasing renames is deep taint analysis, out of scope for v1.
Where the name match cannot connect the flow, this detector is silent rather
than guessing.

KNOWN FALSE POSITIVE (accepted, safe direction): a secret wrapped in a hashing
call -- log(sha256(token).hexdigest()) -- still counts as direct, because the
secret Name is in the sink's argument subtree. Proving a hash neutralizes the
leak is not attempted; over-flagging is the safe direction here.

OUT OF SCOPE: hardcoded secret literals (password = "admin123") are a different
bug and belong to a different detector.

Secret names, the matching rule, and the precision classes are imported from
secret_names.py -- one source of truth, never re-defined here.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import sys

from secret_names import (matched_component, name_list, precision_of,
                          MATCHING_RULE, PRECISION_RULE)
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse
from tiering import IN_TEST_PAIR, down_tier, is_test_path

# precision x directness -> severity
SEVERITY = {("high", "direct"): "HIGH",
            ("high", "indirect"): "REVIEW",
            ("collision", "direct"): "REVIEW",
            ("collision", "indirect"): "LOW"}

# Final callee names that make a call a logging/output sink.
LOG_SINK_NAMES = {"debug", "info", "warning", "warn", "error",
                  "exception", "critical", "log"}
# Bare-name callees that are sinks in their own right.
OUTPUT_SINK_NAMES = {"print"} | LOG_SINK_NAMES




def log_sink_label(call):
    """Return a label if this Call is a logging/output sink, else None."""
    func = call.func
    if isinstance(func, ast.Name) and func.id in OUTPUT_SINK_NAMES:
        return "%s(...)" % func.id
    if isinstance(func, ast.Attribute) and func.attr in LOG_SINK_NAMES:
        return "%s(...)" % ast.unparse(func)
    return None


def call_arguments(call):
    """Positional + keyword argument value subtrees."""
    return list(call.args) + [kw.value for kw in call.keywords]


def secret_in(nodes):
    """Best (identifier, precision) for a secret name anywhere in these
    subtrees. High precision wins when several secret names are present.

    The returned identifier is the FULL name as written (api_key, not "key") --
    the matched component decides precision, the whole identifier is displayed.
    """
    best = (None, None)
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                if not matched_component(sub.id):
                    continue
                prec = precision_of(sub.id)
                if prec == "high":
                    return sub.id, prec
                if best[0] is None:
                    best = (sub.id, prec)
    return best


def names_in(nodes):
    """Every Name id appearing anywhere in these subtrees."""
    found = []
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                found.append(sub.id)
    return found


def collect_carriers(tree):
    """(function, varname) -> (assign_lineno, secret_word, precision) for
    variables that received a secret value: the assigned value is, or contains,
    a secret Name.
    """
    carriers = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        word, prec = secret_in([node.value])
        if word is None:
            continue
        for target in node.targets:
            for sub in ast.walk(target):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    key = (enclosing_function(node), sub.id)
                    carriers.setdefault(key, (node.lineno, word, prec))
    return carriers


def sinks_in(tree):
    """Yield (node, label, argument-subtrees) for every sink in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = log_sink_label(node)
            if label:
                yield node, label, call_arguments(node)
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            label = "raise %s(...)" % ast.unparse(node.exc.func)
            yield node, label, call_arguments(node.exc)


def scan(path, tree):
    link_parents(tree)
    in_test = is_test_path(path)
    carriers = collect_carriers(tree)

    findings = []
    for node, label, args in sinks_in(tree):
        func = enclosing_function(node)
        word, prec = secret_in(args)
        if word is not None:
            severity = SEVERITY[(prec, "direct")]
            extra = ()
            if in_test:
                severity = down_tier(severity)
                extra = (IN_TEST_PAIR,)
            findings.append((path, func, node.lineno, severity,
                             word, prec, "direct", label, extra))
            continue
        for var in names_in(args):
            carried = carriers.get((func, var))
            if carried and carried[0] <= node.lineno:
                assigned_at, carried_word, carried_prec = carried
                severity = SEVERITY[(carried_prec, "indirect")]
                extra = (("carrier", "%s assigned at L%d" % (var, assigned_at)),)
                if in_test:
                    severity = down_tier(severity)
                    extra = extra + (IN_TEST_PAIR,)
                findings.append((path, func, node.lineno, severity,
                                 carried_word, carried_prec, "indirect", label, extra))
                break

    findings.sort(key=lambda f: f[2])
    return findings


NAME = "secret-sink"
SUMMARY = "a secret-named value reaching a log, print, or exception message"
RULES = [
    "sinks: print(...), any bare or attribute call whose final name is one of",
    "  %s," % ", ".join(sorted(LOG_SINK_NAMES)),
    "  plus exception messages -- a Raise whose exception is a Call.",
    "severity = name PRECISION x flow DIRECTNESS:",
    "                    direct-to-sink   indirect (same-var flow)",
    "  high-precision    HIGH             REVIEW",
    "  collision-prone   REVIEW           LOW",
    "test files DOWN-TIER (shared tiering.down_tier), marked in-test. REASON",
    "  (Principle A, fixture-plausible): logging a fixture secret in a test is",
    "  low-risk scaffolding, not a shipped leak. Test files are NEVER skipped.",
    "DIRECT: a secret Name anywhere in the sink's argument subtree (an f-string",
    "  carrying a secret counts as direct). INDIRECT: a variable RECEIVED a secret",
    "  and reaches a sink under THE SAME NAME.",
]
LIMITS = [
    "indirect flow is matched by VARIABLE NAME only. A rename (x = token; y = x;",
    "  log(y)) is NOT tracked and stays silent by design -- deep taint is out of scope.",
    "a secret wrapped in a hashing call -- log(sha256(token).hexdigest()) -- still",
    "  counts as direct. Over-flagging is the safe direction; the hash is not proven",
    "  to neutralize the leak.",
    "hardcoded secret literals (password = \"admin123\") are a different bug, not this one.",
]


def collect(paths):
    findings, skipped = [], []
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        for row in scan(path, tree):
            rpath, func, lineno, severity, word, prec, flow, label, extra = row
            findings.append(Finding(NAME, rpath, lineno, func, severity,
                                    "secret reaches %s" % label,
                                    detail(("name", word), ("precision", prec),
                                           ("flow", flow), ("sink", label),
                                           *extra)))
    return findings, skipped, []


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_secret_sink.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped, []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
