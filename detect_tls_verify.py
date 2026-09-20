"""
Detector 005: disabled TLS certificate verification.

THE BUG: turning off certificate verification makes a connection accept ANY
certificate, an attacker's included. It defeats HTTPS entirely -- the transport
is still encrypted, but to whoever answered. It is usually added to silence a
certificate error during development and never removed.

FIVE SHAPES:

  1. verify=False keyword on any call
       requests.get(url, verify=False), session.post(..., verify=False),
       httpx.get(..., verify=False)
     LIBRARY-AGNOSTIC by design: the keyword itself is the signal, not the
     caller. Trying to prove a call is HTTP is a rabbit hole, and every HTTP
     client worth naming spells this the same way.

  2. an unverified SSL context (stdlib)
       ssl._create_unverified_context()
       ssl._create_default_https_context = ssl._create_unverified_context
     The second form disables verification process-wide, which is worse.

  3. ssl.CERT_NONE
       context.verify_mode = ssl.CERT_NONE

  4. an attribute assignment: <anything>.verify = False
       s = requests.Session(); s.verify = False
     Arguably the commonest production form -- it disables verification once
     for every request a session makes. NO instance tracking is done or needed:
     setting .verify = False on anything IS the vulnerability, whether or not
     the object is a real Session and whether or not .get() is ever called.

  5. a LITERAL kwargs dict: requests.get(url, **{"verify": False})
     The dict is readable, so it is read. A **VARIABLE dict is deliberately
     NOT inspected -- kwargs unpacking is common and usually innocent, and
     flagging every one would flood. Disclosed in LIMITS instead.

VALUE HANDLING for shape 1 is deterministic:
    literal False, or a falsy literal 0  -> the bug
    literal True                         -> SILENT (the correct default)
    a string literal ("/etc/ca.pem")     -> SILENT (a custom CA bundle path,
                                            a legitimate and common pattern)
    a variable, or None                  -> REVIEW: the value cannot be
                                            confirmed non-False from one file,
                                            so this fails loud rather than
                                            guessing either way
    any other truthy literal             -> SILENT

TIERS:
    the bug, in non-test code   -> HIGH
    the bug, in a test file     -> REVIEW, marked in-test. A test against a
                                   self-signed or localhost certificate is a
                                   defensible use. Test files are NOT skipped.
    unconfirmable value         -> REVIEW regardless of location

NO PRECISION TIERING, deliberately: `verify=False` is a literal boolean on a
keyword, not an identifier. The secret-name precision machinery has no name to
classify here, so it is not used -- that is a design decision, not an omission.

Test-file detection REUSES detect_timing_compare.is_test_path -- one mechanism
for the whole tool rather than a second, drifting definition.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import sys

from tiering import IN_TEST_PAIR, down_tier, is_test_path
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse

UNVERIFIED_CONTEXT = "_create_unverified_context"
DEFAULT_HTTPS_CONTEXT = "_create_default_https_context"
CERT_NONE = "CERT_NONE"

NAME = "tls-verify"
SUMMARY = "TLS certificate verification disabled -- the connection accepts any certificate"
RULES = [
    "five shapes:",
    "  1. a `verify=` keyword whose value is literal False (or falsy 0), on ANY",
    "     call -- library-agnostic: the keyword is the signal, not the caller",
    "  2. an unverified SSL context: ssl._create_unverified_context(), or",
    "     assigning it to ssl._create_default_https_context (process-wide)",
    "  3. a reference to ssl.CERT_NONE (context.verify_mode = ssl.CERT_NONE)",
    "  4. an attribute assignment <anything>.verify = False (s.verify = False),",
    "     the commonest production form. No instance tracking: the assignment",
    "     itself is the vulnerability.",
    "  5. a LITERAL kwargs dict, requests.get(url, **{\"verify\": False})",
    "shapes 1, 4 and 5 share ONE value classifier, so False/True/path/variable",
    "  are handled identically in all three.",
    "verify= value handling is deterministic:",
    "  False / falsy 0        -> the bug",
    "  True / a string path   -> SILENT (correct default, or a custom CA bundle)",
    "  a variable / None      -> REVIEW, the value cannot be confirmed from here",
    "tiers: the bug -> HIGH | in a test file -> DOWN-TIER (shared", 
    "  tiering.down_tier), marked in-test. REASON (Principle A, fixture-",
    "  plausible): a test against a self-signed or localhost certificate is a",
    "  defensible use. An unconfirmable value -> REVIEW regardless of location.",
    "NO precision tiering: verify=False is a literal on a keyword, not an",
    "  identifier, so the secret-name machinery has nothing to classify.",
]
LIMITS = [
    "library-agnostic matching means a NON-HTTP function with its own `verify=`",
    "  parameter, or a non-HTTP object with its own `.verify` attribute set to",
    "  False, will flag. Accepted: missing a real TLS bypass is worse than a",
    "  rare false flag, and proving a call is HTTP is out of scope.",
    "a verify value coming from a variable is REVIEW, never resolved -- the",
    "  detector does not track where that variable came from.",
    "NOT INSPECTED: verify passed through a **VARIABLE dict",
    "  (requests.get(url, **config)). The literal form **{\"verify\": False} IS",
    "  read; a variable dict cannot be, and flagging every **kwargs call as",
    "  REVIEW would flood a codebase for almost no yield.",
    "NOT DETECTED: a verify value assembled at runtime (verify=os.getenv(...)",
    "  resolving to a falsy string), or an ssl context whose verify_mode is set",
    "  through a variable rather than the ssl.CERT_NONE constant.",
]




def classify_verify_value(node):
    """('bug'|'silent'|'unconfirmable', rendered-value) for a verify= value."""
    if isinstance(node, ast.Constant):
        value = node.value
        if value is False:
            return "bug", "False"
        if value is True:
            return "silent", "True"
        if value is None:
            return "unconfirmable", "None"
        if isinstance(value, str):
            return "silent", repr(value)          # a CA bundle path
        if isinstance(value, (int, float)) and not value:
            return "bug", repr(value)             # falsy literal, e.g. 0
        return "silent", repr(value)
    return "unconfirmable", ast.unparse(node)


def final_name(node):
    """The attribute/name a node refers to, for shapes 2 and 3."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def report_verify(add, node, kind, rendered, *pairs):
    """One reporting path for every shape that carries a `verify` value.

    Shapes 1, 4 and 5 all route through classify_verify_value() and then here,
    so the value handling (False/0 -> bug, True/path -> silent, variable/None
    -> unconfirmable) exists once and cannot drift between them.
    """
    # The shape pair stays first and `verify` second, matching the layout the
    # keyword form has always printed.
    ordered = (pairs[0], ("verify", rendered)) + tuple(pairs[1:])
    if kind == "bug":
        add(node, "bug", "TLS certificate verification disabled", ordered)
    else:
        add(node, "unconfirmable",
            "verify= set from a variable/None, cannot confirm it is not False",
            ordered)


def scan(path, tree):
    link_parents(tree)
    in_test = is_test_path(path)
    rows = []

    def add(node, kind, message, pairs):
        severity = "HIGH" if kind == "bug" else "REVIEW"
        if in_test:
            severity = down_tier(severity) if kind == "bug" else severity
            pairs = pairs + (IN_TEST_PAIR,)
        rows.append((path, enclosing_function(node), node.lineno, severity,
                     message, pairs))

    seen = set()
    for node in ast.walk(tree):
        # shape 4 -- an attribute assignment: <anything>.verify = <value>
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            attrs = [t for t in targets
                     if isinstance(t, ast.Attribute) and t.attr == "verify"]
            if attrs and node.value is not None:
                kind, rendered = classify_verify_value(node.value)
                if kind != "silent":
                    where = ast.unparse(attrs[0])
                    report_verify(add, node, kind, rendered,
                                  ("shape", "verify-attribute"), ("target", where))
            continue

        # shapes 1 and 5 -- a verify= keyword, or a literal **{"verify": ...}
        if isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            for kw in node.keywords:
                if kw.arg == "verify":
                    kind, rendered = classify_verify_value(kw.value)
                    if kind != "silent":
                        report_verify(add, node, kind, rendered,
                                      ("shape", "verify-kwarg"),
                                      ("call", "%s(...)" % callee))
                elif kw.arg is None and isinstance(kw.value, ast.Dict):
                    # shape 5 -- **{"verify": False}. A LITERAL dict is readable,
                    # so it is analyzed. A **variable dict is NOT inspected: kwargs
                    # unpacking is common and usually innocent, and flagging every
                    # one as REVIEW would flood. Disclosed in LIMITS instead.
                    for key, value in zip(kw.value.keys, kw.value.values):
                        if not (isinstance(key, ast.Constant) and key.value == "verify"):
                            continue
                        kind, rendered = classify_verify_value(value)
                        if kind != "silent":
                            report_verify(add, node, kind, rendered,
                                          ("shape", "verify-kwargs-dict"),
                                          ("call", "%s(...)" % callee))
            continue

        # shapes 2 and 3 -- stdlib ssl references
        name = final_name(node)
        if name not in (UNVERIFIED_CONTEXT, CERT_NONE):
            continue
        key = (node.lineno, name)
        if key in seen:
            continue
        seen.add(key)
        if name == UNVERIFIED_CONTEXT:
            parent = getattr(node, "_parent", None)
            process_wide = (isinstance(parent, ast.Assign)
                            and any(final_name(t) == DEFAULT_HTTPS_CONTEXT
                                    for t in parent.targets))
            message = ("unverified SSL context installed process-wide"
                       if process_wide else "unverified SSL context created")
            add(node, "bug", message,
                (("shape", "unverified-context"),
                 ("ref", ast.unparse(node)),
                 ("scope", "process-wide" if process_wide else "call-site")))
        else:
            add(node, "bug", "certificate validation disabled (ssl.CERT_NONE)",
                (("shape", "cert-none"), ("ref", ast.unparse(node))))

    rows.sort(key=lambda r: r[2])
    return rows


def collect(paths):
    """(findings, skipped, stats) -- the shared interface every detector exposes."""
    findings, skipped = [], []
    files_with = 0
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        rows = scan(path, tree)
        if rows:
            files_with += 1
        for rpath, func, lineno, severity, message, pairs in rows:
            findings.append(Finding(NAME, rpath, lineno, func, severity,
                                    message, detail(*pairs)))
    stats = ["files with a TLS-verification finding: %d" % files_with] if findings else []
    return findings, skipped, stats


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_tls_verify.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)] if stats else []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
