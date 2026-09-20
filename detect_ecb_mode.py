"""
Detector 006: ECB cipher mode.

THE BUG: ECB encrypts each block independently and deterministically, so
identical plaintext blocks produce identical ciphertext. Structure survives
encryption -- the famous penguin -- and an attacker can reorder, splice or
replay blocks without touching the key. It is essentially never the right mode
for real data, which makes this a high-confidence detector.

TWO LIBRARY IDIOMS, distinct node shapes, same verdict:

  1. PyCryptodome / PyCrypto constant
       AES.new(key, AES.MODE_ECB) | DES.new(key, DES.MODE_ECB) |
       Blowfish.new(..., MODE_ECB, ...)
     The signal is the MODE_ECB reference itself -- an attribute or a bare
     name -- wherever it appears.

  2. the `cryptography` library
       Cipher(algorithms.AES(key), modes.ECB())
     The signal is the ECB reference from the modes module, called or not.

LIBRARY-AGNOSTIC ON THE CIPHER, matching the MODE: ECB is wrong for AES, DES
and Blowfish alike, so the cipher name is irrelevant. Same principle as #5
matching `verify=False` rather than the HTTP client.

DETERMINISTIC VALUE HANDLING, like #5:
    a literal ECB reference (AES.MODE_ECB, MODE_ECB, modes.ECB) -> HIGH
    a literal OTHER mode (MODE_CBC, MODE_GCM, modes.CBC)        -> SILENT,
        confirmed not ECB
    a cipher constructor whose mode comes from a VARIABLE       -> REVIEW,
        "cipher mode set from a variable, cannot confirm it isn't ECB".
        HIGH would assert a certainty the tool does not have; silence would
        hide a possible ECB. REVIEW is the honest verdict.

FLAT HIGH for confirmed ECB. No precision tiering -- there is no identifier to
classify, so the secret-name machinery is inapplicable here rather than
omitted. And NO test-file down-tier: unlike #5's self-signed certificate in a
test, ECB's wrongness does not depend on context, and a test that demonstrates
ECB is exactly the rare case worth seeing.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import sys

from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse

ECB_CONSTANT = "MODE_ECB"          # PyCryptodome / PyCrypto
ECB_MODE = "ECB"                   # cryptography's modes.ECB
MODE_PREFIX = "MODE_"
CONSTRUCTOR = "new"                # AES.new(...), DES.new(...)

NAME = "ecb-mode"
SUMMARY = "ECB cipher mode -- identical plaintext blocks produce identical ciphertext"
RULES = [
    "two idioms, matched on the MODE rather than the cipher (library-agnostic):",
    "  1. a MODE_ECB reference (AES.MODE_ECB, DES.MODE_ECB, bare MODE_ECB)",
    "  2. an ECB reference from the cryptography modes module (modes.ECB())",
    "deterministic value handling:",
    "  a literal ECB reference           -> HIGH (confirmed ECB)",
    "  a literal other mode (MODE_CBC..) -> SILENT (confirmed not ECB)",
    "  X.new(key, <variable>)            -> REVIEW, the mode cannot be confirmed",
    "    from here; HIGH would assert certainty the tool lacks, silence would",
    "    hide a possible ECB.",
    "FLAT HIGH: no precision tiering (no identifier to classify -- inapplicable,",
    "  not omitted) and NO test-file down-tier. REASON (Principle A,",
    "  wrong-regardless): ECB is broken wherever it appears, and a test is",
    "  exactly where someone might quietly normalize it. Contrast the",
    "  fixture-plausible detectors, which DO down-tier in tests.",
]
LIMITS = [
    "ECB over a SINGLE block of already-random data (wrapping a key with a KEK)",
    "  is rare, expert-level and occasionally legitimate -- it still flags HIGH.",
    "  A reviewer should glance at any ECB use; proving the data is one random",
    "  block is out of scope.",
    "a mode held in a variable is REVIEW, never resolved -- `mode = AES.MODE_ECB`",
    "  followed by `AES.new(key, mode)` reports the constant AND the REVIEW,",
    "  rather than connecting them.",
    "a bare name `ECB` is taken as the cryptography mode; an unrelated variable",
    "  of that name would flag.",
]




def final_name(node):
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def is_cipher_constructor(call):
    """X.new(...) -- the PyCryptodome/PyCrypto constructor shape."""
    func = call.func
    return (isinstance(func, ast.Attribute) and func.attr == CONSTRUCTOR
            and isinstance(func.value, ast.Name))


def mode_arguments(call):
    """The argument nodes that could carry a cipher mode."""
    args = list(call.args[1:])                      # arg 0 is the key
    args += [kw.value for kw in call.keywords if kw.arg in ("mode", None)]
    return args


def literal_mode(node):
    """The MODE_* name a node refers to, if it is a literal mode reference."""
    name = final_name(node)
    if name and name.startswith(MODE_PREFIX):
        return name
    return None


def scan(path, tree):
    link_parents(tree)
    rows = []
    seen = set()

    # 1 + 2 -- any literal ECB reference, wherever it appears.
    for node in ast.walk(tree):
        name = final_name(node)
        if name not in (ECB_CONSTANT, ECB_MODE):
            continue
        if isinstance(getattr(node, "_parent", None), ast.Attribute):
            continue                                # inner part of a longer chain
        key = (node.lineno, name)
        if key in seen:
            continue
        seen.add(key)
        idiom = "pycryptodome-constant" if name == ECB_CONSTANT else "cryptography-modes"
        rows.append((path, enclosing_function(node), node.lineno, "HIGH",
                     "ECB cipher mode selected",
                     (("idiom", idiom), ("ref", ast.unparse(node)))))

    # unconfirmable -- a cipher constructor whose mode is not a literal
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not is_cipher_constructor(node):
            continue
        args = mode_arguments(node)
        if not args:
            continue
        if any(literal_mode(a) for a in args):
            continue                                # a literal settled it already
        candidate = args[0]
        rows.append((path, enclosing_function(node), node.lineno, "REVIEW",
                     "cipher mode set from a variable, cannot confirm it is not ECB",
                     (("idiom", "pycryptodome-constant"),
                      ("call", "%s(...)" % ast.unparse(node.func)),
                      ("mode", ast.unparse(candidate)))))

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
    stats = ["files with an ECB finding: %d" % files_with] if findings else []
    return findings, skipped, stats


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_ecb_mode.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)] if stats else []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
