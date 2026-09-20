"""
Detector 008: hardcoded secrets.

THE BUG: a credential committed to source is readable by everyone with repo
access and every system that ever mirrors it, and rotating it means a code
change. THE DIFFICULTY: telling a real credential from a placeholder, an
example, or a test fixture. This is the least precise detector class for every
linter that has one, so the honest target is a TRUSTWORTHY HIGH tier with the
fuzzy cases parked in REVIEW -- not perfection, and above all not a flood.

CANDIDATES: a string literal bound to a name -- an assignment, a default
argument, or a dict value under a string key -- where EITHER the TARGET is
secret-named, OR the VALUE looks secret-like. When both fire on one literal it
is ONE finding, tiered by the stronger signal; never double-reported.

DISCRIMINATION PIPELINE, first decisive gate wins:

  STEP 1  PLACEHOLDER DENYLIST -> SILENT
      "YOUR_KEY_HERE", "changeme", "example", "test", "", "...", "<token>",
      "aaaa", and PUBLISHED EXAMPLE CREDENTIALS. Running this FIRST is what
      resolves the AKIAIOSFODNN7EXAMPLE case: that string carries a real AWS
      key prefix, but it is AWS's own documented example key, published in
      their docs and present in countless tutorials. A published example is a
      placeholder that happens to be well-formed, so step 1 beats step 2 and
      it stays SILENT. The ordering IS the rule.

  STEP 2  KNOWN CREDENTIAL FORMAT -> HIGH
      sk-live- / sk- / pk-, AKIA (AWS), ghp_ gho_ ghs_ github_pat_ (GitHub),
      xox (Slack), -----BEGIN (PEM private key), AIza / ya29. (Google),
      SG. (SendGrid), and similar. These shapes are near-certain real
      credentials, so they are HIGH regardless of the target's name.

  STEP 3  ENTROPY + CONTEXT
      Entropy is ONE signal and NEVER the sole decider: a real password
      ("hunter2") is low-entropy, and a random-looking placeholder is not a
      secret. It is combined with length, character-class diversity, and the
      target name:
        secret-named target + real-looking value -> HIGH
        secret-named target + ambiguous value    -> REVIEW
        secret-looking value, non-secret target  -> REVIEW  (good-faith catch)
        no signal                                -> SILENT

TEST FILES down-tier one step (a hardcoded secret under tests/ is very likely a
fixture), reusing the shared test-path mechanism rather than a second copy.

VALUES ARE NEVER PRINTED IN FULL. A security tool that echoes the credential
into logs, CI output and SARIF artifacts has moved the secret somewhere new.
Findings show a short prefix and the length instead.

Plain `ast` + `ast.walk`. No external libs.
"""

import ast
import math
import re
import sys

from tiering import IN_TEST_PAIR, down_tier, is_test_path
from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from secret_names import precision_of
from source_files import safe_parse

# Step 1 -- exact placeholder values (lowercased, stripped).
PLACEHOLDER_EXACT = {
    "", "...", "-", "n/a", "na", "none", "null", "nil", "empty",
    "example", "changeme", "change_me", "change-me",
    "your_key_here", "yourkeyhere", "your-key-here", "yourkey", "your_key",
    "xxx", "xxxx", "xxxxx", "test", "testing", "tests", "foo", "bar", "baz",
    "dummy", "placeholder", "todo", "fixme", "sample", "secret", "password",
    "hello world", "string", "value", "abc", "123",
}
# Step 1 -- markers that make any containing value a placeholder. Kept small and
# strong: a real credential containing "example" or "changeme" is vanishingly
# unlikely, and this is what catches PUBLISHED example keys.
PLACEHOLDER_MARKERS = (
    "example", "changeme", "change_me", "placeholder", "yourkey", "your_key",
    "dummy", "todo", "fixme", "redacted", "insert_", "notarealkey", "xxxxx",
)

# Step 2 -- known credential shapes.
KNOWN_FORMATS = (
    "sk-live-", "sk-test-", "sk-", "pk-", "rk-",          # Stripe-style
    "akia", "asia",                                        # AWS access key ids
    "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_", # GitHub
    "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xox",             # Slack
    "-----begin",                                          # PEM private key
    "aiza", "ya29.",                                       # Google
    "sg.",                                                 # SendGrid
    "sq0atp-", "sq0csp-",                                  # Square
    "amzn.mws.",                                           # Amazon MWS
    "eyj",                                                 # a JWT (base64 '{"')
)

# Step 3 shape gate -- URIs and filesystem paths are never credentials, and
# their length/entropy/character-class profile otherwise looks exactly like one.
# STRUCTURAL, matched on the LEADING shape: a base64 secret ("aB3/xY9z...")
# contains slashes but is not path-shaped, and must stay eligible. Never gate on
# the mere presence of "/".
URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
PATH_START = re.compile(r"^(/|\./|\.\./|~/|[A-Za-z]:[\\/])")

# Step 3 shape gate, part two -- RECOGNIZED structured values. These are TIGHT
# structural recognizers, never a "looks complicated" heuristic: a real
# credential (sk-live-abc123, AKIA..., a base64 key) matches NONE of them and
# still flags. Only trigger B (the value heuristic) is gated; trigger A (a
# secret-named target) is untouched, exactly as with the URI/path gate.
VERSION_STRING = re.compile(r"^\d+\.\d+(\.\d+)*([.\-+][A-Za-z0-9]+)*$")
USER_AGENT = re.compile(r"^[A-Za-z][\w.+-]*/\d[\w.+-]*(\s|$)")
KV_SEGMENT = re.compile(r"(?:^|\s)[A-Za-z_][\w.-]*=[^\s=]+")
COLON_SEGMENT = re.compile(r"(?:^|\s)[A-Za-z_][\w.-]*:\s+\S+")

MIN_SECRET_LENGTH = 10
MIN_ENTROPY_BITS = 3.0
MIN_CHAR_CLASSES = 3

NAME = "hardcoded-secret"
SUMMARY = "a credential written directly into the source"
RULES = [
    "candidates: a string literal bound to a name (assignment, default argument,",
    "  or dict value under a string key) where the TARGET is secret-named OR the",
    "  VALUE looks secret-like. Both signals on one literal = ONE finding.",
    "pipeline, first decisive gate wins:",
    "  1. PLACEHOLDER denylist -> SILENT. Includes PUBLISHED example credentials,",
    "     which is what makes AKIAIOSFODNN7EXAMPLE silent despite carrying a real",
    "     AWS prefix: step 1 runs BEFORE step 2, and the ordering is the rule.",
    "  2. KNOWN CREDENTIAL FORMAT -> HIGH regardless of the target name",
    "     (sk-live-, AKIA, ghp_, xox, -----BEGIN, AIza, ...).",
    "  3. SHAPE GATE then ENTROPY + CONTEXT. Rejected BEFORE entropy scoring:",
    "     URI-shaped (^scheme://), path-shaped (leading / ./ ../ ~/ or a drive",
    "     letter), and RECOGNIZED STRUCTURES -- version strings (1.4.2-rc1), user",
    "     agents (MyApp/2.1 (...)), key=value and key: value formats. Never",
    "     credentials, but they score exactly like one. TIGHT recognizers, never",
    "     \"looks complicated\": a base64 secret with slashes is not path-shaped,",
    "     and sk-live-abc123 matches no structure, so both still flag. Trigger A",
    "     (a secret-named target) is UNAFFECTED by the gate.",
    "     Entropy is one signal, NEVER the sole decider:",
    "       secret-named target + real-looking value -> HIGH",
    "       secret-named target + ambiguous value    -> REVIEW",
    "       secret-looking value, non-secret target  -> REVIEW (good faith)",
    "       no signal                                -> SILENT",
    "ASSEMBLY (REVIEW only): a KNOWN credential-format prefix concatenated or",
    "  f-string-interpolated with a variable -- \"sk-live-\" + suffix,",
    "  f\"AKIA{rest}\" -- reads as a split hardcoded key. Gated STRICTLY on a known",
    "  prefix: \"user-\" + name, f\"{host}:{port}\", \"https://\" + domain and",
    "  f\"hello {user}\" carry no credential prefix and stay SILENT.",
    "test files DOWN-TIER (shared tiering.down_tier), marked in-test. REASON",
    "  (Principle A, fixture-plausible): a hardcoded credential under tests/ is",
    "  very likely a fixture. Test files are NEVER skipped.",
    "values are NEVER printed in full: a tool that echoes a credential into logs,",
    "  CI output and SARIF artifacts has moved the secret somewhere new.",
]
LIMITS = [
    "this is the least precise detector here, by the nature of the problem. HIGH is",
    "  calibrated to be trustworthy (known formats, or a secret name with a",
    "  real-looking value); REVIEW holds the genuinely fuzzy cases.",
    "LOW-ENTROPY REAL SECRETS ARE MISSED: password = \"hunter2\" has no known",
    "  format and little entropy, and is caught only via its target name.",
    "a novel placeholder not in the denylist will flag -- the denylist cannot",
    "  anticipate every convention.",
    "structured non-secret values -- version strings, user agents, key=value and",
    "  key: value formats -- are REJECTED by the shape gate (they used to reach",
    "  REVIEW). Only these RECOGNIZED structures are rejected; a structured format",
    "  the recognizers do not know can still reach REVIEW.",
    "only literal strings are scored by the pipeline. An assembled value is seen",
    "  ONLY when it starts with a known credential-format prefix (REVIEW); a",
    "  secret built entirely from variables, or from a literal with no known",
    "  prefix, is still not seen.",
    "the AWS temporary-key prefixes (akia/asia) are short, so an assembled value",
    "  like f\"asia-{region}\" reads as a credential assembly and reaches REVIEW.",
    "KNOWN GAP -- a connection string with an embedded credential",
    "  (postgres://user:PASSWORD@host) is URI-shaped, so the value heuristic",
    "  stays silent on it. A secret-named target still yields REVIEW. Parsing",
    "  credentials out of URIs is a separate concern, not attempted here.",
]




def is_placeholder(value):
    """Step 1. A known non-secret: template, filler, or published example."""
    text = value.strip()
    low = text.lower()
    if low in PLACEHOLDER_EXACT:
        return True
    if len(text) <= 3:
        return True
    if text.startswith("<") and text.endswith(">"):
        return True
    if text.startswith("{{") or text.startswith("${"):
        return True
    if len(set(text)) == 1:                       # "aaaa"
        return True
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def known_format(value):
    """Step 2. The credential shape this value matches, or None."""
    low = value.strip().lower()
    for prefix in KNOWN_FORMATS:
        if low.startswith(prefix):
            return prefix
    return None


def entropy_bits(value):
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def char_classes(value):
    classes = 0
    for test in (str.islower, str.isupper, str.isdigit):
        if any(test(c) for c in value):
            classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


def structured_value(value):
    """The recognized structure this value has, or None.

    Tight recognizers only. Anything not matching one of these -- including
    every credential shape -- falls through to the entropy test.
    """
    text = value.strip()
    if VERSION_STRING.match(text):
        return "version-string"
    if USER_AGENT.match(text) and "(" in text and ")" in text:
        return "user-agent"
    if len(KV_SEGMENT.findall(text)) >= 2:
        return "key-value-format"
    if len(COLON_SEGMENT.findall(text)) >= 2:
        return "key-value-format"
    return None


def uri_or_path_shaped(value):
    """Step 3 gate. True for a URI or a filesystem path -- never a credential.

    Matched on the LEADING structure only. `aB3/xY9zK2mP7qR/tW` contains
    slashes but starts like neither, so it stays eligible as a secret.
    """
    text = value.strip()
    return bool(URI_SCHEME.match(text) or PATH_START.match(text))


def looks_secret(value):
    """Step 3. Shape gate first, then entropy AND length AND character
    diversity -- never entropy alone."""
    text = value.strip()
    if uri_or_path_shaped(text) or structured_value(text):
        return False
    return (len(text) >= MIN_SECRET_LENGTH
            and char_classes(text) >= MIN_CHAR_CLASSES
            and entropy_bits(text) >= MIN_ENTROPY_BITS)


def preview(value):
    """A short prefix and the length -- never the whole credential."""
    text = value.strip()
    head = text[:4].replace("\n", " ")
    return "%s...(%d chars)" % (head, len(text))


def leading_literal(node):
    """The literal text a concatenation or f-string STARTS with, plus whether a
    variable part follows. ("sk-live-", True) for f"sk-live-{env}".

    Only the LEADING literal matters: a credential-format prefix followed by a
    variable is the one genuinely suspicious assembly shape.
    """
    if isinstance(node, ast.JoinedStr):
        text, saw_var = "", False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if not saw_var:
                    text += part.value
            elif isinstance(part, ast.FormattedValue):
                saw_var = True
        return text, saw_var
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
            left = left.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return left.value, True
    return "", False


def assembled_credential(node):
    """The credential prefix an assembly starts with, or None.

    GATED STRICTLY on a KNOWN credential format. Ordinary string building --
    "user-" + name, f"{host}:{port}", "https://" + domain, f"hello {user}" --
    carries no credential prefix and stays SILENT. That gate is what keeps this
    from flooding: the ocean of legitimate concatenation is untouched.
    """
    text, saw_var = leading_literal(node)
    if not text or not saw_var:
        return None
    if is_placeholder(text):
        return None
    return known_format(text)


def candidates(tree):
    """(target-name, string-node, kind) for every literal worth examining."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        out.append((target.id, node.value, "assignment"))
        elif isinstance(node, ast.AnnAssign):
            if (node.value is not None and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and isinstance(node.target, ast.Name)):
                out.append((node.target.id, node.value, "assignment"))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            defaults = list(node.args.defaults) + list(node.args.kw_defaults)
            for arg, default in zip(args[-len(defaults):] if defaults else [], defaults):
                if (default is not None and isinstance(default, ast.Constant)
                        and isinstance(default.value, str)):
                    out.append((arg.arg, default, "default-arg"))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)):
                    out.append((key.value, value, "dict-value"))
    return out


def classify(target, value):
    """(severity, why, extra detail pairs) following the ordered pipeline."""
    if is_placeholder(value):
        return None, "placeholder", ()
    fmt = known_format(value)
    if fmt:
        return "HIGH", "known credential format", (("format", fmt),)

    named = precision_of(target) if target else None
    real_looking = looks_secret(value)          # False for URI/path shapes
    if named and real_looking:
        return "HIGH", "secret-named target with a real-looking value", \
            (("target_precision", named),)
    if named:
        return "REVIEW", "secret-named target with an ambiguous value", \
            (("target_precision", named),)
    if real_looking:
        return "REVIEW", "secret-looking value in a non-secret target", ()
    return None, "no signal", ()


def shape_note(value):
    """Why a value was gated, for the record."""
    return "uri-or-path" if uri_or_path_shaped(value) else None


def assembly_rows(tree, in_test):
    """ITEM 5 -- a credential-format prefix assembled with a variable.

    REVIEW only, never HIGH: the secret may well live in the variable (which is
    safer), so this is genuinely ambiguous. It is worth a look because it also
    looks exactly like a hardcoded key that was split up.
    """
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.JoinedStr, ast.BinOp)):
            continue
        fmt = assembled_credential(node)
        if not fmt:
            continue
        severity = down_tier("REVIEW") if in_test else "REVIEW"
        pairs = (("kind", "assembled"), ("format", fmt),
                 ("expr", ast.unparse(node)[:60]))
        if in_test:
            pairs = pairs + (IN_TEST_PAIR,)
        rows.append((node.lineno, severity,
                     "credential-format prefix assembled with a variable -- "
                     "verify it is not a split hardcoded key", pairs))
    return rows


def scan(path, tree):
    link_parents(tree)
    in_test = is_test_path(path)
    rows = []
    seen = set()
    for target, node, kind in candidates(tree):
        key = (node.lineno, getattr(node, "col_offset", 0))
        if key in seen:                       # one literal, one finding
            continue
        severity, why, extra = classify(target, node.value)
        if severity is None:
            continue
        seen.add(key)
        if in_test:
            severity = down_tier(severity)
            extra = extra + (IN_TEST_PAIR,)
        pairs = (("target", target), ("kind", kind),
                 ("value", preview(node.value))) + extra
        rows.append((path, enclosing_function(node), node.lineno, severity, why, pairs))
    for lineno, severity, message, pairs in assembly_rows(tree, in_test):
        node = next((n for n in ast.walk(tree)
                     if getattr(n, "lineno", None) == lineno), tree)
        rows.append((path, enclosing_function(node), lineno, severity, message, pairs))

    rows.sort(key=lambda r: r[2])
    return rows


def collect(paths):
    """(findings, skipped, stats) -- the shared interface every detector exposes."""
    findings, skipped = [], []
    for path in paths:
        tree, error = safe_parse(path)
        if tree is None:
            skipped.append((path, error))
            continue
        for rpath, func, lineno, severity, why, pairs in scan(path, tree):
            findings.append(Finding(NAME, rpath, lineno, func, severity, why,
                                    detail(*pairs)))
    return findings, skipped, []


def main(argv):
    import report
    paths = argv[1:]
    if not paths:
        print("usage: detect_hardcoded_secret.py FILE [FILE ...]", file=sys.stderr)
        return 2
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped, []))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
