"""
Detector 001 v4: swallowed exception.

A swallow bug is BROAD CATCH x ERROR DOESN'T PROPAGATE. Both axes enumerated:

AXIS 1 -- broad catch (handler.type):
    bare `except:`                  type is None                    broad
    `except Exception:`             Name 'Exception'                broad
    `except BaseException:`         Name 'BaseException'            broad
    `except (Exception, X):`        Tuple containing a broad Name   broad
    `except ValueError:`            specific Name                   NOT broad
    `except (ValueError, X):`       Tuple with no broad Name        NOT broad
  An `as e` binding does not change breadth.

AXIS 2 -- does the error propagate, and did it leave a trace:
    body re-raises (`raise` / `raise X`)          -> HANDLED, not flagged
    body only discards (pass / return / return None / `...`)  -> SILENT
    body logs (a discarded call) but does not re-raise        -> LOG-AND-SWALLOW
    body is none of the above                                 -> UNCLASSIFIED

SEVERITY:
    HIGH    broad + silent            -- the error vanishes with no trace
    MEDIUM  broad + logged, no raise  -- traced, but the program wrongly continued
    REVIEW  broad + body unclassified -- not handled, not a known swallow; look
    (no LOW tier: a broad catch that re-raises is handled, and is not flagged)

FOUR-WAY DECISION ORDER for a BROAD catch:
    1. re-raises anywhere in the body                  -> HANDLED (not flagged)
    2. else body is all silent-discard                 -> HIGH
    3. else body has >=1 recognized LOGGING call       -> MEDIUM
       (non-logging calls may also be present; the trace defines MEDIUM)
    4. else                                            -> REVIEW
       (calls present but none logging -> no trace, unclassified work)

REVIEW BOUNDARY: REVIEW fires ONLY on broad catches. A narrow catch (specific
Name, or Tuple with no broad Name) is out of scope entirely and stays silent
whatever its body does. REVIEW replaces the earlier fail-open silence, where a
broad catch with an unrecognized body was indistinguishable from clean.

LOGGING HEURISTIC (v4, on the record): NAME-BASED recognition. A discarded
call counts as logging only if its callee matches a known logging shape --
a final name in LOG_NAMES, or any dotted component containing "log"
(logger.error, logging.warning, self.log.debug, log_event). Calls like
some_cleanup(), undo(), rollback() are NON-logging.

This is name-based guessing: a logger with an unusual name (audit.record())
will be missed and its handler will read REVIEW instead of MEDIUM, and a
non-logger whose name contains "log" (catalog_write()) will be misread as a
trace. The recognized list prints with every run so the guess is auditable.

BODY SHAPE: a body of nothing but silent-discard statements is HIGH. A body
containing a recognized logging call is MEDIUM. Everything else under a broad
catch -- assignments, real returns, branches, non-logging calls -- is REVIEW,
never silence.

Plain `ast` + `ast.walk`. No NodeVisitor, no external linters.
"""

import ast
import builtins
import sys

from ast_helpers import enclosing_function, link_parents
from findings import Finding, detail
from source_files import safe_parse
from tiering import IN_TEST_PAIR, down_tier, is_test_path

# The real builtins list, not a hand-typed subset -- type/str/len/isinstance/...
BUILTIN_NAMES = frozenset(dir(builtins))

BROAD_NAMES = {"Exception", "BaseException"}

# Final callee names recognized as logging (case-insensitive).
LOG_NAMES = {"log", "print", "warn", "warning", "error",
             "exception", "critical", "debug", "info"}
# Any dotted component containing this substring also reads as logging.
LOG_SUBSTRING = "log"


def broad_trigger(handler):
    """Return the trigger label if this handler catches broadly, else None."""
    node = handler.type
    if node is None:
        return "bare"
    if isinstance(node, ast.Name):
        return node.id if node.id in BROAD_NAMES else None
    if isinstance(node, ast.Tuple):
        for elt in node.elts:
            if isinstance(elt, ast.Name) and elt.id in BROAD_NAMES:
                return "tuple"
        return None
    return None


def is_discard_stmt(stmt):
    """`pass`, bare `return`, `return None`, or `...` -- nothing else."""
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Return):
        if stmt.value is None:
            return True
        return isinstance(stmt.value, ast.Constant) and stmt.value.value is None
    if isinstance(stmt, ast.Expr):
        return isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis
    return False


def callee_components(func):
    """Dotted name components of a call's callee: self.log.debug -> [self, log, debug]."""
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return parts


def is_logging_call(call):
    """Name-based: recognized final name, or any component containing 'log'."""
    parts = callee_components(call.func)
    if not parts:
        return False
    if parts[-1].lower() in LOG_NAMES:
        return True
    return any(LOG_SUBSTRING in p.lower() for p in parts)


def is_call_stmt(stmt):
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)


def is_logging_stmt(stmt):
    """A discarded call whose callee reads as a logger."""
    return is_call_stmt(stmt) and is_logging_call(stmt.value)


def reraises(handler):
    """True if the handler body re-raises at all (bare `raise` or `raise X`)."""
    for stmt in handler.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                return True
    return False


def build_helper_index(trees):
    """name -> [FunctionDef, ...] across the analyzed file set.

    Every def is indexed by its simple name, so a bare-name callee (guard(e))
    and an attribute callee (main._bug_guard(e), self._guard(e)) both resolve
    by that final name.
    """
    index = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index.setdefault(node.name, []).append(node)
    return index


def function_raises(func_def):
    """True if a raise exists ANYWHERE in the def -- a CONDITIONAL raise counts.

    `if isinstance(exc, _PROGRAMMING_ERRORS): raise exc` re-raises on one path,
    and that is exactly the remediation this check exists to recognize.
    """
    for node in ast.walk(func_def):
        if isinstance(node, ast.Raise):
            return True
    return False


def is_self_attribute_call(call):
    """self.x(...) -- an attribute call on `self`, which may be a real helper."""
    func = call.func
    return (isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "self")


def delegation_candidates(handler, index):
    """Callee names in the handler body that could ACTUALLY be remediation.

    A call is a candidate if and ONLY if:
      (A) it RESOLVES to a def in the analyzed files (bare name or attribute
          resolved by final name -- main._bug_guard resolves to _bug_guard), OR
      (B) it is a BARE-NAME or self-attribute call whose name is not a builtin.

    Everything else is NOT delegation and is left to body classification:
      - builtins (type, str, len, isinstance, ...), taken from the real
        `builtins` module rather than a hand-typed subset;
      - attribute calls on objects other than self that resolve to no def --
        out.put(...), x.strip(), df.append(...) are library calls, not guards.

    Recognized LOGGING calls are excluded too: a log is a trace, not a helper.
    Returns [(name, resolved_defs_or_None), ...] in source order.
    """
    out = []
    for stmt in handler.body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call) or is_logging_call(node):
                continue
            parts = callee_components(node.func)
            if not parts:
                continue
            name = parts[-1]
            defs = index.get(name)
            if defs:                                    # (A) resolves to a def
                out.append((name, defs))
                continue
            shaped = isinstance(node.func, ast.Name) or is_self_attribute_call(node)
            if shaped and name not in BUILTIN_NAMES:    # (B) plausible helper
                out.append((name, None))
    return out


def delegation_verdict(handler, index):
    """('handled', name) | ('unresolved', name) | ('none', None).

    A helper is trusted ONLY when its definition is found AND verifiably
    contains a raise -- never because of its name. TIE RULE: when several defs
    share a name, ALL must raise; if any candidate lacks a raise the helper is
    not trusted (the safe direction).
    """
    unresolved = None
    for name, defs in delegation_candidates(handler, index):
        if defs is None:
            if unresolved is None:
                unresolved = name
            continue
        if all(function_raises(d) for d in defs):
            return "handled", name
    if unresolved is not None:
        return "unresolved", unresolved
    return "none", None


def classify(handler, index=None):
    """Verdict for a BROAD catch. (None, reason) means HANDLED/not flagged.

    Never called for narrow catches -- REVIEW is bounded to broad catches only.
    """
    if reraises(handler):
        return None, "re-raises"
    if index is not None:
        kind, name = delegation_verdict(handler, index)
        if kind == "handled":
            return None, "delegates to verified re-raising helper '%s'" % name
        if kind == "unresolved":
            return ("REVIEW",
                    "delegates to unresolved helper '%s', cannot verify it re-raises" % name)
    if not handler.body:
        return "REVIEW", "body-unclassified"
    if all(is_discard_stmt(stmt) for stmt in handler.body):
        return "HIGH", "silent"
    if any(is_logging_stmt(stmt) for stmt in handler.body):
        return "MEDIUM", "logged-not-reraised"
    return "REVIEW", "body-unclassified"




def parse_file(path):
    """(tree, None) or (None, reason) -- per-file isolation lives in source_files."""
    tree, error = safe_parse(path)
    if tree is not None:
        link_parents(tree)
    return tree, error


def scan(path, tree, index):
    """Return (findings, total_handler_count, handlers_by_line)."""
    in_test = is_test_path(path)
    findings = []
    handlers = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        handlers[node.lineno] = node
        trigger = broad_trigger(node)
        if trigger is None:
            continue
        severity, why = classify(node, index)
        if severity is not None:
            extra = ()
            if in_test:
                severity = down_tier(severity)
                extra = (IN_TEST_PAIR,)     # detail pair, as every detector does
            findings.append((path, enclosing_function(node), node.lineno, severity,
                             trigger, why, extra))

    findings.sort(key=lambda f: f[2])
    return findings, len(handlers), handlers


NAME = "swallowed-exception"
SUMMARY = "a broad except whose body discards the error instead of propagating it"
RULES = [
    "decision order for a BROAD catch (Exception/BaseException/bare/tuple-with-broad):",
    "  1. literal raise in body                       -> HANDLED, not flagged",
    "  2. delegates to a RESOLVED helper that raises  -> HANDLED, not flagged",
    "  3. delegates to an UNRESOLVED helper           -> REVIEW (cannot verify)",
    "  4. else body is all-discard                    -> HIGH",
    "  5. else >=1 recognized log call                -> MEDIUM (trace exists)",
    "  6. else                                        -> REVIEW (body-unclassified)",
    "helper trust is STRUCTURAL, never by name: trusted only when the def is found in",
    "  the analyzed files AND contains a raise. A CONDITIONAL raise counts. TIE RULE:",
    "  if several defs share the name, ALL must raise. An unresolvable helper is never",
    "  silently trusted; it is REVIEW.",
    "delegation CANDIDATE gate: (A) the call resolves to a def in the analyzed files,",
    "  or (B) it is a bare-name or self.x(...) call whose name is not a Python builtin",
    "  (%d builtins). Everything else -- type(e), str(e).strip(), out.put(...) -- is NOT" % len(BUILTIN_NAMES),
    "  delegation and is judged by its body, under a true label rather than a false one.",
    "test files DOWN-TIER (shared tiering.down_tier), marked with the",
    "  in_test=true detail pair as every detector does. REASON",
    "  (Principle A, fixture-plausible): a test that swallows is often exercising",
    "  an error path deliberately -- the audit's test_rate_limit.py fixture",
    "  reproduced a swallow ON PURPOSE -- and a swallow in test code is unlikely",
    "  to be a shipped production defect. Test files are NEVER skipped.",
    "NARROW catches are out of scope entirely and stay silent -- never REVIEW.",
    "logging heuristic: NAME-BASED. A discarded call is a log trace when its final",
    "  callee name is in: %s," % ", ".join(sorted(LOG_NAMES)),
    "  or any dotted component contains %r (logger.error, self.log.debug, log_event)." % LOG_SUBSTRING,
]
LIMITS = [
    "helper resolution covers only files passed to THIS run -- pass the whole tree at",
    "  once, or cross-file helpers read as unresolved (REVIEW, never silently trusted).",
    "the logging heuristic is a guess by name: an oddly-named logger (audit.record())",
    "  reads as REVIEW, and a non-logger containing 'log' reads as a trace.",
]


def collect(paths):
    """(findings, skipped, stats) -- the shared interface every detector exposes."""
    trees = {}
    skipped = []
    for path in paths:
        tree, error = parse_file(path)
        if tree is None:
            skipped.append((path, error))
            continue
        trees[path] = tree
    index = build_helper_index(trees.values())

    findings = []
    handlers_seen = 0
    for path in trees:
        rows, total, _ = scan(path, trees[path], index)
        handlers_seen += total
        for rpath, func, lineno, severity, trigger, why, extra in rows:
            findings.append(Finding(NAME, rpath, lineno, func, severity, why,
                                    detail(("trigger", trigger), *extra)))
    rate = (len(findings) / handlers_seen * 100) if handlers_seen else 0.0
    stats = ["handlers scanned: %d | flagged: %d | flag rate: %.1f%%"
             % (handlers_seen, len(findings), rate)]
    return findings, skipped, stats


def main(argv):
    import report
    if len(argv) < 2:
        print("usage: detect_swallowed_except.py FILE [FILE ...]", file=sys.stderr)
        return 2
    paths = argv[1:]
    findings, skipped, stats = collect(paths)
    print(report.render(findings, [sys.modules[__name__]], len(paths), skipped,
                        [(NAME, stats)]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
