"""
Shared: reading and parsing source files, with per-file error isolation.

ONE source of truth. Every detector parses through safe_parse() rather than
opening files itself, so the discipline below cannot drift between detectors.

THE BUG THIS FIXES: each detector used to call open() directly with no
isolation. On a 4,336-file scan of Saleor, ONE unreadable file (a Windows path
over 260 characters) raised FileNotFoundError out of the file loop and aborted
the whole run with zero output. Worse than the crash: a scan that quietly
skipped files would have been indistinguishable from a clean full scan -- the
exact fail-open shape detector #1 exists to catch, living in the tools.

THE PRINCIPLE -- this is _bug_guard's logic applied to the file loop:

  EXPECTED INPUT FAILURES are caught, recorded with a reason, and REPORTED:
      OSError (incl. FileNotFoundError, PermissionError) -- unreadable file,
          or a path Windows cannot open
      UnicodeDecodeError -- not UTF-8
      SyntaxError (incl. its ValueError-ish kin from ast.parse) -- not
          parseable Python
  A PROGRAMMING ERROR in a detector still PROPAGATES and crashes the run.
  The catch is deliberately NARROW: there is no `except Exception: continue`
  here, because that would rebuild the very swallow this project flags. A
  NameError or AttributeError raised while walking a tree is our bug, and it
  must reach the developer with a traceback rather than be filed as a "bad
  input file".

LOUD PARTIAL-SCAN REPORTING: format_coverage() renders the summary every run.
A scan that skipped files is visually distinct from a clean one at a glance,
and a clean scan says "0 skipped" explicitly, so silence is confirmed rather
than assumed.

KNOWN LIMITATION (documented, not solved): Windows MAX_PATH. A path longer
than 260 characters cannot be opened without a \\\\?\\ prefix, and
os.path.exists() reports False for it rather than raising. This module does not
implement long-path support -- it catches the failure and reports the file as
skipped, which makes a scan CORRECT (never silently partial) even where it
cannot read those files.
"""

import ast

# Expected, per-file input failures. Anything not listed here is a bug in the
# detector and is allowed to propagate.
INPUT_ERRORS = (OSError, UnicodeDecodeError, SyntaxError, ValueError)


def safe_parse(path):
    """Return (tree, None) on success, or (None, reason) for an expected failure.

    Only the narrow input-error set above is caught. A defect in the caller
    still raises.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        return None, "%s: %s" % (type(exc).__name__, _short(exc))
    try:
        return ast.parse(source, filename=path), None
    except SyntaxError as exc:
        where = " (line %s)" % exc.lineno if exc.lineno else ""
        return None, "SyntaxError: %s%s" % (exc.msg, where)
    except ValueError as exc:
        # ast.parse raises ValueError for source containing null bytes.
        return None, "ValueError: %s" % _short(exc)


def _short(exc):
    text = str(exc)
    return text if len(text) <= 160 else text[:157] + "..."


def format_coverage(total, skipped, unit="files"):
    """Lines describing scan coverage. Partial scans are impossible to miss.

    `skipped` is a list of (path, reason).
    """
    scanned = total - len(skipped)
    lines = []
    if skipped:
        lines.append("!" * 72)
        lines.append("!! PARTIAL SCAN -- scanned %d of %d %s | %d SKIPPED"
                     % (scanned, total, unit, len(skipped)))
        lines.append("!! These %s were NOT analyzed. Findings below are incomplete."
                     % unit)
        lines.append("!" * 72)
        for path, reason in skipped:
            lines.append("!! SKIPPED %s -- %s" % (path, reason))
        lines.append("!" * 72)
    else:
        lines.append("scanned %d of %d %s | 0 skipped (full coverage)"
                     % (scanned, total, unit))
    return lines
