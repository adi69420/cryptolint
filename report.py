"""
Shared: the one reporting layer.

Formats a combined list of Findings from every detector, and consolidates the
four per-detector banners into one. Auditability was a core discipline before
unification -- each run stated its rules and limits -- and unification must not
quietly drop it. It is consolidated here, not removed.

SORT: severity (HIGH, MEDIUM, REVIEW, LOW), then file, then line. All HIGH
findings group together ACROSS detectors, because the confident view is what a
user triages first; which rule produced a HIGH matters less than that it is
HIGH. File-then-severity would read better when walking one file end to end,
but it buries the confident view among LOWs, so severity-first is the default.
"""

from findings import SEVERITIES, SEVERITY_ORDER
from secret_names import name_list, MATCHING_RULE, PRECISION_RULE
from source_files import format_coverage

RULE = "=" * 78


def visible(findings, threshold=None):
    """The default working view: not suppressed, and at or above threshold.

    Threshold is a VIEW FILTER -- below-threshold findings stay in the counts
    and in every machine format. Nothing is deleted here.
    """
    limit = SEVERITY_ORDER.get(threshold, 99) if threshold else 99
    return [f for f in findings
            if not f.suppressed and SEVERITY_ORDER.get(f.severity, 9) <= limit]


def render_findings(findings):
    lines = []
    for f in sorted(findings, key=lambda x: x.sort_key()):
        detail = f.detail_str()
        lines.append("%-6s %-20s %s:%d  %s()  %s%s"
                     % (f.severity, f.detector, f.file, f.line, f.function,
                        f.message, "  (%s)" % detail if detail else ""))
    return lines


def render_suppression(findings, unused, malformed, threshold, show_suppressed):
    """ACTIVE DISCLOSURE -- stated every run, including when there is nothing to
    state, so silence is confirmed rather than assumed."""
    hidden = [f for f in findings if f.suppressed]
    high = [f for f in hidden if f.severity == "HIGH"]
    lines = []
    if high:
        lines.append("  suppressed: %d (INCLUDING %d HIGH -- hidden from the working view)"
                     % (len(hidden), len(high)))
        for f in high:
            lines.append("    !! HIGH suppressed: %s %s:%d  -- %s"
                         % (f.detector, f.file, f.line, f.suppression_reason))
    else:
        lines.append("  suppressed: %d" % len(hidden))
    if unused:
        lines.append("  UNUSED suppressions: %d (matched no current finding -- stale?)"
                     % len(unused))
        for s in unused:
            where = "%s:%d" % (s.file, s.line) if s.line else s.file
            lines.append("    - %s [%s] %s" % (where, s.rule, s.reason))
    else:
        lines.append("  unused suppressions: 0")
    if malformed:
        lines.append("  MALFORMED suppressions: %d (ignored -- they suppress nothing)"
                     % len(malformed))
        for s in malformed:
            where = "%s:%d" % (s.file, s.line) if s.line else s.file
            lines.append("    - %s: %s" % (where, s.malformed))
    else:
        lines.append("  malformed suppressions: 0")
    if threshold:
        below = [f for f in findings
                 if not f.suppressed
                 and SEVERITY_ORDER.get(f.severity, 9) > SEVERITY_ORDER.get(threshold, 99)]
        lines.append("  below threshold %s: %d (view filter only -- still counted, "
                     "still in JSON/SARIF)" % (threshold, len(below)))
    if hidden and not show_suppressed:
        lines.append("  (run with --show-suppressed to list every suppressed finding)")
    return lines


def render_suppressed_list(findings):
    hidden = [f for f in findings if f.suppressed]
    if not hidden:
        return []
    lines = [RULE, "SUPPRESSED  (hidden from the working view, kept in the record)", RULE]
    for f in sorted(hidden, key=lambda x: x.sort_key()):
        lines.append("%-6s %-20s %s:%d  %s()  %s  -- %s"
                     % (f.severity, f.detector, f.file, f.line, f.function,
                        f.message, f.suppression_reason))
    return lines


def render_counts(findings, detectors):
    lines = [RULE, "SUMMARY"]
    lines.append("  total findings: %d" % len(findings))
    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    lines.append("  by severity: " + " | ".join("%s %d" % (s, by_sev[s]) for s in SEVERITIES))
    lines.append("  by detector:")
    for det in detectors:
        rows = [f for f in findings if f.detector == det.NAME]
        if not rows:
            lines.append("    %-20s 0" % det.NAME)
            continue
        counts = " ".join("%s %d" % (s, sum(1 for f in rows if f.severity == s))
                          for s in SEVERITIES
                          if any(f.severity == s for f in rows))
        lines.append("    %-20s %-4d (%s)" % (det.NAME, len(rows), counts))
    return lines


def render_banner(detectors, total_files, skipped, stats=()):
    """One consolidated banner: coverage, per-detector scan stats, shared
    naming, per-detector rules, and every known limitation in one place."""
    lines = [RULE, "COVERAGE"]
    lines += ["  " + l for l in format_coverage(total_files, skipped)]
    for name, rows in stats:
        for row in rows:
            lines.append("  [%s] %s" % (name, row))

    lines += ["", RULE, "SHARED SECRET-NAME MATCHING (secret_names.py)"]
    lines.append("  names: %s" % name_list())
    lines.append("  matching rule: %s" % MATCHING_RULE)
    lines.append("  precision rule: %s" % PRECISION_RULE)

    lines += ["", RULE, "DETECTOR RULES"]
    for det in detectors:
        lines.append("  [%s] %s" % (det.NAME, det.SUMMARY))
        for rule in det.RULES:
            lines.append("    " + rule)

    limits = []
    for det in detectors:
        for lim in det.LIMITS:
            limits.append("  [%s] %s" % (det.NAME, lim))
    limits.append("  [all] SARIF output is SARIF 2.1.0, structurally self-checked against 14")
    limits.append("        constraints. It is NOT schema-validated and NOT verified against")
    limits.append("        GitHub code scanning; partialFingerprints and artifacts[] are not")
    limits.append("        emitted. Release gate: run a real schema validator and a GitHub")
    limits.append("        ingestion test before any claim of validity.")
    limits.append("  [all] Windows MAX_PATH: a path over 260 characters cannot be opened")
    limits.append("        and os.path.exists() reports False for it. Such files are")
    limits.append("        reported as skipped above, never silently dropped.")
    lines += ["", RULE, "KNOWN LIMITATIONS"] + limits
    lines.append(RULE)
    return lines


def render(findings, detectors, total_files, skipped, stats=(),
           unused=(), malformed=(), threshold=None, show_suppressed=False):
    out = []
    rows = render_findings(visible(findings, threshold))
    if rows:
        out += [RULE, "FINDINGS  (severity, then file, then line)", RULE] + rows
    else:
        out += [RULE, "FINDINGS", RULE, "  none"]
    if show_suppressed:
        listing = render_suppressed_list(findings)
        if listing:
            out += [""] + listing
    out += [""] + render_counts(findings, detectors)
    out += render_suppression(findings, unused, malformed, threshold, show_suppressed)
    out += [""] + render_banner(detectors, total_files, skipped, stats)
    return "\n".join(out)
