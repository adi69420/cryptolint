"""
Suppression -- hiding a finding from the WORKING VIEW, never from the RECORD.

THE GOVERNING ETHIC: a suppressed finding is still found, still counted, still
in the JSON and SARIF output. The tool ACTIVELY discloses every suppression in
every run -- it is the tool's job to show, not the reader's to ask. That is why
the summary always states a suppression count (including zero, so silence is
confirmed rather than assumed) and calls out suppressed HIGHs specifically.

PRIMARY MECHANISM -- an inline comment on the flagged line, so the decision
lives WITH the code where reviewers see it in diffs:

    is_private = random.choice([True, False])  # cryptolint: ignore[weak-random] -- boolean flag, not key material

Three properties, each deliberate:
  SPECIFIC   it suppresses findings of THAT rule on THAT line only. Never the
             rule elsewhere, never "all findings named is_private". One
             reviewed line, one suppression.
  REASONED   the `-- reason` is MANDATORY. An ignore with no reason is
             reported as MALFORMED and does NOT suppress. No reasonless hiding.
  CHECKED    the rule id must match the finding's detector. An ignore for the
             wrong rule does not suppress -- you cannot accidentally mute a
             different finding than the one you reviewed.

SECONDARY MECHANISM -- a config-file list keyed by a CONTENT FINGERPRINT
(detector + file + function + identifier), not a bare line number, so it does
not rot the moment a line moves. This exists for vendored or generated code you
cannot edit; the inline comment is the default path.

SELF-HONESTY: the tool applies its own discipline to its suppressions. A
well-formed suppression matching no current finding is reported as UNUSED (the
code may have changed and a real finding moved), and a malformed one is
reported as MALFORMED. Neither is silently ignored.

FUTURE GATE (not implemented this round, by instruction): an
`allow_suppress_high` config option would slot into `apply()` -- the single
place where a suppression is bound to a finding -- rejecting the binding when
the finding is HIGH and the option is false. Loud disclosure is the default
because over-friction makes people route around the tool.
"""

import dataclasses
import re

# # cryptolint: ignore[<rule>] -- <reason>
PATTERN = re.compile(r"#\s*cryptolint:\s*ignore\s*\[([^\]]*)\](.*)$", re.IGNORECASE)
REASON = re.compile(r"^\s*--\s*(.+?)\s*$")


@dataclasses.dataclass
class Suppression:
    file: str
    line: int
    rule: str
    reason: str
    source: str = "inline"          # "inline" or "config"
    malformed: str = None           # why it is malformed, if it is
    used: int = 0                   # how many findings it suppressed

    def is_valid(self):
        return self.malformed is None


def parse_file(path, known_rules):
    """Every cryptolint suppression comment in one file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError):
        return []                    # unreadable files are already reported skipped
    if "cryptolint:" not in text:
        return []

    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = PATTERN.search(line)
        if not m:
            continue
        rule = m.group(1).strip()
        rest = m.group(2)
        rm = REASON.match(rest)
        reason = rm.group(1) if rm else None
        malformed = None
        if not rule:
            malformed = "no rule id in ignore[...]"
        elif rule not in known_rules:
            malformed = ("unknown rule id %r (known: %s)"
                         % (rule, ", ".join(sorted(known_rules))))
        if reason is None or not reason.strip():
            detail = "missing mandatory reason -- use `-- why this is safe`"
            malformed = detail if malformed is None else malformed + "; " + detail
        out.append(Suppression(path, lineno, rule, reason, "inline", malformed))
    return out


def collect(paths, known_rules, config_entries=()):
    """Inline suppressions from every scanned file, plus config fingerprints."""
    found = []
    for path in paths:
        found.extend(parse_file(path, known_rules))
    for entry in config_entries:
        rule = (entry.get("detector") or "").strip()
        reason = (entry.get("reason") or "").strip()
        malformed = None
        if rule not in known_rules:
            malformed = "unknown rule id %r" % rule
        if not reason:
            detail = "missing mandatory reason"
            malformed = detail if malformed is None else malformed + "; " + detail
        s = Suppression(entry.get("file", ""), 0, rule, reason, "config", malformed)
        s.fingerprint = (rule, entry.get("file", ""), entry.get("function", ""),
                         entry.get("identifier", ""))
        found.append(s)
    return found


def _identifier(finding):
    """The detail value a config fingerprint keys on."""
    d = dict(finding.detail)
    for key in ("name", "target", "call", "trigger"):
        if key in d:
            return d[key].split("/")[0]
    return ""


def apply(findings, suppressions):
    """Mark findings suppressed. Returns (findings, unused, malformed).

    The findings list keeps EVERY finding -- suppression sets a flag, it never
    removes. This is the single binding point where a future
    `allow_suppress_high` gate would live.
    """
    inline = {}
    for s in suppressions:
        if s.source == "inline" and s.is_valid():
            inline.setdefault((s.file, s.line, s.rule), []).append(s)
    config = {}
    for s in suppressions:
        if s.source == "config" and s.is_valid():
            config.setdefault(s.fingerprint, []).append(s)

    out = []
    for f in findings:
        hit = inline.get((f.file, f.line, f.detector))
        if not hit:
            hit = config.get((f.detector, f.file, f.function, _identifier(f)))
        if hit:
            hit[0].used += 1
            out.append(dataclasses.replace(f, suppressed=True,
                                           suppression_reason=hit[0].reason))
        else:
            out.append(f)

    unused = [s for s in suppressions if s.is_valid() and s.used == 0]
    malformed = [s for s in suppressions if not s.is_valid()]
    return out, unused, malformed
