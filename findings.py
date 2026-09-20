"""
Shared: the one Finding structure every detector emits.

Before unification each detector printed its own line format and its own
banner. They now build Findings instead, and one reporting layer formats them.
Detectors changed HOW they report; nothing changed about WHAT they find.

COMMON CORE -- every detector fills all of these:
    detector   the rule that fired ("swallowed-exception", "timing-compare",
               "secret-sink", "weak-random")
    file, line, function
    severity   HIGH | MEDIUM | REVIEW | LOW
    message    a human-readable one-line reason

DETAIL -- ordered (key, value) pairs carrying whatever the common core does
not, so no detector loses information it used to print:
    #1  trigger (Exception/bare/tuple/BaseException)
    #2  name, precision, operator and both operands, in-test marker
    #3  name, precision, flow (direct/indirect), sink, carrier
    #4  call, and the axes that fired (target / func / shape)

Detail is ordered pairs rather than a bare string so Round 2 (JSON / SARIF)
has structure to serialize. It renders as `k=v, k=v` -- the same key names and
values each detector printed before unification.
"""

from dataclasses import dataclass, field

# Confident view first. Everything a user triages by default is at the top.
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "REVIEW": 2, "LOW": 3}
SEVERITIES = ("HIGH", "MEDIUM", "REVIEW", "LOW")


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    function: str
    severity: str
    message: str
    detail: tuple = field(default=())
    # Suppression marks a finding hidden from the WORKING VIEW. It is never
    # removed: it stays in the counts and in every machine format.
    suppressed: bool = False
    suppression_reason: str = None

    def detail_str(self):
        return ", ".join("%s=%s" % (k, v) for k, v in self.detail)

    def sort_key(self):
        """Severity first, then file, then line -- the confident view first."""
        return (SEVERITY_ORDER.get(self.severity, 9), self.file, self.line,
                self.detector)


def detail(*pairs):
    """Build an ordered detail tuple, dropping empty values."""
    return tuple((k, v) for k, v in pairs if v not in (None, "", ()))
