"""
Shared: test-file recognition and the one down-tier operation.

Before this module the tool had drifted: three detectors down-tiered findings in
test files, five did not, and only one of the five had actually DECIDED the
question -- the rest were silent on it. Two detectors handling the same situation
differently, for no stated reason, makes a tool unpredictable.

PRINCIPLE A -- FIXTURE PLAUSIBILITY decides:
    DOWN-TIER when a test occurrence is plausibly a legitimate fixture. A
      self-signed certificate, a throwaway token, a logged sample value or a
      deliberately swallowed error in a test is scaffolding, not a shipped
      vulnerability.
    STAY HIGH when the construct is wrong REGARDLESS of where it appears. A
      broken cipher mode or a broken hash primitive is broken in a test too,
      and a test is exactly where someone might quietly normalize one.

  Every detector states its choice and its reason in its own RULES. None is
  silent on the question.

THE LADDER: HIGH -> REVIEW -> LOW, with MEDIUM -> REVIEW. HIGH and MEDIUM both
land on REVIEW because REVIEW is the "look at this, it may well be fine" tier,
which is exactly what a test-file occurrence deserves. This preserves the
behavior timing-compare has had since it introduced test-awareness -- the shared
helper adopts the existing semantics rather than redefining them.

TEST FILES ARE NEVER SKIPPED. Down-tiering makes a finding quieter and
filterable; it never makes it disappear. A real bug can live in a test helper,
and silence is the failure mode this project exists to prevent.
"""

import os

DOWN_TIER = {"HIGH": "REVIEW", "MEDIUM": "REVIEW", "REVIEW": "LOW", "LOW": "LOW"}

IN_TEST_PAIR = ("in_test", "true")


def is_test_path(path):
    """A test file: under a tests/ or test/ dir, or named test_*.py / *_test.py."""
    norm = path.replace("\\", "/").lower()
    if "/tests/" in norm or "/test/" in norm:
        return True
    base = os.path.basename(norm)
    return base.startswith("test_") or base.endswith("_test.py")


def down_tier(severity):
    """One step down the ladder. The single down-tier operation in the tool."""
    return DOWN_TIER.get(severity, severity)
