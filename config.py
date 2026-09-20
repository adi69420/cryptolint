"""
Optional project configuration: .cryptolint.toml

A project sets its defaults once. The file is entirely optional -- with no
config the tool behaves exactly as it did before this existed.

PRECEDENCE: config supplies DEFAULTS; the command line OVERRIDES them. A
--format / --only / --skip / --severity-threshold on the command line always
wins over the file, so a per-run investigation never fights the project setting.

    # .cryptolint.toml
    detectors = ["timing-compare", "secret-sink"]   # default: all four
    severity_threshold = "REVIEW"                   # default: show everything
    skip_paths = ["**/migrations/**"]               # default: skip nothing

    [[suppress]]                    # fallback for un-editable code only
    detector = "weak-random"
    file = "vendor/gen.py"
    function = "build"
    identifier = "key"
    reason = "generated file, value is a dict key"

severity_threshold is a VIEW FILTER, not suppression. A below-threshold finding
is still found, still counted in the summary, and still present in JSON and
SARIF -- it is simply not printed in the default human listing. Nothing is
deleted by a threshold.
"""

import fnmatch
import os
import tomllib

CONFIG_NAME = ".cryptolint.toml"

DEFAULTS = {
    "detectors": None,             # None = all
    "severity_threshold": None,    # None = show every tier
    "skip_paths": [],
    "suppress": [],
}


def find(explicit=None, start=None):
    """The config path: explicit, else CONFIG_NAME in cwd, else None."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    candidate = os.path.join(start or os.getcwd(), CONFIG_NAME)
    return candidate if os.path.exists(candidate) else None


def load(path):
    """Parse the config, or return defaults when there is none."""
    cfg = dict(DEFAULTS)
    if not path:
        return cfg, None
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    for key in ("detectors", "severity_threshold", "skip_paths", "suppress"):
        if key in raw:
            cfg[key] = raw[key]
    return cfg, path


def path_is_skipped(path, patterns):
    """True when a path matches any configured skip glob."""
    norm = path.replace("\\", "/")
    for pat in patterns or ():
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(os.path.basename(norm), pat):
            return True
    return False
