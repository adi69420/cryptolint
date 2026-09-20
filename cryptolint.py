"""
cryptolint -- one entry point for all four detectors.

    python cryptolint.py <path> [<path> ...]
    python cryptolint.py --only timing,sink <path>
    python cryptolint.py --skip swallowed <path>
    python cryptolint.py --format json <path>
    python cryptolint.py --format sarif <path>
    python cryptolint.py --show-suppressed <path>
    python cryptolint.py --config path/to/.cryptolint.toml <path>
    python cryptolint.py --severity-threshold REVIEW <path>

Configuration is optional (.cryptolint.toml in the working directory). CONFIG
SUPPLIES DEFAULTS; THE COMMAND LINE OVERRIDES THEM.

A <path> may be a file or a directory (walked for *.py).

All four detectors run by default; --only and --skip select a subset. Each
detector still performs its OWN file traversal and parsing this round --
parse-once/shared-AST is deliberately deferred, because bundling an
optimization into the unification would risk exactly the kind of regression
this round exists to rule out.
"""

import os
import sys

import detect_swallowed_except
import detect_timing_compare
import detect_secret_sink
import detect_weak_random
import detect_tls_verify
import detect_ecb_mode
import detect_weak_hash
import detect_hardcoded_secret
import config as config_mod
import formats
import report
import suppression as suppression_mod
from findings import SEVERITIES

FORMATS = ("human", "json", "sarif")

DETECTORS = [detect_swallowed_except, detect_timing_compare,
             detect_secret_sink, detect_weak_random, detect_tls_verify,
             detect_ecb_mode, detect_weak_hash, detect_hardcoded_secret]

# Short selectors accepted by --only / --skip.
ALIASES = {
    "swallowed": "swallowed-exception", "swallowed-exception": "swallowed-exception",
    "timing": "timing-compare", "timing-compare": "timing-compare",
    "sink": "secret-sink", "secret-sink": "secret-sink",
    "random": "weak-random", "weak-random": "weak-random",
    "tls": "tls-verify", "tls-verify": "tls-verify",
    "ecb": "ecb-mode", "ecb-mode": "ecb-mode",
    "hash": "weak-hash", "weak-hash": "weak-hash",
    "secret": "hardcoded-secret", "secrets": "hardcoded-secret",
    "hardcoded-secret": "hardcoded-secret",
}


def expand(paths):
    """Files as given; directories walked for *.py."""
    out = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                out.extend(os.path.join(root, n).replace("\\", "/")
                           for n in sorted(names) if n.endswith(".py"))
        else:
            out.append(path.replace("\\", "/"))
    return out


def resolve(spec, flag):
    names = set()
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part not in ALIASES:
            print("%s: unknown detector %r. Known: %s"
                  % (flag, part, ", ".join(sorted(set(ALIASES.values())))),
                  file=sys.stderr)
            raise SystemExit(2)
        names.add(ALIASES[part])
    return names


def main(argv):
    args, only, skip, fmt = [], None, set(), None
    cfg_path, threshold, show_suppressed = None, None, False
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--show-suppressed":
            show_suppressed = True; i += 1
            continue
        if arg == "--config" and i + 1 < len(argv):
            cfg_path = argv[i + 1]; i += 2
            continue
        if arg.startswith("--config="):
            cfg_path = arg.split("=", 1)[1]; i += 1
            continue
        if arg == "--severity-threshold" and i + 1 < len(argv):
            threshold = argv[i + 1].strip().upper(); i += 2
            continue
        if arg.startswith("--severity-threshold="):
            threshold = arg.split("=", 1)[1].strip().upper(); i += 1
            continue
        if arg == "--format" and i + 1 < len(argv):
            fmt = argv[i + 1].strip().lower(); i += 2
            continue
        if arg.startswith("--format="):
            fmt = arg.split("=", 1)[1].strip().lower(); i += 1
            continue
        if arg == "--only" and i + 1 < len(argv):
            only = resolve(argv[i + 1], "--only"); i += 2
        elif arg.startswith("--only="):
            only = resolve(arg.split("=", 1)[1], "--only"); i += 1
        elif arg == "--skip" and i + 1 < len(argv):
            skip = resolve(argv[i + 1], "--skip"); i += 2
        elif arg.startswith("--skip="):
            skip = resolve(arg.split("=", 1)[1], "--skip"); i += 1
        else:
            args.append(arg); i += 1

    # ---- config supplies DEFAULTS; anything given on the CLI overrides it ----
    found_cfg = config_mod.find(cfg_path)
    cfg, cfg_used = config_mod.load(found_cfg)
    if only is None and cfg["detectors"]:
        only = resolve(",".join(cfg["detectors"]), "config detectors")
    if threshold is None and cfg["severity_threshold"]:
        threshold = str(cfg["severity_threshold"]).strip().upper()
    if fmt is None:
        fmt = "human"
    if threshold is not None and threshold not in SEVERITIES:
        print("--severity-threshold: unknown severity %r. Known: %s"
              % (threshold, ", ".join(SEVERITIES)), file=sys.stderr)
        return 2

    if fmt not in FORMATS:
        print("--format: unknown format %r. Known: %s" % (fmt, ", ".join(FORMATS)),
              file=sys.stderr)
        return 2

    if not args:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    selected = [d for d in DETECTORS
                if (only is None or d.NAME in only) and d.NAME not in skip]
    if not selected:
        print("no detectors selected", file=sys.stderr)
        return 2

    paths = expand(args)
    config_skipped = [p for p in paths
                      if config_mod.path_is_skipped(p, cfg["skip_paths"])]
    paths = [p for p in paths if p not in set(config_skipped)]

    findings, stats = [], []
    skipped, seen_skips = [], set()
    for det in selected:
        det_findings, det_skipped, det_stats = det.collect(paths)
        findings.extend(det_findings)
        if det_stats:
            stats.append((det.NAME, det_stats))
        # Each detector traverses independently, so the same unreadable file is
        # reported by each. Aggregate to one entry per file for the report.
        for path, reason in det_skipped:
            if path not in seen_skips:
                seen_skips.add(path)
                skipped.append((path, reason))

    # ---- suppression: mark, never remove ----
    known_rules = {d.NAME for d in DETECTORS}
    suppressions = suppression_mod.collect(paths, known_rules, cfg["suppress"])
    findings, unused, malformed = suppression_mod.apply(findings, suppressions)

    if config_skipped:
        stats.append(("config", ["skip_paths excluded %d file(s) from the scan"
                                 % len(config_skipped)]))
    if cfg_used:
        stats.append(("config", ["loaded %s" % cfg_used]))

    if fmt == "json":
        print(formats.to_json(findings, selected, len(paths), skipped, stats,
                              unused, malformed))
    elif fmt == "sarif":
        print(formats.to_sarif(findings, selected, len(paths), skipped, stats,
                               unused, malformed))
    else:
        print(report.render(findings, selected, len(paths), skipped, stats,
                            unused, malformed, threshold, show_suppressed))
    return 0


def cli():
    """Console-script entry point: `cryptolint <path>` after installation.

    setuptools calls this with no arguments, so it supplies sys.argv itself.
    main(argv) stays the testable form.
    """
    return main(sys.argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
