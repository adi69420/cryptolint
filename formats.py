"""
Machine-readable serializations of the same Findings the human report shows.

FAITHFULNESS IS THE RULE: JSON and SARIF carry EVERY field the human report
carries -- detector, file, line, function, severity, message, and all of the
ordered detail pairs each detector produced. A machine format that drops detail
to look clean is less useful than the text output, which is backwards. The
finding SET is identical across all three formats; only serialization differs.

The partial-scan disclosure survives into both machine formats too: JSON gets a
`coverage` object listing every skipped file with its reason, SARIF gets them as
invocation notifications. A partial scan must never look complete in any format.

WHAT THE SARIF CLAIM IS, EXACTLY -- this tool emits SARIF 2.1.0 and checks it
STRUCTURALLY against 14 constraints. It is NOT schema-validated and NOT verified
against GitHub code scanning. Saying "valid SARIF" on that basis would be the
same unverified assertion this tool flags in other people's code.

  SELF-CHECKED (14): version == "2.1.0"; $schema present; non-empty runs;
    driver.name; rule id uniqueness; every rule.shortDescription.text a string;
    every result.ruleId declared in driver.rules; ruleIndex in range AND
    matching its ruleId; result.level in {error, warning, note, none};
    result.message.text present; artifactLocation.uri present;
    region.startLine an integer >= 1; result.properties an object;
    invocation.executionSuccessful a bool.

  NOT CHECKED (6, all material): full JSON-Schema conformance (types,
    additionalProperties, patterns); RFC-3986 URI validity, including
    file:///C:/... Windows drive URIs; originalUriBaseIds / artifacts[]
    correlation; GitHub code-scanning ingestion limits (result count, payload
    size); partialFingerprints, which GitHub uses to dedup alerts across runs
    and which this tool does not emit; suppressions[].kind enum conformance
    beyond the single literal emitted.

  RELEASE GATE (not done, not claimed): before any "valid SARIF" claim, run a
    real JSON-Schema validator against the 2.1.0 schema AND a GitHub
    code-scanning ingestion test. Neither has been run.
"""

import json

TOOL_NAME = "cryptolint"
VERSION = "0.2.0"
INFORMATION_URI = "https://example.invalid/cryptolint"

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")

# SARIF's level vocabulary is error|warning|note|none, which does not match our
# four tiers. Map for compatibility; the TRUE tier is preserved verbatim in
# result.properties.cryptolintSeverity so nothing is collapsed or distorted.
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning",
               "REVIEW": "warning", "LOW": "note"}

from findings import SEVERITIES


def _summary(findings, detectors):
    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    by_det = {}
    for det in detectors:
        rows = [f for f in findings if f.detector == det.NAME]
        by_det[det.NAME] = {
            "total": len(rows),
            "by_severity": {s: sum(1 for f in rows if f.severity == s)
                            for s in SEVERITIES},
        }
    return {"total": len(findings), "by_severity": by_sev, "by_detector": by_det}


def _sorted(findings):
    return sorted(findings, key=lambda f: f.sort_key())


def to_json(findings, detectors, total_files, skipped, stats=(),
            unused=(), malformed=()):
    doc = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "summary": _summary(findings, detectors),
        "suppression": {
            "suppressed_count": sum(1 for f in findings if f.suppressed),
            "suppressed_high": sum(1 for f in findings
                                   if f.suppressed and f.severity == "HIGH"),
            "unused": [{"file": s.file, "line": s.line, "rule": s.rule,
                        "reason": s.reason} for s in unused],
            "malformed": [{"file": s.file, "line": s.line, "problem": s.malformed}
                          for s in malformed],
        },
        "coverage": {
            "files_given": total_files,
            "scanned": total_files - len(skipped),
            "skipped_count": len(skipped),
            "partial": bool(skipped),
            "skipped": [{"file": p, "reason": r} for p, r in skipped],
        },
        "stats": {name: list(rows) for name, rows in stats},
        "findings": [
            {
                "detector": f.detector,
                "file": f.file,
                "line": f.line,
                "function": f.function,
                "severity": f.severity,
                "message": f.message,
                "detail": {k: v for k, v in f.detail},
                # Suppressed findings are INCLUDED and marked -- the record is
                # complete even when the working view is not.
                "suppressed": bool(f.suppressed),
                "suppression_reason": f.suppression_reason,
            }
            for f in _sorted(findings)
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False)


def _uri(path):
    """SARIF wants a URI. Absolute Windows/POSIX paths become file:// URIs."""
    norm = path.replace("\\", "/")
    if len(norm) > 2 and norm[1] == ":" and norm[0].isalpha():
        return "file:///" + norm
    if norm.startswith("/"):
        return "file://" + norm
    return norm


def to_sarif(findings, detectors, total_files, skipped, stats=(),
             unused=(), malformed=()):
    rules, rule_index = [], {}
    for det in detectors:
        rule_id = "%s/%s" % (TOOL_NAME, det.NAME)
        rule_index[det.NAME] = len(rules)
        rules.append({
            "id": rule_id,
            "name": det.NAME.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": det.SUMMARY},
            "fullDescription": {"text": " ".join(det.RULES) if det.RULES else det.SUMMARY},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"limitations": list(det.LIMITS)},
        })

    results = []
    for f in _sorted(findings):
        properties = {"cryptolintSeverity": f.severity, "function": f.function}
        properties.update({k: v for k, v in f.detail})
        result = {
            "ruleId": "%s/%s" % (TOOL_NAME, f.detector),
            "ruleIndex": rule_index.get(f.detector, 0),
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": "%s: %s" % (f.detector, f.message)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file)},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": properties,
        }
        if f.suppressed:
            # SARIF's native suppression channel: a dashboard shows the result
            # AS suppressed rather than never seeing it.
            result["suppressions"] = [{
                "kind": "inSource",
                "justification": f.suppression_reason or "",
            }]
        results.append(result)

    notifications = [{
        "level": "warning",
        "message": {"text": "PARTIAL SCAN: %d of %d files skipped and NOT analyzed"
                            % (len(skipped), total_files)},
    }] if skipped else []
    for path, reason in skipped:
        notifications.append({
            "level": "warning",
            "message": {"text": "skipped %s -- %s" % (path, reason)},
            "locations": [{"physicalLocation":
                           {"artifactLocation": {"uri": _uri(path)}}}],
        })

    invocation = {
        "executionSuccessful": True,
        "properties": {
            "filesGiven": total_files,
            "filesScanned": total_files - len(skipped),
            "partialScan": bool(skipped),
            "stats": {name: list(rows) for name, rows in stats},
            "suppressedCount": sum(1 for f in findings if f.suppressed),
            "suppressedHigh": sum(1 for f in findings
                                  if f.suppressed and f.severity == "HIGH"),
            "unusedSuppressions": [
                {"file": s.file, "line": s.line, "rule": s.rule} for s in unused],
            "malformedSuppressions": [
                {"file": s.file, "line": s.line, "problem": s.malformed}
                for s in malformed],
        },
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": VERSION,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "invocations": [invocation],
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, sort_keys=False)
