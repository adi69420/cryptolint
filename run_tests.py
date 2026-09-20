"""
cryptolint test suite -- run with `python run_tests.py` or `python -m unittest`.

WHAT THIS ACTUALLY VERIFIES. A test that executes code without checking the
result is the exact failure mode this project exists to catch, so every test
here asserts against a recorded expectation:

  1. COUNTS -- each detector's corpus produces an exact total AND an exact
     per-severity breakdown. A finding that appears, vanishes or changes tier
     fails the suite; a bare "it ran" is not a pass.
  2. INVARIANTS -- specific must-flag and must-stay-SILENT behaviours, named
     line by line. Counts alone could stay right while two findings swapped
     places, so the properties that matter are asserted individually.
  3. EXEMPTIONS -- the structural exemptions (hmac.compare_digest,
     random.SystemRandom, usedforsecurity=False, published example keys) are
     asserted silent, because a broken exemption is a false positive on
     correct code.
  4. INFRASTRUCTURE -- unreadable and unparseable files are reported as
     skipped rather than crashing the run or silently shrinking coverage.
  5. SARIF -- validated against the official SARIF 2.1.0 JSON Schema when
     `jsonschema` is installed (`pip install -e .[dev]`), skipped with a
     visible message when it is not. Never silently passed.

The expected numbers below are the CURRENT measured values, re-derived
whenever a detection round changes them. They are not aspirational.
"""

import json
import os
import sys
import unittest

import cryptolint
import formats
import report

HERE = os.path.dirname(os.path.abspath(__file__))


def corpus(*names):
    return [os.path.join(HERE, n).replace("\\", "/") for n in names]


# detector -> (corpus files, total, {severity: count})
EXPECTED = {
    "swallowed-exception": (corpus("testcases.py"),
                            18, {"HIGH": 5, "MEDIUM": 4, "REVIEW": 9, "LOW": 0}),
    "timing-compare": (corpus("testcases_timing.py", "test_timing_fixtures.py"),
                       15, {"HIGH": 7, "MEDIUM": 0, "REVIEW": 5, "LOW": 3}),
    "secret-sink": (corpus("testcases_sink.py"),
                    21, {"HIGH": 12, "MEDIUM": 0, "REVIEW": 8, "LOW": 1}),
    "weak-random": (corpus("testcases_random.py"),
                    17, {"HIGH": 9, "MEDIUM": 0, "REVIEW": 6, "LOW": 2}),
    "tls-verify": (corpus("testcases_tls.py", "test_tls_fixtures.py"),
                   15, {"HIGH": 10, "MEDIUM": 0, "REVIEW": 5, "LOW": 0}),
    "ecb-mode": (corpus("testcases_ecb.py"),
                 6, {"HIGH": 5, "MEDIUM": 0, "REVIEW": 1, "LOW": 0}),
    "weak-hash": (corpus("testcases_hash.py"),
                  9, {"HIGH": 4, "MEDIUM": 0, "REVIEW": 5, "LOW": 0}),
    "hardcoded-secret": (corpus("testcases_secret.py", "test_secret_fixtures.py"),
                         14, {"HIGH": 5, "MEDIUM": 0, "REVIEW": 9, "LOW": 0}),
}

DETECTORS = {d.NAME: d for d in cryptolint.DETECTORS}


def run(name):
    """Findings from one detector over its own corpus."""
    paths, _, _ = EXPECTED[name]
    findings, skipped, _ = DETECTORS[name].collect(paths)
    assert not skipped, "corpus for %s should be readable: %s" % (name, skipped)
    return findings


def functions_with(findings):
    return {f.function for f in findings}


class TestCorpusCounts(unittest.TestCase):
    """Every detector's corpus produces an exact, recorded result."""


def _make_count_test(name):
    def test(self):
        _, total, by_sev = EXPECTED[name]
        findings = run(name)
        self.assertEqual(len(findings), total,
                         "%s: expected %d findings, got %d" % (name, total, len(findings)))
        for sev, want in by_sev.items():
            got = sum(1 for f in findings if f.severity == sev)
            self.assertEqual(got, want,
                             "%s: expected %d %s, got %d" % (name, want, sev, got))
    return test


for _name in EXPECTED:
    setattr(TestCorpusCounts, "test_%s" % _name.replace("-", "_"), _make_count_test(_name))


class TestInvariants(unittest.TestCase):
    """Named behaviours, asserted individually -- counts alone are not enough."""

    def test_swallowed_catches_the_silent_forms(self):
        funcs = functions_with(run("swallowed-exception"))
        for fn in ("fetch_price", "sync_ledger", "close_position", "resolve_route"):
            self.assertIn(fn, funcs, "swallowed-exception must flag %s" % fn)

    def test_swallowed_trusts_a_verified_reraising_helper(self):
        funcs = functions_with(run("swallowed-exception"))
        for fn in ("delegates_to_guard", "delegates_to_always", "delegates_to_bug_guard"):
            self.assertNotIn(fn, funcs,
                             "a helper verified to re-raise must be HANDLED: %s" % fn)

    def test_swallowed_does_not_trust_a_fake_guard(self):
        self.assertIn("delegates_to_fake_guard", functions_with(run("swallowed-exception")),
                      "a guard-looking helper that never raises must NOT be trusted")

    def test_timing_exempts_real_constant_time_compare(self):
        funcs = functions_with(run("timing-compare"))
        self.assertNotIn("verify_safely", funcs, "hmac.compare_digest is the fix")
        self.assertNotIn("verify_safely_secrets", funcs, "secrets.compare_digest is the fix")

    def test_timing_does_not_trust_a_lookalike_compare_digest(self):
        self.assertIn("compare_digest", functions_with(run("timing-compare")),
                      "a local compare_digest that uses == must still flag")

    def test_secret_sink_silent_on_rename(self):
        self.assertNotIn("rename_then_log", functions_with(run("secret-sink")),
                         "a renamed carrier is out of scope and must stay silent")

    def test_weak_random_exempts_csprng_and_secrets(self):
        funcs = functions_with(run("weak-random"))
        for fn in ("secure_pick", "issue_token_safely", "make_key_safely"):
            self.assertNotIn(fn, funcs, "%s uses a secure source" % fn)

    def test_weak_random_silent_on_simulation(self):
        funcs = functions_with(run("weak-random"))
        for fn in ("coin_flip", "pick", "reorder", "simulate", "make_noise"):
            self.assertNotIn(fn, funcs, "simulation use must stay silent: %s" % fn)

    def test_weak_random_resolves_import_aliases(self):
        funcs = functions_with(run("weak-random"))
        self.assertIn("issue_aliased_token", funcs, "import random as rnd must resolve")
        self.assertIn("issue_aliased_ri", funcs, "from random import x as y must resolve")

    def test_tls_catches_attribute_and_literal_kwargs_forms(self):
        funcs = functions_with(run("tls-verify"))
        for fn in ("build_session", "disable_on_module_session", "fetch_literal_kwargs"):
            self.assertIn(fn, funcs, "tls-verify must catch %s" % fn)

    def test_tls_silent_on_correct_usage(self):
        funcs = functions_with(run("tls-verify"))
        for fn in ("fetch_verified", "fetch_default", "fetch_custom_ca",
                   "session_verified", "session_literal_ca", "fetch_variable_kwargs"):
            self.assertNotIn(fn, funcs, "correct TLS usage must stay silent: %s" % fn)

    def test_ecb_silent_on_other_modes(self):
        funcs = functions_with(run("ecb-mode"))
        for fn in ("encrypt_cbc", "encrypt_gcm", "build_cbc_cipher"):
            self.assertNotIn(fn, funcs, "a confirmed non-ECB mode must stay silent: %s" % fn)

    def test_weak_hash_honours_usedforsecurity_false(self):
        funcs = functions_with(run("weak-hash"))
        self.assertNotIn("bucket", funcs, "usedforsecurity=False is a structural exemption")
        self.assertNotIn("store_strong", funcs, "SHA-256 is not a weak hash")

    def test_weak_hash_silent_without_security_context(self):
        self.assertNotIn("checksum_with", functions_with(run("weak-hash")),
                         "a context-free variable-algorithm checksum must stay silent")

    def test_hardcoded_secret_silent_on_placeholders_and_structure(self):
        findings = run("hardcoded-secret")
        targets = {dict(f.detail).get("target") for f in findings}
        for t in ("api_key_template", "default_password", "session_token", "AWS_KEY",
                  "name", "url", "url_example", "db_path", "path", "greeting",
                  "ua", "version", "log_fmt"):
            self.assertNotIn(t, targets,
                             "placeholder/structured/ordinary value must stay silent: %s" % t)

    def test_hardcoded_secret_catches_real_credentials(self):
        findings = run("hardcoded-secret")
        highs = {dict(f.detail).get("target") for f in findings if f.severity == "HIGH"}
        for t in ("api_key", "password", "private_key", "gh_token"):
            self.assertIn(t, highs, "a real credential must be HIGH: %s" % t)


class TestInfrastructure(unittest.TestCase):
    """Unreadable input is reported, never crashed on and never silently dropped."""

    def setUp(self):
        self.tmp = os.path.join(HERE, "_test_tmp")
        os.makedirs(self.tmp, exist_ok=True)
        self.bad = os.path.join(self.tmp, "broken.py")
        with open(self.bad, "w", encoding="utf-8") as fh:
            fh.write("def broken(:\n")
        self.good = os.path.join(self.tmp, "fine.py")
        with open(self.good, "w", encoding="utf-8") as fh:
            fh.write("def f():\n    try:\n        g()\n    except Exception:\n        pass\n")

    def tearDown(self):
        for p in (self.bad, self.good):
            if os.path.exists(p):
                os.remove(p)
        if os.path.isdir(self.tmp):
            os.rmdir(self.tmp)

    def test_unparseable_file_is_skipped_not_fatal(self):
        det = DETECTORS["swallowed-exception"]
        findings, skipped, _ = det.collect([self.bad, self.good])
        self.assertEqual(len(skipped), 1, "the broken file must be reported as skipped")
        self.assertIn("SyntaxError", skipped[0][1])
        self.assertEqual(len(findings), 1, "the readable file must still be analyzed")

    def test_partial_scan_is_visually_distinct(self):
        clean = report.render([], list(cryptolint.DETECTORS), 2, [])
        partial = report.render([], list(cryptolint.DETECTORS), 2,
                                [("x.py", "SyntaxError: invalid syntax")])
        self.assertIn("0 skipped (full coverage)", clean)
        self.assertIn("PARTIAL SCAN", partial)
        self.assertNotIn("PARTIAL SCAN", clean)


class TestOutputFormats(unittest.TestCase):
    """All three formats carry the same finding set."""

    def test_all_formats_agree(self):
        paths, total, _ = EXPECTED["tls-verify"]
        det = [DETECTORS["tls-verify"]]
        findings, skipped, stats = det[0].collect(paths)
        # collect() returns raw stat lines; the reporting layer takes
        # (detector-name, lines) pairs, which is how cryptolint.main wraps them.
        stats = [(det[0].NAME, stats)] if stats else []
        doc = json.loads(formats.to_json(findings, det, len(paths), skipped, stats))
        sarif = json.loads(formats.to_sarif(findings, det, len(paths), skipped, stats))
        self.assertEqual(len(doc["findings"]), total)
        self.assertEqual(len(sarif["runs"][0]["results"]), total)
        self.assertEqual(doc["summary"]["total"], total)

    def test_sarif_validates_against_the_official_schema(self):
        """The release gate. Skipped VISIBLY when jsonschema is absent."""
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed -- run `pip install -e .[dev]` "
                          "to run the real SARIF schema validation")
        schema_path = os.path.join(HERE, "sarif-2.1.0.schema.json")
        if not os.path.exists(schema_path):
            self.skipTest("SARIF schema not vendored at %s -- fetch it to run this test"
                          % schema_path)
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        paths, _, _ = EXPECTED["hardcoded-secret"]
        det = [DETECTORS["hardcoded-secret"]]
        findings, skipped, stats = det[0].collect(paths)
        stats = [(det[0].NAME, stats)] if stats else []
        doc = json.loads(formats.to_sarif(findings, det, len(paths), skipped, stats))
        errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc),
                        key=lambda e: list(e.absolute_path))
        self.assertEqual(errors, [], "SARIF schema errors: %s"
                         % [e.message[:120] for e in errors[:5]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
