# Contributing

## Running the tests

```bash
python run_tests.py              # verbose, all 28 tests
python -m unittest run_tests -v  # same suite via unittest
```

The suite is plain `unittest` from the standard library — **pytest is not
required and is not a dependency**. `python -m pytest run_tests.py` also works
if you happen to have pytest installed, since pytest collects `unittest.TestCase`
classes, but nothing here depends on it.

One test needs an optional dependency:

```bash
pip install -e ".[dev]"          # installs jsonschema
```

`test_sarif_validates_against_the_official_schema` validates the tool's SARIF
output against the vendored SARIF 2.1.0 JSON Schema
(`sarif-2.1.0.schema.json`). Without `jsonschema` it **skips with a visible
message** rather than passing quietly — a skipped check must never look like a
passed one.

### What the suite actually checks

A test that runs code without checking the result is the failure mode this
project exists to catch, so the suite asserts on four levels:

1. **Exact counts** — every detector's corpus produces a recorded total *and*
   per-severity breakdown. A finding that appears, vanishes, or changes tier
   fails.
2. **Named invariants** — specific must-flag and must-stay-silent behaviours,
   asserted individually, because counts alone could stay right while two
   findings swapped places.
3. **Structural exemptions** — `hmac.compare_digest`, `random.SystemRandom`,
   `usedforsecurity=False` and published example keys are asserted *silent*. A
   broken exemption is a false positive on correct code.
4. **Infrastructure** — an unparseable file is reported as skipped, the readable
   files are still analyzed, and a partial scan renders visibly differently from
   a clean one.

If you change detection behaviour, the counts in `EXPECTED` will move. Update
them to the **measured** values and say so in the change description — never
adjust a corpus to make a test pass.

## Adding a detector

Detectors plug in through one interface. Nothing in the reporting, serialization,
suppression or config layers needs to know a new detector exists — the last three
detectors were each added by touching `cryptolint.py` only.

A detector module exposes:

```python
NAME = "your-rule"                      # the rule id, used in output,
                                        # SARIF ruleId, and ignore[...] comments
SUMMARY = "one line: what the bug is"   # shown in the banner and SARIF
RULES = [...]                           # the decision logic, printed every run
LIMITS = [...]                          # what it does NOT catch, printed every run

def collect(paths):
    """-> (findings, skipped, stats)"""
    ...
```

`collect` returns:

- **findings** — `findings.Finding` objects: `detector`, `file`, `line`,
  `function`, `severity` (`HIGH`/`MEDIUM`/`REVIEW`/`LOW`), `message`, and
  ordered `detail` pairs built with `findings.detail(...)`.
- **skipped** — `(path, reason)` for every file that could not be read or
  parsed. Use `source_files.safe_parse`; never open files directly, or a bad
  file will abort the run instead of being reported.
- **stats** — optional lines for the coverage block (e.g. "N calls seen, M
  silent by design").

Then register it in `cryptolint.py`: an import, an entry in `DETECTORS`, and a
short alias in `ALIASES`. That is the whole wiring.

### Shared machinery — import it, do not copy it

| helper | module | use it for |
|---|---|---|
| `safe_parse`, `format_coverage` | `source_files` | reading and parsing files |
| `enclosing_function`, `link_parents` | `ast_helpers` | AST traversal |
| `is_test_path`, `down_tier`, `IN_TEST_PAIR` | `tiering` | test-file recognition and down-tiering |
| `precision_of`, `matched_component` | `secret_names` | secret-name classification |
| `Finding`, `detail` | `findings` | building findings |

Each of these was extracted after copies drifted across detectors. If you find
yourself writing a second version of one, import the first instead.

### Conventions a new detector is expected to follow

- **State every choice.** If your detector down-tiers in test files, say why in
  `RULES`; if it deliberately stays HIGH, say why. Silence on the question is
  the thing the consistency passes were for.
- **A value you cannot read is REVIEW, not a guess.** `verify=flag`,
  `AES.new(key, mode)`, `hashlib.new(algo)` all resolve this way. Asserting
  HIGH claims certainty you lack; going silent hides a possible bug.
- **Exemptions are structural, never nominal.** Trust `hmac.compare_digest`
  because the callee resolves to the `hmac` module, not because a function is
  named `compare_digest`.
- **Document what you miss.** An undisclosed false negative is a defect here,
  not an omission. Put it in `LIMITS`, where it prints on every run.

## Corpus files

Each detector has a `testcases_*.py` corpus with the expected verdict labelled
in a comment above every case, including the cases that must stay **silent**.
Silent cases carry as much weight as findings — precision is the point.

Add cases for new behaviour in both directions: what it now catches, and what it
must still ignore.
