# cryptolint

A static analyzer for Python cryptographic misuse, built on a single rule:
**never report more confidence than it has, and never hide what it cannot see.**

Most of the work in a security linter is not finding suspicious code. It is
deciding what to do when the evidence is incomplete — and being straight with
the reader about which case you are in. cryptolint is organised around that
decision. Every finding says how sure it is and why. Every run says what it
skipped, what was muted, and what it structurally cannot cover.

---

## What makes it different

### Confidence tiers that mean something

| tier | meaning |
|---|---|
| **HIGH** | Confirmed. The construct is what the detector says it is. |
| **MEDIUM** | The error left a trace but did not propagate. |
| **REVIEW** | *Cannot confirm.* The tool sees something it is unable to resolve — a value from a variable, a helper it cannot find, a body it cannot classify. Worth a human look. |
| **LOW** | A weak signal, surfaced quietly so it can be filtered. |

REVIEW is the tier that carries the design. When a detector meets a value it
cannot read — `requests.get(url, verify=flag)`, `AES.new(key, mode)`,
`hashlib.new(algo)` — it does not guess in either direction. Asserting HIGH
would claim certainty it lacks; going silent would hide a possible bug. It says
so, and moves on.

Every finding carries the evidence that produced it:

```
HIGH   timing-compare  auth.py:150  load_user()  eq-compare-of-secret
       (name=jwt_token_key, precision=high, op=!=, left=user.jwt_token_key, right=user_jwt_token)
```

### Active disclosure

Every run states its own coverage, whether or not there is anything to report.
A scan that skipped files is impossible to mistake for a clean one:

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! PARTIAL SCAN -- scanned 4319 of 4336 files | 17 SKIPPED
!! These files were NOT analyzed. Findings below are incomplete.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! SKIPPED src/migrations/0021_rename_....py -- FileNotFoundError: ...
```

A clean scan says `scanned 15 of 15 files | 0 skipped (full coverage)` — silence
is confirmed, not assumed. The same applies to suppression counts, which are
printed on every run including when they are zero.

### A limitation ledger that ships with the tool

Twenty-eight documented limitations — twenty-six detector-specific, two shared —
print in every run's banner. They are specific, not hedges:

> *indirect flow is matched by VARIABLE NAME only. A rename (`x = token; y = x; log(y)`) is NOT tracked and stays silent by design — deep taint is out of scope.*

> *LOW-ENTROPY REAL SECRETS ARE MISSED: `password = "hunter2"` has no known format and little entropy, and is caught only via its target name.*

A false negative the tool knows about is written down. The goal is that a reader
never has to guess whether silence means "clean" or "not looked at".

### Suppression that never hides silently

Mute a finding where the code is, with a mandatory reason:

```python
is_private = random.choice([True, False])  # cryptolint: ignore[weak-random] -- boolean flag, not key material
```

The suppression is specific — that rule, that line, nothing else — and the tool
reports it regardless:

```
suppressed: 2 (INCLUDING 1 HIGH -- hidden from the working view)
  !! HIGH suppressed: secret-sink app.py:23  -- demo fixture, not a real credential
UNUSED suppressions: 1 (matched no current finding -- stale?)
MALFORMED suppressions: 2 (ignored -- they suppress nothing)
```

An ignore with no reason is reported as malformed and suppresses nothing. An
ignore for the wrong rule does not suppress. A suppression that no longer
matches anything is reported as stale. Suppressed findings stay in the JSON and
SARIF output, marked — hidden from the working view, never from the record.

---

## What it is not

**cryptolint is not a replacement for Bandit or Semgrep.** Those tools have far
broader rule coverage, multi-language support, cross-file taint analysis, and
years of hardening against real codebases. If you need breadth, use them.

cryptolint covers eight checks for a specific class of Python crypto misuse. Its
distinction is discipline, not coverage: tight confidence tiers, disclosed gaps,
and a refusal to guess. Running it alongside a broader scanner is the sensible
arrangement, not running it instead.

Stating this plainly is the same standard the tool applies to the code it reads.

---

## How it works

Pure `ast` from the standard library — no external dependencies, no pattern
matching over source text. Each detector walks the parse tree and matches
**structural node shapes**, which is what lets exemptions be structural too:

- **#2 timing-compare** trusts `hmac.compare_digest(...)` because its callee is
  an `Attribute` whose base resolves to the `hmac` module — not because a
  function is *named* `compare_digest`. A local look-alike is not trusted.
- **#4 weak-random** exempts `random.SystemRandom().randint(...)` by walking the
  callee's base chain for the CSPRNG constructor, even though the function name
  is identical to the insecure form.
- **#1 swallowed-exception** decides whether a broad `except` is handled by
  *resolving the helper it delegates to* and confirming that definition contains
  a `raise` — including a conditional one. A helper it cannot resolve is REVIEW,
  never silently trusted.

**Shared machinery, one copy each.** Secret-name classification
(`secret_names.py`) assigns every identifier a precision: *high* (`password`,
`api_key`, `token`) or *collision-prone* (`key`, `hash`, `digest`, `sig` — words
that usually mean a dict key or a checksum). A combination rule keeps the
catastrophes: `private` alone is collision-prone, but `private_key` and
`signing_key` are high. Test-file recognition and severity down-tiering
(`tiering.py`), AST traversal (`ast_helpers.py`), and file reading
(`source_files.py`) are each defined once and imported by every detector.

**Two detectors are flow-aware.** `secret-sink` tracks a secret through a
same-function variable assignment into a log or exception message.
`weak-random` tracks a stored generator (`rng = np.random.default_rng()`) to its
uses. Both stop at the same boundary: when a name is aliased, passed, stored on
an attribute or returned, tracking ends and the detector goes **silent** rather
than guessing. That boundary is documented, not incidental.

**Context decides, not keywords.** `hashlib.md5()` is a bug when it hashes a
password and fine when it makes a cache key, so `weak-hash` requires a security
signal — a secret input, a secret-named target, or a security-named function —
before it reports anything. `weak-random` applies the same idea to numpy: a
codebase full of `rng.normal()` Monte Carlo draws produces no findings.

---

## What it detects

**Crypto-specific**

| detector | what it catches |
|---|---|
| `weak-random` | A non-cryptographic RNG (stdlib `random`, numpy) feeding a token, key or nonce — predictable output where unpredictability was the point. |
| `tls-verify` | Certificate verification disabled (`verify=False`, `s.verify = False`, unverified SSL context, `CERT_NONE`) — HTTPS that accepts any certificate. |
| `ecb-mode` | ECB cipher mode, where identical plaintext blocks produce identical ciphertext, leaking structure and permitting block manipulation. |
| `weak-hash` | MD5, SHA-1 or MD4 used for security work — broken primitives that cannot carry an integrity or authentication guarantee. |
| `hardcoded-secret` | A credential written into the source, separated from placeholders, published examples and test fixtures. |
| `timing-compare` | A secret compared with `==`/`!=`, which short-circuits and leaks how many leading bytes matched. |

**Silent failure**

| detector | what it catches |
|---|---|
| `swallowed-exception` | A broad `except` whose body discards the error — the bug that turns a `NameError` into a silent `None` that reads downstream as a normal result. |
| `secret-sink` | A secret-named value reaching a log, `print`, or exception message, where it is persisted somewhere it was never meant to go. |

Each carries the confidence tiers above: a form the detector can confirm is
HIGH, a form it cannot resolve is REVIEW, and a form with no supporting context
is silent by design.

---

## Usage

```bash
python cryptolint.py src/                     # all eight detectors
python cryptolint.py --only timing,sink src/  # a subset
python cryptolint.py --skip swallowed src/
python cryptolint.py --severity-threshold HIGH src/
python cryptolint.py --show-suppressed src/
python cryptolint.py --format json src/
python cryptolint.py --format sarif src/ > results.sarif
python cryptolint.py --config ci/.cryptolint.toml src/
```

A path may be a file or a directory (walked for `*.py`).

> **Note on `swallowed-exception`:** pass the whole tree in one invocation. It
> resolves remediation helpers across the files given to that run, so scanning
> file-by-file makes cross-file helpers read as unresolved.

### Output

```
==============================================================================
FINDINGS  (severity, then file, then line)
==============================================================================
HIGH   weak-random          examples/mixed_demo.py:9   issue()  insecure RNG feeds a security-sensitive value  (call=random.randbytes, target=token/high, shape=randbytes)
HIGH   timing-compare       examples/mixed_demo.py:10  issue()  eq-compare-of-secret  (name=api_key, precision=high, op===, left=api_key, right=real_key)
HIGH   secret-sink          examples/mixed_demo.py:11  issue()  secret reaches logger.error(...)  (name=token, precision=high, flow=direct, sink=logger.error(...))
HIGH   swallowed-exception  examples/mixed_demo.py:15  issue()  silent  (trigger=Exception)

==============================================================================
SUMMARY
  total findings: 4
  by severity: HIGH 4 | MEDIUM 0 | REVIEW 0 | LOW 0
  suppressed: 0
```

Findings sort by severity across detectors, so the confident view is at the top
regardless of which rule produced it. The full run also prints coverage, the
shared naming rules, each detector's decision order, and the limitation ledger.

`--severity-threshold` filters the **human view only**. Below-threshold findings
stay in the counts and in the machine formats — a threshold never deletes a
finding.

**JSON** (`--format json`) carries every field the human report does, plus the
skipped-file list and suppression state.

**SARIF** (`--format sarif`) emits SARIF 2.1.0 for CI ingestion, with rule
declarations, `error`/`warning`/`note` levels, the true cryptolint severity
preserved in `properties.cryptolintSeverity`, and suppressed results marked via
SARIF's native `suppressions` array.

> The SARIF output is **validated against the official SARIF 2.1.0 JSON Schema**
> (0 errors; `run_tests.py` runs this check when `jsonschema` is installed). It
> has **not** been verified against GitHub code scanning ingestion, and
> `partialFingerprints` / `artifacts[]` are not emitted. See
> [Limitations](#limitations).

### Configuration

Optional `.cryptolint.toml` in the working directory. **Config supplies
defaults; the command line overrides them.**

```toml
detectors = ["timing-compare", "secret-sink"]   # default: all eight
severity_threshold = "REVIEW"                   # default: show every tier
skip_paths = ["**/migrations/**"]               # default: skip nothing

[[suppress]]                    # fallback for code you cannot edit
detector = "weak-random"
file = "vendor/generated.py"
function = "build"
identifier = "key"
reason = "generated file, value is a dict key"
```

Inline suppression is the primary mechanism, because the reason then lives in
the diff where a reviewer sees it:

```python
# cryptolint: ignore[<rule>] -- <reason>
```

The reason is mandatory. Rule ids are the detector names: `swallowed-exception`,
`timing-compare`, `secret-sink`, `weak-random`, `tls-verify`, `ecb-mode`,
`weak-hash`, `hardcoded-secret`.

---

## Limitations

The full ledger prints under `KNOWN LIMITATIONS` on every run. It is meant to be
read. A selection:

**Cross-file and flow**
- Helper resolution for `swallowed-exception` covers only the files passed to a
  single run.
- Secret flow is matched by variable name within one function. Renames, values
  passed to other functions, and attribute-stored state are not tracked, and the
  detector goes silent rather than guessing.
- Generator instance tracking (`weak-random`) ends when the name is aliased,
  passed, stored or returned.

**Recognition boundaries**
- `weak-random` resolves module-level import aliases for `random` and `numpy`
  only; arbitrary indirection (`r = random; r.randint(...)`) is not tracked.
- `hardcoded-secret` misses low-entropy real secrets with no known format, and
  reads only literal strings — a value assembled entirely from variables is not
  seen. It flags an assembled value only when it starts with a known credential
  prefix.
- `weak-hash` and `secret-sink` rely on name-based signals; `key`, `hash` and
  `digest` are exactly what innocent checksum variables are called, so
  collision-prone names produce REVIEW noise in the fuzzy tier.

**Accepted false positives, in the safe direction**
- A non-HTTP function with its own `verify=` parameter flags in `tls-verify`.
- ECB over a single block of already-random data (a KEK key wrap) flags in
  `ecb-mode` — a reviewer should glance at any ECB use.

**Platform and tooling**
- Windows `MAX_PATH`: paths over 260 characters cannot be opened, and
  `os.path.exists()` reports `False` rather than raising. Such files are reported
  as skipped, never silently dropped. Long-path support is not implemented.
- SARIF output **is** validated against the official SARIF 2.1.0 JSON Schema
  (draft-07), with zero errors, as part of the test suite. It has **not** been
  verified against GitHub code scanning ingestion — that needs a real repository
  push and is untested here. `partialFingerprints` (used by GitHub to dedup
  alerts across runs) and `artifacts[]` are not emitted.

---

## Install

Not published to PyPI. Install from a clone:

```bash
git clone <repository-url>
cd cryptolint
pip install .            # provides a `cryptolint` command
cryptolint path/to/your/code
```

Or run it directly with no install at all:

```bash
python cryptolint.py path/to/your/code
```

**Zero runtime dependencies** — the tool imports only the standard library
(`ast`, `re`, `json`, `math`, `os`, `sys`, `fnmatch`, `builtins`, `dataclasses`,
`tomllib`). Verified by auditing every import across all modules.

Requires **Python 3.11+**, the floor set by `tomllib` (config parsing).
Developed and tested on Python 3.12; 3.11 is inferred from the stdlib
requirement and has not been separately exercised here.

`pip install cryptolint` from PyPI does not work — no package has been
published.

## Development

```bash
python run_tests.py          # 28 tests, stdlib unittest, no pytest needed
pip install -e ".[dev]"      # adds jsonschema for the SARIF schema test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for what the suite asserts and how to add
a detector.
