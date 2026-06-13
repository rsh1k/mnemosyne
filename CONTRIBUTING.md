# Contributing

Thanks for your interest in improving Mnemosyne. This project guards a security
boundary, so contributions are held to a high bar for tests and clarity.

## Development setup

```bash
git clone https://github.com/rsh1k/mnemosyne.git
cd mnemosyne
python -m venv .venv && source .venv/bin/activate
pip install -e ".[api,dev]"
pre-commit install
```

## The golden rule

Every change is checked by `make all` (lint, type-check, security scan, tests).
CI runs the same targets. Run it locally before opening a PR:

```bash
make all
```

Individual targets:

```bash
make test        # pytest
make lint        # ruff
make typecheck   # mypy
make security    # bandit + pip-audit
```

## Tests are mandatory

- New detectors, policy rules, or gateway behaviour **must** come with tests.
- Security-relevant changes should extend the **red-team corpus**
  (`tests/test_redteam_corpus.py`). If you add a detection capability, add the
  attack payloads it catches; if you relax something, prove benign writes still
  pass. The aggregate detection-rate / false-positive-rate assertions must stay
  green.
- The cardinal invariant (untrusted content never reaches the `INSTRUCTION`
  surface) is sacred. A PR that weakens it will not be merged without an
  explicit, documented security rationale.

## Adding a detector

1. Implement the `Detector` protocol in `src/mnemosyne/detectors/`.
2. Return a `ScanResult` of `Finding`s with a `severity`, a `score` in `[0,1]`,
   and a `metadata["kind"]` (use `secret`/`pii` only for sensitive-data findings
   — the policy engine routes those through the dedicated secrets rule).
3. Register it in `default_registry()` (or document it as opt-in).
4. Add unit tests and, where relevant, corpus entries.

## Changing policy

The default posture lives in `src/mnemosyne/policy/default_policy.yaml`. It is
security-critical configuration — explain the threat rationale in the PR. Keep
"most restrictive wins" intact.

## Updating the NIST mapping

The catalog in `src/mnemosyne/nist/__init__.py` is the single source of truth.
After editing it, regenerate the doc:

```bash
python scripts/gen_nist_doc.py
```

## Style

- Code is formatted/linted by `ruff` (line length 100) and type-checked by
  `mypy`. Public functions get type hints and a docstring explaining the *why*.
- Prefer clarity over cleverness; this is security code that will be audited.

## Commit / PR hygiene

- Small, focused PRs with a clear description of the threat or behaviour changed.
- Reference any related issue.
- By contributing you agree your contributions are licensed under Apache-2.0.
