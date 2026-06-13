## Summary

<!-- What does this change and why? Reference any related issue. -->

## Type of change

- [ ] Bug fix
- [ ] New feature (detector / policy / endpoint)
- [ ] Refactor / internal
- [ ] Docs / NIST mapping

## Security considerations

<!-- Does this touch a trust boundary? If it changes the policy, the cardinal
     INSTRUCTION-surface invariant, or any detector, explain the threat rationale. -->

## Checklist

- [ ] `make all` passes locally (ruff, mypy, bandit, pytest)
- [ ] Added/updated tests; security-relevant changes extend the red-team corpus
- [ ] The cardinal invariant (untrusted content never reaches `INSTRUCTION`) is intact
- [ ] Updated docs and, if the control catalog changed, ran `python scripts/gen_nist_doc.py`
- [ ] Updated `CHANGELOG.md`
