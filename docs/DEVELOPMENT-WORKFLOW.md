# Development workflow — Sentinel Hound

```
Requirement
    ↓
AI design proposal
    ↓
Human review
    ↓
AI implementation
    ↓
Automated tests          python3 -m unittest discover -s tests -v
    ↓
Static analysis          python3 -m py_compile $(git ls-files '*.py')
    ↓
Security scanning        secret/signature scan (see Makefile `security`)
    ↓
Adversarial review       docs/DETECTION-REVIEW.md checklist
    ↓
Human git diff review    git status / git diff
    ↓
Commit (human only)
```

## Rules
- The human accepts or rejects every change. The AI is an assistant, not an authority.
- "Tests passed" is never sufficient alone: also require static analysis, security
  scan, adversarial review, and a human-read `git diff`.
- No auto-commit. No history rewrites. No fake commits.
- Commit granularity: one focused change per commit (e.g. "one rule + its tests").
- Tooling note (2026-09-06): this environment is offline with no pip; pytest/ruff/bandit
  are unavailable, so the Makefile uses stdlib gates (unittest, py_compile, grep-based
  secret scan). If ruff/bandit are installed later, prefer `ruff check .` and `bandit -r .`
  with narrow per-rule suppressions, and record the change in docs/DECISIONS.md.

## Change verification (per change)
1. What changed. 2. Why. 3. Security implications. 4. Failure modes.
5. Tests validating it. 6. Test run. 7. Lint/security run. 8. `git diff` shown.
