# AGENTS.md — AI-assisted security-engineering rules (Sentinel Hound)

## SECURITY
- Defensive security only. Lab, CTF, authorized testing, or owned systems only.
- Never introduce malware, persistence, credential theft, destructive behavior, unauthorized exploitation, or evasion.
- Treat all external input (log lines, IOC files, allowlists, CLI args) as untrusted. Parsers must not crash on malformed/empty input; use the `unparsed` fallback pattern.
- Never introduce secrets into source, tests, docs, or commits. Sample data uses RFC5737 TEST-NET addresses only.

## DEVELOPMENT
- Inspect existing code (`sentinel_hound/*.py`, `config/*.json`) before modifying it.
- Prefer small, focused changes. Do not rewrite working components without justification.
- Do not add dependencies: this project is stdlib-only by design. Any new dependency needs explicit human approval with rationale.
- Explain significant architectural tradeoffs (e.g. count-based vs time-based windows).
- Preserve CLI interfaces (`analyze`, `cases`, `serve`) unless the change is intentional and documented.

## TESTING
- Every new detection rule requires positive tests; add negative/benign tests where practical.
- Test threshold boundaries, malformed and empty input, and error paths.
- Run: `python3 -m unittest discover -s tests -v` (37 tests, stdlib only).
- Do not weaken or delete tests merely to make the implementation pass.
- Do not claim functionality that is not tested.

## SECURITY DETECTION QUALITY
- Detection heuristics are triage signals, not proof of compromise. Say so in code, docs, and reports.
- Document false-positive / false-negative considerations and detection assumptions.
- Challenge detection logic with adversarial examples (encoded payloads, attacker-controlled fields, log rotation gaps, noisy legitimate traffic).
- MITRE ATT&CK mappings must be defensible; record rationale in `docs/DECISIONS.md`.

## DOCUMENTATION
- Documentation must reflect actual implementation. No stale test counts, no unsupported capability claims.
- Limitations must be explicit. Sample data is synthetic/lab data — label it as such.

## GIT
- Never commit automatically. Never rewrite history. Never create fake historical commits.
- Keep commits focused. Inspect `git diff` before committing.
- Do not commit generated artifacts (`sentinel.db`, `report.json`, `report.html`) or secrets. See `.gitignore`.

## QUALITY
- Avoid resource leaks (close SQLite connections/files; context managers).
- Handle expected errors cleanly; validate user-controlled input (paths, IDs, statuses).
- Avoid unnecessary complexity. Keep code understandable to a human reviewer.
