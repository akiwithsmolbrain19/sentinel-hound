# Architecture decision records — Sentinel Hound

## 1. Stdlib-only, zero runtime dependencies
- Context: lab tool that must run on stock installs.
- Alternatives: click/typer, rich, pandas, SQLAlchemy.
- Decision: stdlib only (argparse, sqlite3, unittest, http.server).
- Rationale: zero install friction, tiny attack surface, reproducible.
- Tradeoffs: plainer CLI/HTML output; hand-rolled parsing.
- Consequences: dev tooling (ruff/bandit/pytest) stays optional, never runtime deps.

## 2. Regex web-signature detection framed as triage signal
- Context: need exploit-probe visibility without a WAF.
- Alternatives: no signatures; full parser/normalizer.
- Decision: regex signatures on attacker-controlled fields, explicitly documented as evadable.
- Rationale: cheap, explainable baseline.
- Tradeoffs: FPs on odd-benign input; FNs on encoded/novel payloads.
- Consequences: never present as proof; adversarial cases in docs/DETECTION-REVIEW.md.

## 3. Sliding time windows with count fallback for SSH rules
- Context: logs may lack parseable timestamps.
- Alternatives: strict time-window only; pure counts.
- Decision: time window when timestamps exist, count fallback otherwise.
- Rationale: graceful degradation on real-world messy logs.
- Tradeoffs: fallback windows are less precise; document which mode fired.
- Consequences: tests cover both modes (timestamped + timestamp-less).

## 4. SQLite case store + localhost-only web UI without auth
- Context: need alert lifecycle without Elastic/Splunk.
- Alternatives: flat files; full web framework with auth.
- Decision: SQLite workflow (`open → investigating → closed/false_positive`) + minimal stdlib `http.server` UI bound to localhost.
- Rationale: persistent, queryable, zero deps.
- Tradeoffs: no multi-user/auth — local-only by design; `serve` must never bind public interfaces.
- Consequences: RUNBOOK documents localhost-only constraint.

## 5. MITRE ATT&CK IDs as analyst hints, not verdicts
- Context: every finding carries technique IDs.
- Alternatives: no mapping; per-alert confidence in mapping.
- Decision: map to best-fit technique, documented as defensible-but-debatable (see DECISION log when disputed).
- Rationale: common analyst language, training value.
- Tradeoffs: heuristic→technique mapping is inherently approximate.
- Consequences: challenge mappings in review; record rejections.
