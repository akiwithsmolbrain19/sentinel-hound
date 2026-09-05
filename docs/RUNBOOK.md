# Lab SOC runbook — triaging a Sentinel Hound alert (5–10 min)

1. `analyze` produces findings ranked critical → low. Start with `SSH_SUCCESS_AFTER_FAILS` / `IOC_MATCH`.
2. Read evidence lines (raw log excerpts stored in the finding + JSON report).
3. Correlate: same `src_ip` across rules? e.g. `203.0.113.45` hits SSH_BRUTEFORCE + SUCCESS_AFTER_FAILS + IOC_MATCH → single incident, not three.
4. Store in SQLite: `--db sentinel.db`, then `cases list` / `cases set-status`.
5. Decide: `investigating` (needs log/host check) → `closed` (contained: rotate creds, block IP, patch) or `false_positive` (document why).
6. Response checklist for SSH compromise: isolate host, force password/key rotation, check `lastlog`/`auth.log` for other successes, block IOC at firewall, review web logs for same IP.

## Example session

```
python3 -m sentinel_hound.cli analyze --auth-log sample_data/auth.log --access-log sample_data/access.log --db sentinel.db --html-out report.html
python3 -m sentinel_hound.cli cases list --db sentinel.db
python3 -m sentinel_hound.cli cases set-status --db sentinel.db --id 3 --status-set investigating
```

# Tuning guide

- `config/rules.json` thresholds: raise `ssh_bruteforce_threshold` if your baseline has noisy scanners; lower `web_scanner_threshold` for low-traffic internal apps.
- Known limitations: count-based windows (no true time-window yet), regex web signatures (evadable), no auth for the HTML report (local file only).
