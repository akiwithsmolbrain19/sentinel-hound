# Detection review — Sentinel Hound

Triage signals, not proof of compromise. For each rule: what triggers it, required
evidence, legitimate triggers, evasion, thresholds, FP/FN risks, analyst validation.

## SSH_BRUTEFORCE
- Triggers: ≥N failed sshd logins from one IP within window (`ssh_bruteforce_threshold`, `ssh_bruteforce_window_seconds`).
- Evidence: count of failed events + raw excerpts.
- Legitimate: misconfigured automation, monitoring logins, shared NAT egress.
- Evasion: low-and-slow (below threshold/window), password spraying across users/hosts, log deletion.
- FP risk: medium in noisy environments. FN risk: slow/distributed attacks.
- Validate: correlate with SUCCESS_AFTER_FAILS + IOC_MATCH; check `lastlog`, source reputation, auth success on host.

## SSH_SUCCESS_AFTER_FAILS (possible compromise)
- Triggers: success from an IP with recent prior failures within `ssh_success_window_seconds`.
- Evidence: prior-fail count + success line.
- Legitimate: user retrying after typos.
- Evasion: stolen-key login with no prior fails (no signal by design); wiped logs.
- FP risk: medium (typos). Treat as "investigate", never as confirmed compromise.
- Validate: was the login expected? new key/host? other successes from same IP?

## WEB_SCANNER
- Triggers: high request diversity/rate per IP (`web_scanner_threshold`).
- Evidence: request count, path entropy, UA.
- Legitimate: monitoring systems, legitimate scanners (e.g. approved vuln scans), crawlers, scheduled jobs.
- Evasion: low-and-slow, rotating IPs/UAs, browsing-like pacing.
- Validate: UA + path patterns; is the source an approved scanner?

## WEB_EXPLOIT_PROBES (SQLi/LFI/RCE/XSS signatures)
- Triggers: regex match on attacker-controlled fields (path, query, UA).
- Evidence: matched pattern + raw line.
- Legitimate: security researchers testing own apps, WAF test traffic, false regex hits on odd-but-benign input.
- Evasion: encoding (URL/double/unicode), split payloads, POST bodies (if not parsed), novel payloads.
- FN risk: high against encoded/novel payloads — signatures are a floor, not a ceiling.
- Validate: response status/size, whether the app is actually vulnerable, WAF logs.

## HIGH_404_RATE
- Triggers: 404 ratio/count above threshold per IP.
- Evidence: 404 count vs total.
- Legitimate: broken links, moved content, aggressive crawlers on new sites.
- Evasion: targeted single-request exploitation (no 404s at all).
- Validate: which paths 404'd — random/probe-like or legitimate stale links?

## IOC_MATCH
- Triggers: source IP present in `config/iocs.json` (lab blocklist).
- Evidence: exact IOC entry.
- Legitimate: none if list is curated — but stale lists cause FPs; TEST-NET values are lab-only.
- Evasion: new infrastructure not on the list (expected — lists are always incomplete).
- Validate: list freshness, independent reputation check, correlation with behavioral rules.

## Adversarial testing examples
- Feed encoded payloads (`%27%20OR%201=1--`, `..%2f..%2fetc%2fpasswd`) — do signatures catch them? (Document gaps, don't overclaim.)
- Feed reordered/duplicated log lines, missing timestamps, rotated/truncated logs — parsers must not crash; detections degrade gracefully.
- Feed allowlisted IPs doing malicious-looking things — confirm they are skipped (allowlist = explicit blind spot, document it).
- Feed benign bursts (CI health checks) — confirm no critical findings.

## Log-specific limits (acknowledged, not solved)
Missing events, reordered events, timestamp skew, rotation gaps, attacker-controlled
fields, encoded payloads, duplicates, noisy legitimate traffic — implementation
degrades gracefully but does not solve these. Do not claim otherwise.
