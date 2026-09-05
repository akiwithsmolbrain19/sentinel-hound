"""Detection engine: each rule returns finding dicts. Tuning lives in config/rules.json."""
import re
from datetime import datetime
from urllib.parse import unquote_plus
from collections import defaultdict, Counter

RULE_META = {
    "SSH_BRUTEFORCE": {"title": "SSH brute-force / password spraying", "severity": "high",
        "mitre": ["T1110.001", "T1021.004"], "tactic": "Credential Access / Lateral Movement"},
    "SSH_SUCCESS_AFTER_FAILS": {"title": "Successful SSH login after repeated failures (possible compromise)",
        "severity": "critical", "mitre": ["T1078"], "tactic": "Persistence"},
    "WEB_SCANNER": {"title": "Web path scanning / enumeration", "severity": "medium",
        "mitre": ["T1595.002", "T1083"], "tactic": "Reconnaissance / Discovery"},
    "WEB_EXPLOIT_PROBE": {"title": "Web exploit probe (SQLi/LFI/RCE patterns)", "severity": "high",
        "mitre": ["T1190"], "tactic": "Initial Access"},
    "HIGH_404_RATE": {"title": "High 404 rate from single source", "severity": "low",
        "mitre": ["T1595"], "tactic": "Reconnaissance"},
    "IOC_MATCH": {"title": "Traffic from known-malicious IOC", "severity": "critical",
        "mitre": ["T1071"], "tactic": "Command and Control"},
}

EXPLOIT_PATTERNS = [
    (r"(\%27|'|\"|%22).*(union|select|sleep\(|benchmark|or\s+1=1)", "sqli"),
    (r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow)", "lfi/path-traversal"),
    (r"(;\s*(cat|id|whoami|nc|curl|wget)\b|`[^`]+`|__import__|os\.system|\$\([a-z])", "rce"),
    (r"(<script|javascript:|onerror=|%3Cscript)", "xss"),
    (r"(wp-login\.php|xmlrpc\.php|\.env$|\.git/config|phpmyadmin|/wp-admin/?$)", "sensitive-path"),
]

def _windowed(events, key):
    """Group events per key."""
    groups = defaultdict(list)
    for e in events:
        k = e.get(key)
        if k:
            groups[k].append(e)
    return groups


def parse_ts(e):
    """Parse an event timestamp to datetime; None if missing/unparseable.

    Auth events carry ISO-8601; anything else is best-effort. A rule that
    needs time falls back to order/count-based logic when this is None.
    """
    ts = e.get("ts")
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def max_in_window(times, window_seconds):
    """Max events inside any sliding window of window_seconds (times sorted)."""
    best, start = 0, 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > window_seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def apply_allowlist(events, allowlist):
    """Drop events from trusted IPs (CI, monitors, own scanners)."""
    trusted = set((allowlist or {}).get("ips", []))
    if not trusted:
        return list(events)
    return [e for e in events if e.get("src_ip") not in trusted]


def detect_ssh_bruteforce(events, threshold=5, window_seconds=None):
    fails = [e for e in events if e.get("event_type") == "ssh_failed"]
    findings = []
    for ip, evs in _windowed(fails, "src_ip").items():
        timed = sorted(t for e in evs if (t := parse_ts(e)) is not None)
        if window_seconds and timed:
            count = max_in_window(timed, window_seconds)
            scope = f"within {window_seconds}s"
        else:
            count = len(evs)
            scope = "in batch"
        if count >= threshold:
            users = sorted({e.get("user") for e in evs if e.get("user")})
            findings.append({"rule_id": "SSH_BRUTEFORCE", **RULE_META["SSH_BRUTEFORCE"],
                "src_ip": ip, "count": count,
                "description": f"{count} failed SSH logins from {ip} {scope} targeting {len(users)} user(s): {', '.join(users[:5])}",
                "evidence": [e["raw"] for e in evs[:5]], "users": users})
    return findings

def detect_success_after_fails(events, threshold=3, window_seconds=None):
    findings = []
    fail_times = defaultdict(list)  # ip -> sorted datetimes of fails seen so far
    fail_counts = Counter()  # fallback when timestamps are absent
    for e in events:
        if e.get("event_type") == "ssh_failed" and e.get("src_ip"):
            fail_counts[e["src_ip"]] += 1
            if (t := parse_ts(e)) is not None:
                fail_times[e["src_ip"]].append(t)
        elif e.get("event_type") == "ssh_success" and e.get("src_ip"):
            ip = e["src_ip"]
            now = parse_ts(e)
            if window_seconds and now is not None and fail_times.get(ip):
                recent = sum((now - t).total_seconds() >= 0 and
                             (now - t).total_seconds() <= window_seconds
                             for t in fail_times[ip])
            else:
                recent = fail_counts.get(ip, 0)
            if recent >= threshold:
                findings.append({"rule_id": "SSH_SUCCESS_AFTER_FAILS", **RULE_META["SSH_SUCCESS_AFTER_FAILS"],
                    "src_ip": e["src_ip"], "count": recent,
                    "description": f"Successful SSH login for '{e.get('user')}' from {e['src_ip']} after {recent} prior failures — treat as possible compromise",
                    "evidence": [e["raw"]], "users": [e.get("user")],
                    "response": "Isolate host, rotate credentials/keys, hunt other Accepted logins, block IOC."})
    return findings

def detect_web_scanner(events, threshold=15):
    reqs = [e for e in events if e.get("event_type") == "http_request"]
    findings = []
    for ip, evs in _windowed(reqs, "src_ip").items():
        uniq = {e.get("path") for e in evs}
        if len(evs) >= threshold and len(uniq) >= threshold // 2:
            findings.append({"rule_id": "WEB_SCANNER", **RULE_META["WEB_SCANNER"],
                "src_ip": ip, "count": len(evs),
                "description": f"{len(evs)} requests to {len(uniq)} unique paths from {ip} — directory/scan behavior",
                "evidence": [e["raw"] for e in evs[:5]], "users": []})
    return findings

def detect_exploit_probes(events):
    compiled = [(re.compile(p, re.I), label) for p, label in EXPLOIT_PATTERNS]
    findings = []
    for e in events:
        if e.get("event_type") != "http_request":
            continue
        blob = unquote_plus(f"{e.get('path','')} {e.get('ua','')}")
        for rx, label in compiled:
            if rx.search(blob):
                findings.append({"rule_id": "WEB_EXPLOIT_PROBE", **RULE_META["WEB_EXPLOIT_PROBE"],
                    "src_ip": e.get("src_ip"), "count": 1,
                    "description": f"Possible {label} probe from {e.get('src_ip')}: {e.get('method')} {e.get('path')}",
                    "evidence": [e["raw"]], "users": [], "subtype": label})
                break
    return findings

def detect_high_404(events, threshold=10):
    reqs = [e for e in events if e.get("event_type") == "http_request" and e.get("status") == 404]
    findings = []
    for ip, evs in _windowed(reqs, "src_ip").items():
        if len(evs) >= threshold:
            findings.append({"rule_id": "HIGH_404_RATE", **RULE_META["HIGH_404_RATE"],
                "src_ip": ip, "count": len(evs),
                "description": f"{len(evs)} HTTP 404s from {ip} — possible forced browsing / enumeration",
                "evidence": [e["raw"] for e in evs[:5]], "users": []})
    return findings

def detect_ioc(events, iocs):
    ips = set(iocs.get("ips", []))
    groups = {}
    for e in events:
        if e.get("src_ip") in ips:
            groups.setdefault(e["src_ip"], []).append(e)
    findings = []
    for ip, evs in groups.items():
        kinds = sorted({e.get("event_type") for e in evs})
        findings.append({"rule_id": "IOC_MATCH", **RULE_META["IOC_MATCH"],
            "src_ip": ip, "count": len(evs),
            "description": f"{len(evs)} event(s) from blocklisted IOC {ip} [{', '.join(kinds)}]",
            "evidence": [e["raw"] for e in evs[:5]],
            "users": sorted({e.get("user") for e in evs if e.get("user")})})
    return findings

def run_all_detections(events, config=None, iocs=None, allowlist=None):
    config = config or {}
    iocs = iocs or {}
    events = apply_allowlist(events, allowlist)
    out = []
    out += detect_ssh_bruteforce(events, config.get("ssh_bruteforce_threshold", 5),
                                 config.get("ssh_bruteforce_window_seconds"))
    out += detect_success_after_fails(events, config.get("ssh_success_threshold", 3),
                                      config.get("ssh_success_window_seconds"))
    out += detect_web_scanner(events, config.get("web_scanner_threshold", 15))
    out += detect_exploit_probes(events)
    out += detect_high_404(events, config.get("high_404_threshold", 10))
    out += detect_ioc(events, iocs)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda f: (sev_rank.get(f["severity"], 9), f["rule_id"]))
