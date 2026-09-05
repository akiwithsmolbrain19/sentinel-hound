"""Parsers for syslog auth logs and nginx/combined access logs -> normalized event dicts."""
import ipaddress
import re
from datetime import datetime

AUTH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<proc>sshd(?:\[\d+\])?):\s*(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+|\S+) port \d+")
ACCEPT_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)(?: "[^"]*" "(?P<ua>[^"]*)")?'
)
MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def _auth_ts(month, day, time, year=2026):
    try:
        h, m, s = map(int, time.split(":"))
        return datetime(year, MONTHS.get(month, 1), int(day), h, m, s).isoformat()
    except Exception:
        return None

def valid_ip(s):
    """Return IP string if valid IPv4/IPv6, else None (prevents garbage IOC joins)."""
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s.strip("[]")))
    except ValueError:
        return None


def parse_auth_log(path, year=2026):
    events = []
    try:
        f = open(path, errors="replace")
    except FileNotFoundError:
        raise FileNotFoundError(f"auth log not found: {path}")
    with f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = AUTH_RE.match(line)
            if not m:
                events.append({"source": "auth", "raw": line, "lineno": lineno,
                               "event_type": "unparsed", "src_ip": None, "user": None, "ts": None})
                continue
            msg = m.group("msg")
            fm, am = FAILED_RE.search(msg), ACCEPT_RE.search(msg)
            if fm:
                events.append({"source": "auth", "raw": line, "lineno": lineno,
                               "event_type": "ssh_failed", "src_ip": valid_ip(fm.group("ip")),
                               "user": fm.group("user"), "ts": _auth_ts(m.group("month"), m.group("day"), m.group("time"), year)})
            elif am:
                events.append({"source": "auth", "raw": line, "lineno": lineno,
                               "event_type": "ssh_success", "src_ip": valid_ip(am.group("ip")),
                               "user": am.group("user"), "ts": _auth_ts(m.group("month"), m.group("day"), m.group("time"), year)})
            else:
                events.append({"source": "auth", "raw": line, "lineno": lineno,
                               "event_type": "ssh_other", "src_ip": None, "user": None,
                               "ts": _auth_ts(m.group("month"), m.group("day"), m.group("time"), year)})
    return events

def parse_access_log(path):
    events = []
    try:
        f = open(path, errors="replace")
    except FileNotFoundError:
        raise FileNotFoundError(f"access log not found: {path}")
    with f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = ACCESS_RE.match(line)
            if not m:
                events.append({"source": "web", "raw": line, "lineno": lineno,
                               "event_type": "unparsed", "src_ip": None, "user": None, "ts": None})
                continue
            events.append({"source": "web", "raw": line, "lineno": lineno,
                           "event_type": "http_request", "src_ip": valid_ip(m.group("ip")),
                           "user": None, "ts": m.group("ts"), "method": m.group("method"),
                           "path": m.group("path"), "status": int(m.group("status")),
                           "ua": m.group("ua") or ""})
    return events

def normalize_event(e):
    e.setdefault("src_ip", None)
    e.setdefault("user", None)
    return e
