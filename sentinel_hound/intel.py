"""IOC loader: JSON blocklist of malicious IPs/domains/hashes (sample/lab only)."""
import json


def load_iocs(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"ips": [], "domains": [], "hashes": []}
    except (json.JSONDecodeError, OSError, AttributeError):
        return {"ips": [], "domains": [], "hashes": []}
    if not isinstance(data, dict):
        return {"ips": [], "domains": [], "hashes": []}
    return {"ips": [x for x in data.get("malicious_ips", []) if isinstance(x, str)],
            "domains": [x for x in data.get("malicious_domains", []) if isinstance(x, str)],
            "hashes": [x for x in data.get("malicious_hashes", []) if isinstance(x, str)]}


def load_allowlist(path):
    """Load trusted IPs skipped by all rules. Safe defaults on any error."""
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"ips": []}
        return {"ips": [x for x in data.get("ips", []) if isinstance(x, str)]}
    except (FileNotFoundError, json.JSONDecodeError, OSError, AttributeError):
        return {"ips": []}
