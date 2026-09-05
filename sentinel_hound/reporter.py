"""Reporters: console table, JSON, and single-file HTML dashboard."""
import html
import json
from datetime import datetime, timezone

RESPONSE_PLAYBOOK = {
    "SSH_BRUTEFORCE": "Block IOC at firewall, enforce key-only SSH, review Accepted logins.",
    "SSH_SUCCESS_AFTER_FAILS": "Treat as compromise: isolate host, rotate creds/keys, hunt lateral movement.",
    "WEB_SCANNER": "Review WAF logs, block scanner IP if external, check for follow-on exploit probes.",
    "WEB_EXPLOIT_PROBE": "Check app logs for 200s on probed URLs, patch app, review WAF blocks.",
    "HIGH_404_RATE": "Usually recon; correlate with scanner/exploit findings before escalating.",
    "IOC_MATCH": "Block at perimeter, hunt across all telemetry for the IOC.",
}


def to_json(findings, dest):
    with open(dest, "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(),
                   "finding_count": len(findings), "findings": findings}, f, indent=2)
    return dest


def console_summary(findings):
    lines = [f"[sentinel-hound] {len(findings)} finding(s)"]
    for f in findings:
        lines.append(f"  [{str(f.get('severity','?')).upper():8}] {f.get('rule_id','?'):24} "
                     f"{str(f.get('src_ip','-')):15} {str(f.get('description',''))[:100]}")
    return "\n".join(lines)


def to_html(findings, dest, title="Sentinel Hound Report"):
    cards = []
    for f in findings:
        ev = "".join(f"<li><code>{html.escape(str(x)[:300])}</code></li>"
                      for x in f.get("evidence", [])[:5])
        cards.append(
            f"<section><h2>[{html.escape(str(f.get('severity','')))}] "
            f"{html.escape(str(f.get('rule_id','')))} — {html.escape(str(f.get('src_ip','')))}</h2>"
            f"<p><b>{html.escape(str(f.get('title','')))}</b><br>{html.escape(str(f.get('description','')))}</p>"
            f"<p>MITRE: {html.escape(' / '.join(f.get('mitre', [])))} "
            f"({html.escape(str(f.get('tactic','')))})</p>"
            f"<p>Response: {html.escape(str(f.get('response', RESPONSE_PLAYBOOK.get(f.get('rule_id',''), 'Triage per runbook.'))))}</p>"
            f"<ul>{ev}</ul></section>")
    body = "\n".join(cards) or "<p>No findings — clean.</p>"
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1420;color:#e6e9f0;max-width:60rem}}
section{{border:1px solid #333;padding:1rem;margin-bottom:1rem;background:#151c2a}}
code{{font-size:.8rem;word-break:break-all}}</style>
</head><body><h1>Sentinel Hound Report</h1>
<p>Generated {html.escape(datetime.now(timezone.utc).isoformat())} — {len(findings)} finding(s). Lab/defensive use only.</p>
{body}</body></html>"""
    with open(dest, "w") as f:
        f.write(page)
    return dest
