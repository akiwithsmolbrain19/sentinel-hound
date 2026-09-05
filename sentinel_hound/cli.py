"""CLI: analyze logs -> findings -> SQLite cases + reports. Stdlib only (argparse)."""
import argparse
import json
import os
import sys

from .parser import parse_auth_log, parse_access_log
from .detections import run_all_detections
from .intel import load_iocs, load_allowlist
from .cases import CaseStore
from .reporter import to_json, to_html, console_summary


def load_config(path):
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        print(f"warning: config not found: {path} (using defaults)", file=sys.stderr)
        return {}
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON in config {path}: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_analyze(args):
    if not args.auth_log and not args.access_log and not args.log:
        print("error: provide --auth-log and/or --access-log (or --log FILE)", file=sys.stderr)
        return 2
    events = []
    try:
        if args.auth_log:
            events += parse_auth_log(args.auth_log)
        if args.access_log:
            events += parse_access_log(args.access_log)
        if args.log and not events:
            with open(args.log, errors="replace") as fh:
                sample = fh.read(4096)
            if "sshd" in sample:
                events += parse_auth_log(args.log)
            else:
                events += parse_access_log(args.log)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: cannot read log: {e}", file=sys.stderr)
        return 2
    config = load_config(args.config)
    iocs = load_iocs(args.iocs) if args.iocs else {"ips": [], "domains": [], "hashes": []}
    allowlist = load_allowlist(args.allowlist) if args.allowlist else {"ips": []}
    findings = run_all_detections(events, config, iocs, allowlist)
    print(console_summary(findings))
    if args.json_out:
        to_json(findings, args.json_out)
        print(f"Wrote JSON: {args.json_out}")
    if args.html_out:
        to_html(findings, args.html_out)
        print(f"Wrote HTML: {args.html_out}")
    if args.db:
        store = CaseStore(args.db)
        store.add_findings(findings)
        store.close()
        print(f"Stored {len(findings)} finding(s) in {args.db}")
    return 0


def cmd_cases(args):
    if args.action == "set-status" and (args.id is None or args.status_set is None):
        print("error: set-status requires --id N --status-set {open,investigating,closed,false_positive}",
              file=sys.stderr)
        return 2
    store = CaseStore(args.db)
    try:
        if args.action == "list":
            rows = store.list_cases(args.status)
            if not rows:
                print("(no cases)")
            for row in rows:
                print(f"#{row[0]} [{row[3]}] {row[1]} {row[2]} ({row[4]}) \u2014 {row[5]}")
        elif args.action == "set-status":
            try:
                ok = store.set_status(args.id, args.status_set)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print("updated" if ok else "not found")
            return 0 if ok else 1
    finally:
        store.close()
    return 0


def cmd_serve(args):
    from .web import serve
    if args.port < 1 or args.port > 65535:
        print("error: --port must be 1-65535", file=sys.stderr)
        return 2
    serve(args.db, args.port)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="sentinel-hound",
                                description="Local-first log threat detection + SOC triage")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze log files")
    a.add_argument("--auth-log", default=None)
    a.add_argument("--access-log", default=None)
    a.add_argument("--log", default=None, help="auto-detect single log file")
    a.add_argument("--config", default="config/rules.json")
    a.add_argument("--iocs", default="config/iocs.json")
    a.add_argument("--allowlist", default="config/allowlist.json",
                   help="trusted IPs skipped by all rules")
    a.add_argument("--json-out", default=None)
    a.add_argument("--html-out", default=None)
    a.add_argument("--db", default=None)
    a.set_defaults(func=cmd_analyze)
    c = sub.add_parser("cases", help="triage stored cases")
    c.add_argument("action", choices=["list", "set-status"])
    c.add_argument("--db", default="sentinel.db")
    c.add_argument("--status", default=None)
    c.add_argument("--id", type=int, default=None)
    c.add_argument("--status-set", default=None)
    c.set_defaults(func=cmd_cases)
    s = sub.add_parser("serve", help="serve minimal case-review web UI (localhost only)")
    s.add_argument("--db", default="sentinel.db")
    s.add_argument("--port", type=int, default=8620)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
