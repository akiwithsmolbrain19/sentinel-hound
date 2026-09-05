"""Minimal read-mostly web UI for case review (stdlib http.server, no dependencies).

Localhost-only triage helper, NOT a production console: no auth, no TLS.
Binds 127.0.0.1 by default; never expose to a network. For real use, put it
behind SSH port-forwarding and rely on the SQLite file permissions.
"""
import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from .cases import CaseStore

STATUSES = ("open", "investigating", "closed", "false_positive")
SEV_COLOR = {"critical": "#ff6b6b", "high": "#ffa94d", "medium": "#ffd43b", "low": "#69db7c"}


def case_rows(store, status=None):
    return store.list_cases(status)


def render(status_filter=None):
    store = CaseStore(_DB)
    try:
        rows = case_rows(store, status_filter)
    finally:
        store.close()
    filt_links = " | ".join(
        f'<a href="/?status={s}">{s}</a>' for s in ("all",) + STATUSES)
    trs = []
    for cid, rule, ip, sev, st, title, desc in rows:
        color = SEV_COLOR.get(sev, "#e6e9f0")
        opts = "".join(
            f'<option value="{s}"{" selected" if s == st else ""}>{s}</option>'
            for s in STATUSES)
        trs.append(
            f"<tr><td>#{cid}</td>"
            f'<td style="color:{color}"><b>{html.escape(str(sev))}</b></td>'
            f"<td>{html.escape(str(rule))}</td><td>{html.escape(str(ip))}</td>"
            f"<td>{html.escape(str(title))}<br><small>{html.escape(str(desc)[:200])}</small></td>"
            f"<td>{html.escape(str(st))}</td>"
            f'<td><form method="post" action="/status">'
            f'<input type="hidden" name="id" value="{cid}">'
            f'<select name="status">{opts}</select> '
            f'<button type="submit">set</button></form></td></tr>')
    body = "\n".join(trs) or '<tr><td colspan="7">No cases.</td></tr>'
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Sentinel Hound Cases</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1420;color:#e6e9f0}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #333;padding:.5rem;text-align:left;vertical-align:top}}
a{{color:#74c0fc}}small{{color:#adb5bd}}</style>
</head><body><h1>Sentinel Hound Cases</h1>
<p>Filter: {filt_links}</p>
<table><tr><th>ID</th><th>Sev</th><th>Rule</th><th>IP</th><th>Title / description</th><th>Status</th><th>Triage</th></tr>
{body}</table>
<p><small>Localhost-only lab tool. No auth — do not expose to a network.</small></p>
</body></html>"""


_DB = "sentinel.db"


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelHound/1.0"

    def log_message(self, *a):
        pass  # keep lab output clean; front with a real server for access logs

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/":
            self.send_error(404, "not found")
            return
        qs = urllib.parse.parse_qs(parsed.query)
        status = (qs.get("status", [None])[0] or None)
        if status == "all":
            status = None
        if status is not None and status not in STATUSES:
            self.send_error(400, "bad status filter")
            return
        page = render(status).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/status":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 4096:  # tiny form; reject anything bigger
            self.send_error(413, "form too large")
            return
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        try:
            cid = int((form.get("id", [""])[0] or "").strip())
        except ValueError:
            self.send_error(400, "bad id")
            return
        status = (form.get("status", [""])[0] or "").strip()
        store = CaseStore(_DB)
        try:
            try:
                ok = store.set_status(cid, status)
            except ValueError:
                self.send_error(400, "bad status")
                return
        finally:
            store.close()
        if not ok:
            self.send_error(404, "case not found")
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def serve(db="sentinel.db", port=8620):
    """Run the UI forever. Always binds 127.0.0.1 (refuses other hosts)."""
    global _DB
    _DB = db
    httpd = HTTPServer(("127.0.0.1", port), Handler)
    print(f"serving cases from {db} at http://127.0.0.1:{port}/ (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
