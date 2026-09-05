"""SQLite-backed case store for SOC triage workflow (stdlib sqlite3)."""
import json
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT, src_ip TEXT, severity TEXT, status TEXT DEFAULT 'open',
  title TEXT, description TEXT, evidence TEXT, created_at REAL, updated_at REAL
);
"""

class CaseStore:
    def __init__(self, path="sentinel.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def list_cases(self, status=None):
        q = "SELECT id, rule_id, src_ip, severity, status, title, description FROM cases"
        args = ()
        if status:
            q += " WHERE status=?"; args = (status,)
        q += " ORDER BY id"
        return self.conn.execute(q, args).fetchall()

    def add_findings(self, findings):
        """Insert findings; skip exact duplicates (same rule+ip+description)."""
        now = time.time()
        for f in findings:
            dup = self.conn.execute(
                "SELECT 1 FROM cases WHERE rule_id=? AND IFNULL(src_ip,'')=IFNULL(?, '') AND description=? LIMIT 1",
                (f["rule_id"], f.get("src_ip"), f["description"])).fetchone()
            if dup:
                continue
            self.conn.execute(
                "INSERT INTO cases (rule_id, src_ip, severity, status, title, description, evidence, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (f["rule_id"], f.get("src_ip"), f["severity"], "open", f["title"],
                 f["description"], json.dumps(f.get("evidence", [])), now, now))
        self.conn.commit()

    def set_status(self, case_id, status):
        if status not in ("open", "investigating", "closed", "false_positive"):
            raise ValueError("invalid status")
        cur = self.conn.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?",
                                (status, time.time(), case_id))
        self.conn.commit()
        return cur.rowcount > 0

    def close(self):
        self.conn.close()
