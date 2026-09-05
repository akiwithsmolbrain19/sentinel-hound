"""Unit tests (stdlib unittest, no dependencies). Run: python3 -m unittest discover -s tests -v"""
import json
import os
import urllib.parse
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_hound.parser import parse_auth_log, parse_access_log, valid_ip
from sentinel_hound.detections import (
    run_all_detections, detect_ssh_bruteforce, detect_success_after_fails,
    detect_exploit_probes, detect_web_scanner, detect_high_404, detect_ioc,
    apply_allowlist, parse_ts, max_in_window)
from sentinel_hound.cases import CaseStore
from sentinel_hound.reporter import to_json, to_html, console_summary
from sentinel_hound import cli as cli_mod
from sentinel_hound import web as web_mod

BASE = os.path.join(os.path.dirname(__file__), "..")


def ev(ip, kind="ssh_failed", user="root", raw="x"):
    return {"source": "auth", "raw": raw, "lineno": 1, "event_type": kind,
            "src_ip": ip, "user": user, "ts": "2026-09-05T09:00:00"}


def wev(ip, path="/", status=200, raw="x"):
    return {"source": "web", "raw": raw, "lineno": 1, "event_type": "http_request",
            "src_ip": ip, "user": None, "ts": "t", "method": "GET",
            "path": path, "status": status, "ua": "test"}


class TestParsers(unittest.TestCase):
    def test_auth_parses(self):
        evs = parse_auth_log(os.path.join(BASE, "sample_data", "auth.log"))
        kinds = {e["event_type"] for e in evs}
        self.assertIn("ssh_failed", kinds)
        self.assertIn("ssh_success", kinds)

    def test_web_parses(self):
        evs = parse_access_log(os.path.join(BASE, "sample_data", "access.log"))
        self.assertTrue(any(e["event_type"] == "http_request" for e in evs))

    def test_malformed_and_empty(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("\n   \nTHIS IS NOT A LOG LINE\n")
            name = f.name
        try:
            auth = parse_auth_log(name)
            web = parse_access_log(name)
            self.assertTrue(all(e["event_type"] == "unparsed" for e in auth if e))
            self.assertTrue(all(e["event_type"] == "unparsed" for e in web if e))
        finally:
            os.unlink(name)
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            name = f.name
        try:
            self.assertEqual(parse_auth_log(name), [])
            self.assertEqual(parse_access_log(name), [])
        finally:
            os.unlink(name)

    def test_missing_file_raises_clear_error(self):
        with self.assertRaises(FileNotFoundError):
            parse_auth_log("/nonexistent/auth.log")

    def test_valid_ip(self):
        self.assertEqual(valid_ip("10.0.0.1"), "10.0.0.1")
        self.assertIsNone(valid_ip("999.999.1.1"))
        self.assertIsNone(valid_ip("not-an-ip"))
        self.assertIsNone(valid_ip(None))

    def test_timestamps_present(self):
        evs = parse_auth_log(os.path.join(BASE, "sample_data", "auth.log"))
        fails = [e for e in evs if e["event_type"] == "ssh_failed"]
        self.assertTrue(all(e["ts"] and "2026" in e["ts"] for e in fails))


class TestDetections(unittest.TestCase):
    def setUp(self):
        self.auth = parse_auth_log(os.path.join(BASE, "sample_data", "auth.log"))
        self.web = parse_access_log(os.path.join(BASE, "sample_data", "access.log"))
        with open(os.path.join(BASE, "config", "rules.json")) as f:
            self.cfg = json.load(f)
        with open(os.path.join(BASE, "config", "iocs.json")) as f:
            raw = json.load(f)
        self.iocs = {"ips": raw["malicious_ips"], "domains": [], "hashes": []}

    def test_bruteforce_fires(self):
        f = run_all_detections(self.auth, self.cfg, {"ips": []})
        self.assertTrue(any(x["rule_id"] == "SSH_BRUTEFORCE" for x in f))

    def test_success_after_fails_fires(self):
        f = run_all_detections(self.auth, self.cfg, {"ips": []})
        self.assertTrue(any(x["rule_id"] == "SSH_SUCCESS_AFTER_FAILS" for x in f))

    def test_no_false_positive_low_noise(self):
        evs = [e for e in self.auth if e.get("src_ip") == "10.0.0.8"]
        f = run_all_detections(evs, self.cfg, {"ips": []})
        self.assertFalse(any(x["rule_id"] == "SSH_BRUTEFORCE" for x in f))

    def test_web_rules_fire(self):
        f = run_all_detections(self.web, self.cfg, self.iocs)
        ids = {x["rule_id"] for x in f}
        self.assertIn("WEB_SCANNER", ids)
        self.assertIn("WEB_EXPLOIT_PROBE", ids)
        self.assertIn("IOC_MATCH", ids)

    def test_ioc_empty_no_crash(self):
        f = run_all_detections(self.web, self.cfg, {"ips": []})
        self.assertIsInstance(f, list)

    def test_threshold_boundary(self):
        base = [ev("9.9.9.9", raw=f"fail{i}") for i in range(4)]
        self.assertEqual(detect_ssh_bruteforce(base, 5), [])
        base.append(ev("9.9.9.9", raw="fail4"))
        self.assertEqual(len(detect_ssh_bruteforce(base, 5)), 1)

    def test_success_without_prior_fails_no_alert(self):
        f = detect_success_after_fails([ev("1.1.1.1", "ssh_success")], 3)
        self.assertEqual(f, [])

    def test_success_before_fails_no_alert_ordering(self):
        # success comes FIRST, fails after -> must not alert (ordering-aware)
        seq = [ev("2.2.2.2", "ssh_success")] + [ev("2.2.2.2") for _ in range(5)]
        self.assertEqual(detect_success_after_fails(seq, 3), [])

    def test_multiple_attackers(self):
        evs = [ev("3.3.3.3", raw=f"a{i}") for i in range(5)] + [ev("4.4.4.4", raw=f"b{i}") for i in range(5)]
        f = detect_ssh_bruteforce(evs, 5)
        self.assertEqual({x["src_ip"] for x in f}, {"3.3.3.3", "4.4.4.4"})

    def test_encoded_sqli_detected(self):
        e = wev("5.5.5.5", "/search?q=%27%20UNION%20SELECT%201--")
        self.assertTrue(any(x["subtype"] == "sqli" for x in detect_exploit_probes([e])))

    def test_benign_union_word_no_alert(self):
        # 'union station' without quote should not fire sqli (requires quote char)
        e = wev("5.5.5.5", "/union-station-hours")
        self.assertEqual([x for x in detect_exploit_probes([e]) if x.get("subtype") == "sqli"], [])

    def test_xss_escaped_detected(self):
        e = wev("5.5.5.5", "/q=%3Cscript%3Ealert(1)")
        self.assertTrue(any(x["subtype"] == "xss" for x in detect_exploit_probes([e])))

    def test_duplicates_count(self):
        evs = [ev("6.6.6.6", raw="same") for _ in range(5)]
        f = detect_ssh_bruteforce(evs, 5)
        self.assertEqual(f[0]["count"], 5)


def tev(ip, kind="ssh_failed", ts="2026-09-05T09:00:00", user="root", raw="x"):
    return {"source": "auth", "raw": raw, "lineno": 1, "event_type": kind,
            "src_ip": ip, "user": user, "ts": ts}


class TestWindowsAllowlist(unittest.TestCase):
    def test_allowlist_suppresses(self):
        evs = [ev("7.7.7.7", raw=f"f{i}") for i in range(6)]
        out = run_all_detections(evs, {"ssh_bruteforce_threshold": 5}, {"ips": []},
                                 {"ips": ["7.7.7.7"]})
        self.assertEqual(out, [])
        self.assertEqual(len(apply_allowlist(evs, {"ips": []})), 6)

    def test_bruteforce_window_expiry(self):
        # 5 fails spread over 2h: fires without window, silent with 600s window
        evs = [tev("8.8.8.8", ts=f"2026-09-05T0{i}:00:00", raw=f"f{i}") for i in range(5)]
        self.assertEqual(len(detect_ssh_bruteforce(evs, 5)), 1)
        self.assertEqual(detect_ssh_bruteforce(evs, 5, 600), [])

    def test_bruteforce_window_burst_fires(self):
        evs = [tev("8.8.8.9", ts=f"2026-09-05T09:00:{i:02d}", raw=f"f{i}") for i in range(5)]
        f = detect_ssh_bruteforce(evs, 5, 600)
        self.assertEqual(len(f), 1)
        self.assertIn("within 600s", f[0]["description"])

    def test_success_outside_window_no_alert(self):
        evs = [tev("9.9.9.9", ts="2026-09-05T06:00:00", raw=f"f{i}") for i in range(4)]
        evs.append(tev("9.9.9.9", "ssh_success", ts="2026-09-05T09:00:00", raw="ok"))
        self.assertEqual(detect_success_after_fails(evs, 3, 3600), [])
        self.assertEqual(len(detect_success_after_fails(evs, 3)), 1)  # no-window fallback still fires

    def test_missing_ts_falls_back_to_count(self):
        evs = [dict(tev("1.2.3.9", raw=f"f{i}"), ts=None) for i in range(5)]
        self.assertEqual(len(detect_ssh_bruteforce(evs, 5, 600)), 1)

    def test_parse_ts_bad_input(self):
        self.assertIsNone(parse_ts({"ts": "not-a-date"}))
        self.assertIsNone(parse_ts({}))

    def test_max_in_window(self):
        from datetime import datetime
        base = datetime(2026, 9, 5, 9, 0, 0)
        from datetime import timedelta
        times = [base + timedelta(seconds=s) for s in (0, 60, 120, 3600, 3700)]
        self.assertEqual(max_in_window(times, 600), 3)


class TestCases(unittest.TestCase):
    def test_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "t.db")
            s = CaseStore(db)
            s.add_findings([{"rule_id": "SSH_BRUTEFORCE", "src_ip": "1.2.3.4",
                             "severity": "high", "title": "t", "description": "d", "evidence": []}])
            rows = s.list_cases()
            self.assertEqual(len(rows), 1)
            s.set_status(rows[0][0], "investigating")
            self.assertEqual(s.list_cases("investigating")[0][0], rows[0][0])
            s.close()

    def test_dedupe_and_rowcount(self):
        with tempfile.TemporaryDirectory() as d:
            s = CaseStore(os.path.join(d, "t.db"))
            f = {"rule_id": "X", "src_ip": "1.1.1.1", "severity": "low",
                 "title": "t", "description": "d", "evidence": []}
            s.add_findings([f, dict(f)])
            self.assertEqual(len(s.list_cases()), 1)
            self.assertFalse(s.set_status(9999, "closed"))
            with self.assertRaises(ValueError):
                s.set_status(1, "bogus")
            s.close()


class TestReporter(unittest.TestCase):
    def test_json_valid_and_html_escapes(self):
        findings = [{"rule_id": "WEB_EXPLOIT_PROBE", "src_ip": "1.2.3.4", "severity": "high",
                     "title": "t<script>", "description": "<img src=x onerror=alert(1)>",
                     "evidence": ["<script>evil</script>"], "mitre": ["T1190"],
                     "tactic": "Initial Access", "count": 1, "users": []}]
        with tempfile.TemporaryDirectory() as d:
            jp, hp = os.path.join(d, "r.json"), os.path.join(d, "r.html")
            to_json(findings, jp)

            with open(jp) as f:
                data = json.load(f)

            self.assertEqual(data["finding_count"], 1)

            to_html(findings, hp)

            with open(hp) as f:
                page = f.read()
            self.assertNotIn("<script>evil</script>", page)
            self.assertIn("&lt;script&gt;", page)
            self.assertIn("T1190", page)
        self.assertIn("1 finding", console_summary(findings))


class TestCLI(unittest.TestCase):
    def test_missing_files_exit2(self):
        rc = cli_mod.main(["analyze", "--auth-log", "/nonexistent.log"])
        self.assertEqual(rc, 2)

    def test_no_inputs_exit2(self):
        rc = cli_mod.main(["analyze"])
        self.assertEqual(rc, 2)

    def test_bad_config_exit2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{invalid")
            name = f.name
        try:
            with self.assertRaises(SystemExit) as cm:
                cli_mod.load_config(name)
            self.assertEqual(cm.exception.code, 2)
        finally:
            os.unlink(name)


if __name__ == "__main__":
    unittest.main()


class TestWebUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        from http.server import HTTPServer
        cls._tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls._tmp.name, "web.db")
        s = CaseStore(cls.db)
        s.add_findings([{"rule_id": "SSH_BRUTEFORCE", "src_ip": "1.2.3.4",
                         "severity": "high", "title": "t<script>",
                         "description": "<img src=x onerror=alert(1)>",
                         "evidence": []}])
        s.close()
        web_mod._DB = cls.db
        cls.httpd = HTTPServer(("127.0.0.1", 0), web_mod.Handler)
        cls.port = cls.httpd.server_address[1]
        import threading
        cls._th = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls._th.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._tmp.cleanup()

    def _get(self, path):
        import urllib.request
        with urllib.request.urlopen(self.base + path) as r:
            return r.status, r.read().decode()

    def test_index_lists_and_escapes(self):
        code, page = self._get("/")
        self.assertEqual(code, 200)
        self.assertIn("SSH_BRUTEFORCE", page)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_filter_and_bad_filter(self):
        code, _ = self._get("/?status=open")
        self.assertEqual(code, 200)
        import urllib.request, urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/?status=bogus")
        self.assertEqual(cm.exception.code, 400)

    def test_post_status_roundtrip(self):
        import urllib.request
        data = urllib.parse.urlencode({"id": "1", "status": "investigating"}).encode()
        req = urllib.request.Request(self.base + "/status", data=data)
        with urllib.request.urlopen(req) as r:
            pass  # follows 303 to /
        s = CaseStore(self.db)
        try:
            self.assertEqual(s.list_cases("investigating")[0][0], 1)
        finally:
            s.close()

    def test_post_bad_status_400(self):
        import urllib.request, urllib.error
        data = urllib.parse.urlencode({"id": "1", "status": "bogus"}).encode()
        req = urllib.request.Request(self.base + "/status", data=data)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)

    def test_binds_localhost_only(self):
        import inspect
        src = inspect.getsource(web_mod.serve)
        self.assertIn("127.0.0.1", src)
