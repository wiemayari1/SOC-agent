import tempfile
import unittest
from soc.config import Workspace, load_patterns
from soc.parsers import parse_auth_line, parse_fw_line, parse_nginx_line, parse_file_line, parse_wazuh_line, load_all
from soc.extractor import build_alerts, max_in_window, max_distinct_in_window, is_internal, classify_request, compile_sqli
from soc import simulator
from datetime import datetime, timedelta


class TestParsers(unittest.TestCase):
    def test_ssh_failed_iso_and_classic(self):
        e = parse_auth_line("2026-11-07T10:15:32 srv sshd[12]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2")
        self.assertEqual((e.type, e.user, e.src_ip, e.details["invalid_user"]), ("ssh_failed", "admin", "1.2.3.4", True))
        e2 = parse_auth_line("Nov  7 10:15:32 srv sshd[12]: Accepted password for bob from 10.0.0.9 port 22 ssh2", year=2026)
        self.assertEqual((e2.type, e2.ts.month, e2.ts.year), ("ssh_success", 11, 2026))

    def test_ubuntu_2404_timestamp_with_timezone(self):
        """Format réel d'Ubuntu 24.04 : microsecondes + fuseau horaire."""
        e = parse_auth_line("2026-11-07T10:15:32.123456+00:00 srv sshd[12]: Failed password for root from 1.2.3.4 port 22 ssh2")
        self.assertEqual((e.src_ip, e.ts.second), ("1.2.3.4", 32))

    def test_firewall_nginx_file(self):
        e = parse_fw_line("2026-11-07T10:00:00 srv kernel: [UFW BLOCK] IN=eth0 SRC=9.9.9.9 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=3389 SYN")
        self.assertEqual((e.type, e.details["dport"]), ("fw_block", 3389))
        n = parse_nginx_line('1.1.1.1 - - [07/Nov/2026:10:00:00 +0000] "GET /a?id=1 HTTP/1.1" 500 12 "-" "sqlmap"')
        self.assertEqual((n.details["status"], n.details["url"]), (500, "/a?id=1"))
        f = parse_file_line('{"ts":"2026-11-07T10:00:00","event":"created","path":"/tmp/a.exe","sha256":"ab"}')
        self.assertEqual(f.type, "file_created")

    def test_garbage_is_skipped_not_fatal(self):
        ws = Workspace(tempfile.mkdtemp())
        ws.ensure()
        (ws.logs / "auth.log").write_text("n'importe quoi\n2026-11-07T10:15:32 srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
        events, stats = load_all(ws)
        self.assertEqual(len(events), 1)
        self.assertEqual(stats["auth.log"]["skipped"], 1)

    def test_wazuh_full_log(self):
        line = '{"rule":{"id":"5710"},"full_log":"Nov  7 10:15:32 srv sshd[12]: Failed password for root from 5.5.5.5 port 22 ssh2"}'
        self.assertEqual(parse_wazuh_line(line, 2026).src_ip, "5.5.5.5")


class TestExtractor(unittest.TestCase):
    def test_windows(self):
        t0 = datetime(2026, 1, 1)
        self.assertEqual(max_in_window([t0 + timedelta(seconds=s) for s in (0, 10, 20, 500)], 60), 3)
        self.assertEqual(max_distinct_in_window([(t0 + timedelta(seconds=s), p) for s, p in ((0, 1), (1, 2), (2, 2), (300, 3))], 60), 2)

    def test_internal(self):
        self.assertTrue(is_internal("10.1.2.3"))
        self.assertFalse(is_internal("203.0.113.5"))   # plage de documentation : traitée comme externe

    def test_sqli_classification(self):
        c = compile_sqli(load_patterns())
        self.assertEqual(classify_request("/p?id=1%20UNION%20SELECT%20NULL--", c)[0], "strong")
        self.assertEqual(classify_request("/search?q=O%27Brien", c)[0], "weak")
        self.assertIsNone(classify_request("/products?id=3", c)[0])

    def test_simulated_alerts(self):
        ws = Workspace(tempfile.mkdtemp())
        simulator.generate(ws)
        events, _ = load_all(ws)
        alerts = build_alerts(events, load_patterns())
        self.assertEqual(len(alerts), 12)
        self.assertEqual({a.scenario for a in alerts}, {"ssh_bruteforce", "port_scan", "web_sqli", "malicious_file"})


if __name__ == "__main__":
    unittest.main()
