#!/usr/bin/env python3
"""
scripts/generate_logs.py
────────────────────────
Generates realistic mixed log traffic and POSTs it to the SIEM ingest API.

Traffic mix (configurable at top of file):
  70%  Normal GET/POST traffic (HTTP 200/304)
  15%  Failed login attempts (HTTP 401/403)
  10%  Server errors (HTTP 500)
   5%  Simulated attack patterns (rapid 404s, SQL injection strings)

Usage:
  # Basic — 500 events/min to localhost
  python generate_logs.py

  # Custom rate and target
  python generate_logs.py --rate 200 --api http://localhost:8000

  # Run for a fixed number of events then stop
  python generate_logs.py --count 5000

  # Use CLF file upload instead of JSON
  python generate_logs.py --mode file
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone, timedelta
from io import StringIO

try:
    import httpx
except ImportError:
    print("Missing dependency: pip install httpx")
    sys.exit(1)

API_KEY = __import__("os").getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")


# ── Fake data pools ───────────────────────────────────────────────────────────

NORMAL_IPS = [
    "203.0.113.10", "198.51.100.20", "192.0.2.50", "10.0.0.15",
    "172.16.0.30", "185.220.101.1", "45.33.32.156", "104.21.0.1",
    "8.8.8.8", "1.1.1.1", "151.101.1.140", "93.184.216.34",
]

ATTACK_IPS = [
    "192.168.100.99", "10.0.0.254", "172.31.255.1",
    "45.155.205.233", "91.108.4.1", "194.165.16.11",
]

SYSLOG_HOSTS = [
    "web01", "web02", "db-primary", "auth-server",
    "loadbalancer", "mail-relay", "vpn-gateway",
]

PATHS = [
    "/", "/index.html", "/login", "/api/v1/users", "/api/v1/orders",
    "/dashboard", "/admin", "/static/app.js", "/static/style.css",
    "/favicon.ico", "/health", "/metrics", "/api/v1/auth/token",
    "/wp-admin", "/phpmyadmin", "/.env", "/config.json",
]

ATTACK_PATHS = [
    "/login?user=admin'--",
    "/search?q=<script>alert(1)</script>",
    "/api/users?id=1 UNION SELECT * FROM users--",
    "/../../../../etc/passwd",
    "/login?user=admin&pass=' OR '1'='1",
    "/shell.php?cmd=whoami",
    "/.git/config",
    "/api/v1/users?id=1;DROP TABLE logs--",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "curl/8.7.1",
    "python-httpx/0.27.0",
    "Go-http-client/2.0",
    "Nmap Scripting Engine",   # suspicious UA
    "sqlmap/1.8.0#stable",     # known attack tool
]

USERNAMES = [
    "admin", "root", "karan", "alice", "bob", "service_account",
    "deploy", "jenkins", "postgres", "ubuntu", "ec2-user",
]

SYSLOG_MESSAGES = [
    "Failed password for {user} from {ip} port {port} ssh2",
    "Accepted publickey for {user} from {ip} port {port} ssh2",
    "pam_unix(sshd:auth): authentication failure; user={user}",
    "sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    "kernel: iptables DENY IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
    "systemd[1]: Started nginx.service.",
    "cron[1234]: ({user}) CMD (/usr/bin/backup.sh)",
    "postfix/smtp[5678]: connect to mail.example.com[{ip}]:25",
]


# ── Event builders ────────────────────────────────────────────────────────────

def rand_ts(offset_seconds=0):
    """ISO timestamp, optionally offset into the past."""
    ts = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return ts.isoformat()


def normal_event():
    """70% — standard web traffic."""
    ip = random.choice(NORMAL_IPS)
    path = random.choice(PATHS)
    method = random.choices(["GET", "POST", "PUT", "DELETE"], weights=[70, 20, 7, 3])[0]
    status = random.choices([200, 201, 204, 301, 304, 404], weights=[55, 10, 5, 10, 15, 5])[0]
    return {
        "timestamp": rand_ts(random.randint(0, 3600)),
        "source_type": "apache",
        "source_host": "web01",
        "level": "INFO" if status < 400 else "WARN",
        "source_ip": ip,
        "user": random.choice([None, random.choice(USERNAMES)]),
        "action": f"{method} {path}",
        "status_code": status,
        "message": f'{ip} - "{method} {path} HTTP/1.1" {status}',
    }


def failed_login_event():
    """15% — brute force / credential stuffing pattern."""
    ip = random.choice(ATTACK_IPS)
    user = random.choice(USERNAMES)
    status = random.choice([401, 403])
    return {
        "timestamp": rand_ts(random.randint(0, 300)),  # recent — within last 5 min
        "source_type": "apache",
        "source_host": "web01",
        "level": "WARN",
        "source_ip": ip,
        "user": user,
        "action": f"POST /login",
        "status_code": status,
        "message": f'Failed login attempt for user "{user}" from {ip}',
    }


def server_error_event():
    """10% — HTTP 500 / application errors."""
    ip = random.choice(NORMAL_IPS)
    path = random.choice(["/api/v1/orders", "/api/v1/users", "/dashboard", "/report"])
    return {
        "timestamp": rand_ts(random.randint(0, 1800)),
        "source_type": random.choice(["apache", "json"]),
        "source_host": random.choice(["web01", "web02", "api-server"]),
        "level": "ERROR",
        "source_ip": ip,
        "action": f"GET {path}",
        "status_code": 500,
        "message": random.choice([
            f"Internal Server Error at {path}: NullPointerException in OrderController",
            f"Database connection timeout after 30s",
            f"Unhandled exception: ValueError: invalid literal for int()",
            f"Out of memory: Kill process or sacrifice child",
        ]),
    }


def attack_event():
    """5% — SQL injection / path traversal / scanning."""
    ip = random.choice(ATTACK_IPS)
    path = random.choice(ATTACK_PATHS)
    return {
        "timestamp": rand_ts(random.randint(0, 600)),
        "source_type": "apache",
        "source_host": "web01",
        "level": "WARN",
        "source_ip": ip,
        "user": None,
        "action": f"GET {path}",
        "status_code": random.choice([400, 404, 403, 200]),
        "message": f'Suspicious request from {ip}: "GET {path} HTTP/1.1"',
    }


def syslog_event():
    """Mixed syslog events (SSH auth, sudo, kernel, cron)."""
    host = random.choice(SYSLOG_HOSTS)
    ip = random.choice(NORMAL_IPS + ATTACK_IPS)
    user = random.choice(USERNAMES)
    port = random.randint(32768, 60999)
    msg = random.choice(SYSLOG_MESSAGES).format(ip=ip, user=user, port=port)
    level = "WARN" if "Failed" in msg or "DENY" in msg or "failure" in msg else "INFO"
    return {
        "timestamp": rand_ts(random.randint(0, 3600)),
        "source_type": "syslog",
        "source_host": host,
        "level": level,
        "source_ip": ip if "ssh" in msg.lower() else None,
        "user": user,
        "action": None,
        "status_code": None,
        "message": msg,
    }


# ── Event picker ──────────────────────────────────────────────────────────────

EVENT_BUILDERS = [
    (normal_event,       70),
    (failed_login_event, 15),
    (server_error_event, 10),
    (attack_event,        5),
]

WEIGHTS = [w for _, w in EVENT_BUILDERS]
BUILDERS = [b for b, _ in EVENT_BUILDERS]


def next_event():
    """Pick a random event type according to traffic mix weights."""
    builder = random.choices(BUILDERS, weights=WEIGHTS)[0]
    event = builder()

    # 20% chance: also generate a paired syslog event for the same IP
    if random.random() < 0.20:
        return [event, syslog_event()]
    return [event]


# ── Sender ────────────────────────────────────────────────────────────────────

def send_json_batch(client, api_base: str, events: list) -> bool:
    """POST a batch of events to /ingest/json. Returns True on success."""
    try:
        r = client.post(f"{api_base}/ingest/json", json=events, timeout=5.0)
        return r.status_code == 200
    except Exception as e:
        print(f"  [!] JSON send error: {e}", file=sys.stderr)
        return False


def build_clf_line(event: dict) -> str | None:
    """Convert a JSON event into an Apache CLF line (best-effort)."""
    if event.get("source_type") not in ("apache", "nginx"):
        return None
    ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    clf_ts = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = event.get("source_ip") or "0.0.0.0"
    user = event.get("user") or "-"
    action = event.get("action") or "GET / HTTP/1.1"
    # action is "METHOD /path" — add protocol
    if len(action.split()) == 2:
        action = f"{action} HTTP/1.1"
    status = event.get("status_code") or 200
    size = random.randint(200, 8192)
    ua = random.choice(USER_AGENTS)
    return f'{ip} - {user} [{clf_ts}] "{action}" {status} {size} "-" "{ua}"'


def send_clf_batch(client, api_base: str, events: list) -> bool:
    """Upload events as an Apache CLF file to /ingest/file."""
    lines = [build_clf_line(e) for e in events]
    lines = [l for l in lines if l]
    if not lines:
        return True
    content = "\n".join(lines) + "\n"
    files = {"file": ("access.log", content.encode(), "text/plain")}
    try:
        r = client.post(f"{api_base}/ingest/file", files=files, timeout=10.0)
        return r.status_code == 200
    except Exception as e:
        print(f"  [!] CLF send error: {e}", file=sys.stderr)
        return False


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Mini SIEM log generator")
    parser.add_argument("--api",   default="http://localhost:8000",
                        help="API base URL (default: http://localhost:8000)")
    parser.add_argument("--rate",  type=int, default=500,
                        help="Target events per minute (default: 500)")
    parser.add_argument("--count", type=int, default=0,
                        help="Stop after N events (0 = run forever)")
    parser.add_argument("--mode",  choices=["json", "file", "mixed"], default="mixed",
                        help="Ingestion mode: json | file | mixed (default: mixed)")
    parser.add_argument("--batch", type=int, default=20,
                        help="Events per API call (default: 20)")
    args = parser.parse_args()

    interval = 60 / args.rate                   # seconds between events
    batch_interval = interval * args.batch       # seconds between batch sends

    print(f"""
╔══════════════════════════════════════════════════╗
║        Mini SIEM — Log Generator                ║
╠══════════════════════════════════════════════════╣
║  API      : {args.api:<36} ║
║  Rate     : {args.rate} events/min{'':<24} ║
║  Batch    : {args.batch} events/call{'':<23} ║
║  Mode     : {args.mode:<36} ║
║  Max      : {'∞' if args.count == 0 else str(args.count):<36} ║
╚══════════════════════════════════════════════════╝
Press Ctrl+C to stop.
""")

    total_sent = 0
    total_failed = 0

    with httpx.Client(headers={"X-API-Key": API_KEY}) as client:
        # Check API is reachable
        try:
            r = client.get(f"{args.api}/health", timeout=5.0)
            print(f"✅ API reachable — {r.json()}")
        except Exception as e:
            print(f"⚠️  Warning: API not reachable ({e}). Will retry each batch.\n")

        try:
            while True:
                batch_start = time.time()
                batch: list[dict] = []

                for _ in range(args.batch):
                    batch.extend(next_event())

                # Choose send mode
                mode = args.mode
                if mode == "mixed":
                    mode = random.choice(["json", "file"])

                if mode == "json":
                    ok = send_json_batch(client, args.api, batch)
                else:
                    ok = send_clf_batch(client, args.api, batch)

                if ok:
                    total_sent += len(batch)
                else:
                    total_failed += len(batch)

                # Progress line
                ts = datetime.now().strftime("%H:%M:%S")
                bar = "█" * min(20, total_sent // 100)
                print(f"\r[{ts}] Sent: {total_sent:>6} | Failed: {total_failed:>4} | {bar}", end="", flush=True)

                if args.count and total_sent >= args.count:
                    print(f"\n\n✅ Reached {args.count} events. Done.")
                    break

                # Sleep to hit the target rate
                elapsed = time.time() - batch_start
                sleep_time = max(0, batch_interval - elapsed)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            print(f"\n\n⏹  Stopped. Total sent: {total_sent} | Failed: {total_failed}")


if __name__ == "__main__":
    main()
