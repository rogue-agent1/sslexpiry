#!/usr/bin/env python3
"""sslexpiry - Check SSL certificate expiry for domains.

One file. Zero deps. Never get surprised by expiring certs.

Usage:
  sslexpiry.py example.com              → check single domain
  sslexpiry.py example.com google.com   → check multiple
  sslexpiry.py domains.txt              → check from file
  sslexpiry.py example.com --warn 30    → warn if <30 days left
  sslexpiry.py example.com --json       → JSON output
"""

import argparse
import json
import os
import socket
import ssl
import sys
from datetime import datetime


def check_cert(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.now(tz=None)).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                sans = []
                for typ, val in cert.get("subjectAltName", []):
                    if typ == "DNS":
                        sans.append(val)
                return {
                    "hostname": hostname,
                    "cn": subject.get("commonName", ""),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_left": days_left,
                    "sans": sans[:10],
                    "serial": cert.get("serialNumber", ""),
                    "version": cert.get("version", ""),
                }
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


def main():
    p = argparse.ArgumentParser(description="Check SSL certificate expiry")
    p.add_argument("domains", nargs="+")
    p.add_argument("--warn", type=int, default=30, help="Warning threshold in days")
    p.add_argument("--json", action="store_true")
    p.add_argument("--port", type=int, default=443)
    args = p.parse_args()

    domains = []
    for d in args.domains:
        if os.path.isfile(d):
            with open(d) as f:
                domains.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
        else:
            domains.append(d)

    results = [check_cert(d, args.port) for d in domains]

    if args.json:
        print(json.dumps(results, indent=2))
        return

    has_warning = False
    for r in results:
        if "error" in r:
            print(f"  ❌ {r['hostname']}: {r['error']}")
            has_warning = True
            continue
        if r["days_left"] < 0:
            icon = "🔴"
            status = f"EXPIRED {-r['days_left']}d ago"
            has_warning = True
        elif r["days_left"] < args.warn:
            icon = "🟡"
            status = f"{r['days_left']}d left ⚠️"
            has_warning = True
        else:
            icon = "🟢"
            status = f"{r['days_left']}d left"
        print(f"  {icon} {r['hostname']:30s} {status:20s} issuer: {r['issuer']}")

    return 1 if has_warning else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
