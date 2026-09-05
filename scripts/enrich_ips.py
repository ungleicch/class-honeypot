#!/usr/bin/env python3
"""Optional soft IP enrichment via ip-api.com free tier.

- Stdlib only (urllib)
- Fail soft: network/HTTP/parse errors become notes, never crash the report
- Rate-limit: default ~1.2s between requests (free tier ~45 req/min)

Usage:
  python3 scripts/enrich_ips.py --log cowrie/var/log/cowrie/cowrie.json
  python3 scripts/analyze_logs.py | tee /tmp/report.md
  python3 scripts/enrich_ips.py --ips 1.2.3.4 5.6.7.8
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_LOG = Path(__file__).resolve().parents[1] / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
API = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query,proxy,hosting"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Soft-enrich source IPs from Cowrie logs")
    p.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Cowrie JSON log path")
    p.add_argument("--ips", nargs="*", default=[], help="Explicit IPs (skip log parse if set)")
    p.add_argument("--delay", type=float, default=1.2, help="Seconds between API calls")
    p.add_argument("--limit", type=int, default=40, help="Max IPs to enrich (free-tier friendly)")
    p.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout seconds")
    return p.parse_args()


def ips_from_log(path: Path) -> list[str]:
    found: dict[str, int] = {}
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = ev.get("src_ip") or ev.get("srcIP")
            if ip and isinstance(ip, str) and ip not in ("127.0.0.1", "::1"):
                found[ip] = found.get(ip, 0) + 1
    return [ip for ip, _ in sorted(found.items(), key=lambda kv: (-kv[1], kv[0]))]


def lookup(ip: str, timeout: float) -> dict[str, Any]:
    url = API.format(ip=ip)
    req = urllib.request.Request(url, headers={"User-Agent": "class-honeypot-enrich/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("status") != "success":
                return {"ip": ip, "ok": False, "error": data.get("message", "lookup failed")}
            return {
                "ip": ip,
                "ok": True,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "proxy": data.get("proxy"),
                "hosting": data.get("hosting"),
            }
    except Exception as exc:  # noqa: BLE001 — intentional fail-soft
        return {"ip": ip, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    args = parse_args()
    try:
        ips = args.ips or ips_from_log(args.log)
    except FileNotFoundError as exc:
        print(f"Error: log not found ({exc}). Pass --ips or a valid --log.", file=sys.stderr)
        return 1

    ips = ips[: max(0, args.limit)]
    print("# IP enrichment (ip-api.com free tier)")
    print("")
    print("_Fail-soft / rate-limited. For class context only — not attribution._")
    print("")
    print("| IP | Country | City | ISP / Org | AS | Notes |")
    print("| --- | --- | --- | --- | --- | --- |")

    for i, ip in enumerate(ips):
        if i:
            time.sleep(max(0.0, args.delay))
        row = lookup(ip, args.timeout)
        if not row.get("ok"):
            print(f"| `{ip}` |  |  |  |  | {row.get('error', 'failed')} |")
            continue
        isp = " / ".join(x for x in [row.get("isp"), row.get("org")] if x)
        notes = []
        if row.get("proxy"):
            notes.append("proxy")
        if row.get("hosting"):
            notes.append("hosting")
        print(
            f"| `{row['ip']}` | {row.get('country') or ''} | {row.get('city') or ''} | "
            f"{isp} | {row.get('as') or ''} | {', '.join(notes)} |"
        )

    print("")
    print(f"_Enriched {len(ips)} IP(s). See docs/ETHICS.md before sharing raw data._")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
