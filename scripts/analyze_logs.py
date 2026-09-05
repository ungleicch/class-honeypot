#!/usr/bin/env python3
"""Parse Cowrie JSON logs into a markdown-friendly class report.

Stdlib only. Default log path matches this repo's compose mount:
  cowrie/var/log/cowrie/cowrie.json

Usage:
  python3 scripts/analyze_logs.py
  python3 scripts/analyze_logs.py --log path/to/cowrie.json --top 20
  python3 scripts/analyze_logs.py --log sample-output/cowrie.json.sample
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


DEFAULT_LOG = Path(__file__).resolve().parents[1] / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Summarize Cowrie JSON logs for class reports")
    p.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help=f"Path to cowrie.json (default: {DEFAULT_LOG})",
    )
    p.add_argument("--top", type=int, default=15, help="How many top items to show (default: 15)")
    return p.parse_args()


def iter_events(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Log not found: {path}")
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"<!-- skip line {lineno}: {exc} -->", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                yield obj


def top_n(counter: Counter, n: int) -> list[tuple[Any, int]]:
    return counter.most_common(n)


def fmt_ts(value: Any) -> str:
    if value is None:
        return "?"
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (OverflowError, OSError, ValueError):
            return str(value)
    return str(value)


def duration_seconds(start: Any, end: Any) -> float | None:
    def to_dt(v: Any) -> datetime | None:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            try:
                return datetime.fromtimestamp(v, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        s = str(v).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None

    a, b = to_dt(start), to_dt(end)
    if a and b:
        return max(0.0, (b - a).total_seconds())
    return None


def analyze(events: Iterable[dict[str, Any]], top: int) -> str:
    ips: Counter = Counter()
    src_ports: Counter = Counter()
    users: Counter = Counter()
    passwords: Counter = Counter()
    creds: Counter = Counter()
    commands: Counter = Counter()
    clients: Counter = Counter()
    event_ids: Counter = Counter()
    sessions: dict[str, dict[str, Any]] = {}
    timeline: list[tuple[str, str, str]] = []
    downloads: list[dict[str, Any]] = []
    login_ok = 0
    login_fail = 0

    for ev in events:
        eid = ev.get("eventid") or ev.get("event_id") or "?"
        event_ids[eid] += 1
        ts = fmt_ts(ev.get("timestamp") or ev.get("time"))
        ip = ev.get("src_ip") or ev.get("srcIP") or "?"
        sport = ev.get("src_port") or ev.get("srcPort")
        session = str(ev.get("session") or "")

        if ip and ip != "?":
            ips[ip] += 1
        if sport is not None:
            src_ports[str(sport)] += 1

        if session:
            s = sessions.setdefault(session, {"ip": ip, "start": None, "end": None, "ok": False})
            if ip and ip != "?":
                s["ip"] = ip
            if s["start"] is None:
                s["start"] = ev.get("timestamp") or ev.get("time")
            s["end"] = ev.get("timestamp") or ev.get("time")

        if eid == "cowrie.session.connect":
            timeline.append((ts, ip, f"connect sport={sport} dst_port={ev.get('dst_port')}"))
            ver = ev.get("version") or ev.get("clientversion")
            if ver:
                clients[str(ver)] += 1
        elif eid in ("cowrie.client.version", "cowrie.client.kex"):
            ver = ev.get("version") or ev.get("clientVersion") or ev.get("hasshClient")
            if ver:
                clients[str(ver)] += 1
            banner = ev.get("message")
            if banner and "SSH-" in str(banner):
                clients[str(banner)] += 1
        elif eid == "cowrie.login.success":
            login_ok += 1
            u, pw = ev.get("username", "?"), ev.get("password", "?")
            users[str(u)] += 1
            passwords[str(pw)] += 1
            creds[f"{u}:{pw}"] += 1
            if session:
                sessions[session]["ok"] = True
            timeline.append((ts, ip, f"LOGIN OK user={u}"))
        elif eid == "cowrie.login.failed":
            login_fail += 1
            u, pw = ev.get("username", "?"), ev.get("password", "?")
            users[str(u)] += 1
            passwords[str(pw)] += 1
            creds[f"{u}:{pw}"] += 1
            timeline.append((ts, ip, f"login fail user={u}"))
        elif eid in ("cowrie.command.input", "cowrie.command.success", "cowrie.command.failed"):
            cmd = ev.get("input") or ev.get("command") or ""
            if cmd:
                commands[str(cmd)] += 1
                timeline.append((ts, ip, f"cmd: {cmd}"))
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_download.failure"):
            downloads.append(
                {
                    "ts": ts,
                    "ip": ip,
                    "url": ev.get("url"),
                    "outfile": ev.get("outfile") or ev.get("destfile"),
                    "shasum": ev.get("shasum"),
                }
            )
            timeline.append((ts, ip, f"download: {ev.get('url') or ev.get('outfile')}"))
        elif eid == "cowrie.session.closed":
            timeline.append((ts, ip, "session closed"))

    durations = []
    for s in sessions.values():
        d = duration_seconds(s.get("start"), s.get("end"))
        if d is not None:
            durations.append(d)

    lines: list[str] = []
    lines.append("# Cowrie Honeypot Analysis Report")
    lines.append("")
    lines.append(f"_Generated by `scripts/analyze_logs.py` — {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}_")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| Unique source IPs | {len(ips)} |")
    lines.append(f"| Sessions seen | {len(sessions)} |")
    lines.append(f"| Login success | {login_ok} |")
    lines.append(f"| Login failed | {login_fail} |")
    lines.append(f"| Commands logged | {sum(commands.values())} |")
    lines.append(f"| Downloads logged | {len(downloads)} |")
    if durations:
        lines.append(f"| Median session duration (s) | {sorted(durations)[len(durations)//2]:.1f} |")
        lines.append(f"| Max session duration (s) | {max(durations):.1f} |")
    lines.append("")

    def section(title: str, rows: list[tuple[Any, int]], headers: tuple[str, str]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if not rows:
            lines.append("_None_")
            lines.append("")
            return
        lines.append(f"| {headers[0]} | {headers[1]} |")
        lines.append("| --- | ---: |")
        for k, c in rows:
            lines.append(f"| `{k}` | {c} |")
        lines.append("")

    section("Top source IPs", top_n(ips, top), ("IP", "Events"))
    section("Top credentials (user:pass)", top_n(creds, top), ("Credential", "Attempts"))
    section("Top usernames", top_n(users, top), ("Username", "Count"))
    section("Top passwords", top_n(passwords, top), ("Password", "Count"))
    section("Top commands", top_n(commands, top), ("Command", "Count"))
    section("SSH client versions / banners", top_n(clients, top), ("Client", "Count"))
    section("Event ID histogram", top_n(event_ids, top), ("Event ID", "Count"))

    lines.append("## Downloads (quarantine — do not execute)")
    lines.append("")
    if not downloads:
        lines.append("_None_")
    else:
        lines.append("| Time | IP | URL / file | SHA256 |")
        lines.append("| --- | --- | --- | --- |")
        for d in downloads[: top * 2]:
            lines.append(
                f"| {d['ts']} | `{d['ip']}` | `{d.get('url') or d.get('outfile') or '?'}` | `{d.get('shasum') or ''}` |"
            )
    lines.append("")

    lines.append("## Timeline (recent)")
    lines.append("")
    recent = timeline[-min(len(timeline), top * 3) :]
    if not recent:
        lines.append("_No events_")
    else:
        lines.append("| Time | IP | Event |")
        lines.append("| --- | --- | --- |")
        for ts, ip, msg in recent:
            safe = str(msg).replace("|", "\\|")
            lines.append(f"| {ts} | `{ip}` | {safe} |")
    lines.append("")
    lines.append("---")
    lines.append("_Defensive coursework only. See docs/ETHICS.md._")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    try:
        events = list(iter_events(args.log))
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(
            "Hint: start the stack, wait for probes, or pass --log sample-output/cowrie.json.sample",
            file=sys.stderr,
        )
        return 1
    report = analyze(events, args.top)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
