#!/usr/bin/env python3
"""Unified Cowrie + Conpot log summary for class reports (stdlib only).

Defaults match this repo's compose mounts:
  cowrie/var/log/cowrie/cowrie.json
  conpot/var/log/conpot.json

Usage:
  python3 scripts/analyze_all.py
  python3 scripts/analyze_all.py \\
    --cowrie sample-output/cowrie.json.sample \\
    --conpot sample-output/conpot.json.sample
  python3 scripts/analyze_all.py --top 20 > report.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COWRIE = ROOT / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
DEFAULT_CONPOT = ROOT / "conpot" / "var" / "log" / "conpot.json"

# Common Modbus function codes (defensive reference only)
MODBUS_FC = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Slave ID",
    43: "Read Device Identification",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Summarize Cowrie + Conpot JSON logs")
    p.add_argument("--cowrie", type=Path, default=DEFAULT_COWRIE, help="Cowrie JSON log")
    p.add_argument("--conpot", type=Path, default=DEFAULT_CONPOT, help="Conpot JSON log")
    p.add_argument("--top", type=int, default=15, help="Top-N rows (default 15)")
    p.add_argument(
        "--skip-missing",
        action="store_true",
        help="If a log is missing, emit a stub section instead of exiting",
    )
    return p.parse_args()


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"<!-- skip {path.name}:{lineno}: {exc} -->", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                yield obj


def top_n(counter: Counter, n: int) -> list[tuple[Any, int]]:
    return counter.most_common(n)


def section(lines: list[str], title: str, rows: list[tuple[Any, int]], headers: tuple[str, str]) -> None:
    lines.append(f"### {title}")
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


def analyze_cowrie(events: Iterable[dict[str, Any]], top: int) -> str:
    ips: Counter = Counter()
    creds: Counter = Counter()
    commands: Counter = Counter()
    clients: Counter = Counter()
    event_ids: Counter = Counter()
    downloads = 0
    login_ok = 0
    login_fail = 0
    sessions: set[str] = set()

    for ev in events:
        eid = ev.get("eventid") or ev.get("event_id") or "?"
        event_ids[eid] += 1
        ip = ev.get("src_ip") or ev.get("srcIP") or "?"
        if ip and ip != "?":
            ips[ip] += 1
        sid = ev.get("session")
        if sid:
            sessions.add(str(sid))

        if eid == "cowrie.login.success":
            login_ok += 1
            creds[f"{ev.get('username', '?')}:{ev.get('password', '?')}"] += 1
        elif eid == "cowrie.login.failed":
            login_fail += 1
            creds[f"{ev.get('username', '?')}:{ev.get('password', '?')}"] += 1
        elif eid in ("cowrie.command.input", "cowrie.command.success", "cowrie.command.failed"):
            cmd = ev.get("input") or ev.get("command")
            if cmd:
                commands[str(cmd)] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_download.failure"):
            downloads += 1
        elif eid in ("cowrie.client.version", "cowrie.session.connect"):
            ver = ev.get("version") or ev.get("clientversion") or ev.get("clientVersion")
            if ver:
                clients[str(ver)] += 1

    lines: list[str] = []
    lines.append("## Cowrie (SSH / Telnet)")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Unique source IPs | {len(ips)} |")
    lines.append(f"| Sessions | {len(sessions)} |")
    lines.append(f"| Login success | {login_ok} |")
    lines.append(f"| Login failed | {login_fail} |")
    lines.append(f"| Commands logged | {sum(commands.values())} |")
    lines.append(f"| Downloads logged | {downloads} |")
    lines.append("")
    section(lines, "Top source IPs", top_n(ips, top), ("IP", "Events"))
    section(lines, "Top credentials (user:pass)", top_n(creds, top), ("Credential", "Attempts"))
    section(lines, "Top commands", top_n(commands, top), ("Command", "Count"))
    section(lines, "SSH client versions", top_n(clients, top), ("Client", "Count"))
    section(lines, "Event ID histogram", top_n(event_ids, top), ("Event ID", "Count"))
    return "\n".join(lines)


def _extract_modbus_fc(ev: dict[str, Any]) -> int | None:
    fc = ev.get("function_code")
    if isinstance(fc, int):
        return fc
    if isinstance(fc, str) and fc.isdigit():
        return int(fc)
    # Sometimes buried in request/response text or nested data
    for key in ("request", "response", "data"):
        val = ev.get(key)
        if isinstance(val, dict):
            nested = val.get("function_code")
            if isinstance(nested, int):
                return nested
    # Hex Modbus TCP ADU: TX.. TX.. PROTO PROTO LEN LEN UNIT FC ...
    req = ev.get("request")
    if isinstance(req, str) and re.fullmatch(r"[0-9a-fA-F]+", req) and len(req) >= 16:
        try:
            return int(req[14:16], 16)
        except ValueError:
            return None
    return None


def analyze_conpot(events: Iterable[dict[str, Any]], top: int) -> str:
    ips: Counter = Counter()
    protocols: Counter = Counter()
    event_types: Counter = Counter()
    dst_ports: Counter = Counter()
    fcs: Counter = Counter()
    sessions: set[str] = set()
    http_reqs: Counter = Counter()
    snmp_reqs: Counter = Counter()
    total = 0

    for ev in events:
        total += 1
        ip = ev.get("src_ip") or ev.get("remote_ip") or "?"
        if ip and ip != "?":
            ips[ip] += 1
        dtype = ev.get("data_type") or ev.get("protocol") or "unknown"
        protocols[str(dtype)] += 1
        et = ev.get("event_type") or ev.get("type")
        if et:
            event_types[str(et)] += 1
        dport = ev.get("dst_port")
        if dport is not None:
            dst_ports[str(dport)] += 1
        sid = ev.get("id") or ev.get("sessionid") or ev.get("session")
        if sid:
            sessions.add(str(sid))

        if str(dtype).lower() == "modbus":
            fc = _extract_modbus_fc(ev)
            if fc is not None:
                label = MODBUS_FC.get(fc, f"FC{fc}")
                fcs[f"{fc} ({label})"] += 1
        elif str(dtype).lower() == "http":
            req = ev.get("request") or ""
            if req:
                # Keep first line / short form
                http_reqs[str(req).split("\n")[0][:120]] += 1
        elif str(dtype).lower() == "snmp":
            req = ev.get("request") or et or ""
            if req:
                snmp_reqs[str(req)[:120]] += 1

    lines: list[str] = []
    lines.append("## Conpot (ICS / SCADA)")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Events | {total} |")
    lines.append(f"| Unique source IPs | {len(ips)} |")
    lines.append(f"| Sessions (ids) | {len(sessions)} |")
    lines.append(f"| Protocols seen | {len(protocols)} |")
    lines.append(f"| Modbus FC kinds | {len(fcs)} |")
    lines.append("")
    section(lines, "Top source IPs", top_n(ips, top), ("IP", "Events"))
    section(lines, "Protocol / data_type", top_n(protocols, top), ("Protocol", "Count"))
    section(lines, "Destination ports", top_n(dst_ports, top), ("Port", "Count"))
    section(lines, "Modbus function codes", top_n(fcs, top), ("Function code", "Count"))
    section(lines, "Event types", top_n(event_types, top), ("Type", "Count"))
    section(lines, "HTTP requests (sample)", top_n(http_reqs, top), ("Request", "Count"))
    section(lines, "SNMP requests (sample)", top_n(snmp_reqs, top), ("Request", "Count"))
    lines.append("_Tank/valve story map: `conpot/etc/WATER_TANK_MAP.md`_")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    lines: list[str] = [
        "# Combined Honeypot Analysis Report",
        "",
        f"_Generated by `scripts/analyze_all.py` — {now}_",
        "",
        "## Architecture snapshot",
        "",
        "| Honeypot | Emulates | Default host ports | Log path |",
        "| --- | --- | --- | --- |",
        "| Cowrie | Ubuntu-like SSH/Telnet | 2222 / 2223 | `cowrie/var/log/cowrie/cowrie.json` |",
        "| Conpot | Siemens-style ICS (Modbus/HTTP/SNMP/S7) | 5020 / 8080 / 1161/udp / 1102 | `conpot/var/log/conpot.json` |",
        "",
    ]

    # Cowrie
    try:
        cowrie_events = list(iter_jsonl(args.cowrie))
        lines.append(analyze_cowrie(cowrie_events, args.top))
    except FileNotFoundError as exc:
        if not args.skip_missing:
            print(f"Error: Cowrie log missing ({exc})", file=sys.stderr)
            print("Hint: pass --cowrie sample-output/cowrie.json.sample or --skip-missing", file=sys.stderr)
            return 1
        lines.append("## Cowrie (SSH / Telnet)\n\n_Log not found — skipped._\n")

    # Conpot
    try:
        conpot_events = list(iter_jsonl(args.conpot))
        lines.append(analyze_conpot(conpot_events, args.top))
    except FileNotFoundError as exc:
        if not args.skip_missing:
            print(f"Error: Conpot log missing ({exc})", file=sys.stderr)
            print("Hint: pass --conpot sample-output/conpot.json.sample or --skip-missing", file=sys.stderr)
            return 1
        lines.append("## Conpot (ICS / SCADA)\n\n_Log not found — skipped._\n")

    lines.append("---")
    lines.append("_Defensive coursework only. See docs/ETHICS.md._")
    lines.append("")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
