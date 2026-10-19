#!/usr/bin/env python3
"""Tail a Wazuh JSON log and normalize Windows Security Event ID 4688 (process creation).

Reads /var/ossec/logs/alerts/alerts.json by default. Wazuh only writes an event there
when a rule fires, so 4688 events must match a rule (see wazuh_rules/local_rules.xml).
To see every event instead, enable <logall_json> in ossec.conf and pass
--log /var/ossec/logs/archives/archives.json.

Usage:
    sudo python3 scripts/log_parser.py                      # follow new events
    sudo python3 scripts/log_parser.py --from-start --once  # parse the whole file, then exit
    sudo python3 scripts/log_parser.py --out parsed_4688.jsonl
"""
import argparse
import json
import os
import sys
import time

DEFAULT_LOG = "/var/ossec/logs/alerts/alerts.json"


def normalize(event):
    """Return a flat dict for a 4688 event, or None for any other event."""
    win = event.get("data", {}).get("win", {})
    system = win.get("system", {})
    if str(system.get("eventID")) != "4688":
        return None
    data = win.get("eventdata", {})
    rule = event.get("rule", {})
    return {
        "time": system.get("systemTime") or event.get("timestamp"),
        "host": system.get("computer") or event.get("agent", {}).get("name"),
        "user": data.get("subjectUserName"),
        "domain": data.get("subjectDomainName"),
        "process": data.get("newProcessName"),
        "parent_process": data.get("parentProcessName"),
        "command_line": data.get("commandLine"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
    }


def follow(path, from_start):
    """Yield lines from a file as it grows, reopening it if Wazuh rotates it."""
    handle = open(path, "r", encoding="utf-8", errors="replace")
    if not from_start:
        handle.seek(0, os.SEEK_END)
    inode = os.fstat(handle.fileno()).st_ino
    while True:
        line = handle.readline()
        if line:
            yield line
            continue
        time.sleep(0.5)
        try:
            if os.stat(path).st_ino != inode:  # rotated: start on the new file
                handle.close()
                handle = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(handle.fileno()).st_ino
        except FileNotFoundError:
            continue


def read_once(path, from_start):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        if not from_start:
            handle.seek(0, os.SEEK_END)
        yield from handle


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", default=DEFAULT_LOG, help="Wazuh JSON log to read (default: %(default)s)")
    parser.add_argument("--from-start", action="store_true", help="read existing lines instead of only new ones")
    parser.add_argument("--once", action="store_true", help="exit at end of file instead of following it")
    parser.add_argument("--out", help="also append normalized events to this JSON Lines file")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[-] Log file not found: {args.log}", file=sys.stderr)
        return 1

    source = read_once(args.log, args.from_start) if args.once else follow(args.log, args.from_start)
    out = open(args.out, "a", encoding="utf-8") if args.out else None
    warned = False
    count = 0
    print(f"[*] Reading {args.log} ({'once' if args.once else 'following'})", file=sys.stderr)

    try:
        for line in source:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            record = normalize(event)
            if record is None:
                continue
            count += 1
            if record["command_line"] is None and not warned:
                print("[!] No command line in this event. Enable 'Include command line in process "
                      "creation events' in Group Policy (Administrative Templates > System > "
                      "Audit Process Creation).", file=sys.stderr)
                warned = True
            print(f"[4688] {record['time']} | {record['user']} | "
                  f"{record['parent_process']} -> {record['process']} | {record['command_line']}", flush=True)
            if out:
                out.write(json.dumps(record) + "\n")
                out.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if out:
            out.close()
    print(f"[*] Parsed {count} event(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
