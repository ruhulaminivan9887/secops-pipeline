# SecOps Detection Engineering & Telemetry Pipeline

![ci](https://github.com/ruhulaminivan9887/secops-pipeline/actions/workflows/ci.yml/badge.svg)

A small SOC lab: a Windows Server host generates process-creation events (Event ID 4688), a Wazuh agent ships them to a Wazuh manager on Ubuntu, custom rules raise alerts, and a Python script turns the raw alert stream into clean, normalized JSON.

## Architecture

```
Windows Server 2025                     Ubuntu Server 26.04.1 (10.30.50.34)
┌────────────────────────┐   Wazuh     ┌──────────────────────────────────────────┐
│ Security log           │   agent     │ Wazuh manager 4.14.7                     │
│ Event ID 4688          │ ──────────▶ │   custom rules (local_rules.xml)         │
│ (process creation)     │             │        │                                 │
└────────────────────────┘             │        ▼                                 │
                                       │ /var/ossec/logs/alerts/alerts.json       │
                                       │        │                                 │
                                       │        ▼                                 │
                                       │ scripts/log_parser.py ─▶ parsed_4688.jsonl│
                                       └──────────────────────────────────────────┘
```

## What is in this repo

| Path | Purpose |
|---|---|
| `scripts/log_parser.py` | Follows the Wazuh JSON log, keeps only 4688 events, and outputs user, host, process, **parent process**, command line, and the rule that fired. Handles log rotation. |
| `sigma_rules/` | Three vendor-neutral Sigma rules (portable detection logic, tagged with MITRE ATT&CK). |
| `wazuh_rules/local_rules.xml` | The same three detections hand-translated to Wazuh rules, because Wazuh does not execute Sigma YAML directly. |
| `docs/` | Screenshots of the lab running. |
| `cases/` | SOC-style case reports written from lab alerts. |
| `samples/` | Synthetic Wazuh alerts in the real alerts.json format, so the parser can be tried without a lab. |
| `tests/` | 22 automated tests for the parser, the Wazuh rules and Sigma/Wazuh consistency. |

## Detections

| Detection | Sigma file | Wazuh rule | Level | ATT&CK |
|---|---|---|---|---|
| Office app spawns a shell or script host | `office_spawns_shell.yml` | 100010 | 12 | T1204.002, T1059 |
| PowerShell with an encoded command | `encoded_powershell.yml` | 100011 | 10 | T1059.001, T1027 |
| Recon tools (`whoami`, `systeminfo`, `nltest`, `quser`, `qwinsta`) | `windows_recon_commands.yml` | 100012 | 7 | T1033, T1082 |
| `net.exe` user, group, or host enumeration | `windows_recon_commands.yml` | 100013 | 7 | T1087 |
| 5 or more failed logons (4625) from one source in 60 s | `windows_failed_logon_burst.yml` | 100014 | 10 | T1110 |

## Setup

**1. Windows Server: log process creation with command lines (Group Policy)**
- Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Detailed Tracking → **Audit Process Creation** → Success
- Computer Configuration → Administrative Templates → System → Audit Process Creation → **Include command line in process creation events** → Enabled
- Run `gpupdate /force`

**2. Ubuntu: add the rules and restart Wazuh**
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml     # append the <group> block from wazuh_rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t             # config test, must print no errors
sudo systemctl restart wazuh-manager
```

**3. Run the parser**
```bash
sudo python3 scripts/log_parser.py --out parsed_4688.jsonl
```
Use `--from-start --once` to parse everything already in the log and exit.

## Trigger each detection (run on the Windows host)

| Command | Expected alert |
|---|---|
| `whoami /all` | 100012 |
| `net user` | 100013 |
| `powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAcwBlAGMAbwBwAHMALQB0AGUAcwB0ACIA` | 100011 |
| Open Word, run a macro that starts `cmd.exe` | 100010 |
| `1..6 \| ForEach-Object { net use \\127.0.0.1\IPC$ /user:fakeuser "wrong$_" }` (needs `auditpol /set /subcategory:"Logon" /failure:enable`) | 60122 x6, then 100014 |

Watch the result on Ubuntu: `sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"id":"10001'`

## Try it without a lab

```bash
python3 scripts/log_parser.py --log samples/sample_alerts.json --from-start --once
```
`samples/sample_alerts.json` is synthetic (written by hand in the Wazuh alert format). It holds one event per detection, two normal events, a non-4688 event and one event with no command line.

## Tests

```bash
pip install pyyaml
python3 -m unittest discover -s tests -v
```
The tests check that the parser extracts every field and survives bad input, that each rule fires on its own sample and stays silent on normal events (including PowerShell with `-ExecutionPolicy Bypass`, which is not an encoded command), and that the Sigma and Wazuh files list the same ATT&CK techniques. They run on every push through GitHub Actions. The rule check is a simulation using Python's regex engine; `wazuh-logtest` uses the generic JSON decoder, so it does not prove a rule fires on live Windows events (see case 003). Always confirm with a live alert.

## Evidence

Screenshots are in `docs/`: the parser reading 362 process-creation events from the Windows host, `wazuh-logtest` matching custom rule 100012, and a live rule 100013 alert (`docs/04-live-alert-rule-100013.png`), a live rule 100011 alert (`docs/05-live-alert-rule-100011.png`), and a live rule 100014 alert (`docs/06-live-alert-rule-100014.png`).

## Case reports

Each detection is followed up like a SOC ticket: what fired, evidence, investigation, verdict, action and a tuning idea. Template: `cases/000-TEMPLATE.md`.

| Case | Topic | Verdict |
|---|---|---|
| 001 | Action1 remote-management agent running PowerShell | Benign true positive (forgotten install, verified by signature and email trail) |
| 002 | `whoami` caught by rule 100012 | Benign true positive (own test) |
| 003 | Custom rules never fired on live traffic (shadowed by built-in rule 67027); fixed, then `net user` caught by 100013 | True positive after fix (own test) |
| 004 | Encoded PowerShell caught live by rule 100011 | True positive (own test, harmless payload) |
| 005 | Failed-logon burst (brute force) caught by rule 100014; found logon auditing was off | True positive (own test) |
| 006 | Suspicious "terms update" email in Spam, proven legitimate with SPF/DKIM/DMARC and link checks | Legitimate (Gmail false positive) | 
| 007 | City Bank awareness email | Benign: legitimate bulk mail (DKIM-aligned DMARC pass) |

## License

MIT, see `LICENSE`.

## Limitations

- Rules are children of built-in rule 67027 (`if_sid`), so they only fire on events that built-in rule matches.
- `alerts.json` only contains events that matched a rule. To parse every event, enable `<logall_json>yes</logall_json>` and point `--log` at `archives.json`.
- The Sigma and Wazuh rules are translated by hand, so they can drift apart. Change both together.
- This is a single-host lab. The rules are tuned to the commands above and will produce false positives from legitimate administration in a real environment.
