# SecOps Detection Engineering & Telemetry Pipeline

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

## Detections

| Detection | Sigma file | Wazuh rule | Level | ATT&CK |
|---|---|---|---|---|
| Office app spawns a shell or script host | `office_spawns_shell.yml` | 100010 | 12 | T1204.002, T1059 |
| PowerShell with an encoded command | `encoded_powershell.yml` | 100011 | 10 | T1059.001, T1027 |
| Recon tools (`whoami`, `systeminfo`, `nltest`, `quser`, `qwinsta`) | `windows_recon_commands.yml` | 100012 | 7 | T1033, T1082 |
| `net.exe` user, group, or host enumeration | `windows_recon_commands.yml` | 100013 | 7 | T1087 |

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

Watch the result on Ubuntu: `sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"id":"10001'`

## Evidence

Screenshots are in `docs/`: the Windows 4688 events, the live parser stream on Ubuntu, an alert entry showing user, process path, and command-line arguments, the Sigma rule, and `wazuh-logtest` matching a custom rule.

## Limitations

- `alerts.json` only contains events that matched a rule. To parse every event, enable `<logall_json>yes</logall_json>` and point `--log` at `archives.json`.
- The Sigma and Wazuh rules are translated by hand, so they can drift apart. Change both together.
- This is a single-host lab. The rules are tuned to the commands above and will produce false positives from legitimate administration in a real environment.
