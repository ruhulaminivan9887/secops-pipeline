# Case 002: Reconnaissance tool executed (rule 100012)

| Field | Value |
|---|---|
| Date and time (UTC) | 2026-10-18 (lab test, host clock 6:06 PM) |
| Host / user | Windows Server lab host / local Administrator |
| Alert / rule ID and level | 100012, level 7, "Windows reconnaissance tool executed" |
| Data source | Windows Security Event 4688 via Wazuh |
| ATT&CK technique | T1033 System Owner/User Discovery, T1082 System Information Discovery |
| Verdict | Benign true positive (my own test) |
| Severity | Low |

## 1. What fired
Rule 100012 matched an event 4688 whose `newProcessName` is `C:\Windows\System32\whoami.exe`.

## 2. Evidence
`wazuh-logtest` output: decoder `json`, event ID 4688, rule 100012, level 7, MITRE T1033 and T1082, tactic Discovery, "Alert to be generated". Screenshot: `docs/03-wazuh-logtest-rule-100012.png`.

## 3. Investigation
- `whoami` shows the current user and, with `/all`, groups and privileges. Attackers run it right after getting a shell to learn their access level.
- I ran it myself on the lab host, so the user and time match my own session.
- A single `whoami` from an administrator is normal. A burst of `whoami`, `systeminfo`, `nltest` and `net user` within a minute from a user who does not normally administer machines would be suspicious.

## 4. Verdict and reasoning
Benign true positive: the detection works, and the activity was mine. The rule is meant to be a **low-severity signal that becomes interesting in combination**, not a stand-alone alarm.

## 5. Action
In a real SOC: close if the user is an administrator or help desk member at a normal time. Escalate if it appears next to other discovery commands, from a non-admin account, or after a suspicious parent (Office, browser, script host).

## 6. Detection improvement
Raise severity only when 3 or more recon commands run from the same host and user within 5 minutes. Exclude known admin accounts and jump hosts, and add parent process to the alert so Tier 1 can see the origin at a glance.
