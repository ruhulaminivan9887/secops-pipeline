# Case 003: Custom rules never fired on live traffic; `net user` caught by rule 100013

| Field | Value |
|---|---|
| Date and time (UTC) | 2026-11-15, live detections at 21:23 and 21:28 |
| Host / user | Windows-Server (Wazuh agent 004) / local Administrator |
| Alert / rule ID and level | 100013, level 7, "net.exe used to enumerate users, groups, or hosts" |
| Data source | Windows Security Event 4688 via Wazuh |
| ATT&CK technique | T1087 Account Discovery (tactic: Discovery) |
| Verdict | True positive after fix (own test). Detection gap found and closed. |
| Severity | Low to medium on its own |

## 1. What fired
After the fix below, running `net user` as Administrator produced rule 100013 four times: `powershell.exe` started `net.exe`, which started its child `net1.exe`, and each command ran twice (21:23 and 21:28). Rule 100012 (`whoami`) fired once.

## 2. The problem I found first
Before the fix, the same `net user` produced only Wazuh's built-in rule **67027** ("A process was created", level 3). Rule 100013 stayed silent, even though `wazuh-logtest` said it matched.

- In `wazuh-logtest` I used a hand-written JSON event, which Wazuh decodes with the generic `json` decoder. The rule matched.
- Live Windows events use the `windows_eventchannel` decoder. Wazuh's built-in Windows rules claimed those events first (67027), and my custom rules, which had no parent rule, were never reached.
- So all four custom rules (100010 to 100013) were silent on live traffic. A passing test hid a broken detection.

## 3. Fix
I made each custom rule a child of 67027 by adding `<if_sid>67027</if_sid>`. I backed up the file first, edited it, restarted `wazuh-manager`, and repeated the live test.

Result: rule 100012 and rule 100013 both fire on live events. Screenshot of the live alert (rule, level 7, T1087, agent Windows-Server): `docs/04-live-alert-rule-100013.png`.

## 4. Investigation
- `net user` lists local accounts. Attackers run it right after getting access to see who exists and who might be worth targeting.
- I ran it myself from an administrator PowerShell session, so the user, time and parent process match my own session.
- Normal administration also uses it, so on its own it is a weak signal. It matters in combination with other discovery commands.

## 5. Verdict and reasoning
True positive (my own test). The activity was mine, but the detection works as designed on live data, and I found and fixed a gap that would have hidden a real attack.

## 6. Action
In a real SOC: close if the user is a known administrator at a normal time. Escalate if `net user` appears with `whoami`, `systeminfo` or `nltest` within a few minutes, from a non-admin account, or after a suspicious parent (Office, browser, script host).

## 7. Detection improvement
- **Test with live events, not only logtest.** A rule is not proven until it fires on real agent traffic.
- **Duplicate alerts:** one `net user` creates two alerts (`net.exe` and its child `net1.exe`). Alert only on `net.exe`, or suppress the child when its parent is `net.exe`.
- **Noise source:** the Wazuh agent runs `net user` on its own (SYSTEM account, parent `wazuh-agent.exe`). Exclude that parent so it does not trigger 100013 repeatedly.
- Raise severity only when several discovery commands run from the same host and user within 5 minutes.
