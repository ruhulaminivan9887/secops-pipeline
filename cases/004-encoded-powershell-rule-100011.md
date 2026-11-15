# Case 004: PowerShell launched with an encoded command (rule 100011)

| Field | Value |
|---|---|
| Date and time (UTC) | 2026-11-15 22:05 |
| Host / user | Windows-Server (Wazuh agent 004) / local Administrator |
| Alert / rule ID and level | 100011, level 10, "PowerShell launched with an encoded command" |
| Data source | Windows Security Event 4688 via Wazuh |
| ATT&CK technique | T1059.001 PowerShell (Execution), T1027 Obfuscated Files or Information (Defense Evasion) |
| Verdict | True positive (own test, harmless payload) |
| Severity | High until the decoded command is read |

## 1. What fired
I ran `powershell -enc <Base64 text>` as Administrator. Wazuh raised rule 100011 once, on a live event, with no logtest involved. Screenshot: `docs/05-live-alert-rule-100011.png` (rule, level 10, T1059.001 and T1027, agent Windows-Server).

## 2. Evidence
- Rule 100011, level 10, tactics Execution and Defense Evasion, fired 1 time.
- One command produced one alert (unlike `net user` in case 003, which produced two).
- The rule was a child of built-in rule 67027 (`if_sid`), the fix from case 003, so it fired on live traffic the first time.

## 3. Investigation
- `-enc` (short for `-EncodedCommand`) makes PowerShell run Base64 text. Attackers use it to hide what a command does from simple log reading and keyword filters.
- Decoding the Base64 reveals the real command. Mine decodes to `Write-Host "secops-test"`, which prints a word and nothing else. In a real case this is the first thing to do.
- I ran it myself from an administrator session, so user, time and host match my own work.
- Normal software also uses `-enc` (some installers and management tools), so the decoded content and the parent process decide the verdict.

## 4. Verdict and reasoning
True positive (my own test): the detection works as designed on live data, and the activity was harmless because I wrote the payload.

## 5. Action
In a real SOC: decode the Base64 first. Close if it is a known admin or management tool with expected content. Escalate immediately if it downloads files, contacts the internet, disables security tools, or its parent is Office, a browser or a script host. Isolate the host if malicious.

## 6. Detection improvement
- Add the decoded command to the alert, so Tier 1 sees the intent without decoding by hand.
- Alert harder when the parent process is Office, a browser or `wscript`/`mshta`.
- Allow-list known management tools by parent process and signer, to cut false positives.
- Also watch for related flags: `-nop`, `-w hidden`, and `IEX (New-Object Net.WebClient)` style download strings.
