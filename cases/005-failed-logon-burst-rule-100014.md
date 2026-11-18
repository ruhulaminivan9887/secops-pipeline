# Case 005: Burst of failed logons (brute force), rule 100014

| Field | Value |
|---|---|
| Date and time (UTC) | 2026-11-16 05:27 |
| Host / user | Windows-Server (Wazuh agent 004) / target account `fakeuser` (does not exist) |
| Alert / rule ID and level | 100014, level 10, "Possible brute force: repeated failed Windows logons from the same source within 60 seconds" |
| Data source | Windows Security Event 4625 (failed logon) via Wazuh, built-in rule 60122 |
| ATT&CK technique | T1110 Brute Force (tactic: Credential Access) |
| Verdict | True positive (own test, simulated attack) |
| Severity | Medium to high (high if the source is external or a success follows) |

## 1. What fired
I ran 8 failed network logins in a few seconds against the lab server using a user name that does not exist. Wazuh raised 7 individual "Logon Failure - Unknown user or bad password" alerts (built-in rule 60122, the lab total reached 13 across two test rounds) and then **one rule 100014 alert** for the burst. Screenshot: `docs/06-live-alert-rule-100014.png` (level 10, T1110, Credential Access, agent Windows-Server).

## 2. What went wrong first (three findings)
1. **No log source.** Windows had `Logon` auditing set to "No Auditing", so failed logins produced no Event 4625 at all and Wazuh had nothing to detect. Fix: `auditpol /set /subcategory:"Logon" /failure:enable`. A detection is only as good as the logging underneath it.
2. **The setting did not last.** After the VM restarted, auditing was back to "No Auditing" and my second test produced no events until I enabled it again. The server's name ends in `.itest.com`, so a policy probably resets it. **Open item:** set it in Group Policy (Advanced Audit Policy, Logon/Logoff, Audit Logon, Failure) so it survives restarts.
3. **Detection gap.** Built-in rules only gave one low-level alert per failure. Six failed logins in about five seconds raised no brute-force alert, because the built-in "multiple failures" rule needs more attempts. That is the gap rule 100014 closes.

## 3. Evidence
- Event: ID 4625, logon type 3 (network), target user `fakeuser`, source address `127.0.0.1`.
- Rule 100014 is a frequency rule: it fires when 5 or more events from rule 60122 share the same `ipAddress` within 60 seconds. It fired once, on the 8th failure of the burst.
- **Unexplained detail:** I expected it on the 5th or 6th failure. I have not found out why it needed 8, and I will test with exactly 5 and 6 attempts to find the real trigger point.

## 4. Investigation
- Logon type 3 is a network logon (file share, remote tools). Brute-force attacks against Windows usually show up as type 3 or type 10 (remote desktop).
- The user name does not exist, so this looks like guessing names (a *user enumeration* or *password spray* pattern), not one account with a wrong password.
- The source is `127.0.0.1`, the machine itself, because I ran the test locally. In a real case, an outside address is the strongest sign of an attack.

## 5. Verdict and reasoning
True positive: the activity was my own simulated attack, and the rule detected it live. The alert is valid and matches ATT&CK T1110.

## 6. Action
In a real SOC:
1. Find the source IP: internal host or internet? Known scanner or admin?
2. List the targeted accounts and check for lockouts.
3. **Check for a successful logon (Event 4624) from the same IP right after the failures.** Failures followed by a success usually means the guess worked, so treat it as a compromise: reset the password, isolate the host, review what the account did.
4. If the source is external, block it at the firewall.

## 7. Detection improvement
- Enforce logon auditing with Group Policy (finding 2).
- Add a second rule for "failures followed by a success from the same source" (4624 after 100014).
- Work out the real trigger point of the frequency rule and tune it.
- The alert inherits the group `process_creation` from the parent rule, which is misleading. Give it an authentication group.
- Exclude known scanners and service accounts that retry with expired passwords.

## Follow-up: permanent fix for logon auditing (19 Nov 2026)
- Problem: Audit Logon (Failure) kept resetting to "No Auditing" after VM restarts, so rule 100014 could silently stop seeing failed logons.
- Fix: set Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon to Success and Failure in Local Group Policy, then ran gpupdate /force.
- Before: auditpol /get /subcategory:"Logon" returned No Auditing.
- After: the same command returned Success and Failure, and still did after a full restart.
- Lesson: a detection rule is only as reliable as the logging under it. Verify that the log source survives a reboot, not just that the rule fires once.
