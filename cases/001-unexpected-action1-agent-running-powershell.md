# Case 001: Action1 remote-management agent running PowerShell with ExecutionPolicy Bypass

| Field | Value |
|---|---|
| Date and time (UTC) | 2026-10-19 01:11:10 |
| Host / user | WIN-I2F3HV2KPMD / machine account (SYSTEM context) |
| Alert / rule ID and level | Found while reading the parsed 4688 stream; no custom rule matched |
| Data source | Windows Security Event 4688 via Wazuh |
| ATT&CK technique | T1219 Remote Access Software, T1059.001 PowerShell (only if malicious) |
| Verdict | Benign true positive (software I installed earlier and had forgotten) |
| Severity | Low |

## 1. What happened
`powershell.exe` was started with `-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command -` by `C:\Windows\Action1\action1_agent.exe`. Those flags are a common attacker pattern, and I did not remember installing a remote-management agent on this server, so I investigated instead of assuming.

## 2. Evidence
- Parent: `C:\Windows\Action1\action1_agent.exe`; process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Command line: `"C:\WINDOWS\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command -`
- The same pattern repeats at 01:11:15, plus a launch with the argument `loggedonuser` at 01:11:13.
- Screenshot: `docs/02-parser-362-events.png`

## 3. Investigation
1. **Host check.** `hostname` returned `WIN-I2F3HV2KPMD`, the host in the alert, so the event came from this VM.
2. **Is it installed and running?** The folder `C:\Windows\Action1` exists, the process `action1_agent` is running, and `Win32_Service` shows a service named `A1Agent` (state Running) with the path `C:\WINDOWS\Action1\action1_agent.exe service`.
3. **Is the file genuine?** `Get-AuthenticodeSignature` returned `Valid`, publisher `CN=Action1 Corporation, O=Action1 Corporation, L=Houston, S=Texas, C=US`.
4. **Who installed it?** My mailbox contains a "Welcome to Action1" email dated 21 August, 9:45 am. The installer comes from an account created with my address, and the date falls after this VM was built (the evaluation licence shows about 84 days remaining in mid-November, which puts the build in mid-August).
5. **File timestamp.** The agent file shows a creation time of 21 May 2026, which is before the VM existed. That is the vendor's build date carried inside the package, so it cannot be used as the install date.
6. **What I could not recover.** System event 7045 (service installed), the MsiInstaller records, a downloaded installer file and an Uninstall registry date returned nothing. The exact install time is therefore unproven.

## 4. Verdict and reasoning
Benign true positive. A validly signed vendor binary, running under the vendor's own service name from its own install folder, matches the account I created with that vendor. The PowerShell flags are how remote-management tools run scripts unattended. Confidence is high but not absolute, because the install logs are missing.

## 5. Action
Closed as benign and recorded as known software on this host. Recommendation: uninstall the agent, because this lab does not need a remote-management tool and it adds attack surface.

## 6. Detection improvement
- Alert on first-seen remote-management software (Action1, AnyDesk, TeamViewer, ScreenConnect, Atera) by file path or service name, and keep an allowlist of approved tools.
- Alert on PowerShell with `-ExecutionPolicy Bypass` only when its parent is not on that allowlist.
- Keep service-install (7045) and installer logs longer, or ship them to Wazuh, so the install time can be proven next time.

## Lessons
- Forgotten software is a real category of finding. Always check the vendor's signature and the account or email trail before calling something malicious.
- Say what you could not prove. Missing logs lower confidence; they do not change the verdict.
