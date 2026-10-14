# SecOps Detection Engineering & Telemetry Pipeline

An end-to-end SOC engineering lab demonstrating Windows endpoint telemetry parsing, custom log ingestion, and Sigma-based threat detection rules.

## Architecture & Infrastructure
- **Endpoint/Victim:** Windows Server 2025 (Generating Event ID 4688 process creation telemetry)
- **SIEM / Pipeline Node:** Ubuntu Server 26.04.1 (`10.30.50.34`)
- **Parser Engine:** Custom Python 3 telemetry normalization (`log_parser.py`)
- **Detection Standards:** Custom Sigma rules for process execution monitoring

## Project Components
1. `scripts/log_parser.py`: Python script designed to extract key fields (Process Name, Parent Process, Account Name, Time) from Windows Security Event ID 4688 logs and structure them into normalized JSON output.
2. `sigma_rules/custom_process_spawn.yml`: Detection rule targetting suspicious process executions (e.g., PowerShell spawning execution binaries or unauthorized commands).

## Verification & Deployment
1. Enabled Process Creation auditing on Windows Server 2025 via standard Group Policy settings.
2. Forwarded telemetry to the Ubuntu parser node over SSH.
3. Validated log normalization and alert logic output against custom Sigma patterns.
