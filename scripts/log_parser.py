import json
import re

def parse_event_4688(raw_log):
    """
    Parses raw Windows Event ID 4688 log strings into normalized JSON telemetry.
    """
    parsed_data = {
        "event_id": 4688,
        "event_type": "Process Creation",
        "account_name": None,
        "new_process_name": None,
        "parent_process_name": None,
        "command_line": None
    }
    
    # Extract field data using regex patterns
    account_match = re.search(r"Account Name:\s+(.+)", raw_log)
    process_match = re.search(r"New Process Name:\s+(.+)", raw_log)
    parent_match = re.search(r"Creator Process Name:\s+(.+)", raw_log)
    cmd_match = re.search(r"Process Command Line:\s+(.+)", raw_log)

    if account_match:
        parsed_data["account_name"] = account_match.group(1).strip()
    if process_match:
        parsed_data["new_process_name"] = process_match.group(1).strip()
    if parent_match:
        parsed_data["parent_process_name"] = parent_match.group(1).strip()
    if cmd_match:
        parsed_data["command_line"] = cmd_match.group(1).strip()

    return json.dumps(parsed_data, indent=4)

if __name__ == "__main__":
    sample_log = """
    Event ID: 4688
    Account Name: Administrator
    New Process Name: C:\\Windows\\System32\\cmd.exe
    Creator Process Name: C:\\Windows\\explorer.exe
    Process Command Line: cmd.exe /c echo Test Security Event
    """
    print(parse_event_4688(sample_log))
