import json
import time

# Target the raw archives stream to catch all telemetry, including level 0 events
LOG_FILE = "/var/ossec/logs/alerts/alerts.json"

def parse_logs():
    print("[*] Starting custom Python telemetry pipeline on archives stream...")
    try:
        with open(LOG_FILE, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                try:
                    event = json.loads(line)
                    # Check if it's a Windows event containing data
                    win_data = event.get("data", {}).get("win", {}).get("eventdata", {})
                    sys_data = event.get("data", {}).get("win", {}).get("system", {})

                    # Fallback check for Event ID 4688 (Process Creation)
                    event_id = sys_data.get("eventID") or event.get("data", {}).get("win", {}).get("system",{}).get("eventID")

                    if str(event_id) == "4688":
                        image = win_data.get("newProcessName", "N/A")
                        command_line = win_data.get("commandLine", "N/A")
                        user = win_data.get("subjectUserName", "N/A")

                        print(f"[PARSED 4688] User: {user} | Process:{image} | Cmd: {command_line}")
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[-] Error: Could not find log file at {LOG_FILE}")

if __name__ == "__main__":
    parse_logs()
