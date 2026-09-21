# agents/root_cause_agent.py

from .base import BaseAgent
from db_helper import DatabaseHelper
import re

class RootCauseAgent(BaseAgent):
    """
    Performs recursive DFS process tree traversal to find the root process (Patient Zero).
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[RootCauseAgent] Running recursive DFS tree traversal to find Patient Zero...")
        
        db = DatabaseHelper()
        
        # 1. Build Process Map & Adjacency List
        # pid -> parent_pid
        parent_map = {}
        # pid -> process details
        proc_details = {}

        for e in state.evtx_events:
            # Only map process creation events to prevent network/other logs from overwriting parent relationships
            if e.get("event_type") != "Process" and e.get("event_id") != 4688:
                continue

            pid = e.get("pid", e.get("NewProcessId", 0))
            parent_pid = e.get("ParentProcessId", 0)
            proc_name = e.get("process", e.get("NewProcessName", "unknown"))
            parent_name = e.get("ParentProcessName", "")
            cmd_line = e.get("CommandLine", "")
            timestamp = e.get("timestamp", "")
            host = e.get("hostname", "unknown-host")

            if pid > 0:
                parent_map[pid] = parent_pid

                proc_details[pid] = {
                    "pid": pid,
                    "parent_pid": parent_pid,
                    "name": proc_name,
                    "parent_name": parent_name,
                    "command_line": cmd_line,
                    "timestamp": timestamp,
                    "host": host
                }

        # 2. Identify all anomalous target PIDs (e.g. shells or network logs)
        target_pids = []
        for e in state.evtx_events:
            proc = e.get("process", "").lower()
            if any(sh in proc for sh in ["powershell", "cmd.exe", "mshta", "wscript", "cscript", "schtasks"]):
                pid = e.get("pid", e.get("NewProcessId", 0))
                if pid > 0:
                    target_pids.append(pid)

        # 3. Recursive DFS traversal function
        def find_root(pid, visited):
            if pid in visited:
                return pid
            visited.add(pid)
            
            parent_pid = parent_map.get(pid)
            # Reconstruct parent if it exists in the active details
            if parent_pid and parent_pid in proc_details:
                return find_root(parent_pid, visited)
            return pid

        # Trace all suspicious processes to find their roots
        roots = []
        for target in target_pids:
            visited = set()
            root_pid = find_root(target, visited)
            if root_pid in proc_details:
                roots.append(proc_details[root_pid])

        # 4. Resolve patient zero
        patient_zero = None
        earliest_time = None
        host = "unknown-host"
        confidence = 40

        # Sort roots by timestamp to find the earliest execution chain
        roots = sorted(roots, key=lambda x: x.get("timestamp", ""))
        
        if roots:
            earliest_root = roots[0]
            host = earliest_root.get("host", host)
            earliest_time = earliest_root.get("timestamp")
            
            # Check command line for input documents / files
            cmd = earliest_root.get("command_line", "")
            # Search for standard phishing/ingress document attachments first
            doc_match = re.search(r'([a-zA-Z0-9_\-\.]+\.(docx|docm|xlsx|xls|pdf|lnk|zip|rar|7z))', cmd.lower())
            doc_name = doc_match.group(1) if doc_match else None
            
            # If no document found, look for executable attachments (excluding the runner itself)
            if not doc_name:
                exe_matches = re.findall(r'([a-zA-Z0-9_\-\.]+\.exe)', cmd.lower())
                p_name_lower = p_name.lower()
                for exe_m in exe_matches:
                    if exe_m != p_name_lower and exe_m != "cmd.exe" and exe_m != "powershell.exe":
                        doc_name = exe_m
                        break
            
            p_name = earliest_root.get("name", "unknown")
            parent_p_name = earliest_root.get("parent_name", "unknown")
            
            if doc_name:
                patient_zero = f"{p_name} opening {doc_name}"
                confidence = 97

            else:
                if "winword" in p_name.lower() or "excel" in p_name.lower():
                    patient_zero = f"{p_name} Macro Execution"
                    confidence = 95
                else:
                    patient_zero = f"{p_name} (PID: {earliest_root.get('pid')}) spawned by {parent_p_name}"
                    confidence = 85
        else:
            # Fallback to earliest process launch in evtx events list
            sorted_events = sorted(state.evtx_events, key=lambda x: x.get("timestamp", ""))
            if sorted_events:
                first = sorted_events[0]
                patient_zero = f"{first.get('process')} (PID: {first.get('pid')})"
                earliest_time = first.get("timestamp")
                host = first.get("hostname", host)

        state.root_cause = {
            "patient_zero": patient_zero or "Unknown entry point",
            "timestamp": earliest_time,
            "host": host,
            "confidence": confidence
        }

        print(f"[RootCauseAgent] DFS completed. Root Cause: {state.root_cause['patient_zero']} on {host} at {earliest_time}")
        
        # Save to DB findings table
        db.insert_finding(
            state.case_id,
            f"Intrusion Patient Zero: {state.root_cause['patient_zero']}",
            confidence,
            state.root_cause,
            "RootCauseAgent",
            is_validated=True
        )

        return state
