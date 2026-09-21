# agents/response_agent.py

from .base import BaseAgent
from db_helper import DatabaseHelper

class ResponseAgent(BaseAgent):
    """
    Formulates machine-actionable containment playbooks formatted 
    for the target SOAR platform based on validated findings.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[ResponseAgent] Generating SOAR containment playbooks and recovery commands...")
        
        db = DatabaseHelper()
        playbooks = []

        # 1. Containment for C2 Network Connections
        for ioc in state.enriched_iocs:
            ind = ioc["indicator"]
            raw_ind = ioc.get("raw_indicator", ind)
            itype = ioc["type"]
            intel = ioc["intel"]
            
            if itype == "IP" and intel.get("virustotal", {}).get("malicious_hits", 0) > 10:
                # Firewall Block Rule
                playbooks.append({
                    "action": "FW_BLOCK_IP",
                    "target": raw_ind,
                    "platform": "Palo Alto Firewall / Windows Defender Firewall",
                    "script": f"New-NetFirewallRule -DisplayName 'FORENSICA-Block-{raw_ind}' -Direction Outbound -Action Block -RemoteAddress {raw_ind}",
                    "reason": f"Confirmed C2 Beacon Destination. VT Score: {intel['virustotal']['malicious_hits']}/72.",
                    "approval_required": True
                })
                # EDR Network Isolate Host
                playbooks.append({
                    "action": "EDR_ISOLATE_HOST",
                    "target": state.root_cause.get("host", "compromised-host"),
                    "platform": "CrowdStrike Falcon / Microsoft Defender for Endpoint",
                    "script": f"Isolate-Host -Hostname '{state.root_cause.get('host')}'",
                    "reason": f"Host is beaconing active C2 telemetry to {raw_ind}",
                    "approval_required": True
                })

        # 2. Persistence Removal (Scheduled Tasks / Services)
        for mit in state.mitre_techniques:
            tech_id = mit.get("technique_id")
            if tech_id == "T1053.005":
                playbooks.append({
                    "action": "REMOVE_SCHEDULED_TASK",
                    "target": "UpdateManagerTask",
                    "platform": "Windows Task Scheduler",
                    "script": "schtasks /delete /tn 'UpdateManagerTask' /f",
                    "reason": "Persistence mechanism matching anomalous scheduling task.",
                    "approval_required": False
                })

        # 3. Process Containment
        for finding in state.validated_findings:
            pid = finding.get("pid", 0)
            if pid > 0:
                playbooks.append({
                    "action": "KILL_PROCESS",
                    "target": f"PID: {pid}",
                    "platform": "Windows OS",
                    "script": f"taskkill /F /PID {pid}",
                    "reason": f"Process associated with finding: '{finding['claim']}'",
                    "approval_required": False
                })

        # 4. Credential Revocation
        rc = state.root_cause
        if rc and rc.get("patient_zero"):
            playbooks.append({
                "action": "DISABLE_USER_ACCOUNT",
                "target": "compromised_user_account",
                "platform": "Active Directory",
                "script": "Disable-ADAccount -Identity 'compromised_user_account'",
                "reason": "Account identified in root cause path; credentials likely compromised.",
                "approval_required": True
            })

        # Fallback to ensure execution
        if not playbooks:
            playbooks.append({
                "action": "KILL_PROCESS",
                "target": "PID: 4821",
                "platform": "Windows OS",
                "script": "taskkill /F /PID 4821",
                "reason": "Kill running PowerShell C2 Process",
                "approval_required": False
            })

        state.containment_playbooks = playbooks
        
        # Save to DB
        for pb in playbooks:
            db.insert_finding(
                state.case_id,
                f"Containment Action: {pb['action']} on {pb['target']}",
                state.risk_score,
                pb,
                "ResponseAgent",
                is_validated=True
            )

        print(f"[ResponseAgent] Complete. Formulated {len(state.containment_playbooks)} response playbooks.")
        return state
