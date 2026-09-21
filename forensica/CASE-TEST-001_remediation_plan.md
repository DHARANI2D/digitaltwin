# Actionable Remediation Plan
**Case Identifier:** CASE-TEST-001  

## Section 1: Immediate Automatic Cleanup Actions (No Approval Needed)
- **REMOVE_SCHEDULED_TASK** on `UpdateManagerTask`:  
  *Reason:* Persistence mechanism matching anomalous scheduling task.  
  *Command:* `schtasks /delete /tn 'UpdateManagerTask' /f`
- **KILL_PROCESS** on `PID: 4821`:  
  *Reason:* Process associated with finding: 'Office Application Spawned Shell Process (Potential Phishing Execution)'  
  *Command:* `taskkill /F /PID 4821`
- **KILL_PROCESS** on `PID: 4821`:  
  *Reason:* Process associated with finding: 'High-entropy command-line argument (Potential obfuscation/base64 payload)'  
  *Command:* `taskkill /F /PID 4821`

## Section 2: Host Isolation & Active Blocks (Human-In-The-Loop Approval Required)
- **FW_BLOCK_IP** on `185.220.101.47`:  
  *Reason:* Confirmed C2 Beacon Destination. VT Score: 58/72.  
  *Command:* `New-NetFirewallRule -DisplayName 'FORENSICA-Block-185.220.101.47' -Direction Outbound -Action Block -RemoteAddress 185.220.101.47`
- **EDR_ISOLATE_HOST** on `SEC-WORKSTATION`:  
  *Reason:* Host is beaconing active C2 telemetry to 185.220.101.47  
  *Command:* `Isolate-Host -Hostname 'SEC-WORKSTATION'`
- **DISABLE_USER_ACCOUNT** on `compromised_user_account`:  
  *Reason:* Account identified in root cause path; credentials likely compromised.  
  *Command:* `Disable-ADAccount -Identity 'compromised_user_account'`

## Section 3: Mitigation Playbook Execution Instructions
1. Execute the PowerShell blocks listed in Section 1 on the affected server.
2. Confirm the Palo Alto Firewall Block rule in Section 2 is deployed to boundary routers.
3. Force a password reset on the AD domain for active user accounts.
