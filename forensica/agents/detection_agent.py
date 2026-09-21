# agents/detection_agent.py

import os
import json
from .base import BaseAgent
from db_helper import DatabaseHelper
from anthropic import Anthropic

class DetectionAgent(BaseAgent):
    """
    Maps confirmed attack techniques and auto-generates customized 
    Sigma, Splunk SPL, and Sentinel KQL rules matching the exact case telemetry.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[DetectionAgent] Dynamically generating custom detection rules for case TTPs...")
        
        db = DatabaseHelper()
        state.detection_rules = []

        # Gather details of the process events and command lines to build rules
        sus_processes = []
        for det in state.detections:
            finding = det.get("finding", "")
            pid = det.get("pid", 0)
            details = det.get("details", "")
            
            # Extract process, parent, command line from detections
            proc_match = re.search(r'spawned:?\s*([a-zA-Z0-9_\-\.]+)', details.lower())
            parent_match = re.search(r'parent:?\s*([a-zA-Z0-9_\-\.]+)', details.lower())
            cmd_match = re.search(r'commandline:?\s*(.+)', details.lower()) or re.search(r'command:?\s*(.+)', details.lower())
            
            proc = proc_match.group(1) if proc_match else None
            parent = parent_match.group(1) if parent_match else None
            cmd = cmd_match.group(1) if cmd_match else None
            
            if not proc and "lolbin" in finding.lower():
                proc = finding.split(":")[-1].strip()
            
            if proc or parent or cmd:
                sus_processes.append({
                    "process": proc,
                    "parent": parent,
                    "command_line": cmd,
                    "finding": finding
                })

        # Gather remote connections
        remote_ips = []
        for ioc in state.iocs:
            if ioc["type"] == "IP":
                remote_ips.append(ioc.get("raw_indicator", ioc["indicator"]))

        # 1. Generate rules using Real AI if key is set
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                print("[DetectionAgent] Invoking Anthropic Claude to craft customized detection rules...")
                client = Anthropic(api_key=api_key)
                
                context = {
                    "observations": sus_processes,
                    "remote_ips": remote_ips,
                    "techniques": [t.get("technique_id") for t in state.mitre_techniques if isinstance(t, dict)]
                }
                
                prompt = f"""
You are a senior Detection Engineer.
Given the observed suspicious processes and network indicators:
{json.dumps(context, indent=2)}

Write three customized detection rules in JSON format containing:
1. A valid Sigma rule (YAML block) detecting the specific process launches or network connections.
2. A Splunk SPL search query targeting the same execution.
3. A Sentinel KQL query targeting the same execution.

Output JSON ONLY with the exact format:
{{"rules": [{{"rule_name": "...", "type": "Sigma|Splunk|KQL", "content": "..."}}]}}
"""
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=1500,
                    system="You are a SIEM query writing system. Output only raw JSON mapping rules.",
                    messages=[{"role": "user", "content": prompt}]
                )
                
                resp_text = response.content[0].text.strip()
                if resp_text.startswith("```json"):
                    resp_text = resp_text[7:-3].strip()
                elif resp_text.startswith("```"):
                    resp_text = resp_text[3:-3].strip()
                    
                obj = json.loads(resp_text)
                for r in obj.get("rules", []):
                    state.detection_rules.append(r)
                    db.insert_detection(state.case_id, r["rule_name"], r["content"], r["type"])
                print(f"[DetectionAgent] Claude successfully generated {len(state.detection_rules)} custom rules.")
            except Exception as e:
                print(f"[DetectionAgent] Claude rule generation failed: {e}. Falling back to templating engine.")
                self._run_templated_engine(state, db, sus_processes, remote_ips)
        else:
            print("[DetectionAgent] ANTHROPIC_API_KEY not found. Running local templated rules generation.")
            self._run_templated_engine(state, db, sus_processes, remote_ips)

        # Fallback default rules if no specific rules got generated
        if not state.detection_rules:
            self._generate_fallbacks(state, db)

        print(f"[DetectionAgent] Complete. Rules registered: {len(state.detection_rules)}")
        return state

    def _run_templated_engine(self, state, db, sus_processes, remote_ips):
        # Generate custom rules dynamically based on parsed variables
        # Process Execution Rule
        for p in sus_processes:
            proc_val = p["process"] or "powershell.exe"
            parent_val = p["parent"] or "winword.exe"
            cmd_snippet = p["command_line"] or "-enc"
            
            base_name = f"Custom_Detect_{proc_val.replace('.exe', '')}_Spawned_By_{parent_val.replace('.exe', '')}"
            
            sigma = f"""title: Custom Detection of {proc_val} Spawns
id: {os.urandom(16).hex()}
status: production
description: Automatically generated rule to detect suspicious spawns of {proc_val} from {parent_val}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\\{parent_val}'
    Image|endswith: '\\{proc_val}'
  condition: selection
level: critical
tags:
  - attack.execution"""
            
            splunk = f'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\\\\{parent_val}" Image="*\\\\{proc_val}"'
            kql = f'SecurityEvent | where EventID == 4688 and ParentProcessName endswith "{parent_val}" and ProcessName endswith "{proc_val}"'
            
            self._add_and_log_rules(state, db, base_name, sigma, splunk, kql)

        # Network Outbound Rule
        for ip in remote_ips:
            # Strip brackets if defanged
            clean_ip = ip.replace("[.]", ".").replace("[", "").replace("]", "")
            base_name = f"Custom_Block_Outbound_C2_{clean_ip.replace('.', '_')}"
            
            sigma = f"""title: Network Connection to Malicious C2 Host {clean_ip}
id: {os.urandom(16).hex()}
status: production
description: Detects outbound TCP connection to identified C2 address {clean_ip}
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '{clean_ip}'
  condition: selection
level: critical
tags:
  - attack.command_and_control"""
            
            splunk = f'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="{clean_ip}"'
            kql = f'DeviceNetworkEvents | where RemoteIP == "{clean_ip}"'
            
            self._add_and_log_rules(state, db, base_name, sigma, splunk, kql)

    def _generate_fallbacks(self, state, db):
        # Fallback static rules if no parameters could be parsed
        sigma = """title: Generic PowerShell Obfuscation Detection
id: de8a01f2-1aef-4b47-b2e1-7cc7112c3f81
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
level: high"""
        splunk = 'index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")'
        kql = 'SecurityEvent | where EventID == 4688 and ProcessName =~ "powershell.exe" and CommandLine has_any ("-enc", "-encodedcommand")'
        
        self._add_and_log_rules(state, db, "PowerShell_Obfuscation_Fallbacks", sigma, splunk, kql)

    def _add_and_log_rules(self, state, db, base_name, sigma, splunk, kql):
        rules = [
            {"rule_name": f"{base_name}_Sigma", "type": "Sigma", "content": sigma},
            {"rule_name": f"{base_name}_Splunk", "type": "Splunk", "content": splunk},
            {"rule_name": f"{base_name}_KQL", "type": "KQL", "content": kql}
        ]
        state.detection_rules.extend(rules)
        for r in rules:
            db.insert_detection(state.case_id, r["rule_name"], r["content"], r["type"])

import re
