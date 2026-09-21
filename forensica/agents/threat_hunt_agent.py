# agents/threat_hunt_agent.py

import os
import re
import json
import math
from .base import BaseAgent
from anthropic import Anthropic
from db_helper import DatabaseHelper

LOLBINS = [
    "powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msiexec.exe", "forfiles.exe",
    "schtasks.exe", "at.exe", "eventvwr.exe", "cmstp.exe"
]

SUSPICIOUS_PATHS = [
    r"\\temp\\", r"\\appdata\\", r"\\users\\public\\", r"\\windows\\temp\\", r"\\downloads\\"
]

def calculate_entropy(text):
    """Computes Shannon Entropy to detect base64/obfuscated strings."""
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy

class ThreatHuntAgent(BaseAgent):
    """
    Identifies living-off-the-land behavior using mathematical entropy checks,
    rule-based heuristics, and LLM-based anomaly reasoning on process creations.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[ThreatHuntAgent] Running advanced Shannon entropy and LOLBin heuristics...")
        
        db = DatabaseHelper()
        detected_items = []

        # 1. Advanced Heuristic Detection
        for e in state.evtx_events:
            proc_path = e.get("NewProcessName", e.get("process", "")).lower()
            cmd_line = e.get("CommandLine", "")
            cmd_line_lower = cmd_line.lower()
            parent_proc = e.get("ParentProcessName", "").lower()
            pid = e.get("pid", e.get("NewProcessId", 0))

            # A. Parent-Child Execution Anomalies
            if parent_proc:
                # Web server spawning shell
                if any(ws in parent_proc for ws in ["w3wp.exe", "tomcat", "httpd", "nginx"]):
                    if any(sh in proc_path for sh in ["cmd.exe", "powershell.exe", "bash", "sh"]):
                        finding = {
                            "finding": "Web Server Spawned Command Shell (Potential Webshell Execution)",
                            "severity": "critical",
                            "pid": pid,
                            "technique": "T1505.003",
                            "details": f"Web Server parent: {parent_proc} spawned: {proc_path}. CommandLine: {cmd_line}"
                        }
                        detected_items.append(finding)
                
                # Office document spawning shell
                if any(office in parent_proc for office in ["winword.exe", "excel.exe", "powerpnt.exe"]):
                    if any(sh in proc_path for sh in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]):
                        finding = {
                            "finding": "Office Application Spawned Shell Process (Potential Phishing Execution)",
                            "severity": "critical",
                            "pid": pid,
                            "technique": "T1566.001",
                            "details": f"Parent: {parent_proc} spawned: {proc_path}. CommandLine: {cmd_line}"
                        }
                        detected_items.append(finding)

            # B. Directory Execution Anomalies
            if any(re.search(path_regex.replace("\\", "\\\\"), proc_path) for path_regex in SUSPICIOUS_PATHS):
                # Script run from temp / public folders
                finding = {
                    "finding": "Process execution initiated from suspicious directory",
                    "severity": "high",
                    "pid": pid,
                    "technique": "T1036",
                    "details": f"Process running from writable path: {proc_path}. CommandLine: {cmd_line}"
                }
                detected_items.append(finding)

            # C. Entropy & Obfuscation Checks
            # Find base64 blocks or highly random arguments
            # Look for args with length > 40 and check entropy
            args = cmd_line.split()
            for arg in args:
                if len(arg) > 40 and not arg.startswith("http"):
                    ent = calculate_entropy(arg)
                    # Base64 strings are characterized by high character diversity / entropy >= 4.5
                    if ent >= 4.5:
                        finding = {
                            "finding": "High-entropy command-line argument (Potential obfuscation/base64 payload)",
                            "severity": "high",
                            "pid": pid,
                            "technique": "T1027",
                            "details": f"Entropy score: {ent:.2f}. Argument: '{arg[:40]}...'. Full command: {cmd_line}"
                        }
                        detected_items.append(finding)
                        break

            # D. Download Cradle and Evasion Checks
            if any(cradle in cmd_line_lower for cradle in ["downloadstring", "downloadfile", "invoke-webrequest", "iex", "downloadstring", "http"]):
                if "powershell" in proc_path:
                    finding = {
                        "finding": "PowerShell Web Download Cradle execution detected",
                        "severity": "critical",
                        "pid": pid,
                        "technique": "T1059.001",
                        "details": f"Powershell cradle arguments seen: {cmd_line}"
                    }
                    detected_items.append(finding)

        # 2. LLM anomaly review if API Key is present
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                print("[ThreatHuntAgent] Querying Anthropic Claude for advanced log anomaly reasoning...")
                client = Anthropic(api_key=api_key)
                
                context = json.dumps(state.evtx_events[:30], indent=2)
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=1000,
                    system="""You are a senior DFIR analyst.
Scan the process logs below and output a JSON array of anomalies. Look for process masquerading, hollowing, webshells, or evasion.
Return JSON ONLY matching this schema: {"detections": [{"finding": "...", "severity": "critical|high|medium", "pid": ..., "technique": "T...."}]}""",
                    messages=[{"role": "user", "content": context}]
                )
                
                resp_text = response.content[0].text.strip()
                if resp_text.startswith("```json"):
                    resp_text = resp_text[7:-3].strip()
                elif resp_text.startswith("```"):
                    resp_text = resp_text[3:-3].strip()
                
                llm_findings = json.loads(resp_text)
                detected_items.extend(llm_findings.get("detections", []))
                print(f"[ThreatHuntAgent] Claude added {len(llm_findings.get('detections', []))} validated findings.")
            except Exception as e:
                print(f"[ThreatHuntAgent] Claude API request failed: {e}. Defaulting to pure heuristics.")
        else:
            print("[ThreatHuntAgent] ANTHROPIC_API_KEY not found. Operating on local heuristics engine.")

        # Save findings to state and database
        state.detections.extend(detected_items)
        for item in detected_items:
            confidence = 95 if item["severity"] == "critical" else (80 if item["severity"] == "high" else 60)
            db.insert_finding(
                state.case_id,
                item["finding"],
                confidence,
                item,
                "ThreatHuntAgent",
                is_validated=True
            )

        print(f"[ThreatHuntAgent] Heuristics engine completed. Total anomalous activities flagged: {len(state.detections)}")
        return state
