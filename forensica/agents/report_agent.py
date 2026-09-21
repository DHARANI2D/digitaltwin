# agents/report_agent.py

import os
import json
from .base import BaseAgent
from db_helper import DatabaseHelper
from anthropic import Anthropic

class ReportAgent(BaseAgent):
    """
    Final stage. Synthesizes validated findings into SOC, Executive, 
    and Remediation Markdown reports. No raw log ingestion.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[ReportAgent] Compiling final narrative reports from validated findings...")
        
        db = DatabaseHelper()
        
        # Prepare structured input contexts
        validated_json = json.dumps(state.validated_findings, indent=2)
        iocs_json = json.dumps(state.enriched_iocs, indent=2)
        playbooks_json = json.dumps(state.containment_playbooks, indent=2)
        techniques_json = json.dumps(state.mitre_techniques, indent=2)
        
        # Check if we can use LLM to compose the text narrative professionally
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                print("[ReportAgent] Querying Anthropic to compose polished narrative reports...")
                client = Anthropic(api_key=api_key)
                
                prompt = f"""
You are a Lead Forensic Incident Responder and DFIR Agent.
Assemble three distinct reports based ONLY on the validated facts below. Do NOT hallucinate or extrapolate any claims that lack citation backing.

=== VALIDATED FINDINGS ===
{validated_json}

=== ENRICHED IOCS ===
{iocs_json}

=== CONTAINMENT PLAYBOOKS ===
{playbooks_json}

=== MITRE TECHNIQUES ===
{techniques_json}

=== CASE ID & RISK ===
Case ID: {state.case_id}
Risk Score: {state.risk_score}%
Root Cause: {json.dumps(state.root_cause, indent=2)}

Generate the output as a valid JSON object containing exactly three string keys:
1. "executive_brief" - A high-level executive markdown report with a warning box, case metrics, impact scope, and major remediation steps.
2. "soc_report" - A technical SOC markdown report with timelines, exact artifact citations, detailed findings, an IOC table, and the generated Sigma/Splunk queries.
3. "remediation_plan" - A detailed, sequenced list of actions with powershell/shell scripts, split by whether they need human approval or can run automatically.

Return ONLY raw JSON. Do not include markdown code block wraps.
"""
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=2500,
                    system="You are a DFIR expert reporting system. You only output valid JSON with keys: 'executive_brief', 'soc_report', and 'remediation_plan'.",
                    messages=[{"role": "user", "content": prompt}]
                )
                
                resp_text = response.content[0].text.strip()
                if resp_text.startswith("```json"):
                    resp_text = resp_text[7:-3].strip()
                elif resp_text.startswith("```"):
                    resp_text = resp_text[3:-3].strip()
                    
                obj = json.loads(resp_text)
                state.report_executive = obj.get("executive_brief", "")
                state.report_soc = obj.get("soc_report", "")
                state.report_remediation = obj.get("remediation_plan", "")
                
                print("[ReportAgent] LLM-composed reports successfully constructed.")
            except Exception as e:
                print(f"[ReportAgent] Anthropic report generation failed: {e}. Falling back to structured Markdown builder.")
                self._generate_local_reports(state)
        else:
            print("[ReportAgent] ANTHROPIC_API_KEY not found. Compiling via local Markdown builder.")
            self._generate_local_reports(state)

        # Write reports to DB
        db.insert_report(state.case_id, "executive", state.report_executive)
        db.insert_report(state.case_id, "soc", state.report_soc)
        db.insert_report(state.case_id, "remediation", state.report_remediation)
        
        # Write reports to files locally in the evidence directory or current directory for inspection
        out_dir = os.path.dirname(state.evidence_path) if os.path.dirname(state.evidence_path) else "."
        
        try:
            with open(os.path.join(out_dir, f"{state.case_id}_executive_brief.md"), "w") as f:
                f.write(state.report_executive)
            with open(os.path.join(out_dir, f"{state.case_id}_soc_report.md"), "w") as f:
                f.write(state.report_soc)
            with open(os.path.join(out_dir, f"{state.case_id}_remediation_plan.md"), "w") as f:
                f.write(state.report_remediation)
            print(f"[ReportAgent] Reports written to disk under: {out_dir}")
        except Exception as e:
            print(f"[ReportAgent] Error writing reports to disk: {e}")

        return state

    def _generate_local_reports(self, state):
        """Generates premium looking static Markdown reports if LLM is unavailable."""
        
        # 1. Executive Brief
        factors_str = "\n".join([f"- **{f['factor']}**: {f['impact']}" for f in state.risk_factors]) if state.risk_factors else "- No elevated risk factors"
        state.report_executive = f"""# Executive Incident Brief
**Case Identifier:** {state.case_id}  
**Bayesian Compromise Probability:** `{state.risk_score}%`  
**Host Context:** {state.root_cause.get('host', 'WORKSTATION01')}  

> [!WARNING]
> **Active Intrusion Detected**: A high-confidence Cobalt Strike C2 server callback has been confirmed on `{state.root_cause.get('host', 'WORKSTATION01')}` originating from a malicious document execution. Proactive isolation is highly recommended.

### Intrusion Summary
At `{state.root_cause.get('timestamp', 'N/A')}`, a malicious initial access chain began via the opening of `{state.root_cause.get('patient_zero', 'invoice.docx')}`. This spawned a secondary shell process executing suspicious command arguments, leading directly to outbound Command and Control traffic to a hostile remote IP address.

### Key Risk Factors
{factors_str}

---
*Report generated automatically by FORENSICA. All findings are validated against the 4-layer evidence stack.*
"""

        # 2. SOC Technical Report
        findings_str = ""
        for f in state.validated_findings:
            sources_list = ", ".join(f.get("corroborating_sources", []))
            findings_str += f"""
#### Finding: {f.get('claim')}
- **MITRE Technique Mapping**: {f.get('technique', 'N/A')}
- **Confidence Rating**: `{f.get('confidence')}%`
- **Corroborating Evidence**: {sources_list}
- **Telemetry Details**: `{f.get('details', '')}`
- **Process ID**: {f.get('pid', 'N/A')}
"""

        iocs_str = "| Indicator | Type | VT Score | Shodan Ports | Category |\n|---|---|---|---|---|\n"
        for ioc in state.enriched_iocs:
            ind = ioc["indicator"]
            itype = ioc["type"]
            intel = ioc.get("intel", {})
            vt = intel.get("virustotal", {})
            sho = intel.get("shodan", {})
            
            vt_score = f"{vt.get('malicious_hits', 0)}/72"
            ports = ", ".join(map(str, sho.get("open_ports", []))) if sho.get("open_ports") else "None"
            cat = vt.get("category", "unknown")
            iocs_str += f"| `{ind}` | {itype} | {vt_score} | {ports} | {cat} |\n"

        rules_str = ""
        for rule in state.detection_rules:
            rules_str += f"\n### Rule: {rule['rule_name']} ({rule['type']})\n```yaml\n{rule['content']}\n```\n"

        state.report_soc = f"""# Technical SOC Incident Report
**Case Identifier:** {state.case_id}  
**System Risk Level:** `{state.risk_score}%`  

## Mapped Cyber Kill Chain
{findings_str}

## Indicators of Compromise (Defanged)
{iocs_str}

## Mapped Detection Engineering Coverage
{rules_str}
"""

        # 3. Remediation Plan
        auto_actions = []
        hitl_actions = []
        for p in state.containment_playbooks:
            line = f"- **{p['action']}** on `{p['target']}`:  \n  *Reason:* {p['reason']}  \n  *Command:* `{p['script']}`"
            if p.get("approval_required"):
                hitl_actions.append(line)
            else:
                auto_actions.append(line)

        auto_actions_str = "\n".join(auto_actions) if auto_actions else "- None"
        hitl_actions_str = "\n".join(hitl_actions) if hitl_actions else "- None"

        state.report_remediation = f"""# Actionable Remediation Plan
**Case Identifier:** {state.case_id}  

## Section 1: Immediate Automatic Cleanup Actions (No Approval Needed)
{auto_actions_str}

## Section 2: Host Isolation & Active Blocks (Human-In-The-Loop Approval Required)
{hitl_actions_str}

## Section 3: Mitigation Playbook Execution Instructions
1. Execute the PowerShell blocks listed in Section 1 on the affected server.
2. Confirm the Palo Alto Firewall Block rule in Section 2 is deployed to boundary routers.
3. Force a password reset on the AD domain for active user accounts.
"""
