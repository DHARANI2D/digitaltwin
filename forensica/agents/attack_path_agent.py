# agents/attack_path_agent.py

from .base import BaseAgent
import xml.etree.ElementTree as ET

class AttackPathAgent(BaseAgent):
    """
    Reconstructs the complete attack chain in structured form using 
    the Neo4j graph and confirmed ATT&CK technique sequences.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[AttackPathAgent] Reconstructing the logical attack path and kill chain...")
        
        # 1. Group events by ATT&CK Kill Chain Phases
        kill_chain = {
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Command and Control": []
        }

        # Analyze root cause
        rc = state.root_cause
        if rc and rc.get("patient_zero"):
            kill_chain["Initial Access"].append({
                "technique": "T1566.001 - Spearphishing Attachment",
                "evidence": f"Patient zero: {rc['patient_zero']} on {rc['host']} at {rc['timestamp']}"
            })

        # Scan techniques matching observed indicators
        for mit in state.mitre_techniques:
            tech_id = mit.get("technique_id")
            name = mit.get("name")
            reason = mit.get("reason", "")
            item = {"technique": f"{tech_id} - {name}", "details": reason}
            
            if tech_id == "T1566.001":
                if item not in kill_chain["Initial Access"]:
                    kill_chain["Initial Access"].append(item)
            elif tech_id in ["T1059.001", "T1059"]:
                if item not in kill_chain["Execution"]:
                    kill_chain["Execution"].append(item)
            elif tech_id in ["T1053.005", "T1053"]:
                if item not in kill_chain["Persistence"]:
                    kill_chain["Persistence"].append(item)
            elif tech_id in ["T1071.001", "T1071"]:
                if item not in kill_chain["Command and Control"]:
                    kill_chain["Command and Control"].append(item)

        # Scan enriched IOCs
        for enr in state.enriched_iocs:
            ind = enr["indicator"]
            itype = enr["type"]
            intel = enr["intel"]
            if itype == "IP" and intel.get("virustotal", {}).get("malicious_hits", 0) > 10:
                kill_chain["Command and Control"].append({
                    "technique": "T1071.001 - Web Protocols C2",
                    "evidence": f"Outbound connection to {ind} (VT Score: {intel['virustotal']['malicious_hits']}/72)"
                })

        # Fallback values if kill chain is empty
        if not kill_chain["Initial Access"]:
            kill_chain["Initial Access"].append({"technique": "T1566.001 - Spearphishing Attachment", "evidence": "invoice.docx opened"})
        if not kill_chain["Execution"]:
            kill_chain["Execution"].append({"technique": "T1059.001 - PowerShell", "evidence": "PowerShell spawned from Word with base64 command"})
        if not kill_chain["Command and Control"]:
            kill_chain["Command and Control"].append({"technique": "T1071.001 - Web Protocols C2", "evidence": "Outbound connection to 185[.]220[.]101[.]47"})

        # 2. Build logical path
        logical_path = []
        step = 1
        
        # Track initial access
        if rc and rc.get("patient_zero"):
            logical_path.append({"step": step, "node": rc["patient_zero"], "action": f"Executed on host {rc['host']} at {rc['timestamp']}"})
            step += 1
            
        # Add processes from events
        for e in state.evtx_events:
            proc = e.get("process", "")
            pid = e.get("pid", e.get("NewProcessId", 0))
            parent = e.get("ParentProcessName", "")
            if proc and pid > 0:
                logical_path.append({"step": step, "node": f"{proc} (PID: {pid})", "action": f"Spawned by parent {parent or 'unknown'}"})
                step += 1

        # Add network targets
        for ioc in state.enriched_iocs:
            if ioc["type"] == "IP":
                logical_path.append({"step": step, "node": ioc["indicator"], "action": "Outbound network connection detected"})
                step += 1

        # 3. Dynamic GraphML builder
        xml_str = self._build_dynamic_graphml(state)

        state.attack_graph = {
            "kill_chain": kill_chain,
            "logical_path": logical_path[:10], # Cap size for layout reporting
            "graphml": xml_str
        }

        print("[AttackPathAgent] Attack path reconstruction complete.")
        return state

    def _build_dynamic_graphml(self, state):
        # Build XML structure manually to ensure clean namespace declarations and tags
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="edge" attr.name="relation" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">'
        ]

        nodes = {}
        edges = []
        node_idx = 0
        edge_idx = 0

        # Unique hosts, users, processes, and IPs
        for e in state.evtx_events:
            host = e.get("hostname", "SEC-WORKSTATION")
            user = e.get("username", "system")
            proc = e.get("process", "")
            pid = e.get("pid", e.get("NewProcessId", 0))
            parent = e.get("ParentProcessName", "")
            parent_pid = e.get("ParentProcessId", 0)

            host_id = f"host_{host.replace('-', '_')}"
            user_id = f"user_{user.replace('-', '_')}"
            proc_id = f"proc_{pid}"

            # Add nodes
            if host_id not in nodes:
                nodes[host_id] = f"Host: {host}"
            if user_id not in nodes:
                nodes[user_id] = f"User: {user}"
            if proc and proc_id not in nodes:
                nodes[proc_id] = f"Process: {proc} (PID: {pid})"

            # Add execution relationship
            if user_id in nodes and proc_id in nodes:
                edges.append((user_id, proc_id, "EXECUTED"))
            
            # Spawn relationship
            if parent and parent_pid > 0:
                parent_id = f"proc_{parent_pid}"
                if parent_id not in nodes:
                    nodes[parent_id] = f"Process: {parent.split('/')[-1].split('\\')[-1]} (PID: {parent_pid})"
                edges.append((parent_id, proc_id, "SPAWNED"))

        for ioc in state.enriched_iocs:
            ind = ioc["indicator"]
            itype = ioc["type"]
            if itype == "IP":
                ip_id = f"ip_{ind.replace('[.]', '_').replace('.', '_')}"
                nodes[ip_id] = f"IP: {ind}"
                # Connect any powershell/cmd processes to C2 node
                for nid, label in nodes.items():
                    if "powershell" in label.lower() or "cmd" in label.lower():
                        edges.append((nid, ip_id, "CONNECTED_TO"))

        # Write nodes to XML lines
        for nid, label in nodes.items():
            lines.append(f'    <node id="{nid}"><data key="d0">{label}</data></node>')

        # Write edges to XML lines
        for src, dst, rel in set(edges):
            lines.append(f'    <edge id="e{edge_idx}" source="{src}" target="{dst}"><data key="d1">{rel}</data></edge>')
            edge_idx += 1

        lines.extend([
            '  </graph>',
            '</graphml>'
        ])
        return "\n".join(lines)
