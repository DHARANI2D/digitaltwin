# agents/memory_agent.py

from .base import BaseAgent
from db_helper import SimpleVectorStore

class MemoryAgent(BaseAgent):
    """
    Interfaces with a vector store for semantic retrieval
    of past incidents and MITRE techniques.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[MemoryAgent] Initializing vector store for historical context and MITRE mapping...")
        
        vstore = SimpleVectorStore()
        
        # Pre-populate Vector Store with MITRE ATT&CK technique descriptions
        vstore.add_document(
            "T1059.001 - PowerShell. Attackers leverage PowerShell commands to run download cradles (DownloadString, IEX) or execute base64-encoded strings.",
            {"technique_id": "T1059.001", "name": "PowerShell"}
        )
        vstore.add_document(
            "T1566.001 - Phishing Spearphishing Attachment. Malicious Office documents (e.g., invoice.docx) spawning CMD/PowerShell to launch malware.",
            {"technique_id": "T1566.001", "name": "Spearphishing Attachment"}
        )
        vstore.add_document(
            "T1071.001 - Web Protocols. Command and Control (C2) agents communicate over standard port 80/443 (HTTP/HTTPS) or port 50050 using beaconing profiles.",
            {"technique_id": "T1071.001", "name": "Web Protocols C2"}
        )
        vstore.add_document(
            "T1053.005 - Scheduled Task. Attackers create tasks under schtasks or XML registration to gain persistence across reboots.",
            {"technique_id": "T1053.005", "name": "Scheduled Task Persistence"}
        )
        vstore.add_document(
            "T1003.001 - LSASS Memory. Attackers dump LSASS credentials using tools like Mimikatz or Task Manager (comsvcs.dll) to obtain NTLM hashes.",
            {"technique_id": "T1003.001", "name": "LSASS Dumping"}
        )

        # Build search queries based on event findings
        # Search techniques matching observed processes
        processes_seen = set()
        for e in state.evtx_events:
            proc = e.get("process", "").lower()
            if proc:
                processes_seen.add(proc)

        print(f"[MemoryAgent] Querying MITRE mappings for processes: {list(processes_seen)}")
        for p in processes_seen:
            hits = vstore.search(p, limit=1)
            for hit in hits:
                state.mitre_techniques.append({
                    "technique_id": hit["metadata"]["technique_id"],
                    "name": hit["metadata"]["name"],
                    "reason": f"Observed process '{p}' matches semantic description: '{hit['text'][:60]}...'"
                })

        # Mock query of previous cases
        vstore.add_document(
            "CASE-2025-001: Cobalt Strike payload loaded via Word macro. Process chain: winword.exe -> powershell.exe -> C2 connection to port 443.",
            {"case_id": "CASE-2025-001", "type": "historical"}
        )
        
        # Query similar cases based on observed state processes
        query = " ".join(list(processes_seen))
        if query:
            hist_hits = vstore.search(query, limit=1)
            for hit in hist_hits:
                if hit["metadata"].get("type") == "historical":
                    state.memory_findings.append({
                        "similar_case": hit["metadata"]["case_id"],
                        "relevance": 0.85,
                        "description": hit["text"]
                    })

        print(f"[MemoryAgent] Map search complete. Identified {len(state.mitre_techniques)} MITRE techniques and {len(state.memory_findings)} historical case matches.")
        return state
