# agents/graph_builder_agent.py

from .base import BaseAgent
from graph.knowledge_graph import DFIRKnowledgeGraph

class GraphBuilderAgent(BaseAgent):
    """
    Interfaces with Neo4j to map entities and causal relationships.
    Uses the DFIRKnowledgeGraph to ingest events.
    """
    def run(self, state: "DFIRState") -> "DFIRState":
        print("[GraphBuilderAgent] Building causal graph from ingested artifacts...")
        
        graph = DFIRKnowledgeGraph()
        
        # 1. Ingest EVTX Events
        for event in state.evtx_events:
            graph.ingest_event(event)
            
            # Map process spawns
            if event.get("event_type") == "Process" or event.get("event_id") == 4688:
                parent_process = event.get("ParentProcessName", "")
                parent_pid = event.get("ParentProcessId", 0)
                child_process = event.get("NewProcessName", event.get("process", ""))
                child_pid = event.get("NewProcessId", event.get("pid", 0))
                hostname = event.get("hostname", "unknown-host")
                timestamp = event.get("timestamp", "")
                
                if parent_process and child_process:
                    parent_node_id = f"proc_{hostname}_{os_basename(parent_process)}_{parent_pid}"
                    child_node_id = f"proc_{hostname}_{os_basename(child_process)}_{child_pid}"
                    
                    # Ensure nodes exist
                    graph.add_node(parent_node_id, "Process", {"name": os_basename(parent_process), "pid": parent_pid})
                    graph.add_node(child_node_id, "Process", {"name": os_basename(child_process), "pid": child_pid})
                    
                    # Add spawn edge
                    graph.add_edge(parent_node_id, child_node_id, "SPAWNED", {"timestamp": timestamp})

        # 2. Ingest Memory/Volatility Network scans
        for finding in state.memory_findings:
            if "remote_ip" in finding:
                graph.ingest_network(finding)
            elif finding.get("plugin") == "windows.netscan":
                graph.ingest_network(finding)

        # 3. Retrieve and record query paths
        paths = graph.query_attack_path()
        for p in paths:
            state.graph_paths.append(p)
            
        print(f"[GraphBuilderAgent] Graph construction complete. Ingested {len(state.graph_paths)} attack path patterns.")
        
        # Keep client connection open/closed cleanly
        graph.close()
        return state

def os_basename(path_str):
    """Simple utility to get file basename from Win/Unix paths."""
    if not path_str:
        return ""
    # Handle Windows backslashes and Unix slashes
    replaced = path_str.replace("\\", "/")
    return replaced.split("/")[-1]
