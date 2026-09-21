# graph/knowledge_graph.py

import os
from neo4j import GraphDatabase

class DFIRKnowledgeGraph:
    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.environ.get("NEO4J_URL", "bolt://localhost:7687")
        self.user = user or os.environ.get("NEO4J_USER", "neo4j")
        self.password = password or os.environ.get("NEO4J_PASSWORD", "DFIRplatform1")
        self.use_in_memory = False
        self.driver = None
        self._init_driver()

    def _init_driver(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connectivity
            self.driver.verify_connectivity()
            print("[DFIRKnowledgeGraph] Connected to Neo4j database.")
        except Exception as e:
            print(f"[DFIRKnowledgeGraph] Neo4j connection failed: {e}. Falling back to In-Memory Graph.")
            self.use_in_memory = True
            # Simple In-Memory graph structure
            self.nodes = {} # node_id -> {type, props}
            self.edges = [] # list of {source, target, type, props}

    def close(self):
        if self.driver:
            self.driver.close()

    def add_node(self, node_id, node_type, props):
        if self.use_in_memory:
            self.nodes[node_id] = {"type": node_type, "props": props}
        else:
            with self.driver.session() as session:
                query = f"MERGE (n:{node_type} {{id: $node_id}}) SET n += $props"
                session.run(query, node_id=node_id, props=props)

    def add_edge(self, source_id, target_id, rel_type, props=None):
        props = props or {}
        if self.use_in_memory:
            self.edges.append({
                "source": source_id,
                "target": target_id,
                "type": rel_type,
                "props": props
            })
        else:
            with self.driver.session() as session:
                # We assume nodes exist, but MERGE handles it safely
                query = f"""
                    MATCH (s) WHERE s.id = $source_id
                    MATCH (t) WHERE t.id = $target_id
                    MERGE (s)-[r:{rel_type}]->(t)
                    SET r += $props
                """
                session.run(query, source_id=source_id, target_id=target_id, props=props)

    def ingest_event(self, event: dict):
        # Build normalized node IDs and properties
        hostname = event.get("hostname", "unknown-host")
        username = event.get("username", "system")
        process_name = event.get("process", "unknown")
        pid = event.get("pid", 0)
        timestamp = event.get("timestamp", "")
        
        proc_node_id = f"proc_{hostname}_{process_name}_{pid}"
        host_node_id = f"host_{hostname}"
        user_node_id = f"user_{username}"
        time_node_id = f"time_{timestamp}"

        self.add_node(host_node_id, "Host", {"name": hostname})
        self.add_node(user_node_id, "User", {"name": username})
        self.add_node(proc_node_id, "Process", {"name": process_name, "pid": pid, "path": event.get("path", "")})
        self.add_node(time_node_id, "Timestamp", {"time": timestamp})

        self.add_edge(host_node_id, proc_node_id, "RAN")
        self.add_edge(user_node_id, proc_node_id, "EXECUTED")
        self.add_edge(proc_node_id, time_node_id, "AT")

    def ingest_network(self, conn: dict):
        pid = conn.get("pid", 0)
        hostname = conn.get("hostname", "unknown-host")
        process_name = conn.get("process", "unknown")
        remote_ip = conn.get("remote_ip", "127.0.0.1")
        port = conn.get("port", 80)
        proto = conn.get("proto", "TCP")

        proc_node_id = f"proc_{hostname}_{process_name}_{pid}"
        ip_node_id = f"ip_{remote_ip}"

        self.add_node(proc_node_id, "Process", {"name": process_name, "pid": pid})
        self.add_node(ip_node_id, "IP", {"address": remote_ip, "malicious": conn.get("malicious", False)})
        self.add_edge(proc_node_id, ip_node_id, "CONNECTED_TO", {"port": port, "proto": proto})

    def query_attack_path(self) -> list:
        if self.use_in_memory:
            # Traversal simulation in memory
            paths = []
            # Find Processes connected to malicious IPs
            for edge in self.edges:
                if edge["type"] == "CONNECTED_TO":
                    target_id = edge["target"]
                    source_id = edge["source"]
                    target_node = self.nodes.get(target_id)
                    if target_node and target_node["props"].get("malicious"):
                        # We have a Process connected to malicious IP!
                        # Now find who executed the process
                        for parent_edge in self.edges:
                            if parent_edge["type"] == "EXECUTED" and parent_edge["target"] == source_id:
                                user_id = parent_edge["source"]
                                paths.append([user_id, "EXECUTED", source_id, "CONNECTED_TO", target_id])
            return paths
        else:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:User)-[r1:EXECUTED]->(p:Process)-[r2:CONNECTED_TO]->(ip:IP)
                    WHERE ip.malicious = true
                    RETURN u.name AS user, p.name AS process, ip.address AS ip, p.pid AS pid
                """)
                return [dict(record) for record in result]

    def query_backward_traversal(self, target_pid) -> list:
        """
        Walks backward along SPAWNED edges from target process to find the origin process.
        """
        if self.use_in_memory:
            path = []
            current_node = None
            # Find the process node with matching pid
            for node_id, node in self.nodes.items():
                if node["type"] == "Process" and node["props"].get("pid") == target_pid:
                    current_node = node_id
                    break

            while current_node:
                path.append(current_node)
                # Find its parent process
                parent = None
                for edge in self.edges:
                    if edge["type"] == "SPAWNED" and edge["target"] == current_node:
                        parent = edge["source"]
                        break
                current_node = parent
            return path
        else:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH p = (start:Process)-[:SPAWNED*0..5]->(target:Process {pid: $target_pid})
                    RETURN p
                """, target_pid=target_pid)
                records = list(result)
                if records:
                    return records[0]["p"]
                return []

    def query_lateral_movement(self) -> list:
        if self.use_in_memory:
            results = []
            for edge in self.edges:
                if edge["type"] == "AUTHENTICATED_TO":
                    # source is a Process or Host, target is a Host
                    results.append({
                        "h1": edge["source"],
                        "p": "Process",
                        "h2": edge["target"]
                    })
            return results
        else:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (h1:Host)-[:RAN]->(p:Process)-[:AUTHENTICATED_TO]->(h2:Host)
                    WHERE h1 <> h2
                    RETURN h1.name AS h1, p.name AS p, h2.name AS h2
                """)
                return [dict(record) for record in result]
