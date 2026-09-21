# orchestrator.py — LangGraph multi-agent DFIR pipeline

from langgraph.graph import StateGraph, END
from agents import (
    ArtifactAgent, GraphBuilderAgent, MemoryAgent, RootCauseAgent,
    ThreatHuntAgent, IOCAgent, DetectionAgent, ThreatIntelAgent,
    AttackPathAgent, RiskEngineAgent, JudgeAgent, ResponseAgent, ReportAgent
)
from state import DFIRState

def build_pipeline() -> StateGraph:
    graph = StateGraph(DFIRState)

    # Register all 13 agents as nodes
    graph.add_node("artifact",       ArtifactAgent().run)
    graph.add_node("graph_builder",  GraphBuilderAgent().run)
    graph.add_node("memory",         MemoryAgent().run)
    graph.add_node("root_cause",     RootCauseAgent().run)
    graph.add_node("threat_hunt",    ThreatHuntAgent().run)
    graph.add_node("ioc",            IOCAgent().run)
    graph.add_node("detection",      DetectionAgent().run)
    graph.add_node("intel",          ThreatIntelAgent().run)
    graph.add_node("attack_path",    AttackPathAgent().run)
    graph.add_node("risk",           RiskEngineAgent().run)
    graph.add_node("judge",          JudgeAgent().run)
    graph.add_node("response",       ResponseAgent().run)
    graph.add_node("report",         ReportAgent().run)

    # DAG Routing
    graph.set_entry_point("artifact")
    
    # Phase 1: Contextualization
    graph.add_edge("artifact", "graph_builder")
    graph.add_edge("graph_builder", "memory")
    graph.add_edge("memory", "root_cause")
    
    # Phase 2: Autonomous Engineering & Hunt
    graph.add_edge("root_cause", "threat_hunt")
    graph.add_edge("threat_hunt", "ioc")
    graph.add_edge("ioc", "intel")
    graph.add_edge("intel", "detection")
    
    # Phase 3: Probabilistic Reasoning & Attribution
    graph.add_edge("detection", "attack_path")
    graph.add_edge("attack_path", "risk")
    graph.add_edge("risk", "judge")
    
    # Phase 4: Response & Reporting
    graph.add_edge("judge", "response")
    graph.add_edge("response", "report")
    graph.add_edge("report", END)

    return graph.compile()

