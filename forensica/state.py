# state.py — the shared investigation state passed between agents

from dataclasses import dataclass, field
from typing import Any

@dataclass
class DFIRState:
    # Metadata
    case_id: str = ""
    evidence_path: str = ""

    # Phase 1: Contextualization (Ingestion & Graph)
    evtx_events: list[dict]      = field(default_factory=list)
    prefetch_records: list[dict] = field(default_factory=list)
    registry_keys: list[dict]    = field(default_factory=list)
    mft_records: list[dict]      = field(default_factory=list)
    memory_findings: list[dict]  = field(default_factory=list)
    timeline: list[dict]         = field(default_factory=list)
    graph_paths: list[dict]      = field(default_factory=list)
    root_cause: dict             = field(default_factory=dict)

    # Phase 2: Autonomous Engineering & Hunt
    detections: list[dict]       = field(default_factory=list)
    mitre_techniques: list[dict] = field(default_factory=list)
    detection_rules: list[dict]  = field(default_factory=list) # Sigma/Splunk
    iocs: list[dict]             = field(default_factory=list)

    # Phase 3: Probabilistic Reasoning & Attribution
    enriched_iocs: list[dict]    = field(default_factory=list)
    attack_graph: dict           = field(default_factory=dict)
    risk_factors: list[dict]     = field(default_factory=list)
    hypotheses: list[dict]       = field(default_factory=list)
    validated_findings: list[dict]= field(default_factory=list)
    risk_score: int = 0

    # Phase 4: Response & Reporting
    containment_playbooks: list[dict] = field(default_factory=list)
    report_soc: str = ""
    report_executive: str = ""
    report_remediation: str = ""
