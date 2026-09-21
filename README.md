# FORENSICA — Swarm Analyst Platform for Automated DFIR

FORENSICA is a multi-agent Digital Forensics & Incident Response (DFIR) platform that automates triage of a Windows incident from raw forensic evidence to analyst-ready reports. A 13-agent [LangGraph](https://github.com/langchain-ai/langgraph) pipeline ingests artifacts (event logs, prefetch, registry, memory), reconstructs the attack chain, hunts for threats, enriches indicators, scores risk with a Bayesian model, validates every claim against evidence, and produces SOC, executive, and remediation reports — with a FastAPI service to drive it all.

> Live code lives in [`forensica/`](forensica/).

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Agent Pipeline](#agent-pipeline)
- [Tech Stack](#tech-stack)
- [Repository Layout](#repository-layout)
- [Getting Started](#getting-started)
- [Running with Docker Compose](#running-with-docker-compose)
- [API Reference](#api-reference)
- [Evidence Collection (`collector.ps1`)](#evidence-collection-collectorps1)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Configuration / Environment Variables](#configuration--environment-variables)
- [Sample Case](#sample-case)

## Overview

Given a package of forensic artifacts collected from a compromised Windows host, FORENSICA:

1. Ingests and hashes the evidence for chain-of-custody.
2. Builds a causal knowledge graph of hosts, users, processes, and network connections.
3. Traces the process tree back to "Patient Zero" (root cause).
4. Hunts for suspicious behavior (LOLBins, encoded commands, anomalous paths, entropy analysis).
5. Extracts and defangs IOCs, then enriches them against threat intel sources.
6. Auto-generates detection content (Sigma / Splunk SPL / Sentinel KQL) tailored to the case telemetry.
7. Reconstructs the attack path across MITRE ATT&CK kill-chain phases.
8. Computes a Bayesian compromise-probability risk score.
9. Runs every finding through a "Judge" evidence validator to suppress unsupported/hallucinated claims.
10. Generates containment/response playbooks and narrative SOC, executive, and remediation reports.

All state flows through a single shared `DFIRState` object as it passes between agent nodes in the graph.

## Architecture

```
Evidence ZIP/Dir
      │
      ▼
┌─────────────────────────────── Phase 1: Contextualization ───────────────────────────────┐
│  ArtifactAgent → GraphBuilderAgent → MemoryAgent → RootCauseAgent                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌───────────────────────── Phase 2: Autonomous Engineering & Hunt ─────────────────────────┐
│  ThreatHuntAgent → IOCAgent → ThreatIntelAgent → DetectionAgent                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌───────────────────── Phase 3: Probabilistic Reasoning & Attribution ─────────────────────┐
│  AttackPathAgent → RiskEngineAgent → JudgeAgent                                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌───────────────────────────── Phase 4: Response & Reporting ──────────────────────────────┐
│  ResponseAgent → ReportAgent                                                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
      │
      ▼
 SOC report · Executive brief · Remediation plan · Risk score · IOCs · Detection rules
```

The DAG is defined in [`forensica/orchestrator.py`](forensica/orchestrator.py) via `build_pipeline()`, which wires all 13 agent nodes onto a `langgraph.graph.StateGraph`.

## Agent Pipeline

| # | Agent | File | Responsibility |
|---|-------|------|-----------------|
| 1 | `ArtifactAgent` | `agents/artifact_agent.py` | Extracts/normalizes evidence (EVTX, prefetch, registry, memory) into `DFIRState`; SHA-256 hash validation for chain-of-custody. |
| 2 | `GraphBuilderAgent` | `agents/graph_builder_agent.py` | Ingests events into a Neo4j (or in-memory) knowledge graph of hosts, users, processes, and network connections. |
| 3 | `MemoryAgent` | `agents/memory_agent.py` | Semantic retrieval over a TF-IDF vector store of MITRE ATT&CK technique descriptions and prior case context. |
| 4 | `RootCauseAgent` | `agents/root_cause_agent.py` | Recursive DFS over the process tree to identify "Patient Zero". |
| 5 | `ThreatHuntAgent` | `agents/threat_hunt_agent.py` | Flags LOLBins, suspicious paths, and high-entropy/obfuscated command lines; optional LLM-assisted triage via Anthropic. |
| 6 | `IOCAgent` | `agents/ioc_agent.py` | Regex-based extraction of IPs, domains, URLs, and file hashes; defangs output. |
| 7 | `ThreatIntelAgent` | `agents/threat_intel_agent.py` | Enriches IOCs against external/internal threat intel feeds (e.g. VirusTotal, AbuseIPDB, OTX, Shodan). |
| 8 | `DetectionAgent` | `agents/detection_agent.py` | Generates Sigma / Splunk SPL / Sentinel KQL detection rules matched to the case's exact telemetry. |
| 9 | `AttackPathAgent` | `agents/attack_path_agent.py` | Reconstructs the attack chain across MITRE kill-chain phases (Initial Access → Execution → Persistence → C2). |
| 10 | `RiskEngineAgent` | `agents/risk_engine_agent.py` | Bayesian belief network estimating conditional compromise probability. |
| 11 | `JudgeAgent` | `agents/judge_agent.py` | Meta-reasoner enforcing a "4-layer truth stack" — never lets the LLM be the source of truth; suppresses unvalidated claims. |
| 12 | `ResponseAgent` | `agents/response_agent.py` | Produces machine-actionable SOAR containment playbooks (e.g. firewall blocks, isolation, remediation commands). |
| 13 | `ReportAgent` | `agents/report_agent.py` | Synthesizes validated findings into SOC, executive, and remediation Markdown reports. |

Every agent implements the `BaseAgent` interface (`agents/base.py`): a single `run(state: DFIRState) -> DFIRState` method.

## Tech Stack

- **Orchestration**: [LangGraph](https://github.com/langchain-ai/langgraph) (`StateGraph`)
- **API**: [FastAPI](https://fastapi.tiangolo.com/) + Uvicorn
- **LLM**: [Anthropic](https://docs.anthropic.com/) (Claude) for narrative synthesis and assisted triage
- **Graph store**: Neo4j (falls back to an in-memory graph if unavailable)
- **Relational store**: PostgreSQL (falls back to local SQLite if `POSTGRES_URL` is unset/unreachable)
- **Object storage**: MinIO (for evidence artifacts, via docker-compose)
- **Log storage**: OpenSearch (via docker-compose)
- **Evidence collection**: PowerShell (`collector.ps1`)

## Repository Layout

```
digitaltwin/
└── forensica/
    ├── agents/                     # All 13 pipeline agents + BaseAgent
    ├── graph/
    │   └── knowledge_graph.py      # Neo4j / in-memory DFIRKnowledgeGraph wrapper
    ├── simulated_evidence/         # Sample evidence fixtures used by tests
    ├── main.py                     # FastAPI application (entry point)
    ├── orchestrator.py             # LangGraph pipeline definition
    ├── state.py                    # Shared DFIRState dataclass
    ├── db_helper.py                # Postgres/SQLite helper + SimpleVectorStore (TF-IDF)
    ├── schema.sql                  # PostgreSQL schema (cases, events, findings, iocs, detections, reports)
    ├── collector.ps1               # Windows-side forensic evidence collector
    ├── test_platform.py            # End-to-end integration test with simulated evidence
    ├── Dockerfile
    ├── docker-compose.yml          # opensearch, neo4j, postgres, minio, platform
    ├── requirements.txt
    └── CASE-*_soc_report.md / _executive_brief.md / _remediation_plan.md   # Sample generated reports
```

## Getting Started

### Prerequisites

- Python 3.11+
- (Optional, for full functionality) PostgreSQL, Neo4j
- An `ANTHROPIC_API_KEY` for LLM-assisted triage and report narration

### Local install

```bash
cd forensica
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...
# Optional — omit to fall back to SQLite / in-memory graph automatically
export POSTGRES_URL=postgresql://dfir:password@localhost:5432/dfir
export NEO4J_URL=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your-password

python main.py
# API now serving on http://localhost:8080
```

If `POSTGRES_URL` or the Neo4j connection is not reachable, `db_helper.DatabaseHelper` and `graph.knowledge_graph.DFIRKnowledgeGraph` transparently fall back to SQLite (`forensica.db`) and an in-memory graph, respectively — useful for local development and the test suite.

## Running with Docker Compose

`docker-compose.yml` stands up the full stack — OpenSearch, Neo4j, PostgreSQL, MinIO, and the FastAPI platform:

```bash
cd forensica
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up --build
```

Services:

| Service | Ports | Purpose |
|---|---|---|
| `opensearch` | 9200 | Log/event storage |
| `neo4j` | 7474 (browser), 7687 (bolt) | Knowledge graph |
| `postgres` | 5432 | Cases, findings, IOCs, detections, reports |
| `minio` | 9000 (API), 9001 (console) | Evidence artifact storage |
| `platform` | 8080 | FastAPI application |

Mount your evidence directory into the `platform` container's `/evidence` volume (see `volumes: ./evidence:/evidence` in `docker-compose.yml`) so `evidence_zip` paths in API requests resolve correctly.

## API Reference

Base URL: `http://localhost:8080`

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/investigate` | Kick off a background swarm analysis run for a given evidence path. |
| `GET` | `/api/case/{case_id}/status` | Poll pipeline status and current risk score. |
| `GET` | `/api/case/{case_id}/report/{report_type}` | Fetch a generated report (`soc`, `executive`, or `remediation`). |
| `GET` | `/api/case/{case_id}/iocs` | List extracted/enriched IOCs for a case. |
| `GET` | `/api/case/{case_id}/findings` | List validated findings for a case. |

### Example: start an investigation

```bash
curl -X POST http://localhost:8080/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"evidence_zip": "/evidence/HOST01_evidence.zip", "case_id": "CASE-2026-001"}'
```

Response:

```json
{
  "status": "triggered",
  "case_id": "CASE-2026-001",
  "message": "Swarm analysis started in background for case: CASE-2026-001"
}
```

### Example: check status

```bash
curl http://localhost:8080/api/case/CASE-2026-001/status
```

```json
{
  "case_id": "CASE-2026-001",
  "pipeline_status": "COMPLETED",
  "risk_score": 96,
  "completed": true
}
```

## Evidence Collection (`collector.ps1`)

`forensica/collector.ps1` is a Windows-side triage collector intended for use by an incident responder on a host they are **authorized to investigate**. Run it from an elevated PowerShell console on the target host:

```powershell
.\collector.ps1
```

It:

1. Verifies it is running elevated (exits otherwise).
2. Stages output under `C:\ProgramData\KAPE_CSIR` in folders for FileSystem, Memory, Additional, LiveResponse, Network, and Timeline artifacts.
3. Records case metadata (hostname, OS, user, timestamp, IP) to `case_meta.json`.
4. Collects live-response triage data: running processes, TCP connections, DNS cache, scheduled tasks, PowerShell command history, and Windows Defender detection logs.
5. Generates a SHA-256 integrity manifest (`artifact_manifest.csv`) for chain-of-custody.
6. Packages everything into `<hostname>_evidence.zip` on the current user's Desktop.
7. Securely wipes (3-pass overwrite) the intermediate staging files and directory, leaving only the final evidence archive — so sensitive collected data isn't left behind in plaintext on the host after handoff.

The resulting ZIP is the input to `POST /api/investigate`.

## Database Schema

Defined in `forensica/schema.sql` (PostgreSQL; an equivalent SQLite schema is created automatically by `db_helper.py` when Postgres is unavailable):

- **`cases`** — case id, evidence path, risk score, creation time.
- **`events`** — normalized timeline events per case.
- **`findings`** — validated claims with confidence, supporting artifacts, and source agent.
- **`iocs`** — indicators of compromise with type, source agent, confidence, and enrichment data.
- **`detections`** — generated detection rules (Sigma / Splunk SPL / KQL) per case.
- **`reports`** — generated SOC / executive / remediation report content per case.

## Testing

An end-to-end integration test (`test_platform.py`) generates a simulated Cobalt Strike-style intrusion (phishing → PowerShell download cradle → C2 beacon → scheduled-task persistence), runs the full pipeline against it, and asserts on the database and final state:

```bash
cd forensica
python test_platform.py
```

The test asserts that events, findings, and IOCs are persisted; the Bayesian risk score reaches the expected threshold; containment playbooks are generated; and all three narrative reports are non-empty. It cleans up its simulated evidence and any local SQLite database on completion.

`simulated_evidence/` in the repo contains a checked-in copy of this fixture data (`case_meta.json`, `evtx_events.json`, `prefetch_records.json`, `registry_keys.json`, `memory_findings.json`, `artifact_manifest.csv`) for reference.

## Configuration / Environment Variables

| Variable | Used by | Default / Fallback |
|---|---|---|
| `ANTHROPIC_API_KEY` | `ThreatHuntAgent`, `DetectionAgent`, `ReportAgent` | Required for LLM-assisted triage/narration |
| `POSTGRES_URL` | `db_helper.DatabaseHelper` | Falls back to local SQLite (`forensica.db`) |
| `NEO4J_URL` | `graph.knowledge_graph.DFIRKnowledgeGraph` | `bolt://localhost:7687`; falls back to in-memory graph |
| `NEO4J_USER` | same | `neo4j` |
| `NEO4J_PASSWORD` | same | `DFIRplatform1` |
| `OPENSEARCH_URL`, `MINIO_URL` | reserved for log/artifact storage integrations | set by `docker-compose.yml` |

## Sample Case

The repository includes generated report samples from two example runs (`CASE-TEST-001` and `CASE-RUN-002`):

- `forensica/CASE-*_soc_report.md` — technical SOC analyst report.
- `forensica/CASE-*_executive_brief.md` — plain-language executive summary.
- `forensica/CASE-*_remediation_plan.md` — prioritized containment/remediation action plan.

These illustrate the kind of output the `ReportAgent` produces at the end of a pipeline run.
