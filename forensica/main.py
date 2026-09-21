# main.py
# FastAPI Entry Point for FORENSICA

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import os
import uuid
from orchestrator import build_pipeline
from state import DFIRState
from db_helper import DatabaseHelper

app = FastAPI(
    title="FORENSICA Swarm Analyst Platform",
    description="Multi-agent swarm platform for automated DFIR triage and verification.",
    version="2.0.0"
)

db = DatabaseHelper()

# In-memory session tracking for active analysis tasks
active_tasks = {}

class InvestigateRequest(BaseModel):
    evidence_zip: str
    case_id: str = None

def run_investigation_graph(case_id: str, evidence_path: str):
    try:
        print(f"[main] Starting LangGraph swarm graph execution for case {case_id}...")
        active_tasks[case_id] = "RUNNING"
        
        # Compile LangGraph
        pipeline = build_pipeline()
        
        # Initialize Shared State
        initial_state = DFIRState(
            case_id=case_id,
            evidence_path=evidence_path
        )
        
        # Execute the pipeline
        final_state = pipeline.invoke(initial_state)
        
        active_tasks[case_id] = "COMPLETED"
        print(f"[main] LangGraph pipeline completed successfully for case {case_id}.")
    except Exception as e:
        active_tasks[case_id] = f"FAILED: {str(e)}"
        print(f"[main] Pipeline error for case {case_id}: {e}")

@app.post("/api/investigate")
def investigate(req: InvestigateRequest, background_tasks: BackgroundTasks):
    # Ensure evidence file/dir exists
    if not os.path.exists(req.evidence_zip):
        raise HTTPException(status_code=400, detail=f"Evidence path '{req.evidence_zip}' does not exist.")
        
    case_id = req.case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}"
    active_tasks[case_id] = "PENDING"
    
    # Run in background to avoid client timeout
    background_tasks.add_task(run_investigation_graph, case_id, req.evidence_zip)
    
    return {
        "status": "triggered",
        "case_id": case_id,
        "message": f"Swarm analysis started in background for case: {case_id}"
    }

@app.get("/api/case/{case_id}/status")
def get_case_status(case_id: str):
    # Fetch status from task tracker and DB
    state_status = active_tasks.get(case_id, "UNKNOWN")
    
    # Fetch risk score if case created
    cursor = db.execute_query("SELECT risk_score FROM cases WHERE case_id = %s", (case_id,))
    row = cursor.fetchone()
    risk_score = row[0] if row else 0
    
    return {
        "case_id": case_id,
        "pipeline_status": state_status,
        "risk_score": risk_score,
        "completed": state_status == "COMPLETED"
    }

@app.get("/api/case/{case_id}/report/{report_type}")
def get_report(case_id: str, report_type: str):
    if report_type not in ["soc", "executive", "remediation"]:
        raise HTTPException(status_code=400, detail="Report type must be 'soc', 'executive', or 'remediation'.")
        
    cursor = db.execute_query("SELECT content FROM reports WHERE case_id = %s AND report_type = %s", (case_id, report_type))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Report '{report_type}' not found for case {case_id}.")
        
    return {
        "case_id": case_id,
        "report_type": report_type,
        "content": row[0]
    }

@app.get("/api/case/{case_id}/iocs")
def get_iocs(case_id: str):
    iocs = db.get_iocs(case_id)
    return {
        "case_id": case_id,
        "count": len(iocs),
        "iocs": iocs
    }

@app.get("/api/case/{case_id}/findings")
def get_findings(case_id: str):
    findings = db.get_findings(case_id)
    return {
        "case_id": case_id,
        "count": len(findings),
        "findings": findings
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
