from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from database import get_db, RunState
import json
import uuid

app = FastAPI()

@app.post("/v2/incidents")
async def create_incident(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    run_id = body.get("runId")
    
    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Invalid profile")
        
    existing = db.query(RunState).filter(RunState.run_id == run_id).first()
    if existing:
        return json.loads(existing.state_json)
        
    response_data = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {"rootCause": "database_connection_exhaustion", "evidence": ["ev_101", "ev_102"]},
        "dispatches": [{
            "actionId": str(uuid.uuid4()),
            "callId": str(uuid.uuid4()),
            "phase": "diagnostic",
            "toolName": "query_metrics",
            "arguments": {},
            "evidence": ["ev_101"],
            "attempt": 1,
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }],
        "approvals": []
    }
    
    db.add(RunState(run_id=run_id, status="waiting", state_json=json.dumps(response_data)))
    db.commit()
    return response_data

@app.post("/v2/incidents/{runId}/receipts")
async def process_receipt(runId: str, request: Request, db: Session = Depends(get_db)):
    existing = db.query(RunState).filter(RunState.run_id == runId).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Run not found")
    return json.loads(existing.state_json)

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str, db: Session = Depends(get_db)):
    existing = db.query(RunState).filter(RunState.run_id == runId).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Run not found")
    return json.loads(existing.state_json)
