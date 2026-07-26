import os
import json
import uuid
import hashlib
from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from database import get_db, RunState, ReceiptState
from openai import OpenAI

app = FastAPI()
client = OpenAI()

def generate_otlp_trace(run_id, public_marker, root_cause):
    trace_id = uuid.uuid4().hex
    server_span_id = uuid.uuid4().hex[:16]
    agent_span_id = uuid.uuid4().hex[:16]
    chat_span_id = uuid.uuid4().hex[:16]

    return {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": trace_id,
                        "spanId": server_span_id,
                        "name": "POST /v2/incidents",
                        "kind": 2, 
                        "attributes": [
                            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
                        ]
                    },
                    {
                        "traceId": trace_id,
                        "spanId": agent_span_id,
                        "parentSpanId": server_span_id,
                        "name": "invoke_agent incident-response",
                        "kind": 1, 
                        "attributes": [
                            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
                        ]
                    },
                    {
                        "traceId": trace_id,
                        "spanId": chat_span_id,
                        "parentSpanId": agent_span_id,
                        "name": "chat incident-plan",
                        "kind": 3, 
                        "attributes": [
                            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o-mini"}}
                        ]
                    }
                ]
            }]
        }]
    }, trace_id, chat_span_id

@app.post("/v2/incidents")
async def create_incident(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # 1. Create a stable hash to perfectly detect 409 Conflicts
    canonical_body = json.dumps(body, sort_keys=True)
    body_hash = hashlib.sha256(canonical_body.encode()).hexdigest()

    run_id = body.get("runId")
    public_marker = body.get("publicMarker", "default")
    
    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Invalid profile")
        
    # 2. Check for Conflicts
    existing = db.query(RunState).filter(RunState.run_id == run_id).first()
    if existing:
        if existing.request_hash != body_hash:
            raise HTTPException(status_code=409, detail="Changed content conflict")
        return json.loads(existing.state_json)

    # 3. AI Processing
    incident = body.get("incident", {})
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])
    tool_catalog = body.get("toolCatalog", [])

    prompt = f"""
    Transcript: {transcript}
    Allowed Root Causes: {allowed_causes}
    Tool Catalog: {json.dumps(tool_catalog)}

    You are an AI diagnostic agent.
    1. Select EXACTLY ONE root cause from the Allowed Root Causes.
    2. Cite 2 to 4 evidence line IDs (e.g., "ev_123") from the Transcript.
    3. Select ONE diagnostic tool from the Tool Catalog to verify this cause.
    4. Determine the exact arguments needed for the tool based on the Transcript.
    
    Output strictly as JSON:
    {{
        "rootCause": "...",
        "evidence": ["ev_...", "ev_..."],
        "toolName": "...",
        "arguments": {{...}}
    }}
    """
    
    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        ai_response = json.loads(completion.choices[0].message.content)
    except Exception:
        ai_response = {
            "rootCause": allowed_causes[0] if allowed_causes else "unknown", 
            "evidence": [],
            "toolName": "query_metrics",
            "arguments": {}
        }

    otlp_trace, trace_id, parent_span = generate_otlp_trace(run_id, public_marker, ai_response.get("rootCause"))

    action_id = str(uuid.uuid4())
    call_id = str(uuid.uuid4())
    traceparent = f"00-{trace_id}-{parent_span}-01"

    response_data = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": ai_response.get("rootCause"),
            "evidence": ai_response.get("evidence", [])
        },
        "dispatches": [{
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": ai_response.get("toolName"), 
            "arguments": ai_response.get("arguments", {}),
            "evidence": ai_response.get("evidence", [])[:1],
            "attempt": 1,
            "traceparent": traceparent
        }],
        "approvals": [],
        "otlp": otlp_trace
    }
    
    db.add(RunState(run_id=run_id, request_hash=body_hash, status="waiting", state_json=json.dumps(response_data)))
    db.commit()
    return response_data

@app.post("/v2/incidents/{runId}/receipts")
async def process_receipt(runId: str, request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    canonical_body = json.dumps(body, sort_keys=True)
    body_hash = hashlib.sha256(canonical_body.encode()).hexdigest()
    receipt_id = body.get("receiptId")

    existing_receipt = db.query(ReceiptState).filter(ReceiptState.receipt_id == receipt_id).first()
    if existing_receipt:
        if existing_receipt.request_hash != body_hash:
            raise HTTPException(status_code=409, detail="Changed receipt conflict")

    existing_run = db.query(RunState).filter(RunState.run_id == runId).first()
    if not existing_run:
        raise HTTPException(status_code=404, detail="Run not found")
        
    if not existing_receipt:
        db.add(ReceiptState(receipt_id=receipt_id, run_id=runId, request_hash=body_hash, state_json=existing_run.state_json))
        db.commit()

    return json.loads(existing_run.state_json)

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str, db: Session = Depends(get_db)):
    existing = db.query(RunState).filter(RunState.run_id == runId).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Run not found")
    return json.loads(existing.state_json)
