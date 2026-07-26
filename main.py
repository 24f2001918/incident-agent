import os
import json
import uuid
import hashlib
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from database import get_db, RunState
from openai import OpenAI

app = FastAPI()

# Automatically uses the OPENAI_API_KEY and OPENAI_BASE_URL from Render environment variables
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
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    run_id = body.get("runId")
    public_marker = body.get("publicMarker", "default")
    
    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Invalid profile")
        
    existing = db.query(RunState).filter(RunState.run_id == run_id).first()
    if existing:
        if existing.request_hash != body_hash:
            return Response(status_code=409, content="Conflict")
        return json.loads(existing.state_json)

    incident = body.get("incident", {})
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])

    prompt = f"""
    Analyze this incident transcript:
    {transcript}
    
    Choose EXACTLY ONE root cause from this list: {allowed_causes}.
    Find 2 to 4 evidence line IDs from the transcript (e.g., ["ev_1", "ev_2"]).
    Return ONLY a JSON object: {{"rootCause": "chosen_cause", "evidence": ["id1", "id2"]}}
    """
    
    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        ai_response = json.loads(completion.choices[0].message.content)
    except Exception:
        ai_response = {"rootCause": allowed_causes[0] if allowed_causes else "unknown", "evidence": []}

    otlp_trace, trace_id, parent_span = generate_otlp_trace(run_id, public_marker, ai_response.get("rootCause"))

    action_id = str(uuid.uuid4())
    call_id = str(uuid.uuid4())
    traceparent = f"00-{trace_id}-{parent_span}-01"

    response_data = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": ai_response,
        "dispatches": [{
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": "query_metrics", 
            "arguments": {},
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
