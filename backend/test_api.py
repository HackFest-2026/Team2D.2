import sys
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import app
import datetime

client = TestClient(app)

def test_unauthorized_post():
    response = client.post("/api/events", json=[])
    assert response.status_code == 401


def test_incident_creation_and_action_delivery():

    headers = {"x-agent-token": os.environ.get("AGENT_TOKEN", "test-token")}
    
    event_low = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "pid": 100,
        "create_time": 123.4,
        "process_name": "test.exe",
        "attribution": "matched",
        "cmdline": ["test.exe"],
        "metrics": {
            "io_write_bytes_delta": 0,
            "watchdog_write_events": 0,
            "watchdog_rename_events": 0,
            "write_entropy_avg": 0,
            "extension_change_ratio": 0,
            "distinct_files_modified": 0,
            "canary_touched": False
        }
    }
    
    # 1. An event scoring below 40 creates no incident
    response = client.post("/api/events", json=[event_low], headers=headers)
    assert response.status_code == 200
    
    res = client.get("/api/incidents")
    assert len(res.json()) == 0

    event_high = event_low.copy()
    event_high["metrics"] = event_low["metrics"].copy()
    event_high["metrics"]["io_write_bytes_delta"] = 500000
    event_high["metrics"]["write_entropy_avg"] = 6.5
    event_high["process_name"] = "python.exe"
    event_high["metrics"]["watchdog_rename_events"] = 40
    event_high["metrics"]["extension_change_ratio"] = 1.0
    event_high["metrics"]["distinct_files_modified"] = 30
    
    # Print score and signal contributions as requested
    from main import compute_score
    import schemas
    score, contribs, reasons = compute_score(schemas.EventMetrics(**event_high["metrics"]), event_high["process_name"])
    print(f"\n[test_api event_high] score={score}, contribs={contribs}")
    
    # 2. Score > 40 creates incident. Since this score is 45, no automatic suspend/terminate action yet.
    response = client.post("/api/events", json=[event_high], headers=headers)
    assert response.status_code == 200
    
    res = client.get("/api/incidents")
    incidents = res.json()
    assert len(incidents) == 1
    incident_id = incidents[0]["id"]
    assert incidents[0]["status"] == "Alert"
    
    res2 = client.get(f"/api/incidents/{incident_id}")
    assert res2.status_code == 200
    data = res2.json()
    assert len(data["events"]) == 2

    # 3. Create a higher score to trigger automatic suspend action (score >= 70)
    event_very_high = event_low.copy()
    event_very_high["metrics"] = event_low["metrics"].copy()
    event_very_high["metrics"]["io_write_bytes_delta"] = 500000
    event_very_high["metrics"]["write_entropy_avg"] = 7.9
    event_very_high["metrics"]["watchdog_rename_events"] = 50
    event_very_high["metrics"]["extension_change_ratio"] = 1.0
    event_very_high["metrics"]["distinct_files_modified"] = 30
    event_very_high["process_name"] = "python.exe"
    event_very_high["metrics"]["canary_touched"] = True

    # Incident status must become Terminate-Pending until the agent acks
    response = client.post("/api/events", json=[event_very_high], headers=headers)
    assert response.status_code == 200
    actions = response.json()
    assert len(actions) == 1
    assert actions[0]["type"] == "terminate"
    action_id = actions[0]["action_id"]

    res = client.get("/api/incidents")
    incidents = res.json()
    assert incidents[0]["status"] == "Terminate-Pending"

    # Action is delivered, shouldn't send again
    response = client.post("/api/events", json=[event_very_high], headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 0

    # Agent acks -> incident becomes Terminated
    result_resp = client.post(f"/api/actions/{action_id}/result", json={"status": "success", "files_restored": 5}, headers=headers)
    assert result_resp.status_code == 200

    res = client.get("/api/incidents")
    incidents = res.json()
    assert incidents[0]["status"] == "Terminated"

    # 4. WebSocket test
    with client.websocket_connect("/ws/incidents") as websocket:
        data = websocket.receive_text()
        assert data == "connected"
