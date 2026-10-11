"""
Tests for the scoring engine and event ingestion.

Uses SQLite in-memory via DATABASE_URL override.
"""
import os
import sys
import json

import os
import sys
import json

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from main import app, compute_score, window_buffer
import schemas


client = TestClient(app)
HEADERS = {"x-agent-token": os.environ.get("AGENT_TOKEN", "test-token")}
NOW = datetime.now(timezone.utc).isoformat()


def _make_event(
    pid=1234,
    create_time=100.0,
    process_name="python.exe",
    attribution="matched",
    io_write=200000,
    renames=150,
    entropy=7.85,
    ext_ratio=0.95,
    distinct=50,
    canary=False,
):
    return {
        "timestamp": NOW,
        "pid": pid,
        "create_time": create_time,
        "process_name": process_name,
        "cmdline": ["python.exe", "simulate.py"],
        "attribution": attribution,
        "metrics": {
            "io_write_bytes_delta": io_write,
            "watchdog_write_events": renames,
            "watchdog_rename_events": renames,
            "write_entropy_avg": entropy,
            "extension_change_ratio": ext_ratio,
            "distinct_files_modified": distinct,
            "canary_touched": canary,
        },
    }


# ─────────────────────────────────────────────────
#  Test 1: Simulator-like window scores >= 70
# ─────────────────────────────────────────────────
def test_simulator_window_scores_above_70():
    """
    A window with high renames, high entropy, high write rate,
    high extension-change ratio, and a script-host process should
    score at least 70 (Suspend tier). With the ransomware_combo,
    the rule engine can now reach > 70.
    """
    ev = _make_event(
        io_write=100000,  # 100 KB/s → 10 pts
        renames=100,      # near saturation → 10 pts
        entropy=7.9,      # high → 14 pts
        ext_ratio=1.0,    # → 15 pts
        process_name="python.exe",  # → +10 script host
    )
    resp = client.post("/api/events", json=[ev], headers=HEADERS)
    assert resp.status_code == 200

    data = resp.json()
    # Should have produced a suspend or terminate action
    assert len(data) >= 1, f"Expected at least 1 action, got {data}"
    assert data[0]["type"] in ("suspend", "terminate")

    # Verify incident was created with correct score
    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["max_score"] >= 70
    assert incidents[0]["status"] in ("Suspend-Pending", "Terminate-Pending")

    # Verify the score breakdown
    metrics = schemas.EventMetrics(**ev["metrics"])
    score, contribs, reasons = compute_score(metrics, "python.exe")
    assert score >= 70, f"Score {score} should be >= 70. Contribs: {contribs}"
    assert contribs["ransomware_combo"] == 45.0
    print(f"\n[test_simulator] score={score}, contribs={json.dumps(contribs, indent=2)}")
    print(f"  reasons: {reasons}")

# ─────────────────────────────────────────────────
#  Test 1.5: Zip/backup-like window scores < 40
# ─────────────────────────────────────────────────
def test_zip_backup_scores_below_40():
    """
    High entropy and high write rate, but low renames and NO extension changes
    (typical of creating a backup archive or downloading a zip).
    Should not trigger the combo, so score stays < 40 (Monitoring).
    """
    ev = _make_event(
        io_write=100000,  # 100 KB/s → max 10 pts
        renames=2,        # low renames → near 0 pts
        entropy=7.9,      # high entropy → 14 pts
        ext_ratio=0.0,    # no ext change → 0 pts
        process_name="7z.exe",  # no script host bonus
    )
    resp = client.post("/api/events", json=[ev], headers=HEADERS)
    assert resp.status_code == 200

    data = resp.json()
    assert len(data) == 0, f"Expected no actions, got {data}"

    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 0, f"Expected no incidents, got {incidents}"

    metrics = schemas.EventMetrics(**ev["metrics"])
    score, contribs, reasons = compute_score(metrics, "7z.exe")
    assert score < 40, f"Score {score} should be < 40. Contribs: {contribs}"
    assert contribs["ransomware_combo"] == 0.0
    print(f"\n[test_backup] score={score}, contribs={json.dumps(contribs, indent=2)}")
    print(f"  reasons: {reasons}")

# ─────────────────────────────────────────────────
#  Test 2: Canary touch floors score at >= 95
# ─────────────────────────────────────────────────
def test_canary_touch_floors():
    """
    Canary touch alone (behavior score < 60) -> score floor 85 (suspend).
    Canary touch + behavior score >= 60 -> score floor 95 (terminate).
    """
    # Clear db to avoid conflicting with previous incidents
    from database import SessionLocal
    import models
    db = SessionLocal()
    db.query(models.Event).delete()
    db.query(models.Action).delete()
    db.query(models.AlertReason).delete()
    db.query(models.Incident).delete()
    db.commit()
    db.close()

    ev_low = _make_event(
        io_write=5000,   # low write rate
        renames=10,      # few renames
        entropy=4.0,     # low entropy
        ext_ratio=0.1,   # low ext change
        canary=True,
        process_name="unknown.exe",  # not a script host
    )
    resp_low = client.post("/api/events", json=[ev_low], headers=HEADERS)
    assert resp_low.status_code == 200
    data_low = resp_low.json()
    assert len(data_low) >= 1
    assert data_low[0]["type"] == "suspend"

    metrics_low = schemas.EventMetrics(**ev_low["metrics"])
    score_low, contribs_low, reasons_low = compute_score(metrics_low, "unknown.exe")
    assert score_low == 85.0
    assert "canary file touched" in reasons_low

    ev_high = _make_event(
        pid=9999,
        io_write=15000000,
        renames=50,
        entropy=7.5,
        ext_ratio=0.8,
        canary=True,
        process_name="powershell.exe",
    )
    resp_high = client.post("/api/events", json=[ev_high], headers=HEADERS)
    assert resp_high.status_code == 200
    data_high = resp_high.json()
    assert len(data_high) >= 1
    assert data_high[0]["type"] == "terminate"

    metrics_high = schemas.EventMetrics(**ev_high["metrics"])
    score_high, contribs_high, reasons_high = compute_score(metrics_high, "powershell.exe")
    assert score_high >= 95.0
    assert "canary file touched" in reasons_high

    # Verify incident
    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 2
    assert incidents[0]["status"] == "Suspend-Pending"
    assert incidents[0]["max_score"] >= 85
    assert incidents[1]["status"] == "Terminate-Pending"
    assert incidents[1]["max_score"] >= 95

    # Verify AlertReason rows
    detail = client.get(f"/api/incidents/{incidents[0]['id']}").json()
    reason_texts = [r["reason"] for r in detail["reasons"]]
    assert any("canary" in r for r in reason_texts), f"Missing canary reason in {reason_texts}"


# ─────────────────────────────────────────────────
#  Test 3: Normal text editing scores < 40
# ─────────────────────────────────────────────────
def test_normal_text_editing_below_40():
    """
    A window with low write rate, no renames, low entropy,
    no canary, and a non-script-host process should score < 40.
    No incident should be created.
    """
    ev = _make_event(
        io_write=2000,    # 2 KB/s
        renames=0,        # no renames
        entropy=3.5,      # text-like entropy
        ext_ratio=0.0,    # no ext changes
        canary=False,
        process_name="notepad.exe",
        attribution="matched",
    )
    resp = client.post("/api/events", json=[ev], headers=HEADERS)
    assert resp.status_code == 200

    data = resp.json()
    assert len(data) == 0, f"Expected no actions, got {data}"

    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 0, f"Expected no incidents, got {incidents}"

    # Verify score
    metrics = schemas.EventMetrics(**ev["metrics"])
    score, contribs, reasons = compute_score(metrics, "notepad.exe")
    assert score < 40, f"Score {score} should be < 40 for text editing. Contribs: {contribs}"
    print(f"\n[test_normal] score={score}, contribs={json.dumps(contribs, indent=2)}")
    print(f"  reasons: {reasons}")


# ─────────────────────────────────────────────────
#  Test 4: Ambiguous/pooled never produces suspend/terminate
# ─────────────────────────────────────────────────
def test_ambiguous_never_produces_action():
    """
    Even with extremely high signals, an ambiguous or pooled event
    must NEVER produce a suspend or terminate action.
    """
    from database import SessionLocal
    import models
    db = SessionLocal()
    db.query(models.Event).delete()
    db.query(models.Action).delete()
    db.query(models.AlertReason).delete()
    db.query(models.Incident).delete()
    db.commit()
    db.close()

    for attr in ("ambiguous", "pooled"):
        # Reset for each attribution type
        window_buffer.clear()
        
        try:
            import os
            os.remove("test.db")
        except:
            pass

        from database import SessionLocal, Base, engine
        import models
        # Recreate tables to ensure empty
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

        ev = _make_event(
            io_write=500000,
            renames=200,
            entropy=7.9,
            ext_ratio=1.0,
            canary=True,     # even with canary!
            process_name="python.exe",
            attribution=attr,
            pid=9999,
            create_time=200.0,
        )
        resp = client.post("/api/events", json=[ev], headers=HEADERS)
        assert resp.status_code == 200

        data = resp.json()
        assert len(data) == 0, (
            f"attribution={attr}: Expected no actions but got {data}"
        )

        incidents = client.get("/api/incidents").json()
        my_incident = [inc for inc in incidents if inc["pid"] == 9999][0]
        assert my_incident["status"] == "Alert", "Status should be Alert"

        # Also test pid=None
        ev_null = _make_event(
            io_write=500000,
            renames=200,
            entropy=7.9,
            ext_ratio=1.0,
            canary=True,
            process_name="host_window",
            attribution="pooled",
            pid=None,
            create_time=0.0,
        )
        resp2 = client.post("/api/events", json=[ev_null], headers=HEADERS)
        assert resp2.status_code == 200
        assert len(resp2.json()) == 0

        incidents_null = client.get("/api/incidents").json()
        my_null_incident = [inc for inc in incidents_null if inc["pid"] is None][0]
        assert my_null_incident["status"] == "Alert"

    print("\n[test_ambiguous] Confirmed: ambiguous/pooled/pid=None never produce actions")


# ─────────────────────────────────────────────────
#  Bonus: Print sample incident JSON with reasons
# ─────────────────────────────────────────────────
def test_print_sample_incident():
    """Create a realistic incident and print its full JSON."""
    ev = _make_event(
        io_write=250000,
        renames=160,
        entropy=7.81,
        ext_ratio=0.99,
        canary=True,
        process_name="python.exe",
        attribution="matched",
        pid=5678,
        create_time=300.0,
    )
    resp = client.post("/api/events", json=[ev], headers=HEADERS)
    assert resp.status_code == 200

    incidents = client.get("/api/incidents").json()
    assert len(incidents) >= 1
    iid = incidents[-1]["id"]

    detail = client.get(f"/api/incidents/{iid}").json()
    print("\n" + "=" * 60)
    print("SAMPLE INCIDENT JSON:")
    print("=" * 60)
    print(json.dumps(detail, indent=2, default=str))
    print("=" * 60)

# ─────────────────────────────────────────────────
#  Test 5: never_act attribution is capped at 69 and Alert only
# ─────────────────────────────────────────────────
def test_never_act_capped():
    """
    A process with never_act attribution hitting a canary yields no suspend/terminate action
    (score capped at 69, Alert only).
    A normal matched process gets the suspend/terminate.
    """
    ev_never = _make_event(
        io_write=500000,
        renames=100,
        entropy=7.9,
        ext_ratio=1.0,
        canary=True,
        process_name="svchost.exe",
        attribution="never_act",
        pid=1111,
        create_time=500.0,
    )
    
    resp_never = client.post("/api/events", json=[ev_never], headers=HEADERS)
    assert resp_never.status_code == 200
    data_never = resp_never.json()
    assert len(data_never) == 0, f"Expected no actions for never_act, got {data_never}"

    ev_normal = _make_event(
        io_write=500000,
        renames=100,
        entropy=7.9,
        ext_ratio=1.0,
        canary=True,
        process_name="python.exe",
        attribution="matched",
        pid=2222,
        create_time=600.0,
    )
    
    resp_normal = client.post("/api/events", json=[ev_normal], headers=HEADERS)
    assert resp_normal.status_code == 200
    data_normal = resp_normal.json()
    assert len(data_normal) >= 1
    assert data_normal[0]["type"] == "terminate", "Normal process should get terminate"
