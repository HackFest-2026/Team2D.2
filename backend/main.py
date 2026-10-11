from fastapi import FastAPI, Depends, HTTPException, Header, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from pydantic import BaseModel
from database import Base, engine, get_db
import os
import models, schemas
import yaml
import datetime

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ActionRequest(BaseModel):
    type: str

_config_path = Path(__file__).parent / "config.yaml"
with open(_config_path, "r") as f:
    config = yaml.safe_load(f)

AGENT_TOKEN = os.environ.get("AGENT_TOKEN")
if not AGENT_TOKEN:
    raise ValueError("Missing AGENT_TOKEN")

SCORING = config.get("scoring", {})
TIERS = config.get("tiers", {"alert": 40, "suspend": 70, "terminate": 90})


def verify_token(x_agent_token: str = Header(None)):
    if x_agent_token != AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API Token")


# ────────────────────────────────────────────────────────────
#  Scoring Engine
# ────────────────────────────────────────────────────────────

def _lerp(value: float, saturate_at: float) -> float:
    """Linear ramp from 0.0 to 1.0 clamped at saturate_at."""
    if saturate_at <= 0:
        return 1.0
    return min(value / saturate_at, 1.0)


def isolation_forest_score(metrics: schemas.EventMetrics) -> float:
    """
    ── STUB ──  IsolationForest contribution (0-30).
    Returns 0 until the model is trained and scoring.isolation_forest_enabled
    is set to true in config.yaml.  When implemented, this function will:
      1. Load the trained IsolationForest model from disk (cached in memory).
      2. Assemble the feature vector:
           [io_write_bytes_delta, watchdog_rename_events, write_entropy_avg,
            extension_change_ratio, distinct_files_modified]
      3. Call model.decision_function() and map the anomaly score to [0, 30].
    """
    if not SCORING.get("isolation_forest_enabled", False):
        return 0.0
    # TODO: load model, extract features, predict, scale to 0-30
    return 0.0


def compute_score(
    metrics: schemas.EventMetrics,
    process_name: Optional[str],
) -> Tuple[float, Dict[str, float], List[str]]:
    """
    Score a 5-second window for a single (pid, create_time).

    Returns (score, signal_contributions, plain_english_reasons).
    Rule engine contributes 0-50, IsolationForest stub contributes 0-30.
    """
    contributions: Dict[str, float] = {}
    reasons: List[str] = []

    # ── 1. Renames (0 – 12) ──
    rename_cfg = SCORING.get("renames", {})
    renames = metrics.watchdog_rename_events
    rename_pts = _lerp(renames, rename_cfg.get("saturate_at", 200)) * rename_cfg.get("max_points", 12)
    contributions["renames"] = round(rename_pts, 2)
    if renames > 5:
        reasons.append(f"{renames} files renamed in 5 s")

    # ── 2. Extension-change ratio (0 – 8) ──
    ext_cfg = SCORING.get("extension_change", {})
    ext_pts = metrics.extension_change_ratio * ext_cfg.get("max_points", 8)
    contributions["extension_change"] = round(ext_pts, 2)
    if metrics.extension_change_ratio > 0.5:
        reasons.append(
            f"extension change ratio {metrics.extension_change_ratio:.2f} "
            f"({int(metrics.extension_change_ratio * 100)}% of renames changed extension)"
        )

    # ── 3. Write rate (0 – 15) ──
    wr_cfg = SCORING.get("write_rate", {})
    wr_pts = _lerp(metrics.io_write_bytes_delta, wr_cfg.get("saturate_at", 500000)) * wr_cfg.get("max_points", 15)
    contributions["write_rate"] = round(wr_pts, 2)
    if metrics.io_write_bytes_delta > 10000:
        rate_kb = metrics.io_write_bytes_delta / 1024
        reasons.append(f"write rate {rate_kb:.1f} KB/s")

    # ── 4. Entropy (0 – 15, capped) ──
    ent_cfg = SCORING.get("entropy", {})
    ent_threshold = ent_cfg.get("threshold", 6.0)
    ent_sat = ent_cfg.get("saturate_at", 7.9)
    ent_max = ent_cfg.get("max_points", 15)
    if metrics.write_entropy_avg >= ent_threshold:
        ent_pts = _lerp(
            metrics.write_entropy_avg - ent_threshold,
            ent_sat - ent_threshold,
        ) * ent_max
    else:
        ent_pts = 0.0
    contributions["entropy"] = round(ent_pts, 2)
    if metrics.write_entropy_avg >= 7.0:
        reasons.append(
            f"write entropy {metrics.write_entropy_avg:.1f}, typical of encrypted data"
        )

    # ── 5. Script-host bonus (flat 10) ──
    script_names = {n.lower() for n in SCORING.get("script_host_names", [])}
    name_lower = (process_name or "").lower()
    if name_lower in script_names:
        contributions["script_host"] = float(SCORING.get("script_host_bonus", 10))
        reasons.append(f"process '{process_name}' is a script host")
    else:
        contributions["script_host"] = 0.0

    # ── 6. Combo bonus ──
    combo = SCORING.get("ransomware_combo", {})
    if (renames >= combo.get("min_renames", 50) and 
        metrics.extension_change_ratio >= combo.get("min_ext_ratio", 0.7) and 
        metrics.write_entropy_avg >= combo.get("min_entropy", 7.0)):
        
        bonus = float(combo.get("bonus", 25))
        contributions["ransomware_combo"] = bonus
        reasons.append("rename + extension change + high entropy together, typical of ransomware")
    else:
        contributions["ransomware_combo"] = 0.0

    # ── 7. IsolationForest stub (0 – 30) ──
    iso_pts = isolation_forest_score(metrics)
    contributions["isolation_forest"] = round(iso_pts, 2)

    # ── Sum rule engine + ML ──
    rule_total = sum(v for k, v in contributions.items() if k != "isolation_forest")
    score = rule_total + iso_pts

    # ── 8. Canary floor ──
    if metrics.canary_touched:
        reasons.append("canary file touched")
        behavior_score = score
        c_floor = 95.0 if behavior_score >= 60.0 else 85.0
        contributions["canary"] = c_floor
        if score < c_floor:
            score = c_floor

    score = min(score, 100.0)
    contributions["total"] = round(score, 2)

    return round(score, 2), contributions, reasons


def _tier_for_score(score: float) -> int:
    if score >= TIERS["terminate"]:
        return TIERS["terminate"]
    if score >= TIERS["suspend"]:
        return TIERS["suspend"]
    if score >= TIERS["alert"]:
        return TIERS["alert"]
    return 0


def _status_for_score(score: float) -> str:
    if score >= TIERS["terminate"]:
        return "Terminate-Pending"
    if score >= TIERS["suspend"]:
        return "Suspend-Pending"
    return "Alert"


def _is_actionable(attribution: Optional[str]) -> bool:
    """pooled, ambiguous, or None events never trigger suspend/terminate."""
    return attribution in ("handle", "matched")


# ────────────────────────────────────────────────────────────
#  Event ingestion
# ────────────────────────────────────────────────────────────

window_buffer: Dict = {}
first_event_times: Dict = {}

@app.post("/api/events", response_model=List[schemas.ActionSchema])
def receive_events(
    events: List[schemas.IncomingEvent],
    db: Session = Depends(get_db),
    token: str = Depends(verify_token),
):
    actions_to_return: List[schemas.ActionSchema] = []

    for ev in events:
        score, contributions, reasons = compute_score(ev.metrics, ev.process_name)
        actionable = _is_actionable(ev.attribution)
        if not actionable and score > 69.0:
            score = 69.0
            
        tier = _tier_for_score(score)

        # ── Buffer for backfill ──
        key = (ev.pid, ev.create_time)
        if key not in first_event_times:
            first_event_times[key] = ev.timestamp
            
        if key not in window_buffer:
            window_buffer[key] = []
        window_buffer[key].append((ev, score, contributions, reasons))
        if len(window_buffer[key]) > 5:
            window_buffer[key].pop(0)

        # ── Display-only events (pooled / ambiguous) ──
        # They create incidents with real pid/name, but we don't create actions if not actionable.
        
        incident = db.query(models.Incident).filter(
            models.Incident.pid == ev.pid,
            models.Incident.create_time == ev.create_time,
        ).first()

        if score >= TIERS["alert"] and not incident:
            # ── New incident ──
            # time_to_detect_ms = incident creation time minus the first sandbox
            # activity attributed to this pid/create_time (sent by agent).
            now_utc = datetime.datetime.utcnow()
            
            incident = models.Incident(
                pid=ev.pid,
                create_time=ev.create_time,
                process_name=ev.process_name,
                cmdline=ev.cmdline,
                status="Alert" if not actionable else _status_for_score(score),
                max_score=score,
                affected_count=ev.modified_files_total or 0,
            )
            db.add(incident)
            db.commit()
            db.refresh(incident)

            # Create action if score warrants it AND actionable
            if actionable and score >= TIERS["suspend"]:
                action_type = "terminate" if score >= TIERS["terminate"] else "suspend"
                db.add(models.Action(
                    incident_id=incident.id, type=action_type, status="pending"
                ))

            # ── Backfill buffered events ──
            for buf_ev, buf_score, buf_contribs, buf_reasons in window_buffer[key]:
                db.add(models.Event(
                    incident_id=incident.id,
                    timestamp=buf_ev.timestamp,
                    write_rate=buf_ev.metrics.io_write_bytes_delta,
                    rename_rate=buf_ev.metrics.watchdog_rename_events,
                    entropy=buf_ev.metrics.write_entropy_avg,
                    score=buf_score,
                    tier=_tier_for_score(buf_score),
                    canary_touched=buf_ev.metrics.canary_touched,
                    signal_contributions=buf_contribs,
                ))

            # ── AlertReason rows ──
            for reason_text in reasons:
                # Derive signal_name from reason text
                if "renamed" in reason_text:
                    sig = "renames"
                elif "extension" in reason_text:
                    sig = "extension_change"
                elif "write rate" in reason_text:
                    sig = "write_rate"
                elif "entropy" in reason_text:
                    sig = "entropy"
                elif "canary" in reason_text:
                    sig = "canary"
                elif "script host" in reason_text:
                    sig = "script_host"
                else:
                    sig = "other"

                db.add(models.AlertReason(
                    incident_id=incident.id,
                    reason=reason_text,
                    signal_name=sig,
                    contribution_score=contributions.get(sig, 0),
                ))

            db.commit()

        elif incident:
            # ── Existing incident – update ──
            if score > incident.max_score:
                incident.max_score = score
            # affected_count = max of what we had vs what the agent reports now
            incident.affected_count = max(incident.affected_count or 0, ev.modified_files_total or 0)

            if actionable and score >= TIERS["terminate"] and incident.status not in (
                "Terminated", "Terminate-Pending"
            ):
                incident.status = "Terminate-Pending"
                db.add(models.Action(
                    incident_id=incident.id, type="terminate", status="pending"
                ))
            elif actionable and score >= TIERS["suspend"] and incident.status == "Alert":
                incident.status = "Suspend-Pending"
                db.add(models.Action(
                    incident_id=incident.id, type="suspend", status="pending"
                ))

            db.add(models.Event(
                incident_id=incident.id,
                timestamp=ev.timestamp,
                write_rate=ev.metrics.io_write_bytes_delta,
                rename_rate=ev.metrics.watchdog_rename_events,
                entropy=ev.metrics.write_entropy_avg,
                score=score,
                tier=tier,
                canary_touched=ev.metrics.canary_touched,
                signal_contributions=contributions,
            ))

            # Record new reasons that weren't already saved
            existing_reasons = {
                r.reason
                for r in db.query(models.AlertReason).filter(
                    models.AlertReason.incident_id == incident.id
                ).all()
            }
            for reason_text in reasons:
                if reason_text not in existing_reasons:
                    if "renamed" in reason_text:
                        sig = "renames"
                    elif "extension" in reason_text:
                        sig = "extension_change"
                    elif "write rate" in reason_text:
                        sig = "write_rate"
                    elif "entropy" in reason_text:
                        sig = "entropy"
                    elif "canary" in reason_text:
                        sig = "canary"
                    elif "script host" in reason_text:
                        sig = "script_host"
                    else:
                        sig = "other"

                    db.add(models.AlertReason(
                        incident_id=incident.id,
                        reason=reason_text,
                        signal_name=sig,
                        contribution_score=contributions.get(sig, 0),
                    ))

            db.commit()

        # ── Return pending actions ──
        if incident:
            pending_actions = (
                db.query(models.Action)
                .filter(
                    models.Action.incident_id == incident.id,
                    models.Action.status == "pending",
                )
                .all()
            )
            for action in pending_actions:
                restore_ts = None
                if action.payload:
                    restore_ts = action.payload.get("restore_timestamp")
                
                actions_to_return.append(
                    schemas.ActionSchema(
                        action_id=str(action.id),
                        pid=incident.pid,
                        create_time=incident.create_time,
                        type=action.type,
                        restore_timestamp=restore_ts
                    )
                )
                action.status = "delivered"
                action.delivered_time = datetime.datetime.utcnow()

            if pending_actions:
                db.commit()

    return actions_to_return


# ────────────────────────────────────────────────────────────
#  Read endpoints
# ────────────────────────────────────────────────────────────

def check_action_timeouts(db: Session):
    now = datetime.datetime.utcnow()
    delivered_actions = db.query(models.Action).filter(models.Action.status == "delivered").all()
    changed = False
    for action in delivered_actions:
        if action.delivered_time and (now - action.delivered_time).total_seconds() > 10:
            if action.retry_count < 1:
                action.status = "pending"
                action.retry_count += 1
                action.delivered_time = None
                changed = True
            else:
                action.status = "failed"
                action.failure_reason = "timeout"
                incident = db.query(models.Incident).filter(models.Incident.id == action.incident_id).first()
                if incident:
                    # leave pending state
                    if incident.status.endswith("-Pending"):
                        incident.status = incident.status.replace("-Pending", "-Failed")
                changed = True
    if changed:
        db.commit()

@app.get("/api/incidents")
def get_incidents(db: Session = Depends(get_db)):
    check_action_timeouts(db)
    return db.query(models.Incident).all()


@app.get("/api/actions")
def get_pending_actions(db: Session = Depends(get_db)):
    check_action_timeouts(db)
    pending_actions = (
        db.query(models.Action)
        .filter(models.Action.status == "pending")
        .all()
    )
    
    actions_to_return = []
    for action in pending_actions:
        incident = db.query(models.Incident).filter(models.Incident.id == action.incident_id).first()
        if incident:
            restore_ts = None
            if action.payload:
                restore_ts = action.payload.get("restore_timestamp")
            
            actions_to_return.append({
                "action_id": str(action.id),
                "pid": incident.pid,
                "create_time": incident.create_time,
                "type": action.type,
                "restore_timestamp": restore_ts
            })
            action.status = "delivered"
            action.delivered_time = datetime.datetime.utcnow()
    
    if pending_actions:
        db.commit()
        
    return actions_to_return


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(
        models.Incident.id == incident_id
    ).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = (
        db.query(models.Event)
        .filter(models.Event.incident_id == incident_id)
        .all()
    )
    actions = (
        db.query(models.Action)
        .filter(models.Action.incident_id == incident_id)
        .all()
    )
    reasons = (
        db.query(models.AlertReason)
        .filter(models.AlertReason.incident_id == incident_id)
        .all()
    )

    return {
        "incident": incident,
        "events": events,
        "actions": actions,
        "reasons": reasons,
    }


class ActionRequest(BaseModel):
    type: str

@app.post("/api/incidents/{incident_id}/actions")
def trigger_incident_action(
    incident_id: str,
    req: ActionRequest,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    if req.type not in ["terminate", "resume", "restore", "suspend"]:
        raise HTTPException(status_code=400, detail="Invalid action type")

    print(f"DEBUG: incident.status is {incident.status} for incident {incident.id}")
    if req.type == "restore":
        if incident.status == "Restored":
            raise HTTPException(status_code=409, detail="Incident already restored")
        if incident.status != "Terminated":
            raise HTTPException(status_code=400, detail="Restore is only allowed after Terminated")

    if req.type == "terminate" and incident.status in ["Terminated", "Restored"]:
        raise HTTPException(status_code=409, detail="Incident already terminated")

    # Deduplicate pending/delivered actions
    existing = db.query(models.Action).filter(
        models.Action.incident_id == incident.id,
        models.Action.type == req.type,
        models.Action.status.in_(["pending", "delivered"])
    ).first()
    
    if existing:
        return {"status": "enqueued", "action_id": str(existing.id)}

    payload = None
    if req.type == "restore":
        first_event = db.query(models.Event).filter(models.Event.incident_id == incident.id).order_by(models.Event.timestamp).first()
        if first_event:
            payload = {"restore_timestamp": first_event.timestamp.timestamp() * 1000 - 5000}
            
    # Set status to pending state
    if req.type == "terminate":
        incident.status = "Terminate-Pending"
    elif req.type == "suspend":
        incident.status = "Suspend-Pending"

    action = models.Action(
        incident_id=incident.id,
        type=req.type,
        status="pending",
        payload=payload
    )
    db.add(action)
    db.commit()
    
    return {"status": "enqueued", "action_id": str(action.id)}


@app.post("/api/actions/{action_id}/result")
def action_result(
    action_id: str,
    result: schemas.ActionResult,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token),
):
    action = db.query(models.Action).filter(models.Action.id == action_id).first()

    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    action.status = "complete" if result.status == "success" else "failed"
    action.result = result.model_dump()

    if result.status == "success":
        incident = (
            db.query(models.Incident)
            .filter(models.Incident.id == action.incident_id)
            .first()
        )
        if incident:
            if action.type in ("suspend", "terminate"):
                if incident.contained_after_ms is None:
                    now_utc = datetime.datetime.utcnow()
                    incident.contained_after_ms = int((now_utc - incident.start_time).total_seconds() * 1000)
                    
            if action.type == "suspend":
                incident.status = "Suspended"
            elif action.type == "terminate":
                incident.status = "Terminated"
                first_event = db.query(models.Event).filter(models.Event.incident_id == incident.id).order_by(models.Event.timestamp).first()
                restore_ts = None
                if first_event:
                    restore_ts = first_event.timestamp.timestamp() * 1000 - 5000
                
                existing_restore = db.query(models.Action).filter(
                    models.Action.incident_id == incident.id,
                    models.Action.type == "restore",
                    models.Action.status.in_(["pending", "delivered"])
                ).first()
                
                if not existing_restore:
                    restore_action = models.Action(
                        incident_id=incident.id,
                        type="restore",
                        status="pending",
                        payload={"restore_timestamp": restore_ts}
                    )
                    db.add(restore_action)
            elif action.type == "resume":
                incident.status = "Resumed"
            elif action.type == "restore":
                if result.files_restored is not None and result.files_restored >= 0 and (result.mismatches is None or result.mismatches == 0):
                    incident.status = "Restored"
                if result.files_restored is not None:
                    incident.restored_count = result.files_restored

    db.commit()
    return {"status": "ok"}


@app.websocket("/ws/incidents")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("connected")
    await websocket.close()
