from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

class EventMetrics(BaseModel):
    io_write_bytes_delta: float = 0.0
    watchdog_write_events: int = 0
    watchdog_rename_events: int = 0
    write_entropy_avg: float = 0.0
    extension_change_ratio: float = 0.0
    distinct_files_modified: int = 0
    canary_touched: bool = False

class IncomingEvent(BaseModel):
    timestamp: datetime
    pid: Optional[int] = None
    create_time: Optional[float] = 0.0
    process_name: Optional[str] = "host_window"
    cmdline: Optional[List[str]] = []
    attribution: Optional[str] = None  # handle | matched | pooled | ambiguous
    modified_files_total: Optional[int] = 0
    first_activity_ts: Optional[float] = None
    metrics: EventMetrics

class ActionSchema(BaseModel):
    action_id: str
    pid: Optional[int] = None
    create_time: Optional[float] = 0.0
    type: str
    restore_timestamp: Optional[float] = None

class ActionResult(BaseModel):
    status: str
    files_restored: Optional[int] = None
    mismatches: Optional[int] = None
