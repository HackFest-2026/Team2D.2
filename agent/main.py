import time
import os
import psutil
import requests
import yaml
import argparse
import datetime
from monitor import AgentMonitor

def create_canaries(sandbox_path):
    canaries = []
    canaries.append(os.path.join(sandbox_path, ".sys_canary.tmp"))
    
    sub = os.path.join(sandbox_path, "docs")
    os.makedirs(sub, exist_ok=True)
    canaries.append(os.path.join(sub, ".sys_canary.tmp"))
    
    for c in canaries:
        with open(c, 'w') as f:
            f.write("canary")
            
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()
    
    import uuid
    run_id = args.run_id if args.run_id else str(uuid.uuid4())
    
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        
    create_canaries(config["sandbox_path"])
    monitor = AgentMonitor(config)
    monitor.start()
    
    import threading
    from vault import Vault
    
    agent_token = os.environ.get("AGENT_TOKEN")
    if not agent_token:
        raise ValueError("Missing AGENT_TOKEN")
    headers = {"x-agent-token": agent_token}
    backend_url = config["backend_url"].rstrip("/")
    
    vault = Vault(config)
    vault_thread = threading.Thread(target=vault.run_loop, daemon=True)
    vault_thread.start()
    
    print(f"[{datetime.datetime.utcnow().isoformat()}] Agent started (PID: {os.getpid()}). Monitoring...", flush=True)
    suspended_pids = set()
    try:
        while True:
            time.sleep(1.0)
            candidates, metrics = monitor.tick()
            
            if metrics is None:
                continue
                
            events = []
            

            
            if candidates:
                if metrics.get("canary_touched", False):
                    eligible_candidates = [c for c in candidates if c["attribution"] in ("handle", "matched")]
                    if len(eligible_candidates) == 1:
                        suspend_target = eligible_candidates[0]
                        if args.dry_run:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [DRY-RUN] Would suspend unique candidate pid {suspend_target['pid']} ({suspend_target['name']})", flush=True)
                        else:
                            try:
                                if suspend_target["pid"] not in suspended_pids:
                                    suspend_target["process"].suspend()
                                    suspended_pids.add(suspend_target["pid"])
                                    print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Suspended unique candidate pid {suspend_target['pid']} ({suspend_target['name']}) due to canary touch", flush=True)
                            except Exception as e:
                                print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to suspend {suspend_target['pid']}: {e}", flush=True)
                    elif len(eligible_candidates) > 1:
                        print(f"[{datetime.datetime.utcnow().isoformat()}] [!] Ambiguous canary alert (Score: 95): {len(eligible_candidates)} eligible candidates out of {len(candidates)} writing. Nobody suspended.", flush=True)

                for c in candidates:
                    pid = c["pid"]
                    is_matched = c["attribution"] in ("handle", "matched")
                    c_metrics = {
                        "io_write_bytes_delta": c["delta"],
                        "watchdog_write_events": metrics["watchdog_write_events"] if is_matched else 0,
                        "watchdog_rename_events": metrics["watchdog_rename_events"] if is_matched else 0,
                        "write_entropy_avg": metrics["write_entropy_avg"] if is_matched else 0.0,
                        "extension_change_ratio": metrics.get("extension_change_ratio", 0.0) if is_matched else 0.0,
                        "distinct_files_modified": metrics["distinct_files_modified"] if is_matched else 0,
                        "canary_touched": metrics.get("canary_touched", False) if is_matched else False,
                        "tick_dt": metrics["tick_dt"]
                    }
                    
                    if c["attribution"] != "ambiguous":
                        events.append({
                            "run_id": run_id,
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "pid": pid,
                            "create_time": c["create_time"],
                            "process_name": c["name"],
                            "cmdline": c["cmdline"],
                            "attribution": c["attribution"],
                            "modified_files_total": c.get("modified_files_total", 0),
                            "first_activity_ts": c.get("first_activity_ts"),
                            "metrics": c_metrics
                        })
                    cmd_str = " ".join(c["cmdline"]) if c["cmdline"] else ""
                    print(f"[{datetime.datetime.utcnow().isoformat()}] [{run_id}] Candidate pid={pid} name={c['name']} cmdline='{cmd_str}' attribution={c['attribution']} write_delta={c['delta']:.0f} wd_writes={metrics['watchdog_write_events']} wd_renames={metrics['watchdog_rename_events']} entropy={metrics['write_entropy_avg']:.2f} ext_ratio={metrics['extension_change_ratio']:.2f} distinct_files={metrics['distinct_files_modified']} canary={metrics['canary_touched']}", flush=True)

                ambiguous_candidates = [c for c in candidates if c["attribution"] == "ambiguous"]
                if ambiguous_candidates:
                    # Emit one pooled event for this tick
                    events.append({
                        "run_id": run_id,
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "pid": None,
                        "create_time": 0.0,
                        "process_name": "host_window",
                        "cmdline": [],
                        "attribution": "pooled",
                        "metrics": metrics
                    })
            
            def execute_actions(actions):
                for act in actions:
                    action_id = act.get("action_id")
                    act_type = act.get("type")
                    target_pid = act.get("pid")
                    
                    success = False
                    if act_type == "suspend":
                        try:
                            p = psutil.Process(target_pid)
                            p.suspend()
                            suspended_pids.add(target_pid)
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Backend requested suspend: pid {target_pid}", flush=True)
                            success = True
                        except psutil.NoSuchProcess:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Process {target_pid} already gone for suspend", flush=True)
                            success = True
                        except Exception as e:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to suspend {target_pid}: {e}", flush=True)
                    elif act_type == "terminate":
                        try:
                            p = psutil.Process(target_pid)
                            p.kill()
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Backend requested terminate: pid {target_pid}", flush=True)
                            success = True
                        except psutil.NoSuchProcess:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Process {target_pid} already gone for terminate", flush=True)
                            success = True
                        except Exception as e:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to terminate {target_pid}: {e}", flush=True)
                    elif act_type == "resume":
                        try:
                            p = psutil.Process(target_pid)
                            p.resume()
                            if target_pid in suspended_pids:
                                suspended_pids.remove(target_pid)
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Backend requested resume: pid {target_pid}", flush=True)
                            success = True
                        except Exception as e:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to resume {target_pid}: {e}", flush=True)
                    elif act_type == "restore":
                        restore_ts = act.get("restore_timestamp")
                        if restore_ts:
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Backend requested restore at timestamp {restore_ts}", flush=True)
                            restored, mismatches = vault.restore(restore_ts)
                            print(f"[{datetime.datetime.utcnow().isoformat()}] [*] Restore complete: {restored} files, {mismatches} mismatches", flush=True)
                            success = True
                            res_payload = {
                                "status": "success",
                                "files_restored": restored,
                                "mismatches": mismatches
                            }
                            try:
                                requests.post(f"{backend_url.rstrip('/')}/api/actions/{action_id}/result", json=res_payload, headers=headers)
                            except:
                                pass
                            continue

                    # Report result back to backend
                    result_url = f"{backend_url.rstrip('/')}/api/actions/{action_id}/result"
                    try:
                        res_payload = {"status": "success" if success else "failed"}
                        requests.post(result_url, json=res_payload, headers=headers)
                    except Exception as e:
                        print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to report action {action_id} result: {e}", flush=True)

            # 1. Post events and process returned actions
            if events:
                try:
                    events_url = f"{backend_url.rstrip('/')}/api/events"
                    res = requests.post(events_url, json=events, headers=headers)
                    if res.status_code == 200:
                        execute_actions(res.json())
                    else:
                        print(f"POST failed with {res.status_code}: {res.text}", flush=True)
                except Exception as e:
                    print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to post events: {e}", flush=True)
            
            # 2. Also fetch any pending actions that were manually triggered
            try:
                action_url = f"{backend_url.rstrip('/')}/api/actions"
                act_res = requests.get(action_url, headers=headers)
                if act_res.status_code == 200:
                    execute_actions(act_res.json())
            except Exception as e:
                print(f"[{datetime.datetime.utcnow().isoformat()}] Failed to fetch actions: {e}", flush=True)

                
    except KeyboardInterrupt:
        monitor.stop()
        print("Agent stopped.", flush=True)

if __name__ == "__main__":
    main()
