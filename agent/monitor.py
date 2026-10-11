import time
import os
import psutil
import threading
import math
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4096)
        if not data: return 0.0
        entropy = 0
        length = len(data)
        for x in range(256):
            p_x = float(data.count(x)) / length
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    except Exception:
        return 0.0

class SandboxHandler(FileSystemEventHandler):
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
        
    def _handle_event(self, event):
        with self.lock:
            self.events.append((time.time(), event))

    def on_created(self, event):
        if not event.is_directory: self._handle_event(event)
    def on_modified(self, event):
        if not event.is_directory: self._handle_event(event)
    def on_deleted(self, event):
        if not event.is_directory: self._handle_event(event)
    def on_moved(self, event):
        if not event.is_directory: self._handle_event(event)

class AgentMonitor:
    def __init__(self, config):
        self.config = config
        self.sandbox_path = os.path.abspath(config["sandbox_path"]).lower()
        self.agent_pid = os.getpid()
        self.handler = SandboxHandler()
        self.observer = Observer()
        self.observer.schedule(self.handler, self.sandbox_path, recursive=True)
        self.io_history = defaultdict(list)
        self.recent_events = []
        self.last_tick = time.time()
        self.tick_dts = []
        self.proc_cache = {}
        # Cumulative per-process modified-file sets: key=(pid, create_time) -> set of rel paths
        self.process_modified_files = defaultdict(set)
        # First activity timestamp per process: key=(pid, create_time) -> epoch float
        self.process_first_activity = {}
        
        self.excluded_pids = {0, 4, self.agent_pid}
        try:
            agent = psutil.Process(self.agent_pid)
            for c in agent.children(recursive=True):
                self.excluded_pids.add(c.pid)
            for p in agent.parents():
                self.excluded_pids.add(p.pid)
        except:
            pass

    def is_protected(self, p, pid):
        if pid in self.excluded_pids: return True
        if pid in self.proc_cache: return self.proc_cache[pid]["is_protected"]
        
        try:
            name = p.name()
            exe = p.exe()
            cmdline = p.cmdline()
            create_time = p.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True
            
        prot = False
        if name and name.lower() in [n.lower() for n in self.config.get("exclude_names", [])]:
            prot = True
        else:
            for ex in self.config.get("exclude_cmdlines", []):
                if any(ex.lower() in arg.lower() for arg in cmdline):
                    prot = True
                    break
        
        never_act = False
        if exe:
            exe_lower = exe.lower()
            if exe_lower.startswith("c:\\windows\\"):
                never_act = True
            else:
                for path in self.config.get("never_act_paths", []):
                    if exe_lower.startswith(path.lower()):
                        never_act = True
                        break
                        
        never_act_names = ["onedrive.exe", "onedrive.sync.service.exe", "msmpeng.exe", "searchindexer.exe", "searchprotocolhost.exe", "svchost.exe", "explorer.exe", "dwm.exe", "dropbox.exe", "googledrivefs.exe"] + [n.lower() for n in self.config.get("never_act_names", [])]
        if name and name.lower() in never_act_names:
            never_act = True
                    
        self.proc_cache[pid] = {
            "name": name,
            "cmdline": cmdline,
            "create_time": create_time,
            "is_protected": prot,
            "is_never_act": never_act
        }
        return prot

    def start(self):
        self.observer.start()
        
    def stop(self):
        self.observer.stop()
        self.observer.join()

    def tick(self):
        t0 = time.time()
        tick_dt = t0 - self.last_tick
        self.last_tick = t0
        
        self.tick_dts.append(tick_dt)
        if len(self.tick_dts) >= 10:
            avg_dt = sum(self.tick_dts) / len(self.tick_dts)
            print(f"Rolling tick_dt (10s avg): {avg_dt:.3f}s", flush=True)
            self.tick_dts = []
        
        with self.handler.lock:
            new_events = self.handler.events[:]
            self.handler.events = []
            
        current_time = time.time()
        self.recent_events.extend(new_events)
        self.recent_events = [ev for ev in self.recent_events if current_time - ev[0] <= 5.0]
        
        write_count = 0
        rename_count = 0
        ext_changes = 0
        canary_touched = False
        file_paths = {}
        
        for ts, ev in self.recent_events:
            if ev.event_type in ('modified', 'created'):
                write_count += 1
                if ev.src_path not in file_paths:
                    file_paths[ev.src_path] = ev.src_path
                if "canary" in ev.src_path.lower() or "do_not_touch" in ev.src_path.lower():
                    canary_touched = True
            elif ev.event_type == 'moved':
                rename_count += 1
                _, ext1 = os.path.splitext(ev.src_path)
                _, ext2 = os.path.splitext(ev.dest_path)
                if ext1.lower() != ext2.lower():
                    ext_changes += 1
                if "canary" in ev.dest_path.lower() or "do_not_touch" in ev.dest_path.lower() or "canary" in ev.src_path.lower() or "do_not_touch" in ev.src_path.lower():
                    canary_touched = True
                
                for k, v in list(file_paths.items()):
                    if v == ev.src_path:
                        file_paths[k] = ev.dest_path
                file_paths[ev.src_path] = ev.dest_path
                file_paths[ev.dest_path] = ev.dest_path
                    
        ext_ratio = (ext_changes / rename_count) if rename_count > 0 else 0.0
        entropies = [calculate_entropy(p) for p in set(file_paths.values()) if os.path.exists(p)]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        metrics = {
            "watchdog_write_events": write_count,
            "watchdog_rename_events": rename_count,
            "write_entropy_avg": avg_entropy,
            "extension_change_ratio": ext_ratio,
            "distinct_files_modified": len(set(file_paths.values())),
            "canary_touched": canary_touched,
            "tick_dt": tick_dt
        }
        
        if write_count == 0 and rename_count == 0:
            return None, metrics
            
        candidates = []
        current_pids = set()
        
        for p in psutil.process_iter(['pid']):
            pid = p.info['pid']
            current_pids.add(pid)
            if self.is_protected(p, pid): continue
            
            try:
                io = p.io_counters()
                if not io: continue
                curr_write = io.write_bytes
                
                history = self.io_history[pid]
                history.append((current_time, curr_write))
                history = [h for h in history if current_time - h[0] <= 5.0]
                self.io_history[pid] = history
                
                delta_per_sec = 0
                if len(history) >= 2:
                    total_dt = history[-1][0] - history[0][0]
                    if total_dt > 0:
                        delta_per_sec = (history[-1][1] - history[0][1]) / total_dt
                        
                if delta_per_sec > self.config.get("write_bytes_threshold", 500000):
                    pc = self.proc_cache[pid]
                    proc_key = (pid, pc["create_time"])

                    # Record first activity timestamp for this process
                    if proc_key not in self.process_first_activity:
                        # Use the earliest sandbox event time in the current window
                        earliest_event_ts = None
                        for ts_ev, _ in self.recent_events:
                            if earliest_event_ts is None or ts_ev < earliest_event_ts:
                                earliest_event_ts = ts_ev
                        self.process_first_activity[proc_key] = earliest_event_ts or current_time

                    # Add current distinct files to cumulative set
                    for fp in set(file_paths.values()):
                        try:
                            rel = os.path.relpath(fp, self.sandbox_path).replace("\\", "/")
                            if rel.endswith(".tmp"):
                                rel = rel[:-4]
                            elif rel.endswith(".locked"):
                                rel = rel[:-7]
                            self.process_modified_files[proc_key].add(rel)
                        except ValueError:
                            pass

                    print(f"[DEBUG] PID {pid} first_activity_ts: {self.process_first_activity[proc_key]} (time.time()={current_time}, delta={current_time - self.process_first_activity[proc_key]})", flush=True)

                    candidates.append({
                        "process": p,
                        "pid": pid,
                        "create_time": pc["create_time"],
                        "name": pc["name"],
                        "cmdline": pc["cmdline"],
                        "delta": delta_per_sec,
                        "modified_files_total": len(self.process_modified_files[proc_key]),
                        "first_activity_ts": self.process_first_activity[proc_key],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        # Clean up history and cache
        new_io = defaultdict(list)
        for pid, v in self.io_history.items():
            if pid in current_pids:
                new_io[pid] = v
        self.io_history = new_io
        self.proc_cache = {pid: v for pid, v in self.proc_cache.items() if pid in current_pids}
        
        candidates.sort(key=lambda x: x["delta"], reverse=True)
        
        filtered = []
        for c in candidates[:5]:
            sandbox_open = False
            try:
                open_files = c["process"].open_files()
                for of in open_files:
                    if os.path.commonpath([of.path.lower(), self.sandbox_path]) == self.sandbox_path:
                        sandbox_open = True
                        break
            except:
                pass
                
            c["sandbox_open"] = sandbox_open
            if sandbox_open or (write_count > 0 or rename_count > 0):
                filtered.append(c)
                
        if not filtered:
            return [], metrics
            
        # Determine unique candidate: largest write delta with at least 3x the runner-up
        if len(filtered) == 1:
            filtered[0]["attribution"] = "handle" if filtered[0]["sandbox_open"] else "matched"
        else:
            first = filtered[0]
            second = filtered[1]
            if first["delta"] >= 3 * second["delta"]:
                first["attribution"] = "handle" if first["sandbox_open"] else "matched"
                for c in filtered[1:]:
                    c["attribution"] = "ambiguous"
            else:
                for c in filtered:
                    c["attribution"] = "ambiguous"
                    
        for c in filtered:
            pc = self.proc_cache.get(c["pid"])
            if pc and pc.get("is_never_act"):
                c["attribution"] = "never_act"
        return filtered, metrics
