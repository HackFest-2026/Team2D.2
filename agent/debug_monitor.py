import psutil
import time

history = {}
t0 = time.time()
while time.time() - t0 < 10:
    for p in psutil.process_iter():
        try:
            name = p.name().lower()
            if not name.startswith("python"): continue
            
            io = p.io_counters()
            pid = p.pid
            
            if pid not in history:
                history[pid] = []
                
            history[pid].append((time.time(), io.write_bytes))
            
            if len(history[pid]) >= 2:
                dt = history[pid][-1][0] - history[pid][0][0]
                if dt > 0:
                    delta_per_sec = (history[pid][-1][1] - history[pid][0][1]) / dt
                    if delta_per_sec > 100:
                        print(f"[{time.time():.1f}] Python PID={pid} delta={delta_per_sec:.1f} cmd={p.cmdline()}")
        except Exception as e:
            pass
            
    time.sleep(1)
