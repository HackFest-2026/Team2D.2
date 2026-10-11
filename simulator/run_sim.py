import subprocess
import sys

profile = sys.argv[1]
with open("sim_pid.txt", "w") as f, open("sim_err.log", "w") as err:
    p = subprocess.Popen(
        [sys.executable, "simulate.py", "--profile", profile, "--run-id", sys.argv[2]], 
        cwd=r".", 
        stdout=subprocess.DEVNULL,
        stderr=err,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    )
    f.write(str(p.pid))
