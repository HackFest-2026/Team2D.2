import subprocess
import time
import os

print("=== M2 Verification a: Dry-run Fast Profile ===")
subprocess.run([r"..\.venv\Scripts\python.exe", "seed.py"], cwd="../simulator")
agent = subprocess.Popen([r"..\.venv\Scripts\python.exe", "main.py", "--dry-run"], cwd="../agent", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
subprocess.run([r"..\.venv\Scripts\python.exe", "simulate.py", "--profile", "fast"], cwd="../simulator")
time.sleep(2)
agent.terminate()
print(agent.stdout.read())
with open("../simulator/manifest.json") as f: print(f.read())

print("\n=== M2 Verification b: Dry-run Slow-and-low Profile ===")
subprocess.run([r"..\.venv\Scripts\python.exe", "seed.py"], cwd="../simulator")
agent = subprocess.Popen([r"..\.venv\Scripts\python.exe", "main.py", "--dry-run"], cwd="../agent", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
# We don't want to wait forever for slow-and-low, just run it for 4 seconds then kill it
sim = subprocess.Popen([r"..\.venv\Scripts\python.exe", "simulate.py", "--profile", "slow-and-low"], cwd="../simulator")
time.sleep(4)
sim.terminate()
agent.terminate()
print(agent.stdout.read())
with open("../simulator/manifest.json") as f: print(f.read())

print("\n=== M2 Verification c: Real Mode Canary Touch ===")
subprocess.run([r"..\.venv\Scripts\python.exe", "seed.py"], cwd="../simulator")
agent = subprocess.Popen([r"..\.venv\Scripts\python.exe", "main.py"], cwd="../agent", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
subprocess.run([r"..\.venv\Scripts\python.exe", "simulate.py", "--profile", "canary-touching"], cwd="../simulator")
time.sleep(2)
agent.terminate()
print(agent.stdout.read())

print("\n=== M2 Verification d: Ambiguous Canary (Writer + Simulator) ===")
subprocess.run([r"..\.venv\Scripts\python.exe", "seed.py"], cwd="../simulator")
agent = subprocess.Popen([r"..\.venv\Scripts\python.exe", "main.py"], cwd="../agent", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
writer = subprocess.Popen([r"..\..\.venv\Scripts\python.exe", "writer.py"], cwd="benign")
sim = subprocess.Popen([r"..\.venv\Scripts\python.exe", "simulate.py", "--profile", "canary-touching"], cwd="../simulator")
time.sleep(3)
writer.terminate()
sim.terminate()
agent.terminate()
print(agent.stdout.read())

