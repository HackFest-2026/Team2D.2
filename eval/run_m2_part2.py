import subprocess
import time
import os
import sys

venv_python = os.path.abspath(r"..\.venv\Scripts\python.exe")
simulator_dir = os.path.abspath("../simulator")
agent_dir = os.path.abspath("../agent")
benign_dir = os.path.abspath("benign")

print("\n=== M2 Verification c: Real Mode Canary Touch ===")
subprocess.run([venv_python, "seed.py"], cwd=simulator_dir)
agent = subprocess.Popen([venv_python, "main.py"], cwd=agent_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
subprocess.run([venv_python, "simulate.py", "--profile", "canary-touching"], cwd=simulator_dir)
time.sleep(2)
agent.terminate()
print(agent.stdout.read())
with open(os.path.join(simulator_dir, "manifest.json")) as f: print(f.read())

print("\n=== M2 Verification d: Ambiguous Canary (Writer + Simulator) ===")
subprocess.run([venv_python, "seed.py"], cwd=simulator_dir)
agent = subprocess.Popen([venv_python, "main.py"], cwd=agent_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(2)
writer = subprocess.Popen([venv_python, "writer.py"], cwd=benign_dir)
sim = subprocess.Popen([venv_python, "simulate.py", "--profile", "canary-touching"], cwd=simulator_dir)
time.sleep(4)
writer.terminate()
sim.terminate()
agent.terminate()
print(agent.stdout.read())
