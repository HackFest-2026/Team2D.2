import os
import random
import shutil
import json
import hashlib

FILE_COUNT = 1000

def get_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

base_dir = os.path.dirname(os.path.abspath(__file__))
sandbox = os.path.abspath(os.path.join(base_dir, "../sandbox"))

if os.path.exists(sandbox):
    shutil.rmtree(sandbox, ignore_errors=True)
os.makedirs(sandbox, exist_ok=True)

extensions = [".docx", ".txt", ".jpg", ".csv"]
baseline = {}
for i in range(FILE_COUNT):
    ext = random.choice(extensions)
    path = os.path.join(sandbox, f"file_{i}{ext}")
    with open(path, "wb") as f:
        f.write(b"Hello world! " * 100 + os.urandom(1024))
    rel = os.path.relpath(path, sandbox).replace("\\", "/")
    baseline[rel] = get_sha256(path)

canary_sub = os.path.join(sandbox, "docs")
os.makedirs(canary_sub, exist_ok=True)
for c in [os.path.join(sandbox, ".sys_canary.tmp"), os.path.join(canary_sub, ".sys_canary.tmp")]:
    with open(c, 'w') as f:
        f.write("canary")
    rel = os.path.relpath(c, sandbox).replace("\\", "/")
    baseline[rel] = get_sha256(c)

baseline_file = os.path.join(base_dir, "sandbox_baseline.json")
with open(baseline_file, "w") as f:
    json.dump(baseline, f, indent=2)

print("Seeded sandbox.")
