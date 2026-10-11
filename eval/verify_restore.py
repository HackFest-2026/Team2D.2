import os
import sys
import json
import hashlib

def get_sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

from pathlib import Path

def main():
    base_dir = Path(__file__).resolve().parent.parent
    sandbox_path = str(base_dir / "sandbox")
    baseline_path = str(base_dir / "simulator" / "sandbox_baseline.json")

    with open(baseline_path, "r") as f:
        baseline = json.load(f)

    matching = 0
    missing = 0
    corrupted = 0
    locked = 0

    # Check baseline files
    for rel_path, expected_hash in baseline.items():
        full_path = os.path.join(sandbox_path, rel_path)
        if not os.path.exists(full_path):
            missing += 1
        else:
            actual_hash = get_sha256(full_path)
            if actual_hash == expected_hash:
                matching += 1
            else:
                corrupted += 1

    # Check for leftover .locked files
    for root, _, files in os.walk(sandbox_path):
        for file in files:
            if file.endswith(".locked"):
                locked += 1

    print(f"matching: {matching}")
    print(f"missing: {missing}")
    print(f"corrupted: {corrupted}")
    print(f"leftover .locked: {locked}")

    if missing == 0 and corrupted == 0 and locked == 0 and matching == len(baseline):
        print("PASS")
    else:
        print("FAIL")

if __name__ == "__main__":
    main()
