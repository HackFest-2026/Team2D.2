import os
import sys
import json
import time
import hashlib
import argparse

def get_sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def count_locked(sandbox_path):
    count = 0
    for root, _, files in os.walk(sandbox_path):
        for f in files:
            if f.endswith(".locked"):
                count += 1
    return count

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()

    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent
    sandbox_path = str(base_dir / "sandbox")
    manifest_path = str(base_dir / "simulator" / "manifest.json")
    baseline_path = str(base_dir / "simulator" / "sandbox_baseline.json")

    with open(manifest_path) as f:
        manifest = json.load(f)

    if manifest.get("run_id") != args.run_id:
        print(f"Warning: manifest run_id ({manifest.get('run_id')}) does not match requested {args.run_id}")

    with open(baseline_path) as f:
        baseline = json.load(f)

    files_encrypted_manifest = manifest.get("files_encrypted", 0)

    # Missing or changed files
    missing_or_changed = []
    for rel_path, expected_hash in baseline.items():
        full_path = os.path.join(sandbox_path, rel_path)
        if not os.path.exists(full_path):
            missing_or_changed.append(rel_path)
        else:
            actual_hash = get_sha256(full_path)
            if actual_hash != expected_hash:
                missing_or_changed.append(rel_path)

    print(f"Missing or changed baseline files: {len(missing_or_changed)}")
    if len(missing_or_changed) <= 10:
        for f in missing_or_changed:
            print(f"  - {f}")

    locked_0 = count_locked(sandbox_path)
    print(f"Files encrypted (manifest): {files_encrypted_manifest}")
    print(f"Files .locked on disk (+0s): {locked_0}")

    print("Waiting 10s to check for plateau...")
    time.sleep(10)
    locked_10 = count_locked(sandbox_path)
    print(f"Files .locked on disk (+10s): {locked_10}")

    print("Plateau achieved!" if locked_0 == locked_10 else "Warning: Encryption did not plateau!")

if __name__ == "__main__":
    main()
