import uuid
import os
import time
import json
import hashlib
import random
import shutil
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argparse

FILE_COUNT = 1000

def seed_sandbox(sandbox):
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
        
    baseline_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_baseline.json")
    with open(baseline_file, "w") as f:
        json.dump(baseline, f, indent=2)
        
    print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S.%f')}] Seeded sandbox.")

def get_files(sandbox_path):
    files = []
    for root, _, filenames in os.walk(sandbox_path):
        for name in filenames:
            if not name.endswith(".locked"):
                files.append(os.path.join(root, name))
    return files

def reset_locked(sandbox_path):
    count = 0
    for root, _, filenames in os.walk(sandbox_path):
        for name in filenames:
            if name.endswith(".locked"):
                locked_path = os.path.join(root, name)
                orig_path = os.path.join(root, name[:-7])
                if os.path.exists(orig_path):
                    os.remove(locked_path)
                else:
                    os.rename(locked_path, orig_path)
                count += 1
    print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S.%f')}] Reset {count} .locked files.")

def get_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def encrypt_file(filepath, chunk_size):
    try:
        orig_hash = get_sha256(filepath)
        key = os.urandom(32)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        tmp_path = filepath + ".tmp"
        with open(filepath, 'rb') as fin, open(tmp_path, 'wb') as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
            
        os.replace(tmp_path, filepath)
        locked_path = filepath + ".locked"
        os.rename(filepath, locked_path)
        return True, orig_hash
    except Exception as e:
        # Silently fail for access denied/missing
        return False, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=False, default="fast")
    parser.add_argument("--run-id", default=str(uuid.uuid4()))
    parser.add_argument("--reseed", action="store_true")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    
    sandbox = os.path.abspath("../sandbox")
    
    if args.reseed:
        seed_sandbox(sandbox)
        return
        
    if args.reset:
        reset_locked(sandbox)
        return
    
    with open("profiles.json") as f:
        profiles = json.load(f)
        
    prof = profiles[args.profile]
    
    run_id = args.run_id
    manifest = {
        "run_id": run_id,
        "profile": args.profile,
        "start_time": time.time(),
        "first_malicious_write_time": None,
        "files_encrypted": 0,
        "encrypted_files": []
    }
    
    def write_manifest(m):
        with open("manifest.json.tmp", "w") as f:
            json.dump(m, f, indent=2)
        for _ in range(5):
            try:
                os.replace("manifest.json.tmp", "manifest.json")
                break
            except Exception:
                time.sleep(0.1)
        
    write_manifest(manifest)
    
    files = get_files(sandbox)
    
    normal_files = [f for f in files if "canary" not in f.lower() and "do_not_touch" not in f.lower()]
    canary_files = [f for f in files if "canary" in f.lower() or "do_not_touch" in f.lower()]
    
    # Randomize the file order so we don't always hit canary last
    random.shuffle(normal_files)
    random.shuffle(canary_files)
    
    target_files = []
    
    if prof.get("touch_canary", False):
        # Insert canary after ~10 files
        target_files.extend(normal_files[:10])
        if canary_files:
            target_files.append(canary_files[0])
        target_files.extend(normal_files[10:])
    else:
        target_files = normal_files
    
    count = 0
    for f in target_files:
        if manifest["first_malicious_write_time"] is None:
            manifest["first_malicious_write_time"] = time.time()
            write_manifest(manifest)
            print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S.%f')}] Starting encryption loop...")
            
        success, orig_hash = encrypt_file(f, prof["chunk_size"])
        if success:
            manifest["files_encrypted"] += 1
            rel_path = os.path.relpath(f, sandbox).replace("\\", "/")
            manifest["encrypted_files"].append(rel_path)
            count += 1
            
            write_manifest(manifest)
                
            if count % 25 == 0:
                print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S.%f')}] Progress: Encrypted {count} files.")
            
        base_delay = prof.get("delay_between_files", 0.0)
        jitter = prof.get("jitter", 0.0)
        if base_delay > 0 or jitter > 0:
            actual_delay = max(0, base_delay + random.uniform(-jitter, jitter))
            time.sleep(actual_delay)
            
    if count % 25 != 0:
        print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S.%f')}] Progress: Encrypted {count} files (Finished).")
        
    write_manifest(manifest)
        
if __name__ == "__main__":
    main()
