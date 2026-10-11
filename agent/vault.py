import os
import shutil
import hashlib
import time
import json
import requests
import datetime

class Vault:
    def __init__(self, config):
        self.sandbox = config["sandbox_path"]
        self.vault = config["vault_path"]
        self.api_url = config["backend_url"].rstrip("/")
        self.token = config["api_token"]
        os.makedirs(self.vault, exist_ok=True)
        self.vault_index_file = os.path.join(self.vault, "index.json")
        self.index = self._load_index()
        self.was_frozen = False

    def _load_index(self):
        if os.path.exists(self.vault_index_file):
            with open(self.vault_index_file, "r") as f:
                return json.load(f)
        return {}

    def _save_index(self):
        with open(self.vault_index_file, "w") as f:
            json.dump(self.index, f, indent=2)

    def _get_sha256(self, filepath):
        h = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _get_freeze_incident(self):
        try:
            headers = {"x-agent-token": self.token}
            r = requests.get(f"{self.api_url}/api/incidents", headers=headers, timeout=2)
            if r.status_code == 200:
                incidents = r.json()
                for inc in incidents:
                    if inc["max_score"] >= 40.0 and inc["status"] not in ("Terminated", "Restored", "Resumed"):
                        return inc
                # If no freeze condition, check for recently resumed/restored for unfreeze reason
                for inc in reversed(incidents):
                    if inc["status"] in ("Resumed", "Restored"):
                        return {"unfreeze_reason": inc["status"].lower()}
            return None
        except Exception as e:
            print(f"[{datetime.datetime.utcnow().isoformat()}] [Vault] Failed to check incident status: {e}")
            return {"id": "unknown_error"} # Fail safe

    def backup(self):
        freeze_inc = self._get_freeze_incident()
        currently_frozen = freeze_inc is not None and "unfreeze_reason" not in freeze_inc
        
        if currently_frozen and not self.was_frozen:
            inc_id = freeze_inc.get("id", "unknown")
            print(f"[{datetime.datetime.utcnow().isoformat()}] [Vault] FROZEN incident={inc_id}", flush=True)
            self.was_frozen = True
        elif not currently_frozen and self.was_frozen:
            reason = freeze_inc.get("unfreeze_reason", "unknown") if freeze_inc else "unknown"
            # It could be 'resumed' or 'restored'
            reason = reason.replace("d", "") if reason.endswith("ed") else reason # resume, restore
            print(f"[{datetime.datetime.utcnow().isoformat()}] [Vault] UNFROZEN reason={reason}", flush=True)
            self.was_frozen = False

        if currently_frozen:
            return

        backed_up = 0
        for root, _, files in os.walk(self.sandbox):
            for name in files:
                if name.endswith(".locked") or "canary" in name.lower() or "do_not_touch" in name.lower():
                    continue
                filepath = os.path.join(root, name)
                rel_path = os.path.relpath(filepath, self.sandbox).replace("\\", "/")
                
                file_hash = self._get_sha256(filepath)
                if not file_hash:
                    continue

                if rel_path not in self.index:
                    self.index[rel_path] = []

                # If this exact version is the latest we have, do nothing.
                if self.index[rel_path] and self.index[rel_path][-1]["hash"] == file_hash:
                    continue

                dest_dir = os.path.join(self.vault, rel_path)
                os.makedirs(dest_dir, exist_ok=True)
                
                ts = int(time.time() * 1000)
                dest_file = os.path.join(dest_dir, f"{ts}_{file_hash}")
                
                try:
                    shutil.copy2(filepath, dest_file)
                    self.index[rel_path].append({
                        "ts": ts,
                        "hash": file_hash,
                        "vault_path": dest_file
                    })
                    backed_up += 1
                except Exception as e:
                    pass
        if backed_up > 0:
            self._save_index()

    def restore(self, restore_ts):
        files_restored = 0
        mismatches = 0
        
        # 1. Clean up .locked files
        import time
        for root, _, files in os.walk(self.sandbox):
            for name in files:
                if name.endswith(".locked"):
                    file_path = os.path.join(root, name)
                    for _ in range(5):
                        try:
                            os.remove(file_path)
                            break
                        except Exception as e:
                            time.sleep(0.2)
        
        # 2. Restore modified/missing files
        for rel_path, versions in self.index.items():
            # Find the newest version strictly older than restore_ts
            target_version = None
            for v in reversed(versions):
                if v["ts"] < restore_ts:
                    target_version = v
                    break
            
            # Fallback to the oldest version if no version is strictly older
            if not target_version and versions:
                target_version = versions[0]
            
            if not target_version:
                continue
                
            sandbox_file = os.path.join(self.sandbox, rel_path)
            current_hash = self._get_sha256(sandbox_file) if os.path.exists(sandbox_file) else None
            
            if current_hash != target_version["hash"]:
                try:
                    shutil.copy2(target_version["vault_path"], sandbox_file)
                    
                    # Verify
                    new_hash = self._get_sha256(sandbox_file)
                    if new_hash == target_version["hash"]:
                        files_restored += 1
                    else:
                        mismatches += 1
                except Exception as e:
                    mismatches += 1

        return files_restored, mismatches

    def run_loop(self):
        self.backup() # Baseline
        while True:
            time.sleep(10.0)
            self.backup()
