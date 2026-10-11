# ThreatShield AI

## What it is
ThreatShield AI is an endpoint ransomware defense system that monitors file system activity to detect and contain malicious encryption processes. It evaluates behavior through a scoring engine and takes immediate action to suspend or terminate threats, alongside restoring affected files.

## The problem
Ransomware attacks happen swiftly. Traditional signature-based antivirus solutions often fail to detect novel or mutated ransomware strains. A fast, behavior-driven approach is required to identify ransomware by its core action (encrypting files) and halt it before significant damage is done.

## Architecture
```text
  +------------------+         +------------------+
  |      Agent       |         | Backend / Scoring|
  | (monitor.py)     |  HTTP   | (FastAPI API)    |
  |  - Watchdog I/O  |-------->|  - Rate Engine   |
  |  - Sandbox       |         |  - ML (IsoForest)|
  |  - Actions       |         +------------------+
  +--------+---------+                  |
           |                            | HTTP / WS
           v                            v
  +------------------+         +------------------+
  |      Vault       |         |    Dashboard     |
  | (Safe Storage)   |         |  (React/Vite)    |
  +------------------+         +------------------+
```

## How detection works
- **Signals:** The agent tracks real-time I/O metrics including write bytes rate, rename events, extension change ratios, and write entropy.
- **Canary files:** Hidden `.sys_canary.tmp` files are placed in the sandbox. Any modification to these triggers an immediate score floor.
- **Tiers (40/70/90):** Scores are categorized into Alert (40+), Suspend (70+), and Terminate (90+). A canary touch yields a floor of 85 (Suspend) or 95 (Terminate) based on the overall behavior score.
- **Never-act list:** Trusted paths (e.g. `C:\Windows`) and processes are excluded from automatic suspension or termination (capped at Alert status) to prevent critical system instability.

## Response and restore
When a process breaches the Suspend or Terminate threshold, the backend issues an action command. The agent halts the offending process (using `kernel32.SuspendThread` or terminating it). Files modified by the contained process are then automatically restored from the secure vault.

## How to run
- **Backend:** `docker compose up --build -d` (requires `.env` setup from `.env.example`).
- **Agent:** Run `python agent/main.py` in the activated virtual environment.
- **Dashboard:** Run `npm run dev` in the `dashboard` directory.
- **Demos:** Execute `reset_demo.ps1` to clear the environment, then `demo_attack.ps1` to simulate an attack.

## Evaluation
| Trial | Profile | Detect Delay (s) | Files Lost | Contained After (s) | Final Status | Verify Restore | Max Score | Incident Count |
|-------|---------|------------------|------------|---------------------|--------------|----------------|-----------|----------------|
| fast_1 | fast | 2.75 | 66 | 0.17 | Restored | PASS | 100.0 | 1 |


An earlier batch on a previous code version (10 fast runs): detection 1.8-2.7 s, 40-60 files encrypted before containment (manifest count), restore verified 10/10.

*Note: affected_count is the agent's own tracked-file counter and is a lower bound; files-encrypted figures in the evaluation come from the simulator manifest.*

## Limitations
- tested only against our own simulator
- files lost scales with encryption speed (simulator ~25 files/s)
- the ML (Isolation Forest) is a minor component and rules/canaries carry detection
- one endpoint, one monitored folder
- path-based trust list is a demo shortcut, production should verify signed publishers
- MITRE coverage is T1486 only
- the dashboard polls every second (no push)
- the benign tests were run from PowerShell, which is in a never-act location

## Built with AI assistance
Built with AI assistance (Antigravity IDE); design decisions and verification by the author.
