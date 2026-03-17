# CyberLab

A local adversarial simulation sandbox that generates labeled attack telemetry across heterogeneous Linux targets using MITRE CALDERA and Docker.

## What It Does

Spins up 5 role-distinct Linux containers, deploys live C2 agents into each, executes a multi-stage MITRE ATT&CK kill chain across all targets simultaneously, and produces structured JSON output per container capturing full attack chains, system profiles, and runtime monitor logs.

Each run produces genuinely varied data via a seeded variation engine that randomizes users, cron jobs, bash history, sensitive file placement, auth log noise, and file timestamps per container per run.

## Architecture

CALDERA C2 Server

- ubuntu-webserver (nginx + php-fpm, port 80)

- ubuntu-dbserver (postgresql + redis, ports 5432/6379)

- ubuntu-devmachine (node.js, port 3000)

- ubuntu-cirunner (jenkins-sim, port 8080)

- ubuntu-mailserver (postfix + dovecot, ports 25/143)

Each container runs:
- A role-specific service stack
- `monitor.py` — system snapshot daemon (processes, network, files every 30s)
- `variation_engine.py` — randomized state seeder at boot
- CALDERA sandcat agent (beacons to C2, executes abilities)

## Output Per Run

For each container:
- `events_{id}_{timestamp}.json` — full system profile + all attack events + monitor logs
- `attack_paths_{id}_{timestamp}.json` — kill chain summary with tactic/technique breakdown

All output goes to `output/`.

## Prerequisites

- Docker Desktop (8+ GB RAM recommended)
- Python 3.11
- CALDERA 5.x cloned into `caldera/`

```bash
pip3.11 install docker requests
```

## Setup

1. Build all 5 images (~15 min first time):

```bash
./build_images.sh
```

2. Start CALDERA (keep this terminal open):

```bash
cd caldera && python3 server.py --insecure
```

3. In CALDERA UI → Campaigns → Adversaries → create/import Linux Multi-Stage Attack adversary with desired abilities.

4. Run simulation (new terminal):

```bash
python3.11 orchestrator.py
```

Runtime: ~10 minutes. Output files written to output/.

### Configuration
Edit the top of orchestrator.py:

```python
CALDERA_API_KEY = "your_key_here"   # from caldera/conf/default.yml
OPERATION_WAIT_SECONDS = 360         # increase if attacks are incomplete
```

### Shutdown

```bash
docker stop target-web-server-01 target-db-server-02 \
    target-dev-machine-03 target-ci-runner-04 target-mail-server-05
# Ctrl+C in CALDERA terminal
```

## Project Structure

- CyberLab/
    - images/
        - shared/
            - monitor.py ---------- # System snapshot daemon
            - variation_engine.py - # Per-run state randomizer
        - web-server/
        - db-server/
        - dev-machine/
        - ci-runner/
        - mail-server/
    - orchestrator.py ------------- # Full multi-target pipeline
    - phase4_output.py ------------ # Single-target output generator
    - build_images.sh ------------- # Build all 5 Docker images
    - output/ --------------------- # Generated data (gitignored)
    - caldera/ -------------------- # CALDERA submodule (gitignored)

### Diversity Per Run
The variation engine seeds randomness from hostname + UTC timestamp, producing different combinations each run:

2–4 extra user accounts with randomized shells and sudo access

2–5 role-appropriate cron jobs

4–15 bash history entries per user (role-specific command pools)

1–3 role-specific sensitive files (credentials, keys, configs)

5–15 auth log noise entries

File timestamp aging (0–90 days old)

3–7 environment variable additions

No two runs produce identical system profiles.