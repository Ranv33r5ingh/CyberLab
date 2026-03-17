from dotenv import load_dotenv, find_dotenv
import os as _os; load_dotenv(find_dotenv())
import requests, json, subprocess, datetime, os

CALDERA_API_KEY = os.getenv("CALDERA_API_KEY", "ADMIN123")
OPERATION_ID = os.getenv("OPERATION_ID", "")
CONTAINER_NAME = "target-1"
PROFILE_ID = "web-server-01"

BASE_URL = os.getenv("CALDERA_URL", "http://localhost:8888")
HEADERS = {"KEY": CALDERA_API_KEY}

LINK_STATUS = {
    0: "success",
    -2: "discarded",
    -3: "failed",
    1: "collected",
    124: "timeout"
}

def ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

def run_in_container(cmd):
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return "ERROR: " + str(e)

def get_links():
    url = BASE_URL + "/api/v2/operations/" + OPERATION_ID + "/links"
    resp = requests.get(url, headers=HEADERS, timeout=15)
    if resp.status_code != 200:
        print("[!] /links returned " + str(resp.status_code))
        return []
    return resp.json()

def get_report():
    url = BASE_URL + "/api/v2/operations/" + OPERATION_ID + "/report"
    resp = requests.post(url, headers=HEADERS, json={"enable_agent_output": True}, timeout=15)
    if resp.status_code != 200:
        print("[!] /report returned " + str(resp.status_code))
        return {}
    return resp.json()

def collect_system_profile():
    print("[*] Collecting system profile...")
    return {
        "hostname": run_in_container("hostname"),
        "os_release": run_in_container("cat /etc/os-release"),
        "kernel": run_in_container("uname -a"),
        "users": run_in_container("cat /etc/passwd"),
        "groups": run_in_container("cat /etc/group"),
        "processes": run_in_container("ps aux --no-headers"),
        "network": run_in_container("ss -tulpn"),
        "interfaces": run_in_container("ip addr show"),
        "routes": run_in_container("ip route"),
        "open_ports": run_in_container("ss -lntp"),
        "crontabs": run_in_container("cat /etc/crontab 2>/dev/null"),
        "suid_files": run_in_container("find / -perm -4000 -type f 2>/dev/null"),
        "installed_pkgs": run_in_container("dpkg -l 2>/dev/null | awk 'NR>5{print $2,$3}'"),
        "shadow_perms": run_in_container("ls -la /etc/shadow"),
        "env_vars": run_in_container("env"),
        "disk": run_in_container("df -h")
    }

def get_monitor_logs():
    print("[*] Collecting monitor logs...")
    raw = run_in_container("cat /var/log/sandbox/events.log 2>/dev/null | tail -200")
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

def parse_links_into_events(links):
    events = []
    for lnk in links:
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
            "ability_desc": ability.get("description", ""),
            "command": cmd,
            "status_code": status_code,
            "status_meaning": LINK_STATUS.get(status_code, "unknown_" + str(status_code)),
            "output": output_str[:2000],
            "executor": lnk.get("executor", {}).get("name", "sh"),
            "host": lnk.get("host", PROFILE_ID),
            "pid": lnk.get("pid", None),
            "agent_paw": lnk.get("paw", "")
        })
    return events

def build_events_file(attack_events, monitor_logs, system_profile, report):
    print("[*] Building events file...")
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    events_doc = {
        "meta": {
            "profile_id": PROFILE_ID,
            "container": CONTAINER_NAME,
            "operation_id": OPERATION_ID,
            "operation_name": report.get("name", ""),
            "operation_start": report.get("start", ""),
            "operation_finish": report.get("finish", ""),
            "generated_at": ts(),
            "total_attack_events": len(attack_events),
            "total_monitor_events": len(monitor_logs)
        },
        "system_profile": system_profile,
        "attack_events": attack_events,
        "monitor_events": monitor_logs
    }
    filename = "events_" + PROFILE_ID + "_" + timestamp + ".json"
    with open(filename, "w") as f:
        json.dump(events_doc, f, indent=2)
    print("[+] Events file written -> " + filename)
    return filename, timestamp

def build_attack_paths_file(attack_events, system_profile, timestamp, report):
    print("[*] Building attack paths file...")
    chain = []
    seen_tactics = []
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
            "output_preview": ev["output"][:300] if ev["output"] else ""
        })
        if tactic not in seen_tactics:
            seen_tactics.append(tactic)
    impacted_assets = []
    for ev in attack_events:
        if ev["status_code"] == 0:
            cmd = ev["command"].lower()
            if "/etc/shadow" in cmd:
                impacted_assets.append("/etc/shadow")
            if "/etc/passwd" in cmd:
                impacted_assets.append("/etc/passwd")
            if "cron" in cmd:
                impacted_assets.append("/etc/cron")
            if "useradd" in cmd:
                impacted_assets.append("user_accounts")
            if "find" in cmd and "perm" in cmd:
                impacted_assets.append("suid_binaries")
            if "log" in cmd and ("rm" in cmd or "truncate" in cmd):
                impacted_assets.append("/var/log")
    success_count = sum(1 for e in attack_events if e["status_code"] == 0)
    skipped_count = sum(1 for e in attack_events if e["status_code"] == -2)
    fail_count = sum(1 for e in attack_events if e["status_code"] == -3)
    paths_doc = {
        "meta": {
            "profile_id": PROFILE_ID,
            "operation_id": OPERATION_ID,
            "generated_at": ts()
        },
        "summary": {
            "total_links": len(attack_events),
            "successful": success_count,
            "failed": fail_count,
            "skipped_discarded": skipped_count,
            "tactics_covered": seen_tactics,
            "kill_chain_coverage": str(len(seen_tactics)) + " tactics",
            "skipped_abilities": report.get("skipped_abilities", [])
        },
        "attack_chain": chain,
        "impacted_assets": list(set(impacted_assets)),
        "system_context": {
            "hostname": system_profile.get("hostname"),
            "kernel": system_profile.get("kernel"),
            "os": system_profile.get("os_release", "")[:200]
        }
    }
    filename = "attack_paths_" + PROFILE_ID + "_" + timestamp + ".json"
    with open(filename, "w") as f:
        json.dump(paths_doc, f, indent=2)
    print("[+] Attack paths file written -> " + filename)
    return filename

print("=" * 55)
print("  CYBERLAB OUTPUT GENERATOR")
print("  Operation : " + OPERATION_ID)
print("  Target    : " + CONTAINER_NAME + " (" + PROFILE_ID + ")")
print("=" * 55)

print("[*] Fetching links from CALDERA...")
links = get_links()
print("    -> " + str(len(links)) + " links found")

print("[*] Fetching operation report...")
report = get_report()

attack_events = parse_links_into_events(links)
system_profile = collect_system_profile()
monitor_logs = get_monitor_logs()
print("    -> " + str(len(monitor_logs)) + " monitor events found")

events_file, timestamp = build_events_file(attack_events, monitor_logs, system_profile, report)
paths_file = build_attack_paths_file(attack_events, system_profile, timestamp, report)

print("=" * 55)
print("  DONE")
print("  -> " + events_file)
print("  -> " + paths_file)
print("=" * 55)

print("\nATTACK CHAIN SUMMARY:")
success = sum(1 for e in attack_events if e["status_code"] == 0)
print("  Total links  : " + str(len(attack_events)))
print("  Successful   : " + str(success))
print("  Other        : " + str(len(attack_events) - success))
print()
for ev in attack_events:
    icon = "OK" if ev["status_code"] == 0 else "--"
    print("  [" + icon + "] " + ev["tactic"].upper() + " | " + ev["ability_name"] + " | " + ev["status_meaning"])
