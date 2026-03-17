import subprocess, json, time, os, datetime

LOG_PATH = "/var/log/sandbox/events.log"
os.makedirs("/var/log/sandbox", exist_ok=True)

def ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except:
        return ""

def log_event(etype, data):
    entry = {"timestamp": ts(), "event_type": etype, "data": data}
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def snapshot():
    log_event("PROCESS_SNAPSHOT", run("ps aux --no-headers"))
    log_event("NETWORK_CONNECTIONS", run("ss -tulpn"))
    log_event("OPEN_FILES", run("lsof -nP 2>/dev/null | head -80"))
    log_event("LOGGED_USERS", run("who"))
    log_event("CRONTABS", run("cat /etc/crontab 2>/dev/null"))
    log_event("PASSWD_STATE", run("cat /etc/passwd"))
    log_event("SHADOW_READABLE", run("ls -la /etc/shadow"))
    log_event("SUID_BINARIES", run("find / -perm -4000 -type f 2>/dev/null"))
    log_event("ENV_VARS", run("env"))
    log_event("ROUTES", run("ip route"))
    log_event("INTERFACES", run("ip addr show"))
    log_event("LISTENING_PORTS", run("ss -lntp"))
    log_event("RUNNING_SERVICES", run("ps -eo pid,ppid,user,comm,args --no-headers"))

def watch_logs():
    for path in ["/var/log/auth.log", "/var/log/syslog"]:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r") as f:
                f.seek(0, 2)
                for line in f:
                    if line.strip():
                        log_event("SYSLOG", line.strip())
        except:
            pass

print("[monitor] Starting at " + ts(), flush=True)
log_event("MONITOR_START", {"pid": os.getpid(), "hostname": run("hostname")})
snapshot()
interval = 0
while True:
    time.sleep(5)
    interval += 1
    watch_logs()
    if interval % 6 == 0:
        snapshot()
