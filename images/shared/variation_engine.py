import random, json, subprocess, os, datetime, hashlib, time

MANIFEST_PATH = "/var/log/sandbox/variation_manifest.json"
os.makedirs("/var/log/sandbox", exist_ok=True)

def get_seed():
    hostname = subprocess.check_output(['hostname'], text=True).strip()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    raw = hostname + ts
    return int(hashlib.sha256(raw.encode()).hexdigest(), 16) % (2**32), hostname, ts

SEED, HOSTNAME, RUN_TS = get_seed()
rng = random.Random(SEED)

def run(cmd, ignore_errors=True):
    try:
        return subprocess.run(cmd, shell=True, text=True,
                              capture_output=True, timeout=15).returncode
    except:
        return -1

def log(msg):
    print("[variation_engine] " + msg, flush=True)

manifest = {
    "seed": SEED,
    "hostname": HOSTNAME,
    "run_timestamp": RUN_TS,
    "applied_variations": []
}

def record(category, detail):
    manifest["applied_variations"].append({
        "category": category,
        "detail": detail,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    })

ROLE = os.environ.get("PROFILE_ROLE", "unknown")

# ── POOL 1: EXTRA USERS ────────────────────────────────────────────────────────
# Only use names that won't conflict with Ubuntu system accounts
USER_POOL = [
    ("alice",    "/bin/bash",         True,  "1101"),
    ("bob",      "/bin/bash",         False, "1102"),
    ("charlie",  "/bin/sh",           False, "1103"),
    ("david",    "/bin/bash",         True,  "1104"),
    ("frank",    "/bin/bash",         False, "1106"),
    ("grace",    "/bin/bash",         True,  "1107"),
    ("henry",    "/bin/sh",           False, "1108"),
    ("sysadm",   "/bin/bash",         True,  "1110"),
    ("deployusr","/bin/bash",         True,  "1113"),
    ("auditlog", "/bin/bash",         False, "1114"),
    ("opsuser",  "/bin/bash",         True,  "1115"),
    ("devops",   "/bin/bash",         True,  "1116"),
    ("analyst",  "/bin/bash",         False, "1117"),
    ("monuser",  "/usr/sbin/nologin", False, "1118"),
    ("bkpuser",  "/usr/sbin/nologin", False, "1119"),
]

num_extra_users = rng.randint(2, 4)
selected_users = rng.sample(USER_POOL, num_extra_users)

log("Adding " + str(num_extra_users) + " extra user accounts...")
created_users = []
for (uname, shell, sudo_access, uid) in selected_users:
    ret = run("id " + uname + " 2>/dev/null || useradd -m -s " + shell + " -u " + uid + " " + uname)
    # Verify home dir actually exists before tracking this user
    home = "/home/" + uname
    if not os.path.exists(home):
        os.makedirs(home, exist_ok=True)
        run("chown " + uname + ":" + uname + " " + home + " 2>/dev/null || true")
    if sudo_access:
        run("echo '" + uname + " ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/" + uname)
        run("chmod 0440 /etc/sudoers.d/" + uname)
    passwd = rng.choice(["pass1234", "secure99", "letmein1", "admin2024", "abc123xyz"])
    run("echo '" + uname + ":" + passwd + "' | chpasswd")
    created_users.append((uname, shell, sudo_access, uid))
    record("extra_user", {
        "username": uname, "shell": shell,
        "sudo": sudo_access, "uid": uid, "password": passwd
    })

# ── POOL 2: CRON JOBS ──────────────────────────────────────────────────────────
CRON_POOL_GENERAL = [
    ("*/5 * * * * root /usr/bin/find /tmp -mtime +1 -delete 2>/dev/null",       "cleanup_tmp"),
    ("0 2 * * * root /usr/bin/apt-get update -q 2>/dev/null",                   "apt_update"),
    ("*/15 * * * * root /bin/df -h >> /var/log/disk_usage.log 2>/dev/null",     "disk_monitor"),
    ("0 * * * * root /usr/sbin/logrotate /etc/logrotate.conf 2>/dev/null",      "logrotate"),
    ("*/30 * * * * root ss -tulpn >> /var/log/netstat.log 2>/dev/null",         "netstat_log"),
    ("0 4 * * * root find /var/log -name '*.gz' -mtime +30 -delete",            "log_cleanup"),
    ("*/10 * * * * root /usr/bin/ps aux >> /var/log/ps_snapshot.log 2>/dev/null","ps_snapshot"),
    ("0 0 * * 0 root find / -perm -4000 > /var/log/suid_report.txt 2>/dev/null","suid_report"),
    ("*/3 * * * * root /usr/bin/who >> /var/log/who_log.txt 2>/dev/null",       "who_monitor"),
    ("0 6 * * * root /usr/bin/last > /var/log/last_report.txt 2>/dev/null",     "last_report"),
]

CRON_POOL_BY_ROLE = {
    "nginx web server": [
        ("*/2 * * * * root /usr/sbin/nginx -t 2>/dev/null",                            "nginx_check"),
        ("0 3 * * * root /usr/sbin/logrotate /etc/logrotate.d/nginx 2>/dev/null",      "nginx_logrotate"),
        ("*/10 * * * * root /usr/bin/curl -s http://localhost/ > /dev/null 2>&1",      "web_healthcheck"),
    ],
    "postgresql database server": [
        ("0 1 * * * postgres /opt/backup.sh >> /var/log/backup.log 2>&1",              "db_backup"),
        ("*/5 * * * * postgres pg_isready -q 2>/dev/null",                             "pg_health"),
        ("0 3 * * * root redis-cli BGSAVE 2>/dev/null",                                "redis_persist"),
    ],
    "developer workstation": [
        ("*/15 * * * * root cd /opt/project && git fetch 2>/dev/null",                 "git_fetch"),
        ("0 * * * * root npm audit --prefix /opt/project 2>/dev/null",                 "npm_audit"),
        ("*/30 * * * * root env >> /home/devuser/env_snapshots.log 2>/dev/null",       "env_snapshot"),
    ],
    "jenkins CI runner": [
        ("*/5 * * * * root /opt/builds/run_build.sh >> /var/log/sandbox/build.log 2>&1","build_trigger"),
        ("0 * * * * root find /var/jenkins_home/workspace -mtime +7 -delete 2>/dev/null","workspace_cleanup"),
        ("*/10 * * * * root curl -s http://localhost:8080 > /dev/null 2>&1",            "jenkins_healthcheck"),
    ],
    "postfix mail server": [
        ("0 6 * * * root /usr/sbin/postqueue -f 2>/dev/null",                          "mail_flush"),
        ("*/30 * * * * root find /var/mail -size +10M -delete 2>/dev/null",            "mail_cleanup"),
        ("0 * * * * root /usr/sbin/postfix check >> /var/log/postfix_check.log 2>/dev/null","postfix_check"),
    ],
}

num_crons = rng.randint(2, 4)
cron_selection = rng.sample(CRON_POOL_GENERAL, min(num_crons, len(CRON_POOL_GENERAL)))
role_crons = CRON_POOL_BY_ROLE.get(ROLE, [])
if role_crons:
    cron_selection += rng.sample(role_crons, min(2, len(role_crons)))

log("Adding " + str(len(cron_selection)) + " cron jobs...")
for (cron_line, cron_name) in cron_selection:
    run("echo '" + cron_line + "' >> /etc/crontab")
    record("cron_job", {"entry": cron_line, "name": cron_name})

# ── POOL 3: BASH HISTORY ───────────────────────────────────────────────────────
HISTORY_GENERAL = [
    "sudo su -", "sudo -l", "cat /etc/shadow", "cat /etc/passwd",
    "id", "whoami", "uname -a", "netstat -tulpn", "ss -tulpn", "ps aux",
    "ls -la /etc/", "find / -perm -4000 2>/dev/null",
    "find / -name '*.conf' 2>/dev/null | head -20",
    "grep -r 'password' /etc/ 2>/dev/null", "last -n 20", "w", "history", "env",
]

HISTORY_BY_ROLE = {
    "nginx web server": [
        "nginx -t", "cat /var/www/html/config.php", "cat /var/www/html/.htpasswd",
        "tail -f /var/log/nginx/access.log", "ls -la /var/www/html/",
    ],
    "postgresql database server": [
        "psql -U dbadmin -d mydb", "cat /root/.pgpass", "redis-cli keys '*'",
        "pg_dump -U dbadmin mydb > /tmp/dump.sql",
        "cat /etc/postgresql/14/main/pg_hba.conf",
    ],
    "developer workstation": [
        "cat /home/devuser/.env", "cat /home/devuser/.ssh/id_rsa",
        "git log --oneline -20", "env | grep -i key", "env | grep -i pass",
        "cat /home/devuser/.aws/credentials",
    ],
    "jenkins CI runner": [
        "cat /var/jenkins_home/secrets/initialAdminPassword",
        "cat /var/jenkins_home/credentials.xml", "cat /opt/builds/deploy.sh",
        "find /var/jenkins_home -name '*.xml' 2>/dev/null",
    ],
    "postfix mail server": [
        "cat /var/mail/root", "cat /var/mail/mailuser",
        "cat /etc/postfix/sasl/smtpd.conf", "cat /root/.muttrc",
        "postfix status", "cat /etc/aliases",
    ],
}

history_pool = HISTORY_GENERAL + HISTORY_BY_ROLE.get(ROLE, [])
num_history = rng.randint(8, 15)
history_lines = rng.sample(history_pool, min(num_history, len(history_pool)))
rng.shuffle(history_lines)

# Only write history to users whose home dirs actually exist
history_targets = []
for candidate in ["/root/.bash_history"] + ["/home/" + u[0] + "/.bash_history" for u in created_users]:
    hdir = os.path.dirname(candidate)
    if os.path.isdir(hdir):
        history_targets.append(candidate)

log("Writing bash history to " + str(len(history_targets)) + " users...")
for htarget in history_targets:
    user_lines = rng.sample(history_lines, rng.randint(4, len(history_lines)))
    try:
        with open(htarget, "a") as f:
            for line in user_lines:
                f.write(line + "\n")
        run("chmod 600 " + htarget)
        record("bash_history", {"file": htarget, "entries": len(user_lines)})
    except Exception as e:
        log("WARN: could not write " + htarget + ": " + str(e))

# ── POOL 4: SENSITIVE FILES ────────────────────────────────────────────────────
SENSITIVE_FILES_BY_ROLE = {
    "nginx web server": [
        ("/var/www/html/db_backup.sql",
         "-- MySQL dump\n-- Credentials: dbadmin:Sup3rS3cr3t!\nCREATE DATABASE mydb;\n"),
        ("/var/www/html/install.php",
         "<?php\ndefine('DB_USER','dbadmin');\ndefine('DB_PASS','Sup3rS3cr3t!');\n"),
        ("/etc/nginx/.admin_token",
         "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.faketoken.signature\n"),
    ],
    "postgresql database server": [
        ("/opt/backups/schema.sql",
         "-- Host: db-server-02 User: dbadmin Pass: Sup3rS3cr3t!\nCREATE TABLE users (id serial, email text);\n"),
        ("/root/redis_migration.sh",
         "#!/bin/bash\nredis-cli -h db-server-02 KEYS '*' | xargs redis-cli DEL\n"),
        ("/tmp/pg_export.csv",
         "id,email,password_hash\n1,admin@company.internal,$2b$12$fakehash1\n"),
    ],
    "developer workstation": [
        ("/home/devuser/.aws/credentials",
         "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
        ("/opt/project/.git/config",
         "[remote \"origin\"]\n\turl = https://oauth2:ghp_faketoken123@github.com/company/private-repo.git\n"),
        ("/home/devuser/notes.txt",
         "DB prod: dbadmin/Sup3rS3cr3t!\nJenkins: admin/8a4b9c3d2e1f0a7b\n"),
    ],
    "jenkins CI runner": [
        ("/opt/builds/config.properties",
         "deploy.password=Build@Pr0d123!\ndb.password=Sup3rS3cr3t!\n"),
        ("/tmp/build_env.sh",
         "export DOCKER_REGISTRY_PASS=Reg1stry@2024\nexport NEXUS_PASS=Nex@s2024!\n"),
        ("/var/jenkins_home/workspace/build-prod/Makefile",
         "deploy:\n\tsshpass -p 'Build@Pr0d123!' ssh deploy@prod.internal 'systemctl restart app'\n"),
    ],
    "postfix mail server": [
        ("/etc/postfix/relay_credentials",
         "smtp.company.internal smtprelay:Rel@y2024!\n"),
        ("/var/mail/ops",
         "From: it-ops@company.internal\nSubject: Credentials\nDB: dbadmin/Sup3rS3cr3t!\n"),
        ("/root/mail_migration_log.txt",
         "Relay auth: smtprelay/Rel@y2024!\nDovecot admin: doveadm/D0vecot@dm1n\n"),
    ],
}

role_files = SENSITIVE_FILES_BY_ROLE.get(ROLE, [])
num_files = rng.randint(1, len(role_files)) if role_files else 0
selected_files = rng.sample(role_files, num_files)

log("Creating " + str(num_files) + " role-specific sensitive files...")
for (fpath, content) in selected_files:
    try:
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(content)
        perm = rng.choice([0o644, 0o640, 0o600])
        os.chmod(fpath, perm)
        record("sensitive_file", {"path": fpath, "permissions": oct(perm)})
    except Exception as e:
        log("WARN: could not create " + fpath + ": " + str(e))

# ── POOL 5: AUTH LOG NOISE ─────────────────────────────────────────────────────
AUTH_NOISE_TEMPLATES = [
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Accepted password for {user} from {ip} port {port} ssh2",
    "Failed password for root from {ip} port {port} ssh2",
    "Invalid user {user} from {ip} port {port}",
    "pam_unix(sudo:session): session opened for user root by {user}(uid=0)",
    "sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
]

fake_ips = ["10.0.0." + str(rng.randint(2, 254)) for _ in range(5)]
fake_users = [u[0] for u in created_users] + ["admin", "root", "ubuntu"]
num_noise = rng.randint(5, 15)

log("Injecting " + str(num_noise) + " auth log entries...")
try:
    with open("/var/log/auth.log", "a") as f:
        for _ in range(num_noise):
            template = rng.choice(AUTH_NOISE_TEMPLATES)
            entry = template.format(
                user=rng.choice(fake_users),
                ip=rng.choice(fake_ips),
                port=rng.randint(50000, 65000)
            )
            ts_str = datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")
            f.write(ts_str + " " + HOSTNAME + " sshd[" +
                    str(rng.randint(1000, 9999)) + "]: " + entry + "\n")
    record("auth_log_noise", {"entries_added": num_noise})
except Exception as e:
    log("WARN: auth log write failed: " + str(e))

# ── POOL 6: FILE TIMESTAMPS ────────────────────────────────────────────────────
AGE_TARGETS = [
    ("/var/log/auth.log",   rng.randint(0, 7)),
    ("/etc/passwd",         rng.randint(10, 90)),
    ("/etc/shadow",         rng.randint(1, 30)),
    ("/etc/crontab",        rng.randint(0, 14)),
    ("/root/.bash_history", rng.randint(0, 3)),
]

log("Setting file age variations...")
for (fpath, days_old) in AGE_TARGETS:
    if os.path.exists(fpath):
        run("touch -d '-" + str(days_old) + " days' " + fpath)
        record("file_age", {"path": fpath, "days_old": days_old})

# ── POOL 7: ENV VARS ───────────────────────────────────────────────────────────
ENV_VARS_POOL = [
    ("COMPANY_ENV",      rng.choice(["production", "staging", "development"])),
    ("BACKUP_SERVER",    rng.choice(["backup-01.internal", "backup-02.internal"])),
    ("LOG_LEVEL",        rng.choice(["DEBUG", "INFO", "WARN", "ERROR"])),
    ("MAX_CONNECTIONS",  str(rng.randint(50, 500))),
    ("REGION",           rng.choice(["us-east-1", "eu-west-1", "ap-south-1"])),
    ("DEPLOY_VERSION",   "v" + str(rng.randint(1,9)) + "." + str(rng.randint(0,9)) + "." + str(rng.randint(0,99))),
    ("INTERNAL_API_URL", "http://api.company.internal:" + str(rng.choice([3000,4000,5000,8000,9000]))),
]

num_env = rng.randint(3, len(ENV_VARS_POOL))
selected_env = rng.sample(ENV_VARS_POOL, num_env)
try:
    with open("/etc/environment", "a") as f:
        for (k, v) in selected_env:
            f.write(k + "=" + v + "\n")
    record("env_vars", {"added": {k: v for k, v in selected_env}})
except Exception as e:
    log("WARN: env vars write failed: " + str(e))

# ── WRITE MANIFEST ─────────────────────────────────────────────────────────────
manifest["total_variations"] = len(manifest["applied_variations"])
try:
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    log("Variation complete. Seed=" + str(SEED) + " | " +
        str(manifest["total_variations"]) + " variations applied.")
    log("Manifest written to " + MANIFEST_PATH)
except Exception as e:
    print("[variation_engine] FATAL: could not write manifest: " + str(e), flush=True)
