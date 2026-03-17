#!/bin/bash
mkdir -p /var/log/sandbox
chmod 777 /var/log/sandbox
service rsyslog start 2>/dev/null || true
mkdir -p /var/run/postgresql /var/log/postgresql
chown postgres:postgres /var/run/postgresql /var/log/postgresql
su postgres -c "/usr/lib/postgresql/14/bin/pg_ctl \
    -D /var/lib/postgresql/14/main \
    -l /var/log/postgresql/main.log start" 2>/dev/null || true
sleep 5
su postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='dbadmin'\" | grep -q 1 || \
    psql -c \"CREATE USER dbadmin WITH PASSWORD 'Sup3rS3cr3t!';\"" 2>/dev/null || true
su postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='mydb'\" | grep -q 1 || \
    psql -c \"CREATE DATABASE mydb OWNER dbadmin;\"" 2>/dev/null || true
sed -i 's/^host.*all.*all.*md5/host all all all trust/' \
    /etc/postgresql/14/main/pg_hba.conf 2>/dev/null || true
redis-server --daemonize yes --bind 0.0.0.0 2>/dev/null || true
python3 -u /opt/monitor.py >> /var/log/sandbox/monitor_stdout.log 2>&1 &
echo "[db-server] postgresql + redis + monitor launched"
python3 /opt/variation_engine.py >> /var/log/sandbox/variation.log 2>&1
echo "[db-server] Variation engine complete"
tail -f /dev/null