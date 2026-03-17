#!/bin/bash
mkdir -p /var/log/sandbox
chmod 777 /var/log/sandbox
service rsyslog start 2>/dev/null || true
mkdir -p /var/spool/postfix/dev
postfix check 2>/dev/null && postfix start 2>/dev/null || true
sleep 2
dovecot 2>/dev/null || true
python3 -u /opt/monitor.py >> /var/log/sandbox/monitor_stdout.log 2>&1 &
echo "[mail-server] postfix + dovecot + monitor launched"
python3 /opt/variation_engine.py >> /var/log/sandbox/variation.log 2>&1
echo "[mail-server] Variation engine complete"
tail -f /dev/null