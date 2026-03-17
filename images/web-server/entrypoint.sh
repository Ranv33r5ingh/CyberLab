#!/bin/bash
mkdir -p /var/log/sandbox
chmod 777 /var/log/sandbox
service rsyslog start 2>/dev/null || true
mkdir -p /var/run/php
php-fpm8.1 -D 2>/dev/null || true
sleep 1
nginx 2>/dev/null || true
python3 -u /opt/monitor.py >> /var/log/sandbox/monitor_stdout.log 2>&1 &
echo "[web-server] nginx + php-fpm + monitor launched"
python3 /opt/variation_engine.py >> /var/log/sandbox/variation.log 2>&1
echo "[web-server] Variation engine complete"
tail -f /dev/null