#!/bin/bash
mkdir -p /var/log/sandbox
chmod 777 /var/log/sandbox
node /opt/project/server.js >> /var/log/sandbox/node.log 2>&1 &
echo "[dev-machine] Node.js launched (PID $!)"
python3 -u /opt/monitor.py >> /var/log/sandbox/monitor_stdout.log 2>&1 &
echo "[dev-machine] Monitor launched"
python3 /opt/variation_engine.py >> /var/log/sandbox/variation.log 2>&1
echo "[dev-machine] Variation engine complete"
tail -f /dev/null