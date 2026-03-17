#!/bin/bash
mkdir -p /var/log/sandbox
chmod 777 /var/log/sandbox
cd /var/jenkins_home && python3 -u -m http.server 8080 >> /var/log/sandbox/jenkins.log 2>&1 &
echo "[ci-runner] Jenkins HTTP launched (PID $!)"
python3 -u /opt/monitor.py >> /var/log/sandbox/monitor_stdout.log 2>&1 &
echo "[ci-runner] Monitor launched"
python3 /opt/variation_engine.py >> /var/log/sandbox/variation.log 2>&1
echo "[ci-runner] Variation engine complete"
tail -f /dev/null