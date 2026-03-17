#!/bin/bash
set -e
echo "Copying shared files to all image directories..."
for dir in web-server db-server dev-machine ci-runner mail-server; do
    cp /Users/ranveersingh/Desktop/CyberLab/images/shared/monitor.py /Users/ranveersingh/Desktop/CyberLab/images/$dir/monitor.py
    cp /Users/ranveersingh/Desktop/CyberLab/images/shared/variation_engine.py /Users/ranveersingh/Desktop/CyberLab/images/$dir/variation_engine.py
done

echo ""
echo "Building 5 images..."
echo ""

echo "[1/5] Building ubuntu-webserver..."
docker build -t ubuntu-webserver:latest /Users/ranveersingh/Desktop/CyberLab/images/web-server/ && echo "  Done."

echo "[2/5] Building ubuntu-dbserver..."
docker build -t ubuntu-dbserver:latest /Users/ranveersingh/Desktop/CyberLab/images/db-server/ && echo "  Done."

echo "[3/5] Building ubuntu-devmachine..."
docker build -t ubuntu-devmachine:latest /Users/ranveersingh/Desktop/CyberLab/images/dev-machine/ && echo "  Done."

echo "[4/5] Building ubuntu-cirunner..."
docker build -t ubuntu-cirunner:latest /Users/ranveersingh/Desktop/CyberLab/images/ci-runner/ && echo "  Done."

echo "[5/5] Building ubuntu-mailserver..."
docker build -t ubuntu-mailserver:latest /Users/ranveersingh/Desktop/CyberLab/images/mail-server/ && echo "  Done."

echo ""
echo "All images built:"
docker images | grep -E "ubuntu-webserver|ubuntu-dbserver|ubuntu-devmachine|ubuntu-cirunner|ubuntu-mailserver"
