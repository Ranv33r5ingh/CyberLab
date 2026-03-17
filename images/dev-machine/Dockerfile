FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y curl ca-certificates gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y nodejs

RUN apt-get install -y \
    git python3 python3-pip \
    rsyslog wget net-tools iproute2 \
    openssh-server cron sudo \
    lsof strace tcpdump nmap psmisc \
    vim nano inotify-tools lsb-release build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install psutil requests --quiet

RUN useradd -m -s /bin/bash devuser && \
    echo "devuser:devpass123" | chpasswd && \
    usermod -aG sudo devuser && \
    useradd -m -s /bin/bash targetuser && \
    echo "targetuser:password123" | chpasswd

RUN mkdir -p /home/devuser/.ssh /home/devuser/.aws /opt/project /var/log/sandbox

RUN ssh-keygen -t rsa -b 2048 -f /home/devuser/.ssh/id_rsa -N "" -q && \
    cat /home/devuser/.ssh/id_rsa.pub >> /home/devuser/.ssh/authorized_keys && \
    chmod 600 /home/devuser/.ssh/id_rsa && \
    chown -R devuser:devuser /home/devuser/.ssh

RUN printf 'API_KEY=sk-live-7f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c\nDB_PASSWORD=Sup3rS3cr3t!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nJWT_SECRET=mySuperSecretJWTKey2024\n' \
    > /home/devuser/.env && chown devuser:devuser /home/devuser/.env

RUN printf 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion=us-east-1\n' \
    > /home/devuser/.aws/credentials && \
    chown -R devuser:devuser /home/devuser/.aws && chmod 600 /home/devuser/.aws/credentials

RUN printf '{"name":"internal-app","version":"1.0.0"}\n' > /opt/project/package.json && \
    printf 'const http = require("http");\nhttp.createServer((req,res)=>{ res.writeHead(200); res.end("Internal App v1.0"); }).listen(3000,"0.0.0.0",()=>console.log("Running on port 3000"));\n' \
    > /opt/project/server.js && chown -R devuser:devuser /opt/project

RUN echo "devuser ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser

COPY monitor.py /opt/monitor.py
COPY variation_engine.py /opt/variation_engine.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 3000
ENTRYPOINT ["/entrypoint.sh"]
