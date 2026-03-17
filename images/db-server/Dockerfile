FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    postgresql-14 postgresql-client-14 \
    redis-server \
    rsyslog python3 python3-pip \
    curl wget net-tools iproute2 \
    openssh-server cron sudo \
    lsof strace tcpdump nmap psmisc \
    vim nano git inotify-tools lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install psutil requests --quiet

RUN useradd -m -s /bin/bash targetuser && \
    echo "targetuser:password123" | chpasswd && \
    usermod -aG sudo targetuser

RUN mkdir -p /var/log/sandbox /opt/sandbox /opt/backups

RUN echo "localhost:5432:mydb:dbadmin:Sup3rS3cr3t!" > /root/.pgpass && \
    chmod 644 /root/.pgpass

RUN printf '#!/bin/bash\nPGPASSWORD=Sup3rS3cr3t! pg_dump -h localhost -U dbadmin mydb > /opt/backups/mydb_$(date +%%Y%%m%%d).sql\necho "Backup complete"\n' \
    > /opt/backup.sh && chmod +x /opt/backup.sh

RUN echo 'postgres ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/postgres && \
    chmod 0440 /etc/sudoers.d/postgres

RUN printf '0 2 * * * root /opt/backup.sh >> /var/log/db_backup.log 2>&1\n' >> /etc/crontab

COPY monitor.py /opt/monitor.py
COPY variation_engine.py /opt/variation_engine.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 5432 6379
ENTRYPOINT ["/entrypoint.sh"]
