FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nginx php8.1-fpm php8.1-cli \
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

RUN mkdir -p /var/www/html /var/log/sandbox /opt/sandbox

RUN printf '<?php\n$db_host = "db-server-02";\n$db_user = "dbadmin";\n$db_pass = "Sup3rS3cr3t!";\n$db_name = "mydb";\n?>\n' \
    > /var/www/html/config.php && \
    echo 'admin:$apr1$xyz12345$fakeHashedPasswordHere' > /var/www/html/.htpasswd && \
    echo '<html><body><h1>Company Internal Portal</h1></body></html>' > /var/www/html/index.html && \
    chown -R www-data:www-data /var/www/html

RUN printf 'user www-data;\nworker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n  server {\n    listen 80;\n    root /var/www/html;\n    autoindex on;\n    index index.html index.php;\n  }\n}\n' > /etc/nginx/nginx.conf

RUN echo "www-data ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/www-data && \
    chmod 0440 /etc/sudoers.d/www-data

RUN printf '*/10 * * * * www-data /usr/bin/find /var/www -name "*.tmp" -delete\n0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n' >> /etc/crontab

COPY monitor.py /opt/monitor.py
COPY variation_engine.py /opt/variation_engine.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
