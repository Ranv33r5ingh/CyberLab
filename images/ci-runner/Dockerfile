FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    make gcc ant python3 python3-pip \
    rsyslog curl wget net-tools iproute2 \
    openssh-server cron sudo \
    lsof strace tcpdump nmap psmisc \
    vim nano git inotify-tools lsb-release sshpass unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install psutil requests --quiet

RUN useradd -m -s /bin/bash jenkins && \
    echo "jenkins:jenkins123" | chpasswd && \
    usermod -aG sudo jenkins && \
    useradd -m -s /bin/bash targetuser && \
    echo "targetuser:password123" | chpasswd

RUN mkdir -p /var/jenkins_home/secrets \
    /var/jenkins_home/workspace/build-prod \
    /var/jenkins_home/jobs/deploy-pipeline \
    /opt/builds /var/log/sandbox && \
    chmod 777 /var/log/sandbox && \
    chown -R jenkins:jenkins /var/jenkins_home /opt/builds

RUN echo "8a4b9c3d2e1f0a7b" > /var/jenkins_home/secrets/initialAdminPassword

RUN printf '<credentials>\n  <entry>\n    <username>deploy</username>\n    <password>Build@Pr0d123!</password>\n    <privateKey>gh_pat_faketoken9x3k2j1h</privateKey>\n  </entry>\n</credentials>\n' \
    > /var/jenkins_home/credentials.xml && chmod 644 /var/jenkins_home/credentials.xml

RUN printf '#!/bin/bash\nsshpass -p "Build@Pr0d123!" scp -o StrictHostKeyChecking=no /opt/builds/app.jar deploy@prod.internal:/opt/app/\n' \
    > /opt/builds/deploy.sh && chmod +x /opt/builds/deploy.sh && \
    printf 'deploy.password=Build@Pr0d123!\ndb.password=Sup3rS3cr3t!\n' \
    > /opt/builds/config.properties && \
    chown -R jenkins:jenkins /var/jenkins_home /opt/builds

RUN echo "jenkins ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/jenkins && \
    chmod 0440 /etc/sudoers.d/jenkins

COPY monitor.py /opt/monitor.py
COPY variation_engine.py /opt/variation_engine.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 8080
ENTRYPOINT ["/entrypoint.sh"]
