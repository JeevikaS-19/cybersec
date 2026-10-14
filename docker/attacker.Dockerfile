# Attacker's machine on the same network: just an SSH client.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client sshpass iputils-ping \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
