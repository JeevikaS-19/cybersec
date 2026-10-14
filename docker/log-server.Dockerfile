# Log server: the protected machine. Fake bank + agent + Layer 1 tripwire + Layer 3 quarantine, and sshd so
# people (and the attacker) log in the way they would on a real server.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps passwd login util-linux e2fsprogs vim-tiny nano sed coreutils iproute2 \
        auditd inotify-tools \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
    && ln -sf /usr/bin/vim.tiny /usr/local/bin/vim
# Wheels from `python docker/fetch_wheels.py` make the build work offline; otherwise PyPI is used.
COPY docker/wheels /wheels
RUN PKGS='PyYAML==6.0.3 cryptography==50.0.2 requests==2.33.1 psycopg[binary]==3.2.13'; \
    if ls /wheels/*.whl >/dev/null 2>&1; then pip install --no-cache-dir --no-index --find-links /wheels $PKGS; \
    else pip install --no-cache-dir --retries 10 --timeout 60 $PKGS; fi \
    && rm -rf /wheels
WORKDIR /opt/coc
COPY shared ./shared
COPY agent ./agent
COPY victim ./victim
COPY layers ./layers
COPY config ./config
# Same config as the repo, with the real lockout on and "site down" = pause the bank.
RUN sed -e 's|^  dry_run: true.*|  dry_run: false|' \
        -e 's|^  site_down: \[\].*|  site_down: ["pkill -STOP -f victim/bank.py"]|' \
        -e 's|^  site_up: \[\].*|  site_up: ["pkill -CONT -f victim/bank.py"]|' \
        -e 's|^    watch: \[\].*|    watch: [/var/log/bank, /var/lib/bank]|' \
        -e 's|^    allowed_writers: \[\].*|    allowed_writers: ["victim/bank.py"]|' \
        config/layers.yaml > config/layers.container.yaml \
    && grep -q "dry_run: false" config/layers.container.yaml && grep -q "pkill -STOP" config/layers.container.yaml
COPY docker/log-server/entrypoint.sh /entrypoint.sh
ENV PYTHONPATH=/opt/coc COC_LAYERS_CONFIG=/opt/coc/config/layers.container.yaml \
    BANK_DB_PATH=/var/lib/bank/bank.db AGENT_DB_PATH=/var/lib/coc/agent.db COC_SPOOL=/var/spool/coc
EXPOSE 22
CMD ["bash", "/entrypoint.sh"]
