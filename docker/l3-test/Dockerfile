# Linux box for proving the Layer 3 lockout for real (dry_run off). Not the production image.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-yaml python3-cryptography python3-requests procps passwd login \
        openssh-server openssh-client util-linux e2fsprogs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd
WORKDIR /opt/coc
COPY shared ./shared
COPY layers ./layers
COPY config ./config
COPY docker/l3-test/run_test.sh ./run_test.sh
CMD ["bash", "/opt/coc/run_test.sh"]
