# Witness: the outside party. API port only, no SSH server installed, runs as an unprivileged user.
FROM python:3.12-slim
# Wheels from `python docker/fetch_wheels.py` make the build work offline; otherwise PyPI is used.
COPY docker/wheels /wheels
RUN PKGS="fastapi==0.115.12 uvicorn==0.34.0 PyYAML==6.0.3 cryptography==50.0.2 pycryptodome==3.23.0"; \
    if ls /wheels/*.whl >/dev/null 2>&1; then pip install --no-cache-dir --no-index --find-links /wheels $PKGS; \
    else pip install --no-cache-dir --retries 10 --timeout 60 $PKGS; fi \
    && rm -rf /wheels \
    && useradd --system --home /data witness && mkdir -p /data && chown witness /data
WORKDIR /opt/coc
COPY shared ./shared
COPY witness ./witness
COPY layers/__init__.py ./layers/__init__.py
COPY layers/common ./layers/common
COPY config/layers.yaml ./config/layers.yaml
ENV PYTHONPATH=/opt/coc WITNESS_DB_PATH=/data/witness.db
USER witness
EXPOSE 8000
# First start: split the Layer 3 unlock secret 2-of-3 into /data/shares (hand out, then delete).
CMD ["sh", "-c", "[ -d /data/shares ] || python -m witness.keyholders init /data/witness.db /data/shares 'SOC lead' Auditor 'Compliance officer'; exec python -m uvicorn --factory witness.app:create_app --host 0.0.0.0 --port 8000"]
