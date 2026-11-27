FROM node:24-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS python-dependencies
RUN python -m venv /opt/venv
COPY backend/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tmp/requirements.txt

FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SECUREVAULT_INTERNAL_HOST=0.0.0.0 SECUREVAULT_INTERNAL_PORT=8443 \
    SECUREVAULT_TLS_CERT_FILE=/tls/tls-cert.pem SECUREVAULT_TLS_KEY_FILE=/tls/tls-key.pem \
    SECUREVAULT_TLS_CA_FILE=/tls/tls-ca.pem
RUN addgroup -g 10001 securevault \
    && adduser -D -H -u 10001 -G securevault securevault \
    && install -d -m 0700 -o 10001 -g 10001 /data /data/database /data/backups /data/logs
WORKDIR /app/backend
COPY --from=python-dependencies /opt/venv /opt/venv
COPY backend/app ./app
COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY --from=frontend /build/dist /app/frontend/dist
USER 10001:10001
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=7s --start-period=30s --retries=3 CMD ["python", "-m", "app.healthcheck"]
CMD ["python", "-m", "app.serve"]
