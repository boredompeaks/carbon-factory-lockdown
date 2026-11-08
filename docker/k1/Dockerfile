# syntax=docker/dockerfile:1.7
# K1 app image — HARDENED (6B-7), unified to canonical files/docker/k1/ 2026-11-08.
# Owner/FDE build only. Build from repo root, no pull:
#   docker build --pull=false -t k1-app:latest files/docker/k1
#
# Pins (verified 2026-11-08 against local images, offline):
#   python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1
#   postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
#     (sidecar in compose.yaml; full pins in image-pins.json)
#
# Network (F-13): no ports are published. The app's fake provider binds
# 127.0.0.1:8081 inside the container on an internal network, so there
# is no 0.0.0.0 publish. pg2a/pg2b are outside K1.
#
# /work (F-13): DECIDED noexec. The probe client is baked into the image
# (/opt/k1/probe_client.py) so probes never need an executable /work.
# Runtime tmpfs for /work is noexec,nosuid,nodev (see compose.yaml).
#
# Multi-stage: the build stage only installs pinned runtime dependencies from
# requirements.txt. No application code is baked in; the sealed repo is
# mounted read-only at /repo/base and /repo/head.

FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1 AS build
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /install
COPY requirements.txt requirements.lock ./
RUN mkdir -p /install \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/repo/head/backend
RUN useradd --uid 10001 --create-home --shell /bin/sh k1 \
    && mkdir -p /work /repo/base /repo/head \
    && chown 10001:10001 /work
COPY --from=build /install /usr/local
COPY fake_provider.py seed.py entrypoint.sh /opt/k1/
COPY probe_client.py /opt/k1/probe_client.py
RUN chmod 0555 /opt/k1/entrypoint.sh /opt/k1/probe_client.py
USER 10001:10001
WORKDIR /work
# Loopback inside the container only; nothing is published to the host.
EXPOSE 8081
ENTRYPOINT ["/opt/k1/entrypoint.sh"]
CMD ["sleep", "infinity"]
