# syntax=docker/dockerfile:1.7
# K1 app image — HARDENED (6B-7). Owner/FDE build only.
#
# Pins (F-13):
#   python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1
#     (local digest recorded in files/docker/k1/Dockerfile TODO and in
#      redaction.json fixture_allowlist; build with --pull=false offline)
#   postgres:17-alpine is run as a sidecar on the internal network and is
#     NOT pinned here: the owner must record its digest in
#     image-pins.json before the image is treated as sealed (see
#     HARDENING.md — status is IMPLEMENTED but UNSEALED until then).
#
# Network (F-13): no ports are published. The app's fake provider binds
# 127.0.0.1:8081 inside the container on an internal network, so there
# is no 0.0.0.0 publish. pg2a/pg2b in the plan are outside K1 and keep
# their current publishes; K1 itself never publishes.
#
# /work (F-13): DECIDED noexec. The probe client is baked into the
# image (/opt/k1/probe_client.py) so probes never need an executable
# /work. Runtime tmpfs for /work is noexec,nosuid,nodev.

FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1 AS build
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /install
COPY files/docker/k1/requirements.txt files/docker/k1/requirements.lock ./
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
COPY files/docker/k1/fake_provider.py files/docker/k1/seed.py files/docker/k1/entrypoint.sh /opt/k1/
COPY docker/k1/probe_client.py /opt/k1/probe_client.py
RUN chmod 0555 /opt/k1/entrypoint.sh /opt/k1/probe_client.py
USER 10001:10001
WORKDIR /work
# Loopback inside the container only; nothing is published to the host.
EXPOSE 8081
ENTRYPOINT ["/opt/k1/entrypoint.sh"]
CMD ["sleep", "infinity"]
