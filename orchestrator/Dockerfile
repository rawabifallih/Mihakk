# Orchestrator images. Dependencies are installed at build time so neither
# container needs a network to run or to be tested.
#
# Two targets, because the image that runs the service should carry only what
# the service runs:
#
#   runtime   the service: the app, the dashboard, the runtime dependencies.
#             No tests, no pytest. This is what the compose file deploys, and
#             it is the LAST stage so a build without --target produces it.
#   test      the same base plus the development dependencies and the test
#             tree, for scripts/test-orchestrator.sh.
#
# The build context is the repository root, not orchestrator/, because this image
# serves the dashboard and that lives beside the orchestrator rather than inside
# it. The engine's image is built the same way for the same reason.
FROM python:3.11-alpine AS base

WORKDIR /srv
COPY orchestrator/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/app ./app
# Served by this process, so the image carries it.
COPY dashboard ./dashboard

# 10010 is the group that may use the engine's control socket. The compose file
# grants it with group_add; declaring it here gives the number a name in the
# image and nothing more.
RUN adduser -D -u 10002 mihakk \
 && addgroup -g 10010 mihakkctl \
 && mkdir -p /data && chown mihakk /data
USER mihakk

ENV MIHAKK_DB=/data/mihakk.db
EXPOSE 8100

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python3 -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8100/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]


FROM base AS test

USER root
COPY orchestrator/requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY orchestrator/tests ./tests
USER mihakk


FROM base AS runtime
