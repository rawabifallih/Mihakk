# Local testbed image. Standard library only: nothing is installed at build
# time beyond the base image, and the container needs no network access to run.
FROM python:3.11-alpine

WORKDIR /app
COPY app.py isolation_probe.py ./

RUN adduser -D -u 10001 mihakk
USER mihakk

# Documents the port. It is deliberately NOT published to the host: see
# deploy/docker-compose.yml and scripts/verify-testbed-isolation.sh.
EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python3 -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"

CMD ["python3", "-u", "app.py"]
