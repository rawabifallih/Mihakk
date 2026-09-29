# The image the dashboard's browser test runs in.
#
# The Playwright base image ships the browsers but not the Python package, so it
# is added here and pinned. Built once and cached, so only the first run needs the
# network -- every other test in this project needs none at all, and this is the
# documented exception.
ARG BASE=mcr.microsoft.com/playwright/python:v1.49.0-noble
FROM ${BASE}

# --break-system-packages: the base is a Debian image whose Python is
# externally managed, and this container exists only to run one test.
RUN pip install --no-cache-dir --break-system-packages playwright==1.49.0

# The browsers are already in the image; this only checks the wiring.
RUN python3 -c "from playwright.sync_api import sync_playwright; print('playwright ready')"
