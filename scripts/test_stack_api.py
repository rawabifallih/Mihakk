#!/usr/bin/env python3
"""Host-side API request helper for the isolated live-stack test."""

import os
import sys
import urllib.error
import urllib.request

from local_api_transport import diagnostic_for_refusal, open_loopback


def main() -> None:
    method, url, out = sys.argv[1:4]
    body = open(sys.argv[4], "rb").read() if len(sys.argv) > 4 and sys.argv[4] else None
    container = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
    request = urllib.request.Request(url, method=method, data=body, headers={
        "Authorization": "Bearer " + os.environ["MIHAKK_DASHBOARD_TOKEN"],
        "Content-Type": "application/json"})
    try:
        response = open_loopback(request, timeout=60)
        code, data = response.status, response.read()
    except urllib.error.HTTPError as exc:
        code, data = exc.code, exc.read()
    except Exception as exc:
        code, data = 0, str(exc).encode()
    if code == 403:
        diagnostic = diagnostic_for_refusal(data, body or b"", container=container)
        if diagnostic is not None:
            print(diagnostic, file=sys.stderr)
    open(out, "wb").write(data)
    print(code)


if __name__ == "__main__":
    main()
