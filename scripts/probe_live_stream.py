"""Drop a real engine NDJSON connection and resume it from its last event.

Run inside the isolated orchestrator container, which alone has the control
socket. This is a bounded probe, not a follower: the orchestrator remains the
owner of the session and stores the full stream independently.
"""

import asyncio
import json
import os
import sys

import httpx


async def next_event(client: httpx.AsyncClient, session_id: str, after: int) -> dict:
    async with client.stream(
        "GET", f"/v1/runs/{session_id}/events", params={"from_seq": after},
        headers={"Authorization": f"Bearer {os.environ['MIHAKK_CONTROL_TOKEN']}"},
    ) as response:
        response.raise_for_status()
        async for line in response.aiter_lines():
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("seq", 0) > 0:
                return event
    raise RuntimeError("stream closed before another numbered event")


async def main(session_id: str) -> None:
    transport = httpx.AsyncHTTPTransport(uds="/run/mihakk/control.sock")
    async with httpx.AsyncClient(base_url="http://engine", transport=transport,
                                 timeout=httpx.Timeout(10.0, read=15.0)) as client:
        first = await next_event(client, session_id, 0)
        assert first.get("type") != "done", "run ended before the deliberate drop"
        seq = first["seq"]
        # next_event has closed the first HTTP stream. A fresh socket connection
        # must resume after exactly that event, not start over or skip one.
        second = await next_event(client, session_id, seq)
        assert second["seq"] == seq + 1, (seq, second.get("seq"))
        print(f"dropped after seq {seq}; from_seq={seq} returned seq {second['seq']}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: probe_live_stream.py SESSION_ID")
    asyncio.run(main(sys.argv[1]))
