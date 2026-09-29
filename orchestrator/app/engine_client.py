"""The only path from the orchestrator to the engine.

This module talks to the engine's control API and to nothing else. It sends no
request to a target, and it has no way to: the control API exposes no endpoint
that forwards a caller-composed request, so scope checking, address pinning,
the limits and the kill switch stay entirely inside the engine.

Reconnection is the interesting part. A dropped stream is normal -- a restart,
a network blip -- and resuming from the last contiguous sequence number
recovers it. What must not happen is a resume that quietly skips: if the
engine can no longer supply events from the requested point, it says so in
band, and that notice is recorded rather than swallowed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Optional

import httpx

from .config import Settings, engine_endpoint

log = logging.getLogger("mihakk.engine")

# Sequence number 0 marks an out-of-band notice rather than a stream event.
GAP_SEQ = 0


class EngineError(RuntimeError):
    """The engine refused or could not be reached."""

    def __init__(self, message: str, status: Optional[int] = None,
                 detail: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail or {}


@dataclass
class StartedRun:
    session_id: str
    engine_version: str
    scope_digest: str
    corpus_digest: str
    config_digest: str
    planned_cases: int


class EngineClient:
    """A client for the engine's control API."""

    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None) -> None:
        self._settings = settings
        if client is None:
            # Read strictly: a value that is neither a socket nor an http URL
            # stops the service here rather than leaving it pointed nowhere.
            endpoint = engine_endpoint(settings.engine_base_url)
            transport = (httpx.AsyncHTTPTransport(uds=endpoint.socket_path)
                         if endpoint.socket_path else None)
            client = httpx.AsyncClient(
                base_url=endpoint.base_url,
                transport=transport,
                timeout=httpx.Timeout(10.0, read=None),  # no read timeout: streams are long
            )
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        # The shared token. Every endpoint but the health check requires it.
        return {"Authorization": f"Bearer {self._settings.engine_token}"}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def health(self) -> dict[str, Any]:
        response = await self._client.get("/healthz")
        response.raise_for_status()
        return response.json()

    async def start_run(self, payload: dict[str, Any]) -> StartedRun:
        """Ask the engine to start a run.

        The payload carries the session config, including the authorisation
        acknowledgement. The orchestrator does not validate it and does not
        need to: the engine refuses anything it is not authorised to do, and
        duplicating that check here would create a second opinion about what
        is allowed.
        """
        try:
            response = await self._client.post("/v1/runs", json=payload, headers=self._headers)
        except httpx.HTTPError as exc:
            raise EngineError(f"the engine could not be reached: {exc}") from exc

        if response.status_code >= 400:
            detail = _safe_json(response)
            raise EngineError(
                detail.get("detail") or f"the engine refused the run ({response.status_code})",
                status=response.status_code,
                detail=detail,
            )

        body = response.json()
        return StartedRun(
            session_id=body["session_id"],
            engine_version=body.get("engine_version", ""),
            scope_digest=body.get("scope_digest", ""),
            corpus_digest=body.get("corpus_digest", ""),
            config_digest=body.get("config_digest", ""),
            planned_cases=int(body.get("planned_cases", 0)),
        )

    async def stop_run(self, session_id: str) -> None:
        try:
            response = await self._client.delete(
                f"/v1/runs/{session_id}", headers=self._headers
            )
        except httpx.HTTPError as exc:
            raise EngineError(f"the engine could not be reached: {exc}") from exc
        if response.status_code == 404:
            raise EngineError("the engine has no such run", status=404)
        if response.status_code >= 400:
            raise EngineError(
                f"the engine refused to stop the run ({response.status_code})",
                status=response.status_code,
            )

    async def run_status(self, session_id: str) -> dict[str, Any]:
        response = await self._client.get(f"/v1/runs/{session_id}", headers=self._headers)
        if response.status_code == 404:
            raise EngineError("the engine has no such run", status=404)
        response.raise_for_status()
        return response.json()

    async def aggregate(self, session_id: str) -> dict[str, Any]:
        """Fetch the engine's grouped results for a session.

        The engine serves this from its store rather than from a live run, so it
        answers for a finished session and for one whose run the engine has since
        forgotten. Nothing is interpreted here: the document is passed to the
        analysis layer as it arrived.
        """
        try:
            response = await self._client.get(
                f"/v1/runs/{session_id}/aggregate", headers=self._headers)
        except httpx.HTTPError as exc:
            raise EngineError(f"the engine could not be reached: {exc}") from exc

        if response.status_code == 404:
            raise EngineError("the engine has no stored session with that id", status=404)
        if response.status_code >= 400:
            detail = _safe_json(response)
            raise EngineError(
                detail.get("detail") or f"the engine refused the aggregate "
                                        f"({response.status_code})",
                status=response.status_code, detail=detail)
        try:
            body = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise EngineError(f"the engine's aggregate is not valid JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise EngineError("the engine's aggregate is not an object")
        return body

    async def stream_events(self, session_id: str, from_seq: int) -> AsyncIterator[dict[str, Any]]:
        """Yield events after from_seq, one decoded object at a time."""
        url = f"/v1/runs/{session_id}/events"
        async with self._client.stream(
            "GET", url, params={"from_seq": from_seq}, headers=self._headers
        ) as response:
            if response.status_code >= 400:
                await response.aread()
                raise EngineError(
                    f"the engine refused the event stream ({response.status_code})",
                    status=response.status_code,
                )
            async for line in response.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    log.warning("discarding an unparseable stream line for %s", session_id)


@dataclass
class ConsumeOutcome:
    """What happened while consuming a stream."""

    finished: bool          # a `done` event arrived
    events_stored: int
    duplicates: int
    gap_notices: int
    attempts: int
    last_error: Optional[str] = None


async def consume_stream(
    client: EngineClient,
    session_id: str,
    *,
    resume_from: Callable[[], int],
    on_event: Callable[[dict[str, Any]], bool],
    on_gap: Callable[[dict[str, Any]], None],
    attempts: int,
    delay: float,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> ConsumeOutcome:
    """Consume a run's events, reconnecting on a dropped stream.

    `resume_from` is called before every attempt rather than once, so a
    reconnect always asks for what is actually missing now, not what was
    missing when the loop started.
    """
    stored = duplicates = gaps = 0
    finished = False
    last_error: Optional[str] = None
    attempt = 0

    while attempt < attempts and not finished:
        attempt += 1
        start_at = resume_from()
        try:
            async for event in client.stream_events(session_id, start_at):
                if int(event.get("seq", -1)) == GAP_SEQ:
                    # An out-of-band notice: events that existed and will
                    # never arrive. It is recorded, never treated as data.
                    gaps += 1
                    on_gap(event)
                    continue

                if on_event(event):
                    stored += 1
                else:
                    duplicates += 1

                if event.get("type") == "done":
                    finished = True
                    break
        except (EngineError, httpx.HTTPError) as exc:
            last_error = str(exc)
            log.warning("event stream for %s dropped on attempt %d: %s",
                        session_id, attempt, exc)
            if attempt < attempts:
                await sleep(delay)
            continue

        if not finished:
            # The stream ended without a done event: the engine went away, or
            # the connection closed early. Try again from where we are.
            last_error = last_error or "the stream ended before the run finished"
            if attempt < attempts:
                await sleep(delay)

    return ConsumeOutcome(
        finished=finished,
        events_stored=stored,
        duplicates=duplicates,
        gap_notices=gaps,
        attempts=attempt,
        last_error=last_error,
    )


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
        return body if isinstance(body, dict) else {"detail": str(body)}
    except (json.JSONDecodeError, ValueError):
        return {"detail": response.text[:500]}
