"""The orchestrator's HTTP API.

Nothing here reaches a target. Every endpoint either reads stored rows or asks
the engine to do something through its control API, and the engine refuses
anything outside the scope it was authorised for.

The one rule worth stating twice: a session is reported as `completed` only
when the events stored for it are provably everything the run produced. If
anything is missing -- a gap in the sequence, a stream that ended early, an
engine that evicted events before they could be delivered -- the status is
`incomplete` and the reason says what is absent. A caller must never be able
to read a partial result set as a whole one.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import auth
from . import db as store
from . import classify, delivery, report as report_mod
from .config import Settings, load_settings
from .engine_client import EngineClient, EngineError, consume_stream

log = logging.getLogger("mihakk.orchestrator")

@asynccontextmanager
async def _lifespan(_: FastAPI):
    if _db is None:
        configure(_settings)
    # A restart must not abandon a run that was in progress. Without this the
    # session stays `running` for ever, its remaining events are never
    # collected, and nothing ever says why.
    await resume_running_sessions()
    yield
    for task in list(_tasks.values()):
        task.cancel()


app = FastAPI(
    lifespan=_lifespan,
    title="Mihakk orchestrator",
    description=(
        "Sessions, storage and analysis for the Mihakk engine. Results are "
        "indicators that need verification, never confirmed vulnerabilities."
    ),
    version="0.5.0",
)

_settings: Settings = load_settings()
_db: Optional[store.Database] = None
_client: Optional[EngineClient] = None
_sessions: Optional[auth.SessionStore] = None

# Where the dashboard's files live. Served by this process on purpose: one
# origin means no CORS to configure, `connect-src 'self'` becomes meaningful,
# and the session cookie is same-origin without exception.
#
# Resolved against the candidates rather than one fixed path, because the image
# and the test container lay the tree out differently.
def _dashboard_dir() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for candidate in (here.parent.parent / "dashboard",
                      here.parent.parent.parent / "dashboard",
                      pathlib.Path("/dashboard")):
        if (candidate / "index.html").is_file():
            return candidate
    return here.parent.parent.parent / "dashboard"


DASHBOARD_DIR = _dashboard_dir()
_tasks: dict[str, asyncio.Task] = {}


def configure(settings: Settings, database: Optional[store.Database] = None,
              client: Optional[EngineClient] = None) -> None:
    """Replace the runtime wiring. Used by tests and by startup."""
    global _settings, _db, _client
    _settings = settings
    if _db is not None and database is not None:
        _db.close()
    _db = database if database is not None else store.Database(settings.database_path)
    _client = client if client is not None else EngineClient(settings)
    global _sessions
    _sessions = auth.SessionStore(_db, settings)


def database() -> store.Database:
    if _db is None:
        configure(_settings)
    assert _db is not None
    return _db


def engine() -> EngineClient:
    if _client is None:
        configure(_settings)
    assert _client is not None
    return _client


def sessions() -> auth.SessionStore:
    if _sessions is None:
        configure(_settings)
    assert _sessions is not None
    return _sessions


# --- the route manifest ------------------------------------------------------
#
# Every path this service answers, and what it takes to reach it. Declared rather
# than derived so that adding a route is a deliberate act: a test compares the
# app's real routes against this table and fails on anything not listed here.
#
# The unauthenticated surface is four entries, and none of them runs JavaScript.
OPEN_PATHS = {
    "/healthz": {"GET"},
    "/auth/login": {"GET", "POST"},
    "/assets/login.css": {"GET"},
}

# Paths that need a live session but are not state-changing, so no CSRF token.
READ_PATHS = {
    "/",
    "/auth/csrf",
    "/assets/{name}",
    "/v1/sessions",
    "/v1/sessions/{session_id}",
    "/v1/sessions/{session_id}/events",
    "/v1/sessions/{session_id}/findings",
    "/v1/sessions/{session_id}/report",
}

# Paths that change something, so a cookie-authenticated caller must also present
# the CSRF token.
WRITE_PATHS = {
    "/auth/logout",
    "/v1/sessions",
    "/v1/sessions/{session_id}/start",
    "/v1/sessions/{session_id}/stop",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- models ----------------------------------------------------------------


# A session id becomes a directory name in the engine's store, so anything that
# could be read as a path is refused. The engine enforces this itself and stays
# the authority; refusing it here as well means a bad id is answered with a 422
# at the edge instead of travelling on to be rejected further in. Nothing on this
# side builds a filesystem path from it -- the database binds it as a parameter --
# so this is about not forwarding what the engine will refuse.
SESSION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"

# The same rule for an id that arrives in the URL path rather than the body.
SessionId = Annotated[str, PathParam(pattern=SESSION_ID_PATTERN, max_length=128)]


class CreateSession(BaseModel):
    """A new session.

    The config and corpus are passed through to the engine untouched. The
    orchestrator does not inspect the authorisation acknowledgement or the
    scope: the engine is the single authority on what may be reached, and a
    second opinion here could only ever disagree with it.
    """

    session_id: str = Field(min_length=1, max_length=128, pattern=SESSION_ID_PATTERN)
    config: dict[str, Any]
    corpus: Optional[dict[str, Any]] = None
    openapi: Optional[str] = None
    base_url: Optional[str] = None
    seed: str = Field(min_length=2)
    mutation_config: Optional[dict[str, Any]] = None
    max_cases: Optional[int] = None


class SessionView(BaseModel):
    session_id: str
    status: str
    # What the engine said when the run ended, kept separate from whether the
    # stream arrived whole. `status` is the combination of the two.
    engine_status: Optional[str] = None
    engine_incomplete_reason: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    engine_version: Optional[str] = None
    scope_digest: Optional[str] = None
    planned_cases: int = 0
    findings: int = 0
    completeness: dict[str, Any]
    # What became of the requests, from the engine's own counts: refused before
    # sending, attempted, and answered. Attempted is not a claim that the target
    # received anything (app/delivery.py).
    delivery: dict[str, Any] = {}
    # Present whenever the stored results are not everything the run produced.
    incomplete_reason: Optional[str] = None
    note: str = (
        "Results are indicators that need verification, not confirmed vulnerabilities."
    )


# --- routes ----------------------------------------------------------------


# --- authentication ---------------------------------------------------------


def _client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# Methods that change nothing. Everything else is treated as state-changing and
# needs the CSRF token when the caller authenticated with a cookie.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _is_open(path: str, method: str) -> bool:
    """Whether this exact path and method are reachable without credentials.

    Default-deny: a path not listed here needs a credential, so a route added
    later is protected before anyone remembers to protect it.
    """
    allowed = OPEN_PATHS.get(path)
    return allowed is not None and method.upper() in allowed


def _refuse(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


@app.middleware("http")
async def guard(request: Request, call_next):
    """Authenticate before anything else happens.

    Before this was middleware it was a call at the top of each handler, which
    FastAPI runs AFTER validating the request body -- so a POST with a malformed
    body came back 422 to a caller with no credentials at all, describing the
    schema on the way. Running here means an unauthenticated request is refused
    before its body is parsed.
    """
    path = request.url.path
    method = request.method.upper()

    # Health is answerable always: it is how a container reports itself, and it
    # says nothing but that the process is alive.
    if path == "/healthz":
        return await call_next(request)

    if not _settings.dashboard_enabled:
        return _refuse(503,
                       "the dashboard is not configured: set MIHAKK_DASHBOARD_TOKEN. "
                       "It is deliberately not served without a credential.")

    if not auth.host_allowed(request.headers.get("host"), _settings.allowed_hosts):
        return _refuse(421, "this service does not answer to that host name")

    if _is_open(path, method):
        return await call_next(request)

    session = None
    header = request.headers.get("authorization", "")
    if header.startswith("Bearer "):
        presented = header[len("Bearer "):].strip()
        if not auth.tokens_equal(presented, _settings.dashboard_token):
            return _refuse(401, "invalid credentials")
        # A bearer credential is not ambient: a browser never attaches an
        # Authorization header by itself, which is exactly why cross-site request
        # forgery cannot drive this path and why it needs no CSRF token.
    else:
        session = sessions().get(request.cookies.get(auth.SESSION_COOKIE))
        if session is None:
            if path == "/" and method == "GET":
                return RedirectResponse(url="/auth/login", status_code=303)
            return _refuse(401, "a dashboard session is required")

        if method not in SAFE_METHODS:
            # The Origin must be present and must be this exact origin -- scheme,
            # host and port together. Refused even when the CSRF token is right,
            # because the two answer different questions and a browser that would
            # not tell us where a request came from is not one to trust with a
            # state change.
            if not auth.origin_allowed(request.headers.get("origin"),
                                       request.url.scheme,
                                       request.headers.get("host")):
                return _refuse(403,
                               "a state-changing request must carry an Origin "
                               "matching this service exactly")
            presented = request.headers.get(auth.CSRF_HEADER, "")
            if not presented or not auth.tokens_equal(presented, session.csrf_token):
                return _refuse(403,
                               "a valid CSRF token is required for this request")

    request.state.session = session
    response = await call_next(request)

    # Rotate a live session's id once it is old enough, narrowing the window in
    # which a leaked id is worth anything.
    if session is not None and sessions().due_for_rotation(session):
        fresh = sessions().rotate(session)
        _set_session_cookie(response, fresh, request.url.scheme == "https")
    return response


def _session_of(request: Request) -> Optional[auth.Session]:
    return getattr(request.state, "session", None)


def _set_session_cookie(response: Response, session: auth.Session, secure: bool) -> None:
    response.set_cookie(
        auth.SESSION_COOKIE, session.key,
        httponly=True, samesite="strict", secure=secure, path="/",
        max_age=_settings.session_absolute_seconds,
    )


DASHBOARD_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'; "
    "frame-ancestors 'none'"
)

# The login page runs no script at all, so its policy forbids script outright. The
# one relaxation is form-action, which a plain HTML form needs and which the rest
# of the dashboard does not get.
LOGIN_CSP = (
    "default-src 'none'; script-src 'none'; style-src 'self'; form-action 'self'; "
    "img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


def _security_headers(csp: str) -> dict[str, str]:
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


@app.get("/auth/login")
async def login_page(request: Request) -> Response:
    """The login form: plain HTML, no JavaScript, one stylesheet.

    Served from its own path rather than from `/` so that the dashboard's files
    stay behind authentication. This and POST /auth/login and the one stylesheet
    are the entire surface reachable without credentials.
    """
    prelogin = auth.new_token()
    page = (DASHBOARD_DIR / "login.html").read_text(encoding="utf-8")
    page = page.replace("{{CSRF}}", prelogin)

    response = Response(content=page, media_type="text/html; charset=utf-8",
                        headers=_security_headers(LOGIN_CSP))
    # Paired with the hidden field, so a login cannot be forced from another site.
    response.set_cookie(auth.PRELOGIN_COOKIE, prelogin, httponly=True,
                        samesite="strict", secure=request.url.scheme == "https",
                        path="/auth/login", max_age=600)
    return response


async def _read_form(request: Request) -> dict[str, str]:
    """Parse an urlencoded body with the standard library.

    FastAPI's Form() needs python-multipart, and one small parser is a better
    trade than a dependency for a project that vendors its only Go dependency and
    builds with no network. Only the login form posts a body like this.
    """
    raw = await request.body()
    if len(raw) > 8192:
        raise HTTPException(status_code=413, detail="the form is too large")
    parsed = urllib.parse.parse_qs(raw.decode("utf-8", errors="replace"),
                                   keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items() if values}


@app.post("/auth/login")
async def login(request: Request) -> Response:
    form = await _read_form(request)
    token = form.get("token", "")
    csrf_token = form.get(auth.CSRF_FIELD, "")

    address = _client_address(request)
    store_ = sessions()

    # One message for every failure. Distinguishing "wrong token" from "locked
    # out" would tell someone probing which of the two they achieved.
    generic = "invalid credentials"

    if store_.locked_out(address):
        raise HTTPException(status_code=429, detail=generic)

    expected_prelogin = request.cookies.get(auth.PRELOGIN_COOKIE, "")
    if not expected_prelogin or not auth.tokens_equal(csrf_token, expected_prelogin):
        store_.record_failure(address)
        raise HTTPException(status_code=403, detail=generic)

    if not token or not auth.tokens_equal(token, _settings.dashboard_token):
        store_.record_failure(address)
        raise HTTPException(status_code=401, detail=generic)

    store_.clear_failures(address)
    # A fresh id, so a session planted before login cannot be adopted.
    session = store_.create()

    response = RedirectResponse(url="/", status_code=303,
                                headers=_security_headers(DASHBOARD_CSP))
    _set_session_cookie(response, session, request.url.scheme == "https")
    response.delete_cookie(auth.PRELOGIN_COOKIE, path="/auth/login")
    return response


@app.get("/auth/csrf")
async def csrf(request: Request) -> JSONResponse:
    """The CSRF token for this session, for the page's own JavaScript.

    Returned in a body rather than a readable cookie so the comparison happens
    server-side. The page holds it in memory; it is never put in a URL, a file or
    browser storage. The control API token is not involved in any of this.
    """
    session = _session_of(request)
    if session is None:
        # A bearer caller has no CSRF token because it does not need one.
        return JSONResponse({"csrf_token": None,
                             "note": "bearer-authenticated callers do not use CSRF tokens"})
    return JSONResponse({"csrf_token": session.csrf_token})


@app.post("/auth/logout")
async def logout(request: Request) -> Response:
    session = _session_of(request)
    if session is not None:
        sessions().destroy(session.key)
    response = Response(status_code=204, headers=_security_headers(DASHBOARD_CSP))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response


@app.get("/")
async def dashboard_page(request: Request) -> Response:
    """The dashboard itself. Behind authentication, like everything it reads."""
    page = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    response = Response(content=page, media_type="text/html; charset=utf-8",
                        headers=_security_headers(DASHBOARD_CSP))
    return response


@app.get("/assets/login.css")
async def login_stylesheet(request: Request) -> Response:
    """The only asset the login page needs, and the only open one."""
    body = (DASHBOARD_DIR / "assets" / "login.css").read_text(encoding="utf-8")
    return Response(content=body, media_type="text/css; charset=utf-8",
                    headers=_security_headers(LOGIN_CSP))


@app.get("/assets/{name}")
async def asset(request: Request, name: str) -> Response:
    """The dashboard's own files, behind authentication.

    The name is checked against a fixed list rather than joined into a path: this
    endpoint takes a caller-supplied string and turns it into a file, which is the
    shape that let a session id walk out of the engine's store.
    """
    allowed = {"app.js": "text/javascript; charset=utf-8",
               "app.css": "text/css; charset=utf-8"}
    if name not in allowed:
        raise HTTPException(status_code=404, detail="no such asset")
    body = (DASHBOARD_DIR / "assets" / name).read_text(encoding="utf-8")
    response = Response(content=body, media_type=allowed[name],
                        headers=_security_headers(DASHBOARD_CSP))
    return response


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": "mihakk-orchestrator"}


@app.post("/v1/sessions", status_code=201)
async def create_session(request: Request, body: CreateSession) -> dict[str, Any]:
    db = database()
    if db.get_session(body.session_id):
        raise HTTPException(status_code=409, detail=f"session {body.session_id} already exists")
    db.create_session(body.session_id, _now())
    return {"session_id": body.session_id, "status": store.CREATED}


@app.post("/v1/sessions/{session_id}/start", status_code=202)
async def start_session(request: Request, session_id: SessionId, body: CreateSession,
                        background: BackgroundTasks) -> dict[str, Any]:
    db = database()
    session = db.get_session(session_id)
    if session is None:
        db.create_session(session_id, _now())
    elif session["status"] == store.RUNNING:
        raise HTTPException(status_code=409, detail="the session is already running")

    payload: dict[str, Any] = {
        "session_id": session_id,
        "config": body.config,
        "seed": body.seed,
    }
    if body.corpus is not None:
        payload["corpus"] = body.corpus
    if body.openapi:
        payload["openapi"] = body.openapi
    if body.base_url:
        payload["base_url"] = body.base_url
    if body.mutation_config is not None:
        payload["mutation_config"] = body.mutation_config
    if body.max_cases:
        payload["max_cases"] = body.max_cases

    try:
        started = await engine().start_run(payload)
    except EngineError as exc:
        # The engine's refusal is passed through as-is. Rewriting it here
        # would hide which rule was broken.
        db.update_session(session_id, status=store.FAILED, incomplete_reason=str(exc))
        status = exc.status if exc.status and exc.status < 500 else 502
        raise HTTPException(status_code=status, detail=str(exc)) from exc

    db.update_session(
        session_id,
        status=store.RUNNING,
        started_at=_now(),
        engine_version=started.engine_version,
        scope_digest=started.scope_digest,
        corpus_digest=started.corpus_digest,
        config_digest=started.config_digest,
        planned_cases=started.planned_cases,
    )

    _follow_in_background(session_id)
    return {
        "session_id": session_id,
        "status": store.RUNNING,
        "planned_cases": started.planned_cases,
        "scope_digest": started.scope_digest,
    }


def _follow_in_background(session_id: str) -> bool:
    """Start following a session, unless it is already being followed.

    Two followers on one session would both consume the stream, both write
    the same rows and race on the final status. The guard is what makes
    restart recovery safe to call alongside a start that is already running.
    """
    existing = _tasks.get(session_id)
    if existing is not None and not existing.done():
        return False
    _tasks[session_id] = asyncio.create_task(_follow(session_id))
    return True


async def resume_running_sessions() -> list[str]:
    """Pick up sessions that were mid-run when the service stopped.

    Each resumes from the last contiguous sequence number already stored, so
    nothing is re-requested that is already held and nothing is skipped. If
    the engine no longer knows the run, the follower exhausts its retries and
    records `interrupted` with the reason -- which is the point: a session
    must not sit at `running` because the process that was watching it died.
    """
    db = database()
    resumed: list[str] = []
    for row in db.list_sessions():
        if row.get("status") != store.RUNNING:
            continue
        session_id = row["session_id"]
        if _follow_in_background(session_id):
            resumed.append(session_id)
            # This is an operational recovery event, not ordinary request
            # noise: keep the resume point visible with the deployment's
            # default warning-level application logger.
            log.warning("resuming session %s from seq %d after a restart",
                        session_id, db.last_contiguous_seq(session_id))
    return resumed


async def _follow(session_id: str) -> None:
    """Consume the engine's stream into storage, then settle the status."""
    db = database()

    def on_event(event: dict[str, Any]) -> bool:
        stored_now = db.append_event(session_id, event)
        if event.get("type") == "finding":
            finding = event.get("finding")
            if isinstance(finding, dict) and finding.get("case_id"):
                db.append_finding(session_id, finding["case_id"],
                                  int(event.get("seq", 0)), finding)
        if event.get("type") == "warning":
            warning = event.get("warning") or {}
            if warning.get("code") == "results_not_persisted":
                # The engine could not write down something it observed. The
                # stream is fine; the results are not.
                db.update_session(
                    session_id,
                    engine_incomplete_reason=str(warning.get("message", "")),
                )
        if event.get("type") == "done":
            done = event.get("done") or {}
            db.update_session(
                session_id,
                total_seq=int(done.get("total_seq", 0)) or None,
                engine_status=str(done.get("status") or "") or None,
                ended_at=_now(),
            )
        return stored_now

    def on_gap(event: dict[str, Any]) -> None:
        warning = event.get("warning") or {}
        db.append_gap_notice(
            session_id,
            event.get("at"),
            int(warning.get("events_dropped", 0)),
            str(warning.get("message", "")),
        )

    outcome = await consume_stream(
        engine(),
        session_id,
        resume_from=lambda: db.last_contiguous_seq(session_id),
        on_event=on_event,
        on_gap=on_gap,
        attempts=_settings.reconnect_attempts,
        delay=_settings.reconnect_delay_seconds,
    )

    completeness = db.refresh_completeness(session_id)

    row = db.get_session(session_id) or {}
    engine_status: Optional[str] = row.get("engine_status")
    if engine_status is None:
        for event in reversed(db.events(session_id)):
            if event.get("type") == "done":
                engine_status = (event.get("done") or {}).get("status")
                break

    if not outcome.finished:
        # The stream never reached `done`, so what is stored is whatever
        # arrived before it broke. That is not a completed session.
        engine_status = store.INTERRUPTED
        reason = (
            f"the event stream ended after {outcome.attempts} attempt(s) without the "
            f"run reporting completion ({outcome.last_error or 'reason unknown'}); "
            "the stored results are whatever arrived before it broke"
        )
        log.warning("session %s marked interrupted: %s", session_id, reason)
        existing = completeness.reason
        db.update_session(
            session_id,
            incomplete_reason=f"{existing}; {reason}" if existing else reason,
            complete=0,
        )

    db.update_session(
        session_id,
        status=store.resolve_status(engine_status, completeness),
        ended_at=_now(),
    )
    _tasks.pop(session_id, None)


@app.get("/v1/sessions")
async def list_sessions(request: Request) -> dict[str, Any]:
    db = database()
    return {"sessions": [_view(db, row["session_id"]).model_dump() for row in db.list_sessions()]}


@app.get("/v1/sessions/{session_id}")
async def get_session(request: Request, session_id: SessionId) -> SessionView:
    db = database()
    if db.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="no such session")
    return _view(db, session_id)


@app.post("/v1/sessions/{session_id}/stop", status_code=202)
async def stop_session(request: Request, session_id: SessionId) -> dict[str, Any]:
    db = database()
    if db.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="no such session")
    try:
        await engine().stop_run(session_id)
    except EngineError as exc:
        if exc.status == 404:
            raise HTTPException(status_code=404, detail="the engine has no such run") from exc
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.update_session(session_id, status=store.STOPPED)
    return {"session_id": session_id, "stopping": True}


@app.get("/v1/sessions/{session_id}/events")
async def session_events(request: Request, session_id: SessionId, after_seq: int = 0,
                         limit: int = 500) -> dict[str, Any]:
    db = database()
    if db.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="no such session")
    completeness = db.compute_completeness(session_id)
    return {
        "session_id": session_id,
        "events": db.events(session_id, after_seq=after_seq, limit=limit),
        "completeness": _completeness_view(db, session_id, completeness),
    }


@app.get("/v1/sessions/{session_id}/findings")
async def session_findings(request: Request, session_id: SessionId) -> dict[str, Any]:
    db = database()
    if db.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="no such session")
    completeness = db.compute_completeness(session_id)
    findings = db.findings(session_id)
    return {
        "session_id": session_id,
        "findings": findings,
        "count": len(findings),
        # Repeated on the findings themselves, because this is the response a
        # reader is most likely to treat as the whole picture.
        "completeness": _completeness_view(db, session_id, completeness),
        "note": (
            "These are indicators that need verification, not confirmed "
            "vulnerabilities. Detailed classification and confidence are assigned "
            "by the analysis phase."
        ),
    }


@app.get("/v1/sessions/{session_id}/report")
async def session_report(request: Request, session_id: SessionId,
                         format: str = "json") -> Response:
    """The session's report, derived on every read.

    Nothing is cached. A stored report would keep asserting a completeness that a
    later-discovered gap had already contradicted, which is the failure the whole
    completeness rule exists to prevent.

    The engine's aggregate is fetched live, so a report is only ever as good as
    what the engine can still account for. If the engine cannot be reached, that is
    said plainly rather than answered from the rows alone -- a report built from
    half its sources would look like a report.
    """

    if format not in ("json", "html"):
        raise HTTPException(status_code=400,
                            detail="format must be json or html")

    db = database()
    if db.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="no such session")

    try:
        aggregate = await engine().aggregate(session_id)
    except EngineError as exc:
        status = exc.status if exc.status and exc.status < 500 else 502
        raise HTTPException(
            status_code=status,
            detail=f"the engine's aggregation could not be read, so no report can be "
                   f"produced: {exc}") from exc

    view = _view(db, session_id).model_dump()
    groups = classify.classify_document(
        aggregate,
        baseline_unstable=_baseline_was_unstable(db, session_id),
    )
    try:
        document = report_mod.build_report(session_id, view, aggregate, groups)
    except report_mod.InconsistentAggregate as exc:
        # No report, in either format. A document whose totals contradict its own
        # groups cannot be shown as a result with a warning attached: the warning
        # is the part a reader skips, and the numbers are the part they quote.
        raise HTTPException(
            status_code=502,
            detail=f"the engine's aggregate is internally inconsistent, so no "
                   f"report was produced: {exc.reason}") from exc

    if format == "json":
        return JSONResponse(content=document)
    return Response(content=report_mod.render_html(document),
                    headers=report_mod.report_headers())


def _baseline_was_unstable(db: store.Database, session_id: str) -> bool:
    """Did the run warn that its sense of normal was shaky?

    Read from the stored events rather than guessed: the engine emits the warning,
    and a comparison against an unstable baseline deserves less confidence.
    """
    for event in db.events(session_id):
        if event.get("type") != "warning":
            continue
        warning = event.get("warning") or {}
        if warning.get("code") == "baseline_unstable":
            return True
    return False


def _completeness_view(db: store.Database, session_id: str,
                       c: store.Completeness) -> dict[str, Any]:
    view: dict[str, Any] = {
        "complete": c.complete,
        "events_received": c.events_received,
        "events_dropped": c.events_dropped,
        "last_seq": c.last_seq,
        "total_seq": c.total_seq,
        "reason": c.reason,
    }
    if not c.complete:
        view["warning"] = (
            "This result set is a subset of what the run produced. Absence of a "
            "finding here does not mean the engine did not observe one."
        )
        if c.missing_seqs:
            view["missing_seqs"] = c.missing_seqs[:50]
    return view


def _view(db: store.Database, session_id: str) -> SessionView:
    row = db.get_session(session_id) or {}
    completeness = db.compute_completeness(session_id)
    status = row.get("status", store.CREATED)

    # A stored status of `completed` is re-checked against the rows on every
    # read, so a session cannot keep claiming completeness after a later gap
    # is discovered.
    if status == store.COMPLETED and not completeness.complete:
        status = store.INCOMPLETE
    if status == store.COMPLETED and row.get("engine_status") == store.INCOMPLETE:
        # The engine admitted it lost something. A whole stream does not
        # override that, however the status happened to be stored.
        status = store.INCOMPLETE

    return SessionView(
        session_id=session_id,
        status=status,
        engine_status=row.get("engine_status"),
        engine_incomplete_reason=row.get("engine_incomplete_reason"),
        created_at=row.get("created_at", ""),
        started_at=row.get("started_at"),
        ended_at=row.get("ended_at"),
        engine_version=row.get("engine_version"),
        scope_digest=row.get("scope_digest"),
        planned_cases=int(row.get("planned_cases", 0)),
        findings=len(db.findings(session_id)),
        completeness=_completeness_view(db, session_id, completeness),
        delivery=delivery.from_progress(
            (db.last_event(session_id, "progress") or {}).get("progress"),
            final=status not in (store.CREATED, store.RUNNING)),
        incomplete_reason=_merge_reasons(completeness.reason, row.get("incomplete_reason")),
    )


def _merge_reasons(computed: Optional[str], stored: Optional[str]) -> Optional[str]:
    """Combine what the rows say now with what was recorded when it ended.

    The completeness reason is recomputed on every read, so preferring it
    alone silently dropped the detail recorded at the end -- that the stream
    never finished and why. Both matter: one says what is missing, the other
    says what went wrong.
    """
    if not stored:
        return computed
    if not computed or computed in stored:
        return stored
    return f"{computed}; {stored}"
