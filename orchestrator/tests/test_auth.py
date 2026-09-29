"""Authentication, and the route surface it protects.

The orchestrator had none of this until the dashboard existed. It was published
on loopback and every caller was a script, so "no authentication" was a deployment
choice rather than a hole. Pointing a browser at it changes that: a browser
carries other sites' sessions, and every endpoint here starts fuzzing runs.

What each control actually covers is worth keeping straight, because the plan for
this got it wrong once. HttpOnly stops script READING the cookie; it does not stop
an injected script from making authenticated requests, since the browser attaches
the cookie itself. So these tests are layers around the real defence, which is
that the dashboard never turns data into markup.
"""

from __future__ import annotations

import dataclasses
import re
import time
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app import auth
from app import db as store
from app import main
from app.config import Settings
from app.engine_client import EngineClient

from conftest import DASHBOARD_TOKEN, FakeEngine, bearer, sign_in

# What a browser on this service actually sends with a state-changing request:
# TestClient uses http://testserver, so this is that exact origin.
SAME_ORIGIN = "http://testserver"


def browser_write(token: str) -> dict[str, str]:
    """Headers a legitimate dashboard request carries."""
    return {auth.CSRF_HEADER: token, "Origin": SAME_ORIGIN}


def build(settings: Settings, fake_engine: FakeEngine) -> None:
    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)


@pytest.fixture
def anon(settings: Settings, fake_engine: FakeEngine):
    """A client with no credentials at all."""
    build(settings, fake_engine)
    with TestClient(main.app) as client:
        yield client


@pytest.fixture
def signed_in(settings: Settings, fake_engine: FakeEngine):
    """A client that logged in the way a browser does, plus its CSRF token."""
    build(settings, fake_engine)
    with TestClient(main.app) as client:
        token = sign_in(client)
        yield client, token


# --- what is reachable without credentials ----------------------------------


class TestTheUnauthenticatedSurface:
    """Four things, and none of them runs JavaScript."""

    def test_health_is_open_and_says_only_that_it_is_alive(self, anon: TestClient):
        response = anon.get("/healthz")
        assert response.status_code == 200
        body = response.json()
        assert set(body) <= {"status", "service"}, f"healthz reveals more than liveness: {body}"
        serialised = str(body)
        assert DASHBOARD_TOKEN not in serialised
        assert "test-control-token" not in serialised

    def test_the_login_page_is_open(self, anon: TestClient):
        response = anon.get("/auth/login")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")

    def test_the_login_stylesheet_is_open(self, anon: TestClient):
        response = anon.get("/assets/login.css")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/css")

    def test_the_login_page_runs_no_javascript(self, anon: TestClient):
        """The whole open surface, and not a line of script in it."""
        response = anon.get("/auth/login")
        page = response.text.lower()
        assert "<script" not in page
        assert "javascript:" not in page
        assert not re.search(r'\son[a-z]+\s*=', page), "the login page carries an event handler"
        csp = response.headers["content-security-policy"]
        assert "script-src 'none'" in csp, csp

    def test_the_login_page_may_submit_a_form_and_the_dashboard_may_not(
            self, signed_in):
        client, _token = signed_in
        login_csp = client.get("/auth/login").headers["content-security-policy"]
        assert "form-action 'self'" in login_csp
        dash_csp = client.get("/").headers["content-security-policy"]
        assert "form-action 'none'" in dash_csp, \
            "the relaxation for the login form leaked into the dashboard"

    @pytest.mark.parametrize("path", [
        "/", "/assets/app.js", "/assets/app.css", "/auth/csrf",
        "/v1/sessions", "/v1/sessions/s1", "/v1/sessions/s1/findings",
        "/v1/sessions/s1/events", "/v1/sessions/s1/report",
    ])
    def test_everything_else_needs_credentials(self, anon: TestClient, path: str):
        response = anon.get(path, follow_redirects=False)
        # The dashboard page redirects a person to the form; the rest refuse.
        assert response.status_code in (401, 303), f"{path} answered {response.status_code}"
        if response.status_code == 303:
            assert path == "/", f"{path} should refuse, not redirect"

    @pytest.mark.parametrize("path", [
        "/v1/sessions", "/v1/sessions/s1/start", "/v1/sessions/s1/stop", "/auth/logout",
    ])
    def test_state_changing_paths_need_credentials(self, anon: TestClient, path: str):
        assert anon.post(path, json={}).status_code == 401, path

    def test_an_unknown_asset_is_not_a_way_in(self, signed_in):
        client, _ = signed_in
        # The name is checked against a list, never joined into a path.
        for name in ("../app/main.py", "..%2fmain.py", "secrets.txt"):
            assert client.get(f"/assets/{name}").status_code in (404, 401, 403), name


# --- the dashboard refuses to be served without a credential -----------------


class TestUnconfiguredIsNotOpen:
    def test_without_a_dashboard_token_nothing_is_served(
            self, settings: Settings, fake_engine: FakeEngine):
        """Fail closed, as the engine does about its control API token."""
        build(dataclasses.replace(settings, dashboard_token=""), fake_engine)
        with TestClient(main.app) as client:
            assert client.get("/auth/login").status_code == 503
            assert client.get("/v1/sessions", headers=bearer()).status_code == 503
            assert client.get("/healthz").status_code == 200


# --- logging in --------------------------------------------------------------


class TestLogin:
    def test_the_right_token_produces_a_session(self, anon: TestClient):
        page = anon.get("/auth/login")
        field = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = anon.post("/auth/login",
                             data={"token": DASHBOARD_TOKEN, "csrf_token": field},
                             follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        cookie = response.headers.get("set-cookie", "")
        assert auth.SESSION_COOKIE in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie.replace("samesite", "SameSite")

    def test_a_wrong_token_is_refused_with_one_generic_message(self, anon: TestClient):
        page = anon.get("/auth/login")
        field = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = anon.post("/auth/login",
                             data={"token": "not-it", "csrf_token": field},
                             follow_redirects=False)
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid credentials"

    def test_a_login_without_the_paired_field_is_refused(self, anon: TestClient):
        """Login CSRF: a sign-in cannot be forced from another site."""
        anon.get("/auth/login")
        response = anon.post("/auth/login",
                             data={"token": DASHBOARD_TOKEN, "csrf_token": "forged"},
                             follow_redirects=False)
        assert response.status_code == 403

    def test_repeated_failures_lock_the_address_out(self, anon: TestClient):
        page = anon.get("/auth/login")
        field = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        codes = []
        for _ in range(8):
            codes.append(anon.post("/auth/login",
                                   data={"token": "wrong", "csrf_token": field},
                                   follow_redirects=False).status_code)
        assert 429 in codes, f"no lockout after repeated failures: {codes}"
        # And the message stays the same, so probing learns nothing.
        anon.get("/auth/login")
        locked = anon.post("/auth/login",
                           data={"token": DASHBOARD_TOKEN, "csrf_token": field},
                           follow_redirects=False)
        assert locked.json()["detail"] == "invalid credentials"

    def test_the_session_id_is_replaced_on_login(self, anon: TestClient):
        """Rotation on login, so an id planted beforehand cannot be adopted."""
        first = sign_in(anon)
        before = anon.cookies.get(auth.SESSION_COOKIE)
        anon.cookies.delete(auth.SESSION_COOKIE)
        second = sign_in(anon)
        after = anon.cookies.get(auth.SESSION_COOKIE)
        assert before and after and before != after
        assert first != second


# --- using a session ---------------------------------------------------------


class TestSessionUse:
    def test_a_signed_in_client_can_read(self, signed_in):
        client, _ = signed_in
        assert client.get("/v1/sessions").status_code == 200
        assert client.get("/").status_code == 200
        assert client.get("/assets/app.js").status_code == 200

    def test_logout_invalidates_the_session_server_side(self, signed_in):
        client, token = signed_in
        key = client.cookies.get(auth.SESSION_COOKIE)
        assert client.post("/auth/logout",
                           headers=browser_write(token)).status_code == 204
        # The key is gone from the store, not merely cleared in the browser.
        client.cookies.set(auth.SESSION_COOKIE, key)
        assert client.get("/v1/sessions").status_code == 401

    def _age_session(self, key: str, *, created_delta: float = 0.0,
                     seen_delta: float = 0.0) -> None:
        """Push a stored session's timestamps into the past.

        Ageing the row rather than shortening the lifetimes, because a lifetime of
        zero expires the session between logging in and using it, so the test
        could never reach what it means to check.
        """
        with main.database().transaction() as conn:
            conn.execute(
                "UPDATE dashboard_sessions SET created_at = created_at - ?, "
                "last_seen_at = last_seen_at - ? WHERE session_key = ?",
                (created_delta, seen_delta, key))

    def test_a_session_past_its_idle_timeout_is_refused_and_deleted(self, signed_in):
        client, _ = signed_in
        key = client.cookies.get(auth.SESSION_COOKIE)
        self._age_session(key, seen_delta=31 * 60)

        assert client.get("/v1/sessions").status_code == 401
        assert main.sessions().count() == 0, "the expired row was not deleted"

    def test_a_session_past_its_absolute_lifetime_is_refused(self, signed_in):
        """Still in active use, but old enough that the clock wins."""
        client, _ = signed_in
        key = client.cookies.get(auth.SESSION_COOKIE)
        self._age_session(key, created_delta=13 * 60 * 60)

        assert client.get("/v1/sessions").status_code == 401
        assert main.sessions().count() == 0

    def test_a_session_inside_both_limits_still_works(self, signed_in):
        """The other half: the timeouts must not refuse a live session."""
        client, _ = signed_in
        key = client.cookies.get(auth.SESSION_COOKIE)
        self._age_session(key, created_delta=60, seen_delta=60)
        assert client.get("/v1/sessions").status_code == 200

    def test_a_live_session_id_is_rotated_once_it_is_old_enough(self, signed_in):
        client, _ = signed_in
        before = client.cookies.get(auth.SESSION_COOKIE)
        with main.database().transaction() as conn:
            conn.execute("UPDATE dashboard_sessions SET rotated_at = rotated_at - ? "
                         "WHERE session_key = ?", (61 * 60, before))

        assert client.get("/v1/sessions").status_code == 200
        after = client.cookies.get(auth.SESSION_COOKIE)
        assert after and after != before, "the id was not rotated"
        # And the previous id stops working.
        client.cookies.set(auth.SESSION_COOKIE, before)
        assert client.get("/v1/sessions").status_code == 401

    def test_a_forged_session_key_is_refused(self, anon: TestClient):
        anon.cookies.set(auth.SESSION_COOKIE, auth.new_token())
        assert anon.get("/v1/sessions").status_code == 401


# --- CSRF, origin, host ------------------------------------------------------


class TestEachLayerRefusesOnItsOwn:
    """Three independent layers. Each is exercised with the others satisfied."""

    def test_a_state_change_without_the_csrf_token_is_refused(self, signed_in):
        """The CSRF layer alone, with the Origin satisfied."""
        client, _token = signed_in
        response = client.post("/v1/sessions",
                               json={"session_id": "s1", "config": {}, "seed": "ab"},
                               headers={"Origin": SAME_ORIGIN})
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_a_state_change_with_a_wrong_csrf_token_is_refused(self, signed_in):
        client, _token = signed_in
        response = client.post("/v1/sessions",
                               json={"session_id": "s1", "config": {}, "seed": "ab"},
                               headers={auth.CSRF_HEADER: auth.new_token(),
                                        "Origin": SAME_ORIGIN})
        assert response.status_code == 403

    def test_a_legitimate_browser_state_change_succeeds(self, signed_in):
        """Both layers satisfied: the request a real dashboard makes."""
        client, token = signed_in
        response = client.post("/v1/sessions",
                               json={"session_id": "s1", "config": {}, "seed": "ab"},
                               headers=browser_write(token))
        assert response.status_code == 201, response.text

    @pytest.mark.parametrize("origin,label", [
        (None, "absent"),
        ("", "empty"),
        ("null", "null"),
        ("https://evil.invalid", "another site"),
        ("http://testserver.evil.invalid", "a suffix of ours"),
        ("https://testserver", "the right host, wrong scheme"),
        ("http://testserver:8100", "the right host, wrong port"),
        ("http://TESTSERVER", "a different case"),
    ])
    def test_the_origin_must_be_this_exact_origin(self, signed_in, origin, label):
        """Origin alone, with the CSRF token satisfied every time.

        A missing Origin used to be accepted here on the reasoning that non-browser
        clients send none -- but those authenticate with a bearer header and never
        reach this branch, so the exemption covered nobody it was for and every
        cross-site request it was meant to stop.
        """
        client, token = signed_in
        headers = {auth.CSRF_HEADER: token}
        if origin is not None:
            headers["Origin"] = origin
        response = client.post("/v1/sessions",
                               json={"session_id": "s2", "config": {}, "seed": "ab"},
                               headers=headers)
        assert response.status_code == 403, f"{label} was accepted"
        assert "Origin" in response.json()["detail"]

    def test_an_unknown_host_is_refused_even_with_credentials(self, signed_in):
        """Host alone, with everything else satisfied. This is DNS rebinding."""
        client, token = signed_in
        response = client.get("/v1/sessions", headers={"Host": "rebound.invalid"})
        assert response.status_code == 421
        response = client.post("/v1/sessions",
                               json={"session_id": "s3", "config": {}, "seed": "ab"},
                               headers={auth.CSRF_HEADER: token, "Host": "rebound.invalid"})
        assert response.status_code == 421

    def test_reads_do_not_need_a_csrf_token(self, signed_in):
        client, _ = signed_in
        assert client.get("/v1/sessions").status_code == 200


# --- the bearer path ---------------------------------------------------------


class TestBearerCallers:
    """Scripts, curl and the integration suites. Same secret, no CSRF needed."""

    def test_a_bearer_caller_can_read_and_write_without_a_csrf_token(
            self, settings: Settings, fake_engine: FakeEngine):
        build(settings, fake_engine)
        with TestClient(main.app, headers=bearer()) as client:
            assert client.get("/v1/sessions").status_code == 200
            assert client.post("/v1/sessions",
                               json={"session_id": "s1", "config": {},
                                     "seed": "ab"}).status_code == 201

    def test_a_wrong_bearer_token_is_refused(self, settings: Settings,
                                            fake_engine: FakeEngine):
        build(settings, fake_engine)
        with TestClient(main.app, headers={"Authorization": "Bearer nope"}) as client:
            assert client.get("/v1/sessions").status_code == 401

    def test_the_control_api_token_is_not_a_dashboard_credential(
            self, settings: Settings, fake_engine: FakeEngine):
        """The two credentials are not interchangeable in either direction."""
        build(settings, fake_engine)
        with TestClient(main.app,
                        headers={"Authorization": f"Bearer {settings.engine_token}"}) as client:
            assert client.get("/v1/sessions").status_code == 401

    def test_bearer_callers_get_no_csrf_token(self, settings: Settings,
                                             fake_engine: FakeEngine):
        build(settings, fake_engine)
        with TestClient(main.app, headers=bearer()) as client:
            body = client.get("/auth/csrf").json()
            assert body["csrf_token"] is None


# --- the control API token never reaches a browser ---------------------------


class TestTheControlTokenStaysInside:
    def test_it_appears_in_no_response_a_browser_can_read(self, signed_in,
                                                          settings: Settings):
        client, token = signed_in
        paths = ["/", "/assets/app.js", "/assets/app.css", "/auth/csrf",
                 "/auth/login", "/assets/login.css", "/healthz", "/v1/sessions"]
        for path in paths:
            response = client.get(path)
            assert settings.engine_token not in response.text, \
                f"the control API token appears in {path}"

    def test_it_appears_in_no_dashboard_file_on_disk(self, settings: Settings):
        for path in main.DASHBOARD_DIR.rglob("*"):
            if not path.is_file():
                continue
            body = path.read_text(encoding="utf-8")
            assert settings.engine_token not in body, f"{path} carries the control token"
            assert "MIHAKK_CONTROL_TOKEN" not in body, \
                f"{path} mentions the control token variable"


# --- the declared route surface ---------------------------------------------


class TestTheRouteManifestIsComplete:
    """Every route is declared, so adding one is deliberate.

    The earlier version of this test only constrained /v1 paths. The dashboard
    adds a page, assets and auth endpoints, and an unlisted route is exactly how a
    new surface would arrive unnoticed.
    """

    def test_every_route_is_accounted_for(self):
        declared = set(main.OPEN_PATHS) | main.READ_PATHS | main.WRITE_PATHS
        actual = {route.path for route in main.app.routes
                  if getattr(route, "methods", None)}
        # FastAPI's own docs routes are not part of this surface.
        actual -= {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

        undeclared = actual - declared
        assert not undeclared, f"routes exist that the manifest does not declare: {undeclared}"

        stale = declared - actual
        assert not stale, f"the manifest declares routes that do not exist: {stale}"

    def test_no_route_forwards_a_caller_composed_request(self):
        for route in main.app.routes:
            path = route.path
            assert "proxy" not in path and "fetch" not in path and "request" not in path, path

    def test_every_v1_route_is_scoped_to_a_session(self):
        for route in main.app.routes:
            if route.path.startswith("/v1/"):
                assert route.path.startswith("/v1/sessions"), route.path

    def test_the_open_surface_is_exactly_four_entries(self):
        assert set(main.OPEN_PATHS) == {"/healthz", "/auth/login", "/assets/login.css"}
        assert main.OPEN_PATHS["/auth/login"] == {"GET", "POST"}


class TestTheChecksFailClosed:
    """A security check with nothing configured must refuse, not wave through."""

    def test_an_empty_host_allowlist_refuses_everything(self):
        assert auth.host_allowed("127.0.0.1:8100", ()) is False
        assert auth.host_allowed("localhost", ()) is False
        assert auth.host_allowed(None, ()) is False

    def test_a_populated_allowlist_still_works(self):
        allowed = ("127.0.0.1:8100", "localhost:8100")
        assert auth.host_allowed("127.0.0.1:8100", allowed) is True
        assert auth.host_allowed("LOCALHOST:8100", allowed) is True
        assert auth.host_allowed("evil.invalid", allowed) is False
        assert auth.host_allowed(None, allowed) is False

    def test_an_empty_allowlist_refuses_even_a_signed_in_caller(
            self, settings: Settings, fake_engine: FakeEngine):
        """End to end, not only the helper: nothing configured means nothing served."""
        build(dataclasses.replace(settings, allowed_hosts=()), fake_engine)
        with TestClient(main.app) as client:
            assert client.get("/auth/login").status_code == 421
            assert client.get("/v1/sessions", headers=bearer()).status_code == 421

    def test_origin_must_match_scheme_host_and_port_together(self):
        # Against a request whose real origin is http://h:1
        for rejected in (None, "", "null",
                         "http://other:1",      # another host
                         "https://h:1",         # right host, wrong scheme
                         "http://h:2",          # right host, wrong port
                         "http://h",            # port missing
                         "http://h:1.evil.test",  # ours as a prefix
                         "http://evil.test/?x=http://h:1"):
            assert auth.origin_allowed(rejected, "http", "h:1") is False, rejected

        assert auth.origin_allowed("http://h:1", "http", "h:1") is True
        # Surrounding whitespace is trimmed rather than treated as a mismatch.
        assert auth.origin_allowed("  http://h:1  ", "http", "h:1") is True
        assert auth.origin_allowed("https://h:1", "https", "h:1") is True

        # Nothing to compare against is a refusal, not a pass.
        assert auth.origin_allowed("http://h:1", None, "h:1") is False
        assert auth.origin_allowed("http://h:1", "http", None) is False
