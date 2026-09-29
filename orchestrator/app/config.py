"""Runtime configuration, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Everything the orchestrator needs to run."""

    database_path: str
    engine_base_url: str
    engine_token: str

    # How long to wait before reconnecting to a dropped event stream.
    reconnect_delay_seconds: float
    # How many times to retry a dropped stream before giving up and marking
    # the session interrupted.
    reconnect_attempts: int

    # --- the dashboard -----------------------------------------------------
    #
    # These carry defaults so that a Settings built without them is the SAFE
    # shape, not a broken one: an empty dashboard_token means the dashboard is
    # not served at all. The engine makes the same choice about its control API
    # token -- refuse rather than default to open.

    # Deliberately NOT the control API token: that one reaches the engine and
    # must never be in a browser's hands, not even briefly.
    dashboard_token: str = ""

    # A session's absolute lifetime and its idle timeout, whichever expires
    # first, so a leaked cookie has a horizon either way.
    session_absolute_seconds: int = 12 * 60 * 60
    session_idle_seconds: int = 30 * 60
    # How often a live session's id is replaced, narrowing the window in which a
    # leaked id is worth anything.
    session_rotate_seconds: int = 60 * 60

    # Failed logins tolerated from one address inside the window. The token is
    # generated and long, so entropy is the real barrier; this is depth.
    login_max_failures: int = 5
    login_window_seconds: int = 300
    login_lockout_seconds: int = 300

    # Host header values the dashboard answers to. A name an attacker controls
    # can be made to resolve to loopback, which makes their page same-origin
    # with this service as far as the browser is concerned; the Host header is
    # what still distinguishes them.
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:8100", "localhost:8100",
                                      "127.0.0.1", "localhost")

    @property
    def engine_configured(self) -> bool:
        return bool(self.engine_base_url and self.engine_token)

    @property
    def dashboard_enabled(self) -> bool:
        """Whether the dashboard may be served at all."""
        return bool(self.dashboard_token.strip())


@dataclass(frozen=True)
class EngineEndpoint:
    """Where the engine's control API is, and how to get there."""

    # What httpx puts in front of every request path.
    base_url: str
    # The control socket, when the API is on one. None means plain TCP.
    socket_path: str | None = None


# A socket URL names a file and nothing else. The host part httpx sends is
# fixed, because over a socket it identifies nothing.
_SOCKET_PREFIX = "unix:"
_SOCKET_HOST = "http://engine"


def engine_endpoint(url: str) -> EngineEndpoint:
    """Read MIHAKK_ENGINE_URL, refusing anything that is not clearly one of two forms.

        unix:/absolute/path/to/control.sock   the deployed shape, since phase 8a
        http://host:port                      stub engines and local runs

    A malformed value is an error, not a guess: the alternative to failing here is
    an orchestrator that starts, looks healthy, and reaches nothing -- or reaches
    something it was not meant to.
    """
    if url.startswith(_SOCKET_PREFIX):
        path = url[len(_SOCKET_PREFIX):]
        if path.startswith("//"):
            raise ValueError(
                "MIHAKK_ENGINE_URL: write a socket as unix:/path, not unix://path")
        if not path.startswith("/"):
            raise ValueError("MIHAKK_ENGINE_URL: the socket path must be absolute")
        if any(ch in path for ch in "?#") or any(ord(ch) < 0x21 for ch in path):
            raise ValueError("MIHAKK_ENGINE_URL: the socket path carries characters "
                             "a file name here never needs")
        if "/../" in path + "/" or "/./" in path + "/":
            raise ValueError("MIHAKK_ENGINE_URL: the socket path must be normalised")
        return EngineEndpoint(base_url=_SOCKET_HOST, socket_path=path)
    if url.startswith(("http://", "https://")):
        return EngineEndpoint(base_url=url)
    raise ValueError("MIHAKK_ENGINE_URL must be unix:/path/to/socket or an http(s) URL")


def load_settings() -> Settings:
    return Settings(
        database_path=os.environ.get("MIHAKK_DB", "./data/mihakk.db"),
        # Deployed, the engine is on a Unix socket in a volume the two services
        # share, and on no network. The TCP default serves local runs; there is
        # no default pointing anywhere public.
        engine_base_url=os.environ.get("MIHAKK_ENGINE_URL", "http://engine:8900"),
        engine_token=os.environ.get("MIHAKK_CONTROL_TOKEN", ""),
        reconnect_delay_seconds=float(os.environ.get("MIHAKK_RECONNECT_DELAY", "0.5")),
        reconnect_attempts=int(os.environ.get("MIHAKK_RECONNECT_ATTEMPTS", "5")),
        dashboard_token=os.environ.get("MIHAKK_DASHBOARD_TOKEN", ""),
        session_absolute_seconds=int(
            os.environ.get("MIHAKK_SESSION_ABSOLUTE_SECONDS", str(12 * 60 * 60))),
        session_idle_seconds=int(
            os.environ.get("MIHAKK_SESSION_IDLE_SECONDS", str(30 * 60))),
        session_rotate_seconds=int(
            os.environ.get("MIHAKK_SESSION_ROTATE_SECONDS", str(60 * 60))),
        login_max_failures=int(os.environ.get("MIHAKK_LOGIN_MAX_FAILURES", "5")),
        login_window_seconds=int(os.environ.get("MIHAKK_LOGIN_WINDOW_SECONDS", "300")),
        login_lockout_seconds=int(os.environ.get("MIHAKK_LOGIN_LOCKOUT_SECONDS", "300")),
        allowed_hosts=tuple(
            h.strip() for h in os.environ.get(
                "MIHAKK_ALLOWED_HOSTS",
                "127.0.0.1:8100,localhost:8100,127.0.0.1,localhost",
            ).split(",") if h.strip()),
    )
