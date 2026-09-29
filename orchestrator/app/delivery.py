"""What became of a session's requests, in words that claim no more than was seen.

A session that completed is not a session that tested anything. Three things can
happen to a request, and each surface that presents a session (the session view,
the dashboard, the JSON and HTML reports) keeps them apart:

    refused     the safety layer stopped it before it left. Nothing was sent.
    attempted   the safety layer let it through. That is all it means: a
                connection the target refused, a reset, a timeout are attempts.
    answered    a response from the target was observed. Only this is evidence
                that the target received anything.

And two units, never shown as one: CASES (the plan's cases and the baseline's
requests) and HTTP REQUESTS, one per redirect hop -- a redirected case is one
case and several requests, and the budget is charged per request.

Two judgements come out of the engine's own counts, never from the absence of
findings:

    verdict     none_attempted / partly_refused / none_refused / unknown
                -- did the safety layer let anything through?
    responses   none_answered / partly_answered / all_answered /
                not_applicable (nothing attempted) / unknown
                -- did the target answer what was attempted?

A count that is missing or unreadable is unknown. It is never zero: a session
recorded before these counts existed was not counted, and a zero would say it
was counted and came to nothing.

The session status is deliberately NOT changed by any of this. What changes is
what may be said about the target.
"""

from __future__ import annotations

from typing import Any, Optional

NONE_ATTEMPTED = "none_attempted"
PARTLY_REFUSED = "partly_refused"
NONE_REFUSED = "none_refused"
UNKNOWN = "unknown"

NONE_ANSWERED = "none_answered"
PARTLY_ANSWERED = "partly_answered"
ALL_ANSWERED = "all_answered"
NOT_APPLICABLE = "not_applicable"

COUNT_KEYS = ("cases_attempted", "cases_refused", "cases_answered",
              "baseline_attempted", "baseline_refused", "baseline_answered",
              "http_answered", "http_unanswered", "http_refused")


def _count(value: Any) -> Optional[int]:
    # bool is an int in Python; a true/false where a count belongs is unreadable.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _sum(*values: Optional[int]) -> Optional[int]:
    return None if any(v is None for v in values) else sum(values)  # type: ignore[arg-type]


def assess(counts: dict[str, Any], *, source: str, final: bool = True) -> dict[str, Any]:
    """Judge one session's counts. Pure: the same counts give the same answer."""
    c = {key: _count(counts.get(key)) for key in COUNT_KEYS}
    case_refused = _sum(c["cases_refused"], c["baseline_refused"])
    http_attempted = _sum(c["http_answered"], c["http_unanswered"])
    so_far = "" if final else "So far: "

    # The headline judgement is about actual HTTP round trips, not plan cases.
    # A case can consume several requests through redirects, and can receive a
    # response on an early hop before a later hop is refused. The case counts
    # remain useful, but cannot answer whether anything was attempted.
    refusal_known = case_refused is not None and c["http_refused"] is not None
    any_refused = refusal_known and (case_refused > 0 or c["http_refused"] > 0)
    if http_attempted is None or not refusal_known:
        verdict = UNKNOWN
        first = ("The engine did not count what it attempted and what its safety layer "
                 "refused for this session, so whether the target was contacted at all "
                 "is unknown. Do not read the absence of indicators as a result about "
                 "the target.")
    elif http_attempted == 0:
        verdict = NONE_ATTEMPTED
        first = (f"Nothing was attempted against the target. At the case level, the safety "
                 f"layer refused {c['cases_refused']} case(s) and "
                 f"{c['baseline_refused']} baseline request(s). At the per-hop HTTP level, "
                 f"it refused {c['http_refused']} connect(s). These are separate views, not "
                 "totals to add. Nothing left the engine, so this session evaluated nothing "
                 "about the target and the absence of indicators is not a result." if any_refused else
                 "Nothing was attempted against the target: no request passed the safety "
                 "layer. This session evaluated nothing about the target, and the absence "
                 "of indicators is not a result.")
    elif any_refused:
        verdict = PARTLY_REFUSED
        first = (f"At least one request was refused before sending, while "
                 f"{http_attempted} HTTP request(s) were attempted (redirect hops included). "
                 f"The separate case and HTTP counts below show each unit without adding "
                 "overlapping counts together. Indicators, and their absence, cover at most "
                 "the requests that got a response.")
    else:
        verdict = NONE_REFUSED
        first = (f"The safety layer refused nothing. {http_attempted} HTTP request(s) were "
                 "attempted (redirect hops included).")

    if verdict == NONE_ATTEMPTED:
        responses, second = NOT_APPLICABLE, ""
    elif http_attempted is None:
        responses = UNKNOWN
        second = ("The engine did not count responses for this session, so whether the "
                  "target answered anything is unknown.")
    elif c["http_answered"] == 0:
        responses = NONE_ANSWERED
        second = (f"No response was observed for any of the {http_attempted} HTTP request(s) "
                  "attempted (redirect hops included): a refused connection, a reset or a "
                  "timeout. Nothing establishes that the target received them, and nothing "
                  "here is evidence about it.")
    elif c["http_unanswered"]:
        responses = PARTLY_ANSWERED
        second = (f"{c['http_answered']} of {http_attempted} HTTP request(s) attempted "
                  f"(redirect hops included) got a response; {c['http_unanswered']} got "
                  "none. Only answered requests are evidence about the target.")
    else:
        responses = ALL_ANSWERED
        second = (f"Every one of the {http_attempted} HTTP request(s) attempted (redirect "
                  "hops included) got a response.")

    return {
        "source": source,
        "final": final,
        "verdict": verdict,
        "responses": responses,
        "message": so_far + " ".join(part for part in (first, second) if part),
        "cases": {"attempted": c["cases_attempted"], "refused": c["cases_refused"],
                  "answered": c["cases_answered"]},
        "baseline": {"attempted": c["baseline_attempted"], "refused": c["baseline_refused"],
                     "answered": c["baseline_answered"]},
        "http_requests": {"attempted": http_attempted, "answered": c["http_answered"],
                          "unanswered": c["http_unanswered"], "refused": c["http_refused"]},
    }


def from_aggregate(aggregate: dict[str, Any]) -> dict[str, Any]:
    """The engine's final record of the run, as the report reads it.

    `accounting` is null for a session recorded before it existed; every count in
    it is then unknown, not zero.
    """
    session = aggregate.get("session")
    if not isinstance(session, dict):
        session = {}
    accounting = session.get("accounting")
    if not isinstance(accounting, dict):
        accounting = {}
    counts = {key: accounting.get(key) for key in COUNT_KEYS}
    counts["cases_refused"] = session.get("refused_cases")
    return assess(counts, source="engine_record")


def from_progress(progress: Optional[dict[str, Any]], *, final: bool) -> dict[str, Any]:
    """The latest progress event the orchestrator stored, as the session view reads it."""
    if not isinstance(progress, dict):
        progress = {}
    counts = {key: progress.get(key) for key in COUNT_KEYS}
    counts["cases_attempted"] = progress.get("attempted")
    counts["cases_refused"] = progress.get("refused")
    counts["cases_answered"] = progress.get("answered")
    return assess(counts, source="progress_events", final=final)
