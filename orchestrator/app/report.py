"""Session reports, in JSON and in HTML.

Three things govern this module.

**It is derived on every read, never stored.** A report that was written to disk
would go on claiming a session complete after a later gap was discovered, which is
the mistake the whole completeness rule exists to prevent. Every request rebuilds
from the rows and the engine's aggregate as they are now.

**Completeness is the worse of two independent answers.** The orchestrator knows
whether it received everything the engine emitted; the engine knows whether it
managed to write down everything it saw. Neither implies the other, a report built
on a partial result set must say so, and each reason is attributed to the side that
found it -- "the stream broke" and "the engine could not save three cases" call for
different responses from a reader.

**The HTML is built as if the content were hostile, because some of it is.** The
engine's own indicator reason embeds bytes taken from the target's response body,
the request summary carries the mutated payload, and the response summary carries
transport error text. All of that reaches the page. So:

  - every value is escaped, in one function, and there is no path that writes a
    value into the document unescaped -- no template that could be handed raw
    markup, no string concatenation of caller data into a tag;
  - values go into text nodes only, never into an attribute, a URL, a style or a
    script context. The request URL is shown as text, not as a link, because a
    link is an attribute and a mutated URL is exactly the kind of string that
    should not become one;
  - the page contains no JavaScript at all and no event-handler attributes. A
    static document needs none, and the absence is easier to verify than any
    sanitiser;
  - nothing is loaded from anywhere: no fonts, no stylesheets, no images. Required
    in any case, since the project builds and runs with no network.

The Content-Security-Policy that backs all of that is a real response header, set
where the page is served; the meta tag here is only a fallback for a copy saved to
disk, where there are no headers left.
"""

from __future__ import annotations

import html
from typing import Any, Optional

from . import delivery as delivery_mod

REPORT_VERSION = "1"

# The engine's session statuses that mean its stored results are not everything.
# `stopped` is deliberately absent: a run an operator stopped holds everything it
# produced before the stop, and boundary 8 keeps that status as its own thing. It
# is surfaced as a note instead, so "complete" is never read as "the plan was
# covered".
ENGINE_INCOMPLETE = "incomplete"
ENGINE_FAILED = "failed"
ENGINE_STOPPED = "stopped"

THE_NOTE = (
    "Results are indicators that need verification, not confirmed vulnerabilities."
)

# Repeated wherever a partial result set is presented, because this is the
# sentence a reader most needs and most easily skips.
SUBSET_WARNING = (
    "This result set is a subset of what the run produced. Absence of a "
    "finding here does not mean the engine did not observe one."
)

# How many case ids a group shows before it stops listing them. The JSON report
# keeps every id; only the display is bounded, and it says what it left out.
CASE_ID_DISPLAY_LIMIT = 20


# --- completeness ------------------------------------------------------------


def combine_completeness(session_view: dict[str, Any],
                         aggregate: dict[str, Any]) -> dict[str, Any]:
    """Combine the orchestrator's and the engine's accounts. The worse wins."""
    orchestrator = session_view.get("completeness")
    if not isinstance(orchestrator, dict):
        orchestrator = {}
    engine = aggregate.get("completeness")
    if not isinstance(engine, dict):
        engine = {}

    reasons: list[dict[str, str]] = []

    stream_whole = orchestrator.get("complete")
    if stream_whole is not True:
        reasons.append({
            "side": "orchestrator",
            "reason": str(orchestrator.get("reason")
                          or "the events stored for this session are not provably "
                             "everything the run emitted"),
        })

    engine_saved_everything = True

    # The engine's own verdict on itself, decisive on its own.
    #
    # Counting unsaved cases and audit failures is not enough: the engine sets
    # `incomplete` when it observed something it could not write down, and it is
    # free to say so without every counter being populated -- an older record, a
    # failure counted somewhere this report does not read, a reason field the
    # engine filled and a counter it did not. Deriving completeness only from the
    # counters meant a run the engine had explicitly declared incomplete could be
    # reported as a complete result set, which is the overclaim this whole rule
    # exists to prevent. If the engine says it did not finish cleanly, that
    # settles it, whatever the counters say.
    engine_status = engine.get("engine_status")
    if engine_status == ENGINE_INCOMPLETE:
        engine_saved_everything = False
        reasons.append({
            "side": "engine",
            "reason": "the engine reported this run as incomplete: it observed "
                      "something it could not record, so the stored results are a "
                      "subset of what the run found",
        })
    elif engine_status == ENGINE_FAILED:
        engine_saved_everything = False
        reasons.append({
            "side": "engine",
            "reason": "the run failed, so nothing establishes that what is stored is "
                      "everything it would have found",
        })

    if engine.get("consistent") is not True:
        engine_saved_everything = False
        reasons.append({
            "side": "engine",
            "reason": str(engine.get("reason")
                          or "the engine's case log does not hold as many cases as "
                             "its record says were saved"),
        })
    for field, description in (
        ("unsaved_cases", "indicator(s) the engine observed and could not write down"),
        ("audit_failures", "audit event(s) the engine could not record"),
    ):
        count = engine.get(field)
        if isinstance(count, int) and count > 0:
            engine_saved_everything = False
            reasons.append({"side": "engine", "reason": f"{count} {description}"})
    if engine.get("incomplete_reason"):
        engine_saved_everything = False
        reasons.append({"side": "engine", "reason": str(engine["incomplete_reason"])})

    complete = stream_whole is True and engine_saved_everything

    combined: dict[str, Any] = {
        "complete": complete,
        "stream_whole": stream_whole is True,
        "engine_saved_everything": engine_saved_everything,
        "reasons": reasons,
        "orchestrator": {
            "events_received": orchestrator.get("events_received"),
            "events_dropped": orchestrator.get("events_dropped"),
            "last_seq": orchestrator.get("last_seq"),
            "total_seq": orchestrator.get("total_seq"),
        },
        "engine": {
            "engine_status": engine.get("engine_status"),
            "saved_cases_stated": engine.get("saved_cases_stated"),
            "cases_in_store": engine.get("cases_in_store"),
            "unsaved_cases": engine.get("unsaved_cases"),
            "audit_failures": engine.get("audit_failures"),
        },
    }
    if engine_status == ENGINE_STOPPED:
        combined["stopped_early"] = True
        combined["stopped_note"] = (
            "The run was stopped before it finished its plan. What is stored is "
            "everything it produced up to that point, which is not the same as "
            "everything the plan would have covered."
        )

    if not complete:
        combined["warning"] = SUBSET_WARNING
    return combined


# --- scope -------------------------------------------------------------------


def present_scope(aggregate: dict[str, Any]) -> dict[str, Any]:
    """Decide what may be said about the scope, and how it should be labelled.

    Three outcomes, and only the first may be called the session's scope:

      recorded and consistent -> the scope, with the authorised addresses withheld
      recorded but not consistent -> shown, labelled as NOT coherent, with the
          reason; it must not be read as the scope the run enforced
      not recorded -> a summary of target authorities, and nothing more
    """
    scope = aggregate.get("scope")
    if not isinstance(scope, dict):
        return {
            "title": "Targets summary",
            "trustworthy": False,
            "recorded": False,
            "consistent": False,
            "reason": "the engine's aggregate carries no scope block",
            "targets_summary": [],
            "targets": [],
            "digest": None,
        }

    recorded = scope.get("recorded") is True
    consistent = scope.get("consistent") is True
    trustworthy = recorded and consistent

    if trustworthy:
        title = "Scope enforced for this session"
    elif recorded:
        title = "Recorded scope — NOT internally coherent"
    else:
        title = "Targets summary — not the session's full scope"

    presented: dict[str, Any] = {
        "title": title,
        "trustworthy": trustworthy,
        "recorded": recorded,
        "consistent": consistent,
        "digest": scope.get("digest"),
        "recomputed_digest": scope.get("recomputed_digest"),
        "max_redirects": scope.get("max_redirects"),
        "targets_summary": list(scope.get("targets_summary") or []),
        "targets": [],
        "withheld": list(scope.get("withheld") or []),
    }
    if not trustworthy:
        presented["reason"] = str(scope.get("inconsistency_reason") or
                                  "the scope could not be established")

    # The structural targets are carried through as the aggregate gave them --
    # which already excludes allowed_addresses -- and filtered again here rather
    # than trusted, so a future aggregate that started including them would not
    # leak them through this path.
    for target in scope.get("targets") or []:
        if not isinstance(target, dict):
            continue
        presented["targets"].append({
            "scheme": target.get("scheme"),
            "host": target.get("host"),
            "port": target.get("port"),
            "path_prefixes": list(target.get("path_prefixes") or []),
            "methods": list(target.get("methods") or []),
        })
    return presented


# --- the JSON report ---------------------------------------------------------


class InconsistentAggregate(Exception):
    """The aggregate's declared totals and its own groups disagree.

    Raised rather than reported, because a report built on a document that
    contradicts itself cannot be trusted to account for the run -- and a 200 with
    a warning buried in it is exactly how such a report gets read as a result.
    Whether the discrepancy hides results or invents them is unknown, which is
    reason enough not to publish either answer.
    """

    def __init__(self, reason: str, conservation: dict[str, Any]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.conservation = conservation


def build_report(session_id: str, session_view: dict[str, Any],
                 aggregate: dict[str, Any],
                 classified_groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the report document. Pure: the same inputs give the same output."""
    completeness = combine_completeness(session_view, aggregate)
    totals = aggregate.get("totals")
    if not isinstance(totals, dict):
        totals = {}

    declared = totals.get("indicator_instances")
    counted = sum(g.get("occurrences", 0) for g in classified_groups
                  if isinstance(g.get("occurrences"), int))
    covered: set[str] = set()
    for group in classified_groups:
        for case_id in group.get("case_ids") or []:
            covered.add(case_id)

    conservation = {
        "declared_indicator_instances": declared,
        "occurrences_summed": counted,
        "declared_cases": totals.get("cases"),
        "cases_covered_by_groups": len(covered),
        "consistent": (declared == counted and totals.get("cases") == len(covered)),
    }
    if not conservation["consistent"]:
        conservation["reason"] = (
            f"the aggregate declares {declared} indicator instance(s) across "
            f"{totals.get('cases')} case(s), but its groups account for {counted} "
            f"instance(s) across {len(covered)} case(s); the document contradicts "
            f"itself, so no report can account for every result the engine stored"
        )

    if not conservation["consistent"]:
        raise InconsistentAggregate(conservation["reason"], conservation)

    return {
        "report_version": REPORT_VERSION,
        "session_id": session_id,
        "status": session_view.get("status"),
        "session": aggregate.get("session") or {},
        "scope": present_scope(aggregate),
        "completeness": completeness,
        # Before the groups, because it decides what they can mean: a report on
        # a session with no answered request has nothing to conclude about the target.
        "delivery": delivery_mod.from_aggregate(aggregate),
        "conservation": conservation,
        "groups": classified_groups,
        "note": THE_NOTE,
    }


# --- the HTML report ---------------------------------------------------------


def _e(value: Any) -> str:
    """The only way a value enters the document.

    Escapes for a text node, with quotes included so the same function stays safe
    if a value is ever placed in an attribute. Nothing in this module writes a
    caller-supplied value to the page except through here.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "form-action 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox"
)

_STYLE = """
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem 1rem;
       line-height: 1.5; max-width: 60rem; margin-inline: auto; }
h1, h2, h3 { line-height: 1.25; }
.banner { border: 2px solid currentColor; padding: 0.75rem 1rem; margin: 1rem 0;
          border-radius: 0.25rem; }
.banner strong { display: block; }
.group { border: 1px solid currentColor; border-radius: 0.25rem;
         padding: 0.75rem 1rem; margin: 1rem 0; }
.meta { font-size: 0.875rem; opacity: 0.85; }
pre { white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere;
      border: 1px solid currentColor; padding: 0.5rem; border-radius: 0.25rem; }
ul { margin: 0.25rem 0 0.5rem 1.25rem; padding: 0; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 0.25rem 0.5rem; vertical-align: top;
         border-bottom: 1px solid currentColor; }
code { overflow-wrap: anywhere; }
"""


def _completeness_html(completeness: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if completeness.get("stopped_early"):
        out.append("<div class=\"banner\"><strong>The run was stopped early</strong>"
                   f"<p>{_e(completeness.get('stopped_note'))}</p></div>")
    if completeness.get("complete"):
        out.append("<p class=\"banner\"><strong>Complete result set</strong>"
                   "The stored events run unbroken from the start of the run to the "
                   "end the engine reported, and the engine recorded everything it "
                   "observed.</p>")
        return out

    out.append("<div class=\"banner\">")
    out.append("<strong>Incomplete result set</strong>")
    out.append(f"<p>{_e(SUBSET_WARNING)}</p>")
    out.append("<ul>")
    for entry in completeness.get("reasons") or []:
        side = "The orchestrator" if entry.get("side") == "orchestrator" else "The engine"
        out.append(f"<li>{_e(side)}: {_e(entry.get('reason'))}</li>")
    out.append("</ul>")
    out.append("</div>")
    return out


def _scope_html(scope: dict[str, Any]) -> list[str]:
    out = [f"<h2>{_e(scope.get('title'))}</h2>"]

    if not scope.get("trustworthy"):
        out.append("<div class=\"banner\">")
        out.append("<strong>This is not an established description of what the run "
                   "was allowed to reach</strong>")
        out.append(f"<p>{_e(scope.get('reason'))}</p>")
        if scope.get("recorded"):
            out.append(f"<p class=\"meta\">stored digest: <code>{_e(scope.get('digest'))}</code>"
                       f" &middot; the stored scope hashes to: "
                       f"<code>{_e(scope.get('recomputed_digest'))}</code></p>")
        out.append("</div>")
    else:
        out.append(f"<p class=\"meta\">scope digest: <code>{_e(scope.get('digest'))}</code>"
                   f" &middot; max redirects: {_e(scope.get('max_redirects'))}</p>")

    summary = scope.get("targets_summary") or []
    if summary:
        out.append("<h3>Target authorities</h3><ul>")
        for item in summary:
            out.append(f"<li><code>{_e(item)}</code></li>")
        out.append("</ul>")

    targets = scope.get("targets") or []
    if targets:
        out.append("<h3>Authorised requests</h3>")
        out.append("<table><thead><tr><th>Scheme</th><th>Host</th><th>Port</th>"
                   "<th>Path prefixes</th><th>Methods</th></tr></thead><tbody>")
        for target in targets:
            prefixes = ", ".join(str(p) for p in target.get("path_prefixes") or [])
            methods = ", ".join(str(m) for m in target.get("methods") or [])
            out.append(
                "<tr>"
                f"<td>{_e(target.get('scheme'))}</td>"
                f"<td>{_e(target.get('host'))}</td>"
                f"<td>{_e(target.get('port'))}</td>"
                f"<td>{_e(prefixes)}</td>"
                f"<td>{_e(methods)}</td>"
                "</tr>")
        out.append("</tbody></table>")

    withheld = scope.get("withheld") or []
    if withheld:
        out.append(f"<p class=\"meta\">Withheld from this report: "
                   f"{_e(', '.join(str(w) for w in withheld))}. The digest above covers "
                   f"the full scope including what is withheld, so the omission cannot "
                   f"make a different scope hash the same.</p>")
    return out


def _empty_result(delivered: dict[str, Any]) -> str:
    """What an empty result may be said to mean, given what became of the requests."""
    verdict, responses = delivered.get("verdict"), delivered.get("responses")
    if verdict == delivery_mod.NONE_ATTEMPTED:
        return ("No indicator was stored, and none could have been: nothing was "
                "attempted against the target.")
    if verdict == delivery_mod.UNKNOWN or responses == delivery_mod.UNKNOWN:
        return ("No indicator was stored. What became of the requests is not fully "
                "known, so this is not a result about the target.")
    if responses == delivery_mod.NONE_ANSWERED:
        return ("No indicator was stored, and no response was observed from the target, "
                "so this is not a result about it.")
    if verdict == delivery_mod.PARTLY_REFUSED or responses == delivery_mod.PARTLY_ANSWERED:
        return ("No indicator was stored for the requests that were answered. Those that "
                "were refused, or got no response, tested nothing.")
    return "No indicator was stored for this session."


def _delivery_html(delivered: dict[str, Any]) -> list[str]:
    """What became of the requests. The section carries both judgements as
    data-delivery and data-responses, so a check reads them from the structure
    rather than the wording; cases and HTTP requests are two separate tables."""
    verdict = delivered.get("verdict") or delivery_mod.UNKNOWN
    responses = delivered.get("responses") or delivery_mod.UNKNOWN
    title = _DELIVERY_TITLES.get(verdict) or _RESPONSE_TITLES.get(responses)
    out = [f"<section id=\"delivery\" data-delivery=\"{_e(verdict)}\" "
           f"data-responses=\"{_e(responses)}\">",
           "<h2>What became of the requests</h2>",
           (f"<p class=\"banner\"><strong>{_e(title)}</strong>"
            f"{_e(delivered.get('message'))}</p>") if title
           else f"<p>{_e(delivered.get('message'))}</p>"]

    def shown(value: Any) -> str:
        return "unknown" if value is None else str(value)

    cases = delivered.get("cases") or {}
    baseline = delivered.get("baseline") or {}
    out.append("<table><caption>Cases (the plan's cases, and the baseline's requests)"
               "</caption><thead><tr><th></th><th>Attempted</th>"
               "<th>Ended in local refusal</th><th>Final response observed</th></tr></thead><tbody>")
    for label, block in (("Cases", cases), ("Baseline", baseline)):
        out.append(f"<tr><th>{_e(label)}</th>"
                   + "".join(f"<td><code>{_e(shown(block.get(k)))}</code></td>"
                             for k in ("attempted", "refused", "answered"))
                   + "</tr>")
    out.append("</tbody></table>")

    http = delivered.get("http_requests") or {}
    out.append("<table><caption>HTTP requests (one per redirect hop; the unit the "
               "budget is charged in)</caption><tbody>")
    for label, key in (("Response observed", "answered"),
                       ("Attempted, no response", "unanswered"),
                       ("Refused at connect (not sent)", "refused")):
        out.append(f"<tr><th>{_e(label)}</th><td><code>{_e(shown(http.get(key)))}"
                   "</code></td></tr>")
    out.append("</tbody></table></section>")
    return out


_DELIVERY_TITLES = {
    delivery_mod.NONE_ATTEMPTED: "Nothing was attempted against the target",
    delivery_mod.PARTLY_REFUSED: "Part of this session was refused before sending",
    delivery_mod.UNKNOWN: "Whether anything was attempted is unknown",
}
_RESPONSE_TITLES = {
    delivery_mod.NONE_ANSWERED: "No response was observed from the target",
    delivery_mod.PARTLY_ANSWERED: "Some requests got no response",
    delivery_mod.UNKNOWN: "Whether the target answered is unknown",
}


def _group_html(group: dict[str, Any]) -> list[str]:
    signature = group.get("signature") or {}
    classification = group.get("classification") or {}
    representative = group.get("representative") or {}
    request = representative.get("request_summary") or {}
    response = representative.get("response_summary") or {}
    case_ids = group.get("case_ids") or []

    out = ["<div class=\"group\">"]
    out.append(f"<h3>{_e(signature.get('indicator_type'))} &mdash; "
               f"{_e(signature.get('method'))} {_e(signature.get('path'))}</h3>")

    status = signature.get("status_code")
    bits = [f"occurrences: {_e(group.get('occurrences'))}",
            f"cases: {_e(len(case_ids))}",
            f"target: {_e(signature.get('target'))}"]
    if status is not None:
        bits.append(f"status: {_e(status)}")
    out.append(f"<p class=\"meta\">{' &middot; '.join(bits)}</p>")

    out.append(f"<p><strong>Confidence: {_e(classification.get('confidence'))}</strong>"
               f" &middot; priority: {_e(classification.get('priority'))}</p>")
    out.append(f"<p class=\"meta\">{_e(classification.get('note'))}</p>")
    out.append("<h4>Why it is rated this way</h4><ul>")
    for sentence in classification.get("rationale") or []:
        out.append(f"<li>{_e(sentence)}</li>")
    out.append("</ul>")

    out.append("<h4>What the engine observed</h4>")
    # The reason embeds bytes from the target's response body. It goes in a text
    # node, escaped, and nowhere else.
    out.append(f"<pre>{_e(representative.get('reason'))}</pre>")

    out.append("<h4>Representative case</h4>")
    out.append("<table><tbody>")
    # The URL is shown as text. It is a mutated string from the run, and turning it
    # into an href would put caller-influenced data into an attribute.
    for label, value in (
        ("Case id", representative.get("case_id")),
        ("Case index", representative.get("case_index")),
        ("Method", request.get("method")),
        ("URL (shown as text, not a link)", request.get("url")),
        ("Status code", response.get("status_code")),
        ("Latency (ms)", response.get("latency_ms")),
        ("Response bytes", response.get("body_bytes")),
        ("Transport error", response.get("error")),
    ):
        if value is None or value == "":
            continue
        out.append(f"<tr><th>{_e(label)}</th><td><code>{_e(value)}</code></td></tr>")
    out.append("</tbody></table>")

    body_preview = request.get("body_preview")
    if body_preview:
        out.append("<h4>Request body (mutated, redacted)</h4>")
        out.append(f"<pre>{_e(body_preview)}</pre>")

    out.append("<h4>How to reproduce it</h4>")
    reproduction = representative.get("reproduction") or {}
    out.append("<table><tbody>")
    for label, key in (("Engine version", "engine_version"), ("Seed", "master_seed"),
                       ("Case index", "case_index"), ("Corpus digest", "corpus_digest"),
                       ("Config digest", "config_digest"), ("Mutation target", "target")):
        out.append(f"<tr><th>{_e(label)}</th>"
                   f"<td><code>{_e(reproduction.get(key))}</code></td></tr>")
    out.append("</tbody></table>")

    out.append(f"<h4>Cases in this group ({_e(len(case_ids))})</h4>")
    shown = case_ids[:CASE_ID_DISPLAY_LIMIT]
    out.append("<p class=\"meta\">")
    out.append(" ".join(f"<code>{_e(cid)}</code>" for cid in shown))
    out.append("</p>")
    if len(case_ids) > len(shown):
        out.append(f"<p class=\"meta\">{_e(len(case_ids) - len(shown))} further case id(s) "
                   f"are not listed here; the JSON report carries all of them.</p>")

    out.append("</div>")
    return out


def render_html(report: dict[str, Any]) -> str:
    """Render the report as a single self-contained page.

    No script of any kind, no event-handler attribute, no external reference, and
    every caller-supplied value passed through _e.
    """
    session = report.get("session") or {}
    completeness = report.get("completeness") or {}
    conservation = report.get("conservation") or {}

    parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        # A fallback for a copy saved to disk, where the real header is gone. The
        # served response carries the same policy as an HTTP header.
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_e(CSP)}\">",
        f"<title>Mihakk report &mdash; {_e(report.get('session_id'))}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Mihakk session report</h1>",
        f"<p class=\"meta\">session <code>{_e(report.get('session_id'))}</code>"
        f" &middot; status <code>{_e(report.get('status'))}</code>"
        f" &middot; engine <code>{_e(session.get('engine_version'))}</code></p>",
        f"<p class=\"banner\"><strong>What these results are</strong>{_e(THE_NOTE)}</p>",
    ]

    delivered = report.get("delivery") or {}
    parts.extend(_delivery_html(delivered))

    parts.append("<h2>Completeness</h2>")
    parts.extend(_completeness_html(completeness))

    if conservation and conservation.get("consistent") is False:
        parts.append("<div class=\"banner\"><strong>The aggregate does not add up</strong>"
                     f"<p>{_e(conservation.get('reason'))}</p></div>")

    parts.extend(_scope_html(report.get("scope") or {}))

    parts.append("<h2>The run</h2>")
    parts.append("<table><tbody>")
    for label, key in (("Operator", "operator"), ("Started", "started_at"),
                       ("Ended", "ended_at"), ("Planned cases", "planned_cases"),
                       ("Cases completed without local refusal (legacy count)", "executed_cases"),
                       ("Cases ending in local refusal", "refused_cases"),
                       ("Saved cases", "saved_cases"),
                       ("Corpus digest", "corpus_digest"),
                       ("Config digest", "config_digest")):
        value = session.get(key)
        if value is None:
            continue
        parts.append(f"<tr><th>{_e(label)}</th><td><code>{_e(value)}</code></td></tr>")
    parts.append("</tbody></table>")

    groups = report.get("groups") or []
    parts.append(f"<h2>Grouped indicators ({_e(len(groups))})</h2>")
    if not groups:
        # Not "no indicator was stored" on its own: that reads as a result.
        parts.append(f"<p data-delivery=\"{_e(delivered.get('verdict'))}\">"
                     f"{_e(_empty_result(delivered))}</p>")
        if not completeness.get("complete"):
            parts.append(f"<p class=\"banner\">{_e(SUBSET_WARNING)}</p>")
    for group in groups:
        parts.extend(_group_html(group))

    parts.append(f"<hr><p class=\"meta\">{_e(THE_NOTE)}</p>")
    parts.append("</body></html>")
    return "\n".join(parts)


def report_headers() -> dict[str, str]:
    """The headers the HTML report is served with.

    The policy belongs in a response header, not only in a meta tag: the browser
    reaches this over HTTP, and several directives are ignored in meta. nosniff
    matters because a report full of target-controlled bytes must never be
    re-interpreted as some other content type.
    """
    return {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": CSP,
    }
