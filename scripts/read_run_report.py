"""Judge a live run from the orchestrator's own API responses.

This exists because the checks it performs read values that came off an HTTP
response. An earlier version of the live integration script had python print
`KEY=value` lines which bash then `source`d -- that is, it executed a file built
out of a server's reply as shell. A reason string containing `$(...)` would have
run. Nothing here is executed: values are parsed, type-checked and compared, and
the only thing the caller reads back is a verdict line.

Output is one line per check:

    PASS<TAB>message
    FAIL<TAB>message
    UNVERIFIED<TAB>message

Tabs, newlines and carriage returns are stripped from messages, so one check is
always exactly one line however hostile the input was.

    exit 0  every check passed
    exit 1  at least one check failed
    exit 2  at least one check could not be judged -- which is not a pass. A
            missing field means the answer is unknown, and unknown must never
            read as clean.
"""

from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNVERIFIED = 2

PASS = "PASS"
FAIL = "FAIL"
UNVERIFIED = "UNVERIFIED"


def flatten(text: object) -> str:
    """Make any value safe to emit as one field of one line.

    Control characters are what would let a crafted response forge extra
    verdict lines, so they go. The result is data for display, never code.
    """
    s = str(text)
    for ch in ("\t", "\n", "\r", "\x00"):
        s = s.replace(ch, " ")
    return s.strip()


class Report:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def add(self, verdict: str, message: str) -> None:
        self.lines.append((verdict, flatten(message)))

    def exit_code(self) -> int:
        verdicts = {v for v, _ in self.lines}
        if UNVERIFIED in verdicts:
            return EXIT_UNVERIFIED
        if FAIL in verdicts:
            return EXIT_FAILED
        return EXIT_OK


def load(path: str, report: Report, label: str) -> object | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        report.add(UNVERIFIED, f"{label} could not be read: {exc}")
        return None
    if not text.strip():
        report.add(UNVERIFIED, f"{label} is empty; the request to the orchestrator likely failed")
        return None
    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError) as exc:
        report.add(UNVERIFIED, f"{label} is not valid JSON ({exc})")
        return None


def as_dict(value: object, report: Report, label: str) -> dict | None:
    if not isinstance(value, dict):
        report.add(UNVERIFIED, f"{label} is {type(value).__name__}, not an object")
        return None
    return value


def compare_case_ids(events: object, findings: list, report: Report) -> None:
    """Match the findings stored against the findings the engine announced.

    "Some findings arrived and their recipes look intact" is a weaker claim than
    the acceptance criterion makes: it passes even if a case the engine reported
    never reached the table, because a complete event sequence says nothing about
    whether every finding inside it was written down. So the case ids are
    compared, not counted.
    """
    if not isinstance(events, list):
        report.add(UNVERIFIED, "the event list is unavailable, so case ids cannot be compared")
        return

    announced: list[str] = []
    for event in events:
        if not isinstance(event, dict) or event.get("type") != "finding":
            continue
        body = event.get("finding")
        if not isinstance(body, dict):
            report.add(UNVERIFIED,
                       f"a finding event (seq {event.get('seq')}) carries no finding object")
            return
        case_id = body.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            report.add(UNVERIFIED,
                       f"a finding event (seq {event.get('seq')}) carries no case_id")
            return
        announced.append(case_id)

    stored: list[str] = []
    for item in findings:
        case_id = item.get("case_id") if isinstance(item, dict) else None
        if not isinstance(case_id, str) or not case_id:
            report.add(UNVERIFIED, "a stored finding carries no case_id")
            return
        stored.append(case_id)

    if not announced:
        report.add(UNVERIFIED,
                   "no finding event was found in the stream, so there is nothing to "
                   "compare the stored findings against")
        return

    announced_set = set(announced)
    stored_set = set(stored)

    if len(stored) != len(stored_set):
        duplicates = sorted({c for c in stored if stored.count(c) > 1})
        report.add(FAIL, f"the same case is stored more than once: {duplicates[:5]}")
        return

    missing = sorted(announced_set - stored_set)
    extra = sorted(stored_set - announced_set)

    if missing or extra:
        detail = []
        if missing:
            detail.append(f"{len(missing)} announced but not stored (e.g. {missing[:5]})")
        if extra:
            detail.append(f"{len(extra)} stored but never announced (e.g. {extra[:5]})")
        report.add(FAIL, "the stored findings do not match what the engine announced: "
                         + "; ".join(detail))
        return

    if len(stored_set) != len(announced_set):
        report.add(FAIL, f"case id counts differ: {len(announced_set)} announced, "
                         f"{len(stored_set)} stored")
        return

    note = ""
    if len(announced) != len(announced_set):
        # Legitimate: the findings table is keyed on (session, case), so a resent
        # event collapses. Said out loud so it is not mistaken for loss.
        note = (f" (the stream carried {len(announced)} finding events for "
                f"{len(announced_set)} distinct cases; duplicates collapse on store)")
    report.add(PASS, f"every case id the engine announced is stored, and no other: "
                     f"{len(stored_set)} of {len(announced_set)}{note}")


def judge(view: dict, findings_body: dict, events_body: dict, report: Report) -> None:
    completeness = view.get("completeness")
    if not isinstance(completeness, dict):
        report.add(UNVERIFIED, "the session view carries no completeness block")
        completeness = {}

    # --- the session settled the way a whole run should ---
    status = view.get("status")
    if not isinstance(status, str) or not status:
        report.add(UNVERIFIED, "the session view carries no status")
    elif status == "completed":
        report.add(PASS, "the session completed: the engine finished and the stream arrived whole")
    else:
        report.add(FAIL, f"the session ended as {status!r}, not 'completed'; "
                         f"reason: {view.get('incomplete_reason')}")

    engine_status = view.get("engine_status")
    if engine_status is None:
        report.add(UNVERIFIED, "the engine's own status never reached the orchestrator")
    elif engine_status == "completed":
        report.add(PASS, "the engine's own status crossed the wire intact ('completed')")
    else:
        report.add(FAIL, f"the engine status arrived as {engine_status!r}")

    # --- the stream carried what it should have ---
    events = events_body.get("events")
    if not isinstance(events, list):
        report.add(UNVERIFIED, "the events response carries no event list")
        events = None

    received = completeness.get("events_received")
    if events is None or not isinstance(received, int):
        report.add(UNVERIFIED, "cannot tell how many events were stored")
    elif len(events) == 0:
        report.add(FAIL, "no events were stored; the stream carried nothing")
    elif len(events) != received:
        report.add(UNVERIFIED,
                   f"only {len(events)} of {received} stored events were fetched, "
                   "so the sequence cannot be judged from this page")
    else:
        report.add(PASS, f"NDJSON events survived a real connection ({len(events)} stored)")

        seqs = sorted(e.get("seq") for e in events
                      if isinstance(e, dict) and isinstance(e.get("seq"), int))
        last_seq = completeness.get("last_seq")
        total_seq = completeness.get("total_seq")
        if len(seqs) != len(events):
            report.add(UNVERIFIED, "an event arrived without an integer seq")
        elif not isinstance(last_seq, int) or not isinstance(total_seq, int):
            report.add(UNVERIFIED,
                       f"last_seq/total_seq are not both integers "
                       f"({last_seq!r}/{total_seq!r})")
        elif seqs == list(range(1, len(seqs) + 1)) and last_seq == total_seq:
            report.add(PASS, f"the stored sequence runs 1..{total_seq} with no gap, "
                             "proved from the rows")
        else:
            report.add(FAIL, f"the stored sequence is not provably whole "
                             f"(last={last_seq} total={total_seq})")

    complete = completeness.get("complete")
    if not isinstance(complete, bool):
        report.add(UNVERIFIED, f"completeness.complete is {complete!r}, not a boolean")
    elif complete:
        report.add(PASS, "the orchestrator reports the result set as complete")
    else:
        report.add(FAIL, f"the orchestrator reports the result set as incomplete: "
                         f"{completeness.get('reason')}")

    # --- the findings arrived whole ---
    findings = findings_body.get("findings")
    if not isinstance(findings, list):
        report.add(UNVERIFIED, "the findings response carries no findings list")
        return

    if not findings:
        report.add(FAIL, "no findings reached storage, though the testbed has planted behaviours")
        return
    report.add(PASS, f"findings were extracted from the stream into SQLite ({len(findings)})")

    compare_case_ids(events, findings, report)

    recipe_fields = ("engine_version", "master_seed", "corpus_digest", "config_digest")
    intact = 0
    unreadable = 0
    rated = 0
    for finding in findings:
        if not isinstance(finding, dict):
            unreadable += 1
            continue
        recipe = finding.get("reproduction")
        if isinstance(recipe, dict) and all(recipe.get(f) for f in recipe_fields):
            intact += 1
        indicators = finding.get("indicators")
        if isinstance(indicators, list):
            for indicator in indicators:
                if isinstance(indicator, dict) and "confidence" in indicator:
                    rated += 1
        else:
            unreadable += 1

    if unreadable:
        report.add(UNVERIFIED, f"{unreadable} finding(s) could not be inspected")
    elif intact == len(findings):
        report.add(PASS, "every stored finding kept its full regeneration recipe across the wire")
    else:
        report.add(FAIL, f"a finding lost its regeneration recipe in transit "
                         f"({intact}/{len(findings)})")

    # The engine records what it saw; rating it belongs to the analysis phase.
    if rated == 0:
        report.add(PASS, "no engine-produced indicator carries a confidence rating")
    else:
        report.add(FAIL, f"{rated} indicator(s) arrived already rated by the engine")


def main() -> int:
    report = Report()
    if len(sys.argv) != 4:
        report.add(UNVERIFIED,
                   "usage: read_run_report.py <session-view> <findings> <events>")
        emit(report)
        return report.exit_code()

    view = as_dict(load(sys.argv[1], report, "the session view"), report, "the session view")
    findings = as_dict(load(sys.argv[2], report, "the findings response"),
                       report, "the findings response")
    events = as_dict(load(sys.argv[3], report, "the events response"),
                     report, "the events response")

    if view is None or findings is None or events is None:
        report.add(UNVERIFIED, "the run cannot be judged from these responses")
        emit(report)
        return report.exit_code()

    judge(view, findings, events, report)
    emit(report)
    return report.exit_code()


def emit(report: Report) -> None:
    for verdict, message in report.lines:
        sys.stdout.write(f"{verdict}\t{message}\n")


if __name__ == "__main__":
    sys.exit(main())
