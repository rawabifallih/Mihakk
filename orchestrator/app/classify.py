"""Rating the engine's observations, and saying why.

The engine records what it saw and what it compared it against. It assigns no
confidence, on purpose: judging how much to trust an observation is a different
job from making it, and a number invented at the point of measurement would be
guessed at. This module is that different job.

Two things this is not.

It is not a severity model. `confidence` here answers "how much should a reader
trust that this observation means something about the application", not "how bad
would it be". A 500 the application returned about itself is a high-confidence
observation and might still be trivial; a latency outlier is a low-confidence
observation and might be the most serious thing in the run. Conflating the two is
how a tool starts telling people what to fix first on the strength of a timing
measurement.

It is not a verdict. Nothing here decides a group is a vulnerability. Every rule
that fires contributes a sentence, and the sentences are carried into the report
so a reader can disagree with the reasoning rather than only with the conclusion.

The rules are deliberately dull and readable. There is no model, no scoring
weights to tune, and no threshold that changes with the data -- a rule either
fired or it did not, and it says so in words.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# The engine's indicator types. Kept in step with schemas/case.schema.json, whose
# parity with the engine's own constants is enforced by a test on the Go side.
HTTP_5XX = "http_5xx"
TIMEOUT = "timeout"
CONNECTION_ERROR = "connection_error"
APP_ERROR_PATTERN = "app_error_pattern"
LATENCY_ANOMALY = "latency_anomaly"
SIZE_ANOMALY = "size_anomaly"

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}
_LEVELS = [LOW, MEDIUM, HIGH]

# What the tool will not say, in the one place that could be tempted to say it.
NOT_A_VERDICT = (
    "This is an indicator that needs verification, not a confirmed vulnerability."
)


def _raise(level: str, steps: int = 1) -> str:
    return _LEVELS[min(_ORDER[level] + steps, _ORDER[HIGH])]


def _lower(level: str, steps: int = 1) -> str:
    return _LEVELS[max(_ORDER[level] - steps, _ORDER[LOW])]


@dataclass
class Classification:
    """A rating and the reasoning that produced it."""

    confidence: str
    priority: str
    # One sentence per rule that fired, in the order they were applied.
    rationale: list[str] = field(default_factory=list)
    note: str = NOT_A_VERDICT

    def as_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "priority": self.priority,
            "rationale": list(self.rationale),
            "note": self.note,
        }


# --- the base rules ---------------------------------------------------------
#
# Each entry is (confidence, the sentence explaining it). The sentence is the
# point: a reader who disagrees with the rating can see what it rests on.

_BASE: dict[str, tuple[str, str]] = {
    HTTP_5XX: (
        HIGH,
        "The application answered with a 5xx status, which is the application "
        "reporting its own failure rather than an inference drawn about it.",
    ),
    APP_ERROR_PATTERN: (
        MEDIUM,
        "The response carried an error signature that the unmutated sample's "
        "response did not, so the input changed how the application behaved; what "
        "the signature means is not established here.",
    ),
    TIMEOUT: (
        MEDIUM,
        "The request did not complete within the per-request timeout. The engine "
        "cannot tell a stalled application from a slow network or a loaded test "
        "machine, so the observation is real but its cause is not established.",
    ),
    CONNECTION_ERROR: (
        MEDIUM,
        "The request failed before a response arrived. As with a timeout, the "
        "engine cannot distinguish the application refusing or dropping the "
        "connection from a fault on the path to it.",
    ),
    LATENCY_ANOMALY: (
        LOW,
        "The response was slower than the unmutated sample's median by more than "
        "the threshold. Timing varies for reasons that have nothing to do with the "
        "input, and this indicator is the noisiest the engine produces.",
    ),
    SIZE_ANOMALY: (
        LOW,
        "The response body differed in size from the unmutated sample's median by "
        "more than the threshold. A size difference can be an ordinary difference "
        "in content.",
    ),
}

_UNKNOWN_TYPE = (
    LOW,
    "The engine reported an indicator type this analysis does not recognise, so it "
    "is rated no higher than the least trusted kind until someone looks at it.",
)

# How many distinct mutations must land on one signature before repetition counts
# for anything. Two could be a coincidence of neighbouring inputs.
_REPETITION_THRESHOLD = 5


def classify_group(group: dict[str, Any], *,
                   reproduced: Optional[bool] = None,
                   baseline_unstable: bool = False) -> Classification:
    """Rate one aggregated group.

    `reproduced` is three-valued on purpose: True means a reproduce run was
    performed and the indicator reappeared, False means it was performed and did
    not, and None means none was performed. None must never be read as False --
    "we did not check" and "we checked and it did not recur" are different facts,
    and collapsing them would let an unchecked group look worse than a checked one.
    """
    signature = group.get("signature") or {}
    indicator_type = signature.get("indicator_type")

    level, sentence = _BASE.get(indicator_type, _UNKNOWN_TYPE)
    rationale = [sentence]

    # --- repetition across independent mutations ---
    occurrences = group.get("occurrences")
    case_ids = group.get("case_ids") or []
    distinct = len(case_ids)
    if isinstance(occurrences, int) and distinct >= _REPETITION_THRESHOLD:
        level = _raise(level)
        rationale.append(
            f"{distinct} different mutations of the same endpoint produced it, so it "
            f"is a repeatable response to a class of input rather than a one-off."
        )
    elif distinct == 1:
        rationale.append(
            "Only one mutation produced it, so there is nothing yet to show it is "
            "repeatable."
        )

    # --- a shaky sense of normal ---
    if baseline_unstable and indicator_type in (LATENCY_ANOMALY, SIZE_ANOMALY):
        level = _lower(level)
        rationale.append(
            "The run reported its baseline as unstable, and this indicator is a "
            "comparison against that baseline, so the comparison itself is doubtful."
        )
    elif baseline_unstable:
        rationale.append(
            "The run reported its baseline as unstable. This indicator does not "
            "depend on the baseline, so the rating is unchanged."
        )

    # --- did anyone re-run it? ---
    if reproduced is True:
        level = _raise(level)
        rationale.append(
            "A reproduce run was performed and the same indicator was observed "
            "again, which makes it easier to investigate. It remains an indicator."
        )
    elif reproduced is False:
        level = _lower(level)
        rationale.append(
            "A reproduce run was performed and the indicator did not reappear, so "
            "it may have depended on conditions that no longer hold."
        )
    else:
        rationale.append(
            "No reproduce run was performed for this group, so nothing here says "
            "whether it recurs."
        )

    return Classification(confidence=level, priority=level, rationale=rationale)


def classify_document(aggregate: dict[str, Any], *,
                      reproduced: Optional[dict[str, bool]] = None,
                      baseline_unstable: bool = False) -> list[dict[str, Any]]:
    """Rate every group, returning one entry per group in the document's order.

    The document's order is already deterministic, and it is preserved rather than
    re-sorted by rating: sorting by confidence would bury a low-confidence group
    that happens to matter, and the report can order its own display.
    """
    reproduced = reproduced or {}
    groups = aggregate.get("groups") or []
    out: list[dict[str, Any]] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        result = classify_group(
            group,
            reproduced=reproduced.get(group.get("group_id")),
            baseline_unstable=baseline_unstable,
        )
        entry = dict(group)
        entry["classification"] = result.as_dict()
        out.append(entry)
    return out
