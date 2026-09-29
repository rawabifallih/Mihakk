"""The classification rules.

Two properties are worth more than any individual rating.

Confidence is about the observation, not the damage. The tests below assert the
ordering the rules encode -- a 500 the application reported about itself is trusted
more than a timing outlier -- and never that one is "worse" than the other.

Every rating carries its reasoning. A rule that fires without a sentence would
leave a reader with a level and nothing to disagree with, so the rationale is
checked as strictly as the level.
"""

from __future__ import annotations

from app import classify
from conftest import aggregate_document, aggregate_group


def group(indicator_type: str, *, cases: int = 1) -> dict:
    return aggregate_group(
        indicator_type=indicator_type,
        case_ids=[f"s1-{i:06d}" for i in range(1, cases + 1)],
    )


class TestTheBaseRules:
    def test_an_application_reported_failure_is_trusted_most(self):
        result = classify.classify_group(group(classify.HTTP_5XX))
        assert result.confidence == classify.HIGH
        assert any("reporting its own failure" in s for s in result.rationale)

    def test_timing_is_trusted_least(self):
        result = classify.classify_group(group(classify.LATENCY_ANOMALY))
        assert result.confidence == classify.LOW
        assert any("noisiest" in s for s in result.rationale)

    def test_a_transport_failure_says_it_cannot_apportion_blame(self):
        for kind in (classify.TIMEOUT, classify.CONNECTION_ERROR):
            result = classify.classify_group(group(kind))
            assert result.confidence == classify.MEDIUM
            assert any("cannot" in s for s in result.rationale), \
                f"{kind} should admit what it cannot establish: {result.rationale}"

    def test_the_ordering_is_what_the_rules_encode(self):
        order = {classify.LOW: 0, classify.MEDIUM: 1, classify.HIGH: 2}
        five_hundred = classify.classify_group(group(classify.HTTP_5XX))
        latency = classify.classify_group(group(classify.LATENCY_ANOMALY))
        assert order[five_hundred.confidence] > order[latency.confidence]

    def test_an_unknown_type_is_rated_low_and_says_so(self):
        result = classify.classify_group(group("something_new"))
        assert result.confidence == classify.LOW
        assert any("does not recognise" in s for s in result.rationale)


class TestRepetition:
    def test_many_distinct_mutations_raise_confidence(self):
        one = classify.classify_group(group(classify.LATENCY_ANOMALY, cases=1))
        many = classify.classify_group(group(classify.LATENCY_ANOMALY, cases=12))
        order = {classify.LOW: 0, classify.MEDIUM: 1, classify.HIGH: 2}
        assert order[many.confidence] > order[one.confidence]
        assert any("different mutations" in s for s in many.rationale)

    def test_a_single_occurrence_says_nothing_is_established_yet(self):
        result = classify.classify_group(group(classify.LATENCY_ANOMALY, cases=1))
        assert any("nothing yet to show it is repeatable" in s for s in result.rationale)

    def test_repetition_cannot_push_past_high(self):
        result = classify.classify_group(group(classify.HTTP_5XX, cases=50))
        assert result.confidence == classify.HIGH


class TestBaselineStability:
    def test_an_unstable_baseline_lowers_a_comparison_against_it(self):
        steady = classify.classify_group(group(classify.LATENCY_ANOMALY, cases=12))
        shaky = classify.classify_group(group(classify.LATENCY_ANOMALY, cases=12),
                                       baseline_unstable=True)
        order = {classify.LOW: 0, classify.MEDIUM: 1, classify.HIGH: 2}
        assert order[shaky.confidence] < order[steady.confidence]
        assert any("comparison itself is doubtful" in s for s in shaky.rationale)

    def test_an_unstable_baseline_does_not_touch_a_status_code(self):
        """A 500 is not a comparison, so a shaky baseline is irrelevant to it."""
        steady = classify.classify_group(group(classify.HTTP_5XX))
        shaky = classify.classify_group(group(classify.HTTP_5XX), baseline_unstable=True)
        assert shaky.confidence == steady.confidence
        assert any("rating is unchanged" in s for s in shaky.rationale)


class TestReproduction:
    def test_not_checked_is_not_the_same_as_did_not_recur(self):
        """The distinction the three-valued argument exists for."""
        unchecked = classify.classify_group(group(classify.HTTP_5XX), reproduced=None)
        did_not = classify.classify_group(group(classify.HTTP_5XX), reproduced=False)
        order = {classify.LOW: 0, classify.MEDIUM: 1, classify.HIGH: 2}
        assert order[did_not.confidence] < order[unchecked.confidence], \
            "a group that was checked and did not recur should not rate the same as one " \
            "nobody checked"
        assert any("No reproduce run was performed" in s for s in unchecked.rationale)
        assert any("did not reappear" in s for s in did_not.rationale)

    def test_a_recurrence_raises_confidence_but_not_to_a_verdict(self):
        result = classify.classify_group(group(classify.LATENCY_ANOMALY), reproduced=True)
        assert any("observed again" in s for s in result.rationale)
        assert any("remains an indicator" in s for s in result.rationale)
        assert result.note == classify.NOT_A_VERDICT


class TestTheWholeDocument:
    def test_every_group_is_rated_and_the_order_is_preserved(self):
        groups = [
            aggregate_group(indicator_type=classify.HTTP_5XX, group_id="sha256:" + "1" * 64,
                            case_ids=["s1-000001"]),
            aggregate_group(indicator_type=classify.LATENCY_ANOMALY,
                            group_id="sha256:" + "2" * 64, case_ids=["s1-000002"]),
        ]
        document = aggregate_document(groups=groups)
        rated = classify.classify_document(document)

        assert len(rated) == 2
        assert [g["group_id"] for g in rated] == [g["group_id"] for g in groups], \
            "the document's deterministic order must be preserved, not re-sorted by rating"
        for entry in rated:
            assert entry["classification"]["rationale"]
            assert entry["classification"]["confidence"] in (
                classify.LOW, classify.MEDIUM, classify.HIGH)

    def test_the_original_group_fields_survive(self):
        document = aggregate_document()
        rated = classify.classify_document(document)
        original = document["groups"][0]
        for key in ("group_id", "signature", "occurrences", "case_ids", "representative"):
            assert rated[0][key] == original[key], f"{key} was altered by classification"

    def test_nothing_is_rated_when_there_is_nothing(self):
        assert classify.classify_document(aggregate_document(groups=[])) == []
        assert classify.classify_document({}) == []

    def test_a_malformed_group_is_skipped_not_guessed_at(self):
        document = aggregate_document()
        document["groups"] = ["not an object", {"group_id": "sha256:" + "3" * 64,
                                                "signature": {"indicator_type": "http_5xx"},
                                                "occurrences": 1,
                                                "case_ids": ["s1-000001"]}]
        rated = classify.classify_document(document)
        assert len(rated) == 1
