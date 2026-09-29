"""Judge a live report against the findings the run actually stored.

The report is produced by Python from an aggregate produced by Go, and the two
meet over a socket. So the checks here are the ones a fixture cannot make: they
compare the report against the case ids that genuinely crossed the wire in this
run, rather than against numbers the report itself declares.

Conservation is the heart of it. Grouping forty near-identical indicators into one
row is only honest if the row still accounts for all forty, so the union of the
groups' case ids must be exactly the set of stored findings -- not a superset, not
a subset, and not merely the same count.

Output is one verdict per line, tab-separated, to be READ by the caller and never
executed. Values that came off an HTTP response are stripped of control characters
so a crafted one cannot forge a verdict line.

    exit 0  every check passed
    exit 1  at least one failed
    exit 2  at least one could not be judged
"""

from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNVERIFIED = 2


def flat(value: object) -> str:
    text = str(value)
    for char in ("\t", "\n", "\r", "\x00"):
        text = text.replace(char, " ")
    return text.strip()


def load(path: str, label: str, out: list[tuple[str, str]]):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            body = handle.read()
    except OSError as exc:
        out.append(("UNVERIFIED", f"{label} could not be read: {flat(exc)}"))
        return None
    if not body.strip():
        out.append(("UNVERIFIED", f"{label} is empty"))
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, json.JSONDecodeError) as exc:
        out.append(("UNVERIFIED", f"{label} is not valid JSON: {flat(exc)}"))
        return None
    if not isinstance(parsed, dict):
        out.append(("UNVERIFIED", f"{label} is not an object"))
        return None
    return parsed


def judge(report: dict, findings: dict, out: list[tuple[str, str]]) -> None:
    groups = report.get("groups")
    if not isinstance(groups, list):
        out.append(("UNVERIFIED", "the report carries no group list"))
        return

    stored_list = findings.get("findings")
    if not isinstance(stored_list, list):
        out.append(("UNVERIFIED", "the findings response carries no list"))
        return
    stored_ids = {f.get("case_id") for f in stored_list if isinstance(f, dict)}
    if not stored_ids:
        out.append(("UNVERIFIED", "no stored findings to compare the report against"))
        return

    covered: set = set()
    summed = 0
    for group in groups:
        if not isinstance(group, dict):
            out.append(("UNVERIFIED", "a group is not an object"))
            return
        ids = group.get("case_ids")
        if not isinstance(ids, list):
            out.append(("UNVERIFIED", "a group carries no case id list"))
            return
        covered.update(ids)
        occurrences = group.get("occurrences")
        if not isinstance(occurrences, int):
            out.append(("UNVERIFIED", "a group carries no occurrence count"))
            return
        summed += occurrences

    # --- conservation, against what the run really stored ---
    conservation = report.get("conservation") or {}
    if conservation.get("consistent") is True:
        out.append(("PASS", "the report's own conservation check holds"))
    else:
        out.append(("FAIL", "the report reports its totals as inconsistent: "
                            f"{flat(conservation.get('reason'))}"))

    if covered == stored_ids:
        out.append(("PASS", "every stored case id appears in a group, and no others "
                            f"({len(covered)})"))
    else:
        missing = sorted(x for x in stored_ids - covered if x)[:5]
        extra = sorted(x for x in covered - stored_ids if x)[:5]
        out.append(("FAIL", f"groups cover {len(covered)} case id(s), storage holds "
                            f"{len(stored_ids)}; missing {missing}; extra {extra}"))

    declared = conservation.get("declared_indicator_instances")
    if isinstance(declared, int) and summed == declared:
        out.append(("PASS", f"group occurrences sum to the declared indicator "
                            f"instances ({summed})"))
    else:
        out.append(("FAIL", f"occurrences sum to {summed}, the aggregate declares "
                            f"{flat(declared)}"))

    # --- the scope ---
    scope = report.get("scope")
    if not isinstance(scope, dict):
        out.append(("UNVERIFIED", "the report carries no scope block"))
    else:
        if scope.get("recorded") and scope.get("consistent") and scope.get("trustworthy"):
            out.append(("PASS", "the scope crossed the wire and is coherent"))
        else:
            out.append(("FAIL", "the scope is not presented as coherent: "
                                f"{flat(scope.get('reason'))}"))

        summary = scope.get("targets_summary") or []
        if any("testbed:8000" in str(entry) for entry in summary):
            out.append(("PASS", "the report names the target the run was authorised for"))
        else:
            out.append(("FAIL", f"the target authority is missing: {flat(summary)}"))

        leaked = [t for t in (scope.get("targets") or [])
                  if isinstance(t, dict) and "allowed_addresses" in t]
        if leaked or "/32" in json.dumps(report):
            out.append(("FAIL", "an authorised address reached the shareable report"))
        else:
            out.append(("PASS", "no authorised address is in the shareable report"))

    # --- ratings explain themselves ---
    rated = [g for g in groups
             if isinstance(g.get("classification"), dict)
             and g["classification"].get("rationale")]
    if groups and len(rated) == len(groups):
        out.append(("PASS", f"every group carries a rating with its reasoning "
                            f"({len(groups)})"))
    else:
        out.append(("FAIL", f"{len(rated)} of {len(groups)} groups explain their rating"))

    # --- completeness ---
    completeness = report.get("completeness") or {}
    if completeness.get("complete") is True:
        out.append(("PASS", "the report reports the result set as complete"))
    else:
        out.append(("FAIL", "the report reports the result set as incomplete: "
                            f"{flat(completeness.get('reasons'))}"))


def main() -> int:
    out: list[tuple[str, str]] = []
    if len(sys.argv) != 3:
        print("UNVERIFIED\tusage: check_report_conservation.py <report.json> <findings.json>")
        return EXIT_UNVERIFIED

    report = load(sys.argv[1], "the report", out)
    findings = load(sys.argv[2], "the findings response", out)
    if report is not None and findings is not None:
        judge(report, findings, out)

    for verdict, message in out:
        print(f"{verdict}\t{message}")

    verdicts = {v for v, _ in out}
    if "UNVERIFIED" in verdicts:
        return EXIT_UNVERIFIED
    if "FAIL" in verdicts:
        return EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
