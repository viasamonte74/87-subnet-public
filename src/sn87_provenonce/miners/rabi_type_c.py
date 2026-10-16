"""Rabi TYPE-C-RELEASE miner — same grammar checks as the public baseline, precise refs.

The matched baseline cites every event for every finding. This method cites:

* ``MISSING_*``: ``$completeness`` plus every event id present
* other defect codes: every event id present (includes duplicates)

That matches published ``required_refs`` on the committed TYPE-C golden set and scores
better under precision-aware evidence credit than cite-all.
"""

from __future__ import annotations

from typing import Any

from sn87_provenonce.miners import register
from sn87_provenonce.pilot import contracts as tc

CLASS_ID = "TYPE-C-RELEASE"
METHOD_ID = "rabi_type_c"
ABSTAIN = "INSUFFICIENT_EVIDENCE_ABSTAIN"
_MISSING = {
    "SUBMIT": "MISSING_SUBMIT_EVENT",
    "REVIEW": "MISSING_REVIEW_GATE",
    "VALIDATE": "MISSING_VALIDATION_GATE",
    "RELEASE": "MISSING_RELEASE_EVENT",
}
_DUPLICATE = {
    "SUBMIT": "DUPLICATE_SUBMIT_EVENT",
    "REVIEW": "DUPLICATE_REVIEW_EVENT",
    "VALIDATE": "DUPLICATE_VALIDATION_EVENT",
    "RELEASE": "DUPLICATE_RELEASE_EVENT",
}


def _refs_for(code: str, events: list[dict[str, Any]]) -> list[str]:
    ids = sorted(e["event_id"] for e in events)
    if code.startswith("MISSING_"):
        return sorted(set(ids) | {"$completeness"})
    return ids


def _differential(c: dict[str, Any], codes: set[str], state: str | None = None) -> dict[str, Any]:
    state = state or ("FINDINGS" if codes else "NO_MATERIAL_DEVIATION")
    return {
        "schema_version": c["schema_version"],
        "qid": c["qid"],
        "capsule_commitment": c["evidence_commitment"],
        "method": METHOD_ID,
        "state": state,
        "rationale": f"Rabi type-c grammar witness: {state}.",
        "findings": [
            {
                "code": code,
                "severity": tc.DEFECT_SEVERITY[code],
                "evidence_refs": _refs_for(code, c["events"]),
                "rationale": "Disclosed release-workflow grammar fails in the bound record.",
                "confidence": "1",
            }
            for code in sorted(codes)
        ],
    }


def rabi_type_c(c: dict[str, Any]) -> dict[str, Any]:
    tc.validate_capsule(c)
    if not c["completeness"]["complete"]:
        return _differential(c, set(), ABSTAIN)
    events, order = c["events"], c["policy"]["required_event_order"]
    kinds = [e["kind"] for e in events]
    codes = {_MISSING[k] for k in order if k not in kinds}
    codes |= {_DUPLICATE[k] for k in order if kinds.count(k) > 1}
    if not codes and [kinds.index(k) for k in order] != sorted(kinds.index(k) for k in order):
        codes.add("INVALID_WORKFLOW_ORDER")
    links = zip(events, events[1:], strict=False)
    if any(a["output_commitment"] != b["input_commitment"] for a, b in links):
        codes.add("EVIDENCE_CHAIN_BREAK")
    if "REVIEW" in kinds and not any(
        e.get("approved") is True for e in events if e["kind"] == "REVIEW"
    ):
        codes.add("REVIEW_NOT_APPROVED")
    release = kinds.index("RELEASE") if "RELEASE" in kinds else None
    if release is not None and release < len(kinds) - 1:
        codes.add("EVENT_AFTER_RELEASE")
    submit = kinds.index("SUBMIT") if "SUBMIT" in kinds else None
    if any(
        k == "OBSERVE" and (submit is None or release is None or not submit < i < release)
        for i, k in enumerate(kinds)
    ):
        codes.add("OBSERVATION_OUTSIDE_WORKFLOW")
    return _differential(c, codes)


register(CLASS_ID, METHOD_ID, rabi_type_c)
