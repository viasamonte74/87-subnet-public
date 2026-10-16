"""Rabi IC miner — public contract only, stricter than stock ``approval_witness``.

Beyond ``witness_ic`` (LIMITATIONS item 13 gaps):

* require the reviewed condition to have been governed before the review
* require reviewer/approver actor separation
* require inbound handoff topology when an action sits in a receiving episode
* keep minimal witness citations (not cite-all)

Still abstains on incomplete/ambiguous capsules and on broken approval chains.
"""

from __future__ import annotations

from typing import Any

from sn87_provenonce.institutional_v02 import contracts as ic
from sn87_provenonce.miners import register

CLASS_ID = "IC-APPROVAL-APPLICABILITY"
METHOD_ID = "rabi_approval_witness"
ABSTAIN = "INSUFFICIENT_EVIDENCE_ABSTAIN"


def _differential(c: dict[str, Any], state: str, witness: set[str]) -> dict[str, Any]:
    findings = [
        {
            "code": "STALE_APPROVAL",
            "severity": ic.DEFECT_SEVERITY["STALE_APPROVAL"],
            "evidence_refs": sorted(witness),
            "confidence": "1",
            "rationale": (
                "The review behind the action's approval certified a condition "
                "that was no longer the governing one when the action ran."
            ),
        }
        if state == "FINDINGS"
        else None
    ]
    return {
        "schema_version": c["schema_version"],
        "qid": c["qid"],
        "capsule_commitment": c["evidence_commitment"],
        "method": METHOD_ID,
        "state": state,
        "rationale": f"Rabi approval-chain witness: {state}.",
        "findings": [f for f in findings if f],
    }


def _handoff_ok(action: dict[str, Any], of: dict[str, list], token: str) -> bool:
    """If any handoff targets this episode, one must carry the token to this actor."""
    inbound = [h for h in of["HANDOFF"] if h["to_episode"] == action["episode"]]
    if not inbound:
        return True
    matched = [
        h
        for h in inbound
        if h["carried_token"] == token and h["to_actor"] == action["actor_id"]
    ]
    if len(matched) != 1:
        return False
    handoff = matched[0]
    prior = [
        a
        for a in of["ACTION"]
        if a["episode"] == handoff["from_episode"] and a["actor_id"] == handoff["from_actor"]
    ]
    return bool(prior)


def rabi_approval_witness(c: dict[str, Any]) -> dict[str, Any]:
    ic.validate_capsule(c)
    policy = c["policy"]
    if not all(policy["completeness"].values()) or policy["mapping_uncertainty"] != "NONE":
        return _differential(c, ABSTAIN, set())
    by_id = {e["event_id"]: e for e in c["events"]}
    of = {k: [e for e in c["events"] if e["kind"] == k] for k in ic.FIELDS}
    witness: set[str] = set()
    if not of["ACTION"]:
        return _differential(c, ABSTAIN, set())
    for action in of["ACTION"]:
        links = [x for x in of["APPROVAL_LINK"] if x["local_token"] == action["approval_token"]]
        approval = by_id.get(links[0]["approval_ref"]) if len(links) == 1 else None
        if not approval or approval["kind"] != "APPROVAL":
            return _differential(c, ABSTAIN, set())
        review = by_id.get(approval["review_ref"])
        if not review or review["kind"] != "REVIEW":
            return _differential(c, ABSTAIN, set())
        link = links[0]
        chain_ok = (
            review["approved"]
            and review["at"] < approval["at"] <= link["at"] < action["at"] < approval["valid_until"]
            and review["scope"] == approval["scope"] == action["scope"]
            and review["artifact_commitment"]
            == approval["artifact_commitment"]
            == action["artifact_commitment"]
            and review["actor_id"] != approval["actor_id"]
            and _handoff_ok(action, of, action["approval_token"])
        )
        governing = [
            v
            for v in of["POLICY_VERSION"]
            if v["effective_at"] <= action["at"] and v["at"] < action["at"]
        ]
        newest = max((v["effective_at"] for v in governing), default=None)
        current = [v for v in governing if v["effective_at"] == newest]
        if not chain_ok or not current or len({v["condition_commitment"] for v in current}) != 1:
            return _differential(c, ABSTAIN, set())
        if review["condition_commitment"] != current[0]["condition_commitment"]:
            reviewed = [
                v["event_id"]
                for v in of["POLICY_VERSION"]
                if v["condition_commitment"] == review["condition_commitment"]
                and v["at"] < review["at"]
            ]
            # Reference gap vs stock candidate: condition must have been governed before review.
            if not reviewed:
                return _differential(c, ABSTAIN, set())
            witness |= {
                action["event_id"],
                link["event_id"],
                approval["event_id"],
                review["event_id"],
                current[0]["event_id"],
                *reviewed,
                "$completeness",
            }
            for h in of["HANDOFF"]:
                if (
                    h["carried_token"] == action["approval_token"]
                    and h["to_episode"] == action["episode"]
                ):
                    witness |= {
                        h["event_id"],
                        *(
                            a["event_id"]
                            for a in of["ACTION"]
                            if a["episode"] == h["from_episode"]
                        ),
                    }
    return _differential(c, "FINDINGS" if witness else "NO_MATERIAL_DEVIATION", witness)


register(CLASS_ID, METHOD_ID, rabi_approval_witness)
