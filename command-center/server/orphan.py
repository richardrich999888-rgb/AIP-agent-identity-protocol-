"""Orphan and owner status from lineage, grants and revocations (item 2.4; native, not P0-059). Pure.

Inputs:
- `agents`: the registry's agents (each has `parent` and `owner`);
- `grants`: agent_id -> the jti of the grant that agent holds from its parent
  (for a root agent, its root grant). In this lab the grants file is issued by
  the lab, not by AIP delegation tokens; that is a stated limitation;
- `revoked_jtis`: the operator-signed revocation list (already verified);
- `principals`: the humans currently in the directory (owners must be here).

Rule (declared; the first that applies is the status, all that apply are findings):
  INVALID_LINEAGE   — the parent chain has a cycle (the registry does not forbid one);
  UNKNOWN_AUTHORITY — the agent or an ancestor has no grant on record;
  REVOKED           — the agent's own grant is revoked;
  ORPHANED          — an ancestor's grant is revoked, the agent's own is not:
                      it still holds a key, but its lineage has no authority;
  UNKNOWN_OWNER     — the owner is not in the principal directory;
  ACTIVE            — none of the above.
A never-seen agent can still be ORPHANED: status is about authority, not activity.

`authority_chain(agent)` is the jti list root-first, i.e. exactly what the
agent must present to the gate; OPA denies it if any element is revoked, so
an ORPHANED or REVOKED agent is refused at the gate (PREVENTION through the
gate). UNKNOWN_OWNER is ADVISORY: the gate does not read the directory.
"""

from __future__ import annotations

from dataclasses import dataclass

INVALID_LINEAGE = "INVALID_LINEAGE"
UNKNOWN_AUTHORITY = "UNKNOWN_AUTHORITY"
REVOKED = "REVOKED"
ORPHANED = "ORPHANED"
UNKNOWN_OWNER = "UNKNOWN_OWNER"
ACTIVE = "ACTIVE"
PRECEDENCE = (INVALID_LINEAGE, UNKNOWN_AUTHORITY, REVOKED, ORPHANED, UNKNOWN_OWNER)


class LineageError(ValueError):
    """The parent chain is not a finite path to a root."""


@dataclass(frozen=True)
class Status:
    agent_id: str
    status: str
    findings: tuple[str, ...]
    lineage: tuple[str, ...]          # root first, ending with the agent ('' if INVALID_LINEAGE)
    enforcement: str                  # PREVENTION (refused at the gate) | ADVISORY | NONE


def lineage(agents: dict[str, dict], agent_id: str) -> tuple[str, ...]:
    """Root-first ancestor path ending with `agent_id`. LineageError on a cycle or a missing parent."""
    path, seen, cur = [], set(), agent_id
    while cur is not None:
        if cur in seen:
            raise LineageError(f"cycle at {cur!r}")
        if cur not in agents:
            raise LineageError(f"parent {cur!r} is not registered")
        seen.add(cur)
        path.append(cur)
        cur = agents[cur]["parent"]
    return tuple(reversed(path))


def authority_chain(agents: dict[str, dict], grants: dict[str, str], agent_id: str) -> list[str]:
    """The grant jtis root-first that `agent_id` presents to the gate. KeyError if a grant is missing."""
    return [grants[a] for a in lineage(agents, agent_id)]


def classify_one(agents: dict[str, dict], grants: dict[str, str], revoked_jtis: set[str],
                 principals: set[str], agent_id: str) -> Status:
    """Status of one registered agent under the declared rule."""
    findings: list[str] = []
    try:
        path = lineage(agents, agent_id)
    except LineageError as e:
        return Status(agent_id, INVALID_LINEAGE, (f"{INVALID_LINEAGE}: {e}",), (), "NONE")
    missing = [a for a in path if a not in grants]
    if missing:
        findings.append(f"{UNKNOWN_AUTHORITY}: no grant for {', '.join(missing)}")
    if agent_id in grants and grants[agent_id] in revoked_jtis:
        findings.append(f"{REVOKED}: own grant {grants[agent_id]} revoked")
    dead = [a for a in path[:-1] if a in grants and grants[a] in revoked_jtis]
    if dead and not (agent_id in grants and grants[agent_id] in revoked_jtis):
        findings.append(f"{ORPHANED}: ancestor {dead[-1]} revoked")
    if agents[agent_id]["owner"] not in principals:
        findings.append(f"{UNKNOWN_OWNER}: {agents[agent_id]['owner']} not in the principal directory")
    status = next((s for s in PRECEDENCE if any(f.startswith(s + ":") for f in findings)), ACTIVE)
    enforcement = {REVOKED: "PREVENTION", ORPHANED: "PREVENTION", UNKNOWN_OWNER: "ADVISORY"}.get(status, "NONE")
    return Status(agent_id, status, tuple(findings), path, enforcement)


def classify(agents: dict[str, dict], grants: dict[str, str], revoked_jtis, principals) -> dict[str, Status]:
    """Status for every registered agent, by id."""
    rv, pr = set(revoked_jtis), set(principals)
    return {aid: classify_one(agents, grants, rv, pr, aid) for aid in sorted(agents)}
