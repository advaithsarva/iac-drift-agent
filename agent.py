"""Scan -> classify -> propose -> gate -> apply -> verify, with an audit trail.

THE GATE
--------
**Nothing is applied that the plan did not name, and anything that could cause
an outage or destroy data requires explicit human approval that no flag
grants.**

The failure this prevents is not a hallucinating model. It is the ordinary one:
an agent that "reverts drift" and, because someone had legitimately scaled a
production autoscaling group up during an incident, reverts it back down at
03:00. The change is *exactly* what the configuration says. It is still an
outage, and the agent caused it.

So remediation is split by what reverting would do:

    auto        reverting restores a protection. Safe by construction: the
                declared value is the stricter one. Closing an accidentally
                open security group is never the wrong call.
    approve     reverting removes capacity, changes an instance class, or
                touches anything with a blast radius. A human decides.
    accept      the live value is arguably right and the CONFIGURATION is
                what should change. The agent cannot edit .tf files, so it
                says so and stops.

`--auto-remediate` covers the first tier only. There is deliberately no flag
for the second.

VERIFY
------
After applying, the resource is re-read and re-diffed. A remediation is
"applied" only when the finding is gone on a fresh scan -- not when the API
call returned success. Those differ whenever something else is also writing to
the resource, which is the situation that produced the drift in the first
place.
"""

import json
import time
from dataclasses import asdict, dataclass, field

import drift as drift_mod
from state import COMPUTED_ATTRIBUTES

AUTO = "auto"
APPROVE = "approve"
ACCEPT = "accept"
MANUAL = "manual"

# Reverting these restores a protection: the declared value is the safe one by
# construction, so putting it back cannot make things worse.
RESTORES_PROTECTION = {
    "block_public_acls", "block_public_policy", "ignore_public_acls",
    "restrict_public_buckets", "encrypted", "versioning",
    "deletion_protection", "publicly_accessible", "acl",
    "ingress", "egress", "policy", "assume_role_policy",
    "source_dest_check", "monitoring", "backup_retention_period",
}

# Reverting these can take production down even though the declared value is
# "correct". Capacity and instance sizing are changed by hand for good reasons.
BLAST_RADIUS = {
    "min_size", "max_size", "desired_capacity", "instance_class",
    "instance_type", "allocated_storage", "engine_version", "multi_az",
    "health_check_type", "health_check_grace_period",
}


@dataclass
class Proposal:
    address: str
    attribute: str
    action: str              # auto | approve | accept | manual
    rationale: str
    declared: object = None
    live: object = None
    severity: str = "medium"

    def to_dict(self):
        return asdict(self)


@dataclass
class Applied:
    address: str
    attribute: str
    approved_by: str
    verified: bool
    note: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Scan:
    at: float
    report: object
    proposals: list = field(default_factory=list)
    applied: list = field(default_factory=list)
    blocked: list = field(default_factory=list)

    def to_dict(self):
        return {"at": self.at, "drift": self.report.to_dict(),
                "proposals": [p.to_dict() for p in self.proposals],
                "applied": [a.to_dict() for a in self.applied],
                "blocked": [p.to_dict() for p in self.blocked]}


class DriftAgent:
    """Watches declared state against live state and closes the loop."""

    def __init__(self, state, live, auto_remediate=False, approvals=None,
                 attribute_ignores=(), clock=time.time):
        self.state = state
        self.live = live
        self.auto_remediate = auto_remediate
        # Approvals are explicit and per-attribute: {"aws_db_instance.orders.min_size":
        # "priya"}. A blanket "yes" is not expressible, on purpose.
        self.approvals = dict(approvals or {})
        self.attribute_ignores = tuple(attribute_ignores)
        self.clock = clock
        self.scans = []
        self.audit = []

    # -- the loop --------------------------------------------------------

    def scan(self):
        report = drift_mod.diff(self.state, self.live, self.attribute_ignores)
        current = Scan(at=self.clock(), report=report)
        current.proposals = [self.propose(f) for f in report.findings]

        for proposal in current.proposals:
            decision, who = self._gate(proposal)
            if not decision:
                current.blocked.append(proposal)
                self._record("blocked", proposal, who)
                continue
            applied = self._apply(proposal, who)
            current.applied.append(applied)
            self._record("applied", proposal, who, verified=applied.verified)

        self.scans.append(current)
        return current

    # -- proposal --------------------------------------------------------

    def propose(self, finding):
        """What to do about one finding, and why."""
        attribute = finding.attribute

        if finding.kind == "missing_live":
            return Proposal(
                finding.address, attribute, MANUAL,
                "the resource or attribute no longer exists in the cloud; "
                "recreating it is a terraform apply, not an attribute write",
                finding.declared, finding.live, finding.severity)

        if attribute in drift_mod.COSMETIC_ATTRIBUTES:
            # Cosmetic drift is usually somebody labelling something correctly.
            # Reverting it destroys their work to satisfy a file.
            return Proposal(
                finding.address, attribute, ACCEPT,
                "cosmetic; the live value is probably the intended one and the "
                "configuration is what should be updated",
                finding.declared, finding.live, finding.severity)

        if attribute in BLAST_RADIUS:
            return Proposal(
                finding.address, attribute, APPROVE,
                "reverting changes capacity or sizing; someone may have done "
                "this deliberately during an incident",
                finding.declared, finding.live, finding.severity)

        if attribute in RESTORES_PROTECTION:
            return Proposal(
                finding.address, attribute, AUTO,
                "reverting restores the stricter declared value; it cannot "
                "weaken anything",
                finding.declared, finding.live, finding.severity)

        return Proposal(
            finding.address, attribute, APPROVE,
            "no rule covers this attribute, so it is not auto-remediated",
            finding.declared, finding.live, finding.severity)

    # -- gate ------------------------------------------------------------

    def _gate(self, proposal):
        """The single decision point. Returns (allowed, approver)."""
        key = f"{proposal.address}.{proposal.attribute}"
        approver = self.approvals.get(key)

        if proposal.action == ACCEPT:
            return False, None          # nothing to apply; the .tf file changes
        if proposal.action == MANUAL:
            return False, None
        if proposal.action == APPROVE:
            return (True, approver) if approver else (False, None)
        if proposal.action == AUTO:
            if approver:
                return True, approver
            return (True, "auto-remediate") if self.auto_remediate else (False, None)
        return False, None

    # -- apply and verify ------------------------------------------------

    def _apply(self, proposal, approved_by):
        self.live.apply(proposal.address, {proposal.attribute: proposal.declared},
                        principal=f"iac-drift-agent ({approved_by})")
        # Re-diff from scratch rather than trusting the write. If something
        # else is also writing to this resource -- which is how the drift got
        # there -- the value can already be wrong again.
        fresh = drift_mod.diff(self.state, self.live, self.attribute_ignores)
        still = any(f.address == proposal.address and f.attribute == proposal.attribute
                    for f in fresh.findings)
        return Applied(proposal.address, proposal.attribute, approved_by,
                       verified=not still,
                       note="" if not still else
                       "re-scan still shows drift; something else is writing here")

    # -- audit -----------------------------------------------------------

    def _record(self, outcome, proposal, approver, verified=None):
        self.audit.append({
            "at": self.clock(), "outcome": outcome,
            "address": proposal.address, "attribute": proposal.attribute,
            "action": proposal.action, "severity": proposal.severity,
            "rationale": proposal.rationale,
            "approved_by": approver,
            **({"verified": verified} if verified is not None else {})})

    def summary(self):
        report = self.scans[-1].report if self.scans else None
        return {
            "scans": len(self.scans),
            "resources_checked": report.resources_checked if report else 0,
            "findings": len(report.findings) if report else 0,
            "by_severity": report.counts() if report else {},
            "suppressed": len(report.suppressed) if report else 0,
            "applied": sum(len(s.applied) for s in self.scans),
            "verified": sum(1 for s in self.scans for a in s.applied if a.verified),
            "blocked": sum(len(s.blocked) for s in self.scans),
        }

    def write_audit(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.audit, fh, indent=2, default=str)
        return path


def format_report(scan, show_suppressed=False):
    """The dashboard, as text. Severity first, then address."""
    report = scan.report
    lines = [f"{report.resources_checked} resources checked, "
             f"{len(report.findings)} drifted, "
             f"{len(report.suppressed)} attributes suppressed by rule"]
    counts = report.counts()
    lines.append("  " + "  ".join(f"{s}: {counts[s]}" for s in drift_mod.SEVERITIES))
    lines.append("")

    by_key = {(p.address, p.attribute): p for p in scan.proposals}
    applied = {(a.address, a.attribute): a for a in scan.applied}
    for finding in report.findings:
        lines.append(finding.summary())
        if finding.principal:
            lines.append(f"             changed by {finding.principal} "
                         f"via {finding.source}")
        proposal = by_key.get((finding.address, finding.attribute))
        if proposal:
            done = applied.get((finding.address, finding.attribute))
            mark = ("applied" if done and done.verified else
                    "APPLIED-UNVERIFIED" if done else proposal.action)
            lines.append(f"             -> {mark}: {proposal.rationale}")
    if show_suppressed:
        lines.append("")
        lines.append("suppressed:")
        by_rule = {}
        for item in report.suppressed:
            by_rule.setdefault(item.rule, []).append(
                f"{item.address}.{item.attribute}")
        for rule, items in sorted(by_rule.items()):
            lines.append(f"  {rule} ({len(items)})")
            for item in items[:6]:
                lines.append(f"    {item}")
            if len(items) > 6:
                lines.append(f"    ... and {len(items) - 6} more")
    return "\n".join(lines)
