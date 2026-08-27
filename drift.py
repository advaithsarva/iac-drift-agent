"""Structural diff between declared and live state, classified by blast radius.

THE INVARIANT
-------------
**Every attribute that differs between declared and live is either reported as
drift, or excluded by a named rule that says which rule and why.**

There is no third option, and that is the whole point. "The diff was noisy so
we filtered it" is how a drift tool ends up silently dropping the one change
that mattered. `diff()` returns findings *and* `suppressed`, every suppression
carries the rule that made it, and `--show-suppressed` prints them. A filter
you cannot enumerate is indistinguishable from a bug.

WHY A PLAIN DIFF DOES NOT WORK
------------------------------
Live cloud state always contains attributes the configuration never set: `arn`,
`id`, `owner_id`, `create_date`, `endpoint`, `status`. The provider assigns
them. They are in the state file because Terraform recorded them, and they are
in the live description because they exist.

Diff those naively and **every resource in the account is drifted on the first
run**. That is not a small nuisance -- it is the reason drift dashboards get
muted, and once muted the real drift is invisible too. `bench.py` measures
exactly how bad it is.

So the comparison is asymmetric and rule-driven:

    computed attribute        never drift, whatever it says
    absent from declared      not drift; the configuration expressed no opinion
    absent from live          drift, and a serious one: the resource lost it
    both present, differ      drift, classified by what the attribute controls

SEVERITY IS ABOUT BLAST RADIUS, NOT ABOUT SIZE OF CHANGE
--------------------------------------------------------
One boolean flipping `block_public_acls` to False is a critical finding. An
autoscaling group's desired capacity moving from 4 to 9 is medium. A tag
changing is cosmetic. The ordering is by *what happens if this stays wrong*,
not by how many bytes moved, and `SECURITY_ATTRIBUTES` is where that judgement
lives so it can be argued with in one place.
"""

import json
from dataclasses import dataclass, field

from state import (COMPUTED_ATTRIBUTES, COSMETIC_ATTRIBUTES,
                   SECURITY_ATTRIBUTES)

SEVERITIES = ("critical", "high", "medium", "cosmetic")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Attributes that are not security controls but whose loss causes an outage or
# an unrecoverable deletion. Separated from SECURITY_ATTRIBUTES because the
# remediation urgency is the same and the *reason* is not.
AVAILABILITY_ATTRIBUTES = {
    "deletion_protection", "backup_retention_period", "multi_az",
    "min_size", "skip_final_snapshot", "final_snapshot_identifier",
}

# Attributes whose SAFE value is False. Everything else in the security set
# follows the pattern "declared True, live False = a protection was turned
# off"; these inverted ones broke it silently. `publicly_accessible` going
# False -> True on a production database was classified **high** rather than
# **critical** in 27 of 100 scenarios -- still reported, still in the
# dashboard, just sorted below things that did not matter. A severity bug does
# not lose the finding, it buries it.
DANGEROUS_WHEN_TRUE = {
    "publicly_accessible", "associate_public_ip_address",
    "skip_final_snapshot", "force_destroy",
}

# A cidr block that means "the whole internet". Checked explicitly because the
# difference between 10.0.0.0/8 and 0.0.0.0/0 on port 22 is the difference
# between a config nit and an incident.
WORLD = {"0.0.0.0/0", "::/0"}


@dataclass
class Finding:
    address: str
    attribute: str
    declared: object
    live: object
    severity: str
    reason: str
    kind: str = "changed"        # changed | missing_live | unmanaged
    principal: str = None
    changed_at: float = None
    source: str = None

    def to_dict(self):
        return {"address": self.address, "attribute": self.attribute,
                "kind": self.kind, "severity": self.severity,
                "reason": self.reason, "declared": self.declared,
                "live": self.live,
                **({"principal": self.principal} if self.principal else {}),
                **({"source": self.source} if self.source else {}),
                **({"changed_at": self.changed_at} if self.changed_at else {})}

    def summary(self):
        return (f"[{self.severity:<8}] {self.address}.{self.attribute}: "
                f"{_short(self.declared)} -> {_short(self.live)}  ({self.reason})")


@dataclass
class Suppressed:
    address: str
    attribute: str
    rule: str

    def to_dict(self):
        return {"address": self.address, "attribute": self.attribute,
                "rule": self.rule}


@dataclass
class DriftReport:
    findings: list = field(default_factory=list)
    suppressed: list = field(default_factory=list)
    resources_checked: int = 0

    def by_severity(self, severity):
        return [f for f in self.findings if f.severity == severity]

    def counts(self):
        return {s: len(self.by_severity(s)) for s in SEVERITIES}

    def to_dict(self):
        return {"resources_checked": self.resources_checked,
                "counts": self.counts(),
                "findings": [f.to_dict() for f in self.findings],
                "suppressed": [s.to_dict() for s in self.suppressed]}


def diff(state, live, attribute_ignores=()):
    """Compare a TerraformState against a LiveCloud. Returns a DriftReport.

    `attribute_ignores` is an explicit allowlist of `address.attribute` strings
    a human decided to accept. They still appear in `suppressed`, tagged with
    the rule that dropped them, because an accepted exception that nobody can
    list is an exception nobody reviews.
    """
    report = DriftReport()
    ignores = set(attribute_ignores)

    for address, declared in sorted(state.resources.items()):
        actual = live.describe(address)
        report.resources_checked += 1

        if actual is None:
            # The resource is in state and not in the cloud. Someone deleted it
            # outside Terraform, and the next apply will try to recreate it.
            report.findings.append(Finding(
                address, "*", declared, None, "critical",
                "resource exists in state but not in the cloud",
                kind="missing_live"))
            continue

        for attribute in sorted(declared):
            key = f"{address}.{attribute}"
            if attribute in COMPUTED_ATTRIBUTES:
                report.suppressed.append(
                    Suppressed(address, attribute, "provider-computed"))
                continue
            if key in ignores:
                report.suppressed.append(
                    Suppressed(address, attribute, "explicit-ignore"))
                continue

            want, got = declared[attribute], actual.get(attribute, _MISSING)
            if got is _MISSING:
                report.findings.append(Finding(
                    address, attribute, want, None, "high",
                    "declared attribute is absent from the live resource",
                    kind="missing_live"))
                continue
            if _equal(want, got):
                continue

            severity, reason = classify(attribute, want, got)
            report.findings.append(
                Finding(address, attribute, want, got, severity, reason))

        # Attributes present live and never declared are NOT drift. The
        # configuration expressed no opinion, and a tool that reports them
        # produces a finding for every provider default in the account.
        for attribute in sorted(actual):
            if attribute not in declared:
                report.suppressed.append(
                    Suppressed(address, attribute, "not-declared"))

    attribute_change_log(report, live)
    report.findings.sort(
        key=lambda f: (SEVERITY_ORDER[f.severity], f.address, f.attribute))
    return report


def classify(attribute, declared, live):
    """Severity and a one-line reason. Blast radius, not size of change."""
    if attribute in SECURITY_ATTRIBUTES:
        opened = _opened_to_world(attribute, declared, live)
        if opened:
            return "critical", opened
        if _weakened(attribute, declared, live):
            return "critical", (f"{attribute} was turned ON, which removes a "
                                f"protection" if attribute in DANGEROUS_WHEN_TRUE
                                else f"{attribute} was weakened")
        return "high", f"{attribute} is a security control and it changed"

    if attribute in AVAILABILITY_ATTRIBUTES:
        if _reduced(declared, live):
            return "high", f"{attribute} was reduced ({declared} -> {live})"
        return "medium", f"{attribute} changed"

    if attribute in COSMETIC_ATTRIBUTES:
        return "cosmetic", f"{attribute} changed; no effect on behaviour"

    return "medium", f"{attribute} changed outside Terraform"


def _opened_to_world(attribute, declared, live):
    """Did a rule set start accepting traffic from anywhere?

    Checked structurally rather than by string comparison because the finding
    that matters is not "the ingress list changed" -- it is "port 22 is now
    open to 0.0.0.0/0", and a reviewer needs to be told which port.
    """
    if attribute not in ("ingress", "egress", "cidr_blocks"):
        return None
    before = _world_ports(declared)
    after = _world_ports(live)
    new = sorted(after - before)
    if not new:
        return None
    ports = ", ".join(str(p) for p in new)
    return f"port(s) {ports} now reachable from 0.0.0.0/0"


def _world_ports(rules):
    out = set()
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if set(rule.get("cidr_blocks", [])) & WORLD:
                out.add(rule.get("from_port"))
    return out


def _weakened(attribute, declared, live):
    """A protection turned off, or an IAM policy widened to a wildcard."""
    if attribute in DANGEROUS_WHEN_TRUE:
        return live is True and declared is not True
    if declared is True and live is False:
        return True
    if attribute in ("policy", "assume_role_policy"):
        return _has_wildcard(live) and not _has_wildcard(declared)
    if attribute == "acl":
        return str(live).startswith("public")
    return False


def _has_wildcard(policy):
    text = json.dumps(policy, sort_keys=True) if not isinstance(policy, str) else policy
    return '"*"' in text or '"s3:*"' in text or '":*"' in text


def _reduced(declared, live):
    return (isinstance(declared, (int, float)) and isinstance(live, (int, float))
            and not isinstance(declared, bool) and live < declared) or \
           (declared is True and live is False)


def attribute_change_log(report, live):
    """Attach who-changed-what from the audit trail, where it exists.

    Deliberately a *decoration*, applied after detection is complete. Drift
    detection that depends on the audit trail stops working when the trail is
    delayed, filtered, or was never enabled -- which is common, and is exactly
    when someone is changing things by hand.
    """
    index = {}
    for event in live.change_log:
        index.setdefault((event.get("address"), event.get("attribute")), event)
    for finding in report.findings:
        event = index.get((finding.address, finding.attribute))
        if not event:
            continue
        finding.principal = event.get("principal")
        finding.changed_at = event.get("at")
        finding.source = event.get("source")


def _equal(a, b):
    """Order-insensitive for lists of rule dicts; exact otherwise.

    Security group rules come back from the API in whatever order the provider
    feels like. Comparing them as ordered lists reports drift on every scan and
    is the second-most-common false positive after computed attributes.
    """
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return sorted(map(_canonical, a)) == sorted(map(_canonical, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return _canonical(a) == _canonical(b)
    return a == b


def _canonical(value):
    return json.dumps(value, sort_keys=True, default=str)


def _short(value, width=44):
    text = value if isinstance(value, str) else _canonical(value)
    return text if len(text) <= width else text[:width - 3] + "..."


class _Missing:
    def __repr__(self):
        return "<absent>"


_MISSING = _Missing()
