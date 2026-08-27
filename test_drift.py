"""One test per real bug, plus the invariant.

    python test_drift.py

No pytest, no network, no cloud credential. Runs in under a second.

`verify_suite_is_not_decorative()` re-installs the pre-fix comparison and
severity rules and asserts the suite catches them.
"""

import copy
import json
import os
import sys
import tempfile

import agent as agent_mod
import bench
import drift as drift_mod
import state as state_mod

_results = []


def check(name):
    def wrap(fn):
        _results.append((name, fn))
        return fn
    return wrap


def scenario(**kw):
    kw.setdefault("seed", 42)
    kw.setdefault("n_drifts", 4)
    return state_mod.scenario(**kw)


def keys(findings):
    return {(f.address, f.attribute) for f in findings}


def truth_keys(truth):
    return {(t["address"], t["attribute"]) for t in truth}


# --------------------------------------------------------------------------
# THE INVARIANT
# --------------------------------------------------------------------------

@check("INVARIANT: every difference is a finding or a named suppression")
def _():
    # Nothing may be dropped quietly. Walk every attribute on both sides and
    # assert it is accounted for exactly once.
    st, live, _ = scenario()
    report = drift_mod.diff(st, live)
    accounted = keys(report.findings) | {(s.address, s.attribute)
                                         for s in report.suppressed}
    for address, declared in st.resources.items():
        actual = live.describe(address) or {}
        for attribute in set(declared) | set(actual):
            same = drift_mod._equal(declared.get(attribute), actual.get(attribute))
            if same and attribute in declared and attribute in actual:
                continue                # identical and declared: nothing to say
            assert (address, attribute) in accounted, \
                f"{address}.{attribute} differs and is neither reported nor suppressed"


@check("every suppression names the rule that made it")
def _():
    st, live, _ = scenario()
    report = drift_mod.diff(st, live)
    assert report.suppressed
    rules = {s.rule for s in report.suppressed}
    assert rules <= {"provider-computed", "not-declared", "explicit-ignore"}, rules
    assert all(s.rule for s in report.suppressed)


@check("an explicit ignore is suppressed, not silently skipped")
def _():
    st, live, truth = scenario()
    target = truth[0]
    key = f"{target['address']}.{target['attribute']}"
    report = drift_mod.diff(st, live, attribute_ignores=(key,))
    assert (target["address"], target["attribute"]) not in keys(report.findings)
    assert any(s.rule == "explicit-ignore"
               and s.address == target["address"]
               and s.attribute == target["attribute"] for s in report.suppressed)


# --------------------------------------------------------------------------
# the two rules that make the diff usable
# --------------------------------------------------------------------------

@check("provider-computed attributes are never drift")
def _():
    # THE bug that makes a naive drift tool useless. Live state always carries
    # arn/id/create_date; the configuration never sets them.
    st, live, truth = scenario()
    report = drift_mod.diff(st, live)
    assert keys(report.findings) == truth_keys(truth), \
        sorted(keys(report.findings) ^ truth_keys(truth))
    assert any(s.rule == "provider-computed" for s in report.suppressed)


@check("reordered rule lists are not drift")
def _():
    # A provider returns security-group rules in arbitrary order. Comparing
    # them as ordered lists reports drift on every scan.
    st, live, _ = scenario(n_drifts=0)
    rules = live.resources["aws_security_group.web"]["ingress"]
    live.resources["aws_security_group.web"]["ingress"] = list(reversed(rules))
    report = drift_mod.diff(st, live)
    assert ("aws_security_group.web", "ingress") not in keys(report.findings), \
        [f.summary() for f in report.findings]


@check("a clean estate produces no findings at all")
def _():
    st, live, _ = scenario(n_drifts=0)
    report = drift_mod.diff(st, live)
    assert report.findings == [], [f.summary() for f in report.findings]
    assert report.resources_checked == len(st.resources)


@check("an attribute the configuration never set is not drift")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_instance.bastion"]["ebs_optimized"] = True
    report = drift_mod.diff(st, live)
    assert ("aws_instance.bastion", "ebs_optimized") not in keys(report.findings)
    assert any(s.attribute == "ebs_optimized" and s.rule == "not-declared"
               for s in report.suppressed)


@check("an attribute that vanished from the live resource IS drift")
def _():
    st, live, _ = scenario(n_drifts=0)
    del live.resources["aws_s3_bucket.assets"]["encrypted"]
    report = drift_mod.diff(st, live)
    finding = next(f for f in report.findings if f.attribute == "encrypted")
    assert finding.kind == "missing_live" and finding.severity == "high"


@check("a resource deleted outside Terraform is critical")
def _():
    st, live, _ = scenario(n_drifts=0)
    del live.resources["aws_db_instance.orders"]
    report = drift_mod.diff(st, live)
    finding = next(f for f in report.findings
                   if f.address == "aws_db_instance.orders")
    assert finding.severity == "critical" and finding.kind == "missing_live"


# --------------------------------------------------------------------------
# severity is about blast radius
# --------------------------------------------------------------------------

@check("port 22 opened to the world is critical, and says which port")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_security_group.web"]["ingress"] = [
        {"from_port": 443, "to_port": 443, "protocol": "tcp",
         "cidr_blocks": ["0.0.0.0/0"]},
        {"from_port": 22, "to_port": 22, "protocol": "tcp",
         "cidr_blocks": ["0.0.0.0/0"]}]
    finding = next(f for f in drift_mod.diff(st, live).findings
                   if f.attribute == "ingress")
    assert finding.severity == "critical", finding.summary()
    assert "22" in finding.reason, finding.reason
    # 443 was ALREADY open to the world; it must not be reported as newly open.
    assert "443" not in finding.reason, finding.reason


@check("an inverted-polarity flag is critical when turned ON")
def _():
    # A real bug: every other security attribute follows "declared True, live
    # False = protection off", so publicly_accessible going False -> True on a
    # production database scored **high**. Still reported, just sorted below
    # things that did not matter -- a severity bug buries a finding rather than
    # losing it.
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_db_instance.orders"]["publicly_accessible"] = True
    finding = next(f for f in drift_mod.diff(st, live).findings
                   if f.attribute == "publicly_accessible")
    assert finding.severity == "critical", finding.summary()


@check("an IAM policy widened to a wildcard is critical")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_iam_role.app"]["policy"] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    finding = next(f for f in drift_mod.diff(st, live).findings
                   if f.attribute == "policy")
    assert finding.severity == "critical", finding.summary()


@check("a tag change is cosmetic, not medium")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_instance.bastion"]["tags"] = {"env": "prod", "x": "y"}
    finding = next(f for f in drift_mod.diff(st, live).findings
                   if f.attribute == "tags")
    assert finding.severity == "cosmetic", finding.summary()


@check("severity is right on every drift in the library")
def _():
    wrong = []
    for entry in state_mod.DRIFT_LIBRARY:
        name, address, attribute, value, expected = entry
        st, live, _ = scenario(n_drifts=0)
        live.resources[address][attribute] = copy.deepcopy(value)
        found = [f for f in drift_mod.diff(st, live).findings
                 if f.address == address and f.attribute == attribute]
        if not found:
            wrong.append((name, "not detected"))
        elif found[0].severity != expected:
            wrong.append((name, f"{found[0].severity} != {expected}"))
    assert not wrong, wrong


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------

@check("INVARIANT: nothing is applied that the plan did not name")
def _():
    st, live, _ = scenario()
    before = copy.deepcopy(live.resources)
    agent = agent_mod.DriftAgent(st, live, auto_remediate=True)
    scan = agent.scan()
    named = {(a.address, a.attribute) for a in scan.applied}
    changed = set()
    for address, attributes in live.resources.items():
        for attribute, value in attributes.items():
            if not drift_mod._equal(before[address].get(attribute), value):
                changed.add((address, attribute))
    assert changed <= named, f"changed without a proposal: {changed - named}"


@check("capacity and sizing are never auto-remediated")
def _():
    # The failure this exists for: someone scaled a production ASG up during an
    # incident, and the agent reverts it at 03:00 because the file says 3.
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_autoscaling_group.web"]["desired_capacity"] = 9
    live.resources["aws_db_instance.orders"]["instance_class"] = "db.r6g.xlarge"
    agent = agent_mod.DriftAgent(st, live, auto_remediate=True)
    scan = agent.scan()
    assert scan.applied == [], [a.to_dict() for a in scan.applied]
    assert all(p.action == agent_mod.APPROVE for p in scan.proposals), \
        [p.to_dict() for p in scan.proposals]
    assert live.resources["aws_autoscaling_group.web"]["desired_capacity"] == 9


@check("an approval is per-attribute and is recorded by name")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_autoscaling_group.web"]["desired_capacity"] = 9
    live.resources["aws_autoscaling_group.web"]["max_size"] = 40
    agent = agent_mod.DriftAgent(
        st, live,
        approvals={"aws_autoscaling_group.web.desired_capacity": "priya"})
    scan = agent.scan()
    assert [(a.address, a.attribute) for a in scan.applied] == \
        [("aws_autoscaling_group.web", "desired_capacity")]
    assert scan.applied[0].approved_by == "priya"
    assert live.resources["aws_autoscaling_group.web"]["max_size"] == 40
    assert any(e["outcome"] == "blocked" and e["attribute"] == "max_size"
               for e in agent.audit)


@check("a protection is restored automatically, and verified by re-scan")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_s3_bucket.assets"]["block_public_acls"] = False
    agent = agent_mod.DriftAgent(st, live, auto_remediate=True)
    scan = agent.scan()
    assert len(scan.applied) == 1 and scan.applied[0].verified
    assert live.resources["aws_s3_bucket.assets"]["block_public_acls"] is True
    assert drift_mod.diff(st, live).findings == []


@check("without --auto-remediate nothing is applied at all")
def _():
    st, live, _ = scenario()
    before = copy.deepcopy(live.resources)
    agent = agent_mod.DriftAgent(st, live, auto_remediate=False)
    scan = agent.scan()
    assert scan.applied == []
    assert live.resources == before
    assert scan.blocked


@check("cosmetic drift is accepted, not reverted")
def _():
    # Reverting a tag someone deliberately fixed destroys their work to satisfy
    # a file. The correct output is "update the configuration".
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_instance.bastion"]["tags"] = {"env": "prod", "x": "y"}
    agent = agent_mod.DriftAgent(st, live, auto_remediate=True)
    scan = agent.scan()
    assert [p.action for p in scan.proposals] == [agent_mod.ACCEPT]
    assert scan.applied == []
    assert live.resources["aws_instance.bastion"]["tags"] == {"env": "prod", "x": "y"}


@check("verification re-scans instead of trusting the write")
def _():
    st, live, _ = scenario(n_drifts=0)
    live.resources["aws_s3_bucket.assets"]["encrypted"] = False

    original_apply = live.apply

    def apply_but_something_else_writes(address, attributes, principal="terraform"):
        original_apply(address, attributes, principal)
        live.resources[address]["encrypted"] = False     # a competing writer
        return True

    live.apply = apply_but_something_else_writes
    agent = agent_mod.DriftAgent(st, live, auto_remediate=True)
    scan = agent.scan()
    assert len(scan.applied) == 1
    assert scan.applied[0].verified is False, "reported success on a failed fix"
    assert "still shows drift" in scan.applied[0].note


@check("the audit log records blocked actions, not only applied ones")
def _():
    st, live, _ = scenario()
    agent = agent_mod.DriftAgent(st, live, auto_remediate=False)
    agent.scan()
    outcomes = {e["outcome"] for e in agent.audit}
    assert "blocked" in outcomes
    assert all(e.get("rationale") for e in agent.audit)


# --------------------------------------------------------------------------
# the state file is real
# --------------------------------------------------------------------------

@check("a written state file round-trips through the v4 format")
def _():
    st, _, _ = scenario()
    handle, path = tempfile.mkstemp(suffix=".tfstate")
    os.close(handle)
    try:
        st.save(path)
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        assert raw["version"] == 4
        assert raw["resources"][0]["mode"] == "managed"
        assert "instances" in raw["resources"][0]
        reloaded = state_mod.TerraformState.load(path)
    finally:
        os.unlink(path)
    assert reloaded.resources == st.resources


@check("a state file of the wrong version is refused, not guessed at")
def _():
    handle, path = tempfile.mkstemp(suffix=".tfstate")
    os.close(handle)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 3, "modules": []}, fh)
        try:
            state_mod.TerraformState.load(path)
        except ValueError as exc:
            assert "version 3" in str(exc)
        else:
            raise AssertionError("loaded a version-3 state without complaining")
    finally:
        os.unlink(path)


@check("data sources are not treated as managed resources")
def _():
    handle, path = tempfile.mkstemp(suffix=".tfstate")
    os.close(handle)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 4, "serial": 1, "lineage": "x", "resources": [
                {"mode": "data", "type": "aws_ami", "name": "ubuntu",
                 "instances": [{"attributes": {"id": "ami-1"}}]},
                {"mode": "managed", "type": "aws_instance", "name": "web",
                 "instances": [{"attributes": {"instance_type": "t3.small"}}]}]}, fh)
        loaded = state_mod.TerraformState.load(path)
    finally:
        os.unlink(path)
    assert set(loaded.resources) == {"aws_instance.web"}


# --------------------------------------------------------------------------
# the naive baseline really is that bad
# --------------------------------------------------------------------------

@check("the naive differ drowns in false positives")
def _():
    # If it did not, this project would not need to exist.
    st, live, truth = scenario()
    naive = set(bench.naive_diff(st, live))
    real = truth_keys(truth)
    assert real <= naive, "the naive differ missed real drift; that is not the claim"
    # The claim is about PRECISION, not volume: most of what it reports is
    # noise, so the real findings are buried rather than missing.
    precision = len(real) / len(naive)
    assert precision < 0.5, \
        f"naive precision {precision:.3f} on {len(naive)} findings -- if the " \
        f"cheap version were this good, this project would not need to exist"


# --------------------------------------------------------------------------
# Phase 5: prove the suite fails on the code it was written against
# --------------------------------------------------------------------------

def _old_equal(a, b):
    """Exact comparison. Reported reordered rule lists as drift."""
    return a == b


def _old_weakened(attribute, declared, live):
    """No inverted-polarity set. publicly_accessible True scored 'high'."""
    if declared is True and live is False:
        return True
    if attribute in ("policy", "assume_role_policy"):
        return drift_mod._has_wildcard(live) and not drift_mod._has_wildcard(declared)
    if attribute == "acl":
        return str(live).startswith("public")
    return False


REGRESSIONS = {
    "_equal": (_old_equal, ("reordered rule lists are not drift",
                            "provider-computed attributes are never drift")),
    "_weakened": (_old_weakened,
                  ("an inverted-polarity flag is critical when turned ON",
                   "severity is right on every drift in the library")),
}


def verify_suite_is_not_decorative():
    by_name = dict(_results)
    lines, total = [], 0
    for name, (old, targets) in REGRESSIONS.items():
        original = getattr(drift_mod, name)
        setattr(drift_mod, name, old)
        try:
            caught = 0
            for target in targets:
                try:
                    by_name[target]()
                except AssertionError:
                    caught += 1
        finally:
            setattr(drift_mod, name, original)
        total += caught
        lines.append(f"  pre-fix {name:<12} {caught}/{len(targets)} of its tests fail")
    return lines, total


def main():
    failed = 0
    for name, fn in _results:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}\n      {exc}")
    print(f"\n{len(_results) - failed}/{len(_results)} passed")

    print("\nagainst the pre-fix implementations:")
    lines, caught = verify_suite_is_not_decorative()
    print("\n".join(lines))
    if caught < len(REGRESSIONS):
        print("the suite does not detect every bug it was written for")
        failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
