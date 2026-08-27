"""Scan for drift, or run the remediation loop.

    python cli.py --demo                          # generated estate, dry run
    python cli.py --demo --show-suppressed        # and what was filtered, by rule
    python cli.py --demo --auto-remediate         # apply the safe-by-construction tier
    python cli.py --demo --approve aws_autoscaling_group.web.min_size=priya
    python cli.py --demo --json --audit audit.json
    python cli.py --state terraform.tfstate --live live.json

    python cli.py --write-fixtures ./fixtures     # dump a scenario to real files

THE MACHINE INTERFACE
---------------------
`--json` emits the whole scan: every finding with severity, reason, declared
and live values and attribution; every proposal with its action and rationale;
everything applied and everything blocked; and the suppressed list with the
rule that dropped each entry. That last part is the one that matters for an
agent consuming this -- it can see what was filtered and disagree.

Real files work: `--state` reads a genuine `terraform.tfstate` (version 4), and
`--write-fixtures` writes one so the format can be inspected.
"""

import argparse
import json
import sys

import agent as agent_mod
import drift as drift_mod
import state as state_mod


def _parse_approvals(pairs):
    """`aws_db_instance.orders.min_size=priya` -> {address.attribute: who}.

    Approval is per attribute and carries a name. A blanket `--approve-all` is
    deliberately not expressible: the audit log has to be able to say who
    agreed to each specific change.
    """
    out = {}
    for pair in pairs or ():
        if "=" not in pair:
            raise SystemExit(f"--approve wants ADDRESS.ATTRIBUTE=who, got {pair!r}")
        key, who = pair.split("=", 1)
        out[key.strip()] = who.strip()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", help="path to a terraform.tfstate (version 4)")
    ap.add_argument("--live", help="path to a live-cloud snapshot JSON")
    ap.add_argument("--demo", action="store_true",
                    help="use a generated estate with known injected drift")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--drifts", type=int, default=4)
    ap.add_argument("--auto-remediate", action="store_true",
                    help="apply the tier where reverting cannot weaken anything")
    ap.add_argument("--approve", action="append", metavar="ADDR.ATTR=who",
                    help="approve one change; repeatable")
    ap.add_argument("--ignore", action="append", metavar="ADDR.ATTR",
                    help="accept one divergence; still listed as suppressed")
    ap.add_argument("--severity", choices=drift_mod.SEVERITIES,
                    help="only show findings at this severity or worse")
    ap.add_argument("--show-suppressed", action="store_true")
    ap.add_argument("--audit", help="write the audit log to this path")
    ap.add_argument("--write-fixtures", metavar="DIR",
                    help="write a scenario out as real tfstate + live JSON")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.write_fixtures:
        import os
        os.makedirs(args.write_fixtures, exist_ok=True)
        st, live, truth = state_mod.scenario(args.seed, args.drifts)
        st.save(os.path.join(args.write_fixtures, "terraform.tfstate"))
        live.save(os.path.join(args.write_fixtures, "live.json"))
        with open(os.path.join(args.write_fixtures, "injected.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(truth, fh, indent=2)
        print(f"wrote terraform.tfstate, live.json and injected.json "
              f"to {args.write_fixtures}", file=sys.stderr)
        return 0

    if args.demo or not (args.state and args.live):
        if not args.demo:
            print("no --state/--live given; using --demo", file=sys.stderr)
        st, live, _ = state_mod.scenario(args.seed, args.drifts)
    else:
        st = state_mod.TerraformState.load(args.state)
        live = state_mod.LiveCloud.load(args.live)

    agent = agent_mod.DriftAgent(
        st, live, auto_remediate=args.auto_remediate,
        approvals=_parse_approvals(args.approve),
        attribute_ignores=tuple(args.ignore or ()))
    scan = agent.scan()

    if args.severity:
        limit = drift_mod.SEVERITY_ORDER[args.severity]
        scan.report.findings = [f for f in scan.report.findings
                                if drift_mod.SEVERITY_ORDER[f.severity] <= limit]

    if args.audit:
        agent.write_audit(args.audit)

    if args.json:
        payload = scan.to_dict()
        payload["summary"] = agent.summary()
        if not args.show_suppressed:
            payload["drift"].pop("suppressed", None)
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(agent_mod.format_report(scan, show_suppressed=args.show_suppressed))
        print()
        print("  ".join(f"{k}: {v}" for k, v in agent.summary().items()
                        if k != "by_severity"))

    # Exit code is the interface for CI: non-zero when something critical is
    # still outstanding after the loop has done what it is allowed to do.
    outstanding = [f for f in scan.report.findings
                   if f.severity == "critical"
                   and not any(a.address == f.address
                               and a.attribute == f.attribute and a.verified
                               for a in scan.applied)]
    return 2 if outstanding else 0


if __name__ == "__main__":
    sys.exit(main())
