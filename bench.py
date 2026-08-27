"""Three differs on the same seeded scenarios, scored against known drift.

    python bench.py
    python bench.py --trials 200 --json
    python bench.py --ablate

THE BASELINE THAT EVERYONE ACTUALLY SHIPS
-----------------------------------------
    naive       every attribute present in both declared and live, compared
                for exact equality. This is `DeepDiff(state, live)` and it is
                what a drift checker looks like when someone writes one in an
                afternoon.
    ordered     the same, but with provider-computed attributes excluded --
                the single biggest fix -- and nothing else.
    agent       this project: computed attributes excluded, list order
                normalised, undeclared attributes ignored, severity assigned.

Scored against the drifts `state.scenario` actually injected:

    recall      of the real drifts, how many were found
    precision   of the reported drifts, how many were real
    severity    of the correctly-found drifts, how many got the right severity

**Precision is the column that decides whether a drift tool gets used.** A
dashboard with 40 findings of which 4 are real is worse than no dashboard,
because the 4 are now hidden and everyone has learned to ignore the page. The
naive differ does not fail by missing drift -- it finds all of it -- it fails
by finding everything else too.

`--ablate` turns the three rules on one at a time to show which one is carrying
the result, rather than asserting that they all matter.
"""

import argparse
import json
import statistics

import drift as drift_mod
import state as state_mod


def naive_diff(state, live, skip_computed=False, order_insensitive=False):
    """The afternoon version: compare what is in both, report what differs."""
    found = []
    for address, declared in state.resources.items():
        actual = live.describe(address) or {}
        for attribute, want in declared.items():
            if skip_computed and attribute in state_mod.COMPUTED_ATTRIBUTES:
                continue
            got = actual.get(attribute)
            same = (drift_mod._equal(want, got) if order_insensitive
                    else want == got)
            if not same:
                found.append((address, attribute))
        for attribute in actual:
            if attribute in declared:
                continue
            if skip_computed and attribute in state_mod.COMPUTED_ATTRIBUTES:
                continue
            found.append((address, attribute))
    return found


DIFFERS = {
    "naive": lambda s, l: naive_diff(s, l),
    "no-computed": lambda s, l: naive_diff(s, l, skip_computed=True),
    "agent": lambda s, l: [(f.address, f.attribute)
                           for f in drift_mod.diff(s, l).findings],
}


def score(found, truth, severities=None):
    real = {(t["address"], t["attribute"]) for t in truth}
    got = set(found)
    hit = real & got
    result = {
        "recall": len(hit) / len(real) if real else 1.0,
        "precision": len(hit) / len(got) if got else 1.0,
        "reported": len(got),
        "real": len(real),
        "false_positives": len(got - real),
    }
    if severities is not None:
        expected = {(t["address"], t["attribute"]): t["severity"] for t in truth}
        correct = sum(1 for key in hit if severities.get(key) == expected[key])
        result["severity_accuracy"] = correct / len(hit) if hit else 0.0
    return result


def run(trials, drifts, seed0=1):
    rows = {name: [] for name in DIFFERS}
    for i in range(trials):
        st, live, truth = state_mod.scenario(seed=seed0 + i, n_drifts=drifts)
        for name, fn in DIFFERS.items():
            found = fn(st, live)
            severities = None
            if name == "agent":
                severities = {(f.address, f.attribute): f.severity
                              for f in drift_mod.diff(st, live).findings}
            rows[name].append(score(found, truth, severities))
    return rows


def aggregate(scores):
    out = {key: round(statistics.mean([s[key] for s in scores]), 4)
           for key in ("recall", "precision")}
    out["mean_reported"] = round(statistics.mean(
        [s["reported"] for s in scores]), 2)
    out["mean_false_positives"] = round(statistics.mean(
        [s["false_positives"] for s in scores]), 2)
    out["mean_real"] = round(statistics.mean([s["real"] for s in scores]), 2)
    if "severity_accuracy" in scores[0]:
        out["severity_accuracy"] = round(statistics.mean(
            [s["severity_accuracy"] for s in scores]), 4)
    return out


def ablate(trials, drifts, seed0=1):
    """Turn the rules on one at a time. Which one is carrying the result?"""
    variants = {
        "nothing": dict(skip_computed=False, order_insensitive=False),
        "+skip computed": dict(skip_computed=True, order_insensitive=False),
        "+order-insensitive": dict(skip_computed=True, order_insensitive=True),
    }
    out = {}
    for label, kwargs in variants.items():
        scores = []
        for i in range(trials):
            st, live, truth = state_mod.scenario(seed=seed0 + i, n_drifts=drifts)
            scores.append(score(naive_diff(st, live, **kwargs), truth))
        out[label] = aggregate(scores)
    scores = []
    for i in range(trials):
        st, live, truth = state_mod.scenario(seed=seed0 + i, n_drifts=drifts)
        scores.append(score(DIFFERS["agent"](st, live), truth))
    out["+ignore undeclared (agent)"] = aggregate(scores)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--drifts", type=int, default=4)
    ap.add_argument("--ablate", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.ablate:
        report = {"trials": args.trials, "drifts_per_trial": args.drifts,
                  "ablation": ablate(args.trials, args.drifts)}
        if args.json:
            print(json.dumps(report, indent=2))
            return
        print(f"{args.trials} scenarios, {args.drifts} injected drifts each\n")
        print(f"{'rules enabled':<30}{'recall':>9}{'prec':>9}{'reported':>10}"
              f"{'false+':>9}")
        for label, row in report["ablation"].items():
            print(f"{label:<30}{row['recall']:>9.4f}{row['precision']:>9.4f}"
                  f"{row['mean_reported']:>10.2f}{row['mean_false_positives']:>9.2f}")
        return

    rows = run(args.trials, args.drifts)
    report = {"trials": args.trials, "drifts_per_trial": args.drifts,
              "differs": {name: aggregate(scores) for name, scores in rows.items()}}
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"{args.trials} scenarios, {args.drifts} injected drifts each "
          f"(mean {report['differs']['agent']['mean_real']} distinct attributes)\n")
    print(f"{'':<14}{'recall':>9}{'prec':>9}{'severity':>10}{'reported':>10}"
          f"{'false+':>9}")
    for name in DIFFERS:
        row = report["differs"][name]
        severity = row.get("severity_accuracy")
        print(f"{name:<14}{row['recall']:>9.4f}{row['precision']:>9.4f}"
              f"{('-' if severity is None else f'{severity:.4f}'):>10}"
              f"{row['mean_reported']:>10.2f}{row['mean_false_positives']:>9.2f}")


if __name__ == "__main__":
    main()
