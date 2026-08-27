# IaC Drift Detection and Remediation Agent

Compares live cloud infrastructure against a Terraform state file, classifies
every divergence by **blast radius**, proposes a remediation, applies only the
tier that cannot make things worse, and gates everything else behind a named
human approval — with an audit log of what it did and what it refused to do.

**Across 100 seeded scenarios: recall 1.000, precision 1.000, severity accuracy
1.000. The naive diff everybody writes first scores precision 0.325 — 8.3 false
positives per scan.** Full numbers, the ablation showing which rule earns its
place, and the two bugs found on the way in [RESULTS.md](RESULTS.md).

```bash
python cli.py --demo                              # dashboard, dry run
python cli.py --demo --show-suppressed            # and what was filtered, by rule
python cli.py --demo --auto-remediate             # apply the safe tier
python cli.py --demo --approve aws_autoscaling_group.web.min_size=priya
python test_drift.py                              # 26/26
python bench.py --ablate                          # which rule is doing the work
```

Exit code 2 when a critical finding is still outstanding after the loop, so it
drops into CI without a wrapper.

---

## Why a plain diff does not work

This is the whole problem, and it is not the one it looks like.

Live cloud state always carries attributes nobody configured: `arn`, `id`,
`owner_id`, `create_date`, `endpoint`, `status`. The provider assigns them,
Terraform records them in the state file, and **they change under you** — an
`id` recorded against a resource that has since been replaced, a `status` that
depends on what the instance is doing right now.

Diff those naively and every resource in the account is drifted on the first
run. The failure is not that the tool misses drift — it finds **all** of it.
The failure is precision:

| | recall | precision | reported | false positives |
|---|---|---|---|---|
| naive `DeepDiff`-style | 1.0000 | 0.3249 | 12.33 | 8.33 |
| **this project** | **1.0000** | **1.0000** | 4.00 | 0.00 |

A dashboard with 12 findings of which 4 are real is worse than no dashboard,
because the 4 are now hidden and everyone has learned to ignore the page.

---

## The rule the whole thing turns on

> **Every attribute that differs between declared and live is either reported
> as drift, or excluded by a named rule that says which rule and why.**

There is no third option. "The diff was noisy so we filtered it" is exactly how
a drift tool silently drops the one change that mattered.

So `diff()` returns findings **and** `suppressed`; every suppression carries
the rule that made it (`provider-computed`, `not-declared`, `explicit-ignore`);
`--show-suppressed` prints them grouped by rule, and they are in the JSON. A
filter you cannot enumerate is indistinguishable from a bug — and a test walks
every attribute on both sides asserting each one is accounted for exactly once.

---

## Severity is blast radius, not size of change

One boolean flipping `block_public_acls` to `False` is **critical**. An
autoscaling group's desired capacity moving 4 → 9 is **medium**. A tag changing
is **cosmetic**. The ordering is by *what happens if this stays wrong*.

Two checks are structural rather than textual, because the finding a reviewer
needs is not "the ingress list changed":

- **Opened to the world.** Which *ports* became reachable from `0.0.0.0/0`. A
  port that was already open does not get reported as newly open.
- **Policy widened.** An IAM policy that gained a `"*"` it did not have.

---

## The gate, and the outage it prevents

The failure being designed against is not a hallucinating model. It is the
ordinary one: an agent that reverts drift and, because someone legitimately
scaled a production autoscaling group up during an incident, scales it back
down at 03:00. The change is *exactly* what the configuration says. It is still
an outage, and the agent caused it.

So remediation is split by what **reverting** would do:

| tier | when | who decides |
|---|---|---|
| `auto` | reverting restores the stricter declared value and cannot weaken anything — closing an accidentally-open security group, re-enabling encryption | `--auto-remediate` |
| `approve` | reverting changes capacity, sizing or engine version | **a named human, per attribute.** No flag grants this |
| `accept` | the live value is arguably right and the *configuration* should change (tags, descriptions) | reported, never applied |
| `manual` | the resource or attribute is gone; recreating it is a `terraform apply`, not an attribute write | reported, never applied |

Approvals are per-attribute and carry a name —
`--approve aws_db_instance.orders.min_size=priya`. A blanket "yes" is
deliberately not expressible, because the audit log has to say who agreed to
each specific change.

**And verification re-scans.** A remediation counts as applied only when the
finding is gone from a *fresh* diff — not when the write returned success.
Those differ whenever something else is also writing to the resource, which is
the situation that produced the drift in the first place. There is a test that
injects a competing writer and asserts the agent reports `verified: False`.

---

## What is real and what is simulated

Stated plainly, because it is the first question worth asking.

**The state file is real.** `terraform.tfstate` version 4 is a documented JSON
format and `state.py` reads and writes it faithfully — `resources` with `mode`,
`type`, `name`, `provider` and `instances` carrying `attributes`. A state file
from a real `terraform apply` loads. Data sources are skipped, a version-3 file
is refused rather than guessed at, and `--write-fixtures` dumps one so the
format can be inspected. Three tests cover it.

**The live cloud is simulated.** The alternative is an AWS account, a
credential, a bill, and a test suite that cannot run offline or twice. What is
modelled is the *shape* that matters — server-assigned attributes present on
both sides and drifting on one, list attributes returned in arbitrary order,
and a CloudTrail-shaped change log for attribution.

**No `boto3` call is implemented and no remediation has run against real
infrastructure.** RESULTS.md §6 says so before anyone asks.

---

## Files

| file | what is in it |
|---|---|
| `state.py` | tfstate v4 read/write, the live-cloud model, the scenario generator and its drift library |
| `drift.py` | the comparison, the suppression rules, and severity classification |
| `agent.py` | propose → gate → apply → verify, the audit log, and the dashboard |
| `cli.py` | `--json`, `--show-suppressed`, `--approve`, `--write-fixtures`, CI exit codes |
| `bench.py` | three differs on the same scenarios, plus `--ablate` |
| `test_drift.py` | 26 tests, one per real bug, and a check that they fail on the old code |

Standard library only.
