# Results

Every number below has the command that produced it printed above it. All
scenarios are seeded and the generator is deterministic, so they reproduce
exactly.

Environment: Windows 11, Python 3.12.1, standard library only.

---

## 1. Against the diff everybody writes first

```bash
python bench.py --trials 100
```

100 scenarios, 4 injected drifts each, 6 resources per estate.

| | recall | precision | severity acc. | reported | false positives |
|---|---|---|---|---|---|
| `naive` — exact equality on every shared attribute | 1.0000 | 0.3249 | – | 12.33 | 8.33 |
| `no-computed` — plus provider-computed attributes excluded | 1.0000 | 0.9340 | – | 4.33 | 0.33 |
| **`agent`** — this project | **1.0000** | **1.0000** | **1.0000** | 4.00 | 0.00 |

**All three find every real drift.** Recall is 1.000 across the board and it is
the least interesting column here — drift detection is not hard, and a tool
that misses drift is obviously broken. What separates them is precision, and
the naive version reports **three false findings for every real one**.

That is the failure mode that matters. A dashboard at 0.325 precision gets
muted within a week, and a muted dashboard hides the real drift too.

---

## 2. Which rule is actually doing the work

Asserting that three rules all matter is cheap. This turns them on one at a
time:

```bash
python bench.py --trials 100 --ablate
```

| rules enabled | recall | precision | reported | false positives |
|---|---|---|---|---|
| nothing | 1.0000 | 0.3249 | 12.33 | 8.33 |
| + skip provider-computed attributes | 1.0000 | 0.9340 | 4.33 | 0.33 |
| + order-insensitive list comparison | 1.0000 | 1.0000 | 4.00 | 0.00 |
| + ignore undeclared attributes (full agent) | 1.0000 | 1.0000 | 4.00 | 0.00 |

**Two of the three rules earn their place and the third does not, on this
corpus.**

- **Skipping provider-computed attributes is 96% of the fix** (0.325 → 0.934).
  `arn`, `id`, `create_date`, `status` are recorded in the state file *and*
  returned live, and they change under you.
- **Order-insensitive comparison closes the rest** (0.934 → 1.000). A provider
  returns security-group rules in whatever order it likes; comparing them as
  ordered lists reports drift on every scan.
- **Ignoring undeclared attributes adds nothing measurable here**, and that is
  reported rather than hidden. It matters on real estates full of provider
  defaults; this generator does not produce them, so on this corpus the rule is
  unexercised. The honest statement is "no measured benefit in this benchmark",
  not "it works".

### The ablation caught a hole in the generator

The first version of this table showed order-insensitivity contributing
**nothing** — because the generator never shuffled list order, so the rule was
never exercised. That is a benchmark measuring its own assumptions.

`state.scenario(shuffle_lists=True)` now reorders list-valued attributes in the
live copy, which is what a real provider does. It moved the naive baseline's
precision from 0.1250 to 0.1235 and, more importantly, made the second rule's
0.934 → 1.000 contribution real rather than decorative.

---

## 3. The severity bug that buried a finding instead of losing it

```bash
python test_drift.py    # "an inverted-polarity flag is critical when turned ON"
```

Every security attribute in the model followed one pattern: *declared `True`,
live `False` = a protection was turned off*. Three attributes invert it —
`publicly_accessible`, `associate_public_ip_address`, `skip_final_snapshot` —
where **`True` is the dangerous value**.

So `publicly_accessible` flipping `False → True` on a production database was
classified **high** instead of **critical**, in **27 of 100 scenarios**.

It was still detected. It was still on the dashboard. It was sorted below
things that did not matter. **A severity bug does not lose a finding, it buries
one**, which is strictly harder to notice than a missing finding: the count is
right, the resource is listed, and only the ordering is wrong.

Severity accuracy before the fix: **0.9325**. After: **1.0000**.

Every entry in `state.DRIFT_LIBRARY` now carries its expected severity and
`severity is right on every drift in the library` checks all 16.

---

## 4. The gate

```bash
python cli.py --demo --seed 7 --drifts 3 --auto-remediate
```

```
6 resources checked, 3 drifted, 28 attributes suppressed by rule
  critical: 1  high: 0  medium: 1  cosmetic: 1

[critical] aws_s3_bucket.assets.encrypted: true -> false  (encrypted was weakened)
             changed by arn:aws:iam::123456789012:role/deploy-ci via api
             -> applied: reverting restores the stricter declared value

[medium  ] aws_autoscaling_group.web.desired_capacity: 4 -> 9
             changed by arn:aws:iam::123456789012:user/priya via console
             -> approve: reverting changes capacity or sizing; someone may have
                done this deliberately during an incident

[cosmetic] aws_security_group.web.tags: {"owner": "platform"} -> {"owner": "web-team"}
             changed by arn:aws:iam::123456789012:user/dana via console
             -> accept: the live value is probably the intended one and the
                configuration is what should be updated
```

**Three findings, three different answers, one flag.** `--auto-remediate`
restored the encryption and did not touch the other two. The autoscaling group
needs `--approve aws_autoscaling_group.web.desired_capacity=<name>`; there is
no flag that covers it.

Pinned by `capacity and sizing are never auto-remediated`, which sets a desired
capacity and an instance class, runs with `--auto-remediate`, and asserts
**nothing was applied**.

### Exit codes for CI

```bash
python cli.py --demo --seed 7 --drifts 3                 # exit 2
python cli.py --demo --seed 7 --drifts 3 --auto-remediate # exit 0
```

Non-zero when a critical finding is still outstanding *after* the loop has done
what it was allowed to do. The same scenario exits 0 once the fix is applied
and verified.

### Verification re-scans rather than trusting the write

```bash
python test_drift.py    # "verification re-scans instead of trusting the write"
```

The test injects a competing writer that resets `encrypted` to `False`
immediately after the agent writes it. The API call succeeds. The agent reports
**`verified: False`** with the note `re-scan still shows drift; something else
is writing here`.

That situation is not hypothetical — something writing to a resource outside
Terraform is what produced the drift in the first place.

---

## 5. Tests

```bash
python test_drift.py
```

```
26/26 passed

against the pre-fix implementations:
  pre-fix _equal       1/2 of its tests fail
  pre-fix _weakened    2/2 of its tests fail
```

The second block is the point. `verify_suite_is_not_decorative()` re-installs
the pre-fix exact-equality comparison and the pre-fix severity rule and re-runs
the tests written against them.

The invariant test is the one worth reading: it walks **every attribute on both
sides** of every resource and asserts each one is either a finding or a
suppression with a named rule. It is the only test here that would catch a
future filter added quietly to make the dashboard look calmer.

Also covered, because the state format is the half a reviewer can check:

- a written state file round-trips through the real v4 schema
- a version-3 file is **refused**, not guessed at
- `mode: "data"` entries are not treated as managed resources

---

## 6. What has NOT been verified

- **No `boto3` call exists and no remediation has ever run against real
  infrastructure.** `LiveCloud` is a dict. Every "applied" and "verified" in
  this document is against the simulator.
- **No `terraform plan` was ever run.** The comparison is against the state
  file directly, which is deliberate — `terraform plan` needs the provider,
  credentials and network, and it also refreshes state as a side effect. But it
  means this has not been cross-checked against Terraform's own opinion of what
  has drifted, and that is the obvious next validation.
- **The resource model is six resources of five types.** Real estates have
  hundreds of resources and provider schemas with hundreds of attributes each.
  `COMPUTED_ATTRIBUTES` is a hand-written list of 22 names; a real
  implementation reads the provider schema.
- **`ignore undeclared attributes` has no measured benefit** on this corpus
  (§2). It is retained on the argument that real estates are full of provider
  defaults, which this generator does not produce — an argument, not a
  measurement.
- **Root-cause attribution is decoration, not detection.** The change log is
  attached after the diff is complete. It has never been tested against a real
  CloudTrail export, and real trails are frequently delayed, filtered or off —
  which is precisely when someone is changing things by hand. Detection works
  without it by design.
