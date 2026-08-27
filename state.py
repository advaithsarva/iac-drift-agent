"""Terraform state, a live cloud snapshot, and a generator that can drift them.

WHY THE CLOUD IS SIMULATED AND THE STATE FILE IS NOT
----------------------------------------------------
Two different things are being modelled and they deserve different treatment.

**The state file is real.** `terraform.tfstate` is a documented JSON format
(version 4) and this module reads and writes it faithfully -- `resources` with
`mode`, `type`, `name`, `provider`, and `instances` carrying `attributes`. A
real state file from a real `terraform apply` loads here. That half is not a
simulation, and it is the half a reviewer can check.

**The live cloud is simulated**, because the alternative is an AWS account, a
credential, a bill, and a test suite that cannot run offline or twice. What
matters is that the *shape* of live data is right, and the shape that matters
is this:

    a live resource always carries attributes the configuration never set

`arn`, `id`, `owner_id`, `create_date`, `vpc_id`, `last_modified` -- the server
assigns them, Terraform records them, and **they are not drift**. Any tool that
diffs live against declared without knowing that reports every resource in the
account as drifted on its first run, which is exactly why the naive baseline in
`bench.py` scores the precision it does.

So `LiveCloud` is a dict of resources with those fields populated, plus a
`change_log` in the shape of a CloudTrail event: who changed what, when, and
through which principal. `drift.py` uses it for root-cause attribution and
nothing else -- the detection works without it, because in practice the audit
trail is often missing or delayed.
"""

import copy
import json
import random
import time

# Attributes the provider computes. Present in live state, absent or unknown in
# the configuration, and NEVER drift. This list is the single most important
# piece of domain knowledge in the project.
COMPUTED_ATTRIBUTES = {
    "arn", "id", "unique_id", "owner_id", "create_date", "created_at",
    "last_modified", "hosted_zone_id", "dns_name", "endpoint",
    "primary_network_interface_id", "private_dns", "public_dns",
    "instance_state", "state", "status", "version_id", "etag",
    "self_link", "fingerprint", "generation", "resource_id",
}

# Attributes whose change cannot break anything but is still worth reporting.
COSMETIC_ATTRIBUTES = {"tags", "description", "comment", "display_name", "labels"}

# Attributes where a change is a security event, not a configuration nit.
SECURITY_ATTRIBUTES = {
    "ingress", "egress", "policy", "assume_role_policy", "acl",
    "block_public_acls", "block_public_policy", "ignore_public_acls",
    "restrict_public_buckets", "public_access_block", "encrypted",
    "kms_key_id", "server_side_encryption_configuration", "versioning",
    "publicly_accessible", "iam_instance_profile", "source_dest_check",
    "cidr_blocks", "from_port", "to_port", "protocol",
}

PRINCIPALS = ("arn:aws:iam::123456789012:user/dana",
              "arn:aws:iam::123456789012:user/priya",
              "arn:aws:iam::123456789012:role/deploy-ci",
              "arn:aws:iam::123456789012:role/oncall-break-glass")


def _address(resource_type, name):
    return f"{resource_type}.{name}"


class TerraformState:
    """A `terraform.tfstate` file, read and written in the real v4 format."""

    def __init__(self, resources=None, serial=1, lineage="00000000-0000-0000-0000-000000000001"):
        self.resources = resources or {}     # address -> attributes dict
        self.serial = serial
        self.lineage = lineage

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        if raw.get("version") != 4:
            raise ValueError(
                f"state version {raw.get('version')!r}; this reads version 4. "
                f"Run `terraform state pull` against a current Terraform.")
        resources = {}
        for entry in raw.get("resources", []):
            if entry.get("mode") == "data":
                continue        # data sources are reads, not managed resources
            for instance in entry.get("instances", []):
                address = _address(entry["type"], entry["name"])
                resources[address] = instance.get("attributes", {})
        return cls(resources, raw.get("serial", 1),
                   raw.get("lineage", "unknown"))

    def to_dict(self):
        by_type = {}
        for address, attributes in self.resources.items():
            resource_type, name = address.split(".", 1)
            by_type.setdefault((resource_type, name), []).append(attributes)
        return {
            "version": 4,
            "terraform_version": "1.7.5",
            "serial": self.serial,
            "lineage": self.lineage,
            "outputs": {},
            "resources": [
                {"mode": "managed", "type": t, "name": n,
                 "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                 "instances": [{"schema_version": 0, "attributes": a}
                               for a in instances]}
                for (t, n), instances in sorted(by_type.items())],
        }

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
        return path

    def __len__(self):
        return len(self.resources)


class LiveCloud:
    """What the provider says is actually there, plus who changed it."""

    def __init__(self, resources=None, change_log=None):
        self.resources = resources or {}
        self.change_log = change_log or []

    def describe(self, address):
        return self.resources.get(address)

    def apply(self, address, attributes, principal="terraform"):
        """Write declared values back onto the live resource.

        The only mutating operation, so it is the only thing an audit needs to
        watch. `agent.py` routes every remediation through here after the
        policy gate, and records the resulting change-log entry in the incident.
        """
        if address not in self.resources:
            raise LookupError(f"no live resource {address!r}")
        before = copy.deepcopy(self.resources[address])
        for key, value in attributes.items():
            if key in COMPUTED_ATTRIBUTES:
                continue        # never write back a server-assigned field
            self.resources[address][key] = copy.deepcopy(value)
        self.change_log.append({
            "at": time.time(), "address": address, "principal": principal,
            "source": "iac-drift-agent", "before": before,
            "after": copy.deepcopy(self.resources[address])})
        return True

    def to_dict(self):
        return {"resources": self.resources, "change_log": self.change_log}

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls(raw.get("resources", {}), raw.get("change_log", []))

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True, default=str)
        return path


# --------------------------------------------------------------------------
# a small, realistic estate
# --------------------------------------------------------------------------

def baseline_estate(rng):
    """Resources whose declared and live state agree, before any drift.

    Deliberately includes the things that actually go wrong in practice: a
    security group with rules, an S3 bucket with a public-access block, an IAM
    role policy, an RDS instance, an autoscaling group.
    """
    return {
        "aws_security_group.web": {
            "name": "web-sg", "vpc_id": "vpc-0a1b2c3d",
            "description": "web tier",
            "ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp",
                         "cidr_blocks": ["0.0.0.0/0"]},
                        {"from_port": 22, "to_port": 22, "protocol": "tcp",
                         "cidr_blocks": ["10.0.0.0/8"]}],
            "egress": [{"from_port": 0, "to_port": 0, "protocol": "-1",
                        "cidr_blocks": ["0.0.0.0/0"]}],
            "tags": {"env": "prod", "owner": "platform"},
        },
        "aws_s3_bucket.assets": {
            "bucket": "acme-prod-assets", "acl": "private",
            "versioning": True, "encrypted": True,
            "kms_key_id": "arn:aws:kms:eu-west-1:123456789012:key/abc",
            "block_public_acls": True, "block_public_policy": True,
            "tags": {"env": "prod", "owner": "platform"},
        },
        "aws_iam_role.app": {
            "name": "app-runtime",
            "assume_role_policy": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"Service": "ec2.amazonaws.com"}}]},
            "policy": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"],
                 "Resource": "arn:aws:s3:::acme-prod-assets/*"}]},
            "max_session_duration": 3600,
            "tags": {"env": "prod"},
        },
        "aws_db_instance.orders": {
            "identifier": "orders-prod", "instance_class": "db.r6g.large",
            "allocated_storage": 200, "engine": "postgres",
            "engine_version": "15.4", "multi_az": True,
            "publicly_accessible": False, "encrypted": True,
            "backup_retention_period": 14, "deletion_protection": True,
            "tags": {"env": "prod", "owner": "data"},
        },
        "aws_autoscaling_group.web": {
            "name": "web-asg", "min_size": 3, "max_size": 12,
            "desired_capacity": 4, "health_check_type": "ELB",
            "health_check_grace_period": 120,
            "tags": {"env": "prod"},
        },
        "aws_instance.bastion": {
            "instance_type": "t3.micro", "ami": "ami-0abcdef1234567890",
            "monitoring": True, "source_dest_check": True,
            "associate_public_ip_address": True,
            "tags": {"env": "prod", "owner": "platform"},
        },
    }


def _computed_for(address, rng):
    """Server-assigned fields. Present live, absent from the configuration."""
    resource_type = address.split(".", 1)[0]
    common = {
        "id": f"{resource_type.split('_')[-1]}-{rng.randrange(16**12):012x}",
        "arn": f"arn:aws:{resource_type.split('_')[1]}:eu-west-1:123456789012:"
               f"{address.split('.')[-1]}",
        "owner_id": "123456789012",
        "create_date": "2024-11-04T09:12:41Z",
    }
    if resource_type == "aws_db_instance":
        common["endpoint"] = "orders-prod.abc123.eu-west-1.rds.amazonaws.com:5432"
        common["status"] = "available"
    if resource_type == "aws_instance":
        common["private_dns"] = "ip-10-0-3-17.eu-west-1.compute.internal"
        common["instance_state"] = "running"
    return common


# Each entry: (name, address, attribute, new value, expected severity).
# The expected severity is the ground truth `bench.py` scores against.
DRIFT_LIBRARY = [
    ("ssh_open_to_world", "aws_security_group.web", "ingress",
     [{"from_port": 443, "to_port": 443, "protocol": "tcp",
       "cidr_blocks": ["0.0.0.0/0"]},
      {"from_port": 22, "to_port": 22, "protocol": "tcp",
       "cidr_blocks": ["0.0.0.0/0"]}], "critical"),
    ("bucket_public_acls_unblocked", "aws_s3_bucket.assets",
     "block_public_acls", False, "critical"),
    ("bucket_encryption_off", "aws_s3_bucket.assets", "encrypted", False,
     "critical"),
    ("db_made_public", "aws_db_instance.orders", "publicly_accessible", True,
     "critical"),
    ("deletion_protection_off", "aws_db_instance.orders",
     "deletion_protection", False, "high"),
    ("role_policy_widened", "aws_iam_role.app", "policy",
     {"Version": "2012-10-17", "Statement": [
         {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}, "critical"),
    ("backup_retention_cut", "aws_db_instance.orders",
     "backup_retention_period", 1, "high"),
    ("asg_scaled_down", "aws_autoscaling_group.web", "min_size", 1, "high"),
    ("asg_desired_bumped", "aws_autoscaling_group.web", "desired_capacity", 9,
     "medium"),
    ("instance_resized", "aws_instance.bastion", "instance_type", "t3.large",
     "medium"),
    ("db_resized", "aws_db_instance.orders", "instance_class", "db.r6g.xlarge",
     "medium"),
    ("monitoring_disabled", "aws_instance.bastion", "monitoring", False,
     "medium"),
    ("health_check_downgraded", "aws_autoscaling_group.web",
     "health_check_type", "EC2", "medium"),
    ("owner_tag_changed", "aws_security_group.web", "tags",
     {"env": "prod", "owner": "web-team"}, "cosmetic"),
    ("description_edited", "aws_security_group.web", "description",
     "web tier (updated by hand)", "cosmetic"),
    ("tag_added", "aws_instance.bastion", "tags",
     {"env": "prod", "owner": "platform", "cost-centre": "eng"}, "cosmetic"),
]


def scenario(seed=42, n_drifts=3, include_computed=True, include_noise=True,
             shuffle_lists=True):
    """A (state, live, truth) triple with a known set of injected drifts.

    `include_computed` puts the server-assigned attributes into the live
    resources and leaves them out of the configuration -- which is the normal
    state of affairs and the thing that makes a naive diff useless. Turning it
    off is only for showing, in bench.py, exactly how much of the naive
    baseline's error it accounts for.

    `include_noise` additionally jitters a computed field, so live and declared
    differ even for resources nothing has touched.

    `shuffle_lists` reorders list-valued attributes in the live copy, which is
    what a real provider does and what makes ordered comparison wrong.
    """
    rng = random.Random(seed)
    declared = baseline_estate(rng)
    live = copy.deepcopy(declared)

    # A provider returns list-valued attributes -- security group rules above
    # all -- in whatever order it feels like, and that order is not stable
    # between calls. Shuffling them here makes the live state differ from the
    # declared state in a way that is NOT drift, which is the second-commonest
    # false positive after computed attributes and the thing
    # `drift._equal`'s order-insensitivity exists for. Without this the
    # generator quietly never exercises that rule.
    if shuffle_lists:
        for address, attributes in live.items():
            for key, value in attributes.items():
                if isinstance(value, list) and len(value) > 1:
                    rng.shuffle(value)

    if include_computed:
        # Terraform RECORDS server-assigned attributes in the state file -- they
        # are what the API returned at apply time. So they belong on both
        # sides, and modelling them as live-only would have made
        # `drift.py`'s provider-computed rule untestable while the "attribute
        # was never declared" rule quietly did all the work.
        for address in live:
            computed = _computed_for(address, rng)
            live[address].update(computed)
            declared[address].update(copy.deepcopy(computed))
        if include_noise:
            # ...and they change under you. An `id` that was recorded months
            # ago against a resource that has since been replaced, a `status`
            # that depends on what the instance is doing right now. This is the
            # single largest source of false drift and the reason the naive
            # baseline in bench.py scores the precision it does.
            for address in live:
                for key in ("id", "status", "instance_state", "last_modified"):
                    if key in live[address]:
                        live[address][key] = f"{key}-{rng.randrange(16**8):08x}"

    chosen = rng.sample(DRIFT_LIBRARY, min(n_drifts, len(DRIFT_LIBRARY)))
    change_log, truth = [], []
    now = time.time()
    for index, (name, address, attribute, value, severity) in enumerate(chosen):
        live[address][attribute] = copy.deepcopy(value)
        principal = rng.choice(PRINCIPALS)
        change_log.append({
            "at": now - (index + 1) * 3600,
            "address": address, "principal": principal,
            "source": "console" if "user/" in principal else "api",
            "attribute": attribute,
            "event": "ModifyResourceAttribute"})
        truth.append({"name": name, "address": address, "attribute": attribute,
                      "severity": severity})

    return (TerraformState(declared), LiveCloud(live, change_log),
            sorted(truth, key=lambda d: (d["address"], d["attribute"])))
