"""Checks that Cloud Custodian cannot express (they need to read object CONTENT, log events,
policy documents or to cross-reference two resources). Each function receives the names of the
in-scope resources and returns {resource_name: detail} for every NON-COMPLIANT one.
They use plain boto3, so they run unchanged against moto and against real AWS."""
import fnmatch
import hashlib
import json
import os
import re

import boto3
from botocore.exceptions import ClientError

R = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
CHUNK = 8 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_OUTPUT_FIELDS = ("output", "model", "request_id", "user_id")   # content + metadata (LOG-15)


def _s3():
    return boto3.client("s3", region_name=R)


def _objects(s3, bucket, prefix=""):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            yield o["Key"]


def _sha256_object(s3, bucket, key):
    """Streams the object, so a 7 GB checkpoint never has to fit into memory."""
    h = hashlib.sha256()
    body = s3.get_object(Bucket=bucket, Key=key)["Body"]
    for chunk in iter(lambda: body.read(CHUNK), b""):
        h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- MDS-08
def checkpoint_rehash(buckets):
    """Re-calculate the SHA-256 of the stored checkpoint and compare it with the baseline tag."""
    s3, bad = _s3(), {}
    for b in buckets:
        try:
            tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=b)["TagSet"]}
        except ClientError:
            continue                                   # no tags: the baseline-format check flags it
        baseline = tags.get("model-sha256", "")
        if not HEX64.match(baseline):
            continue                                   # no usable baseline: flagged by the format check
        keys = list(_objects(s3, b, "models/"))
        if not keys:
            bad[b] = "no checkpoint object under models/ to verify"
            continue
        for k in keys:
            actual = _sha256_object(s3, b, k)
            if actual != baseline:
                bad[b] = f"{k}: recalculated {actual[:12]}... != baseline {baseline[:12]}..."
                break
    return bad


# ---------------------------------------------------------------- DSP-21
def dataset_manifest(buckets):
    """Re-hash every training object and compare with manifest.json (approved baseline)."""
    s3, bad = _s3(), {}
    for b in buckets:
        try:
            manifest = json.loads(s3.get_object(Bucket=b, Key="manifest.json")["Body"].read())
            expected = manifest["files"]
        except Exception:
            bad[b] = "manifest.json missing or unreadable: no integrity baseline for the dataset"
            continue
        actual_keys = {k for k in _objects(s3, b) if k != "manifest.json"}
        problems = [f"{k}: unlisted object" for k in sorted(actual_keys - set(expected))]
        problems += [f"{k}: listed but missing" for k in sorted(set(expected) - actual_keys)]
        for k in sorted(actual_keys & set(expected)):
            if _sha256_object(s3, b, k) != expected[k]:
                problems.append(f"{k}: content changed since the manifest was approved")
        if problems:
            bad[b] = "; ".join(problems)
    return bad


# ---------------------------------------------------------------- TVM-11
def guardrail_exists(instance_names):
    """The guardrail named in the instance tag guardrail-id must exist (Lambda stand-in or
    Amazon Bedrock guardrail)."""
    ec2 = boto3.client("ec2", region_name=R)
    lam = boto3.client("lambda", region_name=R)
    bad = {}
    for r in ec2.describe_instances()["Reservations"]:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            n, gid = tags.get("Name"), tags.get("guardrail-id")
            if n not in instance_names or not gid:
                continue                               # no tag: flagged by the 'declared' check
            if _lambda_exists(lam, gid) or _bedrock_guardrail_exists(gid):
                continue
            bad[n] = f"guardrail-id '{gid}' does not exist as a Lambda function or a Bedrock guardrail"
    return bad


def _lambda_exists(lam, name):
    try:
        lam.get_function(FunctionName=name)
        return True
    except ClientError:
        return False


def _bedrock_guardrail_exists(gid):
    try:
        boto3.client("bedrock", region_name=R).get_guardrail(guardrailIdentifier=gid)
        return True
    except Exception:                                  # includes "not implemented" in moto
        return False


# ---------------------------------------------------------------- LOG-15
def output_event_fields(groups, sample=50):
    """The newest events must be JSON with the output content and the metadata fields."""
    logs, bad = boto3.client("logs", region_name=R), {}
    for g in groups:
        events = logs.filter_log_events(logGroupName=g, limit=sample).get("events", [])
        if not events:
            bad[g] = "no output events logged at all"
            continue
        missing = set()
        for e in events:
            try:
                body = json.loads(e["message"])
            except ValueError:
                missing.add("(not JSON)")
                continue
            missing |= {f for f in REQUIRED_OUTPUT_FIELDS if not body.get(f)}
        if missing:
            bad[g] = "events lack required field(s): " + ", ".join(sorted(missing))
    return bad


# ---------------------------------------------------------------- IAM-19
def _role_statements(iam, role):
    """All Allow statements of attached managed policies and inline policies of a role."""
    out = []
    for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
        ver = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
        out += [(p["PolicyName"], s) for s in _stmts(doc)]
    for name in iam.list_role_policies(RoleName=role)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
        out += [(name + " (inline)", s) for s in _stmts(doc)]
    return out


def _stmts(doc):
    s = doc.get("Statement", [])
    s = [s] if isinstance(s, dict) else s
    return [x for x in s if x.get("Effect") == "Allow"]


def _as_list(v):
    return [] if v is None else ([v] if isinstance(v, str) else list(v))


def wildcard_action(roles):
    """Allow statements granting '*' or 'service:*' (or NotAction) are not least privilege."""
    iam, bad = boto3.client("iam", region_name=R), {}
    for r in roles:
        hits = [f"{pol}: {a}" for pol, s in _role_statements(iam, r)
                for a in (_as_list(s.get("Action")) + (["NotAction"] if "NotAction" in s else []))
                if a == "*" or a.endswith(":*") or a == "NotAction"]
        if hits:
            bad[r] = "wildcard action in " + "; ".join(sorted(set(hits)))
    return bad


def wildcard_resource(roles):
    """Allow statements on Resource '*' (or NotResource) break resource segregation."""
    iam, bad = boto3.client("iam", region_name=R), {}
    for r in roles:
        hits = [pol for pol, s in _role_statements(iam, r)
                if "*" in _as_list(s.get("Resource")) or "NotResource" in s]
        if hits:
            bad[r] = "Resource '*' in " + "; ".join(sorted(set(hits)))
    return bad


BUILTINS = {
    "checkpoint-rehash": checkpoint_rehash,
    "dataset-manifest": dataset_manifest,
    "guardrail-exists": guardrail_exists,
    "output-event-fields": output_event_fields,
    "wildcard-action": wildcard_action,
    "wildcard-resource": wildcard_resource,
}
