"""Deletes everything setup_resources.py created (moto or real AWS). Only resources whose names
match the project's naming scheme are touched. On real AWS it needs the same --confirm-account
guard as setup_resources.py. Every step is best effort and prints what it did.

  python teardown_resources.py                                  # moto
  python teardown_resources.py --confirm-account 123456789012   # real AWS sandbox
"""
import argparse
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

R = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
MOTO = bool(os.environ.get("AWS_ENDPOINT_URL"))
ap = argparse.ArgumentParser()
ap.add_argument("--confirm-account")
args = ap.parse_args()
ACCOUNT = boto3.client("sts", region_name=R).get_caller_identity()["Account"]
if not MOTO and args.confirm_account != ACCOUNT:
    sys.exit(f"Real AWS detected (account {ACCOUNT}). Re-run with --confirm-account {ACCOUNT}.")

s3, ec2, iam = (boto3.client(x, region_name=R) for x in ("s3", "ec2", "iam"))
logs, kin, kms, lam = (boto3.client(x, region_name=R) for x in ("logs", "kinesis", "kms", "lambda"))


def step(label, fn):
    try:
        fn()
        print("deleted", label)
    except ClientError as e:
        print("skip   ", label, "-", e.response["Error"]["Code"])


def tag_name(x):
    return next((t["Value"] for t in x.get("Tags", []) if t["Key"] == "Name"), "")


# instances
ids = [i["InstanceId"] for r in ec2.describe_instances(Filters=[
    {"Name": "instance-state-name", "Values": ["pending", "running", "stopped", "stopping"]}])["Reservations"]
    for i in r["Instances"] if tag_name(i).startswith("gemma-inference-")]
if ids:
    step(f"{len(ids)} instances", lambda: ec2.terminate_instances(InstanceIds=ids))
    if not MOTO:
        ec2.get_waiter("instance_terminated").wait(InstanceIds=ids)

# security groups, flow logs, vpcs
for sg in ec2.describe_security_groups()["SecurityGroups"]:
    if sg["GroupName"].startswith("gemma-inference-sg-"):
        step("sg " + sg["GroupName"], lambda sg=sg: ec2.delete_security_group(GroupId=sg["GroupId"]))
for vpc in ec2.describe_vpcs()["Vpcs"]:
    if not tag_name(vpc).startswith("gemma-vpc-"):
        continue
    vid = vpc["VpcId"]
    fl = [f["FlowLogId"] for f in ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vid]}])["FlowLogs"]]
    if fl:
        step("flow logs " + vid, lambda: ec2.delete_flow_logs(FlowLogIds=fl))
    for g in ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vid]}])["InternetGateways"]:
        step("igw", lambda g=g: (ec2.detach_internet_gateway(InternetGatewayId=g["InternetGatewayId"], VpcId=vid),
                                 ec2.delete_internet_gateway(InternetGatewayId=g["InternetGatewayId"])))
    for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vid]}])["Subnets"]:
        step("subnet", lambda sn=sn: ec2.delete_subnet(SubnetId=sn["SubnetId"]))
    step("vpc " + tag_name(vpc), lambda: ec2.delete_vpc(VpcId=vid))

# iam
for prof in iam.list_instance_profiles()["InstanceProfiles"]:
    if prof["InstanceProfileName"].startswith("gemma-inference-profile-"):
        for r in prof["Roles"]:
            iam.remove_role_from_instance_profile(InstanceProfileName=prof["InstanceProfileName"], RoleName=r["RoleName"])
        step("profile " + prof["InstanceProfileName"], lambda p=prof: iam.delete_instance_profile(InstanceProfileName=p["InstanceProfileName"]))
for role in iam.list_roles()["Roles"]:
    rn = role["RoleName"]
    if not rn.startswith(("gemma-inference-role-", "gemma-flowlogs-role", "gemma-cwl-to-kinesis", "gemma-guardrail-lambda-role")):
        continue
    for p in iam.list_attached_role_policies(RoleName=rn)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=rn, PolicyArn=p["PolicyArn"])
    for n in iam.list_role_policies(RoleName=rn)["PolicyNames"]:
        iam.delete_role_policy(RoleName=rn, PolicyName=n)
    step("role " + rn, lambda rn=rn: iam.delete_role(RoleName=rn))
for p in iam.list_policies(Scope="Local")["Policies"]:
    if p["PolicyName"].startswith("gemma-inference-policy-") or p["PolicyName"] == "AdministratorAccess":
        step("policy " + p["PolicyName"], lambda p=p: iam.delete_policy(PolicyArn=p["Arn"]))

# lambda, kinesis, logs, kms
step("lambda gemma-guardrail", lambda: lam.delete_function(FunctionName="gemma-guardrail"))
step("kinesis stream", lambda: kin.delete_stream(StreamName="gemma-output-monitor"))
for page in logs.get_paginator("describe_log_groups").paginate():
    for g in page["logGroups"]:
        if g["logGroupName"].startswith(("/gemma/", "/aws/vpc/gemma-")):
            step("log group " + g["logGroupName"], lambda g=g: logs.delete_log_group(logGroupName=g["logGroupName"]))
for k in kms.list_keys()["Keys"]:
    try:
        md = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        if md.get("Description") == "gemma output logs" and md["KeyState"] == "Enabled":
            step("kms key (scheduled, min 7 days on real AWS)",
                 lambda: kms.schedule_key_deletion(KeyId=k["KeyId"], PendingWindowInDays=7))
    except ClientError:
        pass

# s3 (versioned buckets: delete every version first)
for b in s3.list_buckets()["Buckets"]:
    if not b["Name"].startswith("gemma-"):
        continue
    name = b["Name"]
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):      # never-versioned buckets
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=o["Key"])
    step("bucket " + name, lambda name=name: s3.delete_bucket(Bucket=name))

if os.path.exists("seed_state.json"):
    os.remove("seed_state.json")
print("Teardown finished.")
