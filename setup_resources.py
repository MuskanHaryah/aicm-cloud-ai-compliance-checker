"""Creates GOOD and BAD fake AWS resources in moto for all 7 AICM controls.
Run once per moto session (restart moto to reset)."""
import json
import boto3

R = "us-east-1"
s3 = boto3.client("s3", region_name=R)
ec2 = boto3.client("ec2", region_name=R)
iam = boto3.client("iam", region_name=R)
logs = boto3.client("logs", region_name=R)

# ---- MDS-08 : model artifact buckets -------------------------------
for name, good in [("gemma-model-good", True), ("gemma-model-bad", False)]:
    s3.create_bucket(Bucket=name)
    if good:
        s3.put_bucket_versioning(Bucket=name,
            VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
            {"Key": "model-sha256", "Value": "PLACEHOLDER"}]})  # gemma_hash.py fills real value

# ---- DSP-21 : training data buckets --------------------------------
for name, good in [("gemma-data-good", True), ("gemma-data-bad", False)]:
    s3.create_bucket(Bucket=name)
    if good:
        s3.put_bucket_versioning(Bucket=name,
            VersioningConfiguration={"Status": "Enabled"})
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

# ---- AIS-11 : security groups --------------------------------------
vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
for name, cidr in [("gemma-inference-sg-good", "10.0.0.0/16"),
                   ("gemma-inference-sg-bad", "0.0.0.0/0")]:
    sg = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 11434, "ToPort": 11434,
        "IpRanges": [{"CidrIp": cidr}]}])

# ---- TVM-13 (guardrail tag) + AIS-13 (sandboxing) : EC2 ------------
ami = ec2.describe_images()["Images"][0]["ImageId"]
subnet = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
def launch(name, tags, imds, public):
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.large",
        MetadataOptions={"HttpTokens": imds},
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet,
                            "AssociatePublicIpAddress": public}],
        TagSpecifications=[{"ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": name}] + tags}])
launch("gemma-inference-good", [{"Key": "guardrail", "Value": "enabled"}], "required", False)
launch("gemma-inference-bad", [], "optional", True)

# ---- LOG-16 : log groups -------------------------------------------
logs.create_log_group(logGroupName="/gemma/inference-good")
logs.put_retention_policy(logGroupName="/gemma/inference-good", retentionInDays=90)
logs.create_log_group(logGroupName="/gemma/inference-bad")   # no retention

# ---- IAM-18 : policies ---------------------------------------------
bad = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
good = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::gemma-model-good/*"}]}
trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
for name, doc in [("gemma-inference-bad", bad), ("gemma-inference-good", good)]:
    arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    iam.create_role(RoleName=name + "-role", AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=name + "-role", PolicyArn=arn)

print("All fake resources created.")
