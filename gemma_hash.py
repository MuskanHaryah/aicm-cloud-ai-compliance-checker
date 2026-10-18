"""MDS-08 link to the REAL Gemma model: reads the digest of gemma3n:e4b from
the local Ollama server and stores it as tag 'model-sha256' on the fake
model-artifact bucket. Run after setup_resources.py. Ollama must be running."""
import json, urllib.request
import boto3

MODEL = "gemma3n:e4b"
with urllib.request.urlopen("http://localhost:11434/api/tags") as r:
    models = json.load(r)["models"]
digest = next(m["digest"] for m in models if m["name"] == MODEL)
print("Gemma digest:", digest)

s3 = boto3.client("s3", region_name="us-east-1")
s3.put_bucket_tagging(Bucket="gemma-model-good", Tagging={"TagSet": [
    {"Key": "model-sha256", "Value": digest},
    {"Key": "model-name", "Value": MODEL}]})
print("Tagged gemma-model-good with the real model digest.")
