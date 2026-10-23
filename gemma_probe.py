"""LOG-15 demo: sends a prompt to the REAL Gemma (Ollama) and writes the prompt, the output and
the metadata (model, request_id, user_id) into the monitored log group, in the format that
checker.py's 'output-event-fields' check requires. Run after setup_resources.py (moto or AWS).
Ollama must be running (http://localhost:11434)."""
import json
import sys
import time
import urllib.request
import uuid

import boto3

MODEL = "gemma3n:e4b"
prompt = "In one sentence, what is cloud compliance?"
req = urllib.request.Request("http://localhost:11434/api/generate",
    data=json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode(),
    headers={"Content-Type": "application/json"})
try:
    answer = json.load(urllib.request.urlopen(req, timeout=600))["response"]
except Exception as e:
    sys.exit(f"Cannot get an answer from Ollama ({e}). Start Ollama and pull {MODEL}.")
print("Gemma said:", answer)

logs = boto3.client("logs", region_name="us-east-1")
group, stream = "/gemma/inference-good", "probe"
try:
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
except logs.exceptions.ResourceAlreadyExistsException:
    pass
logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=[{
    "timestamp": int(time.time() * 1000),
    "message": json.dumps({"model": MODEL, "request_id": str(uuid.uuid4()), "user_id": "probe-user",
                           "prompt": prompt, "output": answer})}])
print("Logged to", group)
