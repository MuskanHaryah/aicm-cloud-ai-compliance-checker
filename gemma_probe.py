"""LOG-16 / TVM-13 demo: sends a prompt to the REAL Gemma (Ollama) and writes
the prompt + output into the fake CloudWatch log group, so output monitoring
has real model output flowing through it. Run after setup_resources.py."""
import json, time, urllib.request
import boto3

MODEL = "gemma3n:e4b"
prompt = "In one sentence, what is cloud compliance?"
req = urllib.request.Request("http://localhost:11434/api/generate",
    data=json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode(),
    headers={"Content-Type": "application/json"})
answer = json.load(urllib.request.urlopen(req))["response"]
print("Gemma said:", answer)

logs = boto3.client("logs", region_name="us-east-1")
group, stream = "/gemma/inference-good", "probe"
try:
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
except Exception:
    pass
logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=[{
    "timestamp": int(time.time() * 1000),
    "message": json.dumps({"model": MODEL, "prompt": prompt, "output": answer})}])
print("Logged to", group)
