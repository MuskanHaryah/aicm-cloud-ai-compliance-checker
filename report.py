"""Reads Cloud Custodian output/ and prints a per-control PASS/FAIL table.
Also saves compliance_report.csv"""
import csv, json, os

CONTROLS = [
    ("MDS-08", "Model Integrity Checks", "mds-08-model-integrity"),
    ("DSP-21", "Data Poisoning Prevention & Detection", "dsp-21-data-poisoning"),
    ("TVM-13", "Guardrails", "tvm-13-guardrails"),
    ("AIS-11", "Agents Security Boundaries", "ais-11-agent-boundaries"),
    ("AIS-13", "AI Sandboxing", "ais-13-sandboxing"),
    ("LOG-16", "Output Monitoring", "log-16-output-monitoring"),
    ("IAM-18", "Agent Access Restriction", "iam-18-agent-access-restriction"),
]

def name_of(r):
    for k in ("Name", "GroupName", "logGroupName", "PolicyName"):
        if k in r:
            return r[k]
    for t in r.get("Tags", []):
        if t["Key"] == "Name":
            return t["Value"]
    return r.get("InstanceId", "unknown")

rows = []
for cid, title, pol in CONTROLS:
    path = os.path.join("output", pol, "resources.json")
    if not os.path.exists(path):
        rows.append((cid, title, "NOT RUN", "-"))
        continue
    flagged = [name_of(r) for r in json.load(open(path))]
    rows.append((cid, title, "FAIL" if flagged else "PASS", ", ".join(flagged) or "-"))

w = max(len(r[1]) for r in rows)
print(f"{'Control':8}{'Title':{w+2}}{'Status':9}Non-compliant resources")
print("-" * (w + 50))
for r in rows:
    print(f"{r[0]:8}{r[1]:{w+2}}{r[2]:9}{r[3]}")

with open("compliance_report.csv", "w", newline="") as f:
    csv.writer(f).writerows([("Control", "Title", "Status", "Flagged")] + rows)
print("\nSaved compliance_report.csv")
