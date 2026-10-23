"""Short per-control PASS/FAIL table. Reads output/_results.json written by checker.py, so it
includes the builtin content checks too (run checker.py first). Saves compliance_summary.csv.
Exit code 1 if a control was NOT RUN."""
import csv
import json
import os
import sys

path = os.path.join("output", "_results.json")
if not os.path.exists(path):
    sys.exit("output/_results.json not found: run  python checker.py  first.")
res = json.load(open(path, encoding="utf-8"))
cat = json.load(open("controls.json", encoding="utf-8"))

rows = []
for c in cat["controls"]:
    r = res.get(c["id"], {"status": "NOT RUN", "checks": {}})
    flagged = sorted({n for f in r["checks"].values() if f for n in f})
    status = {"COMPLIANT": "PASS", "NON-COMPLIANT": "FAIL"}.get(r["status"], r["status"])
    rows.append((c["id"], c["title"], status, ", ".join(flagged) or "-"))

w = max(len(r[1]) for r in rows)
print(f"{'Control':8}{'Title':{w + 2}}{'Status':9}Non-compliant resources")
print("-" * (w + 50))
for r in rows:
    print(f"{r[0]:8}{r[1]:{w + 2}}{r[2]:9}{r[3]}")
with open("compliance_summary.csv", "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows([("Control", "Title", "Status", "Flagged")] + rows)
print("\nSaved compliance_summary.csv")
sys.exit(1 if any(r[2] == "NOT RUN" for r in rows) else 0)
