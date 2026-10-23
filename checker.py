"""AICM compliance checker.

Reads controls.json (7 AICM controls, 29 sub-checks), runs the Cloud Custodian policies
(policies/aicm-controls.yml) plus the builtin content checks (builtin_checks.py) and reports
for EVERY in-scope resource whether it is COMPLIANT or NON-COMPLIANT and why.

With --validate the result is compared with the seeded good/bad resources
(setup_resources.py). Validation FAILS (exit code 1) when a policy did not run, Custodian
logged an error, a control has no resources in scope, or a flagged set differs from the
expected one.

Usage:
  python checker.py --validate        # test run on the seeded good/bad resources
  python checker.py                   # normal run on whatever exists in the account
  python checker.py --skip-run        # re-use the existing output/ folder
  python checker.py --ollama-weights  # also re-hash the local Gemma weights (MDS-08, host)
"""
import argparse
import csv
import fnmatch
import json
import os
import shutil
import subprocess
import sys

import boto3

import builtin_checks

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
STATES = ["pending", "running", "stopped"]


def load_state():
    try:
        return json.load(open("seed_state.json", encoding="utf-8"))
    except OSError:
        return {"suffix": ""}


SUFFIX = load_state().get("suffix", "")


def norm(name):
    """Strip the S3 suffix that setup_resources.py appended (needed for global bucket names)."""
    return name[:-(len(SUFFIX) + 1)] if SUFFIX and name.endswith("-" + SUFFIX) else name


def name_of(r):
    for k in ("RoleName", "GroupName", "logGroupName", "FunctionName", "PolicyName", "Name"):
        if k in r:
            return r[k]
    for t in r.get("Tags", []):
        if t["Key"] == "Name":
            return t["Value"]
    return r.get("InstanceId") or r.get("VpcId") or "unknown"


def instances(pattern):
    ec2 = boto3.client("ec2", region_name=REGION)
    res = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": STATES}])
    for r in res["Reservations"]:
        for i in r["Instances"]:
            n = next((x["Value"] for x in i.get("Tags", []) if x["Key"] == "Name"), "")
            if fnmatch.fnmatch(n, pattern):
                yield n, i


def list_scope(rtype, pattern):
    """All resources of this type that the control applies to."""
    if rtype == "s3":
        b = boto3.client("s3", region_name=REGION).list_buckets()["Buckets"]
        return sorted(x["Name"] for x in b if fnmatch.fnmatch(x["Name"], pattern))
    if rtype == "ec2":
        return sorted(n for n, _ in instances(pattern))
    if rtype == "sg":
        g = boto3.client("ec2", region_name=REGION).describe_security_groups()["SecurityGroups"]
        return sorted(x["GroupName"] for x in g if fnmatch.fnmatch(x["GroupName"], pattern))
    if rtype == "vpc":
        v = boto3.client("ec2", region_name=REGION).describe_vpcs()["Vpcs"]
        names = [next((t["Value"] for t in x.get("Tags", []) if t["Key"] == "Name"), "") for x in v]
        return sorted(n for n in names if fnmatch.fnmatch(n, pattern))
    if rtype == "logs":
        lg, out = boto3.client("logs", region_name=REGION), []
        for page in lg.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=pattern):
            out += [x["logGroupName"] for x in page["logGroups"]]
        return sorted(out)
    if rtype == "iam-role":
        iam, out = boto3.client("iam", region_name=REGION), []
        for page in iam.get_paginator("list_roles").paginate():
            out += [x["RoleName"] for x in page["Roles"] if x["RoleName"].startswith(pattern)]
        return sorted(out)
    raise ValueError(rtype)


def sg_chain(flagged):
    """AIS-11 evidence: inference instance -> security groups it really uses."""
    lines = []
    for n, i in sorted(instances("gemma-inference-*"), key=lambda x: x[0]):
        groups = {g["GroupName"] for g in i.get("SecurityGroups", [])}
        for nic in i.get("NetworkInterfaces", []):
            groups |= {g["GroupName"] for g in nic.get("Groups", [])}
        lines += [(n, f"security group {g}", g in flagged) for g in sorted(groups)]
    return lines


def role_chain(flagged):
    """IAM-19 evidence: inference instance -> instance profile -> role."""
    iam, lines = boto3.client("iam", region_name=REGION), []
    for n, i in sorted(instances("gemma-inference-*"), key=lambda x: x[0]):
        prof = i.get("IamInstanceProfile", {}).get("Arn", "").split("/")[-1]
        if not prof:
            lines.append((n, "no instance profile attached", False))
            continue
        for role in iam.get_instance_profile(InstanceProfileName=prof)["InstanceProfile"]["Roles"]:
            lines.append((n, f"role {role['RoleName']}", role["RoleName"] in flagged))
    return lines


def run_custodian():
    shutil.rmtree("output", ignore_errors=True)        # never read stale results
    cmd = [sys.executable, "-m", "c7n.cli", "run", "-s", "output",
           os.path.join("policies", "aicm-controls.yml"), "--cache-period", "0"]
    print("Running Cloud Custodian policies ...")
    r = subprocess.run(cmd, capture_output=True, text=True)
    text = r.stdout + r.stderr
    # Custodian silently DROPS a resource whose filter raised an error (exit code stays 0),
    # which would be a false "compliant". Treat any logged error as a failure.
    errors = [l for l in text.splitlines() if ":ERROR" in l or "Traceback" in l]
    if r.returncode != 0 or errors:
        print(text)
        sys.exit("Custodian failed or logged errors. Is moto running and are the AWS_* variables set?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true", help="compare the result with the seeded test setup")
    ap.add_argument("--skip-run", action="store_true")
    ap.add_argument("--ollama-weights", action="store_true", help="also re-hash the local Ollama weights")
    a = ap.parse_args()

    cat = json.load(open("controls.json", encoding="utf-8"))
    if not a.skip_run:
        run_custodian()

    rows, summary, results = [], [], {}
    bad_controls = bad_checks = total_checks = 0
    print(f"\nAICM compliance check, workload {cat['workload']}  (AICM {cat['aicm_version']})\n")
    for c in cat["controls"]:
        print(f"[{c['id']}] {c['title']}  (coverage: {c['coverage']})")
        print(f"    AICM text: {c['official_spec']}")
        scopes = {t: list_scope(t, p) for t, p in c["scopes"].items()}
        all_scope = sorted(n for v in scopes.values() for n in v)
        reasons, per_check, not_run = {}, [], False

        for chk in c["checks"]:
            total_checks += 1
            rtype = chk.get("on") or next(iter(c["scopes"]))
            label = chk.get("policy") or chk["builtin"]
            if "policy" in chk:
                path = os.path.join("output", chk["policy"], "resources.json")
                if not os.path.exists(path):
                    not_run = True
                    per_check.append((label, None, chk, rtype))
                    continue
                f = {name_of(r): "" for r in json.load(open(path, encoding="utf-8"))}
            else:
                f = builtin_checks.BUILTINS[chk["builtin"]](scopes[rtype])
            for n, detail in f.items():
                reasons.setdefault(n, []).append(chk["violation"] + (f" [{detail}]" if detail else ""))
            per_check.append((label, set(f), chk, rtype))

        flagged = sorted(reasons)
        if not all_scope:
            print("    - NO RESOURCES IN SCOPE (control cannot be assessed)")
        for n in all_scope:
            if n in reasons:
                why = " | ".join(reasons[n])
                print(f"    - {n}: NON-COMPLIANT  -> {why}")
                rows.append((c["id"], c["title"], n, "NON-COMPLIANT", why))
            else:
                print(f"    - {n}: COMPLIANT")
                rows.append((c["id"], c["title"], n, "COMPLIANT", c["official_spec"]))
        for n in flagged:           # flagged but not found by the scope listing
            if n not in all_scope:
                why = " | ".join(reasons[n])
                print(f"    - {n}: NON-COMPLIANT (outside listed scope) -> {why}")
                rows.append((c["id"], c["title"], n, "NON-COMPLIANT", why))

        chain = []
        if c["id"] == "AIS-11":
            chain = sg_chain({n for lbl, f, k, t in per_check if f and k.get("policy") == "ais-11-inference-port-open" for n in f})
        if c["id"] == "IAM-19":
            chain = role_chain({n for lbl, f, k, t in per_check if f for n in f})
        for inst, link, bad_link in chain:
            tag = "NON-COMPLIANT" if bad_link else "OK"
            print(f"    Effective access: {inst} -> {link} [{tag}]")
            rows.append((c["id"], c["title"], f"{inst} ({link})", tag, "effective access chain"))
        print(f"    Limitation: {c['limitation']}")
        print("    Not checked here: " + "; ".join(c["not_checked"]))

        if not_run:
            status = "NOT RUN"
        elif not all_scope:
            status = "NO SCOPE"
        else:
            status = "NON-COMPLIANT" if flagged else "COMPLIANT"

        verdict = "-"
        if a.validate:
            if not_run:
                verdict = "NOT RUN"
            elif not all_scope:
                verdict = "NO SCOPE"
            else:
                ok_control = True
                for label, f, chk, rtype in per_check:
                    exp = sorted(chk["expected_noncompliant"])
                    got_n = sorted(norm(x) for x in f)
                    ok = got_n == exp and set(exp) <= {norm(x) for x in scopes[rtype]}
                    bad_checks += 0 if ok else 1
                    ok_control &= ok
                    print(f"    Check {label}: {'MATCH' if ok else 'MISMATCH'} (expected {exp}, got {got_n})")
                verdict = "MATCH" if ok_control else "MISMATCH"
            if verdict != "MATCH":
                bad_controls += 1
                if verdict in ("NOT RUN", "NO SCOPE"):
                    bad_checks += len(c["checks"])
            print(f"    Seeded-test validation: {verdict}")
        elif not_run or not all_scope:
            bad_controls += 1
        print()
        summary.append((c["id"], c["title"], status, len(all_scope), len(flagged), verdict))
        results[c["id"]] = {"status": status, "checks": {
            lbl: (None if f is None else sorted(f)) for lbl, f, k, t in per_check}}

    print("=" * 88)
    print(f"{'Control':8}{'Title':40}{'Status':15}{'In scope':9}{'Flagged':8}{'Validation' if a.validate else ''}")
    print("-" * 88)
    for s in summary:
        print(f"{s[0]:8}{s[1]:40}{s[2]:15}{s[3]:<9}{s[4]:<8}{s[5] if a.validate else ''}")
    if a.validate:
        n = len(summary)
        print(f"\nDetection check: {n - bad_controls}/{n} controls and "
              f"{total_checks - bad_checks}/{total_checks} sub-checks matched the seeded setup "
              f"(every bad resource flagged for exactly its own fault, no good resource flagged).")
        if bad_controls:
            print("VALIDATION FAILED (NOT RUN, NO SCOPE and MISMATCH all count as failures).")

    if a.ollama_weights:
        import verify_ollama_weights
        st, detail = verify_ollama_weights.verify(cat["workload"])
        print(f"\nLocal host (MDS-08), real Gemma weights: {st}: {detail}")
        if st != "OK":
            bad_controls += 1

    os.makedirs("output", exist_ok=True)
    json.dump(results, open(os.path.join("output", "_results.json"), "w"), indent=1)
    with open("compliance_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Control", "Title", "Resource", "Status", "Reason"])
        w.writerows(rows)
    print("\nSaved compliance_report.csv")
    sys.exit(1 if bad_controls else 0)


if __name__ == "__main__":
    main()
