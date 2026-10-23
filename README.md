# Automated Compliance Checking of Cloud AI Systems (CSA AICM)

Cloud Custodian policies (plus a few Python content checks) that test the cloud set-up around an
open-source model (Gemma 3n E4B, `gemma3n:e4b`) against 7 controls of the CSA AI Controls Matrix.
The tool creates GOOD and single-fault BAD resources, runs the checks, and proves that every
check flags exactly its own violation. It runs on **moto** (fake AWS) first, then on a real AWS
sandbox account.

Control IDs, titles and specifications were read from the supplied official sheet
*Auditing Guidelines of AICM v1.0 (based on CCM v4.0.1)*; the exact AICM text is stored in
`controls.json` (`official_spec`).

| Control | Title (official) | Checks |
|---|---|---|
| MDS-08 | Model Integrity Checks | baseline SHA-256 tag valid · **checkpoint re-hashed and compared** · re-verified within 365 days |
| DSP-21 | Data Poisoning Prevention & Detection | public access block · no public ACL · access logging · **dataset re-hashed against approved manifest** |
| TVM-11 | Guardrails | guardrail declared · guardrail exists · reviewed within 180 days |
| AIS-11 | Agents Security Boundaries | inference port 11434 not world-open · VPC flow logs |
| AIS-13 | AI Sandboxing | IMDSv2 · hop limit 1 · no public IP · egress restricted |
| LOG-15 | Output Monitoring | subscription filter (monitor) · **events contain output + metadata** |
| IAM-19 | Agent Access Restriction | no wildcard action (incl. AdministratorAccess) · no wildcard resource |

IDs corrected from the earlier version: `TVM-13 → TVM-11`, `LOG-16 → LOG-15`, `IAM-18 → IAM-19`
(in the official sheet TVM-13 is "Threat Response", IAM-18 is "Output Modification and Special
Authorization", and LOG-16 does not exist). Each check in `controls.json` has a `basis` field:
the AICM spec sentence, the audit-guideline item, or "project hardening/parameter". Only checks that test the control text itself were kept (hardening extras such as versioning, KMS, TLS-only and a log-retention number were removed). The numbers
365 / 180 days are **project parameters**: 365 comes from "at least annually", 180 is our own choice.

## What can and cannot be tested

| Control | Moto (local) | Real AWS | Cannot be checked from cloud configuration at all |
|---|---|---|---|
| MDS-08 | all 3 checks | all 3 (a real 7 GB checkpoint can be uploaded and is re-hashed by streaming) | upstream-provider verification process, escalation process. Local Ollama file: `verify_ollama_weights.py` (not cloud) |
| DSP-21 | all 4 checks | all 4 | poisoned records that were already in the data when the manifest was approved; adversarial training; incident response |
| TVM-11 | 3 checks on a Lambda stand-in guardrail | same, or Bedrock guardrail via `policies/aws-only/` | **whether the guardrail actually blocks anything**. Only `guardrail_probe.py` on real AWS (Bedrock ApplyGuardrail). moto has no Bedrock guardrails |
| AIS-11 | network boundary + flow logs | same | agent roles/tool lists, prompt hardening, step-wise confirmations |
| AIS-13 | 4 instance-level checks | same | container/process sandbox, resource limits, timeouts, file-system/IPC isolation |
| LOG-15 | 2 checks (newest 50 events sampled) | same | completeness of logging, hallucination/violation detection |
| IAM-19 | 2 checks | same | whether each permission is *necessary* (no policy simulator in moto) |

Coverage per control is `partial` or `weak` in `controls.json`; every control lists its
`not_checked` items, and the checker prints them. A green result means "the cloud configuration
matches", never "the AI system is secure".

moto differences (local only): no Bedrock guardrails; `AdministratorAccess` is not preloaded, so setup creates a
stand-in policy of the same name; public-access-block does not override ACLs as in real S3.

## Prerequisites

Python 3.12 or 3.13, `pip install -r requirements.txt` (tested with c7n 0.9.53, moto 5.2.4).
Ollama is only needed for `gemma_probe.py` and `verify_ollama_weights.py`.

## Run on moto

Terminal 1:
```powershell
moto_server -p 5000
```
Terminal 2 (every new terminal needs the 4 variables):
```powershell
$env:AWS_ACCESS_KEY_ID="test"; $env:AWS_SECRET_ACCESS_KEY="test"
$env:AWS_DEFAULT_REGION="us-east-1"; $env:AWS_ENDPOINT_URL="http://localhost:5000"
python setup_resources.py          # once per moto session (restart moto or run teardown_resources.py to reset)
python checker.py --validate       # expected: 7/7 controls and 20/20 sub-checks matched, exit code 0
python report.py                   # short PASS/FAIL table
python gemma_probe.py              # optional: real Gemma answer into the monitored log group
python verify_ollama_weights.py    # optional: re-hash the real Gemma weights (about 1 minute for 7 GB)
```
`$env:OLLAMA_MODELS` must point to the model folder if it is not `%USERPROFILE%\.ollama\models`.
`python checker.py --ollama-weights` adds the local weights check to the report.

`--validate` fails (exit 1) when a policy did not run, Custodian logged an error, a control has
no resources, or the flagged set differs from the expected one. All 7 controls show
NON-COMPLIANT because each has bad resources by design.

## Run on real AWS (sandbox account only; NOT tested in the development sandbox)

The seed creates deliberately insecure resources (public-ACL bucket, world-open security groups,
an admin role, about 15 `t3.micro` instances). Use a dedicated sandbox account and tear down after.
```powershell
Remove-Item Env:AWS_ENDPOINT_URL          # talk to real AWS; use your own credentials/profile
python setup_resources.py --confirm-account <ACCOUNT_ID>
python checker.py --validate
python teardown_resources.py --confirm-account <ACCOUNT_ID>
```
S3 names get the account id as suffix (global uniqueness); the checker strips it before comparing.
Things to watch on first run: IAM propagation delays (setup retries), the public-ACL bucket needs
the account-level Block Public Access for ACLs to be off, a stopped instance loses its public IP
(do not stop instances before the run), For TVM-11 with a real Bedrock guardrail tag instances `guardrail-id=<id>`,
run `custodian run policies/aws-only/tvm-11-bedrock-guardrail.yml`, then `guardrail_probe.py`.

## Files

| File | Purpose |
|---|---|
| `controls.json` | Catalogue: official AICM text, checks with basis, expected seeded result, limitations, not-checked items |
| `policies/aicm-controls.yml` | Custodian policies, one per sub-check |
| `builtin_checks.py` | Content checks Custodian cannot do (re-hash, manifest, log fields, IAM wildcards, guardrail exists) |
| `checker.py` | Runs everything, reports every resource, validates against the seeded setup |
| `setup_resources.py` / `teardown_resources.py` | Create / delete the good and bad resources (moto or AWS) |
| `report.py` | Short PASS/FAIL table |
| `verify_ollama_weights.py` | Re-hash the local Gemma weights file (MDS-08, host level) |
| `gemma_probe.py` | Real Gemma output into the monitored log group (LOG-15) |
| `guardrail_probe.py` | Behavioural guardrail test, real AWS only (TVM-11) |
| `policies/aws-only/` | Policies that need real AWS (Bedrock guardrail) |
