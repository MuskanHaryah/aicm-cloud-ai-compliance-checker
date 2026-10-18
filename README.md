# Automated Compliance Checking of Cloud AI Systems (CSA AICM)

Cloud Custodian policies that check the cloud infrastructure around an open-source
AI model (Gemma 3n E4B, `gemma3n:e4b`) against 7 CSA AI Controls Matrix (AICM)
controls. Everything runs locally against **moto**, a fake AWS, so no AWS account
or cost is needed.

| Control | Title | Policy name |
|---|---|---|
| MDS-08 | Model Integrity Checks | `mds-08-model-integrity` |
| DSP-21 | Data Poisoning Prevention & Detection | `dsp-21-data-poisoning` |
| TVM-13 | Guardrails | `tvm-13-guardrails` |
| AIS-11 | Agents Security Boundaries | `ais-11-agent-boundaries` |
| AIS-13 | AI Sandboxing | `ais-13-sandboxing` |
| LOG-16 | Output Monitoring | `log-16-output-monitoring` |
| IAM-18 | Agent Access Restriction | `iam-18-agent-access-restriction` |

Custodian checks cloud configuration only (bucket settings, security groups, IAM,
logs, tags). It does not look inside the model. Each control is therefore checked
through a configuration proxy.

## Prerequisites

- Windows + PowerShell, Python 3.12 or 3.13 (not 3.14/3.15, `c7n` fails to install there)
- [Ollama](https://ollama.com/download) installed and running, with the model pulled:
  `ollama pull gemma3n:e4b`

Check:

```powershell
python --version
ollama list
```

`ollama list` must show `gemma3n:e4b`. Opening http://localhost:11434 in a browser
should say "Ollama is running".

## 1. Setup (once)

Open PowerShell in the project folder.

```powershell
git clone <REPO_URL>
cd <REPO_FOLDER>

py -3.12 -m venv aicm-env
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
aicm-env\Scripts\activate

pip install -r requirements.txt
custodian version
moto_server --help
```

If a virtual environment `aicm-env` already exists, skip the `py -3.12 -m venv` line.
(`py -3.13` works too.)

## 2. Start the fake AWS (Terminal 1, leave it running)

```powershell
cd <PROJECT_FOLDER>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
aicm-env\Scripts\activate
moto_server -p 5000
```

Moto keeps everything in memory. To reset it, stop it with `Ctrl+C` and start it again.

## 3. Run the checks (Terminal 2)

Open a **new** terminal. Every new terminal needs the 4 environment variables.

```powershell
cd <PROJECT_FOLDER>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
aicm-env\Scripts\activate

$env:AWS_ACCESS_KEY_ID="test"
$env:AWS_SECRET_ACCESS_KEY="test"
$env:AWS_DEFAULT_REGION="us-east-1"
$env:AWS_ENDPOINT_URL="http://localhost:5000"
```

Create the good and bad fake resources (run once per moto session):

```powershell
python setup_resources.py
```

Link the real Gemma model to the model-integrity check (Ollama must be running).
Both Gemma scripts must run **after** `setup_resources.py`:

```powershell
python gemma_hash.py
python gemma_probe.py
```

`gemma_hash.py` stores Gemma's real digest as a tag on the model bucket.
`gemma_probe.py` asks Gemma a question and writes its answer into the fake log group.
It can take a minute or two on CPU.

Run all 7 policies and print the report:

```powershell
custodian run -s output policies/aicm-controls.yml --cache-period 0
python report.py
```

## Expected result

Each of the 7 policies logs `count:1`, and `report.py` shows 7 rows with `FAIL`,
each listing only the deliberately non-compliant `bad` resource (for example
`gemma-model-bad`). The compliant `good` resources are not flagged. The table is also
saved as `compliance_report.csv`.

Flagged resources per policy: `output\<policy-name>\resources.json`

## Troubleshooting

| Problem | Fix |
|---|---|
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `NoCredentialsError` | The 4 `$env:AWS_...` variables are missing in this terminal |
| `already exists` error in `setup_resources.py` | Restart moto (Ctrl+C, `moto_server -p 5000`) and run it again |
| `count:0` right after something changed | Add `--cache-period 0` to the custodian command |
| `ollama` not recognized | Close PowerShell and open a new window |
| `gemma_hash.py` or `gemma_probe.py` cannot connect | Start Ollama and check http://localhost:11434 |
| `pip install c7n` fails with a pyyaml build error | Use Python 3.12 or 3.13 |
| Terminal opened as "Developer PowerShell for VS" | Use normal PowerShell instead |

## Files

| File | Purpose |
|---|---|
| `setup_resources.py` | Creates good and bad fake resources in moto for all 7 controls |
| `policies/aicm-controls.yml` | The 7 Cloud Custodian policies |
| `gemma_hash.py` | Tags the model bucket with the real Gemma digest (MDS-08) |
| `gemma_probe.py` | Sends a prompt to Gemma and logs the output (LOG-16) |
| `report.py` | Builds the per-control PASS/FAIL table and `compliance_report.csv` |
