# AuthGuard: Authentication Anomaly Detector

A defensive Python project using **Isolation Forest** to flag unusual authentication activity in aggregated per-user, per-hour windows. It considers failed logins, unique source IP counts, off-hours logins, and successful logins.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
authguard --baseline data/baseline.csv --evaluate data/evaluation.csv --output findings.json
pytest -q
```

The CSV files contain **synthetic data only**. Lower model scores indicate more unusual activity. The model is an unsupervised triage aid, not proof of compromise. A conservative baseline-range guard flags unusually large counts that Isolation Forest might miss.

## Input schema

`user,window_start,failed_logins,unique_ips,off_hours_logins,successful_logins`

Counts must be nonnegative integers. Each row represents one user and one time window.

## Project structure

- `src/authguard/detector.py`: validation, model training, scoring, and CLI
- `tests/test_detector.py`: unit tests
- `data/`: synthetic baseline and evaluation data

## Limitations

This demonstration has no labeled ground truth, so it does not establish precision or recall. Real deployments need representative historical baselines, drift monitoring, privacy controls, and analyst review. The default contamination of 0.1 is a tunable assumption, not an incident probability.

Only analyze logs you are authorized to access. Do not commit credentials, tokens, or production logs.
