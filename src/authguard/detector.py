"""Train an unsupervised model on aggregated, synthetic authentication activity."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from sklearn.ensemble import IsolationForest

FEATURES = ("failed_logins", "unique_ips", "off_hours_logins", "successful_logins")


def read_rows(path: str | Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"user", "window_start", *FEATURES}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"Missing columns: {sorted(required - set(reader.fieldnames or []))}")
        rows = []
        for row in reader:
            values = [int(row[key]) for key in FEATURES]
            if any(value < 0 for value in values):
                raise ValueError("Counts must be nonnegative")
            rows.append({"user": row["user"], "window_start": row["window_start"], "features": values})
    if not rows:
        raise ValueError("Dataset is empty")
    return rows


def detect(train: list[dict], evaluate: list[dict], contamination: float = 0.1) -> list[dict]:
    if len(train) < 10:
        raise ValueError("At least 10 baseline windows are required")
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be in (0, 0.5]")
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit([row["features"] for row in train])
    predictions = model.predict([row["features"] for row in evaluate])
    maxima = [max(row["features"][i] for row in train) for i in range(len(FEATURES))]
    scores = model.decision_function([row["features"] for row in evaluate])
    return [{"user": row["user"], "window_start": row["window_start"],
             "anomaly": bool(pred == -1 or any(value > max(10, 3 * maximum)
                 for value, maximum in zip(row["features"], maxima))), "score": round(float(score), 5),
             "features": dict(zip(FEATURES, row["features"]))}
            for row, pred, score in zip(evaluate, predictions, scores)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Flag anomalous authentication activity")
    parser.add_argument("--baseline", required=True, help="CSV of known baseline windows")
    parser.add_argument("--evaluate", required=True, help="CSV of windows to score")
    parser.add_argument("--output", help="Optional JSON output path")
    parser.add_argument("--contamination", type=float, default=0.1)
    args = parser.parse_args()
    findings = detect(read_rows(args.baseline), read_rows(args.evaluate), args.contamination)
    output = json.dumps({"findings": findings, "anomalies": sum(x["anomaly"] for x in findings)}, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
