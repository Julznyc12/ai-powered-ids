"""
Intrusion Detection System - Inference Pipeline
Load trained models and classify network traffic as BENIGN or ATTACK
"""
import os
import sys
import argparse
from datetime import datetime, timezone
import pandas as pd
import numpy as np
import joblib
from config import (
    FEATURES,
    BINARY_DETECTOR_PATH,
    ATTACK_CLASSIFIER_PATH,
    DEFAULT_OUTPUT_CSV,
    BINARY_LABELS,
    ATTACK_TYPES
)

ALERT_SEVERITY = {
    "BENIGN": "info",
    "DoS": "high",
    "DDoS": "critical",
    "PortScan": "medium",
    "BruteForce": "high",
    "WebAttack": "high",
    "Bot": "high",
    "Heartbleed": "critical",
}

ALERT_ACTIONS = {
    "BENIGN": "No action required",
    "DoS": "Validate traffic spike, identify affected asset, and apply rate limiting if needed",
    "DDoS": "Escalate immediately, confirm service impact, and activate DDoS mitigation controls",
    "PortScan": "Review source activity, confirm reconnaissance, and consider blocking the source",
    "BruteForce": "Review authentication logs, lock targeted accounts, and block the source if confirmed",
    "WebAttack": "Inspect web server logs, validate exploitation attempts, and isolate affected hosts if needed",
    "Bot": "Check for command-and-control behavior, isolate the endpoint, and investigate persistence",
    "Heartbleed": "Treat as critical, identify exposed services, rotate secrets, and patch vulnerable systems",
}


def load_models():
    """Load pre-trained models."""
    try:
        binary_detector = joblib.load(BINARY_DETECTOR_PATH)
        attack_classifier = joblib.load(ATTACK_CLASSIFIER_PATH)
        for model in (binary_detector, attack_classifier):
            if hasattr(model, "n_jobs"):
                model.set_params(n_jobs=1)
        return binary_detector, attack_classifier
    except FileNotFoundError as e:
        print(f"Error: Model file not found. {e}")
        sys.exit(1)


def preprocess_data(df):
    """Prepare input data for inference. Returns features and indices of valid rows."""
    # Clean column names
    df.columns = df.columns.str.strip()

    # Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Get indices of rows with valid features (before dropping)
    valid_indices = df.dropna(subset=FEATURES).index

    # Extract features for valid rows only
    X = df.loc[valid_indices, FEATURES].copy()

    return X, valid_indices


def build_soc_alerts(df_results):
    """Build SOC-style alerts from attack predictions."""
    alert_rows = df_results[df_results["prediction_label"] == "ATTACK"].copy()
    if alert_rows.empty:
        return pd.DataFrame(columns=[
            "timestamp",
            "alert_id",
            "severity",
            "status",
            "category",
            "dst_port",
            "flow_duration",
            "flow_bytes_per_sec",
            "flow_packets_per_sec",
            "confidence",
            "summary",
            "recommended_action",
        ])

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    alert_rows = alert_rows.reset_index(drop=True)
    alert_rows["timestamp"] = generated_at
    alert_rows["alert_id"] = [f"IDS-{idx:06d}" for idx in range(1, len(alert_rows) + 1)]
    alert_rows["severity"] = alert_rows["attack_type"].map(ALERT_SEVERITY).fillna("medium")
    alert_rows["status"] = "new"
    alert_rows["category"] = alert_rows["attack_type"]
    alert_rows["dst_port"] = alert_rows["Destination Port"]
    alert_rows["flow_duration"] = alert_rows["Flow Duration"]
    alert_rows["flow_bytes_per_sec"] = alert_rows["Flow Bytes/s"]
    alert_rows["flow_packets_per_sec"] = alert_rows["Flow Packets/s"]
    alert_rows["confidence"] = np.where(
        alert_rows["severity"].isin(["critical", "high"]),
        0.90,
        0.75,
    )
    alert_rows["summary"] = alert_rows.apply(
        lambda row: f"{row['attack_type']} activity detected targeting destination port {row['dst_port']}",
        axis=1,
    )
    alert_rows["recommended_action"] = alert_rows["attack_type"].map(ALERT_ACTIONS).fillna(
        "Review event details and investigate the affected host"
    )

    return alert_rows[[
        "timestamp",
        "alert_id",
        "severity",
        "status",
        "category",
        "dst_port",
        "flow_duration",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "confidence",
        "summary",
        "recommended_action",
    ]]


def predict(input_csv, output_csv):
    """Run inference on input data and save predictions."""
    print(f"Loading data from {input_csv}...")
    df = pd.read_csv(input_csv)
    original_count = len(df)

    print(f"Preprocessing {original_count} records...")
    X, valid_indices = preprocess_data(df)
    print(f"Valid records: {len(X)}/{original_count}")

    if len(X) == 0:
        print("Error: No valid records after preprocessing")
        sys.exit(1)

    print("Loading models...")
    binary_detector, attack_classifier = load_models()

    print("Running predictions...")
    # Binary classification: BENIGN (0) or ATTACK (1)
    binary_preds = binary_detector.predict(X)

    # Attack type classification only for predicted attacks
    attack_preds = np.full(len(X), "BENIGN", dtype=object)
    attack_mask = binary_preds == 1
    if attack_mask.any():
        attack_preds[attack_mask] = attack_classifier.predict(X.loc[attack_mask])

    # Build results dataframe with only valid rows
    df_results = df.loc[valid_indices].copy()
    df_results["prediction"] = binary_preds
    df_results["prediction_label"] = df_results["prediction"].map(BINARY_LABELS)
    df_results["attack_type"] = attack_preds

    # Save results
    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    df_results.to_csv(output_csv, index=False)
    print(f"Results saved to {output_csv}")

    alerts_output_csv = os.path.join(output_dir or os.getcwd(), "soc_alerts.csv")
    df_alerts = build_soc_alerts(df_results)
    df_alerts.to_csv(alerts_output_csv, index=False)
    print(f"SOC alerts saved to {alerts_output_csv}")

    # Print summary
    print("\n=== Prediction Summary ===")
    print(df_results["prediction_label"].value_counts())
    print("\nAttack type distribution:")
    print(df_results["attack_type"].value_counts())

    attack_count = int((df_results["prediction_label"] == "ATTACK").sum())
    benign_count = int((df_results["prediction_label"] == "BENIGN").sum())
    print("\n=== SOC Alert Summary ===")
    print(f"Total flows processed: {len(df_results)}")
    print(f"Benign flows: {benign_count}")
    print(f"Attack flows: {attack_count}")

    if attack_count:
        print("Detected attack types:")
        attack_summary = (
            df_results.loc[df_results["prediction_label"] == "ATTACK", "attack_type"]
            .value_counts()
        )
        for attack_type, count in attack_summary.items():
            print(f"- {attack_type}: {count}")
        print(f"SOC alerts generated: {len(df_alerts)}")
    else:
        print("No attack traffic detected. SOC alerts generated: 0")


def main():
    parser = argparse.ArgumentParser(
        description="IDS Inference: Classify network traffic as BENIGN or ATTACK"
    )
    parser.add_argument(
        "input_csv",
        help="Input CSV file with network flow features"
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT_CSV,
        help=f"Output CSV file with predictions (default: {DEFAULT_OUTPUT_CSV})"
    )

    args = parser.parse_args()

    if not args.input_csv.endswith('.csv'):
        print("Error: Input file must be a CSV file")
        sys.exit(1)

    if not os.path.isfile(args.input_csv):
        print(f"Error: Input CSV file not found: {args.input_csv}")
        sys.exit(1)

    try:
        predict(args.input_csv, args.output)
    except Exception as e:
        print(f"Error during inference: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
