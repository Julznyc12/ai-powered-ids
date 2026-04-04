"""
Intrusion Detection System - Inference Pipeline
Load trained models and classify network traffic as BENIGN or ATTACK
"""
import os
import sys
import argparse
import pandas as pd
import numpy as np
import joblib
from config import (
    FEATURES,
    SCALER_PATH,
    BINARY_DETECTOR_PATH,
    ATTACK_CLASSIFIER_PATH,
    DEFAULT_OUTPUT_CSV,
    BINARY_LABELS,
    ATTACK_TYPES
)


def load_models():
    """Load pre-trained models and scaler."""
    try:
        scaler = joblib.load(SCALER_PATH)
        binary_detector = joblib.load(BINARY_DETECTOR_PATH)
        attack_classifier = joblib.load(ATTACK_CLASSIFIER_PATH)
        return scaler, binary_detector, attack_classifier
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
    scaler, binary_detector, attack_classifier = load_models()

    # Scale features
    X_scaled = scaler.transform(X)

    print("Running predictions...")
    # Binary classification: BENIGN (0) or ATTACK (1)
    binary_preds = binary_detector.predict(X_scaled)

    # Attack type classification only for predicted attacks
    attack_preds = np.full(len(X), "BENIGN", dtype=object)
    attack_mask = binary_preds == 1
    if attack_mask.any():
        attack_preds[attack_mask] = attack_classifier.predict(X_scaled[attack_mask])

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

    # Print summary
    print("\n=== Prediction Summary ===")
    print(df_results["prediction_label"].value_counts())
    print("\nAttack type distribution:")
    print(df_results["attack_type"].value_counts())


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
    
