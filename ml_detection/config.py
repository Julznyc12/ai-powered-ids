"""Configuration for IDS inference pipeline."""
import os

# Features used for detection (must match training)
FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s"
]

# Model directory
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
ALERTS_DIR = os.path.join(os.path.dirname(__file__), "alerts")

# Model file paths (general model)
SCALER_PATH = os.path.join(MODEL_DIR, "general_scaler.pkl")
BINARY_DETECTOR_PATH = os.path.join(MODEL_DIR, "general_binary_rf_model.pkl")
ATTACK_CLASSIFIER_PATH = os.path.join(MODEL_DIR, "general_attack_classifier.pkl")
DEFAULT_OUTPUT_CSV = os.path.join(ALERTS_DIR, "predictions.csv")

# Label mappings
BINARY_LABELS = {
    0: "BENIGN",
    1: "ATTACK"
}

ATTACK_TYPES = {
    "BENIGN": "BENIGN",
    "DoS": "DoS",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "BruteForce": "BruteForce",
    "WebAttack": "WebAttack",
    "Bot": "Bot",
    "Heartbleed": "Heartbleed"
}
