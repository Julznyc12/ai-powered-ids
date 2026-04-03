# AI-Powered Intrusion Detection System (AI-IDS)

## Overview
This project is an end-to-end AI-powered intrusion detection system that combines traditional network-based detection with machine learning to identify and analyze malicious activity.

The system integrates a Suricata-based IDS with Splunk for monitoring and visualization, alongside a machine learning pipeline trained on the CICIDS2017 dataset to enhance detection capabilities.

The goal is to simulate a SOC environment where alerts, logs, and intelligent detection mechanisms work together to improve threat visibility and response.

---

## System Components

### 1. Network-Based Detection
- Suricata IDS for real-time traffic monitoring
- Custom and default detection rules
- Alert generation based on network signatures and behavior

### 2. SIEM & Visualization
- Splunk dashboards for:
  - Traffic analysis
  - Alert monitoring
  - Threat visibility
- Configured alerts for:
  - Port scanning activity
  - Traffic spikes (possible DDoS)
  - Repeated suspicious behavior

### 3. Machine Learning Detection
- ML models trained on CICIDS2017 dataset
- Random Forest (classification)
- Isolation Forest (anomaly detection)
- Evaluated using precision, recall, and F1-score

👉 See ML module: `ml_detection/`
---

## Key Features
- Real-time network monitoring with Suricata  
- Log ingestion and analysis using Splunk  
- Machine learning-based threat detection  
- Custom alerting and detection rules  
- SOC-style dashboard visualization  

---

## Technologies Used
- Python  
- Suricata  
- Splunk  
- Jupyter Notebook  
- CICIDS2017 Dataset  

---

## Use Case
This project simulates a Security Operations Center (SOC) workflow by combining:
- Network-level detection (Suricata)
- Log analysis and alerting (Splunk)
- Intelligent detection (Machine Learning)

It demonstrates how multiple layers of security can work together to improve detection accuracy and reduce false positives.

---

## Future Improvements
- Integrate ML predictions into real-time alert pipelines  
- Automate response actions (e.g., IP blocking, rule updates)  
- Enhance feature engineering and model performance  
- Expand detection coverage for additional attack types  
- Deploy as a more automated and scalable system  

---

## Project Context
This project is part of ongoing cybersecurity research and development, focused on bridging machine learning with practical security operations.

It is actively being expanded and improved to reflect real-world SOC environments and modern detection strategies.

---
