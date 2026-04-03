# Machine Learning Intrusion Detection (CICIDS2017)

## Overview
This project focuses on building a machine learning-based intrusion detection system using the CICIDS2017 dataset to identify malicious network activity and anomalous behavior.

The goal is to explore how machine learning can enhance traditional intrusion detection systems by improving detection accuracy and reducing false positives in a SOC environment.

---

## What I Built
- Processed and analyzed network traffic data from CICIDS2017
- Performed feature analysis and preprocessing using Python
- Developed machine learning models for intrusion detection
- Generated predictions for normal vs. malicious activity
- Evaluated model performance using standard classification metrics

---

## Models Used
- **Random Forest** – supervised classification for detecting known attack patterns  
- **Isolation Forest** – unsupervised anomaly detection for identifying unusual behavior  

---

## Evaluation Metrics
Models were evaluated using:
- Accuracy  
- Precision  
- Recall  
- F1-Score  

These metrics were used to assess detection effectiveness and false positive rates.

---

## Key Concepts
- Anomaly Detection  
- Supervised vs. Unsupervised Learning  
- Network Traffic Analysis  
- Model Evaluation  
- Cybersecurity Analytics  

---

## Future Work
- Improve feature engineering and model tuning  
- Expand dataset testing for better generalization  
- Integrate ML predictions with Suricata alerts  
- Feed results into Splunk dashboards for real-time monitoring  
- Develop automated detection and response workflows  

---

## Project Context
This project began as part of a research-focused cybersecurity study and is being further developed as a standalone module within a larger AI-powered IDS system.

The long-term goal is to integrate this ML detection pipeline into a real-time environment using Suricata and Splunk to simulate SOC-level monitoring and response.

---
