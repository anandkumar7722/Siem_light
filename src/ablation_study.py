import os
import time
import numpy as np
import pandas as pd
from src.preprocessing import build_scaler, prepare_dataset, generate_mock_datasets
from src.detectors import train_all_detectors, predict_all
from src.evaluate import evaluate
from src.explainability import get_shap_explainer
from src.mitre_mapper import map_to_mitre

def run_ablation_study(n_test_alerts=50):
    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'

    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    scaler, feature_cols = build_scaler(monday_path)
    X, y, df = prepare_dataset(wednesday_path)
    X_benign_train = X[y == 0]

    iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)

    # --- Config 1: Detection only ---
    start = time.time()
    final_pred, pred_if, pred_svm, pred_ae = predict_all(iso, svm, ae, ae_thresh, X)
    detection_time = time.time() - start
    metrics_detection = evaluate(y, final_pred, "Detection Only")
    per_alert_latency_detection = detection_time / len(X)

    # --- Config 2: Detection + XAI ---
    explainer = get_shap_explainer(iso)
    attack_idx = np.where(y == 1)[0]
    sample_idx = np.random.choice(attack_idx, min(n_test_alerts, len(attack_idx)), replace=False)

    start = time.time()
    for idx in sample_idx:
        _ = explainer.explain_instance(X[idx], feature_cols)
    xai_time = time.time() - start
    per_alert_latency_xai = per_alert_latency_detection + (xai_time / len(sample_idx))

    # --- Config 3: Full pipeline (+ MITRE mapping) ---
    start = time.time()
    for idx in sample_idx:
        label = df.iloc[idx]['Label']
        _ = map_to_mitre(label.replace('DoS ', '') if 'DoS' in str(label) else label)
    mitre_time = time.time() - start
    per_alert_latency_full = per_alert_latency_xai + (mitre_time / len(sample_idx))

    result = pd.DataFrame([
        {"configuration": "Detection Only", "accuracy": round(metrics_detection["accuracy"], 2),
         "fpr": round(metrics_detection["fpr"], 2), "avg_latency_per_alert_sec": round(per_alert_latency_detection, 5)},
        {"configuration": "Detection + XAI", "accuracy": round(metrics_detection["accuracy"], 2),
         "fpr": round(metrics_detection["fpr"], 2), "avg_latency_per_alert_sec": round(per_alert_latency_xai, 5)},
        {"configuration": "Full Pipeline (+MITRE)", "accuracy": round(metrics_detection["accuracy"], 2),
         "fpr": round(metrics_detection["fpr"], 2), "avg_latency_per_alert_sec": round(per_alert_latency_full, 5)},
    ])

    os.makedirs("results", exist_ok=True)
    result.to_csv("results/ablation_study.csv", index=False)
    print("\n--- Ablation Study Summary ---")
    print(result.to_string(index=False))
    return result

if __name__ == "__main__":
    run_ablation_study()
