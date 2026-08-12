import time
import pandas as pd
import numpy as np
import os
import json
from datetime import datetime
from src.preprocessing import build_scaler, prepare_dataset, generate_mock_datasets
from src.detectors import (train_all_detectors, predict_all,
                            fit_score_normalizers, compute_ensemble_anomaly_score,
                            severity_from_score)
from src.explainability import (get_shap_explainer, get_lime_explainer,
                                explain_alert_lime, isolation_forest_proba,
                                parse_lime_feature_name)
from src.mitre_mapper import map_to_mitre

ALERTS_PATH = "data/processed/alerts.csv"
LIVE_STATS_PATH = "results/live_stats.json"

def write_live_stats(total_alerts, false_positives, true_negatives, severity_counts):
    running_fpr = (false_positives / max(1, false_positives + true_negatives)) * 100
    stats = {
        "total_alerts": total_alerts,
        "engine_fpr_pct": round(running_fpr, 2),
        "severity_counts": severity_counts,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    os.makedirs("results", exist_ok=True)
    with open(LIVE_STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

def run_stream(delay_seconds=2, max_events=None):
    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'

    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    scaler, feature_cols = build_scaler(monday_path)
    X, y, df = prepare_dataset(wednesday_path)
    X_benign_train = X[y == 0]

    print("Training detectors once before streaming starts...")
    iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)

    # Calibrate QuantileTransformers against mixed sample (benign + attack)
    calibration_sample = X[np.random.choice(len(X), min(2000, len(X)), replace=False)]
    transformers = fit_score_normalizers(iso, svm, ae, ae_thresh, X_benign_train,
                                         X_sample_mixed=calibration_sample)

    explainer = get_shap_explainer(iso)

    # Set up LIME explainer once before streaming loop starts
    # Subsample 500 background rows for LIME local perturbation calibration
    lime_bg_idx = np.random.choice(len(X_benign_train), min(500, len(X_benign_train)), replace=False)
    lime_bg = X_benign_train[lime_bg_idx]
    lime_explainer = get_lime_explainer(lime_bg, feature_cols)
    predict_proba_fn = lambda data: isolation_forest_proba(iso, data)

    os.makedirs("data/processed", exist_ok=True)
    if os.path.exists(ALERTS_PATH):
        os.remove(ALERTS_PATH)

    n_events = max_events or len(X)
    false_positives, true_negatives, total_alerts = 0, 0, 0
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    print(f"Streaming {n_events} events, {delay_seconds}s apart. Press Ctrl+C to stop.")

    for i in range(n_events):
        x_row = X[i].reshape(1, -1)
        final_pred, pred_if, pred_svm, pred_ae = predict_all(iso, svm, ae, ae_thresh, x_row)
        label = df.iloc[i]['Label']

        # Track running FPR against ground truth
        if final_pred[0] == 1 and label == 'BENIGN':
            false_positives += 1
        if final_pred[0] == 0 and label == 'BENIGN':
            true_negatives += 1

        if final_pred[0] == 1:
            anomaly_score = compute_ensemble_anomaly_score(iso, svm, ae, x_row, transformers)
            severity = severity_from_score(anomaly_score)
            severity_counts[severity] += 1
            total_alerts += 1

            contributions = explainer.explain_instance(X[i], feature_cols)

            # Compute LIME explanation (using num_samples=1000 for low stream latency impact)
            lime_exp = explain_alert_lime(lime_explainer, predict_proba_fn, X[i], num_features=5, num_samples=1000)

            mitre = map_to_mitre(label.replace('DoS ', '') if 'DoS' in str(label) else label) or \
                    {"tactic": "TA0040 Impact", "technique": "T1499", "conf": 85.0}

            alert_row = {
                "alert_id": i + 1,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": df.iloc[i].get('Source IP', 'N/A'),
                "destination_ip": df.iloc[i].get('Destination IP', 'N/A'),
                "label": label,
                "severity": severity,
                "anomaly_score": round(anomaly_score, 3),
                "mitre_tactic": mitre["tactic"],
                "mitre_technique": mitre["technique"],
                "mitre_conf": mitre["conf"],
            }
            
            for j, (fname, fval) in enumerate(contributions[:5], start=1):
                alert_row[f"shap_feat_{j}"] = fname
                alert_row[f"shap_val_{j}"] = round(float(fval), 4)

            for j, (cond_str, weight) in enumerate(lime_exp[:5], start=1):
                clean_feat = parse_lime_feature_name(cond_str, feature_cols) or cond_str
                alert_row[f"lime_feat_{j}"] = clean_feat
                alert_row[f"lime_val_{j}"] = round(float(weight), 4)

            pd.DataFrame([alert_row]).to_csv(
                ALERTS_PATH, mode='a', index=False,
                header=not os.path.exists(ALERTS_PATH)
            )
            print(f"[{alert_row['timestamp']}] ALERT #{i+1} — {label} — {severity} (score={anomaly_score:.3f})")

        write_live_stats(total_alerts, false_positives, true_negatives, severity_counts)
        time.sleep(delay_seconds)

if __name__ == "__main__":
    run_stream(delay_seconds=2, max_events=500)
