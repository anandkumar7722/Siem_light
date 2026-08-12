import os
import pandas as pd
import numpy as np
from src.preprocessing import generate_mock_datasets, build_scaler, prepare_dataset
from src.detectors import train_all_detectors, predict_all
from src.evaluate import evaluate
from src.explainability import get_shap_explainer, explain_alert_shap, fidelity_test
from src.mitre_mapper import map_alert_to_mitre, MITREClassifierFallback
from src.benchmark import ResourceMonitor

def main():
    print("==================================================================")
    print("  Lightweight SIEM Framework — Cyber Threat Detection Pipeline")
    print("==================================================================")

    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'
    alerts_path = 'data/processed/alerts.csv'
    
    os.makedirs('data/processed', exist_ok=True)

    monitor = ResourceMonitor()
    monitor.start_timer()

    # Step 1: Ensure datasets exist (generate synthetic mock if not downloaded yet)
    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        print("\n[Module 1] Raw dataset CSVs not found. Generating mock CICIDS2017 datasets...")
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    # Step 2: Fit Scaler ONLY on Benign Monday Data (prevents data leakage)
    print("\n[Module 1] Building StandardScaler on benign Monday dataset...")
    scaler, feature_cols = build_scaler(monday_path)

    # Step 3: Prepare Wednesday dataset for evaluation
    print("[Module 1] Loading and preprocessing Wednesday flow dataset...")
    X, y, df = prepare_dataset(wednesday_path)

    X_benign_train = X[y == 0]
    X_test, y_test = X, y

    # Step 4: Train Anomaly Detectors
    print("\n[Module 2] Training Lightweight Ensemble Detectors (Isolation Forest, OC-SVM, Autoencoder)...")
    iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)

    # Step 5: Run Ensemble Anomaly Detection
    print("[Module 2] Running Ensemble Majority Voting Detection...")
    final_pred, pred_if, pred_svm, pred_ae = predict_all(iso, svm, ae, ae_thresh, X_test)

    # Step 6: Evaluation Metrics
    print("\n==================================================================")
    print("                DETECTION EVALUATION RESULTS")
    print("==================================================================")
    eval_if = evaluate(y_test, pred_if, "Isolation Forest")
    eval_svm = evaluate(y_test, pred_svm, "One-Class SVM")
    eval_ae = evaluate(y_test, pred_ae, "Autoencoder")
    eval_ens = evaluate(y_test, final_pred, "Ensemble Voting (Proposed)")

    # Step 7: SHAP Explainability & Fidelity Verification
    print("\n[Module 3] Initializing SHAP TreeExplainer engine...")
    shap_explainer = get_shap_explainer(iso)

    alert_indices = np.where(final_pred == 1)[0]
    print(f"[Module 3] Detected {len(alert_indices)} threat alerts out of {len(X_test)} total flows.")

    # Train fallback MITRE classifier
    fallback_clf = MITREClassifierFallback()
    y_labels = df['Label'].values
    fallback_clf.fit(X[y == 1], y_labels[y == 1])

    alert_records = []
    top_feature_idx_list = []
    sample_alerts_for_fidelity = []

    print("[Module 3 & 4] Generating SHAP explanations & MITRE ATT&CK mappings...")
    for count, idx in enumerate(alert_indices):
        X_alert = X_test[idx]
        actual_label = y_labels[idx]

        # Top 5 SHAP feature contributions
        top5_shap = explain_alert_shap(shap_explainer, X_alert.reshape(1, -1), feature_cols)
        
        # MITRE ATT&CK Mapping
        mitre_info = map_alert_to_mitre(actual_label, X_alert, fallback_clf)

        # Store record for dashboard
        record = {
            'alert_id': count + 1,
            'timestamp': df.iloc[idx].get('Timestamp', '2026-07-27 10:00:00'),
            'source_ip': df.iloc[idx].get('Source IP', '172.16.0.1'),
            'destination_ip': df.iloc[idx].get('Destination IP', '192.168.1.50'),
            'label': actual_label,
            'severity': 'Critical' if 'DoS' in str(actual_label) else 'High',
            'mitre_tactic': mitre_info['tactic'],
            'mitre_technique': mitre_info['technique'],
            'mitre_conf': mitre_info['conf']
        }
        
        # Add top 5 SHAP features and values
        top_indices = []
        for i, (fname, fval) in enumerate(top5_shap):
            record[f'shap_feat_{i+1}'] = fname
            record[f'shap_val_{i+1}'] = round(float(fval), 4)
            if fname in feature_cols:
                top_indices.append(feature_cols.index(fname))

        alert_records.append(record)
        
        if count < 200:
            sample_alerts_for_fidelity.append(X_alert)
            top_feature_idx_list.append(top_indices)

    alerts_df = pd.DataFrame(alert_records)
    alerts_df.to_csv(alerts_path, index=False)
    print(f"Saved {len(alerts_df)} processed alerts to {alerts_path}")

    # Calculate SHAP Fidelity score
    if len(sample_alerts_for_fidelity) > 0:
        def iso_decision_fn(X_arr):
            return iso.decision_function(X_arr)
        
        fid_score = fidelity_test(np.array(sample_alerts_for_fidelity),
                                  top_feature_idx_list,
                                  iso_decision_fn)
        print(f"[Module 3] SHAP Top-5 Explanation Fidelity Score: {fid_score:.2f}%")

    elapsed = monitor.stop_timer()
    usage = monitor.get_resource_usage()

    print("\n==================================================================")
    print("                LIGHTWEIGHT PROOF & PERFORMANCE SUMMARY")
    print("==================================================================")
    print(f"Total Pipeline Latency:  {elapsed:.2f} seconds")
    print(f"RAM Memory Footprint:    {usage['ram_mb']} MB")
    print(f"CPU Utilization:         {usage['cpu_percent']}%")
    print(f"Average Latency/Alert:   {(elapsed / max(len(alert_indices), 1)):.4f} seconds/alert")
    print("==================================================================\n")

if __name__ == "__main__":
    main()
