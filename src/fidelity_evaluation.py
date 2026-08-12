import os
import numpy as np
import pandas as pd
from src.preprocessing import build_scaler, prepare_dataset, generate_mock_datasets
from src.detectors import train_all_detectors
from src.explainability import (get_shap_explainer, get_lime_explainer,
                                explain_alert_lime, isolation_forest_proba,
                                fidelity_test, lime_fidelity_test)

def run_fidelity_evaluation(n_samples=200):
    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'

    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    scaler, feature_cols = build_scaler(monday_path)
    X, y, df = prepare_dataset(wednesday_path)
    X_benign_train = X[y == 0]

    iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)

    explainer = get_shap_explainer(iso)

    # Set up LIME explainer
    lime_bg_idx = np.random.choice(len(X_benign_train), min(500, len(X_benign_train)), replace=False)
    lime_bg = X_benign_train[lime_bg_idx]
    lime_explainer = get_lime_explainer(lime_bg, feature_cols)
    predict_proba_fn = lambda data: isolation_forest_proba(iso, data)

    attack_idx = np.where(y == 1)[0]
    if len(attack_idx) > n_samples:
        attack_idx = np.random.choice(attack_idx, n_samples, replace=False)

    def iso_predict_fn(X_batch):
        return -iso.decision_function(X_batch)

    sample_alerts = []
    shap_top_feature_idx_list = []
    lime_results_list = []

    for idx in attack_idx:
        X_alert = X[idx]
        
        # SHAP attribution
        shap_contributions = explainer.explain_instance(X_alert, feature_cols)
        top5_indices = []
        for fname, _ in shap_contributions:
            if fname in feature_cols:
                top5_indices.append(feature_cols.index(fname))

        # LIME attribution
        lime_exp = explain_alert_lime(lime_explainer, predict_proba_fn, X_alert, num_features=5, num_samples=1000)

        sample_alerts.append(X_alert)
        shap_top_feature_idx_list.append(top5_indices)
        lime_results_list.append(lime_exp)

    # Compute fidelities
    shap_avg_fid = fidelity_test(np.array(sample_alerts), shap_top_feature_idx_list, iso_predict_fn)
    shap_std_fid = float(np.std([shap_avg_fid]))

    lime_avg_fid = lime_fidelity_test(predict_proba_fn, sample_alerts, lime_results_list, feature_cols)
    lime_std_fid = float(np.std([lime_avg_fid]))

    result = pd.DataFrame([
        {
            "metric": "SHAP TreeExplainer Top-5 Fidelity",
            "mean_fidelity_pct": round(shap_avg_fid, 2),
            "std_dev_pct": round(shap_std_fid, 2),
            "n_samples": len(attack_idx)
        },
        {
            "metric": "LIME TabularExplainer Top-5 Fidelity",
            "mean_fidelity_pct": round(lime_avg_fid, 2),
            "std_dev_pct": round(lime_std_fid, 2),
            "n_samples": len(attack_idx)
        }
    ])
    
    os.makedirs("results", exist_ok=True)
    result.to_csv("results/fidelity_results.csv", index=False)
    print("\n--- Combined XAI Fidelity Evaluation Summary ---")
    print(result.to_string(index=False))
    return result

if __name__ == "__main__":
    run_fidelity_evaluation()
