import os
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from src.preprocessing import build_scaler, prepare_dataset, generate_mock_datasets
from src.detectors import train_all_detectors, predict_all
from src.evaluate import evaluate

def run_cross_validation(n_folds=5):
    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'

    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    build_scaler(monday_path)
    X, y, df = prepare_dataset(wednesday_path)

    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    fold_results = []

    print(f"\n--- Running {n_folds}-Fold Cross Validation ---")
    for fold_num, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        X_benign_train = X_train[y_train == 0]   # Unsupervised fit on benign split

        iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)
        final_pred, _, _, _ = predict_all(iso, svm, ae, ae_thresh, X_test)

        metrics = evaluate(y_test, final_pred, f"Fold {fold_num}")
        metrics["fold"] = fold_num
        fold_results.append(metrics)

    df_results = pd.DataFrame(fold_results)[["fold", "accuracy", "precision", "recall", "f1", "fpr"]]

    summary = pd.DataFrame({
        "metric": ["accuracy", "precision", "recall", "f1", "fpr"],
        "mean_pct": [round(df_results[c].mean(), 2) for c in ["accuracy", "precision", "recall", "f1", "fpr"]],
        "std_dev_pct": [round(df_results[c].std(), 2) for c in ["accuracy", "precision", "recall", "f1", "fpr"]],
    })

    os.makedirs("results", exist_ok=True)
    df_results.to_csv("results/cross_validation_per_fold.csv", index=False)
    summary.to_csv("results/cross_validation_summary.csv", index=False)
    print("\n--- Cross Validation Summary ---")
    print(summary.to_string(index=False))
    return summary

if __name__ == "__main__":
    run_cross_validation()
