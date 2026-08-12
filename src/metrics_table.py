import os
import pandas as pd
from src.preprocessing import build_scaler, prepare_dataset, generate_mock_datasets
from src.detectors import train_all_detectors, predict_all
from src.evaluate import evaluate
from src.resource_monitor import ResourceMonitor

def run_metrics_table():
    monday_path = 'data/raw/Monday-WorkingHours.pcap_ISCX.csv'
    wednesday_path = 'data/raw/Wednesday-workingHours.pcap_ISCX.csv'

    if not os.path.exists(monday_path) or not os.path.exists(wednesday_path):
        generate_mock_datasets(monday_path, wednesday_path, num_samples=2500)

    monitor = ResourceMonitor(interval=0.2)
    monitor.start()

    build_scaler(monday_path)
    X, y, df = prepare_dataset(wednesday_path)

    X_benign_train = X[y == 0]
    iso, svm, ae, ae_thresh = train_all_detectors(X_benign_train)
    final_pred, pred_if, pred_svm, pred_ae = predict_all(iso, svm, ae, ae_thresh, X)

    rows = []
    for name, preds in [("Isolation Forest", pred_if),
                         ("One-Class SVM", pred_svm),
                         ("Autoencoder", pred_ae),
                         ("Ensemble (Proposed)", final_pred)]:
        metrics = evaluate(y, preds, name)
        metrics["model"] = name
        rows.append(metrics)

    table = pd.DataFrame(rows)[["model", "accuracy", "precision", "recall", "f1", "fpr"]]
    table.columns = ["Model", "Accuracy (%)", "Precision (%)", "Recall (%)", "F1-Score (%)", "FPR (%)"]
    table = table.round(2)

    os.makedirs("results", exist_ok=True)
    table.to_csv("results/detection_metrics_table.csv", index=False)
    print("\n--- Detection Metrics Table ---")
    print(table.to_string(index=False))
    
    monitor.stop("results/resource_usage.csv")
    return table

if __name__ == "__main__":
    run_metrics_table()
