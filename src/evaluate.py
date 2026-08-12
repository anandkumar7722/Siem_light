from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def evaluate(y_true, y_pred, label="Model"):
    acc = accuracy_score(y_true, y_pred) * 100
    prec = precision_score(y_true, y_pred, zero_division=0) * 100
    rec = recall_score(y_true, y_pred, zero_division=0) * 100
    f1 = f1_score(y_true, y_pred, zero_division=0) * 100
    cm = confusion_matrix(y_true, y_pred)
    
    # False Positive Rate: FP / (FP + TN)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (cm[0][0], 0, 0, 0)
    fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0.0

    print(f"--- {label} ---")
    print(f"Accuracy:  {acc:.2f}%")
    print(f"Precision: {prec:.2f}%")
    print(f"Recall:    {rec:.2f}%")
    print(f"F1-Score:  {f1:.2f}%")
    print(f"FPR:       {fpr:.2f}%")
    print("Confusion matrix:\n", cm)
    print("-" * (len(label) + 8))
    
    return {
        "label": label,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "confusion_matrix": cm
    }
