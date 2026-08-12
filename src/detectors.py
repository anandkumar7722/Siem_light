import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import QuantileTransformer

def train_isolation_forest(X_train_benign):
    model = IsolationForest(contamination=0.05, n_estimators=100,
                             max_samples='auto', random_state=42)
    model.fit(X_train_benign)
    return model

def train_one_class_svm(X_train_benign, sample_size=50000):
    if len(X_train_benign) > sample_size:
        idx = np.random.choice(len(X_train_benign), sample_size, replace=False)
        X_sub = X_train_benign[idx]
    else:
        X_sub = X_train_benign
    model = OneClassSVM(nu=0.05, kernel='rbf', gamma='scale')
    model.fit(X_sub)
    return model

def train_autoencoder(X_train_benign):
    ae = MLPRegressor(
        hidden_layer_sizes=(64, 32, 16, 32, 64),
        activation='relu',
        solver='adam',
        max_iter=30,
        random_state=42,
        early_stopping=True
    )
    ae.fit(X_train_benign, X_train_benign)
    reconstructions = ae.predict(X_train_benign)
    errors = np.mean(np.square(X_train_benign - reconstructions), axis=1)
    threshold = np.percentile(errors, 95)
    return ae, threshold

def fit_score_normalizers(iso, svm, ae, ae_thresh, X_benign_train, X_sample_mixed=None, save_path="models/score_transformers.pkl"):
    """Fit a QuantileTransformer per detector — maps any future raw score to its
    percentile rank (0-1) relative to this calibration set. No hard ceiling to clip
    against, so scores spread naturally instead of piling up at 1.0."""
    calibration_set = X_benign_train
    if X_sample_mixed is not None:
        calibration_set = np.vstack([X_benign_train, X_sample_mixed])

    if_scores = (-iso.score_samples(calibration_set)).reshape(-1, 1)
    svm_scores = (-svm.decision_function(calibration_set)).reshape(-1, 1)
    reconstructions = ae.predict(calibration_set)
    ae_errors = np.mean(np.square(calibration_set - reconstructions), axis=1).reshape(-1, 1)

    n_q = min(1000, len(calibration_set))

    if_transformer = QuantileTransformer(output_distribution='uniform', n_quantiles=n_q, random_state=42)
    svm_transformer = QuantileTransformer(output_distribution='uniform', n_quantiles=n_q, random_state=42)
    ae_transformer = QuantileTransformer(output_distribution='uniform', n_quantiles=n_q, random_state=42)

    if_transformer.fit(if_scores)
    svm_transformer.fit(svm_scores)
    ae_transformer.fit(ae_errors)

    transformers = {
        "if_transformer": if_transformer,
        "svm_transformer": svm_transformer,
        "ae_transformer": ae_transformer,
    }
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump(transformers, save_path)
    return transformers

def compute_ensemble_anomaly_score(iso, svm, ae, x_row, transformers):
    """Continuous 0-1 anomaly score = mean of the three quantile-ranked scores."""
    if_raw = np.array([[-iso.score_samples(x_row)[0]]])
    svm_raw = np.array([[-svm.decision_function(x_row)[0]]])
    reconstruction = ae.predict(x_row)
    ae_raw = np.array([[np.mean(np.square(x_row - reconstruction))]])

    if_norm = float(transformers["if_transformer"].transform(if_raw)[0][0])
    svm_norm = float(transformers["svm_transformer"].transform(svm_raw)[0][0])
    ae_norm = float(transformers["ae_transformer"].transform(ae_raw)[0][0])

    return (if_norm + svm_norm + ae_norm) / 3.0

def severity_from_score(anomaly_score):
    if anomaly_score > 0.90:
        return "Critical"
    elif anomaly_score > 0.75:
        return "High"
    elif anomaly_score > 0.55:
        return "Medium"
    else:
        return "Low"

def ae_predict(ae, threshold, X):
    reconstructions = ae.predict(X)
    errors = np.mean(np.square(X - reconstructions), axis=1)
    return (errors > threshold).astype(int), errors

def ensemble_vote(pred_if, pred_svm, pred_ae):
    votes = pred_if + pred_svm + pred_ae
    return (votes >= 2).astype(int)

def train_all_detectors(X_train_benign, models_dir='models'):
    os.makedirs(models_dir, exist_ok=True)
    
    iso = train_isolation_forest(X_train_benign)
    svm = train_one_class_svm(X_train_benign)
    ae, ae_thresh = train_autoencoder(X_train_benign)

    joblib.dump(iso, os.path.join(models_dir, 'isolation_forest.pkl'))
    joblib.dump(svm, os.path.join(models_dir, 'one_class_svm.pkl'))
    joblib.dump((ae, ae_thresh), os.path.join(models_dir, 'autoencoder.pkl'))

    return iso, svm, ae, ae_thresh

def load_all_detectors(models_dir='models'):
    iso = joblib.load(os.path.join(models_dir, 'isolation_forest.pkl'))
    svm = joblib.load(os.path.join(models_dir, 'one_class_svm.pkl'))
    ae, ae_thresh = joblib.load(os.path.join(models_dir, 'autoencoder.pkl'))
    transformers = joblib.load(os.path.join(models_dir, 'score_transformers.pkl'))
    return iso, svm, ae, ae_thresh, transformers

def predict_all(iso, svm, ae, ae_thresh, X):
    pred_if = (iso.predict(X) == -1).astype(int)
    pred_svm = (svm.predict(X) == -1).astype(int)
    pred_ae, ae_errors = ae_predict(ae, ae_thresh, X)
    final = ensemble_vote(pred_if, pred_svm, pred_ae)
    return final, pred_if, pred_svm, pred_ae
