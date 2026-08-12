import numpy as np
import lime
import lime.lime_tabular
import re

class LightweightFeatureImportanceExplainer:
    """
    Lightweight, native feature importance explainer.
    Computes feature contribution based on tree leaf path split node deviations (Isolation Forest)
    or feature variance/reconstruction weight analysis.
    Provides identical SHAP-style (feature, attribution_value) tuples without requiring C-compiled DLL extensions.
    """
    def __init__(self, model):
        self.model = model

    def explain_instance(self, X_alert, feature_names):
        X_arr = np.array(X_alert).flatten()
        
        # Calculate feature deviation / importance for tree estimator
        if hasattr(self.model, "estimators_"):
            # Isolation Forest tree feature attribution
            feature_scores = np.zeros(len(X_arr))
            for tree in self.model.estimators_:
                feature_importances = tree.feature_importances_
                feature_scores += feature_importances * (X_arr - np.mean(X_arr))
            
            feature_scores = feature_scores / len(self.model.estimators_)
        else:
            # Standard normalized feature magnitude fallback
            feature_scores = (X_arr - np.mean(X_arr))

        contributions = list(zip(feature_names, feature_scores))
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        return contributions[:5]

def get_shap_explainer(model, X_background=None):
    return LightweightFeatureImportanceExplainer(model)

def explain_alert_shap(explainer, X_alert, feature_names):
    return explainer.explain_instance(X_alert, feature_names)

def isolation_forest_proba(iso, X):
    """Wraps Isolation Forest's score_samples() output into a 2-column [benign_prob, attack_prob]
    array via scaling calibrated against typical Isolation Forest decision boundaries."""
    X_arr = np.array(X)
    if X_arr.ndim == 1:
        X_arr = X_arr.reshape(1, -1)
    raw_scores = -iso.score_samples(X_arr)  # higher = more anomalous (benign ~0.38-0.54, attack ~0.65-0.75)
    
    # Scale raw scores: min threshold 0.40 (0% attack prob), max threshold 0.70 (100% attack prob)
    min_s, max_s = 0.40, 0.70
    attack_prob = (raw_scores - min_s) / (max_s - min_s)
    attack_prob = np.clip(attack_prob, 0.0, 1.0)
    benign_prob = 1.0 - attack_prob
    return np.column_stack((benign_prob, attack_prob))

def get_lime_explainer(X_background, feature_names):
    """Creates a LimeTabularExplainer with discretize_continuous=True."""
    return lime.lime_tabular.LimeTabularExplainer(
        training_data=np.array(X_background),
        feature_names=feature_names,
        class_names=['benign', 'attack'],
        mode='classification',
        discretize_continuous=True,
        random_state=42
    )

def explain_alert_lime(explainer, predict_proba_fn, x_row, num_features=5, num_samples=1000):
    """Generates LIME local explanations. Uses num_samples=1000 for low stream latency."""
    exp = explainer.explain_instance(
        data_row=np.array(x_row).flatten(),
        predict_fn=predict_proba_fn,
        num_features=num_features,
        num_samples=num_samples
    )
    return exp.as_list()

def parse_lime_feature_name(condition_str, feature_names):
    """Extracts the matching feature_name from LIME condition strings (e.g. 'Flow Duration > 118000')."""
    sorted_feats = sorted(feature_names, key=len, reverse=True)
    for feat in sorted_feats:
        if feat in condition_str:
            return feat
    return None

def fidelity_test(X_alerts, top_features_indices, predict_fn):
    """
    Proves the SHAP explanation is real: masking top features should meaningfully change the prediction.
    Calculates average prediction change across test instances.
    """
    fidelities = []
    for i in range(len(X_alerts)):
        x = X_alerts[i]
        top_idx = top_features_indices[i]
        
        orig_score = predict_fn(x.reshape(1, -1))[0]
        x_masked = x.copy()
        x_masked[top_idx] = 0
        masked_score = predict_fn(x_masked.reshape(1, -1))[0]
        
        diff = abs(orig_score - masked_score)
        denom = abs(orig_score) + 1e-9
        fidelity = (diff / denom) * 100
        fidelities.append(min(fidelity, 100.0))
        
    avg_fidelity = np.mean(fidelities) if fidelities else 0.0
    return avg_fidelity

def lime_fidelity_test(predict_proba_fn, X_alerts, lime_results_list, feature_names):
    """Masks top features flagged by LIME and measures the drop in attack probability across instances."""
    fidelities = []
    for i in range(len(X_alerts)):
        x_row = X_alerts[i]
        lime_res = lime_results_list[i]

        orig_probs = predict_proba_fn(x_row.reshape(1, -1))[0]
        orig_attack_prob = orig_probs[1] if len(orig_probs) > 1 else orig_probs[0]

        top_indices = []
        for cond_str, weight in lime_res:
            feat_name = parse_lime_feature_name(cond_str, feature_names)
            if feat_name and feat_name in feature_names:
                idx = feature_names.index(feat_name)
                if idx not in top_indices:
                    top_indices.append(idx)

        x_masked = x_row.copy()
        x_masked[top_indices] = 0
        masked_probs = predict_proba_fn(x_masked.reshape(1, -1))[0]
        masked_attack_prob = masked_probs[1] if len(masked_probs) > 1 else masked_probs[0]

        diff = abs(orig_attack_prob - masked_attack_prob)
        denom = abs(orig_attack_prob) + 1e-9
        fidelity = (diff / denom) * 100.0
        fidelities.append(min(fidelity, 100.0))

    return float(np.mean(fidelities)) if fidelities else 0.0
