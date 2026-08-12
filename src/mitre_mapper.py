import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Simplified rule table mapping known flow signatures to MITRE ATT&CK TTPs
MITRE_RULES = {
    "DoS Hulk":         {"tactic": "TA0040 Impact", "technique": "T1498.001", "conf": 94.0},
    "DoS GoldenEye":    {"tactic": "TA0040 Impact", "technique": "T1498/T1499", "conf": 93.5},
    "DoS Slowloris":    {"tactic": "TA0040 Impact", "technique": "T1499", "conf": 91.2},
    "DoS Slowhttptest": {"tactic": "TA0040 Impact", "technique": "T1499", "conf": 90.8},
    "Hulk":             {"tactic": "TA0040 Impact", "technique": "T1498.001", "conf": 94.0},
    "GoldenEye":        {"tactic": "TA0040 Impact", "technique": "T1498/T1499", "conf": 93.5},
    "Slowloris":        {"tactic": "TA0040 Impact", "technique": "T1499", "conf": 91.2},
    "Slowhttptest":     {"tactic": "TA0040 Impact", "technique": "T1499", "conf": 90.8},
}

def map_to_mitre(attack_label):
    """Rule-based lookup — the fast path."""
    return MITRE_RULES.get(attack_label, None)

class MITREClassifierFallback:
    """Random Forest fallback for alerts when no rule match is found."""
    def __init__(self):
        self.rf = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_fitted = False
        self.class_names = []

    def fit(self, X_attack_train, y_attack_labels):
        if len(X_attack_train) > 0 and len(np.unique(y_attack_labels)) > 0:
            self.rf.fit(X_attack_train, y_attack_labels)
            self.class_names = list(self.rf.classes_)
            self.is_fitted = True

    def predict(self, feature_vector):
        if not self.is_fitted:
            return {"tactic": "TA0040 Impact", "technique": "T1499 - Generic Anomaly", "conf": 75.0}
        
        proba = self.rf.predict_proba(feature_vector.reshape(1, -1))[0]
        max_idx = np.argmax(proba)
        pred_label = self.class_names[max_idx]
        conf = float(proba[max_idx] * 100)
        
        rule_meta = map_to_mitre(pred_label)
        if rule_meta:
            return {"tactic": rule_meta["tactic"], "technique": rule_meta["technique"], "conf": conf}
        else:
            return {"tactic": "TA0040 Impact", "technique": "T1499", "conf": conf}

def map_alert_to_mitre(attack_label, feature_vector=None, fallback_classifier=None):
    """
    Combines rule-based fast-path lookup with Random Forest ML fallback.
    """
    rule_match = map_to_mitre(attack_label)
    if rule_match:
        return rule_match
    
    if fallback_classifier and feature_vector is not None:
        return fallback_classifier.predict(feature_vector)
    
    return {"tactic": "TA0040 Impact", "technique": "T1499 - Denial of Service", "conf": 85.0}
