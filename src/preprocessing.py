import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

def load_and_clean(filepath):
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()  # Clean leading/trailing spaces in headers (typical in CICIDS2017)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df

def get_feature_columns(df):
    drop_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label']
    feature_cols = [c for c in df.columns if c not in drop_cols]
    return feature_cols

def build_scaler(monday_path, save_path='models/scaler.pkl'):
    """Fit the scaler ONLY on benign Monday data — prevents data leakage, matches paper."""
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    df_benign = load_and_clean(monday_path)
    feature_cols = get_feature_columns(df_benign)
    scaler = StandardScaler()
    scaler.fit(df_benign[feature_cols])
    joblib.dump((scaler, feature_cols), save_path)
    return scaler, feature_cols

def prepare_dataset(wednesday_path, scaler_path='models/scaler.pkl'):
    scaler, feature_cols = joblib.load(scaler_path)
    df = load_and_clean(wednesday_path)
    X = scaler.transform(df[feature_cols])
    y = (df['Label'] != 'BENIGN').astype(int).values   # 1 = attack, 0 = benign
    return X, y, df

def generate_mock_datasets(monday_path='data/raw/Monday-WorkingHours.pcap_ISCX.csv',
                           wednesday_path='data/raw/Wednesday-workingHours.pcap_ISCX.csv',
                           num_samples=2000):
    """Generates synthetic mock datasets matching CICIDS2017 format for instant pipeline testing."""
    os.makedirs(os.path.dirname(monday_path), exist_ok=True)
    os.makedirs(os.path.dirname(wednesday_path), exist_ok=True)

    feature_names = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean"
    ]
    meta_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label']
    all_cols = meta_cols + feature_names

    np.random.seed(42)
    
    # Monday dataset (100% Benign)
    monday_data = []
    for i in range(num_samples):
        row = [f"FLOW_{i}", "192.168.1.10", "192.168.1.50", "2026-07-27 09:00:00", "BENIGN"]
        feats = np.random.normal(loc=10.0, scale=2.0, size=len(feature_names)).tolist()
        monday_data.append(row + feats)
    
    df_monday = pd.DataFrame(monday_data, columns=all_cols)
    df_monday.to_csv(monday_path, index=False)

    # Wednesday dataset (80% Benign, 20% DoS variants)
    attack_types = ["DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest"]
    wednesday_data = []
    for i in range(num_samples):
        is_attack = np.random.rand() < 0.20
        if is_attack:
            label = np.random.choice(attack_types)
            row = [f"FLOW_WED_{i}", "172.16.0.1", "192.168.1.50", "2026-07-27 10:00:00", label]
            # Anomalous feature distribution
            feats = np.random.normal(loc=50.0, scale=15.0, size=len(feature_names)).tolist()
        else:
            label = "BENIGN"
            row = [f"FLOW_WED_{i}", "192.168.1.12", "192.168.1.50", "2026-07-27 10:00:00", label]
            feats = np.random.normal(loc=10.0, scale=2.0, size=len(feature_names)).tolist()
        wednesday_data.append(row + feats)

    df_wednesday = pd.DataFrame(wednesday_data, columns=all_cols)
    df_wednesday.to_csv(wednesday_path, index=False)
    print(f"Generated mock datasets at {monday_path} and {wednesday_path}")
