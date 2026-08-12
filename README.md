# 🛡️ Lightweight Explainable SIEM (Siem_light)

A lightweight, CPU-efficient, explainable Security Information and Event Management (SIEM) framework featuring real-time anomaly detection, Dual-XAI (SHAP + LIME) feature attribution, MITRE ATT&CK mapping, LLM Analyst Copilot synthesis, and a professional SOC dark-theme dashboard.

---

## 🌟 Key Features

- **Lightweight Anomaly Detection Ensemble**: Combines Isolation Forest, One-Class SVM, and Autoencoder models using majority voting to detect network anomalies with high precision and low false-positive rates (FPR).
- **Dual-XAI Feature Attribution**: Provides global feature importance via **SHAP** and local decision boundary explanations via **LIME**.
- **MITRE ATT&CK Automated Mapping**: Maps threat detections to specific tactics (e.g., *Impact*) and techniques (e.g., `T1498`, `T1499`) with mapping confidence scores.
- **LLM Analyst Copilot**: Synthesizes complex SHAP and LIME feature attributions into natural-language incident reports using LLM (GPT) insights.
- **Professional SOC Product Dashboard**: 100% Streamlit-native UI styled with CSS injection into a Datadog/Grafana deep navy aesthetic (`#12173A`), live FPR pulsing indicators, pill severity badges, and dark Matplotlib charts.
- **Minimal Dependencies & CPU-Only Execution**: Designed to run seamlessly on lightweight CPU environments without requiring GPU acceleration.

---

## 📋 Prerequisites

- **Python**: Version `3.9`, `3.10`, or `3.11` recommended.
- **Git**: Installed on your operating system.
- **Operating System**: Windows, macOS, or Linux.

---

## 🚀 Step-by-Step Instructions

### Step 1: Clone the Repository
Open your terminal / PowerShell and clone the project:

```bash
git clone https://github.com/anandkumar7722/Siem_light.git
cd Siem_light
```

---

### Step 2: Set Up a Virtual Environment (Recommended)

Create and activate a isolated Python virtual environment:

#### **On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### **On macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3: Install Required Dependencies

Install all core dependencies specified in `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 4: Run the Main Detection & Explanation Pipeline

Run the primary offline pipeline (`main.py`). This script will:
1. Generate or load synthetic CICIDS2017 flow datasets.
2. Train the ensemble detectors (Isolation Forest, One-Class SVM, Autoencoder).
3. Compute SHAP explanations and MITRE ATT&CK mappings.
4. Output evaluated alerts to `data/processed/alerts.csv`.

```bash
python main.py
```

---

### Step 5: Launch the Professional SOC Streamlit Dashboard

Launch the interactive Streamlit dashboard to monitor live security stream alerts, investigate dual-XAI charts, and generate LLM Copilot reports:

```bash
streamlit run dashboard/app.py
```

After executing the command, open your browser at `http://localhost:8501`.

---

### Step 6: (Optional) Run the Real-Time Stream Simulator

To simulate live streaming network logs into the dashboard in real-time:

Open a separate terminal window (keep the Streamlit dashboard running in the first terminal) and execute:

```bash
python -m src.stream_simulator
```

This updates `results/live_stats.json` and appends streaming alerts to `data/processed/alerts.csv` every few seconds, triggering automatic UI refreshes in the dashboard.

---

## 🔬 Benchmark & Evaluation Scripts

You can run additional evaluation and ablation modules included in `src/`:

- **Cross Validation**:
  ```bash
  python -m src.cross_validation
  ```
- **Ablation Study**:
  ```bash
  python -m src.ablation_study
  ```
- **Fidelity Evaluation**:
  ```bash
  python -m src.fidelity_evaluation
  ```

---

## 📁 Directory Structure

```
Siem_light/
├── dashboard/
│   └── app.py                     # Streamlit SOC Professional Dashboard UI
├── data/
│   ├── processed/
│   │   └── alerts.csv             # Processed security alerts & XAI outputs
│   └── raw/                       # Raw CICIDS flow CSV datasets
├── models/                        # Saved detector models & scalers
├── results/                       # Performance metrics & live stats JSON
├── src/
│   ├── ablation_study.py          # Module ablation experiment runner
│   ├── benchmark.py               # Resource monitoring utilities
│   ├── cross_validation.py        # K-fold evaluation pipeline
│   ├── detectors.py               # Ensemble ML models (IF, SVM, Autoencoder)
│   ├── evaluate.py                # Detection performance metrics
│   ├── explainability.py          # SHAP & LIME XAI explanation engines
│   ├── fidelity_evaluation.py     # Explanation fidelity test suite
│   ├── llm_explainer.py           # LLM Analyst Copilot integration
│   ├── mitre_mapper.py            # MITRE ATT&CK tactic/technique mapping
│   ├── preprocessing.py           # Data normalization & scaler logic
│   ├── resource_monitor.py        # Memory and latency benchmarks
│   └── stream_simulator.py        # Real-time event streaming engine
├── main.py                        # Pipeline entrypoint
├── requirements.txt               # Dependencies listing
└── README.md                      # Project documentation
```

---

## 📜 License

This project is licensed under the MIT License.
