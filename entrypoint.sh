#!/bin/bash
set -e

echo "=================================================================="
echo "🛡️ Starting Lightweight Explainable SIEM (Siem_light) Container..."
echo "=================================================================="

# Generate initial baseline alerts & train models if not already present
if [ ! -f "data/processed/alerts.csv" ] || [ ! -f "models/isolation_forest.pkl" ]; then
    echo "[Entrypoint] Initializing ML models & threat alerts pipeline (main.py)..."
    python main.py
else
    echo "[Entrypoint] Processed alerts & ML models found. Ready to launch."
fi

# Launch Streamlit SOC Dashboard
echo "[Entrypoint] Launching SOC Dashboard at http://0.0.0.0:8501..."
exec streamlit run dashboard/app.py \
    --server.port=8501 \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
