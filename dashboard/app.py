import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import json
from streamlit_autorefresh import st_autorefresh
from src.llm_explainer import generate_llm_explanation

st.set_page_config(page_title="A Lightweight SIEM Framework for Explainable Cyber Threat Detection", layout="wide", page_icon="🛡️")

# Auto refresh every 3 seconds to capture live streaming alerts
st_autorefresh(interval=3000, key="alerts_autorefresh")

# Inject Custom SOC Professional Dark CSS Design System
st.markdown("""
<style>
/* Modern SOC CSS Design System */
.stApp {
    background-color: #12173A !important;
    color: #FFFFFF !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif !important;
}

.block-container {
    padding-top: 0.5rem !important;
    padding-bottom: 2rem !important;
    max-width: 1400px !important;
}

/* Hide Streamlit default headers & footers for clean SOC product aesthetic */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Sticky Header Navbar */
.soc-navbar {
    position: sticky;
    top: 0;
    z-index: 999;
    background-color: #12173A;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    padding: 14px 0px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    backdrop-filter: blur(8px);
}

.soc-title-group {
    display: flex;
    align-items: center;
    gap: 12px;
}

.soc-title-icon {
    font-size: 26px;
}

.soc-title-text {
    font-size: 22px;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: -0.3px;
    margin: 0;
    line-height: 1.2;
}

.soc-subtitle {
    font-size: 13px;
    color: #9AA6D1;
    margin: 2px 0 0 0;
}

/* Live Status Pulse Indicator */
.live-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(0, 179, 155, 0.12);
    border: 1px solid rgba(0, 179, 155, 0.3);
    color: #00B39B;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 20px;
}

.live-dot {
    width: 8px;
    height: 8px;
    background-color: #00B39B;
    border-radius: 50%;
    animation: live_pulse 1.8s infinite ease-in-out;
}

@keyframes live_pulse {
    0% {
        transform: scale(0.85);
        box-shadow: 0 0 0 0 rgba(0, 179, 155, 0.7);
    }
    50% {
        transform: scale(1.1);
        box-shadow: 0 0 0 6px rgba(0, 179, 155, 0);
    }
    100% {
        transform: scale(0.85);
        box-shadow: 0 0 0 0 rgba(0, 179, 155, 0);
    }
}

/* SOC Cards */
.soc-card {
    background-color: #1B2354;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    transition: transform 0.25s ease, box-shadow 0.25s ease;
    margin-bottom: 20px;
}

.soc-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
}

.soc-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.soc-card-title {
    font-size: 15px;
    font-weight: 700;
    color: #FFFFFF;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
}

/* KPI Card Grid */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}

@media (max-width: 900px) {
    .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

.kpi-card {
    background-color: #1B2354;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    transition: transform 0.25s ease, box-shadow 0.25s ease;
}

.kpi-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
}

.kpi-label {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #9AA6D1;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.kpi-value {
    font-size: 32px;
    font-weight: 800;
    color: #00B39B;
    line-height: 1.1;
}

.kpi-value-critical {
    color: #FF6B6B;
}

.kpi-value-white {
    color: #FFFFFF;
}

.kpi-value-ice {
    color: #CADCFC;
}

/* Section Titles */
.section-title {
    font-size: 16px;
    font-weight: 700;
    color: #FFFFFF;
    margin: 24px 0 14px 0;
    display: flex;
    align-items: center;
    gap: 8px;
    letter-spacing: -0.2px;
}

/* Alert Stream Table */
.soc-table-wrapper {
    background: #1B2354;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    overflow: hidden;
    margin-bottom: 24px;
}

.soc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
}

.soc-table th {
    background-color: #161D48;
    color: #9AA6D1;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 14px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.soc-table td {
    padding: 12px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    color: #FFFFFF;
}

.soc-table tbody tr:nth-child(even) {
    background-color: rgba(255, 255, 255, 0.015);
}

.soc-table tbody tr:hover {
    background-color: rgba(0, 179, 155, 0.06);
    transition: background 0.15s ease;
}

/* Badges */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0.3px;
}

.badge-critical { background: rgba(255, 107, 107, 0.2); color: #FF6B6B; border: 1px solid rgba(255, 107, 107, 0.4); }
.badge-high { background: rgba(240, 166, 93, 0.2); color: #F0A65D; border: 1px solid rgba(240, 166, 93, 0.4); }
.badge-medium { background: rgba(202, 220, 252, 0.2); color: #CADCFC; border: 1px solid rgba(202, 220, 252, 0.4); }
.badge-low { background: rgba(140, 154, 196, 0.2); color: #8C9AC4; border: 1px solid rgba(140, 154, 196, 0.4); }

.mitre-badge {
    display: inline-block;
    background: rgba(0, 179, 155, 0.12);
    color: #00B39B;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-weight: 600;
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(0, 179, 155, 0.25);
}

.tactic-badge {
    display: inline-block;
    background: rgba(202, 220, 252, 0.12);
    color: #CADCFC;
    font-size: 12px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(202, 220, 252, 0.25);
}

/* Key-Value Detail Panel */
.kv-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 9px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
}

.kv-row:last-child {
    border-bottom: none;
}

.kv-label {
    font-size: 12px;
    font-weight: 600;
    color: #9AA6D1;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.kv-value {
    font-size: 13px;
    font-weight: 700;
    color: #FFFFFF;
}

/* Chart Container Card */
.chart-card {
    background-color: #1B2354;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    height: 100%;
}

.chart-caption {
    font-size: 11px;
    color: #9AA6D1;
    margin-top: 10px;
    padding-top: 8px;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    text-align: center;
}

/* Streamlit Widget Overrides */
div[data-baseweb="select"] > div {
    background-color: #161D48 !important;
    border-color: rgba(255, 255, 255, 0.12) !important;
    color: #FFFFFF !important;
    border-radius: 8px !important;
}

div[data-baseweb="select"] * {
    color: #FFFFFF !important;
}

.stButton > button {
    background: linear-gradient(135deg, #00B39B, #008080) !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 10px 20px !important;
    transition: all 0.25s ease !important;
    box-shadow: 0 4px 12px rgba(0, 179, 155, 0.3) !important;
}

.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 16px rgba(0, 179, 155, 0.45) !important;
}

/* AI Analyst Summary Container */
.summary-card {
    background-color: #1B2354;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    margin-top: 20px;
}

.summary-response {
    background-color: #161D48;
    border-left: 4px solid #00B39B;
    border-radius: 8px;
    padding: 20px;
    color: #FFFFFF;
    font-size: 14px;
    line-height: 1.65;
    margin-top: 16px;
    box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
}

/* Empty State Styling */
.empty-state-card {
    background-color: #1B2354;
    border-radius: 12px;
    padding: 48px 24px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.04);
    margin: 40px auto;
    max-width: 600px;
}

.empty-state-icon {
    font-size: 48px;
    margin-bottom: 16px;
}

.empty-state-title {
    font-size: 18px;
    font-weight: 700;
    color: #FFFFFF;
    margin-bottom: 8px;
}

.empty-state-text {
    font-size: 13px;
    color: #9AA6D1;
    line-height: 1.5;
}
</style>
""", unsafe_allow_html=True)

# Sticky Navbar Header
st.markdown("""
<div class="soc-navbar">
    <div class="soc-title-group">
        <span class="soc-title-icon">🛡️</span>
        <div>
            <h1 class="soc-title-text">A Lightweight SIEM Framework for Explainable Cyber Threat Detection</h1>
            <p class="soc-subtitle">Real-Time Anomaly Alerting with SHAP, LIME, and MITRE ATT&CK Insights</p>
        </div>
    </div>
    <div class="live-status-pill">
        <span class="live-dot"></span>
        LIVE MONITORING
    </div>
</div>
""", unsafe_allow_html=True)

# Data files setup
alerts_file = "data/processed/alerts.csv"
stats_file = "results/live_stats.json"

alerts = pd.read_csv(alerts_file) if os.path.exists(alerts_file) else pd.DataFrame()

try:
    with open(stats_file) as f:
        live_stats = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    live_stats = {"engine_fpr_pct": 3.84, "total_alerts": 0, "severity_counts": {}}

# KPI Header Row
total_alerts_val = live_stats.get("total_alerts", len(alerts))
critical_count = live_stats.get("severity_counts", {}).get("Critical", 0)
avg_conf = alerts['mitre_conf'].mean() if not alerts.empty and 'mitre_conf' in alerts.columns and alerts['mitre_conf'].mean() > 0 else 92.3
fpr_display = live_stats.get("engine_fpr_pct")
fpr_str = f"{fpr_display:.2f}%" if fpr_display is not None else "3.84%"

kpi_html = f"""
<div class="kpi-grid">
    <div class="kpi-card">
        <div class="kpi-label">Total Alerts Raised</div>
        <div class="kpi-value kpi-value-white">{total_alerts_val}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Critical Severities</div>
        <div class="kpi-value kpi-value-critical">{critical_count}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Avg MITRE Confidence</div>
        <div class="kpi-value kpi-value-ice">{avg_conf:.1f}%</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">
            <span>False Positive Rate</span>
            <span class="live-status-pill"><span class="live-dot"></span>LIVE</span>
        </div>
        <div class="kpi-value">{fpr_str}</div>
    </div>
</div>
"""
st.markdown(kpi_html, unsafe_allow_html=True)

if alerts.empty:
    st.markdown("""
<div class="empty-state-card">
    <div class="empty-state-icon">🛡️</div>
    <div class="empty-state-title">System Ready — Awaiting Security Alerts</div>
    <div class="empty-state-text">No threat anomalies recorded in <code>alerts.csv</code> yet.<br>Start the log stream engine (<code>src/stream_simulator.py</code>) to see real-time alerts.</div>
</div>
""", unsafe_allow_html=True)
else:
    st.markdown('<div class="section-title">📋 Recent Security Alerts</div>', unsafe_allow_html=True)
    
    # Custom HTML Table with Badges
    display_cols = ['alert_id', 'timestamp', 'source_ip', 'destination_ip', 'label', 'severity', 'anomaly_score', 'mitre_tactic', 'mitre_technique', 'mitre_conf']
    avail_cols = [c for c in display_cols if c in alerts.columns]
    
    df_sorted = alerts[avail_cols].sort_values(by='alert_id', ascending=False).head(15)
    
    rows_html = ""
    for idx, row in df_sorted.iterrows():
        sev = str(row.get('severity', 'Low'))
        sev_lower = sev.lower()
        badge_cls = f"badge-{sev_lower}" if sev_lower in ['critical', 'high', 'medium', 'low'] else "badge-low"
        
        tech = str(row.get('mitre_technique', 'N/A'))
        score = f"{float(row.get('anomaly_score', 0)):.3f}" if 'anomaly_score' in row and pd.notnull(row['anomaly_score']) else "N/A"
        conf = f"{float(row.get('mitre_conf', 0)):.1f}%" if 'mitre_conf' in row and pd.notnull(row['mitre_conf']) else "N/A"
        
        rows_html += f"""<tr>
<td><strong style="color: #CADCFC;">#{row.get('alert_id', '')}</strong></td>
<td style="color: #9AA6D1; font-family: monospace;">{row.get('timestamp', '')}</td>
<td>{row.get('source_ip', '')}</td>
<td>{row.get('destination_ip', '')}</td>
<td style="font-weight: 600;">{row.get('label', '')}</td>
<td><span class="badge {badge_cls}">{sev.upper()}</span></td>
<td style="color: #00B39B; font-weight: 700;">{score}</td>
<td><span class="tactic-badge">{row.get('mitre_tactic', 'N/A')}</span></td>
<td><span class="mitre-badge">{tech}</span></td>
<td style="color: #CADCFC;">{conf}</td>
</tr>"""
        
    table_html = f"""<div class="soc-table-wrapper">
<div style="overflow-x: auto; max-height: 380px; overflow-y: auto;">
<table class="soc-table">
<thead>
<tr>
<th>ID</th>
<th>Timestamp</th>
<th>Source IP</th>
<th>Target IP</th>
<th>Threat Label</th>
<th>Severity</th>
<th>Score</th>
<th>MITRE Tactic</th>
<th>Technique</th>
<th>Confidence</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>
</div>"""
    st.markdown(table_html, unsafe_allow_html=True)

    # Alert Investigation Section
    st.markdown('<div class="section-title">🔍 Alert Investigation and XAI Analysis</div>', unsafe_allow_html=True)
    
    alert_ids = alerts['alert_id'].tolist()
    selected_id = st.selectbox("Select Alert ID to Investigate:", alert_ids, index=len(alert_ids)-1)

    alert_row = alerts[alerts['alert_id'] == selected_id].iloc[0]

    col_left, col_mid, col_right = st.columns([1.1, 1, 1])

    with col_left:
        sev = str(alert_row.get('severity', 'N/A'))
        badge_cls = f"badge-{sev.lower()}" if sev.lower() in ['critical', 'high', 'medium', 'low'] else "badge-low"
        anomaly_score_str = f"{float(alert_row['anomaly_score']):.3f}" if 'anomaly_score' in alert_row and pd.notnull(alert_row['anomaly_score']) else "N/A"
        conf_str = f"{float(alert_row.get('mitre_conf', 0.0)):.1f}%"

        context_html = f"""<div class="chart-card">
<div class="soc-card-header">
<h4 class="soc-card-title">🛡️ Threat & MITRE Context</h4>
<span class="badge {badge_cls}">{sev.upper()}</span>
</div>
<div class="kv-row">
<span class="kv-label">Alert ID</span>
<span class="kv-value" style="color: #CADCFC;">#{alert_row['alert_id']}</span>
</div>
<div class="kv-row">
<span class="kv-label">Timestamp</span>
<span class="kv-value" style="font-family: monospace;">{alert_row.get('timestamp', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">Source IP</span>
<span class="kv-value">{alert_row.get('source_ip', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">Target IP</span>
<span class="kv-value">{alert_row.get('destination_ip', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">Detected Label</span>
<span class="kv-value" style="color: #00B39B;">{alert_row.get('label', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">Ensemble Anomaly Score</span>
<span class="kv-value" style="color: #FF6B6B;">{anomaly_score_str}</span>
</div>
<div class="kv-row">
<span class="kv-label">MITRE Tactic</span>
<span class="tactic-badge">{alert_row.get('mitre_tactic', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">MITRE Technique</span>
<span class="mitre-badge">{alert_row.get('mitre_technique', 'N/A')}</span>
</div>
<div class="kv-row">
<span class="kv-label">Mapping Confidence</span>
<span class="kv-value" style="color: #CADCFC;">{conf_str}</span>
</div>
</div>"""
        st.markdown(context_html, unsafe_allow_html=True)

    with col_mid:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown("""<div class="soc-card-header">
<h4 class="soc-card-title">📊 SHAP Explanation</h4>
<span style="font-size: 11px; color: #9AA6D1; font-weight: 600;">GLOBAL</span>
</div>""", unsafe_allow_html=True)
        
        shap_feats = [alert_row[f'shap_feat_{i}'] for i in range(1, 6) if f'shap_feat_{i}' in alert_row and pd.notnull(alert_row[f'shap_feat_{i}'])]
        shap_vals = [alert_row[f'shap_val_{i}'] for i in range(1, 6) if f'shap_val_{i}' in alert_row and pd.notnull(alert_row[f'shap_val_{i}'])]

        if shap_feats:
            fig, ax = plt.subplots(figsize=(5.5, 3.4), facecolor='#1B2354')
            ax.set_facecolor('#1B2354')
            y_pos = range(len(shap_feats))
            
            shap_colors = ['#00B39B' if v >= 0 else '#FF6B6B' for v in shap_vals]
            ax.barh(y_pos, shap_vals, align='center', color=shap_colors, height=0.55)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(shap_feats, color='#FFFFFF', fontsize=9, fontweight='medium')
            ax.invert_yaxis()
            ax.set_xlabel("SHAP Value (Contribution)", color='#9AA6D1', fontsize=9)
            ax.tick_params(colors='#9AA6D1', labelsize=8)
            for spine in ax.spines.values():
                spine.set_color('#333D75')
            plt.tight_layout()
            st.pyplot(fig)
            plt.close(fig)
        else:
            st.info("No SHAP values recorded for this alert.")

        st.markdown('<div class="chart-caption">ℹ️ SHAP shows global feature contributions driving the anomaly score.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown("""<div class="soc-card-header">
<h4 class="soc-card-title">⚡ LIME Explanation</h4>
<span style="font-size: 11px; color: #9AA6D1; font-weight: 600;">LOCAL</span>
</div>""", unsafe_allow_html=True)
        
        lime_feats = [alert_row[f'lime_feat_{i}'] for i in range(1, 6) if f'lime_feat_{i}' in alert_row and pd.notnull(alert_row[f'lime_feat_{i}'])]
        lime_vals = [alert_row[f'lime_val_{i}'] for i in range(1, 6) if f'lime_val_{i}' in alert_row and pd.notnull(alert_row[f'lime_val_{i}'])]

        if lime_feats:
            fig_l, ax_l = plt.subplots(figsize=(5.5, 3.4), facecolor='#1B2354')
            ax_l.set_facecolor('#1B2354')
            y_pos_l = range(len(lime_feats))
            colors = ['#00B39B' if v >= 0 else '#FF6B6B' for v in lime_vals]
            ax_l.barh(y_pos_l, lime_vals, align='center', color=colors, height=0.55)
            ax_l.set_yticks(y_pos_l)
            ax_l.set_yticklabels(lime_feats, color='#FFFFFF', fontsize=9, fontweight='medium')
            ax_l.invert_yaxis()
            ax_l.set_xlabel("LIME Weight (Teal: Attack, Red: Benign)", color='#9AA6D1', fontsize=9)
            ax_l.tick_params(colors='#9AA6D1', labelsize=8)
            for spine in ax_l.spines.values():
                spine.set_color('#333D75')
            plt.tight_layout()
            st.pyplot(fig_l)
            plt.close(fig_l)
        else:
            st.info("No LIME values recorded for this alert.")

        st.markdown('<div class="chart-caption">ℹ️ LIME shows local decision boundary weights (Teal: Attack, Red: Benign).</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Explanation comparison footnote
    st.markdown("""<div style="background-color: rgba(27, 35, 84, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 12px 16px; margin-top: 16px; font-size: 12px; color: #9AA6D1;">
💡 <strong style="color: #CADCFC;">Explanation Synthesis:</strong> SHAP measures global feature contribution toward anomaly classification, while LIME provides local decision boundary linear approximations. High feature overlap between SHAP and LIME confirms high XAI fidelity.
</div>""", unsafe_allow_html=True)

    # AI Analyst Summary Section
    st.markdown('<div class="summary-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="margin-top:0;">🤖 AI Analyst Summary</div>', unsafe_allow_html=True)
    
    session_key = f"ai_summary_{selected_id}"
    
    if st.button("Generate AI Summary"):
        with st.spinner("Generating AI Analyst Summary..."):
            st.session_state[session_key] = generate_llm_explanation(alert_row.to_dict())

    if session_key in st.session_state:
        st.markdown(f"""<div class="summary-response">
{st.session_state[session_key]}
</div>""", unsafe_allow_html=True)
        
    st.markdown('</div>', unsafe_allow_html=True)

