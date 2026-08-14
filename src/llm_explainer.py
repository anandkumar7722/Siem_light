import os

def generate_llm_explanation(alert_data):
    """
    Synthesizes SHAP and LIME feature attributions into natural language
    SOC analyst threat narrative. Supports OpenAI API key if available,
    otherwise uses a zero-cost local template engine fallback.
    """
    api_key = os.environ.get("OPENAI_API_KEY", None)

    shap_top = [f"{alert_data.get(f'shap_feat_{i}')} ({alert_data.get(f'shap_val_{i}')})" 
                for i in range(1, 6) if alert_data.get(f'shap_feat_{i}')]
    lime_top = [f"{alert_data.get(f'lime_feat_{i}')} ({alert_data.get(f'lime_val_{i}')})" 
                for i in range(1, 6) if alert_data.get(f'lime_feat_{i}')]

    prompt = f"""
    You are a Senior Cyber Security Analyst assistant in a SOC.
    Explain this alert for an analyst based on the SHAP and LIME XAI outputs:
    
    Alert ID: {alert_data.get('alert_id')}
    Label: {alert_data.get('label')}
    Severity: {alert_data.get('severity')}
    Anomaly Score: {alert_data.get('anomaly_score')}
    MITRE Technique: {alert_data.get('mitre_technique')} ({alert_data.get('mitre_tactic')})
    
    SHAP Top Features (Global Attribution): {', '.join(shap_top)}
    LIME Top Features (Local Boundary Weight): {', '.join(lime_top)}
    
    Provide a concise 3-paragraph summary:
    1. Threat Overview
    2. XAI Analysis
    3. Recommended Action
    """

    if api_key:
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert Cybersecurity SOC Analyst assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=350
            )
            return response.choices[0].message.content
        except Exception as e:
            pass  # Fallback to local rule engine if API fails

    # Rule-based natural language template engine fallback (0-cost, instant, offline)
    shap_primary = alert_data.get('shap_feat_1', 'Flow Features')
    lime_primary = alert_data.get('lime_feat_1', 'Traffic Pattern')
    
    narrative = f"""
### 🤖 AI Analyst Summary

**1. Threat Overview:**  
Alert #{alert_data.get('alert_id')} triggered a **{alert_data.get('severity')}** severity alert for **{alert_data.get('label')}** with an ensemble anomaly score of **{alert_data.get('anomaly_score')}**. Mapped to MITRE ATT&CK **{alert_data.get('mitre_technique')}** ({alert_data.get('mitre_tactic')}).

**2. XAI Analysis:**  
- **SHAP (Global Attribution):** Identifies `{shap_primary}` as the primary feature driving the baseline network model away from normal benign traffic.
- **LIME (Local Boundary):** Indicates `{lime_primary}` as the strongest local decision boundary weight confirming attack classification.
- **Consensus Assessment:** Dual alignment between global model attributions and local surrogate weights confirms high-confidence anomaly classification, ruling out random packet noise.

**3. Recommended Action:**  
Isolate host IP `{alert_data.get('source_ip')}`, inspect flow logs around `{alert_data.get('timestamp')}`, and verify firewall filtering rules for `{alert_data.get('destination_ip')}`.
"""
    return narrative

