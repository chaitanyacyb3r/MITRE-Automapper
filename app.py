import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from fpdf import FPDF
import base64
import os
import tempfile
import time
import random

from src.mapper import MitreMapper
from src.cve_fetcher import get_cve_details
from src.static_analyzer import StaticAnalyzer
from src.ml_classifier import MalwareClassifier
from src.agent_alerts import RansomGuard

# 1. Custom CSS Theme & Page Setup
st.set_page_config(page_title="Malware Analysis & Threat Attribution", page_icon="🛡️", layout="wide")

# Inject Custom Google Font and Dark/Cyberpunk Theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Sleek card layouts */
    .custom-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }
    
    /* Metrics display */
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #00E5FF;
        line-height: 1.2;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Alert banner styling */
    .critical-alert {
        background-color: rgba(220, 38, 38, 0.2);
        border: 2px solid #dc2626;
        border-radius: 8px;
        padding: 15px;
        color: #fca5a5;
        font-weight: 600;
        text-align: center;
        margin-top: 15px;
        margin-bottom: 15px;
        animation: pulse-glow 2s infinite;
    }
    
    @keyframes pulse-glow {
        0% { box-shadow: 0 0 5px rgba(220, 38, 38, 0.4); }
        50% { box-shadow: 0 0 20px rgba(220, 38, 38, 0.8); }
        100% { box-shadow: 0 0 5px rgba(220, 38, 38, 0.4); }
    }
    
    /* Sub-headers */
    .section-title {
        color: #f3f4f6;
        border-left: 4px solid #00E5FF;
        padding-left: 10px;
        margin-top: 20px;
        margin-bottom: 15px;
    }
</style>
""", unsafe_allow_html=True)

# 2. Caching resource models
@st.cache_resource
def get_mapper():
    return MitreMapper()

@st.cache_resource
def get_classifier():
    clf = MalwareClassifier()
    # Try loading saved model first; if that fails, train from scratch
    if not clf.load_model():
        clf.train()
    return clf

@st.cache_resource
def get_analyzer():
    return StaticAnalyzer()

# 3. PDF Generator Function
def generate_pdf_report(static_res=None, cve_res=None, alerts_res=None, ml_res=None):
    pdf = FPDF()
    pdf.add_page()
    
    # Title Page / Header
    pdf.set_text_color(0, 100, 150)
    pdf.set_font("Arial", 'B', 18)
    pdf.cell(200, 10, txt="Malware Analysis & Threat Attribution Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(200, 7, txt="NFSU Cyber Security Dissertation Project - SOC Forensic Output", ln=True, align='C')
    pdf.ln(10)
    
    # Student Info block
    pdf.set_draw_color(200, 200, 200)
    pdf.rect(10, 27, 190, 22)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", 'B', 10)
    pdf.text(12, 33, "Submitted By: Nenavath Pooja (101CTBMCS2122027)")
    pdf.text(12, 39, "Degree: B Tech-M Tech Integrated (Cyber Security)")
    pdf.text(12, 45, "Institution: National Forensic Sciences University, Gandhinagar")
    pdf.ln(20)
    
    # 1. Static Analysis Section
    if static_res:
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0, 100, 150)
        pdf.cell(200, 10, txt="1. Static Analysis Results", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(200, 6, txt=f"File Name: {static_res['file_name']}", ln=True)
        pdf.cell(200, 6, txt=f"File Size: {static_res['file_size']} Bytes", ln=True)
        pdf.cell(200, 6, txt=f"MD5 Hash: {static_res['md5']}", ln=True)
        pdf.cell(200, 6, txt=f"SHA-256: {static_res['sha256']}", ln=True)
        pdf.cell(200, 6, txt=f"Shannon Entropy: {static_res['entropy']} (Scale 0-8)", ln=True)
        pdf.cell(200, 6, txt=f"Threat Score: {static_res['threat_score']}/10.0 (Classification: {static_res['classification']})", ln=True)
        pdf.ln(4)
        
        # Mapped MITRE techniques
        if static_res.get("mapped_techniques"):
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 8, txt="Mapped MITRE ATT&CK Techniques:", ln=True)
            pdf.set_font("Arial", size=9)
            for tech in static_res["mapped_techniques"]:
                safe_name = tech['name'].encode('latin-1', 'replace').decode('latin-1')
                safe_reason = tech['reason'].encode('latin-1', 'replace').decode('latin-1')
                pdf.cell(200, 6, txt=f"- [{tech['id']}] {safe_name} (Tactic: {tech['tactic']}, Severity: {tech['severity']})", ln=True)
                pdf.multi_cell(0, 5, txt=f"  Reason: {safe_reason}")
                pdf.ln(2)
        pdf.ln(5)
        
    # 2. CVE Lookup Section
    if cve_res:
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0, 100, 150)
        pdf.cell(200, 10, txt="2. CVE & Vulnerability Mapping", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(200, 6, txt=f"CVE ID: {cve_res['id']}", ln=True)
        pdf.cell(200, 6, txt=f"CVSS Score: {cve_res['cvss']}", ln=True)
        pdf.cell(200, 6, txt=f"Published Date: {cve_res['published']}", ln=True)
        safe_desc = cve_res['description'].encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 5, txt=f"Description: {safe_desc}")
        
        if cve_res.get("mapped_techniques"):
            pdf.ln(4)
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 8, txt="BERT Predicted MITRE Techniques:", ln=True)
            pdf.set_font("Arial", size=9)
            for tech in cve_res["mapped_techniques"]:
                safe_tname = tech['name'].encode('latin-1', 'replace').decode('latin-1')
                pdf.cell(200, 6, txt=f"- [{tech['id']}] {safe_tname} ({tech['score']}% Confidence)", ln=True)
        pdf.ln(5)
        
    # 3. Agent Alerts Section
    if alerts_res:
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0, 100, 150)
        pdf.cell(200, 10, txt="3. RansomGuard Heuristic Monitoring", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(200, 6, txt=f"Total monitored events: {len(alerts_res)}", ln=True)
        max_rate = max([a.get("Rate (mod/sec)", 0) for a in alerts_res]) if alerts_res else 0
        pdf.cell(200, 6, txt=f"Peak modification rate: {max_rate} modifications/sec", ln=True)
        
        # Check if ransomware detected
        if max_rate > 5:
            pdf.set_font("Arial", 'B', 10)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(200, 7, txt=">>> CRITICAL WARNING: Ransomware active file encryption behavior detected!", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=9)
            
        pdf.ln(3)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(40, 6, "Timestamp", 1)
        pdf.cell(60, 6, "Event Type", 1)
        pdf.cell(50, 6, "Target File", 1)
        pdf.cell(40, 6, "Entropy", 1)
        pdf.ln()
        pdf.set_font("Arial", size=9)
        for a in alerts_res[-10:]: # Print last 10 events
            safe_file = a['File Name'].encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(40, 6, a['Timestamp'], 1)
            pdf.cell(60, 6, a['Event'], 1)
            pdf.cell(50, 6, safe_file, 1)
            pdf.cell(40, 6, str(a['Entropy']), 1)
            pdf.ln()
        pdf.ln(5)

    # 4. ML Classifier Section
    if ml_res:
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(0, 100, 150)
        pdf.cell(200, 10, txt="4. Machine Learning Classification Profile", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(200, 6, txt=f"Classifier Type: Random Forest Classifier (100 estimators)", ln=True)
        pdf.cell(200, 6, txt=f"Training Accuracy: {ml_res.get('accuracy', '65')}%", ln=True)
        
        if ml_res.get("prediction"):
            pdf.ln(3)
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 8, txt="Latest File Prediction Result:", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(200, 6, txt=f"Predicted Class: {ml_res['prediction']['predicted_family']}", ln=True)
            pdf.cell(200, 6, txt=f"Confidence: {ml_res['prediction']['confidence']}%", ln=True)
            
    pdf_bytes = pdf.output(dest='S')
    if isinstance(pdf_bytes, str):
        pdf_bytes = pdf_bytes.encode('latin-1')
    return pdf_bytes

# 4. Main UI Flow
def main():
    # Header Banner
    col_logo, col_title = st.columns([1, 6])
    with col_logo:
        # Display a lock emoji shield representing NFSU Cyber Security project
        st.markdown("<h1 style='text-align: center; font-size: 5rem;'>🛡️</h1>", unsafe_allow_html=True)
    with col_title:
        st.markdown("<h1 style='margin-bottom:0;'>Malware Analysis & Threat Attribution</h1>", unsafe_allow_html=True)
        st.markdown("<p style='font-size:1.15rem; color:#9ca3af; margin-top:0;'><b>NFSU major project</b>: Unified static analysis, dynamic RansomGuard tracking, Random Forest classification, and BERT threat mapping.</p>", unsafe_allow_html=True)
    
    # Initialize state variables
    if "static_result" not in st.session_state:
        st.session_state.static_result = None
    if "cve_result" not in st.session_state:
        st.session_state.cve_result = None
    if "alerts_list" not in st.session_state:
        st.session_state.alerts_list = []
    if "ml_result" not in st.session_state:
        st.session_state.ml_result = None
        
    # Instantiate modules
    mapper = get_mapper()
    analyzer = get_analyzer()
    classifier = get_classifier()
    
    # 5 Tab layout
    tab_static, tab_cve, tab_alerts, tab_ml, tab_report = st.tabs([
        "📁 Static Analysis",
        "🔍 CVE Lookup",
        "🚨 Agent Alerts",
        "📊 ML Classifier",
        "📄 Report Generator"
    ])
    
    # ------------------ TAB 1: STATIC ANALYSIS ------------------
    with tab_static:
        st.markdown("<h3 class='section-title'>Portable Executable (PE) Analyzer</h3>", unsafe_allow_html=True)
        st.write("Upload a suspicious `.exe`, `.dll`, or document for entropy, hash extraction, and MITRE mapping.")
        
        uploaded_file = st.file_uploader("Choose a file for static scan", type=["exe", "dll", "txt", "pdf", "py"])
        
        if uploaded_file is not None:
            # Save uploaded file temporarily (preserve extension for PE detection)
            file_ext = os.path.splitext(uploaded_file.name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_path = tmp_file.name
                
            if st.button("Run Static Analysis"):
                with st.spinner("Analyzing binary headers and hashes..."):
                    try:
                        res = analyzer.analyze_file(tmp_path)
                        res["file_name"] = uploaded_file.name # restore correct filename
                        st.session_state.static_result = res
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass
                
        # Display results if available
        if st.session_state.static_result:
            res = st.session_state.static_result
            
            # Left/Right columns for metrics & Gauge
            col_left, col_right = st.columns([3, 2])
            
            with col_left:
                st.markdown("<h4 style='color:#00E5FF;'>🔍 General Metadata</h4>", unsafe_allow_html=True)
                
                # HTML Metric cards
                st.markdown(f"""
                <div style="display: flex; gap: 15px; margin-bottom: 15px;">
                    <div class="custom-card" style="flex: 1; text-align: center; margin-bottom: 0;">
                        <div class="metric-label">Shannon Entropy</div>
                        <div class="metric-value">{res['entropy']}</div>
                        <div style="font-size: 0.8rem; color: #9ca3af; margin-top:5px;">
                            { "Encrypted/Packed" if res['entropy'] > 7.0 else ("Compressed" if res['entropy'] > 6.0 else "Normal") }
                        </div>
                    </div>
                    <div class="custom-card" style="flex: 1; text-align: center; margin-bottom: 0;">
                        <div class="metric-label">File Type</div>
                        <div class="metric-value" style="color: #4ade80;">{"PE Binary" if res['is_pe'] else "Non-PE File"}</div>
                        <div style="font-size: 0.8rem; color: #9ca3af; margin-top:5px;">Size: {round(res['file_size']/1024, 2)} KB</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.write(f"**MD5 Hash:** `{res['md5']}`")
                st.write(f"**SHA-256:** `{res['sha256']}`")
                
                if res['detected_apis']:
                    st.write(f"**Suspicious APIs Detected:** {', '.join(res['detected_apis'])}")
                    
            with col_right:
                # Plotly Gauge Chart for Threat Score
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=res['threat_score'],
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Threat Score (Criticality)", 'font': {'size': 16, 'color': '#fff'}},
                    gauge={
                        'axis': {'range': [0, 10], 'tickwidth': 1, 'tickcolor': "#fff"},
                        'bar': {'color': "#00E5FF"},
                        'bgcolor': "rgba(0,0,0,0)",
                        'borderwidth': 2,
                        'bordercolor': "#374151",
                        'steps': [
                            {'range': [0, 4.0], 'color': 'rgba(74, 222, 128, 0.2)'},
                            {'range': [4.0, 7.5], 'color': 'rgba(251, 146, 60, 0.2)'},
                            {'range': [7.5, 10.0], 'color': 'rgba(239, 68, 68, 0.2)'}
                        ]
                    }
                ))
                fig_gauge.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#fff", 'family': "Outfit"},
                    height=260,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_gauge, use_container_width=True)
                
            # Class result banner
            if res['classification'] == "Ransomware":
                st.markdown("""
                <div class="critical-alert">
                    🔴 HIGH RISK: Malware Signature Matches RANSOMWARE (High Entropy Encryption capability found)
                </div>
                """, unsafe_allow_html=True)
            elif res['classification'] == "Trojan":
                st.warning("⚠️ Warning: File classified as Trojan (contains process injection or shell commands signatures).")
            else:
                st.success("🟢 Safe/Benign: No high-risk signatures matched.")
                
            # Mapped techniques list
            st.markdown("<h4 class='section-title'>🧬 Mapped MITRE ATT&CK Techniques (TTPs)</h4>", unsafe_allow_html=True)
            
            # Map tactics bar chart
            if res['mapped_techniques']:
                col_t1, col_t2 = st.columns([1, 1])
                
                with col_t1:
                    tactics_list = [t['tactic'] for t in res['mapped_techniques']]
                    t_counts = pd.Series(tactics_list).value_counts().reset_index()
                    t_counts.columns = ['Tactic', 'Count']
                    
                    fig_bar = px.bar(
                        t_counts, x='Count', y='Tactic', orientation='h',
                        title="TTP Tactic Distribution",
                        color='Count',
                        color_continuous_scale='blues'
                    )
                    fig_bar.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font={'color': "#fff"},
                        height=250
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)
                    
                with col_t2:
                    for tech in res['mapped_techniques']:
                        with st.expander(f"🔴 {tech['id']} - {tech['name']} (Severity: {tech['severity']})"):
                            st.markdown(f"**Tactic:** {tech['tactic']}")
                            st.markdown(f"**Detection Reason:** {tech['reason']}")
                            st.markdown(f"[View MITRE Page]({tech['url']})")
                            
                            # Course of Action from STIX JSON database if available
                            # Map ID to mitigations using mapper techniques_df
                            tech_db = mapper.techniques_df[mapper.techniques_df['id'] == tech['id']]
                            if not tech_db.empty:
                                st.markdown("#### 🛡️ Mitigations")
                                for m in tech_db.iloc[0]['mitigations']:
                                    st.markdown(f"- {m}")
            else:
                st.info("No suspicious MITRE techniques parsed from strings.")
                
    # ------------------ TAB 2: CVE LOOKUP ------------------
    with tab_cve:
        st.markdown("<h3 class='section-title'>Vulnerability & CVE Intelligence</h3>", unsafe_allow_html=True)
        st.write("Query the live CIRCL CVE Search API to fetch vulnerability summaries and map them to threat tactics.")
        
        cve_input = st.text_input("Enter CVE ID (e.g. CVE-2017-0144, CVE-2021-44228)", value="CVE-2017-0144")
        
        if st.button("Fetch and Map CVE"):
            with st.spinner(f"Querying CIRCL API for {cve_input}..."):
                cve_data = get_cve_details(cve_input)
                if cve_data:
                    # Run mapper on description
                    mapped_techs, mapped_tactics = mapper.map_text(cve_data['description'], top_k=6, threshold=0.10)
                    
                    st.session_state.cve_result = {
                        "id": cve_data['id'],
                        "cvss": cve_data['cvss'],
                        "published": cve_data['published'],
                        "description": cve_data['description'],
                        "mapped_techniques": mapped_techs,
                        "mapped_tactics": mapped_tactics
                    }
                    st.success("Successfully fetched and mapped!")
                else:
                    st.error("CVE ID not found or API is currently offline.")
                    
        if st.session_state.cve_result:
            cve = st.session_state.cve_result
            
            # Displays CVE details
            st.markdown(f"### Vulnerability Profile: {cve['id']}")
            
            col_c1, col_c2, col_c3 = st.columns([1, 1, 2])
            with col_c1:
                st.metric("CVSS Severity Score", f"{cve['cvss']} / 10.0")
            with col_c2:
                st.metric("Date Published", cve['published'])
            with col_c3:
                st.info(cve['description'])
                
            st.markdown("<h4 class='section-title'>Predicted Exploitation Attack Vectors</h4>", unsafe_allow_html=True)
            
            col_cv1, col_cv2 = st.columns([3, 2])
            
            with col_cv1:
                if cve['mapped_techniques']:
                    for tech in cve['mapped_techniques']:
                        with st.expander(f"🔴 {tech['id']} - {tech['name']} (Confidence: {tech['score']}%)"):
                            st.write(f"**Predicted Tactics:** {', '.join(tech['tactics'])}")
                            st.write(f"**Brief Description:** {tech['description']}")
                            st.markdown(f"[View MITRE ATT&CK Wiki]({tech['url']})")
                            st.markdown("#### Mitigations:")
                            for mit in tech['mitigations']:
                                st.markdown(f"- {mit}")
                else:
                    st.info("No confidence mappings found for this vulnerability description.")
                    
            with col_cv2:
                if cve['mapped_tactics']:
                    t_df = pd.DataFrame(cve['mapped_tactics'])
                    fig_tac = px.bar(
                        t_df, x='score', y='name', orientation='h',
                        title="Tactic Phase Confidence",
                        labels={'score': 'Confidence %', 'name': 'Attack Phase'},
                        color='score',
                        color_continuous_scale='sunsetdark'
                    )
                    fig_tac.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font={'color': "#fff"},
                        height=300
                    )
                    st.plotly_chart(fig_tac, use_container_width=True)
                    
    # ------------------ TAB 3: AGENT ALERTS (RansomGuard) ------------------
    with tab_alerts:
        st.markdown("<h3 class='section-title'>RansomGuard Heuristic Event Monitor</h3>", unsafe_allow_html=True)
        st.write("Dynamic Agent mimicking the watchdog-based real-time event analyzer. Watch for mass modifications and high-entropy post-write file encryption.")
        
        sim_cols_1, sim_cols_2 = st.columns([1, 3])
        
        with sim_cols_1:
            st.write("**Simulation Controls**")
            btn_start = st.button("Launch Ransomware Attack Sim", key="btn_start_alerts")
            if st.button("Reset Monitoring Log"):
                st.session_state.alerts_list = []
                st.rerun()
                
        with sim_cols_2:
            status_box = st.empty()
            alert_box = st.empty()
            
        if btn_start:
            st.session_state.alerts_list = []
            
            # Placeholders for real-time stream
            tbl_p = st.empty()
            chart_p = st.empty()
            
            files = [f"salary_report", f"database_dump", f"financials", f"customer_records", f"personal_photo", f"source_code", f"backup_config"]
            extensions = [".xlsx", ".sql", ".pdf", ".csv", ".jpg", ".py", ".zip"]
            crypt_extensions = [".crypt", ".locked", ".wannacry", ".locked"]
            
            # Start loop
            rate = 0
            for step in range(35):
                time.sleep(0.2)
                
                # Malicious encryption behavior starts after step 10
                is_malicious = step > 10
                
                if is_malicious:
                    rate = random.randint(6, 18)
                    file_name = random.choice(files) + f"_{step}" + random.choice(crypt_extensions)
                    entropy = round(random.uniform(7.6, 7.98), 2)
                    event_type = "Renamed & Encrypted (Lockout)"
                else:
                    rate = 1 if random.random() > 0.6 else 0
                    file_name = random.choice(files) + random.choice(extensions)
                    entropy = round(random.uniform(3.2, 5.5), 2)
                    event_type = "Modified" if rate > 0 else "None"
                    
                if event_type != "None":
                    st.session_state.alerts_list.append({
                        "Timestamp": time.strftime("%H:%M:%S"),
                        "Event": event_type,
                        "File Name": file_name,
                        "Entropy": entropy,
                        "Rate (mod/sec)": rate
                    })
                    
                # Update tables
                df_alerts = pd.DataFrame(st.session_state.alerts_list)
                tbl_p.dataframe(df_alerts.tail(8), use_container_width=True)
                
                # Update line graph
                fig_line = px.line(
                    df_alerts, y="Rate (mod/sec)", x=df_alerts.index,
                    title="Real-Time File Modification Rate",
                    color_discrete_sequence=["#EF4444" if is_malicious else "#10B981"]
                )
                fig_line.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#fff"},
                    height=280
                )
                try:
                    chart_p.plotly_chart(fig_line, use_container_width=True)
                except Exception:
                    # Fallback: render directly with the top-level Streamlit API
                    # in case the placeholder object does not expose plotly_chart.
                    st.plotly_chart(fig_line, use_container_width=True)
                
                if rate > 5:
                    status_box.error(f"⚠️ SUSPICIOUS BEHAVIOR: Modifications rate is {rate}/sec. High entropy changes detected!")
                    alert_box.markdown("""
                    <div class="critical-alert">
                        🚨 HEURISTIC RANSOMWARE ALERT: Active encryption observed in local directories! Files being locked!
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    status_box.info("Dynamic monitoring active. System state: Normal.")
                    alert_box.empty()
                    
        # If not active, show current log
        elif st.session_state.alerts_list:
            df_alerts = pd.DataFrame(st.session_state.alerts_list)
            st.dataframe(df_alerts, use_container_width=True)
            
            fig_line = px.line(df_alerts, y="Rate (mod/sec)", title="Heuristic Modification Rate Profile", color_discrete_sequence=["#00E5FF"])
            fig_line.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': "#fff"}
            )
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("No active logs. Click 'Launch Ransomware Attack Sim' above to view the heuristic alert process in action.")
            
    # ------------------ TAB 4: ML CLASSIFIER ------------------
    with tab_ml:
        st.markdown("<h3 class='section-title'>Machine Learning Malware Family Classifier</h3>", unsafe_allow_html=True)
        st.write("Train and evaluate a Random Forest model on structural features (entropy, sections, imports) extracted from PE samples.")
        
        ml_col1, ml_col2 = st.columns([1, 2])
        
        with ml_col1:
            st.write("**Model Training Parameters**")
            estimators = st.slider("Number of Decision Trees (Estimators)", min_value=10, max_value=200, value=100)
            
            if st.button("Train Model"):
                with st.spinner("Splitting dataset and fitting Random Forest..."):
                    train_res = classifier.train(n_estimators=estimators)
                    st.session_state.ml_result = train_res
                    st.success("Model trained successfully!")
                    
        with ml_col2:
            if st.session_state.ml_result:
                accuracy = st.session_state.ml_result["accuracy"]
                
                # Accuracy indicator gauge
                fig_acc = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=accuracy,
                    title={'text': "Validation Accuracy (%)", 'font': {'color': "#fff"}},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': '#10B981'},
                        'steps': [
                            {'range': [0, 50], 'color': 'rgba(239, 68, 68, 0.2)'},
                            {'range': [50, 75], 'color': 'rgba(251, 146, 60, 0.2)'},
                            {'range': [75, 100], 'color': 'rgba(16, 185, 129, 0.2)'}
                        ]
                    }
                ))
                fig_acc.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#fff"},
                    height=200,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_acc, use_container_width=True)
                
        if st.session_state.ml_result:
            st.markdown("<h4 style='color:#00E5FF;'>📊 Classification Report & Performance</h4>", unsafe_allow_html=True)
            
            report = st.session_state.ml_result["report"]
            
            # Format report as DataFrame
            report_data = []
            for class_name, metrics in report.items():
                if isinstance(metrics, dict):
                    report_data.append({
                        "Class": class_name,
                        "Precision": round(metrics["precision"], 2),
                        "Recall": round(metrics["recall"], 2),
                        "F1-Score": round(metrics["f1-score"], 2),
                        "Support": int(metrics["support"])
                    })
            df_report = pd.DataFrame(report_data)
            
            mc1, mc2 = st.columns([1, 1])
            with mc1:
                st.write("**Validation Set Class Metrics Table**")
                st.table(df_report)
                
            with mc2:
                st.write("**Dataset Composition Summary**")
                st.markdown("""
                <div class="custom-card" style="margin-bottom:0;">
                    <div style="display:flex; justify-content:space-around; align-items:center; text-align:center; height:120px;">
                        <div>
                            <div class="metric-label">Benign</div>
                            <div class="metric-value" style="color:#10B981;">35</div>
                        </div>
                        <div>
                            <div class="metric-label">Ransomware</div>
                            <div class="metric-value" style="color:#EF4444;">35</div>
                        </div>
                        <div>
                            <div class="metric-label">Trojan</div>
                            <div class="metric-value" style="color:#F59E0B;">30</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
            st.divider()
            
            # Row 2: Charts side-by-side (exactly as shown in Fig 13 of the report)
            cc1, cc2 = st.columns([1, 1])
            
            with cc1:
                # Precision/Recall comparison bar chart
                df_melt = df_report[df_report["Class"].isin(["Benign", "Ransomware", "Trojan"])].melt(
                    id_vars="Class", value_vars=["Precision", "Recall", "F1-Score"],
                    var_name="Metric", value_name="Score"
                )
                fig_metrics = px.bar(
                    df_melt, x="Class", y="Score", color="Metric",
                    barmode="group", title="Performance Metrics by Class",
                    color_discrete_sequence=["#00E5FF", "#10B981", "#F59E0B"]
                )
                fig_metrics.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#fff"},
                    height=300
                )
                st.plotly_chart(fig_metrics, use_container_width=True)
                
            with cc2:
                # Class distribution pie chart
                dist_data = pd.DataFrame({
                    "Family": ["Benign", "Ransomware", "Trojan"],
                    "Count": [35, 35, 30]
                })
                fig_pie = px.pie(
                    dist_data, values="Count", names="Family",
                    title="Class Distribution in Dataset",
                    color_discrete_sequence=["#10B981", "#EF4444", "#F59E0B"]
                )
                fig_pie.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#fff"},
                    height=300
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            
            # Manual Prediction sub-module
            st.markdown("<h4 class='section-title'>🔮 Manual Family Prediction</h4>", unsafe_allow_html=True)
            pred_file = st.file_uploader("Upload PE binary file to predict family classification", type=["exe", "dll", "txt"])
            
            if pred_file:
                file_ext = os.path.splitext(pred_file.name)[1]
                with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_pred:
                    tmp_pred.write(pred_file.read())
                    tmp_pred_path = tmp_pred.name
                    
                if st.button("Predict Family"):
                    with st.spinner("Extracting features and predicting..."):
                        try:
                            pred_res = classifier.predict_file(tmp_pred_path)
                        finally:
                            try:
                                os.unlink(tmp_pred_path)
                            except Exception:
                                pass
                        if pred_res:
                            # Display Prediction result
                            fam = pred_res["predicted_family"]
                            conf = pred_res["confidence"]
                            
                            color = "#10B981" if fam == "Benign" else ("#EF4444" if fam == "Ransomware" else "#F59E0B")
                            
                            st.markdown(f"""
                            <div style="background-color: rgba(0,0,0,0.3); border-left: 5px solid {color}; padding: 15px; border-radius: 5px;">
                                <h4>Predicted Class: <span style="color:{color};">{fam.upper()}</span></h4>
                                <h5>Confidence: {conf}%</h5>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Probabilities horizontal bar chart
                            prob_df = pd.DataFrame(list(pred_res["probabilities"].items()), columns=["Family", "Probability"])
                            fig_prob = px.bar(
                                prob_df, x="Probability", y="Family", orientation="h",
                                title="Prediction Class Distribution",
                                color="Probability",
                                color_continuous_scale="reds" if fam == "Ransomware" else "greens"
                            )
                            fig_prob.update_layout(
                                paper_bgcolor='rgba(0,0,0,0)',
                                plot_bgcolor='rgba(0,0,0,0)',
                                font={'color': "#fff"},
                                height=200
                            )
                            st.plotly_chart(fig_prob, use_container_width=True)
                        else:
                            st.error("Error reading file features.")
        else:
            st.info("Train the Random Forest model using the 'Train Model' button above to unlock metrics and classification tools.")

    # ------------------ TAB 5: REPORT GENERATOR ------------------
    with tab_report:
        st.markdown("<h3 class='section-title'>Export Professional Incident Report</h3>", unsafe_allow_html=True)
        st.write("Generates a comprehensive forensic PDF threat analysis document incorporating static PE results, CVE vulnerability references, agent alerts, and ML models.")
        
        # Report summaries info
        st.markdown("""
        <div class="custom-card">
            <h4>Ready to Export Sections:</h4>
            <ul>
                <li><b>Student details block</b>: (Nenavath Pooja, Enrollment 101CTBMCS2122027)</li>
                <li><b>Static PE Header details</b>: (Entropy, size, hashes, detected patterns)</li>
                <li><b>CVE Vulnerabilities mapped</b>: (CVE parameters, CVSS index, BERT predictions)</li>
                <li><b>RansomGuard logs summary</b>: (Event tracking list, ransomware warnings)</li>
                <li><b>Machine Learning classification details</b>: (Random Forest status, F1-scores)</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Generate Forensic PDF Report"):
            with st.spinner("Rendering PDF document layout..."):
                pdf_bytes = generate_pdf_report(
                    static_res=st.session_state.static_result,
                    cve_res=st.session_state.cve_result,
                    alerts_res=st.session_state.alerts_list,
                    ml_res=st.session_state.ml_result
                )
                
                b64 = base64.b64encode(pdf_bytes).decode()
                href = f'<a class="custom-card" style="display:inline-block; text-decoration:none; color:#00E5FF; border-color:#00E5FF; padding:10px 20px; font-weight:700;" href="data:application/octet-stream;base64,{b64}" download="NFSU_Malware_Analysis_Report.pdf">Download Generated PDF Report</a>'
                st.markdown(href, unsafe_allow_html=True)
                st.success("Report successfully prepared for download!")

if __name__ == "__main__":
    main()
