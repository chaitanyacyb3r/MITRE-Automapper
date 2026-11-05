# 🛡️ Advanced MITRE ATT&CK AutoMapper & SOC Assistant

**Title:** Automated Threat Intelligence Mapping & Mitigation Recommendation System

## 🌟 Unique Features
This project extends the original research (Branescu et al.) by transforming it from a simple "classifier" into a **Full-Fledged Security Operations Center (SOC) Tool**.

### 🚀 What makes this special?
1.  **🔍 Real-Time CVE Lookup:**
    *   Unlike static models, this tool connects to the **CIRCL CVE API**. You can input a fresh vulnerability ID (e.g., `CVE-2023-1234`), and it fetches the live description to analyze instantly.
2.  **�️ Automated Mitigation Recommender:**
    *   It doesn't just tell you *what* the attack is; it tells you **how to fix it**. It parses the "Course of Action" objects from the MITRE STIX data to suggest specific defenses (e.g., "Implement Network Segmentation").
3.  **📊 Interactive Visualization:**
    *   Uses **Plotly** to generate dynamic charts showing the confidence distribution of different attack tactics.
4.  **📑 Automated PDF Reporting:**
    *   Generates a professional **Threat Analysis Report** (PDF) with one click, ready for security analysts to present to management.

---

## 🛠️ Prerequisites
*   Python 3.8+
*   Internet Connection (for API & Model download)

## 🚀 Installation
1.  **Install Requirements:**
    ```bash
    pip install -r requirements.txt
    ```
2.  **Run the App:**
    ```bash
    streamlit run app.py
    ```

## 🎮 How to Use
1.  **Mode 1: Text Analysis:** Paste a blog post or log snippet.
2.  **Mode 2: CVE Lookup:** Enter a CVE ID (e.g., `CVE-2021-44228`).
3.  **View Results:**
    *   See the **Bar Chart** of predicted tactics.
    *   Expand the **Techniques** to read descriptions.
    *   **CRITICAL:** Read the **Recommended Mitigations** for each technique.
4.  **Export:** Click **"Generate PDF Report"** to save your analysis.

---

## 🔬 Technical Stack
*   **NLP Engine:** Sentence-BERT (`all-MiniLM-L6-v2`)
*   **Frontend:** Streamlit
*   **Visualization:** Plotly Express
*   **Data Sources:** MITRE Enterprise ATT&CK (STIX 2.0), CIRCL CVE API
*   **Reporting:** FPDF

