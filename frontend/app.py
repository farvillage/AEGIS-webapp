import os
import pandas as pd
import requests
import streamlit as st
from PIL import Image

# --- 1. Page Configuration ---
icon_path = "aegisicon.png"
icon = Image.open(icon_path) if os.path.exists(icon_path) else "🛡️"

st.set_page_config(
    page_title="AEGIS",
    page_icon=icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. Targeted CSS (Piano-Black UI + Purple Hover Effects) ---
st.markdown(
    """
    <style>
    /* Make the header background transparent */
    [data-testid="stHeader"] {
        background-color: transparent !important;
    }
    
    /* Hide default Cloud toolbars except sidebar toggle */
    [data-testid="stHeader"] > div > div:not(:first-child) {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
    }

    [data-testid="stHeader"] a, 
    [data-testid="stHeader"] button:not([data-testid="collapsedControl"]):not([kind="headerNoPadding"]) {
        display: none !important;
    }

    /* Force monospace font across the app */
    html, body, [class*="css"] {
        font-family: monospace !important;
    }
    
    /* Force links to muted purple */
    a, a:hover, a:visited, a:active {
        color: #484aaa !important;
        text-decoration: none !important;
    }
    a:hover {
        text-decoration: underline !important;
    }
    
    /* Force upload icon/text color */
    [data-testid="stFileUploadDropzone"] * {
        color: #484aaa !important;
        fill: #484aaa !important;
    }
    
    /* Violet accents for inline code tags */
    code {
        color: #dabcff !important;
        background-color: #111111 !important;
        border: 1px solid #484aaa !important;
        padding: 0.2em 0.4em;
        border-radius: 3px;
    }

    /* Purple Hover Effect for Streamlit Buttons */
    div.stButton > button:hover {
        background-color: #484aaa !important;
        color: #ffffff !important;
        border-color: #484aaa !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# --- 3. Header ---
st.title("AEGIS")
st.markdown("Real-time intrusion detection for private 5G edge networks.")
st.markdown("Upload raw network captures (`.pcap`) or processed datasets (`.csv`) from medical sensors to detect malicious behavioral anomalies instantly.")

# --- 4. Sidebar / Who am I? ---
with st.sidebar:
    st.markdown("## About:")
    with st.expander("Who am I?"):
        st.markdown(
            """
            **Ygor Gesteira**  
            *Master's Researcher @ Instituto Federal da Paraíba (IFPB)*
            
            Currently developing AEGIS as part of my Master's research, focusing on machine learning applications for cybersecurity in Internet of Medical Things (IoMT) over private 5G networks.
            
            *"With great power comes great responsibility"* - Stan Lee
            
            [ygorgesteira@gmail.com](mailto:ygorgesteira@gmail.com)
            """
        )

# Backend API URL (FastAPI)
API_URL = "http://127.0.0.1:8000"

# --- 5. File Uploader & API Client Logic ---
uploaded_file = st.file_uploader(
    "Upload Network Traffic Capture", 
    type=["csv", "pcap", "pcapng"]
)

if uploaded_file is not None:
    file_name = uploaded_file.name
    
    if file_name.endswith('.csv'):
        st.info("CSV detected. AEGIS is analyzing...")
        endpoint = "/api/analyze-csv"
        file_key = "text/csv"
    elif file_name.endswith(('.pcap', '.pcapng')):
        st.info("PCAP detected. AEGIS packet parser active...")
        endpoint = "/api/analyze-pcap"
        file_key = "application/vnd.tcpdump.pcap"
    else:
        st.error("Unsupported file format.")
        endpoint = None

    if endpoint and st.button("Run Threat Analysis"):
        with st.spinner("AEGIS engine is processing..."):
            files = {"file": (file_name, uploaded_file.getvalue(), file_key)}
            try:
                response = requests.post(f"{API_URL}{endpoint}", files=files, timeout=60)
                
                if response.status_code == 200:
                    result = response.json()
                    df_result = pd.DataFrame(result["data"])
                    
                    total_rows = result['total_rows']
                    attack_count = result['attack_count']
                    normal_count = total_rows - attack_count
                    
                    st.success(f"Successfully processed {total_rows} network flows!")
                    
                    # --- Executive Summary Metrics ---
                    st.write("### Threat Intelligence Overview")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Total Flows Analyzed", f"{total_rows:,}")
                    col2.metric("Malicious Flows Flagged", f"{attack_count:,}", delta_color="inverse")
                    col3.metric("Normal Traffic Flows", f"{normal_count:,}")
                    
                    # --- Analysis Explanation ---
                    # --- Analysis Explanation ---
                    st.markdown("---")
                    st.markdown("### Behavioral Analysis Breakdown")
                    st.markdown(
                        f"""
                        AEGIS evaluated **{total_rows:,}** network flows:
                        - **{attack_count:,} malicious flows** flagged.
                        - **{normal_count:,} normal flows** verified.
                        """
                    )
                    
                    if attack_count > 0:
                        st.error(f"Alert: {attack_count} malicious network flow(s) identified.")
                    else:
                        st.success("All network traffic flows classified as normal.")
                        
                    # --- Detailed Data Table ---
                    st.write("### Final Threat Report Log:")
                    st.dataframe(df_result, use_container_width=True)
                    
                else:
                    st.error(f"Server Error: {response.json().get('detail', 'Unknown error')}")
                    
            except requests.exceptions.ConnectionError:
                st.error("Could not connect to the AEGIS backend server. Ensure uvicorn is running!")