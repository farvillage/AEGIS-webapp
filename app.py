import os
import pandas as pd
import streamlit as st
import joblib
from PIL import Image
from pcap_parser import extract_features_from_pcap

# --- 1. Page Configuration ---
icon = Image.open("aegisicon.png")
st.set_page_config(
    page_title="Aegis | Behavioral Intrusion Detection",
    page_icon=icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. Brute-Force Purple Theme (CSS Injection) ---
st.markdown(
    """
    <style>
    /* Force main background and text colors */
    .stApp {
        background-color: #0b0f19 !important;
        color: #e2e8f0 !important;
        font-family: monospace !important;
    }
    /* Force sidebar background */
    [data-testid="stSidebar"] {
        background-color: #131b2e !important;
    }
    /* Force sophisticated purple on primary buttons/uploaders */
    div.stButton > button:first-child, .stFileUploader > div > button {
        background-color: #6B21A8 !important;
        color: #ffffff !important;
        border: 1px solid #6B21A8 !important;
        font-family: monospace !important;
    }
    /* Hover effect for buttons */
    div.stButton > button:first-child:hover, .stFileUploader > div > button:hover {
        background-color: #8B5CF6 !important;
        border: 1px solid #8B5CF6 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# --- 3. Skrive-Inspired Header ---
st.markdown(
    """
    <div style='text-align: center; padding-bottom: 2rem;'>
        <h1 style='color: #6B21A8; font-family: monospace; font-size: 3.5rem; margin-bottom: 0;'>🛡️ Aegis</h1>
        <h3 style='color: #e2e8f0; font-family: monospace; font-weight: normal; margin-top: 0.5rem;'>
            Real-time intrusion detection for private 5G edge networks.
        </h3>
        <p style='color: #94a3b8; font-size: 1.1rem; max-width: 600px; margin: 0 auto;'>
            Upload raw network captures (<code>.pcap</code>) or processed datasets (<code>.csv</code>) 
            from medical sensors to detect malicious behavioral anomalies instantly.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# --- 4. About Me (Sidebar) ---
with st.sidebar:
    st.image("aegisicon.png", width=100)
    st.markdown("## Navigation & Controls")
    
    with st.expander("About the Developer"):
        st.markdown(
            """
            **Ygor Gesteira**  
            *Master's Researcher @ Instituto Federal da Paraíba (IFPB)*
            
            Currently developing Aegis as part of my Master's research, focusing on machine learning applications for cybersecurity in Industrial IoT (IIoT) and Internet of Medical Things (IoMT) over private 5G networks.
            
            *"I found it is the small everyday deeds of ordinary folk that keep the darkness at bay."* - J.R.R. Tolkien
            
            [ygorgesteira@gmail.com](mailto:ygorgesteira@gmail.com)
            """
        )

# --- 5. Load Model ---
@st.cache_resource
def load_model():
    return joblib.load('aegis_wustl_model.pkl')

model = load_model()

# --- 6. File Uploader Logic ---
uploaded_file = st.file_uploader(
    "Upload Network Traffic Capture", 
    type=["pcap", "pcapng", "csv"]
)

if uploaded_file is not None:
    
    # === A. HANDLE CSV UPLOADS ===
    if uploaded_file.name.endswith('.csv'):
        st.info("CSV detected. Bypassing packet parser and loading dataset...")
        df_flows = pd.read_csv(uploaded_file)
        st.success(f"Successfully loaded {df_flows.shape[0]} rows and {df_flows.shape[1]} features!")
        st.dataframe(df_flows.head())
        
        # --- INFERENCE FOR CSV ---
        if st.button("Run Threat Analysis"):
            with st.spinner("Classifying flows with Random Forest..."):
                expected_features = model.feature_names_in_
                df_prepared = df_flows.copy()
                
                for col in expected_features:
                    if col not in df_prepared.columns:
                        df_prepared[col] = 0
                
                df_prepared = df_prepared[expected_features]
                predictions = model.predict(df_prepared)
                df_flows['threat_detection'] = predictions
                df_flows['threat_detection'] = df_flows['threat_detection'].apply(
                    lambda x: '[ATTACK DETECTED]' if str(x) in ['1', '1.0', 'Attack'] else '[NORMAL TRAFFIC]'
                )
                
                st.write("### Final Threat Report:")
                st.dataframe(df_flows)
                attack_count = (df_flows['threat_detection'] == '[ATTACK DETECTED]').sum()
                if attack_count > 0:
                    st.error(f"Alert: {attack_count} malicious network flow(s) identified.")
                else:
                    st.success("All network traffic flows classified as normal.")

    # === B. HANDLE PCAP UPLOADS ===
    elif uploaded_file.name.endswith(('.pcap', '.pcapng')):
        st.info("PCAP file detected. Parsing network packets...")
        
        temp_file_path = f"temp_{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        with st.spinner("Extracting packets via Scapy..."):
            df_packets = extract_features_from_pcap(temp_file_path)
            
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
        if not df_packets.empty:
            st.write("### Raw Packet Extraction Preview:")
            st.dataframe(df_packets.head())
            
            st.write("Aggregating packets into network flows...")
            df_flows = df_packets.groupby(
                ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
            ).agg(
                total_packets=('packet_length', 'count'),
                total_bytes=('packet_length', 'sum'),
                start_time=('timestamp', 'min'),
                end_time=('timestamp', 'max')
            ).reset_index()
            
            df_flows['flow_duration_sec'] = df_flows['end_time'] - df_flows['start_time']
            df_flows['flow_duration_sec'] = df_flows['flow_duration_sec'].replace(0, 0.000001)
            df_flows['packets_per_sec'] = df_flows['total_packets'] / df_flows['flow_duration_sec']
            df_flows['bytes_per_sec'] = df_flows['total_bytes'] / df_flows['flow_duration_sec']
            df_flows = df_flows.drop(columns=['start_time', 'end_time'])
            
            st.write("### Standardized Flow Features:")
            st.dataframe(df_flows.head())
            
            # --- INFERENCE FOR PCAP ---
            if st.button("Run Threat Analysis"):
                with st.spinner("Classifying flows with Random Forest..."):
                    expected_features = model.feature_names_in_
                    df_prepared = df_flows.copy()
                    
                    for col in expected_features:
                        if col not in df_prepared.columns:
                            df_prepared[col] = 0
                    
                    df_prepared = df_prepared[expected_features]
                    predictions = model.predict(df_prepared)
                    df_flows['threat_detection'] = predictions
                    df_flows['threat_detection'] = df_flows['threat_detection'].apply(
                        lambda x: '[ATTACK DETECTED]' if str(x) in ['1', '1.0', 'Attack'] else '[NORMAL TRAFFIC]'
                    )
                    
                    st.write("### Final Threat Report:")
                    cols = ['threat_detection', 'src_ip', 'dst_ip', 'src_port', 'dst_port'] + [
                        c for c in df_flows.columns if c not in ['threat_detection', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
                    ]
                    st.dataframe(df_flows[cols])
                    
                    attack_count = (df_flows['threat_detection'] == '[ATTACK DETECTED]').sum()
                    if attack_count > 0:
                        st.error(f"Alert: {attack_count} malicious network flow(s) identified.")
                    else:
                        st.success("All network traffic flows classified as normal.")
        else:
            st.warning("No valid IP packets detected in the uploaded capture.")