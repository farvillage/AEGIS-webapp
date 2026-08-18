import os
import pandas as pd
import streamlit as st
import joblib
from PIL import Image
from pcap_parser import extract_features_from_pcap

# --- 1. Page Configuration ---
icon = Image.open("aegisicon.png")
st.set_page_config(
    page_title="Aegis",
    page_icon=icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. Targeted CSS for UI Clean-up & Colors ---
st.markdown(
    """
    <style>
    /* Hide the top-right Streamlit menu, share button, and GitHub icon */
    [data-testid="stHeader"] {
        visibility: hidden;
    }
    
    /* Force monospace font across the app */
    html, body, [class*="css"] {
        font-family: monospace !important;
    }
    
    /* Change link colors (like the email in About Me) to the requested muted purple */
    a {
        color: #484aaa !important;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
    
    /* Change the file uploader upload icon to the muted purple */
    [data-testid="stFileUploadDropzone"] svg {
        color: #484aaa !important;
        fill: #484aaa !important;
    }
    
    /* Violet accents specifically for inline code like `.pcap` and `.csv` */
    code {
        color: #dabcff !important;
        background-color: rgba(218, 188, 255, 0.1) !important;
        padding: 0.2em 0.4em;
        border-radius: 3px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# --- 3. Simple Header ---
st.title("Aegis")
st.markdown("Real-time intrusion detection for private 5G edge networks.")
st.markdown("Upload raw network captures (`.pcap`) or processed datasets (`.csv`) from medical sensors to detect malicious behavioral anomalies instantly.")

# --- 4. About Me (Sidebar) ---
with st.sidebar:
    st.markdown("## Navigation & Controls")
    
    with st.expander("About the Developer"):
        st.markdown(
            """
            **Ygor Gesteira**  
            *Master's Researcher @ Instituto Federal da Paraíba (IFPB)*
            
            Currently developing Aegis as part of my Master's research, focusing on machine learning applications for cybersecurity in Internet of Medical Things (IoMT) over private 5G networks.
            
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