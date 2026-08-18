import streamlit as st
import pandas as pd
import joblib
import os
from pcap_parser import extract_features_from_pcap

# 1. Page Configuration
import streamlit as st
# 1. Page Configuration (This handles the browser tab and icon)
st.set_page_config(
    page_title="Aegis",
    page_icon="aegisicon.png",  # Make sure aegisicon.png is pushed to GitHub!
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Page Headers (This draws the actual text on the screen)
st.title("Aegis | IoMT Threat Intelligence")
st.markdown("Upload raw network captures (`.pcap`) from medical sensors or private 5G edge networks to detect malicious traffic in real time.")
# 2. Load Model
@st.cache_resource
def load_model():
    return joblib.load('aegis_wustl_model.pkl')

model = load_model()

# 3. File Uploader
uploaded_file = st.file_uploader("Upload Network Traffic Capture (.pcap)", type=["pcap", "pcapng"])

if uploaded_file is not None:
    temp_file_path = "temp_capture.pcap"
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    with st.spinner("Extracting packets via Scapy..."):
        df_packets = extract_features_from_pcap(temp_file_path)
    
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)
    
    if not df_packets.empty:
        st.write("### Raw Packet Extraction Preview:")
        st.dataframe(df_packets.head())
        
        # --- FLOW AGGREGATION (Aegis Standard) ---
        st.write("Aggregating packets into network flows...")
        
        df_flows = df_packets.groupby(
            ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        ).agg(
            total_packets=('packet_length', 'count'),
            total_bytes=('packet_length', 'sum'),
            start_time=('timestamp', 'min'),
            end_time=('timestamp', 'max')
        ).reset_index()
        
        # Compute Flow Duration & Rates
        df_flows['flow_duration_sec'] = df_flows['end_time'] - df_flows['start_time']
        df_flows['flow_duration_sec'] = df_flows['flow_duration_sec'].replace(0, 0.000001)
        
        df_flows['packets_per_sec'] = df_flows['total_packets'] / df_flows['flow_duration_sec']
        df_flows['bytes_per_sec'] = df_flows['total_bytes'] / df_flows['flow_duration_sec']
        
        df_flows = df_flows.drop(columns=['start_time', 'end_time'])
        
        st.write("### Standardized Flow Features:")
        st.dataframe(df_flows.head())
        
        # --- INFERENCE ---
        if st.button("Run Threat Analysis"):
            with st.spinner("Classifying flows with Random Forest..."):
                # Align expected numerical/categorical features
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

# 4. Styling
st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    div.stButton > button:first-child {
        background-color: #0d1117;
        color: #ffffff;
        border: 1px solid #30363d;
        border-radius: 6px;
    }
    </style>
""", unsafe_allow_html=True)