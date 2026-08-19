# Import standard built-in modules for operating system interactions
import os

# Import data manipulation and web framework libraries
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# Import joblib for loading the pre-trained machine learning model
import joblib

# Import PIL to handle the custom browser tab icon
from PIL import Image

# Import custom parsing logic for raw network packets
from pcap_parser import extract_features_from_pcap

# --- 1. Page Configuration ---
# This block sets up the browser tab properties and the default layout width
icon = Image.open("aegisicon.png")
st.set_page_config(
    page_title="AEGIS",
    page_icon=icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 1.1 Browser Tab Title Cleanup ---
# Injects a MutationObserver to strip the trailing "· Streamlit"
components.html(
    """
    <script>
        const observer = new MutationObserver((mutations, obs) => {
            const title = window.parent.document.querySelector('title') || document.querySelector('title');
            if (title && title.innerText.includes('· Streamlit')) {
                title.innerText = title.innerText.replace(' · Streamlit', '').replace(' · Streamlit', '');
                obs.disconnect();
            }
        });
        const target = window.parent.document.querySelector('head') || document.querySelector('head') || document;
        observer.observe(target, { subtree: true, childList: true });
    </script>
    """,
    height=0,
    width=0
)

# --- 2. Targeted CSS to KILL all Blue, Toolbars, & Cloud Badges ---
## This block injects custom CSS directly into the HTML to override Streamlit defaults
st.markdown(
    """
    <style>
    /* 1. Make the header background transparent so it doesn't block the app */
    [data-testid="stHeader"] {
        background-color: transparent !important;
    }
    
    /* 2. Annihilate the Streamlit Cloud Toolbar (Share, Star, Edit, GitHub) */
    /* The header is a flexbox. Child 1 is the sidebar toggle. We permanently hide all other children. */
    [data-testid="stHeader"] > div > div:not(:first-child) {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
    }

    /* 3. Aggressive fallback: destroy any stray links or buttons inside the header */
    /* that aren't specifically the sidebar collapse control */
    [data-testid="stHeader"] a, 
    [data-testid="stHeader"] button:not([data-testid="collapsedControl"]):not([kind="headerNoPadding"]) {
        display: none !important;
    }

    /* 4. Force monospace font across the entire app */
    html, body, [class*="css"] {
        font-family: monospace !important;
    }
    
    /* 5. Force ALL your links (like the sidebar email) to the muted purple */
    a, a:hover, a:visited, a:active {
        color: #484aaa !important;
        text-decoration: none !important;
    }
    a:hover {
        text-decoration: underline !important;
    }
    
    /* 6. Force the upload icon and text to muted purple */
    [data-testid="stFileUploadDropzone"] * {
        color: #484aaa !important;
        fill: #484aaa !important;
    }
    
    /* 7. Violet accents specifically for inline code tags (.pcap, .csv) */
    code {
        color: #dabcff !important;
        background-color: #111111 !important;
        border: 1px solid #484aaa !important;
        padding: 0.2em 0.4em;
        border-radius: 3px;
    }
    </style>
    """,
    unsafe_allow_html=True
)
# --- 3. Simple Header ---
# The main title and description shown at the top of the page
st.title("AEGIS")
st.markdown("Real-time intrusion detection for private 5G edge networks.")
st.markdown("Upload raw network captures (`.pcap`) or processed datasets (`.csv`) from medical sensors to detect malicious behavioral anomalies instantly.")

# --- 4. About Me (Sidebar) ---
# Creates a collapsible sidebar section for developer information
with st.sidebar:
    st.markdown("## About:")
    
    # An expander keeps the sidebar clean until the user clicks to read more
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

# --- 5. Load Model ---
# The @st.cache_resource decorator ensures the model is only loaded into memory once
@st.cache_resource
def load_model():
    return joblib.load('aegis_wustl_model.pkl')

# Initialize the machine learning model
model = load_model()

# --- 6. File Uploader Logic ---
# Creates the drag-and-drop zone for network files
uploaded_file = st.file_uploader(
    "Upload Network Traffic Capture", 
    type=["pcap", "pcapng", "csv"]
)

# This block executes only after a user has uploaded a file
if uploaded_file is not None:
    
    # === A. HANDLE CSV UPLOADS ===
    if uploaded_file.name.endswith('.csv'):
        # Provide feedback that the file is being read directly
        st.info("CSV detected. Bypassing packet parser and loading dataset...")
        
        # Read the CSV into a pandas DataFrame and display a preview
        df_flows = pd.read_csv(uploaded_file)
        st.success(f"Successfully loaded {df_flows.shape[0]} rows and {df_flows.shape[1]} features!")
        st.dataframe(df_flows.head())
        
        # --- INFERENCE FOR CSV ---
        # Wait for the user to click the analysis button
        if st.button("Run Threat Analysis"):
            with st.spinner("Classifying flows with Random Forest..."):
                # Get the exact feature columns the model was trained on
                expected_features = model.feature_names_in_
                df_prepared = df_flows.copy()
                
                # Fill missing columns with 0 to prevent feature mismatch errors
                for col in expected_features:
                    if col not in df_prepared.columns:
                        df_prepared[col] = 0
                
                # Ensure columns are in the exact order the model expects
                df_prepared = df_prepared[expected_features]
                
                # Run the prediction and format the output strings
                predictions = model.predict(df_prepared)
                df_flows['threat_detection'] = predictions
                df_flows['threat_detection'] = df_flows['threat_detection'].apply(
                    lambda x: '[ATTACK DETECTED]' if str(x) in ['1', '1.0', 'Attack'] else '[NORMAL TRAFFIC]'
                )
                
                # Display the results
                st.write("### Final Threat Report:")
                st.dataframe(df_flows)
                
                # Count malicious flows and show appropriate alert/success messages
                attack_count = (df_flows['threat_detection'] == '[ATTACK DETECTED]').sum()
                if attack_count > 0:
                    st.error(f"Alert: {attack_count} malicious network flow(s) identified.")
                else:
                    st.success("All network traffic flows classified as normal.")

    # === B. HANDLE PCAP UPLOADS ===
    elif uploaded_file.name.endswith(('.pcap', '.pcapng')):
        st.info("PCAP file detected. Parsing network packets...")
        
        # Scapy requires a physical file to parse, so we save the uploaded buffer to disk temporarily
        temp_file_path = f"temp_{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        # Extract basic packet data using the custom parser
        with st.spinner("Extracting packets via Scapy..."):
            df_packets = extract_features_from_pcap(temp_file_path)
            
        # Clean up by deleting the temporary file from the server
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
        # Proceed if the parser actually found packets
        if not df_packets.empty:
            st.write("### Raw Packet Extraction Preview:")
            st.dataframe(df_packets.head())
            
            # Group raw packets into standardized network flows based on connection pairs
            st.write("Aggregating packets into network flows...")
            df_flows = df_packets.groupby(
                ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
            ).agg(
                total_packets=('packet_length', 'count'),
                total_bytes=('packet_length', 'sum'),
                start_time=('timestamp', 'min'),
                end_time=('timestamp', 'max')
            ).reset_index()
            
            # Calculate duration, avoiding division by zero by replacing 0 with a microsecond
            df_flows['flow_duration_sec'] = df_flows['end_time'] - df_flows['start_time']
            df_flows['flow_duration_sec'] = df_flows['flow_duration_sec'].replace(0, 0.000001)
            
            # Calculate throughput features for the model
            df_flows['packets_per_sec'] = df_flows['total_packets'] / df_flows['flow_duration_sec']
            df_flows['bytes_per_sec'] = df_flows['total_bytes'] / df_flows['flow_duration_sec']
            
            # Drop raw timestamps as they are not needed for ML inference
            df_flows = df_flows.drop(columns=['start_time', 'end_time'])
            
            st.write("### Standardized Flow Features:")
            st.dataframe(df_flows.head())
            
            # --- INFERENCE FOR PCAP ---
            if st.button("Run Threat Analysis"):
                with st.spinner("Classifying flows with Random Forest..."):
                    expected_features = model.feature_names_in_
                    df_prepared = df_flows.copy()
                    
                    # Pad missing features and align columns for the model
                    for col in expected_features:
                        if col not in df_prepared.columns:
                            df_prepared[col] = 0
                    
                    df_prepared = df_prepared[expected_features]
                    
                    # Predict and map outcomes to readable text
                    predictions = model.predict(df_prepared)
                    df_flows['threat_detection'] = predictions
                    df_flows['threat_detection'] = df_flows['threat_detection'].apply(
                        lambda x: '[ATTACK DETECTED]' if str(x) in ['1', '1.0', 'Attack'] else '[NORMAL TRAFFIC]'
                    )
                    
                    # Reorder columns to show the threat detection and IP/Port data first
                    st.write("### Final Threat Report:")
                    cols = ['threat_detection', 'src_ip', 'dst_ip', 'src_port', 'dst_port'] + [
                        c for c in df_flows.columns if c not in ['threat_detection', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
                    ]
                    st.dataframe(df_flows[cols])
                    
                    # Display summary alerts
                    attack_count = (df_flows['threat_detection'] == '[ATTACK DETECTED]').sum()
                    if attack_count > 0:
                        st.error(f"Alert: {attack_count} malicious network flow(s) identified.")
                    else:
                        st.success("All network traffic flows classified as normal.")
        else:
            st.warning("No valid IP packets detected in the uploaded capture.")