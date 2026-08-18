# AEGIS

Real-time intrusion detection for private 5G edge networks.

## Overview
AEGIS is a web-based threat intelligence platform designed to monitor and classify network traffic in Internet of Medical Things (IoMT) environments. It provides a streamlined interface to upload raw network captures or processed datasets, automatically extracting features and applying machine learning to detect malicious behavioral anomalies instantly.

## Core Features
* **Dual Input Support:** Process raw packet captures (`.pcap`, `.pcapng`) or pre-aggregated flow datasets (`.csv`).
* **Automated Packet Parsing:** Utilizes Scapy to extract raw packet data and group it into standardized network flows based on source/destination IPs, ports, and protocols.
* **Feature Engineering:** Automatically calculates critical flow metrics, including flow duration, packets per second, and bytes per second.
* **Real-time Threat Inference:** Leverages a pre-trained Random Forest model (`aegis_wustl_model.pkl`) to classify flows as normal traffic or flag specific attack vectors.
* **Minimalist UI:** Built with Streamlit, featuring a custom, distraction-free piano black interface.

## Technologies Used
* **Core:** Python
* **Frontend/UI:** Streamlit
* **Data Processing:** Pandas, Scapy
* **Machine Learning:** Scikit-Learn, Joblib

## Installation and Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/farvillage/aegis.git](https://github.com/farvillage/aegis.git)
   cd aegis
   ```

2. **Install dependencies:**
   Ensure you have Python installed, then install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   Launch the Streamlit server locally:
   ```bash
   streamlit run app.py
   ```

## About the Project
AEGIS is developed as part of ongoing Master's research at the Instituto Federal da Paraíba (IFPB). The project focuses on machine learning applications for cybersecurity, specifically addressing the unique constraints and behavioral patterns of IoMT devices operating over private 5G networks.

## Contact
**Ygor Gesteira**  
ygorgesteira@gmail.com
