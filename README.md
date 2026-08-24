# AEGIS

Real-time intrusion detection for private 5G edge networks.

## Overview

AEGIS is an intelligent threat detection and behavioral analysis framework designed for private 5G edge networks, evaluating telemetry from Industrial IoT (IIoT) and Internet of Medical Things (IoMT) environments.

## Architectural Overview

AEGIS utilizes a decoupled client-server architecture:

- **Backend (/backend):** Built with FastAPI, handling high-performance model inference, IP/feature translation schemas, and real-time threat evaluation via a pre-trained Random Forest pipeline.
- **Frontend (/frontend):** Built with Streamlit, providing an interactive dark-themed operator dashboard for metrics visualization, CSV/PCAP ingestion, and threat report generation.

## Core Features

- **Dual Input Support:** Process raw packet captures (`.pcap`, `.pcapng`) or pre-aggregated flow datasets (`.csv`).
- **Automated Packet Parsing:** Utilizes Scapy to extract raw packet data and group it into standardized network flows based on source/destination IPs, ports, and protocols.
- **Feature Engineering & Alignment:** Automatically translates and maps incoming dataset features to standardized model expectations, handling IP-to-numeric encoding safely.
- **Real-time Threat Inference:** Leverages a pre-trained Random Forest model (`aegis_wustl_model.pkl`) via the backend API to classify flows as normal traffic or flag malicious attacks instantly.
- **Operator Dashboard:** Built with Streamlit in a decoupled structure, featuring a custom, distraction-free piano black interface.

## Technologies Used

- **Core:** Python, FastAPI, Uvicorn
- **Frontend/UI:** Streamlit
- **Data Processing:** Pandas, Scapy, Joblib
- **Machine Learning:** Scikit-Learn

## Installation and Running

1. **Clone the repository:**

```bash
git clone https://github.com/ygorgesteira/AEGIS.git
cd AEGIS
```

2. **Start the FastAPI Backend:**

In your first terminal window, launch the backend API server:

```bash
uvicorn backend.main:app --reload --port 8000
```

3. **Launch the Streamlit Frontend:**

In your second terminal window, run the UI client:

```bash
streamlit run frontend/app.py
```

## About the Project

AEGIS is developed by Ygor Gesteira as part of ongoing Master's research at the Instituto Federal da Paraíba (IFPB). The project focuses on machine learning applications for cybersecurity, specifically addressing the unique constraints and behavioral patterns of IoMT devices operating over private 5G networks.

## Contact

**Ygor Gesteira**

ygorgesteira@gmail.com
