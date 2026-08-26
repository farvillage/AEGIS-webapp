# AEGIS Web Application

Real-time intrusion detection and behavioral anomaly analysis platform for private 5G edge networks and Internet of Medical Things (IoMT) environments.

## Overview
AEGIS is an advanced machine learning cybersecurity framework designed to protect private 5G slicing architectures. This web application variant serves as an operator dashboard deployed via cloud infrastructure, capable of ingesting raw packet captures (.pcap, .pcapng) or pre-processed sensor telemetry datasets (.csv) to perform instant threat classification via optimized Random Forest models.

## Core Architecture

- Frontend: Built with Streamlit, providing an interactive dark-mode operator UI, telemetry metrics overview, and automated threat report logs.
- Backend: Built with FastAPI, handling asynchronous file routing, Scapy-based network packet parsing, and feature extraction.
- Inference Engine: Powered by a pre-trained Random Forest model (aegis_wustl_model.pkl) trained on benchmarks such as the WUSTL-EHMS-2020 dataset.

## Project Structure

```
AEGIS-webapp/
│
├── backend/
│   ├── main.py (FastAPI application endpoints)
│   ├── model.py (Feature alignment and ML inference pipeline)
│   └── parser.py (Scapy packet-to-flow aggregation logic)
│
├── frontend/
│   └── app.py (Streamlit web operator dashboard)
│
├── .streamlit/
│   └── config.toml (Global theme and color configuration)
│
├── aegis_wustl_model.pkl (Pre-trained Random Forest model weights)
├── aegisicon.png (Application branding icon)
├── requirements.txt (Python dependencies)
└── render.yaml (Cloud deployment blueprint)
```

## Local Setup & Installation

1. Clone the repository:
```    
bash
git clone https://github.com/farvillage/AEGIS-webapp.git
cd AEGIS-webapp
```    

2. Install dependencies:
```
bash
pip install -r requirements.txt
```

3. Start the FastAPI backend server:
```
bash
uvicorn backend.main:app --reload --port 8000
```

4. In a separate terminal window, launch the Streamlit frontend:
```
bash
streamlit run frontend/app.py
```

## Author
Ygor Gesteira

Master's Researcher @ Instituto Federal da Paraíba (IFPB)

Focusing on machine learning applications for cybersecurity in Internet of Medical Things (IoMT) over private 5G networks.
