import os
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from backend.model import run_inference
from backend.parser import process_pcap_to_flows

app = FastAPI(title="AEGIS Threat Intelligence API", version="2.0")

@app.get("/")
def health_check():
    return {"status": "online", "system": "AEGIS 5G Edge Engine"}

@app.post("/api/analyze-csv")
async def analyze_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Expected .csv")
    try:
        df = pd.read_csv(file.file)
        df_result, attack_count = run_inference(df)
        return {
            "filename": file.filename,
            "total_rows": len(df_result),
            "attack_count": attack_count,
            "data": df_result.to_dict(orient="records")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Receives a raw .pcap/.pcapng file, parses packets, aggregates flows, and runs ML inference."""
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type. Expected .pcap or .pcapng")
    
    temp_file_path = f"temp_{file.filename}"
    try:
        # Save buffer temporarily to disk so Scapy can inspect it
        contents = await file.read()
        with open(temp_file_path, "wb") as f:
            f.write(contents)
            
        df_flows = process_pcap_to_flows(temp_file_path)
        
        if df_flows.empty:
            raise HTTPException(status_code=400, detail="No valid IP packets detected in capture.")
            
        df_result, attack_count = run_inference(df_flows)
        
        return {
            "filename": file.filename,
            "total_rows": len(df_result),
            "attack_count": attack_count,
            "data": df_result.to_dict(orient="records")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)