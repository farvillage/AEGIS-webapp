import os
import joblib
import pandas as pd

# Constants for threat classification
LABEL_ATTACK = "[ATTACK DETECTED]"
LABEL_NORMAL = "[NORMAL TRAFFIC]"

def load_trained_model():
    """Loads the pre-trained Random Forest model."""
    model_path = os.path.join(os.path.dirname(__file__), "../aegis_wustl_model.pkl")
    if not os.path.exists(model_path):
        model_path = "aegis_wustl_model.pkl" # Fallback to root if needed
    return joblib.load(model_path)

def ip_to_int(ip_str):
    """Safely converts an IP string to a numeric float for the model."""
    if pd.isna(ip_str) or not isinstance(ip_str, str):
        return 0.0
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            return float(int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3]))
    except Exception:
        pass
    # Fallback to hash if it's not a standard IPv4 format
    return float(abs(hash(ip_str)) % 100000)

def align_dataset_features(df_input, expected_features):
    """
    Translates raw dataset columns into standardized, numeric AEGIS features.
    """
    df = df_input.copy()
    df_aligned = pd.DataFrame()
    
    # Standardized IP Translation & Numeric Conversion
    src_raw = df['SrcAddr'] if 'SrcAddr' in df.columns else (df['src_ip'] if 'src_ip' in df.columns else 0)
    dst_raw = df['DstAddr'] if 'DstAddr' in df.columns else (df['dst_ip'] if 'dst_ip' in df.columns else 0)
    
    df_aligned['Src_IP'] = src_raw.apply(ip_to_int) if hasattr(src_raw, 'apply') else 0.0
    df_aligned['Dst_IP'] = dst_raw.apply(ip_to_int) if hasattr(dst_raw, 'apply') else 0.0
    
    # Data Volume translation
    if 'TotBytes' in df.columns:
        df_aligned['Data_Volume_Bytes'] = pd.to_numeric(df['TotBytes'], errors='coerce').fillna(0.0)
    elif 'SrcBytes' in df.columns and 'DstBytes' in df.columns:
        df_aligned['Data_Volume_Bytes'] = pd.to_numeric(df['SrcBytes'], errors='coerce').fillna(0.0) + pd.to_numeric(df['DstBytes'], errors='coerce').fillna(0.0)
    elif 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
        df_aligned['Data_Volume_Bytes'] = pd.to_numeric(df['src_bytes'], errors='coerce').fillna(0.0) + pd.to_numeric(df['dst_bytes'], errors='coerce').fillna(0.0)
    else:
        df_aligned['Data_Volume_Bytes'] = 0.0
        
    # Access Frequency translation
    if 'Rate' in df.columns:
        df_aligned['Access_Frequency'] = pd.to_numeric(df['Rate'], errors='coerce').fillna(0.0)
    elif 'TotPkts' in df.columns:
        df_aligned['Access_Frequency'] = pd.to_numeric(df['TotPkts'], errors='coerce').fillna(0.0)
    else:
        df_aligned['Access_Frequency'] = 0.0
        
    # Derived telemetry attributes mapped to floats
    df_aligned['Device_Type'] = pd.to_numeric(df['sMaxPktSz'], errors='coerce').fillna(1.0) if 'sMaxPktSz' in df.columns else 1.0
    df_aligned['Vendor_Identifier'] = pd.to_numeric(df['Sport'], errors='coerce').fillna(0.0) if 'Sport' in df.columns else (pd.to_numeric(df['src_port'], errors='coerce').fillna(0.0) if 'src_port' in df.columns else 0.0)
    df_aligned['Geo_Variability'] = pd.to_numeric(df['Dur'], errors='coerce').fillna(0.0) if 'Dur' in df.columns else (pd.to_numeric(df['duration'], errors='coerce').fillna(0.0) if 'duration' in df.columns else 0.0)
    
    if 'Flgs' in df.columns:
        df_aligned['Support_Session_Active'] = df['Flgs'].apply(lambda x: 1.0 if pd.notna(x) else 0.0)
    else:
        df_aligned['Support_Session_Active'] = 1.0

    # Enforce exact expected model features as floats
    for col in expected_features:
        if col not in df_aligned.columns:
            df_aligned[col] = 0.0
            
    df_aligned = df_aligned[expected_features].astype(float)
    df_aligned.fillna(0.0, inplace=True)
    return df_aligned

def run_inference(df_input):
    """Runs the model inference on a standardized pandas DataFrame."""
    model = load_trained_model()
    expected_features = model.feature_names_in_
    
    df_prepared = align_dataset_features(df_input, expected_features)
    predictions = model.predict(df_prepared)
    print("Unique model predictions found:", set(predictions))
    
    df_result = df_input.copy()
    
    # Map predictions to labels
    df_result['threat_detection'] = [
        LABEL_ATTACK if int(x) == 1 else LABEL_NORMAL 
        for x in predictions
    ]
    
    attack_count = int((predictions == 1).sum())
    return df_result, attack_count