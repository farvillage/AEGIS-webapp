import os
import pandas as pd
from scapy.all import IP, rdpcap

def extract_features_from_pcap(file_path):
    """Parses raw pcap packets using Scapy and extracts basic metrics."""
    packets = rdpcap(file_path)
    packet_data = []

    for pkt in packets:
        if IP in pkt:
            packet_data.append({
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'src_port': int(pkt.sport) if hasattr(pkt, 'sport') else 0,
                'dst_port': int(pkt.dport) if hasattr(pkt, 'dport') else 0,
                'protocol': int(pkt[IP].proto),
                'packet_length': len(pkt)
            })
            
    return pd.DataFrame(packet_data)

def process_pcap_to_flows(file_path):
    """Aggregates raw packets into standardized network flows for the model."""
    df_packets = extract_features_from_pcap(file_path)
    
    if df_packets.empty:
        return pd.DataFrame()
        
    df_flows = df_packets.groupby(
        ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    ).agg(
        total_packets=('packet_length', 'count'),
        total_bytes=('packet_length', 'sum'),
        start_time=('timestamp', 'min'),
        end_time=('timestamp', 'max')
    ).reset_index()
    
    # Calculate duration safely
    df_flows['flow_duration_sec'] = df_flows['end_time'] - df_flows['start_time']
    df_flows['flow_duration_sec'] = df_flows['flow_duration_sec'].replace(0, 0.000001)
    
    # Throughput features
    df_flows['packets_per_sec'] = df_flows['total_packets'] / df_flows['flow_duration_sec']
    df_flows['bytes_per_sec'] = df_flows['total_bytes'] / df_flows['flow_duration_sec']
    
    df_flows = df_flows.drop(columns=['start_time', 'end_time'])
    return df_flows