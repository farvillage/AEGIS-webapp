from scapy.all import PcapReader, IP, TCP, UDP
import pandas as pd

def extract_features_from_pcap(pcap_path):
    packet_data = []
    
    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                protocol = pkt[IP].proto
                pkt_len = len(pkt)
                
                src_port = 0
                dst_port = 0
                
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                
                packet_data.append({
                    "src_ip": ip_src,
                    "dst_ip": ip_dst,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_length": pkt_len,
                    "timestamp": float(pkt.time)
                })
            
    return pd.DataFrame(packet_data)