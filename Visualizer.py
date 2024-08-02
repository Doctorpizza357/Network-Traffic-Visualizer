from scapy.all import sniff, IP
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

data = []

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        data.append({
            "Source": ip_src,
            "Destination": ip_dst,
            "Protocol": protocol,
            "Size": packet_size
        })

print("Starting packet capture...")
sniff(prn=packet_callback, count=100)

df = pd.DataFrame(data)

src_counts = Counter(df['Source'])

src_counts_series = pd.Series(src_counts)

plt.figure(figsize=(10, 5))
src_counts_series.plot(kind='bar')
plt.title('Number of Packets by Source IP')
plt.xlabel('Source IP')
plt.ylabel('Packet Count')
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.show()
