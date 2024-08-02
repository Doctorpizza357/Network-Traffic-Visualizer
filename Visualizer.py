from scapy.all import sniff, IP
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# Initialize a list to store captured packet data
data = []

# Callback function to process captured packets
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

# Start packet capture
print("Starting packet capture...")
sniff(prn=packet_callback, count=100)

# Convert captured data to a Pandas DataFrame
df = pd.DataFrame(data)

# Count the number of packets by source IP
src_counts = Counter(df['Source'])

# Convert Counter to Pandas Series for easy plotting
src_counts_series = pd.Series(src_counts)

# Plot the number of packets by source IP
plt.figure(figsize=(10, 5))
src_counts_series.plot(kind='bar')
plt.title('Number of Packets by Source IP')
plt.xlabel('Source IP')
plt.ylabel('Packet Count')
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.show()
