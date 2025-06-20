from scapy.all import sniff, IP, TCP, UDP

# Callback function to process captured packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            print(f"[TCP] {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif UDP in packet:
            print(f"[UDP] {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
        else:
            print(f"[IP] {ip_src} -> {ip_dst} (Protocol: {proto})")

# Start sniffing (you can set iface='eth0' or 'wlan0' depending on your system)
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=0)
