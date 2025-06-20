✅ Requirements
Before running the script:

You must install scapy:

bash
pip install scapy
Run the script with administrator/root privileges, as packet sniffing requires elevated permissions:

bash
sudo python3 sniffer.py

# Start sniffing (you can set iface='eth0' or 'wlan0' depending on your system)
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=0)
⚙️ How It Works
sniff(...) captures packets in real-time.

prn=packet_callback tells Scapy to call packet_callback for each packet.

filter="ip" captures only IP-based traffic (can be adjusted to tcp, udp, icmp, etc.).

store=0 disables storing packets in memory (good for performance).

🔐 Important Notes
Use responsibly: Packet sniffing can intercept sensitive data; ensure you have permission.

Works best on Linux/macOS with admin/root rights.

For Windows, ensure WinPcap/Npcap is installed.
