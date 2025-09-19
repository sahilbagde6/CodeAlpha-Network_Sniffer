# CodeAlpha-Network_Sniffer
👉 This is a basic sniffer which will capture IP layer packets and print the source, destination and protocol.

# CodeAlpha_NetworkSniffer

## 🚀 Overview
A simple Python-based network sniffer built for the CodeAlpha Cyber Security Internship.  
Captures network packets, parses IP/TCP/UDP details, and prints useful information for analysis and demo purposes.

---

## 🛠 Requirements
- Python 3.8+
- `scapy` (`pip install scapy`)
- (Optional) Run as root for live interface capture

---

## ⚡ Quick Setup
1. Create virtualenv (optional):
```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy

2. Run the sniffer (demo mode - capture 10 packets):


sudo python3 network_sniffer.py


📄 Example Script (network_sniffer.py)

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        info = f"{src} -> {dst} | proto:{proto}"
        # TCP/UDP ports if available
        if TCP in packet:
            info += f" | TCP sport:{packet[TCP].sport} dport:{packet[TCP].dport}"
        elif UDP in packet:
            info += f" | UDP sport:{packet[UDP].sport} dport:{packet[UDP].dport}"
        print(info)

if __name__ == "__main__":
    # capture 10 packets for demo, remove count for continuous capture
    sniff(prn=packet_callback, count=10)


---

🔒 Notes & Ethics

Use only on networks you own or are authorized to test.

Running packet capture may require root privileges.

For full analysis, consider saving to PCAP: sniff(..., prn=lambda p: p.summary(), store=True) and use Wireshark.
