from scapy.all import *
import csv

PORT_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    3389: "RDP"
}

csv_file = "../data/traffic.csv"

def packet_callback(packet):

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        src_port = "N/A"
        dst_port = "N/A"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        service = PORT_SERVICES.get(dst_port, "Unknown")

        print("\n=== Packet Detected ===")
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Source Port:", src_port)
        print("Destination Port:", dst_port)
        print("Service:", service)
        print("Protocol:", protocol)

        with open(csv_file, "a", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                service,
                protocol
            ])

print("=== ProbeR Started ===")
print("Capturing 10 packets...\n")

sniff(prn=packet_callback, count=10)

print("\nCapture Complete!")
