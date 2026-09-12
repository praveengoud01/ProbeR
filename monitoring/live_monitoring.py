import time
import random

print("=== ProbeR Live Threat Monitor ===")

while True:
    threats = [
        "Normal Traffic",
        "HTTPS Connection",
        "DNS Request",
        "Port Scan Detected",
        "Suspicious IP Detected"
    ]

    print(f"[ALERT] {random.choice(threats)}")
    time.sleep(3)
