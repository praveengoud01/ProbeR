import csv
from collections import Counter

SAFE_PORTS = [80, 443, 53]

port_counter = Counter()

with open("../data/traffic.csv", "r") as file:
    reader = csv.reader(file)

    for row in reader:
        if len(row) >= 5:
            try:
                port = int(row[3])
                port_counter[port] += 1
            except:
                pass

risk_score = 0

for port in port_counter:
    if port not in SAFE_PORTS:
        risk_score += 10

if risk_score <= 20:
    status = "SAFE"
elif risk_score <= 50:
    status = "WARNING"
else:
    status = "HIGH RISK"

print("\n=== ProbeR Security Report ===")
print("Risk Score:", risk_score)
print("Status:", status)
