import csv
from collections import Counter

port_counter = Counter()

with open("../data/traffic.csv", "r") as file:
    reader = csv.reader(file)

    for row in reader:
        if len(row) >= 5:
            port = row[3]
            port_counter[port] += 1

print("\n=== ProbeR Port Analysis ===\n")

for port, count in port_counter.most_common():
    print(f"Port {port}: {count} packets")
