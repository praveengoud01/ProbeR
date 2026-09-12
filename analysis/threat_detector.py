import pandas as pd

print("=== ProbeR Threat Detector ===")

df = pd.read_csv("../data/traffic.csv", header=None)

for index, row in df.iterrows():

    protocol = row[5]

    if protocol == 6:
        print(f"⚠ Suspicious Traffic Detected -> {row[0]} -> {row[1]}")
    else:
        print(f"✅ Normal Traffic -> {row[0]} -> {row[1]}")
