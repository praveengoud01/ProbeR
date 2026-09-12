
import pandas as pd
from sklearn.ensemble import IsolationForest

data = pd.read_csv(
    "../data/traffic.csv",
    header=None,
    names=["src_ip","dst_ip","src_port","dst_port","service","protocol"]
)

data["dst_port"] = pd.to_numeric(data["dst_port"], errors="coerce")
data["protocol"] = pd.to_numeric(data["protocol"], errors="coerce")

features = data[["dst_port","protocol"]].fillna(0)

model = IsolationForest(contamination=0.2, random_state=42)
model.fit(features)

predictions = model.predict(features)

data["anomaly"] = predictions

print("\n=== ProbeR AI Analysis ===\n")

for i, row in data.iterrows():
    if row["anomaly"] == -1:
        print(
            f"Suspicious Traffic -> Port {row['dst_port']} "
            f"Protocol {row['protocol']}"
        )
    else:
        print(
            f"Normal Traffic -> Port {row['dst_port']} "
            f"Protocol {row['protocol']}"
        )
