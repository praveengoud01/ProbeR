import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

print("Loading traffic data...")

data = pd.read_csv(
    "../data/traffic.csv",
    header=None
)

data.columns = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "service",
    "protocol"
]

data["dst_port"] = pd.to_numeric(data["dst_port"], errors="coerce")
data["protocol"] = pd.to_numeric(data["protocol"], errors="coerce")

features = data[["dst_port", "protocol"]].fillna(0)

print("Training AI model...")

model = IsolationForest(
    contamination=0.2,
    random_state=42
)

model.fit(features)

joblib.dump(model, "../models/prober_model.pkl")

print("\nModel saved successfully!")
print("Location: ../models/prober_model.pkl")
