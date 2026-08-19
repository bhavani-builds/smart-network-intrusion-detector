import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 07 — ANOMALY DETECTION
# ==========================================


# Load clean dataset

input_file = (
    "C:/smart-network-intrusion-detector/"
    "02_preprocessing/clean_traffic.csv"
)

df = pd.read_csv(input_file)


# ------------------------------------------
# Select network features
# ------------------------------------------

features = [
    "protocol_code",
    "source_port",
    "destination_port",
    "packet_size",
    "packet_count",
    "connection_duration"
]

X = df[features]


# ------------------------------------------
# Create Isolation Forest
# ------------------------------------------

model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)


# Train model

model.fit(X)


# ------------------------------------------
# Detect anomalies
# ------------------------------------------

predictions = model.predict(X)


# Isolation Forest returns:
#
#  1  = normal
# -1  = anomaly


df["anomaly_result"] = predictions


df["anomaly_status"] = (
    df["anomaly_result"]
    .map({
        1: "NORMAL",
        -1: "ANOMALY"
    })
)


# ------------------------------------------
# Display results
# ------------------------------------------

print("=" * 60)
print("              ANOMALY DETECTION")
print("=" * 60)

print(
    "\nTraffic Analysis"
)

print("-" * 60)

print(
    df[
        [
            "packet_size",
            "packet_count",
            "connection_duration",
            "anomaly_status"
        ]
    ].to_string(index=False)
)


# ------------------------------------------
# Count anomalies
# ------------------------------------------

anomaly_count = (
    df["anomaly_status"] == "ANOMALY"
).sum()


normal_count = (
    df["anomaly_status"] == "NORMAL"
).sum()


print(
    f"\nNormal connections : {normal_count}"
)

print(
    f"Anomalies detected : {anomaly_count}"
)


# ------------------------------------------
# Visualization
# ------------------------------------------

plt.figure(
    figsize=(10, 6)
)


normal = df[
    df["anomaly_status"] == "NORMAL"
]

anomalies = df[
    df["anomaly_status"] == "ANOMALY"
]


plt.scatter(
    normal["connection_duration"],
    normal["packet_count"],
    label="Normal",
    s=80
)


plt.scatter(
    anomalies["connection_duration"],
    anomalies["packet_count"],
    label="Anomaly",
    s=120
)


plt.title(
    "Network Anomaly Detection",
    fontsize=18,
    fontweight="bold"
)

plt.xlabel(
    "Connection Duration (seconds)"
)

plt.ylabel(
    "Packet Count"
)

plt.legend()

plt.grid(
    linestyle="--",
    alpha=0.4
)

plt.tight_layout()


# ------------------------------------------
# Save graph
# ------------------------------------------

output_folder = (
    "C:/smart-network-intrusion-detector/"
    "07_anomaly_detection/"
)

plt.savefig(
    output_folder
    + "Figure_7_anomaly_detection.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ------------------------------------------
# Save results
# ------------------------------------------

df.to_csv(
    output_folder
    + "anomaly_results.csv",
    index=False
)


print(
    "\n✅ Anomaly detection completed!"
)

print(
    "✅ Results saved!"
)

print(
    "\n🎉 STAGE 07 COMPLETED!"
)
