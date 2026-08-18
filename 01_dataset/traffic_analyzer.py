import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


# ------------------------------------------
# Project paths
# ------------------------------------------

project_folder = Path(__file__).resolve().parent

data_file = project_folder / "network_traffic.csv"


# ------------------------------------------
# Create sample dataset
# ------------------------------------------

data = {
    "protocol": [
        "TCP", "TCP", "UDP", "TCP", "UDP",
        "TCP", "TCP", "UDP", "TCP", "TCP",
        "UDP", "TCP"
    ],

    "source_port": [
        443, 80, 53, 22, 53,
        443, 80, 53, 8080, 22,
        53, 443
    ],

    "destination_port": [
        5001, 5002, 6001, 7001, 6002,
        5003, 5004, 6003, 9001, 7002,
        6004, 5005
    ],

    "packet_size": [
        512, 420, 128, 850,
        110, 530, 450, 120,
        1500, 920, 100, 500
    ],

    "packet_count": [
        12, 15, 8, 40,
        6, 14, 18, 7,
        95, 55, 5, 13
    ],

    "connection_duration": [
        2.1, 1.8, 0.5, 8.2,
        0.4, 2.3, 2.8, 0.6,
        15.5, 11.2, 0.3, 2.0
    ],

    "label": [
        "NORMAL", "NORMAL", "NORMAL", "NORMAL",
        "NORMAL", "NORMAL", "NORMAL", "NORMAL",
        "SUSPICIOUS", "SUSPICIOUS", "NORMAL", "NORMAL"
    ]
}


df = pd.DataFrame(data)


# ------------------------------------------
# Save dataset
# ------------------------------------------

df.to_csv(
    data_file,
    index=False
)


# ------------------------------------------
# Display dataset
# ------------------------------------------

print("=" * 60)
print("        SMART NETWORK INTRUSION DETECTOR")
print("=" * 60)

print("\nDataset Preview")
print("-" * 60)

print(
    df.head().to_string(
        index=False
    )
)


# ------------------------------------------
# Dataset information
# ------------------------------------------

print("\nDataset Information")
print("-" * 60)

print(
    f"Total connections : {len(df)}"
)

print(
    f"Normal traffic    : "
    f"{(df['label'] == 'NORMAL').sum()}"
)

print(
    f"Suspicious traffic: "
    f"{(df['label'] == 'SUSPICIOUS').sum()}"
)


# ------------------------------------------
# Protocol analysis
# ------------------------------------------

print("\nProtocol Usage")
print("-" * 60)

print(
    df["protocol"].value_counts()
)


# ------------------------------------------
# Traffic visualization
# ------------------------------------------

traffic_counts = (
    df["label"]
    .value_counts()
)


plt.figure(
    figsize=(9, 6)
)

plt.bar(
    traffic_counts.index,
    traffic_counts.values
)

plt.title(
    "Network Traffic Classification",
    fontsize=18,
    fontweight="bold"
)

plt.xlabel(
    "Traffic Type"
)

plt.ylabel(
    "Number of Connections"
)

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.4
)

plt.tight_layout()


# Save figure
figure_path = (
    project_folder
    / "Figure_1.png"
)

plt.savefig(
    figure_path,
    dpi=300,
    bbox_inches="tight"
)

plt.show()


print(
    "\nVisualization saved to:"
)

print(
    figure_path
)
