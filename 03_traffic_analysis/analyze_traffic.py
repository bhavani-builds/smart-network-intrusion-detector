import pandas as pd
import matplotlib.pyplot as plt


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 03 — TRAFFIC ANALYSIS
# ==========================================


# ------------------------------------------
# File paths
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "01_dataset/network_traffic.csv"
)

output_folder = (
    "C:/smart-network-intrusion-detector/"
    "03_traffic_analysis/"
)


# ------------------------------------------
# Load dataset
# ------------------------------------------

df = pd.read_csv(
    input_file
)


print("=" * 60)
print("NETWORK TRAFFIC ANALYSIS")
print("=" * 60)


# ==========================================
# 1. PACKET SIZE ANALYSIS
# ==========================================

plt.figure(
    figsize=(9, 6)
)

plt.hist(
    df["packet_size"],
    bins=8,
    edgecolor="black"
)

plt.title(
    "Packet Size Distribution",
    fontsize=18,
    fontweight="bold"
)

plt.xlabel(
    "Packet Size (bytes)"
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

plt.savefig(
    output_folder
    + "Figure_3_1_packet_size.png",
    dpi=300
)

plt.show()


# ==========================================
# 2. PACKET COUNT VS DURATION
# ==========================================

plt.figure(
    figsize=(9, 6)
)

normal = df[
    df["label"] == "NORMAL"
]

suspicious = df[
    df["label"] == "SUSPICIOUS"
]


plt.scatter(
    normal["connection_duration"],
    normal["packet_count"],
    label="Normal",
    s=80
)

plt.scatter(
    suspicious["connection_duration"],
    suspicious["packet_count"],
    label="Suspicious",
    s=100
)

plt.title(
    "Packet Count vs Connection Duration",
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

plt.savefig(
    output_folder
    + "Figure_3_2_packet_duration.png",
    dpi=300
)

plt.show()


# ==========================================
# 3. NORMAL VS SUSPICIOUS
# ==========================================

traffic_counts = (
    df["label"].value_counts()
)


plt.figure(
    figsize=(8, 6)
)

plt.bar(
    traffic_counts.index,
    traffic_counts.values,
    edgecolor="black"
)

plt.title(
    "Normal vs Suspicious Traffic",
    fontsize=18,
    fontweight="bold"
)

plt.xlabel(
    "Traffic Classification"
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

plt.savefig(
    output_folder
    + "Figure_3_3_traffic_classification.png",
    dpi=300
)

plt.show()


# ==========================================
# PRINT ANALYSIS
# ==========================================

print("\nTraffic Statistics")
print("-" * 60)

print(
    f"Average packet size: "
    f"{df['packet_size'].mean():.2f} bytes"
)

print(
    f"Average packet count: "
    f"{df['packet_count'].mean():.2f}"
)

print(
    f"Average connection duration: "
    f"{df['connection_duration'].mean():.2f} seconds"
)


print("\nSuspicious Traffic Statistics")
print("-" * 60)

if len(suspicious) > 0:

    print(
        f"Average packet size: "
        f"{suspicious['packet_size'].mean():.2f} bytes"
    )

    print(
        f"Average packet count: "
        f"{suspicious['packet_count'].mean():.2f}"
    )

    print(
        f"Average duration: "
        f"{suspicious['connection_duration'].mean():.2f} seconds"
    )


print("\n✅ Three traffic analysis graphs created.")

print("\n🎉 STAGE 03 COMPLETED!")
