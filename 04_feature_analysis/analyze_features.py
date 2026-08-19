import pandas as pd
import matplotlib.pyplot as plt


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 04 — FEATURE ANALYSIS
# ==========================================


# Load the original dataset
input_file = (
    "C:/smart-network-intrusion-detector/"
    "01_dataset/network_traffic.csv"
)

output_folder = (
    "C:/smart-network-intrusion-detector/"
    "04_feature_analysis/"
)


df = pd.read_csv(input_file)


print("=" * 60)
print("NETWORK FEATURE ANALYSIS")
print("=" * 60)


# ------------------------------------------
# Select numerical features
# ------------------------------------------

features = [
    "source_port",
    "destination_port",
    "packet_size",
    "packet_count",
    "connection_duration"
]


feature_data = df[features]


# ------------------------------------------
# Calculate correlations
# ------------------------------------------

correlation = feature_data.corr()


print("\nFeature Correlation")
print("-" * 60)

print(
    correlation.round(2)
)


# ------------------------------------------
# Create correlation heatmap
# ------------------------------------------

plt.figure(
    figsize=(10, 7)
)

plt.imshow(
    correlation,
    interpolation="nearest"
)

plt.colorbar(
    label="Correlation"
)


plt.xticks(
    range(len(features)),
    features,
    rotation=45,
    ha="right"
)

plt.yticks(
    range(len(features)),
    features
)


# Add values to the heatmap

for row in range(len(features)):

    for column in range(len(features)):

        value = correlation.iloc[
            row,
            column
        ]

        plt.text(
            column,
            row,
            f"{value:.2f}",
            ha="center",
            va="center"
        )


plt.title(
    "Network Feature Correlation",
    fontsize=18,
    fontweight="bold"
)

plt.tight_layout()


# Save figure

figure_path = (
    output_folder
    + "Figure_4_correlation.png"
)

plt.savefig(
    figure_path,
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ------------------------------------------
# Compare normal and suspicious traffic
# ------------------------------------------

print(
    "\nAverage Feature Values"
)

print("-" * 60)


summary = (
    df.groupby("label")[features]
    .mean()
    .round(2)
)


print(
    summary
)


# ------------------------------------------
# Save summary
# ------------------------------------------

summary.to_csv(
    output_folder
    + "feature_summary.csv"
)


print(
    "\n✅ Feature correlation calculated."
)

print(
    "✅ Feature summary created."
)

print(
    "\n🎉 STAGE 04 COMPLETED!"
)
