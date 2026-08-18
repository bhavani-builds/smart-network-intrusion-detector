import pandas as pd


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 02 — DATA PREPROCESSING
# ==========================================


# ------------------------------------------
# File paths
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "01_dataset/network_traffic.csv"
)

output_file = (
    "C:/smart-network-intrusion-detector/"
    "02_preprocessing/clean_traffic.csv"
)


# ------------------------------------------
# Load dataset
# ------------------------------------------

df = pd.read_csv(
    input_file
)


print("=" * 60)
print("NETWORK TRAFFIC DATA PREPROCESSING")
print("=" * 60)


print("\nOriginal Dataset")
print("-" * 60)

print(df)


# ------------------------------------------
# Check missing values
# ------------------------------------------

print("\nMissing Values")
print("-" * 60)

print(
    df.isnull().sum()
)


# ------------------------------------------
# Check duplicates
# ------------------------------------------

duplicate_count = df.duplicated().sum()

print("\nDuplicate Rows")
print("-" * 60)

print(
    f"Duplicates found: {duplicate_count}"
)


# Remove duplicates

df = df.drop_duplicates()


# ------------------------------------------
# Convert protocol to numbers
# ------------------------------------------

protocol_mapping = {
    "TCP": 0,
    "UDP": 1
}

df["protocol_code"] = (
    df["protocol"].map(
        protocol_mapping
    )
)


# ------------------------------------------
# Convert labels to numbers
# ------------------------------------------

label_mapping = {
    "NORMAL": 0,
    "SUSPICIOUS": 1
}

df["label_code"] = (
    df["label"].map(
        label_mapping
    )
)


# ------------------------------------------
# Create final clean dataset
# ------------------------------------------

clean_columns = [
    "protocol_code",
    "source_port",
    "destination_port",
    "packet_size",
    "packet_count",
    "connection_duration",
    "label_code"
]


clean_df = df[
    clean_columns
]


# ------------------------------------------
# Display clean dataset
# ------------------------------------------

print("\nClean Dataset")
print("-" * 60)

print(
    clean_df
)


# ------------------------------------------
# Save clean dataset
# ------------------------------------------

clean_df.to_csv(
    output_file,
    index=False
)


print(
    "\n✅ Clean dataset saved!"
)

print(
    "\nLocation:"
)

print(
    output_file
)


print(
    "\n🎉 STAGE 02 COMPLETED!"
)
