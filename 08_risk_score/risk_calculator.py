import pandas as pd

from sklearn.ensemble import RandomForestClassifier


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 08 — RISK SCORE
# ==========================================


# ------------------------------------------
# Load dataset
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "02_preprocessing/clean_traffic.csv"
)

df = pd.read_csv(input_file)


# ------------------------------------------
# Features
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

y = df["label_code"]


# ------------------------------------------
# Train prototype classifier
# ------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)


# ------------------------------------------
# Get suspicious probability
# ------------------------------------------

probabilities = model.predict_proba(X)


classes = list(model.classes_)


if 1 in classes:

    suspicious_index = classes.index(1)

    suspicious_probability = (
        probabilities[:, suspicious_index]
    )

else:

    suspicious_probability = (
        [0] * len(df)
    )


# ------------------------------------------
# Create risk score
# ------------------------------------------

risk_scores = []


for index, row in df.iterrows():

    ml_risk = (
        suspicious_probability[index]
        * 60
    )


    # Packet count contribution
    if row["packet_count"] > 50:

        traffic_risk = 25

    elif row["packet_count"] > 25:

        traffic_risk = 15

    else:

        traffic_risk = 5


    # Connection duration contribution
    if row["connection_duration"] > 10:

        duration_risk = 15

    elif row["connection_duration"] > 5:

        duration_risk = 8

    else:

        duration_risk = 3


    total_score = (
        ml_risk
        + traffic_risk
        + duration_risk
    )


    # Keep score between 0 and 100
    total_score = min(
        round(total_score),
        100
    )


    risk_scores.append(
        total_score
    )


df["risk_score"] = risk_scores


# ------------------------------------------
# Risk level
# ------------------------------------------

def get_risk_level(score):

    if score >= 70:

        return "HIGH"

    elif score >= 40:

        return "MEDIUM"

    else:

        return "LOW"


df["risk_level"] = (
    df["risk_score"]
    .apply(get_risk_level)
)


# ------------------------------------------
# Display results
# ------------------------------------------

print("=" * 65)
print("              NETWORK RISK ANALYSIS")
print("=" * 65)


for index, row in df.iterrows():

    print(
        f"\nConnection {index + 1}"
    )

    print(
        f"  Packet Size : "
        f"{row['packet_size']} bytes"
    )

    print(
        f"  Packet Count: "
        f"{row['packet_count']}"
    )

    print(
        f"  Duration    : "
        f"{row['connection_duration']} seconds"
    )

    print(
        f"  Risk Score  : "
        f"{row['risk_score']}/100"
    )

    print(
        f"  Risk Level  : "
        f"{row['risk_level']}"
    )


# ------------------------------------------
# Summary
# ------------------------------------------

print("\n" + "=" * 65)
print("RISK SUMMARY")
print("=" * 65)


print(
    "\nAverage Risk Score:",
    round(
        df["risk_score"].mean(),
        2
    )
)


print(
    "\nRisk Level Counts:"
)

print(
    df["risk_level"].value_counts()
)


# ------------------------------------------
# Save results
# ------------------------------------------

output_folder = (
    "C:/smart-network-intrusion-detector/"
    "08_risk_score/"
)


df.to_csv(
    output_folder
    + "risk_results.csv",
    index=False
)


print(
    "\n✅ Risk results saved!"
)

print(
    "\n🎉 STAGE 08 COMPLETED!"
)
