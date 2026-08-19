import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 05 — MACHINE LEARNING
# ==========================================


# ------------------------------------------
# File paths
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "02_preprocessing/clean_traffic.csv"
)


# ------------------------------------------
# Load clean dataset
# ------------------------------------------

df = pd.read_csv(
    input_file
)


print("=" * 60)
print("MACHINE LEARNING INTRUSION DETECTION")
print("=" * 60)


print(
    f"\nTotal samples: {len(df)}"
)


# ------------------------------------------
# Select features
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
# Split dataset
# ------------------------------------------

X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )
)


print(
    f"\nTraining samples: {len(X_train)}"
)

print(
    f"Testing samples : {len(X_test)}"
)


# ------------------------------------------
# Create Random Forest model
# ------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# ------------------------------------------
# Train
# ------------------------------------------

model.fit(
    X_train,
    y_train
)


print(
    "\n✅ Model training completed."
)


# ------------------------------------------
# Predict
# ------------------------------------------

predictions = model.predict(
    X_test
)


# ------------------------------------------
# Accuracy
# ------------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)


print(
    f"\nAccuracy: "
    f"{accuracy * 100:.2f}%"
)


# ------------------------------------------
# Classification report
# ------------------------------------------

print(
    "\nClassification Report"
)

print(
    "-" * 60
)

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "NORMAL",
            "SUSPICIOUS"
        ],
        zero_division=0
    )
)


# ------------------------------------------
# Feature importance
# ------------------------------------------

importance = model.feature_importances_


feature_importance = pd.DataFrame({

    "feature": features,

    "importance": importance

})


feature_importance = (
    feature_importance
    .sort_values(
        "importance",
        ascending=False
    )
)


print(
    "\nFeature Importance"
)

print(
    "-" * 60
)

print(
    feature_importance.to_string(
        index=False
    )
)


print(
    "\n🎉 STAGE 05 COMPLETED!"
)
