import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 06 — MODEL EVALUATION
# ==========================================


# ------------------------------------------
# Load clean dataset
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "02_preprocessing/clean_traffic.csv"
)

df = pd.read_csv(input_file)


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
# Split data
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


# ------------------------------------------
# Train model
# ------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(
    X_train,
    y_train
)


# ------------------------------------------
# Predictions
# ------------------------------------------

predictions = model.predict(
    X_test
)


# ------------------------------------------
# Calculate metrics
# ------------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)


# ------------------------------------------
# Display results
# ------------------------------------------

print("=" * 60)
print("              MODEL EVALUATION")
print("=" * 60)

print(
    f"\nAccuracy  : {accuracy:.2f}"
)

print(
    f"Precision : {precision:.2f}"
)

print(
    f"Recall    : {recall:.2f}"
)

print(
    f"F1 Score  : {f1:.2f}"
)


# ------------------------------------------
# Confusion matrix
# ------------------------------------------

matrix = confusion_matrix(
    y_test,
    predictions
)


print("\nConfusion Matrix")
print("-" * 60)

print(matrix)


# ------------------------------------------
# Display confusion matrix
# ------------------------------------------

display = ConfusionMatrixDisplay(
    confusion_matrix=matrix,
    display_labels=[
        "NORMAL",
        "SUSPICIOUS"
    ]
)

display.plot()

plt.title(
    "Network Intrusion Detection\nConfusion Matrix",
    fontsize=16,
    fontweight="bold"
)

plt.tight_layout()


# ------------------------------------------
# Save figure
# ------------------------------------------

output_folder = (
    "C:/smart-network-intrusion-detector/"
    "06_model_evaluation/"
)

plt.savefig(
    output_folder
    + "Figure_6_confusion_matrix.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ------------------------------------------
# Final message
# ------------------------------------------

print(
    "\n✅ Model evaluation completed!"
)

print(
    "\n🎉 STAGE 06 COMPLETED!"
)
