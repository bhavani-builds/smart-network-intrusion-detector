import pandas as pd
from datetime import datetime


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 10 — SECURITY ALERT SYSTEM
# ==========================================


# ------------------------------------------
# File paths
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "08_risk_score/risk_results.csv"
)

output_file = (
    "C:/smart-network-intrusion-detector/"
    "10_alert_system/security_alerts.csv"
)


# ------------------------------------------
# Load risk results
# ------------------------------------------

df = pd.read_csv(
    input_file
)


print("=" * 65)
print("              SECURITY ALERT SYSTEM")
print("=" * 65)


# ------------------------------------------
# Find high-risk connections
# ------------------------------------------

high_risk = df[
    df["risk_level"] == "HIGH"
].copy()


# ------------------------------------------
# Create alerts
# ------------------------------------------

alerts = []


for index, row in high_risk.iterrows():

    alert = {

        "alert_time":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "connection_id":
            index + 1,

        "risk_score":
            row["risk_score"],

        "risk_level":
            row["risk_level"],

        "packet_size":
            row["packet_size"],

        "packet_count":
            row["packet_count"],

        "connection_duration":
            row["connection_duration"],

        "message":
            "High-risk network activity detected"

    }

    alerts.append(alert)


# ------------------------------------------
# Create alert DataFrame
# ------------------------------------------

if alerts:

    alert_df = pd.DataFrame(
        alerts
    )

else:

    alert_df = pd.DataFrame(
        columns=[
            "alert_time",
            "connection_id",
            "risk_score",
            "risk_level",
            "packet_size",
            "packet_count",
            "connection_duration",
            "message"
        ]
    )


# ------------------------------------------
# Display alerts
# ------------------------------------------

print(
    "\nSecurity Alerts"
)

print(
    "-" * 65
)


if len(alert_df) > 0:

    for _, alert in alert_df.iterrows():

        print(
            "\n🚨 SECURITY ALERT"
        )

        print(
            f"Connection ID : "
            f"{alert['connection_id']}"
        )

        print(
            f"Risk Score    : "
            f"{alert['risk_score']}/100"
        )

        print(
            f"Risk Level    : "
            f"{alert['risk_level']}"
        )

        print(
            f"Packet Size   : "
            f"{alert['packet_size']} bytes"
        )

        print(
            f"Packet Count  : "
            f"{alert['packet_count']}"
        )

        print(
            f"Duration      : "
            f"{alert['connection_duration']} seconds"
        )

        print(
            "Action        : "
            "Investigate this connection."
        )

else:

    print(
        "\n✅ No high-risk connections detected."
    )


# ------------------------------------------
# Save alerts
# ------------------------------------------

alert_df.to_csv(
    output_file,
    index=False
)


# ------------------------------------------
# Summary
# ------------------------------------------

print(
    "\n" + "=" * 65
)

print(
    f"Total alerts generated: "
    f"{len(alert_df)}"
)

print(
    "\nAlerts saved to:"
)

print(
    output_file
)

print(
    "\n🎉 STAGE 10 COMPLETED!"
)
