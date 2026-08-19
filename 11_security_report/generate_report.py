import pandas as pd
from datetime import datetime


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 11 — AUTOMATED SECURITY REPORT
# ==========================================


# ------------------------------------------
# File paths
# ------------------------------------------

risk_file = (
    "C:/smart-network-intrusion-detector/"
    "08_risk_score/risk_results.csv"
)

alert_file = (
    "C:/smart-network-intrusion-detector/"
    "10_alert_system/security_alerts.csv"
)

report_file = (
    "C:/smart-network-intrusion-detector/"
    "11_security_report/"
    "network_security_report.txt"
)


# ------------------------------------------
# Load data
# ------------------------------------------

risk_df = pd.read_csv(
    risk_file
)

alert_df = pd.read_csv(
    alert_file
)


# ------------------------------------------
# Calculate statistics
# ------------------------------------------

total_connections = len(
    risk_df
)

normal_connections = (
    risk_df["label_code"] == 0
).sum()

suspicious_connections = (
    risk_df["label_code"] == 1
).sum()

high_risk_connections = (
    risk_df["risk_level"] == "HIGH"
).sum()

medium_risk_connections = (
    risk_df["risk_level"] == "MEDIUM"
).sum()

low_risk_connections = (
    risk_df["risk_level"] == "LOW"
).sum()

average_risk = (
    risk_df["risk_score"].mean()
)


# ------------------------------------------
# Determine overall status
# ------------------------------------------

if high_risk_connections > 0:

    overall_status = (
        "ATTENTION REQUIRED"
    )

elif medium_risk_connections > 0:

    overall_status = (
        "MONITOR NETWORK"
    )

else:

    overall_status = (
        "NORMAL"
    )


# ------------------------------------------
# Create report
# ------------------------------------------

with open(
    report_file,
    "w",
    encoding="utf-8"
) as report:

    report.write(
        "=" * 70 + "\n"
    )

    report.write(
        "             SMART NETWORK SECURITY REPORT\n"
    )

    report.write(
        "=" * 70 + "\n\n"
    )


    # --------------------------------------
    # Report information
    # --------------------------------------

    report.write(
        "REPORT INFORMATION\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        "Generated: "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        + "\n"
    )

    report.write(
        "System: Smart Network Intrusion Detector\n\n"
    )


    # --------------------------------------
    # Overall status
    # --------------------------------------

    report.write(
        "OVERALL SECURITY STATUS\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        f"Status: {overall_status}\n"
    )

    report.write(
        f"Average Risk Score: "
        f"{average_risk:.2f}/100\n\n"
    )


    # --------------------------------------
    # Traffic summary
    # --------------------------------------

    report.write(
        "TRAFFIC SUMMARY\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        f"Total Connections     : "
        f"{total_connections}\n"
    )

    report.write(
        f"Normal Connections    : "
        f"{normal_connections}\n"
    )

    report.write(
        f"Suspicious Connections: "
        f"{suspicious_connections}\n\n"
    )


    # --------------------------------------
    # Risk summary
    # --------------------------------------

    report.write(
        "RISK SUMMARY\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        f"Low Risk Connections   : "
        f"{low_risk_connections}\n"
    )

    report.write(
        f"Medium Risk Connections: "
        f"{medium_risk_connections}\n"
    )

    report.write(
        f"High Risk Connections  : "
        f"{high_risk_connections}\n\n"
    )


    # --------------------------------------
    # Security alerts
    # --------------------------------------

    report.write(
        "SECURITY ALERTS\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        f"Total Alerts: "
        f"{len(alert_df)}\n\n"
    )


    if len(alert_df) > 0:

        for _, alert in alert_df.iterrows():

            report.write(
                f"Alert — Connection "
                f"{alert['connection_id']}\n"
            )

            report.write(
                f"  Risk Score : "
                f"{alert['risk_score']}/100\n"
            )

            report.write(
                f"  Risk Level : "
                f"{alert['risk_level']}\n"
            )

            report.write(
                f"  Packet Size: "
                f"{alert['packet_size']} bytes\n"
            )

            report.write(
                f"  Packets    : "
                f"{alert['packet_count']}\n"
            )

            report.write(
                f"  Duration   : "
                f"{alert['connection_duration']} seconds\n"
            )

            report.write(
                "  Action     : "
                "Investigate the connection.\n\n"
            )

    else:

        report.write(
            "No security alerts were generated.\n\n"
        )


    # --------------------------------------
    # Recommendations
    # --------------------------------------

    report.write(
        "RECOMMENDATIONS\n"
    )

    report.write(
        "-" * 70 + "\n"
    )


    if high_risk_connections > 0:

        report.write(
            "1. Investigate all high-risk connections.\n"
        )

        report.write(
            "2. Review unusually high packet activity.\n"
        )

        report.write(
            "3. Verify suspicious connection durations.\n"
        )

        report.write(
            "4. Perform additional security analysis "
            "before taking action.\n"
        )

    elif medium_risk_connections > 0:

        report.write(
            "1. Continue monitoring network activity.\n"
        )

        report.write(
            "2. Review medium-risk connections.\n"
        )

    else:

        report.write(
            "No immediate candidate risk was detected "
            "by this prototype.\n"
        )


    # --------------------------------------
    # Disclaimer
    # --------------------------------------

    report.write(
        "\n"
    )

    report.write(
        "IMPORTANT NOTE\n"
    )

    report.write(
        "-" * 70 + "\n"
    )

    report.write(
        "This is an educational cybersecurity "
        "prototype.\n"
    )

    report.write(
        "Risk scores and classifications are based "
        "on the project's synthetic dataset and "
        "prototype algorithms.\n"
    )

    report.write(
        "They must not be treated as certified "
        "security detections or as a replacement "
        "for professional security monitoring.\n"
    )


# ------------------------------------------
# Console output
# ------------------------------------------

print("=" * 70)

print(
    "             AUTOMATED SECURITY REPORT"
)

print("=" * 70)

print(
    f"\nOverall Status : {overall_status}"
)

print(
    f"Average Risk  : "
    f"{average_risk:.2f}/100"
)

print(
    f"Security Alerts: "
    f"{len(alert_df)}"
)

print(
    "\n✅ Security report generated!"
)

print(
    "\nSaved to:"
)

print(
    report_file
)

print(
    "\n🎉 STAGE 11 COMPLETED!"
)
