import streamlit as st
import pandas as pd


# ==========================================
# SMART NETWORK INTRUSION DETECTOR
# STAGE 09 — SECURITY DASHBOARD
# ==========================================


# ------------------------------------------
# Page settings
# ------------------------------------------

st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🛡️",
    layout="wide"
)


# ------------------------------------------
# Title
# ------------------------------------------

st.title(
    "🛡️ Smart Network Security Monitor"
)

st.write(
    "Machine-learning based network traffic "
    "monitoring and risk analysis prototype."
)

st.divider()


# ------------------------------------------
# Load risk results
# ------------------------------------------

input_file = (
    "C:/smart-network-intrusion-detector/"
    "08_risk_score/risk_results.csv"
)

try:

    df = pd.read_csv(
        input_file
    )

except FileNotFoundError:

    st.error(
        "risk_results.csv was not found. "
        "Run Stage 08 first."
    )

    st.stop()


# ------------------------------------------
# Calculate dashboard statistics
# ------------------------------------------

total_connections = len(df)

normal_connections = (
    df["label_code"] == 0
).sum()

suspicious_connections = (
    df["label_code"] == 1
).sum()

high_risk = (
    df["risk_level"] == "HIGH"
).sum()

average_risk = (
    df["risk_score"].mean()
)


# ------------------------------------------
# Dashboard metrics
# ------------------------------------------

st.subheader(
    "📊 Security Overview"
)


col1, col2, col3, col4 = (
    st.columns(4)
)


with col1:

    st.metric(
        "Total Connections",
        total_connections
    )


with col2:

    st.metric(
        "Normal Traffic",
        normal_connections
    )


with col3:

    st.metric(
        "Suspicious Traffic",
        suspicious_connections
    )


with col4:

    st.metric(
        "High Risk",
        high_risk
    )


st.divider()


# ------------------------------------------
# Average risk
# ------------------------------------------

st.subheader(
    "⚠️ Network Risk Level"
)


st.metric(
    "Average Risk Score",
    f"{average_risk:.1f} / 100"
)


if average_risk >= 70:

    st.error(
        "🔴 HIGH RISK NETWORK ACTIVITY"
    )

elif average_risk >= 40:

    st.warning(
        "🟡 MEDIUM RISK NETWORK ACTIVITY"
    )

else:

    st.success(
        "🟢 LOW RISK NETWORK ACTIVITY"
    )


# ------------------------------------------
# Risk distribution
# ------------------------------------------

st.divider()

st.subheader(
    "📈 Risk Distribution"
)


risk_counts = (
    df["risk_level"]
    .value_counts()
)


st.bar_chart(
    risk_counts
)


# ------------------------------------------
# Packet activity
# ------------------------------------------

st.subheader(
    "📡 Network Activity"
)


activity_data = df[
    [
        "packet_count",
        "packet_size",
        "connection_duration"
    ]
]


st.line_chart(
    activity_data
)


# ------------------------------------------
# Connection table
# ------------------------------------------

st.divider()

st.subheader(
    "📋 Connection Details"
)


display_columns = [
    "protocol_code",
    "source_port",
    "destination_port",
    "packet_size",
    "packet_count",
    "connection_duration",
    "risk_score",
    "risk_level"
]


st.dataframe(
    df[display_columns],
    use_container_width=True
)


# ------------------------------------------
# High-risk connections
# ------------------------------------------

st.divider()

st.subheader(
    "🔴 High-Risk Connections"
)


high_risk_data = df[
    df["risk_level"] == "HIGH"
]


if len(high_risk_data) > 0:

    st.dataframe(
        high_risk_data[
            display_columns
        ],
        use_container_width=True
    )

else:

    st.success(
        "No high-risk connections detected."
    )


# ------------------------------------------
# Footer
# ------------------------------------------

st.divider()

st.caption(
    "Educational cybersecurity prototype — "
    "risk scores and classifications require "
    "validation before real-world deployment."
)
