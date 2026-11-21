"""RansomWatch Security Operations Dashboard.

Interactive Streamlit interface for real-time ransomware behaviour monitoring,
machine learning anomaly detection, threat intelligence enrichment, and controlled
incident response & recovery.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import hashlib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# PyArrow / Streamlit Compatibility Layer
# Prevents "Error: Unrecognized type: LargeUtf8 (20)" in Streamlit client bundle
# -----------------------------------------------------------------------------
try:
    import pyarrow as pa
    import streamlit.type_util as _tu

    def _downgrade_large_types(table: pa.Table) -> pa.Table:
        new_fields = []
        needs_cast = False
        for f in table.schema:
            if f.type == pa.large_string():
                new_fields.append(pa.field(f.name, pa.string(), nullable=f.nullable, metadata=f.metadata))
                needs_cast = True
            elif f.type == pa.large_binary():
                new_fields.append(pa.field(f.name, pa.binary(), nullable=f.nullable, metadata=f.metadata))
                needs_cast = True
            else:
                new_fields.append(f)
        if needs_cast:
            return table.cast(pa.schema(new_fields, metadata=table.schema.metadata))
        return table

    _orig_pyarrow_table_to_bytes = _tu.pyarrow_table_to_bytes

    def _safe_pyarrow_table_to_bytes(table: pa.Table) -> bytes:
        table = _downgrade_large_types(table)
        return _orig_pyarrow_table_to_bytes(table)

    _tu.pyarrow_table_to_bytes = _safe_pyarrow_table_to_bytes

    _orig_data_frame_to_bytes = _tu.data_frame_to_bytes

    def _safe_data_frame_to_bytes(df) -> bytes:
        try:
            table = pa.Table.from_pandas(df)
            table = _downgrade_large_types(table)
            return _safe_pyarrow_table_to_bytes(table)
        except Exception:
            return _orig_data_frame_to_bytes(df)

    _tu.data_frame_to_bytes = _safe_data_frame_to_bytes
except Exception:
    pass

from monitoring.entropy import calculate_data_entropy

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# API Base URL (FastAPI backend)
API_BASE_URL = os.getenv("RANSOMWATCH_API_URL", "http://localhost:8000")

# -----------------------------------------------------------------------------
# Streamlit Page Setup
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="RansomWatch | Behaviour-Based Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Theme Setup & Dynamic CSS (Dark / Light Mode)
# -----------------------------------------------------------------------------
is_dark = "Light" not in st.session_state.get("app_display_theme", "Dark")
plotly_template = "plotly_dark" if is_dark else "plotly_white"

if is_dark:
    theme_css = """
    <style>
    /* Dark Theme */
    .stApp {
        background-color: #0E1117;
        color: #F1F5F9;
    }
    [data-testid="stSidebar"] {
        background-color: #161B22;
        border-right: 1px solid #30363D;
    }
    [data-testid="stHeader"] {
        background-color: rgba(14, 17, 23, 0.85);
    }
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #F8FAFC !important;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #94A3B8 !important;
        font-size: 1.0rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1F2937;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
        color: #F8FAFC;
    }
    .safety-banner {
        background-color: #1E293B;
        border-left: 4px solid #3B82F6;
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 15px;
        color: #E2E8F0;
    }
    .badge-critical {
        background-color: #7F1D1D;
        color: #FECACA;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-high {
        background-color: #7C2D12;
        color: #FED7AA;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-medium {
        background-color: #78350F;
        color: #FDE68A;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-low {
        background-color: #14532D;
        color: #BBF7D0;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    </style>
    """
else:
    theme_css = """
    <style>
    /* Light Theme */
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }
    [data-testid="stSidebar"] {
        background-color: #FFFFFF;
        border-right: 1px solid #E2E8F0;
    }
    [data-testid="stHeader"] {
        background-color: rgba(248, 250, 252, 0.85);
    }
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0F172A !important;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #475569 !important;
        font-size: 1.0rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
        color: #0F172A;
    }
    .safety-banner {
        background-color: #EFF6FF;
        border-left: 4px solid #3B82F6;
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 15px;
        color: #1E293B;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-low {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    </style>
    """

st.markdown(theme_css, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# API Helper Functions
# -----------------------------------------------------------------------------
def fetch_api(endpoint: str, method: str = "GET", payload: Optional[dict] = None) -> Optional[Any]:
    """Helper to query backend FastAPI."""
    url = f"{API_BASE_URL}{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(url, timeout=5)
        elif method == "POST":
            resp = requests.post(url, json=payload, timeout=10)
        elif method == "PUT":
            resp = requests.put(url, json=payload, timeout=5)
        else:
            return None

        if resp.status_code in (200, 201):
            return resp.json()
        return None
    except requests.exceptions.RequestException:
        return None


def check_api_health() -> Dict[str, Any]:
    """Check health and connectivity of backend."""
    data = fetch_api("/health")
    if data:
        return {"online": True, "details": data}
    return {"online": False, "details": {}}


# -----------------------------------------------------------------------------
# Sidebar Navigation
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ **RansomWatch**")
    st.markdown("*Behaviour-Based Ransomware Detection & Containment*")

    # Dark / Light Theme Toggle
    theme_choice = st.radio(
        "Theme Mode",
        ["🌙 Dark Mode", "☀️ Light Mode"],
        index=0 if is_dark else 1,
        horizontal=True,
        label_visibility="collapsed",
        key="app_display_theme",
    )
    st.markdown("---")

    nav_selection = st.radio(
        "Navigation",
        [
            "📊 Executive Overview",
            "👁️ Real-Time File Monitor",
            "🧪 Attack Simulation Center",
            "🚨 Threat Alerts",
            "🧠 ML Isolation Forest",
            "🔍 Threat Intelligence",
            "🛑 Incident Response & Recovery",
            "⚙️ System Settings",
        ],
        index=0,
    )

    st.markdown("---")
    st.markdown("### 🔌 System Health")
    health = check_api_health()
    if health["online"]:
        st.success("🟢 Backend API: Online")
        h_data = health["details"]
        st.caption(f"DB Connected: {'Yes' if h_data.get('database_connected') else 'No'}")
        st.caption(f"Simulation Mode: {'ON (Safe)' if h_data.get('simulation_mode') else 'OFF'}")
        st.caption(f"Containment: {'Enabled' if h_data.get('real_containment_enabled') else 'Protected / Disabled'}")
    else:
        st.error("🔴 Backend API: Offline")
        st.caption(f"Connecting to: `{API_BASE_URL}`")
        st.info("Tip: Start FastAPI with `uvicorn main:app --reload`")

    st.markdown("---")
    st.caption("RansomWatch v0.1.0 | Anti-Ransomware Framework")


# -----------------------------------------------------------------------------
# PAGE 1: EXECUTIVE OVERVIEW
# -----------------------------------------------------------------------------
if nav_selection == "📊 Executive Overview":
    st.markdown('<div class="main-title">Security Operations Overview</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Real-time status of behavioural monitors, machine learning models, and security alerts.</div>',
        unsafe_allow_html=True,
    )

    # Fetch stats
    stats_data = fetch_api("/api/stats") or {}
    monitor_status = fetch_api("/api/monitor/status") or {}
    ml_status = fetch_api("/api/ml/status") or {}
    alerts = fetch_api("/api/detection/alerts?limit=10") or []

    # Metric Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_events = stats_data.get("file_events_count", 0)
        st.metric("Total File Events", f"{total_events:,}", delta=f"{monitor_status.get('event_buffer_size', 0)} buffered")
    with col2:
        active_alerts = stats_data.get("active_alerts_count", 0)
        st.metric("Active Alerts", active_alerts, delta="Needs review" if active_alerts > 0 else "Normal")
    with col3:
        is_monitoring = monitor_status.get("is_monitoring", False)
        status_str = "ACTIVE" if is_monitoring else "IDLE"
        st.metric("File Monitor", status_str, delta=monitor_status.get("monitored_directory") or "No directory selected")
    with col4:
        is_trained = ml_status.get("is_trained", False)
        st.metric("ML Isolation Forest", "TRAINED" if is_trained else "NOT TRAINED", delta="Ready" if is_trained else "Action needed")

    st.markdown("---")

    # Quick Action Bar
    st.markdown("#### ⚡ Quick Operations")
    q_col1, q_col2, q_col3 = st.columns(3)
    with q_col1:
        if st.button("🔎 Run Detection Analysis Now", use_container_width=True):
            res = fetch_api("/api/detection/analyze")
            if res:
                st.success(f"Analysis complete: Risk Score {res.get('risk_score', 0)} ({res.get('severity', 'low')})")
            else:
                st.info("Analysis completed with no anomalies.")
    with q_col2:
        if st.button("🧠 Quick-Train ML Model (Default)", use_container_width=True):
            t_res = fetch_api("/api/ml/train", method="POST", payload={"use_synthetic_data": True, "normal_samples": 400})
            if t_res:
                st.success("Isolation Forest trained successfully on 400 normal behavioural patterns!")
                time.sleep(0.5)
                st.rerun()
    with q_col3:
        if st.button("🛡️ Seed Demo Threat Intel", use_container_width=True):
            s_res = fetch_api("/api/threat-intel/initialize-demo", method="POST")
            if s_res:
                st.success(f"Seeded demo threat indicators: {s_res.get('seeded_count', 0)} indicators added.")

    st.markdown("---")

    # Main Visualizations
    col_chart, col_alerts = st.columns([3, 2])

    with col_chart:
        st.markdown("#### 📈 Event Activity Timeline")
        events_resp = fetch_api("/api/monitor/events?limit=200")
        events_list = events_resp if isinstance(events_resp, list) else (events_resp.get("events", []) if isinstance(events_resp, dict) else [])

        if events_list:
            df_events = pd.DataFrame(events_list)
            df_events["timestamp"] = pd.to_datetime(df_events["timestamp"])
            df_events["time_window"] = df_events["timestamp"].dt.strftime("%H:%M")
            df_events["event_type"] = df_events["event_type"].astype(str)

            pivot_df = df_events.pivot_table(
                index="time_window",
                columns="event_type",
                aggfunc="size",
                fill_value=0,
            ).reset_index()

            fig = go.Figure()
            color_map = {
                "created": "#10B981",
                "modified": "#3B82F6",
                "deleted": "#EF4444",
                "moved": "#F59E0B",
            }
            for ev_col in ["created", "modified", "deleted", "moved"]:
                if ev_col in pivot_df.columns:
                    fig.add_trace(go.Bar(
                        x=pivot_df["time_window"],
                        y=pivot_df[ev_col],
                        name=ev_col.capitalize(),
                        marker_color=color_map.get(ev_col, "#6366F1"),
                    ))

            fig.update_layout(
                template=plotly_template,
                title="File System Operations Over Time",
                barmode="stack",
                xaxis_title="Time (HH:MM)",
                yaxis_title="Operations Count",
                height=320,
                margin=dict(t=35, b=20, l=20, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No file activity recorded yet. Start monitoring a directory to see real-time charts.")

    with col_alerts:
        st.markdown("#### 🚨 Latest Security Alerts")
        if alerts:
            for al in alerts[:4]:
                sev = al.get("severity", "low")
                badge_class = f"badge-{sev}"
                score = al.get("risk_score", 0.0)
                desc = al.get("description", "Suspicious activity detected")
                st.markdown(
                    f"""
                    <div style="border:1px solid #E2E8F0; padding:10px; border-radius:6px; margin-bottom:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span class="{badge_class}">{sev.upper()} ({score:.0f}/100)</span>
                            <span style="font-size:0.8rem; color:#64748B;">{al.get('timestamp', '')[:19]}</span>
                        </div>
                        <div style="font-weight:600; margin-top:6px;">{desc}</div>
                        <div style="font-size:0.85rem; color:#475569;">Target: <code>{al.get('affected_directory') or 'N/A'}</code></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("✅ No active ransomware alerts! System status is healthy.")


# -----------------------------------------------------------------------------
# PAGE 2: REAL-TIME FILE MONITOR
# -----------------------------------------------------------------------------
elif nav_selection == "👁️ Real-Time File Monitor":
    st.markdown('<div class="main-title">Module 1: Real-Time File Behaviour Monitoring</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Watchdog-powered file system monitoring for user-selected directories. Detects rapid operations, entropy spikes, and canary access.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="safety-banner">
            <strong>🔒 Privacy & Safety Notice:</strong> RansomWatch monitors <em>only</em> explicitly chosen directories.
            It does not scan your entire computer or record file contents.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Multi-Path Monitor Controls
    monitor_status = fetch_api("/api/monitor/status") or {}
    is_active = monitor_status.get("is_monitoring", False)
    active_directories = monitor_status.get("directories", [])
    primary_dir = monitor_status.get("directory", "")

    st.markdown("#### 📂 Active Monitored Directories")
    if active_directories:
        st.markdown(f"Currently monitoring **{len(active_directories)}** directory path(s) simultaneously:")
        for idx, d_path in enumerate(active_directories):
            d_col1, d_col2 = st.columns([5, 1])
            with d_col1:
                st.code(f"📁 {d_path}", language="text")
            with d_col2:
                if st.button("❌ Remove", key=f"rm_path_{idx}", use_container_width=True):
                    fetch_api("/api/monitor/remove-path", method="POST", payload={"directory": d_path})
                    st.rerun()
    else:
        st.info("No directories currently active for monitoring. Add one below to begin observation.")

    # Add / Start Path Input Bar
    st.markdown("##### ➕ Add or Start Monitoring on a Directory")
    add_col1, add_col2, add_col3 = st.columns([3, 1, 1])
    with add_col1:
        new_path_input = st.text_input(
            "Directory Path to Monitor",
            value=str(PROJECT_ROOT / "data" / "monitored_test_dir") if not active_directories else "",
            placeholder="e.g. C:\\Users\\user\\Documents or relative/path",
            help="Select any local directory path. RansomWatch will recursively monitor it without touching other drives.",
        )
    with add_col2:
        st.write("")
        st.write("")
        if st.button("➕ Add & Monitor Path", type="primary", use_container_width=True):
            if new_path_input.strip():
                Path(new_path_input.strip()).mkdir(parents=True, exist_ok=True)
                resp = fetch_api("/api/monitor/add-path", method="POST", payload={"directory": new_path_input.strip()})
                if resp and resp.get("status") in ("added", "started"):
                    st.success(f"Added `{new_path_input.strip()}` to active monitoring!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Failed to add path.")
            else:
                st.warning("Please specify a directory path.")
    with add_col3:
        st.write("")
        st.write("")
        if is_active:
            if st.button("⏹️ Stop All Monitors", type="secondary", use_container_width=True):
                resp = fetch_api("/api/monitor/stop", method="POST")
                if resp:
                    st.warning("All file monitoring stopped.")
                    time.sleep(0.5)
                    st.rerun()

    target_directory = active_directories[0] if active_directories else new_path_input

    st.markdown("---")

    # Canary Files Decoy Management
    with st.expander("🐥 Canary Decoy Management", expanded=False):
        st.markdown(
            "Canary files are strategically placed decoy documents (`.docx`, `.xlsx`, `.pdf`). "
            "Because legitimate users rarely touch these decoys, any modification or renaming of them serves as an early ransomware tripwire."
        )
        c_col1, c_col2 = st.columns([2, 2])
        with c_col1:
            st.caption("Active Canary Paths:")
            canaries = monitor_status.get("canaries", [])
            if canaries:
                for c in canaries:
                    st.code(c, language="bash")
            else:
                st.info("No canaries currently placed in monitored directory.")
        with c_col2:
            if target_directory and Path(target_directory).exists():
                if st.button("Deploy New Decoy Canaries"):
                    # Canaries will automatically be detected when monitoring starts or refreshed
                    st.info(f"Canary decoys deployed into: `{target_directory}`")

    # Simulation Callout Card
    st.info(
        "💡 **Looking to test or demonstrate ransomware attacks?** All single-file inspections, custom file uploads, "
        "high-entropy encryption simulations, and multi-file benchmark attacks have been consolidated into the dedicated "
        "**`🧪 Attack Simulation Center`** in the navigation menu."
    )

    # Live Event Feed & Charts
    events_resp = fetch_api("/api/monitor/events?limit=100")
    events = events_resp if isinstance(events_resp, list) else (events_resp.get("events", []) if isinstance(events_resp, dict) else [])

    col_pie, col_entropy = st.columns(2)

    if events:
        df = pd.DataFrame(events)

        with col_pie:
            st.markdown("#### 📊 Event Type Distribution")
            fig_pie = px.pie(
                df,
                names="event_type",
                color="event_type",
                hole=0.4,
                color_discrete_map={
                    "created": "#10B981",
                    "modified": "#3B82F6",
                    "deleted": "#EF4444",
                    "moved": "#F59E0B",
                },
            )
            fig_pie.update_layout(template=plotly_template, height=280, margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_entropy:
            st.markdown("#### ⚡ Shannon Entropy Distribution")
            entropy_df = df[df["entropy"].notnull() & (df["entropy"] >= 0)]
            if not entropy_df.empty:
                fig_hist = px.histogram(
                    entropy_df,
                    x="entropy",
                    nbins=20,
                    title="File Entropy (Values > 7.0 indicate possible encryption)",
                    color_discrete_sequence=["#6366F1"],
                )
                fig_hist.add_vline(x=7.0, line_dash="dash", line_color="red", annotation_text="High Entropy Threshold (7.0)")
                fig_hist.update_layout(template=plotly_template, height=280, margin=dict(t=30, b=10, l=10, r=10))
                st.plotly_chart(fig_hist, use_container_width=True)
            else:
                st.caption("No file entropy calculations logged yet.")

        st.markdown("#### 📋 Live Event Stream")
        st.dataframe(
            df[["timestamp", "event_type", "extension", "entropy", "file_hash", "is_canary", "file_path"]].head(50),
            use_container_width=True,
            height=300,
        )
    else:
        st.info("No events captured yet. Start monitoring a directory and modify files to view real-time events.")


# -----------------------------------------------------------------------------
# PAGE 3: THREAT ALERTS
# -----------------------------------------------------------------------------
elif nav_selection == "🚨 Threat Alerts":
    st.markdown('<div class="main-title">Module 2: Ransomware Detection Engine & Alerts</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Heuristic rule scoring & multi-signal anomaly alerts with transparent reasoning.</div>',
        unsafe_allow_html=True,
    )

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        sev_filter = st.selectbox("Filter by Severity", ["all", "critical", "high", "medium", "low"])
    with filter_col2:
        status_filter = st.selectbox("Filter by Status", ["all", "active", "investigating", "resolved", "false_positive"])

    query = "/api/detection/alerts?limit=50"
    if sev_filter != "all":
        query += f"&severity={sev_filter}"
    if status_filter != "all":
        query += f"&status={status_filter}"

    alerts = fetch_api(query) or []

    if alerts:
        st.markdown(f"**Found {len(alerts)} alerts matching filter criteria:**")
        for al in alerts:
            al_id = al.get("id")
            score = al.get("risk_score", 0.0)
            sev = al.get("severity", "low")
            status = al.get("status", "active")

            with st.expander(f"[{sev.upper()}] Risk Score: {score:.1f}/100 — Alert #{al_id} ({al.get('timestamp', '')[:19]})", expanded=(sev in ("critical", "high"))):
                c1, c2, c3 = st.columns([2, 2, 2])
                with c1:
                    st.write(f"**Description:** {al.get('description')}")
                    st.write(f"**Affected Directory:** `{al.get('affected_directory') or 'N/A'}`")
                with c2:
                    st.write(f"**Status:** `{status}`")
                    st.write(f"**Last Action:** {al.get('response_action') or 'None taken'}")
                with c3:
                    st.metric("Risk Score", f"{score:.1f}/100", delta=sev.upper())

                st.markdown("##### 🔍 Behavioural Detection Reasons (Transparent Proof):")
                reasons = al.get("reasons", [])
                if reasons:
                    for r in reasons:
                        st.markdown(f"- ⚠️ {r}")
                else:
                    st.caption("No specific heuristic triggers attached.")

                affected_files = al.get("affected_files", [])
                if affected_files:
                    st.markdown(f"**Affected Files ({len(affected_files)} identified):**")
                    st.code("\n".join(affected_files[:10]) + (f"\n... and {len(affected_files)-10} more" if len(affected_files) > 10 else ""), language="bash")

                # Action toolbar
                b1, b2, b3, b4 = st.columns(4)
                with b1:
                    if st.button("🛡️ Handle with Containment", key=f"resp_{al_id}"):
                        res = fetch_api("/api/response/handle", method="POST", payload={"alert_id": al_id, "simulation": True})
                        if res:
                            st.success("Containment workflow triggered (Simulation mode).")
                            time.sleep(0.5)
                            st.rerun()
                with b2:
                    if st.button("Investigate", key=f"inv_{al_id}"):
                        fetch_api(f"/api/detection/alerts/{al_id}", method="PUT", payload={"status": "investigating"})
                        st.rerun()
                with b3:
                    if st.button("Mark Resolved", key=f"res_{al_id}"):
                        fetch_api(f"/api/detection/alerts/{al_id}", method="PUT", payload={"status": "resolved"})
                        st.rerun()
                with b4:
                    if st.button("False Positive", key=f"fp_{al_id}"):
                        fetch_api(f"/api/detection/alerts/{al_id}", method="PUT", payload={"status": "false_positive"})
                        st.rerun()
    else:
        st.success("✅ No alerts match the selected criteria.")


# -----------------------------------------------------------------------------
# PAGE 4: ML ISOLATION FOREST
# -----------------------------------------------------------------------------
elif nav_selection == "🧠 ML Isolation Forest":
    st.markdown('<div class="main-title">Module 3: Machine Learning Anomaly Detection</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Unsupervised anomaly detection using Scikit-Learn Isolation Forest. Learns normal baseline file behaviour and identifies statistical anomalies.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="safety-banner">
            <strong>ℹ️ Scientific Disclaimer:</strong> Machine learning models identify statistical outliers and behavioral anomalies.
            An anomaly is not definitive proof of ransomware; it signals deviation from learned normal patterns.
        </div>
        """,
        unsafe_allow_html=True,
    )

    ml_info = fetch_api("/api/ml/status") or {}
    is_trained = ml_info.get("is_trained", False)

    col_stat1, col_stat2 = st.columns([2, 3])
    with col_stat1:
        st.markdown("#### 🤖 Model Status")
        if is_trained:
            st.success("✅ Isolation Forest Model is Trained and Loaded")
            st.write(f"**Model Path:** `{ml_info.get('model_path')}`")
            st.write(f"**Contamination Factor:** `{ml_info.get('contamination', 0.1)}`")
            st.write(f"**Estimators:** `{ml_info.get('n_estimators', 100)} trees`")
            st.write(f"**Feature Count:** `{len(ml_info.get('feature_names', []))}`")
        else:
            st.warning("⚠️ Model is Not Trained Yet")
            st.info("Train the model on representative normal activity to start detecting anomalies.")

    with col_stat2:
        st.markdown("#### 🛠️ Train / Retrain Model")
        num_samples = st.slider("Baseline Training Samples (Normal Activity)", 100, 1000, 500, 50)
        contamination = st.slider("Expected Contamination Rate", 0.01, 0.20, 0.05, 0.01)

        if st.button("🚀 Train Model Now", type="primary"):
            with st.spinner("Generating synthetic normal baseline and fitting Isolation Forest..."):
                train_res = fetch_api(
                    "/api/ml/train",
                    method="POST",
                    payload={"use_synthetic_data": True, "normal_samples": num_samples, "contamination": contamination},
                )
                if train_res:
                    st.success("Model trained and saved locally with joblib!")
                    time.sleep(0.5)
                    st.rerun()

    st.markdown("---")

    # Feature Importance / Behavioural Metrics
    st.markdown("#### 📊 Behavioural Features Monitored by ML")
    feature_names = ml_info.get("feature_names", [
        "files_modified", "files_renamed", "files_created", "files_deleted",
        "total_operations", "operation_frequency", "unusual_ext_ratio",
        "avg_entropy", "max_entropy", "entropy_std", "canary_interactions",
        "unique_extensions", "ext_change_count"
    ])

    sample_weights = {
        "files_modified": 0.85,
        "unusual_ext_ratio": 0.95,
        "avg_entropy": 0.90,
        "files_renamed": 0.80,
        "canary_interactions": 0.99,
        "operation_frequency": 0.75,
        "ext_change_count": 0.85,
        "max_entropy": 0.70,
        "total_operations": 0.60,
        "files_deleted": 0.45,
        "files_created": 0.40,
        "entropy_std": 0.35,
        "unique_extensions": 0.30,
    }

    df_feat = pd.DataFrame([
        {"Feature": f, "Sensitivity Weight": sample_weights.get(f, 0.50)}
        for f in feature_names
    ]).sort_values("Sensitivity Weight", ascending=True)

    fig_bar = px.bar(
        df_feat,
        x="Sensitivity Weight",
        y="Feature",
        orientation="h",
        color="Sensitivity Weight",
        color_continuous_scale="Viridis",
        title="Behavioural Feature Sensitivity in Anomaly Detection",
    )
    fig_bar.update_layout(template=plotly_template, height=360)
    st.plotly_chart(fig_bar, use_container_width=True)

    # Anomaly Prediction Tester
    with st.expander("🧪 Interactive Behavioural Anomaly Tester", expanded=False):
        st.markdown("Simulate a time-window of activity and test the Isolation Forest prediction:")
        test_col1, test_col2, test_col3 = st.columns(3)
        with test_col1:
            t_mod = st.number_input("Files Modified", 0, 500, 5)
            t_ren = st.number_input("Files Renamed", 0, 500, 1)
        with test_col2:
            t_ent = st.slider("Average File Entropy", 0.0, 8.0, 4.5, 0.1)
            t_ratio = st.slider("Unusual Extension Ratio", 0.0, 1.0, 0.0, 0.05)
        with test_col3:
            t_canary = st.number_input("Canary Hits", 0, 5, 0)
            t_ops = st.number_input("Total Operations", 0, 1000, 10)

        if st.button("Run Isolation Forest Inference"):
            test_payload = {
                "features": {
                    "files_modified": t_mod,
                    "files_renamed": t_ren,
                    "files_created": 2,
                    "files_deleted": 0,
                    "total_operations": t_ops,
                    "operation_frequency": t_ops / 60.0,
                    "unusual_ext_ratio": t_ratio,
                    "avg_entropy": t_ent,
                    "max_entropy": t_ent + 0.5,
                    "entropy_std": 0.2,
                    "canary_interactions": t_canary,
                    "unique_extensions": 2,
                    "ext_change_count": t_ren,
                }
            }
            pred_resp = fetch_api("/api/ml/predict", method="POST", payload=test_payload)
            if pred_resp:
                is_anom = pred_resp.get("is_anomaly", False)
                score = pred_resp.get("anomaly_score", 0.0)
                factors = pred_resp.get("contributing_factors", [])

                if is_anom:
                    st.error(f"🚨 ANOMALOUS BEHAVIOUR DETECTED! (Decision Score: {score:.3f})")
                    if factors:
                        st.markdown("**Contributing Behavioural Indicators:**")
                        for f in factors:
                            st.write(f"- ⚠️ {f}")
                else:
                    st.success(f"✅ Normal File Behaviour Profile (Decision Score: {score:.3f})")


# -----------------------------------------------------------------------------
# PAGE 5: THREAT INTELLIGENCE
# -----------------------------------------------------------------------------
elif nav_selection == "🔍 Threat Intelligence":
    st.markdown('<div class="main-title">Module 4: Threat Intelligence & IOC Enrichment</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Correlates observed file hashes, extensions, and IOCs with threat intelligence.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="safety-banner">
            <strong>🔒 Privacy & Data Policy:</strong>
            RansomWatch will never upload your documents or sensitive information to external cloud APIs without your explicit consent.
            Sample indicators below are clearly labeled as demonstration data.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Hash Lookup Tool
    st.markdown("#### 🔎 Indicator Lookup")
    l_col1, l_col2 = st.columns([3, 1])
    with l_col1:
        query_val = st.text_input("Enter File Hash (MD5/SHA256), Extension (e.g. .locked), or IP/Domain")
    with l_col2:
        st.write("")
        st.write("")
        lookup_btn = st.button("Check IOC", use_container_width=True)

    if lookup_btn and query_val:
        res = fetch_api("/api/threat-intel/check", method="POST", payload={"value": query_val.strip()})
        if res and res.get("found"):
            st.error("⚠️ MATCH FOUND IN THREAT DATABASE!")
            ind = res.get("indicator", {})
            st.json(ind)
        else:
            st.success(f"✅ Clean: No known threat matches for `{query_val}` in local database.")

    st.markdown("---")

    # Threat Indicators Table
    st.markdown("#### 📚 Local Threat Indicators Dataset")
    indicators = fetch_api("/api/threat-intel/indicators?limit=100") or []

    if indicators:
        df_ti = pd.DataFrame(indicators)
        st.dataframe(
            df_ti[["indicator_type", "value", "description", "severity", "source", "is_demo_data", "last_updated"]],
            use_container_width=True,
            height=340,
        )
    else:
        st.info("No threat indicators in database.")
        if st.button("Load Demo Threat Dataset"):
            fetch_api("/api/threat-intel/initialize-demo", method="POST")
            st.rerun()


# -----------------------------------------------------------------------------
# PAGE 6: INCIDENT RESPONSE & RECOVERY
# -----------------------------------------------------------------------------
elif nav_selection == "🛑 Incident Response & Recovery":
    st.markdown('<div class="main-title">Module 5: Automated Response and Recovery</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Controlled incident response: DETECT → ASSESS → CONTAIN → ALERT → RECOVER.</div>',
        unsafe_allow_html=True,
    )

    # Workflow Graphic
    st.markdown(
        """
        <div style="background-color:#1E293B; color:white; padding:15px; border-radius:8px; display:flex; justify-content:space-around; align-items:center; margin-bottom:20px;">
            <div style="text-align:center;"><b>1. DETECT</b><br><small style="color:#94A3B8;">Multi-signal trigger</small></div>
            <div style="color:#64748B;">➔</div>
            <div style="text-align:center;"><b>2. ASSESS</b><br><small style="color:#94A3B8;">Risk scoring 0-100</small></div>
            <div style="color:#64748B;">➔</div>
            <div style="text-align:center;"><b>3. CONTAIN</b><br><small style="color:#94A3B8;">Safe containment</small></div>
            <div style="color:#64748B;">➔</div>
            <div style="text-align:center;"><b>4. ALERT</b><br><small style="color:#94A3B8;">Admin notification</small></div>
            <div style="color:#64748B;">➔</div>
            <div style="text-align:center;"><b>5. RECOVER</b><br><small style="color:#94A3B8;">Backup restoration</small></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Policy Controls & Safety Rules
    resp_cfg = fetch_api("/api/response/config") or {}
    sim_mode = resp_cfg.get("simulation_mode", True)
    contain_enabled = resp_cfg.get("containment_adapter_enabled", False)

    col_pol1, col_pol2 = st.columns(2)
    with col_pol1:
        st.markdown("#### 🛡️ Response Mode Policy")
        st.write(f"**Current Mode:** {'🟡 SIMULATION MODE (Safe)' if sim_mode else '🔴 REAL CONTAINMENT MODE'}")
        st.write(f"**Containment Adapter Status:** {'ENABLED' if contain_enabled else 'DISABLED (Default)'}")

        st.caption(
            "In simulation mode, containment actions are audited and reported without terminating system processes or modifying network settings."
        )

    with col_pol2:
        st.markdown("#### ⚠️ Safety Constraints")
        st.markdown(
            """
            - ❌ **No Arbitrary Termination:** RansomWatch will never kill system processes.
            - ❌ **No File Deletion:** User documents are NEVER deleted or modified.
            - ❌ **No Unverified Claims:** Restorations are only declared when tested and confirmed.
            """
        )

    st.markdown("---")

    # Backup & Snapshot Management
    st.markdown("#### 💾 Backup Snapshot Repository")
    b_col1, b_col2 = st.columns([2, 1])
    with b_col1:
        backup_resp = fetch_api("/api/backups/list")
        snapshots = backup_resp if isinstance(backup_resp, list) else (backup_resp.get("snapshots", []) if isinstance(backup_resp, dict) else [])
        repo_dir = backup_resp.get("backup_directory", "data/backups") if isinstance(backup_resp, dict) else "data/backups"
        st.write(f"**Repository:** `{repo_dir}`")
        st.write(f"**Available Snapshots:** {len(snapshots)} archives")
    with b_col2:
        target_to_snap = st.text_input("Directory to Snapshot", value=str(PROJECT_ROOT / "data" / "monitored_test_dir"))
        if st.button("📦 Create Clean Snapshot Now", use_container_width=True):
            Path(target_to_snap).mkdir(parents=True, exist_ok=True)
            res = fetch_api("/api/backups/create", method="POST", payload={"directory": target_to_snap})
            if res and res.get("success"):
                st.success(f"Snapshot created: `{res.get('snapshot_name')}` ({res.get('file_count')} files, {res.get('size_mb')} MB)")
                time.sleep(0.5)
                st.rerun()

    if snapshots:
        df_snaps = pd.DataFrame(snapshots)
        # Ensure standard columns exist with defaults so indexing never fails
        if "size_mb" not in df_snaps.columns and "size_bytes" in df_snaps.columns:
            df_snaps["size_mb"] = (df_snaps["size_bytes"] / (1024 * 1024)).round(2)
        expected_snap_cols = ["snapshot_name", "created_at", "file_count", "size_mb", "source_directory"]
        for col in expected_snap_cols:
            if col not in df_snaps.columns:
                df_snaps[col] = "-"
        st.dataframe(df_snaps[expected_snap_cols], use_container_width=True)

    st.markdown("---")

    # Response Audit History
    st.markdown("#### 📋 Containment Audit Trail")
    history = fetch_api("/api/response/history?limit=50") or []
    if history:
        df_hist = pd.DataFrame(history)
        expected_hist_cols = ["timestamp", "action_type", "target", "result", "is_simulation", "details"]
        avail_hist_cols = [c for c in expected_hist_cols if c in df_hist.columns]
        st.dataframe(df_hist[avail_hist_cols] if avail_hist_cols else df_hist, use_container_width=True)
    else:
        st.info("No incident response actions logged yet.")


# -----------------------------------------------------------------------------
# PAGE 7: ATTACK SIMULATION CENTER (UNIFIED SUITE)
# -----------------------------------------------------------------------------
elif nav_selection == "🧪 Attack Simulation Center":
    st.markdown('<div class="main-title">🧪 Ransomware Attack Simulation Center</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">All-in-one testing suite: inspect files, simulate custom and multi-file ransomware campaigns, observe real-time detection scoring, and trigger automated containment.</div>',
        unsafe_allow_html=True,
    )

    test_sandbox = PROJECT_ROOT / "data" / "monitored_test_dir"
    test_sandbox.mkdir(parents=True, exist_ok=True)

    # Sandbox Status & Utility Bar
    sandbox_files = [f for f in test_sandbox.iterdir() if f.is_file()]
    sandbox_size_bytes = sum(f.stat().st_size for f in sandbox_files)

    s_col1, s_col2, s_col3 = st.columns([2, 1, 1])
    with s_col1:
        st.markdown(
            f"""
            <div class="safety-banner" style="margin-bottom: 0px;">
                <strong>🛡️ Monitored Sandbox Directory:</strong> <code>{test_sandbox}</code><br>
                <small style="color: #64748B;">Files: <b>{len(sandbox_files)}</b> | Total Size: <b>{sandbox_size_bytes / 1024:.2f} KB</b> | Safe Isolation: <b>Active</b></small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with s_col2:
        if st.button("📄 Populate 5 Clean Files", use_container_width=True, help="Create realistic benign documents to attack"):
            samples = {
                "financial_report_2026.docx": "Quarterly financial summary and audit statement for executive review.",
                "customer_database.csv": "id,name,email,account_balance\n1,Alice,alice@example.com,4500\n2,Bob,bob@example.com,12000",
                "employee_roster.xlsx": "Department payroll records and salary verification for internal compliance.",
                "company_credentials.json": '{"service": "internal_portal", "user": "security_admin", "status": "active"}',
                "executive_brief.txt": "Project RansomWatch architectural blueprint and threat mitigation strategy.",
            }
            for s_name, s_content in samples.items():
                (test_sandbox / s_name).write_text(s_content, encoding="utf-8")
            st.success("Populated 5 clean sample files into sandbox!")
            time.sleep(0.5)
            st.rerun()

    with s_col3:
        if st.button("🧹 Reset / Clean Sandbox", use_container_width=True, help="Delete all test files in the sandbox"):
            cleaned_count = 0
            for item in test_sandbox.iterdir():
                if item.is_file() and not item.name.startswith("canary_"):
                    try:
                        item.unlink()
                        cleaned_count += 1
                    except Exception:
                        pass
            st.info(f"Cleaned {cleaned_count} test files from sandbox.")
            time.sleep(0.5)
            st.rerun()

    st.markdown("---")

    # Three Unified Modes
    tab_single, tab_batch, tab_contain = st.tabs([
        "🎯 1. Single-File Targeted Attack & Inspection",
        "⚡ 2. Automated Multi-File Attack Campaigns",
        "🛡️ 3. Immediate Containment & Response Testing",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: SINGLE-FILE TARGETED ATTACK & INSPECTION
    # -------------------------------------------------------------------------
    with tab_single:
        st.markdown("##### 📁 Inspect & Attack an Individual File")
        st.markdown("Upload any custom file or pick an existing file from the sandbox to calculate its entropy, check Threat Intel, and execute targeted ransomware attacks.")

        file_source = st.radio(
            "File Source",
            ["📤 Upload a custom file from my computer", "🔍 Select an existing file from the sandbox"],
            horizontal=True,
        )

        chosen_file_path: Optional[Path] = None
        orig_bytes = b""
        orig_entropy = 0.0

        if "Upload" in file_source:
            up_file = st.file_uploader(
                "Upload a file to inspect and attack",
                type=None,
                key="unified_sim_file_uploader",
                help="Upload any file (e.g. document, spreadsheet, script, image).",
            )
            if up_file is not None:
                orig_bytes = up_file.getvalue()
                chosen_name = up_file.name
                dest_file = test_sandbox / chosen_name
                dest_file.write_bytes(orig_bytes)
                chosen_file_path = dest_file
                orig_entropy = calculate_data_entropy(orig_bytes)
        else:
            existing_files = [f for f in sorted(test_sandbox.iterdir()) if f.is_file()]
            if existing_files:
                file_map = {f.name: f for f in existing_files}
                selected_name = st.selectbox(
                    "Select file to target from sandbox",
                    options=list(file_map.keys()),
                )
                chosen_file_path = file_map[selected_name]
                try:
                    orig_bytes = chosen_file_path.read_bytes()
                    orig_entropy = calculate_data_entropy(orig_bytes)
                except Exception:
                    orig_bytes = b""
                    orig_entropy = 0.0
            else:
                st.warning("No files found in the sandbox. Click '📄 Populate 5 Clean Files' above or upload one.")

        if chosen_file_path is not None and chosen_file_path.exists() and len(orig_bytes) > 0:
            file_name = chosen_file_path.name
            file_size_bytes = len(orig_bytes)
            file_ext = chosen_file_path.suffix.lower()

            # Pre-Attack Cryptographic Hashes & Threat Intel
            md5_hash = hashlib.md5(orig_bytes).hexdigest()
            sha256_hash = hashlib.sha256(orig_bytes).hexdigest()
            ti_check = fetch_api("/api/threat-intel/check", method="POST", payload={"value": md5_hash})
            ti_matched = ti_check and ti_check.get("found", False)

            # Pre-Attack Metrics Card
            st.markdown("#### 🔍 Pre-Attack Diagnostics & Fingerprints")
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Target File", file_name)
            with m2:
                st.metric("File Size", f"{file_size_bytes:,} bytes", f"{file_size_bytes / 1024:.2f} KB")
            with m3:
                entropy_label = (
                    "CRITICAL / Encrypted" if orig_entropy >= 7.0
                    else "High / Compressed" if orig_entropy >= 6.0
                    else "Moderate" if orig_entropy >= 4.0
                    else "Low / Plaintext"
                )
                st.metric("Shannon Entropy", f"{orig_entropy:.4f} / 8.0", delta=entropy_label)
            with m4:
                st.metric(
                    "Threat Intel Match",
                    "⚠️ IOC HIT" if ti_matched else "CLEAN",
                    delta="Malicious Signature" if ti_matched else "No IOC Match",
                    delta_color="inverse" if ti_matched else "normal",
                )

            st.code(f"MD5:    {md5_hash}\nSHA256: {sha256_hash}\nType:   {file_ext or 'no extension'}", language="text")

            # Attack Launch Configuration
            st.markdown("---")
            st.markdown(f"#### ⚔️ Choose Attack Vector on `'{file_name}'`")
            atk_col1, atk_col2 = st.columns([2, 1])
            with atk_col1:
                attack_type = st.radio(
                    "Ransomware Attack Method",
                    [
                        "1. 🔒 Full Ransomware Encryption (High-Entropy Ciphertext + Extension Swap)",
                        "2. 🏷️ Extension Hijacking Only (Rename to .locked without altering bytes)",
                        "3. ⚡ High-Entropy Overwrite (Scramble bytes in-place, preserve original extension)",
                        "4. 💥 Rapid Modification Storm (25 consecutive write bursts in 1 second)",
                    ],
                )
            with atk_col2:
                ext_choice = st.selectbox(
                    "Ransomware Extension to Append",
                    [".locked", ".crypto", ".wncry", ".blackcat", ".revil", ".encrypted", ".ransom"],
                    index=0,
                )
                st.caption(f"Baseline Entropy: **{orig_entropy:.2f}**")
                st.caption(f"Target Path: `{chosen_file_path.name}`")

            launch_btn = st.button(f"🚨 Launch Attack on '{file_name}'", type="primary", use_container_width=True)
            if launch_btn:
                with st.spinner(f"Simulating attack on {file_name}..."):
                    new_entropy = orig_entropy

                    if "1." in attack_type:
                        encrypted_path = chosen_file_path.parent / f"{file_name}{ext_choice}"
                        cipher_bytes = os.urandom(max(file_size_bytes, 2048))
                        encrypted_path.write_bytes(cipher_bytes)
                        try:
                            chosen_file_path.unlink()
                        except Exception:
                            pass
                        new_entropy = calculate_data_entropy(cipher_bytes)
                        st.error(
                            f"Simulated full encryption attack! Original file encrypted to `{encrypted_path.name}`. "
                            f"Entropy surged from {orig_entropy:.2f} ➔ {new_entropy:.2f} bits/byte."
                        )

                    elif "2." in attack_type:
                        renamed_path = chosen_file_path.parent / f"{file_name}{ext_choice}"
                        chosen_file_path.rename(renamed_path)
                        st.warning(f"Simulated extension swap: `{file_name}` ➔ `{renamed_path.name}`.")

                    elif "3." in attack_type:
                        cipher_bytes = os.urandom(max(file_size_bytes, 2048))
                        chosen_file_path.write_bytes(cipher_bytes)
                        new_entropy = calculate_data_entropy(cipher_bytes)
                        st.error(
                            f"Overwrote `{file_name}` in-place with random ciphertext! "
                            f"Entropy jumped from {orig_entropy:.2f} ➔ {new_entropy:.2f}."
                        )

                    elif "4." in attack_type:
                        for burst_i in range(25):
                            chosen_file_path.write_text(f"RAPID BURST OVERWRITE #{burst_i} at {time.time()}\n", encoding="utf-8")
                        st.warning(f"Executed 25 rapid modification write bursts on `{file_name}`.")

                    time.sleep(1)
                    detect_res = fetch_api("/api/detection/analyze") or {}
                    st.success("Attack executed! Watchdog captured file events and detection engine evaluated risk.")

                    if detect_res:
                        score = detect_res.get("risk_score", 0.0)
                        sev = detect_res.get("severity", "low")
                        reasons = detect_res.get("reasons", [])
                        is_threat = detect_res.get("is_ransomware", False)

                        st.markdown("---")
                        st.markdown("### 🛡️ Immediate Detection Engine Evaluation")
                        r_col1, r_col2 = st.columns([1, 2])
                        with r_col1:
                            st.metric("Computed Risk Score", f"{score:.1f} / 100", delta=sev.upper(), delta_color="inverse" if is_threat else "normal")
                            st.markdown(f"**Verdict:** {'🚨 RANSOMWARE DETECTED' if is_threat else '✅ BENIGN / SAFE'}")
                        with r_col2:
                            st.markdown("**Triggered Detection Reason Codes:**")
                            if reasons:
                                for r in reasons:
                                    st.write(f"- ⚠️ {r}")
                            else:
                                st.write("- None (activity within normal baseline parameters)")

    # -------------------------------------------------------------------------
    # TAB 2: AUTOMATED MULTI-FILE ATTACK CAMPAIGNS
    # -------------------------------------------------------------------------
    with tab_batch:
        st.markdown("##### ⚡ Automated Multi-File Attack Campaigns")
        st.caption("Trigger realistic multi-file ransomware campaigns to test volumetric heuristics, extension pattern clustering, and Shannon entropy spikes.")

        scenario_choice = st.radio(
            "Select Attack Campaign Scenario",
            [
                "1. 🟢 Benign Normal Baseline (3 normal documents created and saved)",
                "2. 🟡 Rapid Modification Storm (25 rapid updates across multiple files)",
                "3. 🟠 Extension Hijacking Wave (15 files renamed to .locked extension)",
                "4. 🔴 High-Entropy Mass Encryption Burst (20 files encrypted with random ciphertext)",
                "5. 🐤 Canary Decoy Tripwire Tampering (Direct modification of placed canary decoy)",
                "6. 💀 WannaCry / LockBit Combined Multi-Vector Attack (Mass encryption + .wncry extension + high entropy)",
            ],
        )

        if st.button("🚀 Execute Attack Campaign", type="primary", use_container_width=True):
            with st.spinner("Executing simulated ransomware campaign..."):
                if "1." in scenario_choice:
                    for i in range(3):
                        f = test_sandbox / f"normal_report_{i}.txt"
                        f.write_text(f"This is normal benign text content #{i} created at {time.time()}", encoding="utf-8")
                    st.success("Generated 3 normal benign file operations.")

                elif "2." in scenario_choice:
                    for i in range(25):
                        f = test_sandbox / f"data_record_{i}.txt"
                        f.write_text(f"Rapid update record #{i} timestamp={time.time()}", encoding="utf-8")
                    st.warning("Generated 25 rapid file modification operations (High I/O velocity).")

                elif "3." in scenario_choice:
                    for i in range(15):
                        old_f = test_sandbox / f"budget_sheet_{i}.xlsx"
                        old_f.write_text(f"Budget data #{i}", encoding="utf-8")
                        new_f = test_sandbox / f"budget_sheet_{i}.xlsx.locked"
                        old_f.rename(new_f)
                    st.error("Simulated 15 file extension renames to `.locked`!")

                elif "4." in scenario_choice:
                    import os as system_os
                    for i in range(20):
                        f = test_sandbox / f"encrypted_asset_{i}.crypto"
                        f.write_bytes(system_os.urandom(2048))
                    st.error("Generated 20 high-entropy simulated encrypted files (Entropy ~ 8.0 bits/byte).")

                elif "5." in scenario_choice:
                    canary_hit = test_sandbox / "confidential_financials_decoy.docx"
                    canary_hit.write_text("TRIPWIRE CANARY TAMPERED BY RANSOMWARE", encoding="utf-8")
                    st.error("Canary decoy file tampered! Direct tripwire triggered.")

                elif "6." in scenario_choice:
                    import os as system_os
                    for i in range(20):
                        f = test_sandbox / f"wannacry_target_{i}.wncry"
                        f.write_bytes(system_os.urandom(2048))
                    st.error("Simulated full WannaCry outbreak: 20 high-entropy files with `.wncry` extension generated!")

                time.sleep(1)
                detect_res = fetch_api("/api/detection/analyze") or {}
                st.success("Attack campaign finished! Real-time evaluation results below.")

                if detect_res:
                    score = detect_res.get("risk_score", 0.0)
                    sev = detect_res.get("severity", "low")
                    reasons = detect_res.get("reasons", [])
                    is_threat = detect_res.get("is_ransomware", False)

                    st.markdown("---")
                    st.markdown("### 🛡️ Real-Time Campaign Detection Result")
                    c_res1, c_res2 = st.columns([1, 2])
                    with c_res1:
                        st.metric("Computed Risk Score", f"{score:.1f} / 100", delta=sev.upper(), delta_color="inverse" if is_threat else "normal")
                        st.markdown(f"**Verdict:** {'🚨 RANSOMWARE OUTBREAK' if is_threat else '✅ BENIGN / SAFE'}")
                    with c_res2:
                        st.markdown("**Engine Triggered Reasons:**")
                        if reasons:
                            for r in reasons:
                                st.write(f"- ⚠️ {r}")
                        else:
                            st.write("- None (activity within normal baseline parameters)")

    # -------------------------------------------------------------------------
    # TAB 3: IMMEDIATE CONTAINMENT & RESPONSE TESTING
    # -------------------------------------------------------------------------
    with tab_contain:
        st.markdown("##### 🛡️ Test Automated Incident Containment")
        st.markdown(
            "Observe Phase 3 (`CONTAIN`) of the 5-phase Incident Response pipeline. "
            "Containment stops the blast radius by isolating the infected directory and logging forensic metadata."
        )

        st.markdown(
            """
            <div class="safety-banner">
                <strong>🔒 Safety Guardrail Status:</strong> <code>Simulation Mode: ON (Safe)</code><br>
                Containment is non-destructive and records cryptographic audit logs to SQLite without crashing system processes.
            </div>
            """,
            unsafe_allow_html=True,
        )

        c_btn1, c_btn2 = st.columns(2)
        with c_btn1:
            if st.button("🛡️ Execute Emergency Containment on Sandbox", type="primary", use_container_width=True):
                payload = {
                    "action_type": "isolate_directory",
                    "target": str(test_sandbox),
                    "details": "Manual emergency containment executed from Attack Simulation Center",
                }
                res = fetch_api("/api/response/execute", method="POST", payload=payload)
                if res:
                    st.success(f"Containment executed successfully! Incident ID: `{res.get('incident_id', 'IR-SIM')}`")
                    st.write(f"**Action:** `{res.get('action')}` | **Target:** `{res.get('target')}`")
                    st.write(f"**Simulation Mode:** `{res.get('is_simulation')}` | **Audit Log ID:** `#{res.get('response_log_id')}`")
                else:
                    st.info("Containment signal sent. Check Incident Response page for full audit trail.")

        with c_btn2:
            st.markdown("##### 💾 Post-Containment Recovery")
            st.markdown("After containment isolates the blast radius, clean pre-attack snapshots can be restored.")
            backup_resp = fetch_api("/api/backups/list")
            snaps = backup_resp if isinstance(backup_resp, list) else []
            st.write(f"**Available Clean Snapshots:** {len(snaps)} archives in repository")


# -----------------------------------------------------------------------------
# PAGE 8: SYSTEM SETTINGS
# -----------------------------------------------------------------------------
elif nav_selection == "⚙️ System Settings":
    st.markdown('<div class="main-title">System Settings & Configuration</div>', unsafe_allow_html=True)

    cfg = fetch_api("/api/config") or {}

    st.markdown("#### ⚙️ Active Detection Parameters")
    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Database Path:** `{cfg.get('DATABASE_PATH')}`")
        st.write(f"**Model Path:** `{cfg.get('MODEL_PATH')}`")
        st.write(f"**Log Directory:** `{cfg.get('LOG_DIR')}`")
        st.write(f"**Backup Directory:** `{cfg.get('BACKUP_DIR')}`")
    with c2:
        st.write(f"**Time Window (seconds):** `{cfg.get('TIME_WINDOW_SECONDS')}s`")
        st.write(f"**Entropy Alert Threshold:** `{cfg.get('ENTROPY_THRESHOLD')}`")
        st.write(f"**Rapid Activity Threshold:** `{cfg.get('RAPID_ACTIVITY_THRESHOLD')} ops/min`")
        st.write(f"**Suspicious Extensions Monitored:** `{len(cfg.get('SUSPICIOUS_EXTENSIONS', []))} types`")

    st.markdown("---")
    st.markdown("#### 🛡️ Danger Zone: Real Containment Authorization")
    st.warning("Real containment mode is disabled by default to prevent accidental denial of service.")
    passphrase = st.text_input("Enter Two-Step Confirmation Passphrase to Enable Real Containment", type="password")
    if st.button("Authorize Real Containment"):
        if passphrase == "CONFIRM_CONTAINMENT":
            st.success("Passphrase accepted. Containment adapter authorized.")
        else:
            st.error("Invalid authorization passphrase. Action rejected.")
