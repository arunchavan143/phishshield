"""Streamlit interface for PhishShield."""

from __future__ import annotations

import json

import plotly.graph_objects as go
import streamlit as st

from engine import URLAnalyzer
from intelligence import ip_info, resolve_ip
from risk import RISK_COLORS, calculate_risk


st.set_page_config(
    page_title="PhishShield | URL Investigation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top right, #11263c 0%, #07101b 38%, #05080d 100%);
    }
    .block-container { padding-top: 2rem; padding-bottom: 3rem; }
    [data-testid="stMetricValue"] { color: #5ee7ff; }
    h1, h2, h3 { letter-spacing: -0.02em; }
    </style>
    """,
    unsafe_allow_html=True,
)



def risk_gauge(score: int, verdict: str) -> go.Figure:
    """Build the risk gauge visualization."""

    color = RISK_COLORS[verdict]
    return go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            title={"text": verdict},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 30], "color": "#153d2a"},
                    {"range": [30, 60], "color": "#4a3712"},
                    {"range": [60, 100], "color": "#4a1f24"},
                ],
            },
        )
    ).update_layout(height=300, margin={"l": 20, "r": 20, "t": 50, "b": 20})


def redirect_graph(chain: tuple[str, ...]) -> go.Figure | None:
    """Render a deterministic redirect graph when redirects are present."""

    if len(chain) < 2:
        return None

    x_values = list(range(len(chain)))
    y_values = [0] * len(chain)
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for index in range(len(chain) - 1):
        edge_x.extend([x_values[index], x_values[index + 1], None])
        edge_y.extend([0, 0, None])

    figure = go.Figure(
        data=[
            go.Scatter(
                x=edge_x,
                y=edge_y,
                mode="lines",
                line={"width": 2, "color": "#64748b"},
                hoverinfo="none",
            ),
            go.Scatter(
                x=x_values,
                y=y_values,
                mode="markers+text",
                text=[f"Step {index + 1}" for index in range(len(chain))],
                customdata=list(chain),
                hovertemplate="%{customdata}<extra></extra>",
                textposition="top center",
                marker={"size": 16, "color": "#5ee7ff"},
            ),
        ]
    )
    figure.update_layout(
        height=280,
        showlegend=False,
        xaxis={"visible": False},
        yaxis={"visible": False},
        plot_bgcolor="#0b1420",
        paper_bgcolor="rgba(0,0,0,0)",
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
    )
    return figure


def render_domain_intelligence(metadata: dict) -> None:
    """Render DNS and IP enrichment information."""

    ip_address = resolve_ip(metadata["domain"])
    if not ip_address:
        st.warning("Unable to resolve an IPv4 address for this hostname.")
        return

    enrichment = ip_info(ip_address)
    if not enrichment:
        st.info(f"Resolved IP address: `{ip_address}`. Public enrichment was unavailable.")
        return

    first, second, third = st.columns(3)
    first.metric("IP address", enrichment["ip"])
    second.metric("Organization", enrichment["org"])
    third.metric("Country", enrichment["country"])
    st.caption(f"Location: {enrichment['city']} · Coordinates: {enrichment['loc']}")


st.title("PhishShield")
st.caption("A focused SOC-style workspace for investigating suspicious URLs.")

with st.sidebar:
    st.header("Investigation guide")
    st.write("PhishShield combines URL structure indicators with bounded redirect and domain lookups.")
    st.info("A low-risk score is not proof that a site is safe. Use this dashboard as an investigation aid.")
    st.divider()
    st.caption("Network lookups use short timeouts and never download page bodies.")

with st.form("investigation_form"):
    url = st.text_input(
        "URL to investigate",
        placeholder="https://example.com/login",
        help="Enter an http:// or https:// URL. If omitted, https:// is assumed.",
    )
    submitted = st.form_submit_button("Start investigation", type="primary", use_container_width=True)

if submitted:
    try:
        with st.spinner("Inspecting URL structure and redirect behavior…"):
            metadata = URLAnalyzer(url).metadata()
        verdict, score, indicators = calculate_risk(metadata)
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    st.divider()
    overview, signals, redirects, intelligence, raw = st.tabs(
        ["Overview", "URL signals", "Redirect path", "Domain intelligence", "Raw data"]
    )

    with overview:
        left, right = st.columns([1.15, 1])
        with left:
            st.plotly_chart(risk_gauge(score, verdict), use_container_width=True, config={"displayModeBar": False})
        with right:
            st.subheader("Investigation summary")
            st.metric("Hostname", metadata["domain"])
            st.metric("Final URL", metadata["final_url"])
            if metadata["network_error"]:
                st.warning(f"Network lookup note: {metadata['network_error']}")
            if indicators:
                st.write("**Indicators contributing to the score**")
                for indicator in indicators:
                    st.write(f"- {indicator}")
            else:
                st.success("No configured risk indicators were triggered.")

    with signals:
        first, second, third = st.columns(3)
        first.metric("Hostname entropy", metadata["entropy"])
        second.metric("IP in hostname", "Yes" if metadata["has_ip"] else "No")
        third.metric("Keyword matches", len(metadata["matched_keywords"]))
        st.write("**Registered domain:**", metadata["registered_domain"])
        if metadata["matched_keywords"]:
            st.write("**Matched keywords:**", ", ".join(metadata["matched_keywords"]))

    with redirects:
        st.metric("Redirects followed", metadata["redirect_count"])
        graph = redirect_graph(tuple(metadata["redirect_chain"]))
        if graph:
            st.plotly_chart(graph, use_container_width=True, config={"displayModeBar": False})
            st.dataframe(
                {"Step": list(range(1, len(metadata["redirect_chain"]) + 1)), "URL": list(metadata["redirect_chain"])},
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No redirects were detected.")

    with intelligence:
        render_domain_intelligence(metadata)

    with raw:
        st.json(metadata)
        st.download_button(
            "Download JSON report",
            data=json.dumps(metadata, indent=2),
            file_name="phishshield-report.json",
            mime="application/json",
        )
