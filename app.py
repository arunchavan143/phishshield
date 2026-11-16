"""Streamlit analyst console for PhishShield."""

from __future__ import annotations

import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from engine import URLAnalyzer
from intelligence import ip_info
from risk import RISK_COLORS
from url_utils import defang_url, redact_report


st.set_page_config(
    page_title="PhishShield | Investigation Console",
    page_icon="PS",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(circle at top right, #10253b 0%, #07101b 38%, #05080d 100%); }
    .block-container { padding-top: 1.5rem; padding-bottom: 3rem; max-width: 1500px; }
    [data-testid="stMetricValue"] { color: #5ee7ff; }
    h1, h2, h3 { letter-spacing: -0.02em; }
    .evidence-card { border: 1px solid #26394e; border-radius: 0.6rem; padding: 0.75rem 1rem; margin-bottom: 0.6rem; background: rgba(10, 21, 34, 0.72); }
    .muted { color: #94a3b8; font-size: 0.9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def risk_gauge(score: int, verdict: str, confidence: int) -> go.Figure:
    """Build a severity and coverage-aware gauge."""

    color = RISK_COLORS.get(verdict, RISK_COLORS["LOW"])
    figure = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100"},
            title={"text": f"{verdict} · {confidence}% collection coverage"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 30], "color": "#153d2a"},
                    {"range": [30, 55], "color": "#4a3712"},
                    {"range": [55, 75], "color": "#4a2c12"},
                    {"range": [75, 100], "color": "#4a1f24"},
                ],
            },
        )
    )
    return figure.update_layout(height=320, margin={"l": 20, "r": 20, "t": 55, "b": 20})


def redirect_graph(chain: list[str]) -> go.Figure | None:
    """Render a redirect path graph when redirects are present."""

    if len(chain) < 2:
        return None
    x_values = list(range(len(chain)))
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for index in range(len(chain) - 1):
        edge_x.extend([x_values[index], x_values[index + 1], None])
        edge_y.extend([0, 0, None])
    figure = go.Figure(
        data=[
            go.Scatter(x=edge_x, y=edge_y, mode="lines", line={"width": 2, "color": "#64748b"}, hoverinfo="none"),
            go.Scatter(
                x=x_values,
                y=[0] * len(chain),
                mode="markers+text",
                text=[f"Step {index + 1}" for index in range(len(chain))],
                customdata=chain,
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


def evidence_frame(report: dict) -> pd.DataFrame:
    """Convert evidence objects into a consistent analyst table."""

    rows = report.get("evidence", [])
    if not rows:
        return pd.DataFrame(columns=["Category", "Rule", "Severity", "Score", "Confidence", "Title", "Detail", "Source", "Status"])
    return pd.DataFrame(
        [
            {
                "Category": item["category"].replace("_", " ").title(),
                "Rule": item["rule_id"],
                "Severity": item["severity"].upper(),
                "Score": item["score"],
                "Destination": defang_url(item["subject_url"]) if item.get("subject_url") else "Investigation",
                "Confidence": f"{item['confidence']}%",
                "Title": item["title"],
                "Detail": item["detail"],
                "Source": item["source"],
                "Status": item["status"],
            }
            for item in rows
        ]
    )


def render_recommendations(report: dict) -> None:
    st.subheader("Recommended analyst actions")
    for recommendation in report.get("recommendations", []):
        st.info(recommendation)


def render_domain_intelligence(report: dict) -> None:
    subject = report["subject"]
    dns = report["dns"]
    st.subheader("Infrastructure evidence")
    first, second, third, fourth = st.columns(4)
    first.metric("Registered domain", subject["registered_domain"] or "Unknown")
    second.metric("TLD", f".{subject['tld']}" if subject["tld"] else "Unknown")
    third.metric("DNS status", dns["status"].title())
    fourth.metric("Resolved addresses", len(dns["addresses"]))

    if dns["addresses"]:
        st.write("**Resolved addresses**")
        st.code("\n".join(dns["addresses"]))
        with st.expander("Optional public IP enrichment"):
            st.caption("This optional lookup sends the selected IP to the configured enrichment service. Do not use it for sensitive internal targets without approval.")
            if st.button("Enrich first resolved IP", key=f"enrich_{report['case_id']}"):
                enrichment = ip_info(dns["addresses"][0])
                if enrichment:
                    report["enrichment"] = enrichment
                else:
                    st.warning("The enrichment provider returned no data.")
            if report.get("enrichment"):
                st.json(report["enrichment"])
    elif dns["error"]:
        st.warning(f"DNS collection failed: {dns['error']}")


def render_overview(report: dict) -> None:
    verdict = report["verdict"]
    score = report["risk_score"]
    confidence = report["coverage"]["percent"]
    evidence = report["evidence"]
    severe_count = sum(item["severity"] in {"critical", "high"} for item in evidence)
    network = report["network"]
    coverage = report["coverage"]

    left, right = st.columns([1.1, 1])
    with left:
        st.plotly_chart(risk_gauge(score, verdict, confidence), use_container_width=True, config={"displayModeBar": False})
    with right:
        st.subheader("Investigation disposition")
        st.metric("Risk band", verdict)
        st.metric("Collection coverage", f"{confidence}% of enabled checks")
        st.caption("Detection confidence is uncalibrated. Risk scores are heuristic, not probabilities.")
        st.metric("High/critical signals", severe_count)
        st.metric("Evidence coverage", f"{coverage['completed_checks']}/{coverage['attempted_checks']} checks")
        if verdict in {"HIGH", "CRITICAL"}:
            st.error("Treat this URL as unsafe until independently cleared.")
        elif verdict == "MEDIUM":
            st.warning("Manual review and reputation checks are required before clearing this URL.")
        else:
            st.info("A low score is not clearance. Review collection gaps and verify the destination independently.")

    st.divider()
    subject = report["subject"]
    first, second, third, fourth = st.columns(4)
    first.metric("Hostname", subject["domain"] or "Unknown")
    second.metric("Final destination", defang_url(network["final_url"] or subject["url"]))
    third.metric("HTTP status", network["status_code"] or "Unavailable")
    fourth.metric("Latency", f"{network['response_time_ms']} ms" if network["response_time_ms"] is not None else "Unavailable")
    if network["error"]:
        st.warning(f"Network evidence is incomplete: {network['error']}")
    st.write("**Collection checks**")
    st.dataframe({"Check": list(coverage["checks"]), "Status": list(coverage["checks"].values())}, hide_index=True)
    reputation = report["reputation"]
    if reputation["status"] in {"disabled", "not_configured"}:
        st.info("Reputation lookup was not run. Review collection-check states to see which evidence was available.")
    elif reputation["status"] == "error":
        st.warning(f"Reputation lookup failed: {reputation['error']}")
    elif reputation["status"] == "match":
        st.error(f"Reputation provider match: {', '.join(reputation['threat_types'])}")
    else:
        st.success("The configured reputation provider returned no matching threat.")
    render_recommendations(report)


def render_evidence(report: dict) -> None:
    frame = evidence_frame(report)
    st.subheader("Explainable evidence ledger")
    st.caption("Signals identify their destination and provenance. Repeated rules contribute their maximum weight once across the redirect chain; rule confidence is an uncalibrated heuristic.")
    if frame.empty:
        st.success("No evidence objects were returned.")
        return
    st.dataframe(
        frame,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Severity": st.column_config.TextColumn("Severity"),
            "Score": st.column_config.NumberColumn("Score", format="%d"),
            "Confidence": st.column_config.TextColumn("Confidence"),
            "Detail": st.column_config.TextColumn("Evidence detail", width="large"),
        },
    )
    counts = frame["Severity"].value_counts().rename_axis("Severity").reset_index(name="Signals")
    st.bar_chart(counts.set_index("Severity"), height=180)


st.title("PhishShield")
st.caption("Explainable URL investigation console for SOC triage and threat-intelligence review.")

with st.sidebar:
    st.header("Investigation controls")
    st.write("PhishShield combines local URL heuristics, bounded network evidence, DNS collection, and optional enrichment.")
    static_only = st.checkbox("Static analysis only", value=False, help="Inspect URL syntax without DNS, HTTP, or reputation requests.")
    total_timeout = st.slider("Target collection budget (seconds)", min_value=5, max_value=90, value=30)
    timeout = st.slider("Network timeout (seconds)", min_value=3, max_value=20, value=8)
    max_redirects = st.slider("Maximum redirects", min_value=1, max_value=20, value=10)
    follow_redirects = st.checkbox("Collect HTTP and follow redirects", value=True, disabled=static_only)
    enable_reputation = st.checkbox(
        "Enable reputation lookup",
        value=False,
        disabled=static_only,
        help="Only enable this when policy permits sending the URL to the configured provider.",
    )
    st.divider()
    st.info("Do not submit credentials or open suspicious URLs in a normal browser. Use an isolated analysis environment.")
    st.caption("Reputation providers are intentionally not enabled by default because URL sharing can have privacy and compliance implications.")

with st.form("investigation_form"):
    url = st.text_input("URL to investigate", placeholder="https://example.com/login", help="Only http:// and https:// URLs are supported. If omitted, https:// is assumed.")
    submitted = st.form_submit_button("Run investigation", type="primary", use_container_width=True)

if submitted:
    try:
        with st.spinner("Collecting explainable evidence…"):
            report = URLAnalyzer(
                url,
                timeout=timeout,
                max_redirects=max_redirects,
                follow_redirects=follow_redirects,
                enable_reputation=enable_reputation,
                static_only=static_only,
                total_timeout=total_timeout,
            ).analyze()
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    cases = st.session_state.setdefault("cases", {})
    cases[report["case_id"]] = report
    while len(cases) > 20:
        del cases[next(iter(cases))]
    st.session_state["selected_case"] = report["case_id"]

cases = st.session_state.get("cases", {})
if cases:
    selected = st.selectbox(
        "Session investigations", list(reversed(cases)), key="selected_case",
        format_func=lambda case: f"{cases[case]['generated_at'][:19]} · {cases[case]['verdict']} · {defang_url(cases[case]['subject']['url'])[:90]}",
    )
    report = cases[selected]
    st.caption(f"Case {report['case_id']} · Engine {report['engine_version']} · Rules {report['ruleset_version']}")
    st.caption("History and analyst notes last for this browser session. Download cases to retain them.")
    analyst = report.setdefault("analyst", {"disposition": "Unreviewed", "notes": ""})
    with st.expander("Analyst disposition and notes"):
        options = ["Unreviewed", "Investigating", "Benign", "Suspicious", "Malicious"]
        analyst["disposition"] = st.selectbox("Disposition", options, index=options.index(analyst["disposition"]), key=f"disposition_{selected}")
        analyst["notes"] = st.text_area("Analyst notes", value=analyst["notes"], key=f"notes_{selected}")
        st.caption("Analyst disposition is recorded separately from the automated risk band.")
    st.write("**Defanged IOCs — copy for your investigation**")
    st.code("\n".join(dict.fromkeys(defang_url(item) for item in report["network"]["redirect_chain"])))
    st.divider()
    overview, evidence, redirects, infrastructure, raw = st.tabs(
        ["Disposition", "Evidence ledger", "Redirect path", "Infrastructure", "Case export"]
    )

    with overview:
        render_overview(report)

    with evidence:
        render_evidence(report)

    with redirects:
        network = report["network"]
        st.subheader("Redirect and transport evidence")
        first, second, third = st.columns(3)
        first.metric("Network status", network["status"].title())
        second.metric("Redirect count", network["redirect_count"])
        third.metric("Final status", network["status_code"] or "Unavailable")
        graph = redirect_graph([defang_url(item) for item in network["redirect_chain"]])
        if graph:
            st.plotly_chart(graph, use_container_width=True, config={"displayModeBar": False})
        st.dataframe(
            {"Step": list(range(1, len(network["redirect_chain"]) + 1)), "URL": [defang_url(item) for item in network["redirect_chain"]]},
            hide_index=True,
            use_container_width=True,
        )
        if network["error"]:
            st.warning(network["error"])

    with infrastructure:
        render_domain_intelligence(report)

    with raw:
        st.subheader("Case export")
        st.write("The export includes schema version, collection time, evidence provenance, network state, DNS state, coverage, and recommendations.")
        include_sensitive = st.checkbox("Include full URL query values and fragments in export", value=False, key=f"sensitive_{selected}")
        export_report = report if include_sensitive else redact_report(report)
        st.caption("Default export redacts URL query values and removes fragments. Hostnames, paths and analyst notes remain; review before sharing.")
        st.download_button(
            "Download investigation JSON",
            data=json.dumps(export_report, indent=2),
            file_name=f"phishshield-{report['case_id']}.json",
            mime="application/json",
            use_container_width=True,
        )
        with st.expander("View raw report"):
            st.json(export_report)
