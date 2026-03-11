import streamlit as st
import plotly.graph_objects as go
import networkx as nx

from engine import URLAnalyzer
from intelligence import resolve_ip,ip_info


st.set_page_config(
    page_title="PhishShield SOC",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>

.stApp {
background: linear-gradient(180deg,#0a0f1a,#05070d);
color:white;
}

h1,h2,h3 {
color:#00c8ff;
}

.block-container{
padding-top:2rem;
}

</style>
""",unsafe_allow_html=True)


st.title("🛡️ PhishShield — URL Forensic Investigation Dashboard")

url = st.text_input("Enter URL to Investigate")


def calculate_risk(meta):

    score = 0
    indicators = []

    if meta["entropy"] > 3.5:
        score += 20
        indicators.append("High domain entropy")

    if meta["has_ip"]:
        score += 30
        indicators.append("IP used in URL")

    if meta["has_keywords"]:
        score += 10
        indicators.append("Suspicious keyword")

    if len(meta["redirect_chain"]) > 2:
        score += 20
        indicators.append("Multiple redirects")

    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return verdict,score,indicators


def risk_gauge(score):

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text":"Risk Score"},
        gauge={
            "axis":{"range":[0,100]},
            "steps":[
                {"range":[0,30],"color":"green"},
                {"range":[30,60],"color":"yellow"},
                {"range":[60,100],"color":"red"}
            ]
        }
    ))

    return fig


def redirect_graph(chain):

    if len(chain) < 2:
        return None

    G = nx.DiGraph()

    for i in range(len(chain)-1):
        G.add_edge(chain[i],chain[i+1])

    pos = nx.spring_layout(G)

    edge_x=[]
    edge_y=[]

    for edge in G.edges():
        x0,y0 = pos[edge[0]]
        x1,y1 = pos[edge[1]]

        edge_x += [x0,x1,None]
        edge_y += [y0,y1,None]

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=2,color="#888"),
        hoverinfo="none",
        mode="lines"
    )

    node_x=[]
    node_y=[]
    text=[]

    for node in G.nodes():

        x,y = pos[node]

        node_x.append(x)
        node_y.append(y)
        text.append(node)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        text=text,
        mode="markers+text",
        textposition="top center",
        marker=dict(size=14,color="cyan")
    )

    fig = go.Figure(data=[edge_trace,node_trace])

    fig.update_layout(
        showlegend=False,
        margin=dict(l=20,r=20,t=20,b=20),
        plot_bgcolor="#0e1117"
    )

    return fig


if st.button("Start Investigation"):

    analyzer = URLAnalyzer(url)

    meta = analyzer.metadata()

    verdict,score,indicators = calculate_risk(meta)

    tab1,tab2,tab3,tab4 = st.tabs([
        "Overview",
        "Redirect Analysis",
        "Domain Intelligence",
        "Raw Data"
    ])

    with tab1:

        st.subheader("Verdict")

        if verdict == "SAFE":
            st.success(verdict)
        elif verdict == "SUSPICIOUS":
            st.warning(verdict)
        else:
            st.error(verdict)

        col1,col2 = st.columns(2)

        with col1:
            st.plotly_chart(risk_gauge(score),use_container_width=True)

        with col2:

            st.write("Indicators")

            for i in indicators:
                st.write("•",i)

    with tab2:

        st.subheader("Redirect Infrastructure")

        fig = redirect_graph(meta["redirect_chain"])

        if fig:
            st.plotly_chart(fig,use_container_width=True)
        else:
            st.info("No redirects detected")

    with tab3:

        st.subheader("Domain Intelligence")

        ip = resolve_ip(meta["domain"])

        if ip:

            info = ip_info(ip)

            col1,col2,col3 = st.columns(3)

            col1.metric("IP Address",ip)

            if info:
                col2.metric("ASN / Org",info["org"])
                col3.metric("Country",info["country"])

        else:

            st.warning("Unable to resolve IP")

    with tab4:

        st.subheader("Raw Metadata")

        st.json(meta)