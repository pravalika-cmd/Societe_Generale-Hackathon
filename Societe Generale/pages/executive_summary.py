import dash
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from utils.data_adapter import BACKEND_DIR

# Register page with path '/' (landing page)
dash.register_page(__name__, path="/")

def get_kpi_card(title, value, risk_class, icon_class):
    return html.Div(
        [
            html.Div(
                [
                    html.I(className=f"{icon_class} text-secondary fs-4"),
                    html.Span(title, className="kpi-label ms-2"),
                ],
                className="d-flex align-items-center justify-content-between mb-2"
            ),
            html.Div(f"{value}", className="kpi-val")
        ],
        className=f"kpi-card {risk_class}"
    )

def layout():
    # Load dummy CSV files. Real backend files can overwrite these paths directly.
    # Paths are relative to the root directory where app.py resides.
    identities_path = "data/unified_identities.csv"
    offboarding_path = "data/offboarding_findings.csv"
    
    if not os.path.exists(identities_path) or not os.path.exists(offboarding_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df = pd.read_csv(identities_path)
    df_off = pd.read_csv(offboarding_path)

    # 1. Calculate KPI Metrics
    total_identities = len(df)
    critical_risks = len(df[df["Severity"] == "Critical"])
    high_risks = len(df[df["Severity"] == "High"])
    medium_risks = len(df[df["Severity"] == "Medium"])
    low_risks = len(df[df["Severity"] == "Low"])
    
    offboarding_gaps = len(df_off)
    
    dormant_admins = len(df[df["Detected Risks"].str.contains("Dormant Admin", na=False)])
    hidden_admins = len(df[df["Detected Risks"].str.contains("Hidden Admin", na=False)])

    # Calculate Alert Reduction Metrics
    audit_events_path = os.path.join(BACKEND_DIR, "data", "audit_events.csv")
    if os.path.exists(audit_events_path):
        df_audit = pd.read_csv(audit_events_path)
        ad_alerts = len(df_audit[df_audit["platform"] == "AD"])
        aws_alerts = len(df_audit[df_audit["platform"] == "AWS"])
        okta_alerts = len(df_audit[df_audit["platform"] == "Okta"])
    else:
        ad_alerts = 258
        aws_alerts = 328
        okta_alerts = 274
        
    raw_alerts = ad_alerts + aws_alerts + okta_alerts
    consolidated_incidents = total_identities
    alert_reduction_pct = round(((raw_alerts - consolidated_incidents) / raw_alerts) * 100, 1)

    # 2. Risk Distribution Donut Chart
    severity_counts = df["Severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    # Enforce standard colors
    color_map = {
        "Critical": "#ff4d4d",
        "High": "#ff944d",
        "Medium": "#ffdb4d",
        "Low": "#2eb82e"
    }
    
    fig_donut = px.pie(
        severity_counts, 
        values="Count", 
        names="Severity", 
        hole=0.6,
        color="Severity",
        color_discrete_map=color_map,
        category_orders={"Severity": ["Critical", "High", "Medium", "Low"]}
    )
    fig_donut.update_traces(
        textinfo="percent", 
        hoverinfo="label+value",
        marker=dict(line=dict(color="#131924", width=2))
    )
    fig_donut.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5),
        margin=dict(t=10, b=80, l=10, r=10),
        height=300
    )

    # 3. Risks by Department Bar Chart
    df_risky = df[df["Risk Score"] >= 50]
    dept_risks = df_risky["Department"].value_counts().reset_index()
    dept_risks.columns = ["Department", "Risky Identities"]
    dept_risks = dept_risks.sort_values(by="Risky Identities", ascending=True)
    
    fig_bar = px.bar(
        dept_risks,
        y="Department",
        x="Risky Identities",
        orientation="h",
        color_discrete_sequence=["#00f2fe"],
        labels={"Risky Identities": "High/Critical Risk Counts"}
    )
    fig_bar.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=False, linecolor="rgba(255,255,255,0.1)"),
        margin=dict(t=20, b=20, l=10, r=10),
        height=280
    )

    # 4. Alert Consolidation Flow Diagram (Sankey)
    fig_sankey = go.Figure(data=[go.Sankey(
        node = dict(
          pad = 15,
          thickness = 15,
          line = dict(color = "#1b2333", width = 0.5),
          label = [f"AD Alerts ({ad_alerts})", f"AWS Alerts ({aws_alerts})", f"Okta Alerts ({okta_alerts})", f"Consolidated Incidents ({consolidated_incidents})"],
          color = ["#3b82f6", "#eab308", "#ef4444", "#00f2fe"]
        ),
        link = dict(
          source = [0, 1, 2],
          target = [3, 3, 3],
          value = [ad_alerts, aws_alerts, okta_alerts],
          color = ["rgba(59, 130, 246, 0.15)", "rgba(234, 179, 8, 0.15)", "rgba(239, 68, 68, 0.15)"]
        )
    )])
    fig_sankey.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc", size=10),
        margin=dict(t=20, b=20, l=10, r=10),
        height=220
    )

    # 5. Top 10 Riskiest Users Table
    df_top_10 = df.sort_values(by="Risk Score", ascending=False).head(10)[["User Name", "Department", "Risk Score", "Severity"]]
    
    table_top_10 = dash_table.DataTable(
        id="top-10-table",
        columns=[
            {"name": "User", "id": "User Name"},
            {"name": "Department", "id": "Department"},
            {"name": "Risk Score", "id": "Risk Score"},
            {"name": "Severity", "id": "Severity"}
        ],
        data=df_top_10.to_dict("records"),
        style_cell={"textAlign": "left", "fontFamily": "'Inter', sans-serif"},
        style_header={
            "backgroundColor": "#1b2333",
            "fontWeight": "bold",
            "color": "#f8fafc",
            "border": "1px solid rgba(255, 255, 255, 0.08)"
        },
        style_data={
            "backgroundColor": "#131924",
            "color": "#f8fafc",
            "border": "1px solid rgba(255, 255, 255, 0.08)"
        },
        style_data_conditional=[
            {
                "if": {"column_id": "Severity", "filter_query": '{Severity} eq "Critical"'},
                "color": "#ff4d4d",
                "fontWeight": "bold"
            },
            {
                "if": {"column_id": "Severity", "filter_query": '{Severity} eq "High"'},
                "color": "#ff944d",
                "fontWeight": "bold"
            },
            {
                "if": {"column_id": "Severity", "filter_query": '{Severity} eq "Medium"'},
                "color": "#ffdb4d",
                "fontWeight": "bold"
            },
            {
                "if": {"column_id": "Severity", "filter_query": '{Severity} eq "Low"'},
                "color": "#2eb82e",
                "fontWeight": "bold"
            }
        ]
    )

    return html.Div(
        [
            # Title banner
            html.Div(
                [
                    html.H2("EXECUTIVE RISK SUMMARY", className="text-white mb-1"),
                    html.P("Real-time aggregation of access vulnerabilities, orphaned sessions, and privilege abuse vectors across active infrastructure.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Row 1: KPI Cards (Grid layout)
            dbc.Row(
                [
                    dbc.Col(get_kpi_card("Total Identities", total_identities, "normal", "fa-solid fa-users"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("Critical Risks", critical_risks, "critical", "fa-solid fa-circle-exclamation"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("High Risks", high_risks, "high", "fa-solid fa-triangle-exclamation"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("Medium Risks", medium_risks, "medium", "fa-solid fa-shield"), width=12, md=6, lg=3, className="mb-4"),
                ]
            ),
            
            # Row 1b: Alert Reduction Metrics KPIs
            dbc.Row(
                [
                    dbc.Col(get_kpi_card("Raw Security Alerts", raw_alerts, "high", "fa-solid fa-bell"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("Consolidated Incidents", consolidated_incidents, "normal", "fa-solid fa-compress"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("Alert Reduction Score", f"-{alert_reduction_pct}%", "low", "fa-solid fa-shield-halved"), width=12, md=6, lg=3, className="mb-4"),
                    dbc.Col(get_kpi_card("Offboarding Gaps", offboarding_gaps, "critical", "fa-solid fa-user-xmark"), width=12, md=6, lg=3, className="mb-4"),
                ]
            ),
            
            # Row 2: Charts Grid
            dbc.Row(
                [
                    # Risk Distribution Chart
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("RISK SEVERITY DISTRIBUTION", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_donut, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12, lg=5
                    ),
                    # Risks by Department Chart
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("HIGH RISK IDENTITIES BY DEPARTMENT", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_bar, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12, lg=7
                    )
                ]
            ),

            # Row 2b: Alert Consolidation Flow & Framework Alignment Posture
            dbc.Row(
                [
                    # Alert Reduction Sankey flow
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("ALERT CONSOLIDATION FLOW MODEL", className="mb-1 text-white"),
                                html.P("Aggregates redundant system warning events into structured corporate identity risks.", className="text-secondary mb-3", style={"fontSize": "11px"}),
                                dcc.Graph(figure=fig_sankey, config={"displayModeBar": False})
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=7, className="mb-4"
                    ),
                    # Framework mapping posture
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("COMPLIANCE FRAMEWORK ALIGNMENT", className="mb-2 text-white border-bottom pb-2 border-secondary"),
                                html.P("Identified anomalies automatically map to auditing controls under ISO 27001, SOC 2, NIST, and GDPR.", className="text-secondary mb-3", style={"fontSize": "12px"}),
                                html.Div(
                                    [
                                        html.Div([
                                            html.Span("NIST: ", style={"color": "#64748b", "fontWeight": "bold", "fontSize": "11px", "display": "inline-block", "width": "60px"}),
                                            html.Span("AC-2 (Account Mgt)", className="badge bg-dark border border-secondary text-info me-1 p-2 mb-1"),
                                            html.Span("AC-6 (Least Priv)", className="badge bg-dark border border-secondary text-info me-1 p-2 mb-1"),
                                            html.Span("IA-4 (ID Mgt)", className="badge bg-dark border border-secondary text-info p-2 mb-1")
                                        ], className="mb-2 d-flex align-items-center flex-wrap"),
                                        html.Div([
                                            html.Span("MITRE: ", style={"color": "#64748b", "fontWeight": "bold", "fontSize": "11px", "display": "inline-block", "width": "60px"}),
                                            html.Span("T1078 (Valid Accs)", className="badge bg-dark border border-secondary text-warning me-1 p-2 mb-1"),
                                            html.Span("T1098 (Acc Manipulation)", className="badge bg-dark border border-secondary text-warning me-1 p-2 mb-1"),
                                            html.Span("T1550 (Token Abuse)", className="badge bg-dark border border-secondary text-warning p-2 mb-1")
                                        ], className="mb-2 d-flex align-items-center flex-wrap"),
                                        html.Div([
                                            html.Span("GDPR: ", style={"color": "#64748b", "fontWeight": "bold", "fontSize": "11px", "display": "inline-block", "width": "60px"}),
                                            html.Span("Art. 5 (Data Principle)", className="badge bg-dark border border-secondary text-danger me-1 p-2 mb-1"),
                                            html.Span("Art. 32 (Security)", className="badge bg-dark border border-secondary text-danger p-2 mb-1")
                                        ], className="mb-2 d-flex align-items-center flex-wrap"),
                                        html.Div([
                                            html.Span("CIS: ", style={"color": "#64748b", "fontWeight": "bold", "fontSize": "11px", "display": "inline-block", "width": "60px"}),
                                            html.Span("Control 5 (Account Inventory)", className="badge bg-dark border border-secondary text-success me-1 p-2 mb-1"),
                                            html.Span("Control 6 (Access Control)", className="badge bg-dark border border-secondary text-success p-2 mb-1")
                                        ], className="d-flex align-items-center flex-wrap")
                                    ]
                                )
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=5, className="mb-4"
                    )
                ]
            ),
            
            # Row 3: Riskiest Users Table
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("TOP 10 RISKIEST IDENTITIES UNDER INVESTIGATION", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                html.Div(table_top_10, className="table-responsive")
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            )
        ]
    )
