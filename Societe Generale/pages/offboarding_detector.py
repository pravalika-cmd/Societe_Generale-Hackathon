import dash
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime

# Register page
dash.register_page(__name__, path="/offboarding")

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
    offboarding_path = "data/offboarding_findings.csv"
    if not os.path.exists(offboarding_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df = pd.read_csv(offboarding_path)

    # 1. Calculate KPIs
    total_gaps = len(df)
    critical_gaps = len(df[df["Exposure Days"] > 30])
    avg_exposure_days = round(df["Exposure Days"].mean(), 1) if total_gaps > 0 else 0

    # 2. Exposure Trend Chart
    # Sort by termination date to show chronological trend
    df_sorted = df.copy()
    df_sorted["Termination Date"] = pd.to_datetime(df_sorted["Termination Date"])
    df_sorted = df_sorted.sort_values(by="Termination Date")
    
    # Calculate cumulative gaps over time
    df_sorted["Gap Count"] = 1
    df_sorted["Cumulative Gaps"] = df_sorted["Gap Count"].cumsum()
    
    fig_trend = px.line(
        df_sorted,
        x="Termination Date",
        y="Cumulative Gaps",
        color_discrete_sequence=["#ff4d4d"],
        labels={"Cumulative Gaps": "Cumulative Gaps Discovered", "Termination Date": "Timeline"}
    )
    fig_trend.update_traces(mode="lines+markers", marker=dict(size=6, color="#ff4d4d"))
    fig_trend.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
        margin=dict(t=20, b=20, l=10, r=10),
        height=300
    )

    # 3. Offboarding Gaps DataTable
    # Highlighting rows where AD is disabled but AWS/Okta are active.
    # In our DataTable, we will style the AWS Status and Okta Status cells to show warning highlight if Active
    table_offboarding = dash_table.DataTable(
        id="offboarding-table",
        columns=[
            {"name": "User", "id": "User"},
            {"name": "Termination Date", "id": "Termination Date"},
            {"name": "AD Status", "id": "AD Status"},
            {"name": "AWS Status", "id": "AWS Status"},
            {"name": "Okta Status", "id": "Okta Status"},
            {"name": "Exposure Days", "id": "Exposure Days"},
            {"name": "Severity", "id": "Severity"}
        ],
        data=df.to_dict("records"),
        page_size=10,
        sort_action="native",
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
            "border": "1px solid rgba(255, 255, 255, 0.05)"
        },
        style_data_conditional=[
            # Highlight AD Status (Disabled is standard/expected)
            {
                "if": {"column_id": "AD Status", "filter_query": '{AD Status} eq "Disabled"'},
                "color": "#64748b",
                "fontStyle": "italic"
            },
            # Highlight active AWS/Okta accounts as critical anomalies (since they should have been offboarded)
            {
                "if": {"column_id": "AWS Status", "filter_query": '{AWS Status} eq "Active"'},
                "backgroundColor": "rgba(255, 77, 77, 0.1)",
                "color": "#ff4d4d",
                "fontWeight": "bold"
            },
            {
                "if": {"column_id": "Okta Status", "filter_query": '{Okta Status} eq "Active"'},
                "backgroundColor": "rgba(255, 77, 77, 0.1)",
                "color": "#ff4d4d",
                "fontWeight": "bold"
            },
            # Colors based on severity
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
            }
        ]
    )

    return html.Div(
        [
            # Title
            html.Div(
                [
                    html.H2("OFFBOARDING GAP DETECTOR", className="text-white mb-1"),
                    html.P("Identifies lingering downstream accounts and orphaned access keys belonging to HR-terminated personnel.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Row 1: KPI Cards
            dbc.Row(
                [
                    dbc.Col(get_kpi_card("Total Offboarding Gaps", total_gaps, "critical", "fa-solid fa-circle-exclamation"), width=12, md=4, className="mb-4"),
                    dbc.Col(get_kpi_card("Critical Risks (>30 Days)", critical_gaps, "critical", "fa-solid fa-user-xmark"), width=12, md=4, className="mb-4"),
                    dbc.Col(get_kpi_card("Average Exposure Days", f"{avg_exposure_days} Days", "high", "fa-solid fa-calendar-days"), width=12, md=4, className="mb-4"),
                ]
            ),
            
            # Row 2: Trend Chart
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("EXPOSURE RISK TREND OVER TIME", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_trend, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            ),
            
            # Row 3: Offboarding Gaps DataTable
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.H5("LINGERING ORPHANED ACCOUNTS LISTING", className="mb-0 text-white"),
                                        html.Span("Critically highlights active AWS or Okta cloud identities linked to terminated Active Directory profiles.", style={"color": "#64748b", "fontSize": "12px"})
                                    ],
                                    className="mb-3"
                                ),
                                html.Div(table_offboarding, className="table-responsive")
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            )
        ]
    )
