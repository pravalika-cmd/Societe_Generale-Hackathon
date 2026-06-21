import dash
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime, timedelta

# Register page
dash.register_page(__name__, path="/dormancy")

def get_dormancy_bin(days):
    if days <= 30:
        return "0–30 Days"
    elif days <= 60:
        return "31–60 Days"
    elif days <= 90:
        return "61–90 Days"
    elif days <= 180:
        return "91–180 Days"
    else:
        return "180+ Days"

def layout():
    identities_path = "data/unified_identities.csv"
    matrix_path = "data/privilege_matrix.csv"
    incidents_path = "data/incidents.csv"
    
    if not os.path.exists(identities_path) or not os.path.exists(matrix_path) or not os.path.exists(incidents_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")

    # Load data
    df_id = pd.read_csv(identities_path).fillna("None")
    df_matrix = pd.read_csv(matrix_path).fillna("None")
    df_incidents = pd.read_csv(incidents_path).fillna("None")

    # Let's compute dormancy metrics per user using real data
    current_date = datetime(2026, 6, 21)

    dormancy_data = []
    for idx, row in df_id.iterrows():
        uname = row["User Name"]
        risks = str(row["Detected Risks"])
        
        # Calculate privilege rank
        pm_rows = df_matrix[df_matrix["username"] == uname]
        if len(pm_rows) > 0:
            pm = pm_rows.iloc[0]
            privs = [pm["Active Directory"], pm["AWS IAM"], pm["Okta"]]
        else:
            privs = ["None", "None", "None"]
        
        # Highest privilege
        highest_priv = "User"
        if "Admin" in privs:
            highest_priv = "Admin"
        elif "Power User" in privs:
            highest_priv = "Power User"
        elif "Read Only" in privs:
            highest_priv = "Read Only"
            
        # Get actual dormancy days
        try:
            dormancy_days = int(float(row["days_since_last_login"]))
        except (ValueError, KeyError, TypeError):
            dormancy_days = 999
            
        last_login_date = current_date - timedelta(days=dormancy_days)
        dormancy_bin = get_dormancy_bin(dormancy_days)
        
        # Severity of dormancy
        if dormancy_days > 180 and highest_priv == "Admin":
            sev = "Critical"
        elif dormancy_days > 90 and highest_priv in ["Admin", "Power User"]:
            sev = "High"
        elif dormancy_days > 30 and highest_priv in ["Admin", "Power User", "Read Only"]:
            sev = "Medium"
        else:
            sev = "Low"

        dormancy_data.append({
            "User": uname,
            "Department": row["Department"],
            "Last Login": last_login_date.strftime("%Y-%m-%d"),
            "Dormancy Days": dormancy_days,
            "Dormancy Bin": dormancy_bin,
            "Privilege Level": highest_priv,
            "Severity": sev
        })

    df_dorm = pd.DataFrame(dormancy_data)

    # 1. Dormancy Distribution Histogram
    bin_order = ["0–30 Days", "31–60 Days", "61–90 Days", "91–180 Days", "180+ Days"]
    df_bins = df_dorm["Dormancy Bin"].value_counts().reindex(bin_order, fill_value=0).reset_index()
    df_bins.columns = ["Inactivity Period", "Account Count"]
    
    fig_dist = px.bar(
        df_bins,
        x="Inactivity Period",
        y="Account Count",
        color_discrete_sequence=["#00f2fe"],
        labels={"Account Count": "Total Accounts"}
    )
    fig_dist.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(showgrid=False, linecolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
        margin=dict(t=20, b=20, l=10, r=10),
        height=280
    )

    # 2. Dormancy Heatmap (Departments vs Inactivity periods)
    heatmap_pivot = df_dorm.pivot_table(
        index="Department",
        columns="Dormancy Bin",
        values="User",
        aggfunc="count",
        fill_value=0
    )
    # Enforce column sorting
    heatmap_pivot = heatmap_pivot.reindex(columns=bin_order, fill_value=0)
    
    fig_heatmap = go.Figure(
        data=go.Heatmap(
            z=heatmap_pivot.values,
            x=heatmap_pivot.columns,
            y=heatmap_pivot.index,
            colorscale="Viridis",
            showscale=True,
            hovertemplate="""
            <b>Dept:</b> %{y}<br>
            <b>Range:</b> %{x}<br>
            <b>Accounts:</b> %{z}<extra></extra>
            """
        )
    )
    fig_heatmap.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        margin=dict(t=20, b=20, l=10, r=10),
        height=280,
        xaxis=dict(tickfont=dict(size=11), side="bottom"),
        yaxis=dict(tickfont=dict(size=11, color="#94a3b8"))
    )

    # 3. Dormant Admins Table (Highly privileged and inactive > 30 days)
    df_dorm_admins = df_dorm[
        (df_dorm["Dormancy Days"] > 30) & 
        (df_dorm["Privilege Level"].isin(["Admin", "Power User"]))
    ].sort_values(by="Dormancy Days", ascending=False)

    table_dormant = dash_table.DataTable(
        id="dormant-table",
        columns=[
            {"name": "User", "id": "User"},
            {"name": "Department", "id": "Department"},
            {"name": "Last Login", "id": "Last Login"},
            {"name": "Dormancy Days", "id": "Dormancy Days"},
            {"name": "Privilege Level", "id": "Privilege Level"},
            {"name": "Severity", "id": "Severity"}
        ],
        data=df_dorm_admins.to_dict("records"),
        page_size=12,
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
            # Color severity
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
                    html.H2("ACCOUNT DORMANCY ANALYSIS", className="text-white mb-1"),
                    html.P("Identifies stale, unused accounts that possess administrative rights, representing high-exposure attack vectors.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Row 1: Visual Charts
            dbc.Row(
                [
                    # Heatmap
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("DEPARTMENTAL DORMANCY MAP", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_heatmap, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12, lg=6
                    ),
                    # Histogram
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("INACTIVITY RANGE DISTRIBUTION", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_dist, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12, lg=6
                    )
                ]
            ),
            
            # Row 2: Dormant Admins DataTable
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.H5("DORMANT PRIVILEGED ACCOUNTS CATALOG", className="mb-0 text-white"),
                                        html.Span("Lists all administrative or power user accounts that have been inactive for more than 30 days.", style={"color": "#64748b", "fontSize": "12px"})
                                    ],
                                    className="mb-3"
                                ),
                                html.Div(table_dormant, className="table-responsive")
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            )
        ]
    )
