import dash
from dash import html, dcc, dash_table, Input, Output, State, callback, no_update
import dash_bootstrap_components as dbc
import pandas as pd
import os

# Register page
dash.register_page(__name__, path="/risk-list")

def layout():
    identities_path = "data/unified_identities.csv"
    if not os.path.exists(identities_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df = pd.read_csv(identities_path)
    
    # Get unique filter values
    departments = sorted(df["Department"].dropna().unique())
    severities = ["Critical", "High", "Medium", "Low"]
    platforms = ["Active Directory", "AWS IAM", "Okta"]

    return html.Div(
        [
            html.Div(
                [
                    html.H2("IDENTITY RISK INDEX", className="text-white mb-1"),
                    html.P("Comprehensive directory of enterprise identity footprints, tracking correlated privilege levels and dynamic risk rankings.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Row of Filters
            html.Div(
                dbc.Row(
                    [
                        # Search Username
                        dbc.Col(
                            [
                                html.Label("Search Username", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Input(
                                    id="search-username",
                                    type="text",
                                    placeholder="Enter username...",
                                    className="w-100 search-input py-2 px-3 text-white"
                                )
                            ],
                            width=12, md=3, className="mb-3"
                        ),
                        
                        # Department Filter
                        dbc.Col(
                            [
                                html.Label("Filter Department", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="filter-department",
                                    options=[{"label": dept, "value": dept} for dept in departments],
                                    placeholder="All Departments",
                                    clearable=True,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=3, className="mb-3"
                        ),
                        
                        # Severity Filter
                        dbc.Col(
                            [
                                html.Label("Filter Severity", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="filter-severity",
                                    options=[{"label": sev, "value": sev} for sev in severities],
                                    placeholder="All Severities",
                                    clearable=True,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=3, className="mb-3"
                        ),
                        
                        # Platform Filter
                        dbc.Col(
                            [
                                html.Label("Filter Platform", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="filter-platform",
                                    options=[{"label": plat, "value": plat} for plat in platforms],
                                    placeholder="All Platforms",
                                    clearable=True,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=3, className="mb-3"
                        ),
                    ]
                ),
                className="security-card mb-4"
            ),
            
            # Row of DataTable
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.H5("IDENTITIES INDEX", className="mb-0 text-white"),
                                        html.Span("Click any row to drill down into incident details and remediation steps.", style={"color": "#64748b", "fontSize": "12px"})
                                    ],
                                    className="mb-3"
                                ),
                                
                                dash_table.DataTable(
                                    id="identity-risk-table",
                                    columns=[
                                        {"name": "Rank", "id": "Rank"},
                                        {"name": "User Name", "id": "User Name"},
                                        {"name": "Department", "id": "Department"},
                                        {"name": "Identity Type", "id": "Identity Type"},
                                        {"name": "Platforms", "id": "Platforms"},
                                        {"name": "Risk Score", "id": "Risk Score"},
                                        {"name": "Severity", "id": "Severity"},
                                        {"name": "Detected Risks", "id": "Detected Risks"}
                                    ],
                                    data=[], # Populated via callback
                                    page_size=15,
                                    page_action="native",
                                    sort_action="native",
                                    sort_by=[{"column_id": "Risk Score", "direction": "desc"}],
                                    export_format="csv",
                                    export_headers="display",
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
                                        # Color cells based on severity
                                        {
                                            "if": {"column_id": "Severity", "filter_query": '{Severity} eq "Critical"'},
                                            "color": "#ff4d4d",
                                            "fontWeight": "bold",
                                            "backgroundColor": "rgba(255, 77, 77, 0.05)"
                                        },
                                        {
                                            "if": {"column_id": "Severity", "filter_query": '{Severity} eq "High"'},
                                            "color": "#ff944d",
                                            "fontWeight": "bold",
                                            "backgroundColor": "rgba(255, 148, 77, 0.05)"
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
                                        },
                                        # Subtle highlight on row hover handled by custom assets/style.css
                                    ]
                                )
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            )
        ]
    )

# Callback to filter the table
@callback(
    Output("identity-risk-table", "data"),
    [
        Input("search-username", "value"),
        Input("filter-department", "value"),
        Input("filter-severity", "value"),
        Input("filter-platform", "value")
    ]
)
def update_table(search_user, dept, severity, platform):
    df = pd.read_csv("data/unified_identities.csv")
    
    # Filter by search
    if search_user:
        df = df[df["User Name"].str.contains(search_user, case=False, na=False) | df["Display Name"].str.contains(search_user, case=False, na=False)]
        
    # Filter by department
    if dept:
        df = df[df["Department"] == dept]
        
    # Filter by severity
    if severity:
        df = df[df["Severity"] == severity]
        
    # Filter by platform
    if platform:
        df = df[df["Platforms"].str.contains(platform, case=False, na=False)]
        
    # Re-calculate rank based on sorted risk score of filtered set, or keep original rank
    # Keeping original rank is generally better for stable identification
    return df.to_dict("records")

# Callback to handle clicking a row and navigating to drilldown
@callback(
    [
        Output("selected-user-store", "data"),
        Output("url", "pathname", allow_duplicate=True)
    ],
    Input("identity-risk-table", "active_cell"),
    State("identity-risk-table", "data"),
    prevent_initial_call=True
)
def handle_row_click(active_cell, table_data):
    if not active_cell or not table_data:
        return no_update, no_update
        
    # Get the row index
    row_idx = active_cell["row"]
    # Get the username from that row
    try:
        username = table_data[row_idx]["User Name"]
        return {"selected_user": username}, "/drilldown"
    except Exception:
        return no_update, no_update
