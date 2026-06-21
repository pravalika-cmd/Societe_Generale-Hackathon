import dash
from dash import html, dcc, Input, Output, callback
import dash_bootstrap_components as dbc
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os

# Register page
dash.register_page(__name__, path="/privileges")

# Map privilege levels to numbers for heatmap coloring
PRIVILEGE_SCALE = {
    "None": 0,
    "User": 1,
    "Read Only": 2,
    "Power User": 3,
    "Admin": 4
}

def layout():
    identities_path = "data/unified_identities.csv"
    matrix_path = "data/privilege_matrix.csv"
    
    if not os.path.exists(identities_path) or not os.path.exists(matrix_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df_identities = pd.read_csv(identities_path)
    
    # Get unique filter values
    departments = sorted(df_identities["Department"].dropna().unique())
    identity_types = sorted(df_identities["Identity Type"].dropna().unique())

    return html.Div(
        [
            html.Div(
                [
                    html.H2("CROSS-PLATFORM PRIVILEGE MATRIX", className="text-white mb-1"),
                    html.P("Correlation of active privileges across directories, cloud providers, and identity providers to detect over-privilege and identity sprawl.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Filters Row
            html.Div(
                dbc.Row(
                    [
                        # Department Filter
                        dbc.Col(
                            [
                                html.Label("Filter Department", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="priv-filter-department",
                                    options=[{"label": dept, "value": dept} for dept in departments],
                                    placeholder="All Departments",
                                    clearable=True,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=4, className="mb-3"
                        ),
                        
                        # Identity Type Filter
                        dbc.Col(
                            [
                                html.Label("Filter Identity Type", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="priv-filter-type",
                                    options=[{"label": itype, "value": itype} for itype in identity_types],
                                    placeholder="All Identity Types",
                                    clearable=True,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=4, className="mb-3"
                        ),
                        
                        # Top N users to display in Heatmap
                        dbc.Col(
                            [
                                html.Label("Show Top Riskiest", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="priv-show-limit",
                                    options=[
                                        {"label": "Top 10 Users", "value": 10},
                                        {"label": "Top 20 Users", "value": 20},
                                        {"label": "Top 50 Users", "value": 50}
                                    ],
                                    value=20,
                                    clearable=False,
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=4, className="mb-3"
                        ),
                    ]
                ),
                className="security-card mb-4"
            ),
            
            # Heatmap Visual Card
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("PRIVILEGE HEATMAP", className="mb-1 text-white"),
                                html.P("Hover over cells to review effective, direct, and inherited privilege mappings.", className="text-secondary mb-3", style={"fontSize": "12px"}),
                                dcc.Graph(id="privilege-heatmap", config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            ),
            
            # Stacked Bar Distribution Card
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("PLATFORM PRIVILEGE LEVEL DISTRIBUTION", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(id="privilege-distribution-bar", config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ]
            )
        ]
    )

# Combined callback for updating both graphs based on filters
@callback(
    [
        Output("privilege-heatmap", "figure"),
        Output("privilege-distribution-bar", "figure")
    ],
    [
        Input("priv-filter-department", "value"),
        Input("priv-filter-type", "value"),
        Input("priv-show-limit", "value")
    ]
)
def update_privilege_graphs(dept, itype, limit):
    df_identities = pd.read_csv("data/unified_identities.csv").fillna("None")
    df_matrix = pd.read_csv("data/privilege_matrix.csv").fillna("None")
    
    # Merge datasets on username
    df_merged = pd.merge(
        df_identities, 
        df_matrix, 
        left_on="User Name", 
        right_on="username", 
        how="inner"
    )
    
    # Apply filters
    if dept:
        df_merged = df_merged[df_merged["Department"] == dept]
    if itype:
        df_merged = df_merged[df_merged["Identity Type"] == itype]
        
    # --- Graph 1: Privilege Heatmap (Top N riskiest users) ---
    df_heatmap_subset = df_merged.sort_values(by="Risk Score", ascending=False).head(limit)
    
    platforms = ["Active Directory", "AWS IAM", "Okta"]
    
    # Construct 2D arrays for colors/values and hover details
    heatmap_z = []
    heatmap_hover_text = []
    heatmap_y = []
    
    # Store custom data for hovertemplate:
    # 0: privilege string, 1: effective privilege, 2: direct privilege, 3: inherited privilege
    custom_data_arr = []
    
    for idx, row in df_heatmap_subset.iterrows():
        heatmap_y.append(row["User Name"])
        z_row = []
        custom_data_row = []
        
        for plat in platforms:
            priv_str = row[plat]
            z_val = PRIVILEGE_SCALE.get(priv_str, 0)
            z_row.append(z_val)
            
            # Determine suffix for accessing details in the matrix
            suffix = "ad" if plat == "Active Directory" else ("aws" if plat == "AWS IAM" else "okta")
            eff = row[f"{suffix}_effective_privilege"]
            direct = row[f"{suffix}_direct_privilege"]
            inh = row[f"{suffix}_inherited_privilege"]
            
            custom_data_row.append([priv_str, eff, direct, inh])
            
        heatmap_z.append(z_row)
        custom_data_arr.append(custom_data_row)
        
    # If no users match filters, return empty dashboard placeholder
    if not heatmap_y:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            xaxis={"visible": False}, yaxis={"visible": False},
            annotations=[{"text": "No records found matching filters.", "xref": "paper", "yref": "paper", "showarrow": False, "font": {"size": 16, "color": "#94a3b8"}}],
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
        )
        return empty_fig, empty_fig

    # Custom colorscale: None -> Dark gray, User -> Blue, Read Only -> Teal, Power User -> Yellow, Admin -> Red
    custom_colorscale = [
        [0.0, "#131924"],   # None
        [0.25, "#3b82f6"],  # User (Blue)
        [0.5, "#06b6d4"],   # Read Only (Teal)
        [0.75, "#eab308"],  # Power User (Yellow/Orange)
        [1.0, "#ef4444"]    # Admin (Red)
    ]

    fig_heatmap = go.Figure(
        data=go.Heatmap(
            z=heatmap_z,
            x=platforms,
            y=heatmap_y,
            colorscale=custom_colorscale,
            showscale=True,
            zmin=0,
            zmax=4,
            customdata=custom_data_arr,
            hovertemplate="""
            <b>User:</b> %{y}<br>
            <b>Platform:</b> %{x}<br>
            <b>Assigned Privilege:</b> %{customdata[0]}<br>
            <b>Effective Access:</b> %{customdata[1]}<br>
            <b>Direct Access:</b> %{customdata[2]}<br>
            <b>Inherited Access:</b> %{customdata[3]}<extra></extra>
            """,
            colorbar=dict(
                title=dict(text="Access Level", font=dict(color="#f8fafc")),
                tickvals=[0, 1, 2, 3, 4],
                ticktext=["None", "User", "Read Only", "Power User", "Admin"],
                tickfont=dict(color="#94a3b8")
            )
        )
    )
    
    fig_heatmap.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        margin=dict(t=10, b=10, l=10, r=10),
        height=max(300, len(heatmap_y) * 20 + 100),
        xaxis=dict(tickfont=dict(size=12, color="#f8fafc"), side="top"),
        yaxis=dict(tickfont=dict(size=11, color="#94a3b8"), autorange="reversed")
    )

    # --- Graph 2: Platform Privilege Distribution (Stacked Bar) ---
    dist_data = []
    levels = ["Admin", "Power User", "Read Only", "User", "None"]
    # Enforce standard colors for stacked bars
    dist_colors = {
        "Admin": "#ef4444",
        "Power User": "#eab308",
        "Read Only": "#06b6d4",
        "User": "#3b82f6",
        "None": "#1e293b"
    }
    
    for lvl in levels:
        row_counts = []
        for plat in platforms:
            count = len(df_merged[df_merged[plat] == lvl])
            row_counts.append(count)
        dist_data.append(go.Bar(
            name=lvl,
            x=platforms,
            y=row_counts,
            marker_color=dist_colors[lvl]
        ))
        
    fig_bar = go.Figure(data=dist_data)
    fig_bar.update_layout(
        barmode="stack",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        margin=dict(t=20, b=20, l=10, r=10),
        height=320,
        xaxis=dict(tickfont=dict(color="#f8fafc"), linecolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", tickfont=dict(color="#94a3b8")),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )

    return fig_heatmap, fig_bar
