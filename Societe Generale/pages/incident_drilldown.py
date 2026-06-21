import dash
from dash import html, dcc, Input, Output, State, callback, no_update
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime
from utils.copilot import query_copilot

# Register page
dash.register_page(__name__, path="/drilldown")

def layout():
    identities_path = "data/unified_identities.csv"
    if not os.path.exists(identities_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df = pd.read_csv(identities_path)
    usernames = sorted(df["User Name"].dropna().unique())

    return html.Div(
        [
            html.Div(
                [
                    html.H2("INCIDENT DRILLDOWN & INVESTIGATION", className="text-white mb-1"),
                    html.P("In-depth forensic analyzer for evaluating risk evidence, event history, and generating platform-specific access mitigation policies.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Select User Row
            html.Div(
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.Label("Select Identity to Investigate", className="text-secondary mb-1", style={"fontSize": "12px", "fontWeight": "600"}),
                                dcc.Dropdown(
                                    id="drilldown-user-dropdown",
                                    options=[{"label": u, "value": u} for u in usernames],
                                    placeholder="Choose username...",
                                    className="filter-dropdown"
                                )
                            ],
                            width=12, md=6
                        ),
                        dbc.Col(
                            html.Div(
                                [
                                    html.I(className="fa-solid fa-circle-info text-info me-2"),
                                    html.Span("Quick-tip: You can click any user in the Identity Risk List to jump directly here.")
                                ],
                                className="text-secondary d-flex align-items-center h-100 pt-4",
                                style={"fontSize": "13px"}
                            ),
                            width=12, md=6
                        )
                    ]
                ),
                className="security-card mb-4"
            ),
            
            # Main Drilldown Layout (Container filled dynamically via callback)
            html.Div(id="drilldown-content-container")
        ]
    )

# Callback to resolve selected user on page load (either from session store or query parameters)
@callback(
    Output("drilldown-user-dropdown", "value"),
    [Input("url", "search")],
    [State("selected-user-store", "data"),
     State("drilldown-user-dropdown", "value")]
)
def resolve_initial_user(url_search, store_data, current_val):
    # 1. Check URL parameters first (e.g. ?user=john.doe)
    if url_search:
        params = dict(x.split('=') for x in url_search.lstrip('?').split('&') if '=' in x)
        if "user" in params:
            return params["user"]
            
    # 2. Check global session store
    if store_data and "selected_user" in store_data:
        return store_data["selected_user"]
        
    # 3. Fallback to default (first user in list)
    if not current_val:
        df = pd.read_csv("data/unified_identities.csv")
        if len(df) > 0:
            return df.iloc[0]["User Name"]
            
    return current_val

# Callback to update the layout based on selected user
@callback(
    Output("drilldown-content-container", "children"),
    Input("drilldown-user-dropdown", "value")
)
def update_drilldown_content(username):
    if not username:
        return html.Div("Please select a user above to begin investigation.", className="text-secondary text-center p-5")
        
    # Load datasets
    df_identities = pd.read_csv("data/unified_identities.csv").fillna("None")
    df_matrix = pd.read_csv("data/privilege_matrix.csv").fillna("None")
    df_incidents = pd.read_csv("data/incidents.csv").fillna("None")
    
    # Extract specific user data
    user_row = df_identities[df_identities["User Name"] == username]
    if user_row.empty:
        return html.Div(f"User '{username}' not found in registry.", className="text-danger p-4")
        
    user_info = user_row.iloc[0]
    user_matrix = df_matrix[df_matrix["username"] == username].iloc[0]
    user_events = df_incidents[df_incidents["username"] == username].sort_values(by="event_timestamp", ascending=False)
    
    # Severity Badge helper
    sev = user_info["Severity"]
    badge_class = f"badge-risk badge-{sev.lower()}"
    
    # Formulate evidence metrics
    last_login = "N/A"
    if not user_events.empty:
        last_login = user_events.iloc[0]["event_timestamp"]
        
    token_age = "N/A"
    aws_key_age_val = user_info.get("AWS_api_key_age")
    if pd.notna(aws_key_age_val) and str(aws_key_age_val).strip() not in ["", "None", "nan"]:
        try:
            days = int(float(aws_key_age_val))
            token_age = f"{days} Days"
            if "Token Abuse" in str(user_info["Detected Risks"]):
                token_age += " (EXPIRED)"
        except ValueError:
            token_age = str(aws_key_age_val)
        
    group_membership = "None"
    direct_grps_val = user_info.get("direct_groups")
    if pd.notna(direct_grps_val) and str(direct_grps_val).strip() not in ["", "None", "nan"]:
        group_membership = ", ".join([g.strip() for g in str(direct_grps_val).split("|")])
        
    # --- Load Risk Score Breakdown (Enhancement 2) ---
    df_results = pd.read_csv("data/risk_results.csv").fillna("None")
    user_res = df_results[df_results["username"] == username]
    
    if not user_res.empty:
        breadth_score = float(user_res.iloc[0]["privilege_breadth_score"])
        dormancy_score = float(user_res.iloc[0]["dormancy_score"])
        spread_score = float(user_res.iloc[0]["platform_spread_score"])
        offboarding_score = float(user_res.iloc[0]["offboarding_score"])
    else:
        # Fallback values
        breadth_score = round(user_info["Risk Score"] * 0.4, 1)
        dormancy_score = round(user_info["Risk Score"] * 0.3, 1)
        spread_score = round(user_info["Risk Score"] * 0.3, 1)
        offboarding_score = 0.0

    fig_breakdown = go.Figure(go.Bar(
        x=[breadth_score, dormancy_score, spread_score, offboarding_score],
        y=["Breadth  ", "Dormancy  ", "Spread  ", "Offboarding  "],
        orientation="h",
        marker_color=["#3b82f6", "#eab308", "#06b6d4", "#ef4444"],
        hovertemplate="Factor: %{y}<br>Contribution: +%{x}<extra></extra>"
    ))
    fig_breakdown.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=False, linecolor="rgba(255,255,255,0.1)"),
        margin=dict(t=10, b=10, l=10, r=10),
        height=180
    )

    # --- Load Direct vs Effective Privilege tables (Enhancement 1) ---
    direct_rows = [
        html.Tr([
            html.Td("Active Directory"),
            html.Td(user_matrix["ad_direct_privilege"]),
            html.Td(user_matrix["Active Directory"], style={"color": "#ff944d" if user_matrix["Active Directory"] == "Admin" else "#94a3b8", "fontWeight": "bold"})
        ]),
        html.Tr([
            html.Td("AWS IAM"),
            html.Td(user_matrix["aws_direct_privilege"]),
            html.Td(user_matrix["AWS IAM"], style={"color": "#ff4d4d" if user_matrix["AWS IAM"] == "Admin" else "#94a3b8", "fontWeight": "bold"})
        ]),
        html.Tr([
            html.Td("Okta"),
            html.Td(user_matrix["okta_direct_privilege"]),
            html.Td(user_matrix["Okta"], style={"color": "#ffdb4d" if user_matrix["Okta"] == "Admin" else "#94a3b8", "fontWeight": "bold"})
        ])
    ]

    ad_chain = f"{user_matrix['ad_direct_privilege']} → {user_matrix['ad_inherited_privilege']}" if user_matrix["ad_inherited_privilege"] != "None" else "Direct Assignment"
    aws_chain = f"{user_matrix['aws_direct_privilege']} → {user_matrix['aws_inherited_privilege']}" if user_matrix["aws_inherited_privilege"] != "None" else "Direct Assignment"
    okta_chain = f"{user_matrix['okta_direct_privilege']} → {user_matrix['okta_inherited_privilege']}" if user_matrix["okta_inherited_privilege"] != "None" else "Direct Assignment"

    effective_rows = [
        html.Tr([
            html.Td("Active Directory"),
            html.Td(user_matrix["ad_effective_privilege"], style={"fontWeight": "bold"}),
            html.Td(ad_chain)
        ]),
        html.Tr([
            html.Td("AWS IAM"),
            html.Td(user_matrix["aws_effective_privilege"], style={"fontWeight": "bold"}),
            html.Td(aws_chain)
        ]),
        html.Tr([
            html.Td("Okta"),
            html.Td(user_matrix["okta_effective_privilege"], style={"fontWeight": "bold"}),
            html.Td(okta_chain)
        ])
    ]

    # Nested hierarchy Accordion items
    accordion_items = []
    
    inherited_via_val = user_info.get("inherited_via")
    if pd.notna(inherited_via_val) and str(inherited_via_val).strip() not in ["", "None", "nan"]:
        accordion_items.append(
            dbc.AccordionItem(
                html.Div([
                    html.I(className="fa-solid fa-triangle-exclamation text-danger me-2"),
                    html.Span("Critical Nested Admin Escalation Path Identified: ", className="text-danger fw-bold"),
                    html.Br(),
                    html.Span("Escalation Group (inherited_via): ", className="text-warning fw-bold"),
                    html.Span(str(inherited_via_val), className="text-info fw-bold"),
                    html.Br(),
                    html.Span("This group grants administrative rights transitively through nested directory group scopes.", className="text-muted")
                ], style={"fontFamily": "monospace", "fontSize": "13px"}),
                title="Transitive Admin Path (inherited_via)"
            )
        )
    if user_matrix["ad_inherited_privilege"] != "None":
        accordion_items.append(
            dbc.AccordionItem(
                html.Div([
                    html.I(className="fa-solid fa-network-wired text-info me-2"),
                    html.Span(f"{user_matrix['ad_direct_privilege']} → ", className="text-secondary"),
                    html.Span(f"{user_matrix['ad_inherited_privilege']} (Group) → ", className="text-warning"),
                    html.Span(f"{user_matrix['ad_effective_privilege']} (Effective Role)", className="text-success fw-bold")
                ], style={"fontFamily": "monospace", "fontSize": "13px"}),
                title="Active Directory Nested Group Path"
            )
        )
    if user_matrix["aws_inherited_privilege"] != "None":
        accordion_items.append(
            dbc.AccordionItem(
                html.Div([
                    html.I(className="fa-solid fa-cubes text-info me-2"),
                    html.Span(f"{user_matrix['aws_direct_privilege']} → ", className="text-secondary"),
                    html.Span(f"{user_matrix['aws_inherited_privilege']} (Policy) → ", className="text-warning"),
                    html.Span(f"{user_matrix['aws_effective_privilege']} (Effective Access)", className="text-success fw-bold")
                ], style={"fontFamily": "monospace", "fontSize": "13px"}),
                title="AWS IAM Inherited Policy Path"
            )
        )
    if user_matrix["okta_inherited_privilege"] != "None":
        accordion_items.append(
            dbc.AccordionItem(
                html.Div([
                    html.I(className="fa-solid fa-key text-info me-2"),
                    html.Span(f"{user_matrix['okta_direct_privilege']} → ", className="text-secondary"),
                    html.Span(f"{user_matrix['okta_inherited_privilege']} (Role) → ", className="text-warning"),
                    html.Span(f"{user_matrix['okta_effective_privilege']} (Effective Access)", className="text-success fw-bold")
                ], style={"fontFamily": "monospace", "fontSize": "13px"}),
                title="Okta Admin Role Assignment Path"
            )
        )

    if not accordion_items:
        accordion_items.append(
            dbc.AccordionItem(
                html.Div("All platforms are direct assignments. No nested groups or inherited role policies detected.", className="text-muted", style={"fontSize": "13px"}),
                title="Direct Assignments Mappings (No Inherited Groups)"
            )
        )

    # --- Load Analyst Context & FP Guidance (Enhancement 4) ---
    context_text = "No justifications found."
    confidence_val = "High"
    
    if not user_events.empty and "analyst_context" in user_events.columns:
        context_text = user_events.iloc[0]["analyst_context"]
        confidence_val = user_events.iloc[0]["confidence_level"]
    else:
        if "Offboarding Gap" in str(user_info["Detected Risks"]):
            context_text = "No justification found. Account is deactivated in HR registry (AD disabled) but remains active in cloud infrastructure."
            confidence_val = "High"
        elif "Token Abuse" in str(user_info["Detected Risks"]):
            context_text = "Session hijacking suspected. Stale API credentials used from unverified source IP."
            confidence_val = "High"
        else:
            context_text = "No anomalies detected. Access parameters match baseline profile."
            confidence_val = "Low"

    confidence_color = "danger" if confidence_val == "High" else ("warning" if confidence_val == "Medium" else "success")
    
    if confidence_val == "High":
        guidance = "Escalate immediately. Access violates active offboarding policies or suggests session abuse."
    elif confidence_val == "Medium":
        guidance = "Requires analyst validation. Cross-platform role transitions or approved emergency access exceptions may explain activity."
    else:
        guidance = "Monitor and review later. Permissions match standard baseline with minor warnings."

    # --- Timeline Plotly Scatter Chart ---
    if not user_events.empty:
        fig_events = px.scatter(
            user_events,
            x="event_timestamp",
            y="platform",
            color="status",
            hover_name="event_name",
            custom_data=["ip_address", "description"],
            color_discrete_map={"Success": "#2eb82e", "Warning": "#ff944d", "Alert": "#ff4d4d"},
            labels={"event_timestamp": "Timestamp", "platform": "Platform", "status": "Status"}
        )
        fig_events.update_traces(
            marker=dict(size=14, symbol="diamond", line=dict(width=1, color="white")),
            hovertemplate="""
            <b>Event:</b> %{hovertext}<br>
            <b>Time:</b> %{x}<br>
            <b>IP:</b> %{customdata[0]}<br>
            <b>Description:</b> %{customdata[1]}<extra></extra>
            """
        )
        fig_events.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f8fafc"),
            xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)", linecolor="rgba(255,255,255,0.1)"),
            yaxis=dict(showgrid=False, linecolor="rgba(255,255,255,0.1)"),
            margin=dict(t=20, b=20, l=10, r=10),
            height=200
        )
        timeline_graph = dcc.Graph(figure=fig_events, config={"displayModeBar": False})
    else:
        timeline_graph = html.Div("No security events recorded for this account.", className="text-secondary text-center py-4")

    # --- HTML Vertical Timeline ---
    timeline_items = []
    for _, ev in user_events.head(6).iterrows(): # Show top 6 events
        status_cls = ev["status"] # Success, Warning, Alert
        timeline_items.append(
            html.Div(
                [
                    html.Div(className="timeline-marker"),
                    html.Div(
                        [
                            html.Div(ev["event_timestamp"], className="timeline-time"),
                            html.Div(
                                [
                                    html.Span(ev["event_name"], className="timeline-title text-white fw-bold me-2"),
                                    html.Span(ev["platform"], style={"fontSize": "11px", "color": "#00f2fe", "backgroundColor": "rgba(0, 242, 254, 0.05)", "padding": "2px 6px", "borderRadius": "4px"})
                                ],
                                className="d-flex align-items-center mb-1"
                            ),
                            html.Div(ev["description"], style={"fontSize": "13px", "color": "#94a3b8"}),
                            html.Div(f"Origin IP: {ev['ip_address']}", style={"fontSize": "11px", "color": "#64748b", "fontFamily": "monospace", "marginTop": "4px"})
                        ],
                        className="timeline-content"
                    )
                ],
                className=f"timeline-item {status_cls}"
            )
        )
        
    html_timeline = html.Div(timeline_items, className="timeline-container")

    # --- Platform-specific Remediation ---
    remediation_cards = []
    
    # Active Directory Remediation
    if user_matrix["Active Directory"] in ["Admin", "Power User"]:
        remediation_cards.append(
            dbc.Col(
                html.Div(
                    [
                        html.H6(
                            [html.I(className="fa-brands fa-windows text-primary me-2"), "Active Directory Mitigation"], 
                            className="text-white border-bottom pb-2 border-secondary"
                        ),
                        html.P("Remove identity from high-privilege directory roles immediately.", style={"fontSize": "12px", "color": "#94a3b8"}),
                        html.Div(
                            [
                                html.Div("# PowerShell Core Cmdlet", style={"color": "#64748b", "fontSize": "11px"}),
                                html.Div(f"Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"{username}\" -Confirm:$false")
                            ],
                            className="remediation-command-box"
                        )
                    ],
                    className="remediation-panel mb-3"
                ),
                width=12, lg=4
            )
        )
        
    # AWS Remediation
    if user_matrix["AWS IAM"] in ["Admin", "Power User"] or "Token Abuse" in str(user_info["Detected Risks"]):
        aws_cmd = f"aws iam detach-user-policy --user-name {username} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        if "Token Abuse" in str(user_info["Detected Risks"]):
            aws_cmd += f"\naws iam deactivate-mfa-device --user-name {username}\naws iam delete-access-key --user-name {username} --access-key-id AKIA..."
            
        remediation_cards.append(
            dbc.Col(
                html.Div(
                    [
                        html.H6(
                            [html.I(className="fa-brands fa-aws text-warning me-2"), "AWS IAM Mitigation"], 
                            className="text-white border-bottom pb-2 border-secondary"
                        ),
                        html.P("Revoke administrator access policies and rotate/deactivate API access tokens.", style={"fontSize": "12px", "color": "#94a3b8"}),
                        html.Div(
                            [
                                html.Div("# AWS CLI v2", style={"color": "#64748b", "fontSize": "11px"}),
                                html.Pre(aws_cmd, style={"margin": "0", "color": "#00f2fe", "fontSize": "12px"})
                            ],
                            className="remediation-command-box"
                        )
                    ],
                    className="remediation-panel mb-3"
                ),
                width=12, lg=4
            )
        )

    # Okta Remediation
    if user_matrix["Okta"] in ["Admin", "Power User"] or "Offboarding Gap" in str(user_info["Detected Risks"]):
        remediation_cards.append(
            dbc.Col(
                html.Div(
                    [
                        html.H6(
                            [html.I(className="fa-solid fa-key text-info me-2"), "Okta IDP Mitigation"], 
                            className="text-white border-bottom pb-2 border-secondary"
                        ),
                        html.P("Deactivate user profile via lifecycle endpoint and clear current active sessions.", style={"fontSize": "12px", "color": "#94a3b8"}),
                        html.Div(
                            [
                                html.Div("# Okta API Session Revocation", style={"color": "#64748b", "fontSize": "11px"}),
                                html.Div(f"curl -X POST https://api.okta.com/v1/users/{username}/lifecycle/deactivate")
                            ],
                            className="remediation-command-box"
                        )
                    ],
                    className="remediation-panel mb-3"
                ),
                width=12, lg=4
            )
        )

    # Return completed page components
    return html.Div(
        [
            # Row 1: Profile, Evidence and Analyst Context
            dbc.Row(
                [
                    # Profile Card
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("IDENTITY PROFILE", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div("Display Name", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(user_info["Display Name"], className="text-white fw-bold fs-6 mb-3"),
                                    ], width=6),
                                    dbc.Col([
                                        html.Div("Risk Status", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(html.Span(sev, className=badge_class), className="mb-3"),
                                    ], width=6)
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div("Department", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(user_info["Department"], className="text-white mb-3", style={"fontSize": "13px"}),
                                    ], width=6),
                                    dbc.Col([
                                        html.Div("Risk Score", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(f"{user_info['Risk Score']} / 100", className="text-white fw-bold mb-3", style={"fontSize": "13px"}),
                                    ], width=6)
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div("Identity Type", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(user_info["Identity Type"], className="text-white mb-3", style={"fontSize": "13px"}),
                                    ], width=6),
                                    dbc.Col([
                                        html.Div("Active Platforms", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Div(user_info["Platforms"], className="text-info mb-3", style={"fontSize": "12px"}),
                                    ], width=6)
                                ]),
                                html.Div("Correlated Risk Vector", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Div(user_info["Detected Risks"], className="text-danger fw-bold", style={"fontSize": "13px"})
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=4, className="mb-3"
                    ),
                    
                    # Evidence Metrics Card
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("EVIDENCE CONSOLE", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div(
                                            [
                                                html.Div("Last Recorded Login", className="kpi-label"),
                                                html.Div(last_login, className="kpi-val", style={"fontSize": "13px", "marginTop": "2px", "color": "#00f2fe"})
                                            ],
                                            className="bg-dark p-2 rounded border border-secondary mb-3"
                                        )
                                    ], width=6),
                                    dbc.Col([
                                        html.Div(
                                            [
                                                html.Div("Access Token Age", className="kpi-label"),
                                                html.Div(token_age, className="kpi-val", style={"fontSize": "13px", "marginTop": "2px", "color": "#eab308"})
                                            ],
                                            className="bg-dark p-2 rounded border border-secondary mb-3"
                                        )
                                    ], width=6)
                                ]),
                                html.Div("Assigned Directory Memberships", className="text-secondary mb-1", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Div(group_membership, className="text-white mb-3", style={"fontSize": "12px", "fontFamily": "monospace"}),
                                
                                html.Div("Effective Platform Access levels", className="text-secondary mb-2", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.Span("AD: ", style={"color": "#64748b", "fontSize": "11px"}),
                                            html.Span(user_matrix["Active Directory"], className="fw-bold", style={"color": "#ff944d" if user_matrix["Active Directory"] == "Admin" else "#94a3b8", "fontSize": "11px"})
                                        ], className="bg-dark px-2 py-1 rounded text-center border border-secondary")
                                    ], width=4),
                                    dbc.Col([
                                        html.Div([
                                            html.Span("AWS: ", style={"color": "#64748b", "fontSize": "11px"}),
                                            html.Span(user_matrix["AWS IAM"], className="fw-bold", style={"color": "#ff4d4d" if user_matrix["AWS IAM"] == "Admin" else "#94a3b8", "fontSize": "11px"})
                                        ], className="bg-dark px-2 py-1 rounded text-center border border-secondary")
                                    ], width=4),
                                    dbc.Col([
                                        html.Div([
                                            html.Span("Okta: ", style={"color": "#64748b", "fontSize": "11px"}),
                                            html.Span(user_matrix["Okta"], className="fw-bold", style={"color": "#ffdb4d" if user_matrix["Okta"] == "Admin" else "#94a3b8", "fontSize": "11px"})
                                        ], className="bg-dark px-2 py-1 rounded text-center border border-secondary")
                                    ], width=4)
                                ])
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=4, className="mb-3"
                    ),

                    # Analyst Context & FP Guidance Card (Enhancement 4)
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("ANALYST CONTEXT & FP GUIDANCE", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div("Confidence Level", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Span(f"{confidence_val} Confidence", className=f"badge bg-{confidence_color} p-2 fw-bold text-uppercase", style={"fontSize": "11px"}),
                                    ], width=6),
                                    dbc.Col([
                                        html.Div("Assessment Flow", className="text-secondary", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                        html.Span(confidence_val if confidence_val == "High" else "Review", className="text-white fw-bold", style={"fontSize": "13px"})
                                    ], width=6)
                                ], className="mb-3"),
                                html.Div("Vulnerability Justification Context", className="text-secondary mb-1", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Div(context_text, className="text-white bg-dark p-2 rounded border border-secondary mb-3", style={"fontSize": "12px", "minHeight": "60px", "lineHeight": "1.4"}),
                                
                                html.Div("Recommended Guidance Action", className="text-secondary mb-1", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Div(guidance, className="text-info fw-bold mb-0", style={"fontSize": "12px"})
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=4, className="mb-3"
                    )
                ],
                className="mb-4"
            ),
            
            # Row 1b: Effective Privilege Analysis & Risk Breakdown (Enhancements 1 & 2)
            dbc.Row(
                [
                    # Effective Privilege analysis
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("EFFECTIVE PRIVILEGE ANALYSIS", className="mb-2 text-white border-bottom pb-2 border-secondary"),
                                html.P("Identifies direct group assignments compared with inherited effective directory access pathways.", className="text-secondary mb-3", style={"fontSize": "12px"}),
                                
                                # Direct table
                                html.Div("Direct Group Mappings", className="text-secondary mb-1", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Table(
                                    [
                                        html.Thead(
                                            html.Tr([
                                                html.Th("Platform", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"}),
                                                html.Th("Direct Assignment", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"}),
                                                html.Th("Direct Privilege Level", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"})
                                            ])
                                        ),
                                        html.Tbody(direct_rows)
                                    ],
                                    className="table report-table mb-3",
                                    style={"color": "#f8fafc"}
                                ),
                                
                                # Effective table
                                html.Div("Effective Privilege Mappings", className="text-secondary mb-1", style={"fontSize": "11px", "textTransform": "uppercase"}),
                                html.Table(
                                    [
                                        html.Thead(
                                            html.Tr([
                                                html.Th("Platform", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"}),
                                                html.Th("Effective Privilege", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"}),
                                                html.Th("Inheritance Source (Derived)", style={"fontSize": "11px", "padding": "5px 10px", "backgroundColor": "#1b2333"})
                                            ])
                                        ),
                                        html.Tbody(effective_rows)
                                    ],
                                    className="table report-table mb-3",
                                    style={"color": "#f8fafc"}
                                ),
                                
                                # Nested Inheritance expandable path
                                dbc.Accordion(accordion_items, start_collapsed=True, className="mt-3")
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=7, className="mb-4"
                    ),
                    
                    # Risk score breakdown bar chart
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("RISK SCORE BREAKDOWN", className="mb-2 text-white border-bottom pb-2 border-secondary"),
                                html.P("Mathematical vectors mapping to final calculated threat levels.", className="text-secondary mb-3", style={"fontSize": "12px"}),
                                dcc.Graph(figure=fig_breakdown, config={"displayModeBar": False}),
                                html.Div(
                                    f"Score Formula: Breadth ({breadth_score}) + Dormancy ({dormancy_score}) + Spread ({spread_score}) + Offboarding ({offboarding_score}) = Final Risk ({user_info['Risk Score']})",
                                    className="bg-dark p-2 border border-secondary text-center text-secondary rounded",
                                    style={"fontSize": "11px", "marginTop": "10px", "fontFamily": "monospace"}
                                )
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=5, className="mb-4"
                    )
                ],
                className="mb-4"
            ),

            # Row 2: Event Timeline Charts
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("FORENSIC EVENTS TIMELINE", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                timeline_graph,
                                html.Div(html_timeline, style={"maxHeight": "400px", "overflowY": "auto", "paddingRight": "10px"})
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ],
                className="mb-4"
            ),
            
            # Row 3: Remediation Playbooks
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("RECOMMENDED MITIGATION ACTIONS", className="mb-3 text-white"),
                                dbc.Row(remediation_cards)
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ],
                className="mb-4"
            ),
            
            # Row 4: AI Analyst Assistant Panel (Enhancement 6)
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.H5(
                                            [
                                                html.I(className="fa-solid fa-wand-magic-sparkles me-2 text-info"),
                                                html.Span("AI Analyst Assistant")
                                            ],
                                            className="mb-1 text-white"
                                        ),
                                        html.P(
                                            "On-demand AI reasoning to analyze findings, compliance posture, and draft audit documents.",
                                            className="text-secondary mb-3",
                                            style={"fontSize": "12px"}
                                        )
                                    ],
                                    className="border-bottom pb-2 border-secondary mb-3"
                                ),
                                
                                # Quick action buttons
                                html.Div(
                                    [
                                        html.Button(
                                            [html.I(className="fa-solid fa-file-invoice me-1"), "Generate Incident Summary"],
                                            id="drilldown-ai-btn-summary",
                                            className="btn-ai-action me-2 mb-2"
                                        ),
                                        html.Button(
                                            [html.I(className="fa-solid fa-wrench me-1"), "Recommend Remediation"],
                                            id="drilldown-ai-btn-remedy",
                                            className="btn-ai-action me-2 mb-2"
                                        ),
                                        html.Button(
                                            [html.I(className="fa-solid fa-calculator me-1"), "Explain Risk Score"],
                                            id="drilldown-ai-btn-score",
                                            className="btn-ai-action me-2 mb-2"
                                        ),
                                        html.Button(
                                            [html.I(className="fa-solid fa-shield-halved me-1"), "Show Compliance Mapping"],
                                            id="drilldown-ai-btn-compliance",
                                            className="btn-ai-action me-2 mb-2"
                                        ),
                                        html.Button(
                                            [html.I(className="fa-solid fa-pen-nib me-1"), "Draft Audit Note"],
                                            id="drilldown-ai-btn-audit",
                                            className="btn-ai-action me-2 mb-2"
                                        )
                                    ],
                                    className="d-flex flex-wrap mb-3"
                                ),
                                
                                # Loading indicator and AI Response container
                                dbc.Spinner(
                                    html.Div(
                                        id="drilldown-ai-response-container",
                                        className="bg-black bg-opacity-25 border border-secondary rounded p-3 text-secondary",
                                        style={"minHeight": "100px", "fontSize": "13px"},
                                        children=dcc.Markdown(
                                            "Select one of the quick actions above to prompt the Identity Security Copilot for this user context.",
                                            className="copilot-markdown"
                                        )
                                    ),
                                    color="info"
                                ),
                                
                                # Small governance note
                                html.Div(
                                    "Disclaimer: Identity Security Copilot augments analyst investigations using contextual explanations and recommendations. All risk findings originate from deterministic detection logic.",
                                    className="text-secondary mt-2",
                                    style={"fontSize": "10px", "fontStyle": "italic"}
                                )
                            ],
                            className="security-card"
                        ),
                        width=12
                    )
                ],
                className="mt-4"
            )
        ]
    )

# Callback to handle AI actions in the Incident Drilldown page
@callback(
    Output("drilldown-ai-response-container", "children"),
    [
        Input("drilldown-ai-btn-summary", "n_clicks"),
        Input("drilldown-ai-btn-remedy", "n_clicks"),
        Input("drilldown-ai-btn-score", "n_clicks"),
        Input("drilldown-ai-btn-compliance", "n_clicks"),
        Input("drilldown-ai-btn-audit", "n_clicks")
    ],
    State("drilldown-user-dropdown", "value")
)
def handle_drilldown_ai(*args):
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update
        
    trigger_id = ctx.triggered[0]["prop_id"].split(".")[0]
    trigger_value = ctx.triggered[0]["value"]
    
    if trigger_value is None or trigger_value == 0:
        return no_update
        
    username = args[5] # dropdown value is the last state argument
    
    # Map button ID to Copilot action
    action = "Explain Incident"
    if trigger_id == "drilldown-ai-btn-summary":
        action = "Explain Incident"
    elif trigger_id == "drilldown-ai-btn-remedy":
        action = "Recommend Remediation"
    elif trigger_id == "drilldown-ai-btn-score":
        action = "Explain Risk Score"
    elif trigger_id == "drilldown-ai-btn-compliance":
        action = "Compliance Mapping"
    elif trigger_id == "drilldown-ai-btn-audit":
        action = "Draft Audit Note"
        
    response = query_copilot(username, action)
    
    return dcc.Markdown(response, className="copilot-markdown")

# Callback to sync dropdown value back to session store (Enhancement: Context Sync)
@callback(
    Output("selected-user-store", "data", allow_duplicate=True),
    Input("drilldown-user-dropdown", "value"),
    prevent_initial_call=True
)
def sync_dropdown_to_store(username):
    if not username:
        return no_update
    return {"selected_user": username}
