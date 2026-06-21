import dash
from dash import html, dcc, Input, Output, State, callback
import dash_bootstrap_components as dbc
from utils.data_adapter import sync_data_to_disk

# Synchronize data from backend outputs on startup
sync_data_to_disk()

# Initialize the Dash app with Pages support and Dark Cyborg theme
app = dash.Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[
        dbc.themes.CYBORG,
        "https://use.fontawesome.com/releases/v6.4.2/css/all.css"
    ],
    suppress_callback_exceptions=True
)

app.title = "Guardrail IAM - Cybersecurity Governance"
server = app.server

# Sidebar Navigation Structure
sidebar_links = [
    {"name": "Executive Summary", "path": "/", "icon": "fa-solid fa-chart-pie"},
    {"name": "Identity Risk List", "path": "/risk-list", "icon": "fa-solid fa-shield-halved"},
    {"name": "Cross-Platform Privilege View", "path": "/privileges", "icon": "fa-solid fa-server"},
    {"name": "Offboarding Gap Detector", "path": "/offboarding", "icon": "fa-solid fa-user-xmark"},
    {"name": "Incident Drilldown", "path": "/drilldown", "icon": "fa-solid fa-magnifying-glass-chart"},
    {"name": "Dormancy Analysis", "path": "/dormancy", "icon": "fa-solid fa-hourglass-half"},
    {"name": "Risk Reports", "path": "/reports", "icon": "fa-solid fa-file-contract"}
]

# Layout for the sidebar
sidebar = html.Div(
    [
        # Brand Container
        html.Div(
            [
                html.I(className="fa-solid fa-user-shield brand-logo"),
                html.Div([
                    html.Div("GUARDRAIL", className="brand-name", style={"letterSpacing": "0.1em", "color": "#00f2fe"}),
                    html.Div("IAM CONSOLE", style={"fontSize": "10px", "color": "#94a3b8", "fontWeight": "bold"})
                ])
            ],
            className="brand-container"
        ),
        
        # Navigation Links
        html.Div(
            [
                dcc.Link(
                    [
                        html.I(className=f"{link['icon']} me-3"),
                        html.Span(link["name"])
                    ],
                    href=link["path"],
                    className="nav-link-custom",
                    id=f"sidebar-link-{link['path'].replace('/', '') or 'home'}"
                )
                for link in sidebar_links
            ],
            style={"flexGrow": "1"}
        ),
        
        # System Integrity / SOC status (Aesthetic element)
        html.Div(
            [
                html.Div(
                    [
                        html.Span(className="spinner-grow spinner-grow-sm text-success me-2", style={"width": "8px", "height": "8px"}),
                        html.Span("Console: ", style={"fontSize": "11px", "color": "#94a3b8"}),
                        html.Span("ONLINE", style={"fontSize": "11px", "color": "#2eb82e", "fontWeight": "bold"})
                    ],
                    className="d-flex align-items-center mb-1"
                ),
                html.Div(
                    [
                        html.Span(className="spinner-grow spinner-grow-sm text-info me-2", style={"width": "8px", "height": "8px"}),
                        html.Span("Threat Engine: ", style={"fontSize": "11px", "color": "#94a3b8"}),
                        html.Span("READY", style={"fontSize": "11px", "color": "#00f2fe", "fontWeight": "bold"})
                    ],
                    className="d-flex align-items-center mb-2"
                ),
                html.Div(
                    "v1.4.2-Hackathon", 
                    style={"fontSize": "10px", "color": "#475569", "textAlign": "center", "borderTop": "1px solid rgba(255,255,255,0.05)", "paddingTop": "10px"}
                )
            ],
            style={"marginTop": "auto", "padding": "15px 0 0 0", "borderTop": "1px solid rgba(255,255,255,0.05)"}
        )
    ],
    className="sidebar"
)

# Top Bar Header
top_header = html.Header(
    dbc.Row(
        [
            dbc.Col(
                html.Div(
                    [
                        html.H4("Identity Sprawl & Privileged Access Abuse Detection", className="mb-0 text-white"),
                        html.Span("Hybrid Enterprise Risk Governance & Threat Monitoring Console", style={"color": "#64748b", "fontSize": "12px", "fontWeight": "500"})
                    ]
                ),
                width=8
            ),
            dbc.Col(
                html.Div(
                    [
                        # Refresh indicator or sync indicator
                        html.Div(
                            [
                                html.I(className="fa-solid fa-rotate me-2", style={"color": "#a855f7"}),
                                html.Span("Data: Active (CSV Mode)", style={"fontSize": "12px", "color": "#ffffff", "fontWeight": "600"})
                            ],
                            className="d-flex align-items-center px-3 py-1 bg-dark rounded me-3",
                            style={"border": "1px solid #a855f7"}
                        ),
                        html.Div(
                            [
                                html.I(className="fa-solid fa-clock me-2", style={"color": "#f97316"}),
                                html.Span("Sync: Live", style={"fontSize": "12px", "color": "#ffffff", "fontWeight": "600"})
                            ],
                            className="d-flex align-items-center px-3 py-1 bg-dark rounded",
                            style={"border": "1px solid #f97316"}
                        )
                    ],
                    className="d-flex align-items-center justify-content-end"
                ),
                width=4
            )
        ],
        className="g-0 align-items-center mb-4 pb-3",
        style={"borderBottom": "1px solid rgba(255,255,255,0.05)"}
    )
)

# Global layout structure
# Floating Copilot UI
copilot_panel = html.Div(
    [
        # Header
        html.Div(
            [
                html.Div(
                    [
                        html.I(className="fa-solid fa-robot me-2 text-info"),
                        html.Span("Identity Security Copilot", style={"fontWeight": "bold", "color": "#00f2fe"})
                    ],
                    className="d-flex align-items-center"
                ),
                html.Button(
                    html.I(className="fa-solid fa-xmark"),
                    id="copilot-close-btn",
                    className="btn-copilot-close",
                    style={"background": "none", "border": "none", "color": "#64748b", "cursor": "pointer"}
                )
            ],
            className="copilot-header"
        ),
        
        # Suggested prompt buttons
        html.Div(
            [
                html.Button("Explain Incident", id="copilot-prompt-explain", n_clicks=0, className="copilot-chip"),
                html.Button("Recommend Remediation", id="copilot-prompt-remediate", n_clicks=0, className="copilot-chip"),
                html.Button("Explain Risk Score", id="copilot-prompt-risk", n_clicks=0, className="copilot-chip"),
                html.Button("Compliance Mapping", id="copilot-prompt-compliance", n_clicks=0, className="copilot-chip"),
                html.Button("Executive Summary", id="copilot-prompt-exec", n_clicks=0, className="copilot-chip"),
                html.Button("Draft Audit Note", id="copilot-prompt-audit", n_clicks=0, className="copilot-chip"),
                html.Button("Alert Consolidation", id="copilot-prompt-consolidate", n_clicks=0, className="copilot-chip"),
            ],
            className="copilot-chips-container"
        ),
        
        # Chat history with spinner
        html.Div(
            dbc.Spinner(
                html.Div(
                    id="copilot-chat-history-container",
                    className="copilot-history"
                ),
                color="info",
                spinner_style={"marginTop": "50px"}
            ),
            className="copilot-history-spinner-wrapper"
        ),
        
        # Footer input
        html.Div(
            [
                dcc.Input(
                    id="copilot-user-input",
                    type="text",
                    placeholder="Ask Copilot a question...",
                    className="copilot-input",
                    n_submit=0
                ),
                html.Button(
                    html.I(className="fa-solid fa-paper-plane"),
                    id="copilot-send-btn",
                    className="copilot-send-btn",
                    n_clicks=0
                )
            ],
            className="copilot-footer"
        ),
        
        # Governance Disclaimer
        html.Div(
            "Disclaimer: Identity Security Copilot augments analyst investigations using contextual explanations and recommendations. All risk findings originate from deterministic detection logic.",
            className="copilot-disclaimer"
        )
    ],
    id="copilot-window",
    className="copilot-window",
    style={"display": "none"}
)

copilot_toggle_btn = html.Button(
    [
        html.I(className="fa-solid fa-robot fs-4 me-2"),
        html.Span("Identity Security Copilot", style={"fontWeight": "600"})
    ],
    id="copilot-toggle-btn",
    className="copilot-toggle-btn",
    n_clicks=0
)

# Global layout structure
app.layout = html.Div(
    [
        # Global storage for interaction between pages
        dcc.Store(id="selected-user-store", storage_type="session"),
        dcc.Store(id="copilot-chat-history", storage_type="session", data=[
            {"role": "assistant", "content": "Hello! I am your Identity Security Copilot. Select a quick action below or type a query to analyze the currently selected user context."}
        ]),
        
        # URL Component to handle page redirection and query parameter reading
        dcc.Location(id="url", refresh=False),
        
        # Left Sidebar
        sidebar,
        
        # Main Dashboard Page Content
        html.Div(
            [
                top_header,
                dash.page_container
            ],
            className="main-content"
        ),
        
        # Copilot Components
        copilot_panel,
        copilot_toggle_btn
    ]
)

# Active link styling callback
@app.callback(
    [dash.Output(f"sidebar-link-{link['path'].replace('/', '') or 'home'}", "className") for link in sidebar_links],
    dash.Input("url", "pathname")
)
def update_active_links(pathname):
    outputs = []
    for link in sidebar_links:
        if pathname == link["path"]:
            outputs.append("nav-link-custom active")
        else:
            outputs.append("nav-link-custom")
    return outputs

# Toggle Copilot Window
@app.callback(
    Output("copilot-window", "style"),
    [
        Input("copilot-toggle-btn", "n_clicks"),
        Input("copilot-close-btn", "n_clicks")
    ],
    State("copilot-window", "style")
)
def toggle_copilot_window(toggle_clicks, close_clicks, current_style):
    ctx = dash.callback_context
    if not ctx.triggered:
        return current_style
        
    trigger_id = ctx.triggered[0]["prop_id"].split(".")[0]
    
    if trigger_id == "copilot-toggle-btn" and toggle_clicks:
        if current_style and current_style.get("display") == "flex":
            return {"display": "none"}
        else:
            return {"display": "flex"}
    elif trigger_id == "copilot-close-btn" and close_clicks:
        return {"display": "none"}
        
    return current_style

# Render Chat History
@app.callback(
    Output("copilot-chat-history-container", "children"),
    Input("copilot-chat-history", "data")
)
def render_chat_history(history):
    if not history:
        return []
    
    bubbles = []
    for msg in history:
        is_user = msg["role"] == "user"
        align_class = "d-flex justify-content-end mb-2" if is_user else "d-flex justify-content-start mb-2"
        bubble_class = "copilot-bubble-user" if is_user else "copilot-bubble-assistant"
        icon_class = "fa-solid fa-user ms-2 text-primary" if is_user else "fa-solid fa-robot me-2 text-info"
        
        content = [
            html.Div(
                [
                    html.Div(
                        [
                            html.I(className=icon_class),
                            html.Span("Analyst" if is_user else "Copilot", style={"fontWeight": "bold", "fontSize": "11px", "marginLeft": "4px", "marginRight": "4px", "color": "#94a3b8"})
                        ],
                        className="mb-1 d-flex align-items-center"
                    ),
                    dcc.Markdown(msg["content"], className="copilot-markdown")
                ],
                className=bubble_class
            )
        ]
        
        bubbles.append(html.Div(content, className=align_class))
            
    return bubbles

# Handle Chat Send and Prompts
@app.callback(
    [
        Output("copilot-chat-history", "data"),
        Output("copilot-user-input", "value")
    ],
    [
        Input("copilot-send-btn", "n_clicks"),
        Input("copilot-user-input", "n_submit"),
        Input("copilot-prompt-explain", "n_clicks"),
        Input("copilot-prompt-remediate", "n_clicks"),
        Input("copilot-prompt-risk", "n_clicks"),
        Input("copilot-prompt-compliance", "n_clicks"),
        Input("copilot-prompt-exec", "n_clicks"),
        Input("copilot-prompt-audit", "n_clicks"),
        Input("copilot-prompt-consolidate", "n_clicks")
    ],
    [
        State("copilot-user-input", "value"),
        State("copilot-chat-history", "data"),
        State("selected-user-store", "data")
    ]
)
def handle_copilot_chat(*args):
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update, dash.no_update
        
    trigger_id = ctx.triggered[0]["prop_id"].split(".")[0]
    trigger_value = ctx.triggered[0]["value"]
    
    # Filter out initial layout load calls (n_clicks = 0)
    if trigger_value is None or trigger_value == 0:
        return dash.no_update, dash.no_update
        
    user_input = args[9]
    history = args[10] or []
    store_data = args[11]
    
    username = store_data.get("selected_user") if store_data else None
    
    prompt_text = ""
    action = "General Query"
    
    if trigger_id == "copilot-send-btn" or trigger_id == "copilot-user-input":
        if not user_input or not user_input.strip():
            return dash.no_update, dash.no_update
        prompt_text = user_input.strip()
    elif trigger_id == "copilot-prompt-explain":
        prompt_text = "Explain Incident"
        action = "Explain Incident"
    elif trigger_id == "copilot-prompt-remediate":
        prompt_text = "Recommend Remediation"
        action = "Recommend Remediation"
    elif trigger_id == "copilot-prompt-risk":
        prompt_text = "Explain Risk Score"
        action = "Explain Risk Score"
    elif trigger_id == "copilot-prompt-compliance":
        prompt_text = "Compliance Mapping"
        action = "Compliance Mapping"
    elif trigger_id == "copilot-prompt-exec":
        prompt_text = "Executive Summary"
        action = "Executive Summary"
    elif trigger_id == "copilot-prompt-audit":
        prompt_text = "Draft Audit Note"
        action = "Draft Audit Note"
    elif trigger_id == "copilot-prompt-consolidate":
        prompt_text = "Alert Consolidation"
        action = "Alert Consolidation"
    else:
        return dash.no_update, dash.no_update

    new_history = list(history)
    new_history.append({"role": "user", "content": prompt_text})
    
    # Dynamic import to avoid circular dependency
    from utils.copilot import query_copilot
    
    response = query_copilot(username, action, user_query=prompt_text)
    new_history.append({"role": "assistant", "content": response})
    
    return new_history, ""

if __name__ == "__main__":
    app.run(debug=True, port=8050)
