import dash
from dash import html, dcc, Input, Output, State, callback, clientside_callback, no_update
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import os
from datetime import datetime

# Register page
dash.register_page(__name__, path="/reports")

def get_remediation_action(risks):
    risk_list = str(risks).split(", ")
    actions = []
    for r in risk_list:
        if r == "Offboarding Gap":
            actions.append("Deactivate downstream accounts on AWS/Okta.")
        elif r == "Token Abuse":
            actions.append("Rotate static API access credentials.")
        elif r == "Privilege Spike":
            actions.append("Conduct access review & revoke unapproved roles.")
        elif r == "Dormant Admin":
            actions.append("Deprovision admin credentials or disable account.")
        elif r == "Hidden Admin":
            actions.append("Audit direct group mappings in Active Directory.")
        elif r == "Cross-Platform Admin":
            actions.append("Enforce Least Privilege policy.")
    return " | ".join(actions) if actions else "No immediate action required."

def layout():
    identities_path = "data/unified_identities.csv"
    results_path = "data/risk_results.csv"
    
    if not os.path.exists(identities_path) or not os.path.exists(results_path):
        return html.Div("Data files not found. Please run data_generator.py first.", className="text-danger p-4")
        
    df_id = pd.read_csv(identities_path)
    df_res = pd.read_csv(results_path)

    # 1. Pie Chart of Risk Types
    fig_pie = px.pie(
        df_res,
        values="count",
        names="risk_type",
        color="severity",
        color_discrete_map={"Critical": "#ff4d4d", "High": "#ff944d", "Medium": "#ffdb4d", "Low": "#2eb82e"}
    )
    fig_pie.update_traces(
        textinfo="percent", 
        hoverinfo="label+value",
        marker=dict(line=dict(color="#131924", width=2))
    )
    fig_pie.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5),
        margin=dict(t=10, b=100, l=10, r=10),
        height=320
    )

    # 2. Fetch Top 10 Critical Identities
    df_critical = df_id[df_id["Severity"].isin(["Critical", "High"])].sort_values(by="Risk Score", ascending=False).head(10)
    
    report_rows = []
    for idx, row in df_critical.iterrows():
        uname = row["User Name"]
        score = row["Risk Score"]
        reasons = row["Detected Risks"]
        action = get_remediation_action(reasons)
        
        report_rows.append(
            html.Tr([
                html.Td(uname, style={"fontWeight": "600"}),
                html.Td(f"{score} / 100", style={"color": "#b91c1c" if score > 85 else "#c2410c", "fontWeight": "bold"}),
                html.Td(reasons),
                html.Td(action)
            ])
        )

    # 3. Aggregated report metrics for Auditor Preview
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_gaps = len(df_id[df_id["Detected Risks"].str.contains("Offboarding Gap", na=False)])
    total_token_abuse = len(df_id[df_id["Detected Risks"].str.contains("Token Abuse", na=False)])
    total_dormant = len(df_id[df_id["Detected Risks"].str.contains("Dormant Admin", na=False)])

    return html.Div(
        [
            # Download components
            dcc.Download(id="download-csv-report"),
            dcc.Download(id="download-text-report"),
            html.Div(id="print-dummy", style={"display": "none"}),
            
            # Title
            html.Div(
                [
                    html.H2("EXECUTIVE COMPLIANCE REPORTS", className="text-white mb-1"),
                    html.P("Generates standardized audit logs and executive summaries aligned with SOC 2, ISO 27001, and SOX identity controls.", className="text-secondary mb-4", style={"fontSize": "14px"})
                ]
            ),
            
            # Row 1: Chart and Options
            dbc.Row(
                [
                    # Risk Breakdown Pie
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("RISK VECTOR DISTRIBUTION", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                dcc.Graph(figure=fig_pie, config={"displayModeBar": False})
                            ],
                            className="security-card"
                        ),
                        width=12, lg=6
                    ),
                    # Action buttons
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("REPORT UTILITIES", className="mb-3 text-white border-bottom pb-2 border-secondary"),
                                html.P("Export the aggregated identity risk dataset or audit findings into standard documentation formats.", style={"fontSize": "13px", "color": "#94a3b8"}),
                                
                                html.Div(
                                    [
                                        dbc.Button(
                                            [html.I(className="fa-solid fa-file-csv me-2"), "Export CSV Dataset"],
                                            id="btn-export-csv",
                                            className="w-100 mb-3 fw-bold",
                                            style={"backgroundColor": "#1e293b", "borderColor": "#3b82f6", "color": "#f8fafc"}
                                        ),
                                        dbc.Button(
                                            [html.I(className="fa-solid fa-file-lines me-2"), "Download Audit Summary"],
                                            id="btn-export-text",
                                            className="w-100 mb-3 fw-bold",
                                            style={"backgroundColor": "#334155", "borderColor": "#475569", "color": "#f8fafc"}
                                        ),
                                        dbc.Button(
                                            [html.I(className="fa-solid fa-print me-2"), "Print Auditor Copy (PDF)"],
                                            id="btn-print-report",
                                            className="w-100 fw-bold",
                                            style={"backgroundColor": "#475569", "borderColor": "#64748b", "color": "#f8fafc"}
                                        )
                                    ],
                                    style={"padding": "10px 0"}
                                )
                            ],
                            className="security-card h-100"
                        ),
                        width=12, lg=6
                    )
                ],
                className="mb-4"
            ),
            
            # Row 2: Auditor Report Preview Container
            dbc.Row(
                [
                    dbc.Col(
                        html.Div(
                            [
                                html.H5("AUDITOR REPORT PREVIEW", className="mb-1 text-white"),
                                html.P("Below is an interactive live-preview of the formal compliance report that is printable to PDF.", className="text-secondary mb-3", style={"fontSize": "12px"}),
                                
                                # Simulated White-Paper Report
                                html.Div(
                                    [
                                        # Header
                                        html.Div(
                                            [
                                                html.Div("GUARDRAIL IDENTITY GOVERNANCE platform", style={"fontSize": "11px", "color": "#475569", "fontWeight": "800", "textTransform": "uppercase"}),
                                                html.H3("IDENTITY COMPLIANCE & RISK AUDIT REPORT", className="report-preview-title mb-1"),
                                                html.Div(f"Generated on: {current_time_str} | Mode: Automated Risk Verification Engine", style={"fontSize": "12px", "color": "#64748b"})
                                            ],
                                            className="report-preview-header"
                                        ),
                                        
                                        # Scope of Audit
                                        html.Div(
                                            [
                                                html.H4("1. Scope of Audit & Standards"),
                                                html.P("This document reviews identity access vulnerabilities across enterprise hybrid platforms including Active Directory, AWS IAM cloud instances, and Okta IDP services. Evaluation standards are mapped against SOC 2 CC6.3 (Access Modification) and ISO 27001 A.9.2 (User Access Management).", style={"fontSize": "13px", "lineHeight": "1.6", "color": "#334155"}),
                                            ],
                                            className="report-preview-section"
                                        ),
                                        
                                        # Aggregate Metrics
                                        html.Div(
                                            [
                                                html.H4("2. Executive Compliance Scorecard"),
                                                dbc.Row([
                                                    dbc.Col([
                                                        html.Div("Offboarding Gaps", style={"fontSize": "12px", "color": "#475569"}),
                                                        html.Div(f"{total_gaps} Violations", style={"fontSize": "18px", "fontWeight": "700", "color": "#b91c1c"})
                                                    ], width=4),
                                                    dbc.Col([
                                                        html.Div("Token Session Abuse", style={"fontSize": "12px", "color": "#475569"}),
                                                        html.Div(f"{total_token_abuse} Cases", style={"fontSize": "18px", "fontWeight": "700", "color": "#b91c1c"})
                                                    ], width=4),
                                                    dbc.Col([
                                                        html.Div("Dormant Admins", style={"fontSize": "12px", "color": "#475569"}),
                                                        html.Div(f"{total_dormant} Stale Profiles", style={"fontSize": "18px", "fontWeight": "700", "color": "#c2410c"})
                                                    ], width=4)
                                                ], className="my-2")
                                            ],
                                            className="report-preview-section"
                                        ),
                                        
                                        # Top Critical Accounts Table
                                        html.Div(
                                            [
                                                html.H4("3. Critical Identity Violations & Remediations"),
                                                html.Table([
                                                    html.Thead([
                                                        html.Tr([
                                                            html.Th("User"),
                                                            html.Th("Risk Score"),
                                                            html.Th("Violations"),
                                                            html.Th("Remediation Playbook")
                                                        ])
                                                    ]),
                                                    html.Tbody(report_rows)
                                                ], className="report-table")
                                            ],
                                            className="report-preview-section"
                                        ),
                                        
                                        # Footer
                                        html.Div(
                                            [
                                                html.P("CONFIDENTIAL - FOR SECURITY AUDIT AND INTERNAL COMPLIANCE USE ONLY", style={"fontSize": "11px", "color": "#94a3b8", "textAlign": "center", "marginTop": "40px", "borderTop": "1px solid #e2e8f0", "paddingTop": "15px"})
                                            ]
                                        )
                                    ],
                                    className="report-preview-container"
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

# Clientside Callback to print the document natively (triggers Save to PDF)
clientside_callback(
    """
    function(n_clicks) {
        if (n_clicks) {
            window.print();
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output("print-dummy", "children"),
    Input("btn-print-report", "n_clicks"),
    prevent_initial_call=True
)

# Callback to download CSV Dataset
@callback(
    Output("download-csv-report", "data"),
    Input("btn-export-csv", "n_clicks"),
    prevent_initial_call=True
)
def download_csv(n_clicks):
    if not n_clicks:
        return no_update
        
    df = pd.read_csv("data/unified_identities.csv")
    csv_string = df.to_csv(index=False)
    return dcc.send_string(csv_string, "identity_risk_dataset.csv", type="text/csv")

# Callback to download Text Audit Summary
@callback(
    Output("download-text-report", "data"),
    Input("btn-export-text", "n_clicks"),
    prevent_initial_call=True
)
def download_text_report(n_clicks):
    if not n_clicks:
        return no_update
        
    df_id = pd.read_csv("data/unified_identities.csv")
    df_res = pd.read_csv("data/risk_results.csv")
    
    total_users = len(df_id)
    critical_risks = len(df_id[df_id["Severity"] == "Critical"])
    high_risks = len(df_id[df_id["Severity"] == "High"])
    
    report_text = f"""==================================================
GUARDRAIL IAM CONSOLE - COMPLIANCE AUDIT LOG
Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
==================================================

1. OVERALL STATUS
Total Identities Evaluated: {total_users}
Critical Severity Risks: {critical_risks}
High Severity Risks: {high_risks}

2. DETECTED RISK VECTORS SUMMARY
"""
    for idx, row in df_res.iterrows():
        report_text += f"- {row['risk_type']}: {row['count']} active cases (Severity: {row['severity']})\n"
        
    report_text += "\n3. TOP 5 CRITICAL ACCOUNTS PLAYBOOK\n"
    df_top5 = df_id.sort_values(by="Risk Score", ascending=False).head(5)
    for idx, row in df_top5.iterrows():
        report_text += f"\nAccount: {row['User Name']}\n- Risk Score: {row['Risk Score']}/100\n- Violations: {row['Detected Risks']}\n- Action: {get_remediation_action(row['Detected Risks'])}\n"
        
    report_text += "\n==================================================\nEND OF AUDIT SUMMARY\n=================================================="
    
    # Replace single LFs with CRLFs for Windows Notepad compatibility
    windows_report_text = report_text.replace("\n", "\r\n")
    return dcc.send_string(windows_report_text, "identity_compliance_summary.txt", type="text/plain")
