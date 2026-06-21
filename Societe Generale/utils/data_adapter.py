import os
import pandas as pd
import numpy as np
from datetime import datetime

# Backend Directory Config
BACKEND_DIR = r"c:\Users\mhari\Downloads\Identity_sprawl_project\Identity_sprawl_project\identity_sprawl"
DASHBOARD_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

# Baseline Date (from backend config)
TODAY = datetime(2026, 6, 21)

# Group privilege hierarchy (from backend engine)
GROUP_HIERARCHY = {
    # AD Groups
    "GG-Domain-Admins"      : {"parent": None,               "platform": "AD",  "privilege_level": "admin"},
    "GG-Enterprise-Admins"  : {"parent": None,               "platform": "AD",  "privilege_level": "admin"},
    "GG-Infra-Ops"          : {"parent": "GG-Domain-Admins", "platform": "AD",  "privilege_level": "elevated"},
    "GG-IT-Staff"           : {"parent": "GG-Infra-Ops",     "platform": "AD",  "privilege_level": "standard"},
    "GG-ServiceDesk"        : {"parent": "GG-Infra-Ops",     "platform": "AD",  "privilege_level": "standard"},
    "GG-Dev-Staff"          : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-Git-Users"          : {"parent": "GG-Dev-Staff",     "platform": "AD",  "privilege_level": "standard"},
    "GG-Finance-Staff"      : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-SAP-Users"          : {"parent": "GG-Finance-Staff", "platform": "AD",  "privilege_level": "standard"},
    "GG-HR-Staff"           : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-HRIS-Access"        : {"parent": "GG-HR-Staff",      "platform": "AD",  "privilege_level": "standard"},
    "GG-Sales-Staff"        : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-CRM-Access"         : {"parent": "GG-Sales-Staff",   "platform": "AD",  "privilege_level": "standard"},
    "GG-Legal-Staff"        : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-DLP-Policy"         : {"parent": "GG-Legal-Staff",   "platform": "AD",  "privilege_level": "standard"},
    "GG-Contractors"        : {"parent": None,               "platform": "AD",  "privilege_level": "limited"},
    "GG-Guest-Access"       : {"parent": None,               "platform": "AD",  "privilege_level": "limited"},
    "GG-VPN-Access"         : {"parent": None,               "platform": "AD",  "privilege_level": "standard"},
    "GG-ReadOnly-FS"        : {"parent": None,               "platform": "AD",  "privilege_level": "limited"},

    # AWS Policies
    "arn:aws:iam::aws:policy/AdministratorAccess"          : {"parent": None,                                          "platform": "AWS", "privilege_level": "admin"},
    "arn:aws:iam::aws:policy/IAMFullAccess"                : {"parent": "arn:aws:iam::aws:policy/AdministratorAccess", "platform": "AWS", "privilege_level": "admin"},
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"      : {"parent": None,                                          "platform": "AWS", "privilege_level": "standard"},
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"       : {"parent": None,                                          "platform": "AWS", "privilege_level": "standard"},
    "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess" : {"parent": None,                                          "platform": "AWS", "privilege_level": "standard"},
    "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"     : {"parent": None,                                          "platform": "AWS", "privilege_level": "standard"},

    # Okta Apps
    "Okta Admin Console"    : {"parent": None, "platform": "Okta", "privilege_level": "admin"},
    "AWS SSO"               : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "GitHub Enterprise"     : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "Salesforce"            : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "Workday"               : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "ServiceNow"            : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "Jira"                  : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "Slack"                 : {"parent": None, "platform": "Okta", "privilege_level": "standard"},
    "CyberArk"              : {"parent": None, "platform": "Okta", "privilege_level": "elevated"},
}

PRIV_LEVEL_MAP = {
    "admin": "Admin",
    "elevated": "Power User",
    "standard": "User",
    "limited": "Read Only",
    "None": "None",
    None: "None"
}

def map_privilege(p):
    return PRIV_LEVEL_MAP.get(p, "None")

def get_username(row):
    """Derives a consistent User Name for each identity_id."""
    if pd.notna(row.get("AD_username")) and str(row["AD_username"]).strip() not in ["", "None", "nan"]:
        return str(row["AD_username"]).strip()
    if pd.notna(row.get("Okta_username")) and str(row["Okta_username"]).strip() not in ["", "None", "nan"]:
        val = str(row["Okta_username"]).strip()
        if "@" in val:
            return val.split("@")[0]
        return val
    if pd.notna(row.get("AWS_username")) and str(row["AWS_username"]).strip() not in ["", "None", "nan"]:
        val = str(row["AWS_username"]).strip()
        if val.startswith("svc-"):
            return val
        return val.replace("-", ".")
    
    name = row.get("name")
    if pd.notna(name) and str(name).strip() != "":
        return str(name).strip().lower().replace(" ", ".")
    return str(row["identity_id"])

def load_backend_data():
    """Loads and returns raw backend datasets."""
    master = pd.read_csv(os.path.join(BACKEND_DIR, "data", "master_identities.csv"))
    snapshots = pd.read_csv(os.path.join(BACKEND_DIR, "data", "platform_snapshots.csv"))
    group_mappings = pd.read_csv(os.path.join(BACKEND_DIR, "data", "group_mappings.csv"))
    audit_events = pd.read_csv(os.path.join(BACKEND_DIR, "data", "audit_events.csv"))
    offboarding_records = pd.read_csv(os.path.join(BACKEND_DIR, "data", "offboarding_records.csv"))
    
    unified_identities = pd.read_csv(os.path.join(BACKEND_DIR, "outputs", "unified_identities.csv"))
    risk_scores = pd.read_csv(os.path.join(BACKEND_DIR, "outputs", "risk_scores.csv"))
    anomalies = pd.read_csv(os.path.join(BACKEND_DIR, "outputs", "anomalies.csv"))
    
    return master, snapshots, group_mappings, audit_events, offboarding_records, unified_identities, risk_scores, anomalies

def build_normalized_data():
    """Builds and normalizes the 5 dashboard-ready datasets."""
    (master, snapshots, group_mappings, audit_events, offboarding_records, 
     unified_backend, risk_scores_backend, anomalies_backend) = load_backend_data()

    # 1. Identity Username Mapping
    id_to_username = {}
    seen_usernames = {}
    for _, row in unified_backend.iterrows():
        base_uname = get_username(row)
        uname = base_uname
        if uname in seen_usernames:
            seen_usernames[uname] += 1
            uname = f"{base_uname}{seen_usernames[uname]}"
        else:
            seen_usernames[uname] = 1
        id_to_username[row["identity_id"]] = uname

    # Map name/email to username in the snapshots and audit logs
    snapshots["username"] = snapshots["identity_id"].map(id_to_username)
    audit_events["username"] = audit_events["identity_id"].map(id_to_username)
    group_mappings["username"] = group_mappings["identity_id"].map(id_to_username)
    offboarding_records["username"] = offboarding_records["identity_id"].map(id_to_username)
    unified_backend["User Name"] = unified_backend["identity_id"].map(id_to_username)
    risk_scores_backend["User Name"] = risk_scores_backend["identity_id"].map(id_to_username)

    # 2. Construct unified_identities.csv
    unified_rows = []
    for _, row in unified_backend.iterrows():
        iid = row["identity_id"]
        uname = id_to_username[iid]
        score_row = risk_scores_backend[risk_scores_backend["identity_id"] == iid].iloc[0]
        
        # Mapped platform list
        plats = []
        if row.get("AD_status") == "active": plats.append("Active Directory")
        if row.get("AWS_status") == "active": plats.append("AWS IAM")
        if row.get("Okta_status") == "active": plats.append("Okta")
        
        # Fallback to present accounts
        if not plats:
            if row.get("AD_status") not in ["not_found", "not_applicable", None, "None"]: plats.append("Active Directory")
            if row.get("AWS_status") not in ["not_found", "not_applicable", None, "None"]: plats.append("AWS IAM")
            if row.get("Okta_status") not in ["not_found", "not_applicable", None, "None"]: plats.append("Okta")
        
        # Risk Tag Scans
        reasons = str(score_row["reasons"])
        risk_tags = []
        if "OFFBOARDING_GAP" in reasons: risk_tags.append("Offboarding Gap")
        if "STALE_TOKEN" in reasons: risk_tags.append("Token Abuse")
        if "PRIVILEGE_ESCALATION" in reasons: risk_tags.append("Privilege Spike")
        if "DORMANT_ADMIN" in reasons or "DORMANT_ADMIN_ROLE_CHANGE" in reasons: risk_tags.append("Dormant Admin")
        if "INHERITED_ADMIN" in reasons: risk_tags.append("Hidden Admin")
        if "CROSS_PLATFORM_ADMIN" in reasons: risk_tags.append("Cross-Platform Admin")
        
        detected_risks = ", ".join(risk_tags) if risk_tags else "None"
        
        unified_rows.append({
            "User Name": uname,
            "Display Name": row["name"],
            "Department": row["department"],
            "Identity Type": str(row["type"]).replace("_", " ").title(),
            "Platforms": ", ".join(plats),
            "Risk Score": round(float(score_row["risk_score"]), 1),
            "Severity": str(score_row["risk_band"]).title(),
            "Detected Risks": detected_risks,
            "days_since_last_login": int(row.get("days_since_last_login", 999)),
            "direct_groups": row.get("direct_groups", "None"),
            "all_effective_groups": row.get("all_effective_groups", "None"),
            "inherited_via": row.get("inherited_via", "None"),
            "AWS_api_key_age": row.get("AWS_api_key_age", "None")
        })
        
    df_unified = pd.DataFrame(unified_rows)
    df_unified = df_unified.sort_values(by="Risk Score", ascending=False).reset_index(drop=True)
    df_unified["Rank"] = df_unified.index + 1

    # Reorder columns to match original
    cols = ["Rank", "User Name", "Display Name", "Department", "Identity Type", "Platforms", "Risk Score", "Severity", "Detected Risks", "days_since_last_login", "direct_groups", "all_effective_groups", "inherited_via", "AWS_api_key_age"]
    df_unified = df_unified[cols]

    # 3. Construct privilege_matrix.csv
    priv_matrix_rows = []
    priv_order = {"admin": 4, "elevated": 3, "standard": 2, "limited": 1, "None": 0}
    
    for _, row in unified_backend.iterrows():
        iid = row["identity_id"]
        uname = id_to_username[iid]
        
        # Mapped platform effective values
        platform_privs = {}
        for plat_code, plat_name in [("AD", "Active Directory"), ("AWS", "AWS IAM"), ("Okta", "Okta")]:
            status = row.get(f"{plat_code}_status")
            if status in ["not_found", "not_applicable", None, "None"]:
                platform_privs[plat_name] = "None"
            else:
                platform_privs[plat_name] = map_privilege(row.get(f"{plat_code}_privilege"))
                
        # Resolve Group path hierarchies per platform
        matrix_details = {}
        for plat_code, prefix in [("AD", "ad"), ("AWS", "aws"), ("Okta", "okta")]:
            status = row.get(f"{plat_code}_status")
            if status in ["not_found", "not_applicable", None, "None"]:
                matrix_details[f"{prefix}_direct_privilege"] = "None"
                matrix_details[f"{prefix}_inherited_privilege"] = "None"
                matrix_details[f"{prefix}_effective_privilege"] = "None"
            else:
                user_plat_groups = group_mappings[(group_mappings["identity_id"] == iid) & (group_mappings["platform"] == plat_code)]
                direct_grp_list = snapshots[(snapshots["identity_id"] == iid) & (snapshots["platform"] == plat_code)]
                
                # Direct Groups
                direct_grps = []
                if len(direct_grp_list) > 0 and pd.notna(direct_grp_list.iloc[0]["role_or_group"]):
                    direct_grps = [g.strip() for g in str(direct_grp_list.iloc[0]["role_or_group"]).split("|")]
                
                matrix_details[f"{prefix}_direct_privilege"] = ", ".join(direct_grps) if direct_grps else "None"
                
                # Inherited Groups
                inh_grps = []
                if len(user_plat_groups) > 0:
                    inh_grps = user_plat_groups["parent_group"].dropna().unique()
                    inh_grps = [g for g in inh_grps if str(g).strip() not in ["", "nan", "None"]]
                matrix_details[f"{prefix}_inherited_privilege"] = ", ".join(inh_grps) if inh_grps else "None"
                
                # Effective Privilege Detail
                if len(user_plat_groups) > 0:
                    user_plat_groups_sorted = user_plat_groups.copy()
                    user_plat_groups_sorted["priv_val"] = user_plat_groups_sorted["effective_privilege"].map(lambda x: priv_order.get(x, 0))
                    best_row = user_plat_groups_sorted.sort_values(by="priv_val", ascending=False).iloc[0]
                    
                    highest_group = best_row["parent_group"] if pd.notna(best_row["parent_group"]) and str(best_row["parent_group"]).strip() != "" else best_row["direct_group"]
                    is_inh = pd.notna(best_row["parent_group"]) and str(best_row["parent_group"]).strip() != ""
                    
                    matrix_details[f"{prefix}_effective_privilege"] = f"{highest_group} (Inherited)" if is_inh else f"{highest_group}"
                else:
                    matrix_details[f"{prefix}_effective_privilege"] = direct_grps[0] if direct_grps else "None"
                    
        priv_matrix_rows.append({
            "username": uname,
            "Active Directory": platform_privs["Active Directory"],
            "AWS IAM": platform_privs["AWS IAM"],
            "Okta": platform_privs["Okta"],
            "ad_effective_privilege": matrix_details["ad_effective_privilege"],
            "ad_direct_privilege": matrix_details["ad_direct_privilege"],
            "ad_inherited_privilege": matrix_details["ad_inherited_privilege"],
            "aws_effective_privilege": matrix_details["aws_effective_privilege"],
            "aws_direct_privilege": matrix_details["aws_direct_privilege"],
            "aws_inherited_privilege": matrix_details["aws_inherited_privilege"],
            "okta_effective_privilege": matrix_details["okta_effective_privilege"],
            "okta_direct_privilege": matrix_details["okta_direct_privilege"],
            "okta_inherited_privilege": matrix_details["okta_inherited_privilege"],
        })
        
    df_privilege = pd.DataFrame(priv_matrix_rows)

    # 4. Construct offboarding_findings.csv
    offboarding_findings_rows = []
    gaps = unified_backend[unified_backend["has_offboarding_gap"] == True]
    for _, row in gaps.iterrows():
        iid = row["identity_id"]
        uname = id_to_username[iid]
        
        term_date = str(row["termination_date"])
        exposure_days = 0
        if pd.notna(row["termination_date"]):
            try:
                term_dt = datetime.strptime(term_date, "%Y-%m-%d")
                exposure_days = max(0, (TODAY - term_dt).days)
            except:
                pass
                
        sev = "Critical" if exposure_days > 30 else ("High" if exposure_days > 15 else "Medium")
        
        offboarding_findings_rows.append({
            "User": uname,
            "Termination Date": term_date,
            "AD Status": str(row.get("AD_status")).title(),
            "AWS Status": str(row.get("AWS_status")).title(),
            "Okta Status": str(row.get("Okta_status")).title(),
            "Exposure Days": exposure_days,
            "Severity": sev
        })
    df_offboarding = pd.DataFrame(offboarding_findings_rows)

    # 5. Construct incidents.csv (Audit logs + Anomalies timeline)
    incidents_rows = []
    
    # Track details for context
    user_to_details = {r["User Name"]: r for r in unified_rows}
    user_to_matrix = {r["username"]: r for r in priv_matrix_rows}

    # Add standard audit events
    for _, row in audit_events.iterrows():
        iid = row["identity_id"]
        if iid not in id_to_username:
            continue
        uname = id_to_username[iid]
        
        platform = row["platform"]
        plat_mapped = "Active Directory" if platform == "AD" else ("AWS IAM" if platform == "AWS" else "Okta")
        
        act = str(row["action"])
        ev_name = "Console Login"
        if act == "group_membership_added":
            ev_name = "Privilege Escalation"
        elif act == "login_success":
            ev_name = "Console Login"
        elif "api" in str(row["event_type"]):
            ev_name = "API Access Event"
            
        sev = row["severity"]
        status = "Alert" if sev == "CRITICAL" else ("Warning" if sev in ["HIGH", "MEDIUM"] else "Success")
        
        # Mapped descriptions
        desc = "Standard authentication flow verified."
        if pd.notna(row["resource"]):
            desc = f"Access to resource: {row['resource']}."
        if act == "group_membership_added":
            desc = f"Added to group or role: {row['resource']}."
        if row["anomaly_type"] == "offboarding_gap":
            desc = "Lingering session activity detected in cloud platform after HR termination date."
        elif row["anomaly_type"] == "token_abuse":
            desc = f"Static API credentials used from source IP: {row['source_ip']} without standard MFA check."

        # Fetch matrix values
        matrix = user_to_matrix.get(uname, {})
        prefix = "ad" if platform == "AD" else ("aws" if platform == "AWS" else "okta")
        
        direct = matrix.get(f"{prefix}_direct_privilege", "None")
        effective = matrix.get(f"{prefix}_effective_privilege", "None")
        inherited = matrix.get(f"{prefix}_inherited_privilege", "None")
        
        chain = "Direct Assignment"
        if inherited != "None":
            chain = f"{direct} -> {inherited} -> {effective}"

        # Context details
        anom_type = str(row["anomaly_type"])
        context = "No anomalies detected. Access parameters match baseline profile."
        confidence = "Low"
        
        if pd.notna(row["anomaly_type"]):
            confidence = "High" if sev == "CRITICAL" else "Medium"
            if anom_type == "offboarding_gap":
                context = "Account is deactivated in HR registry (AD disabled) but remains active in cloud infrastructure."
            elif anom_type == "token_abuse":
                context = "API credentials used from unverified source IP."
            elif anom_type == "privilege_escalation":
                context = "Unapproved privilege elevation in directory logs."
                
        incidents_rows.append({
            "username": uname,
            "event_timestamp": str(row["timestamp"]),
            "event_name": ev_name,
            "platform": plat_mapped,
            "status": status,
            "ip_address": row["source_ip"],
            "description": desc,
            "direct_privileges": direct,
            "effective_privileges": effective,
            "inheritance_chain": chain,
            "analyst_context": context,
            "confidence_level": confidence
        })
        
    # Inject static anomalies as threat events on timeline (2026-06-20)
    for _, row in anomalies_backend.iterrows():
        iid = row["identity_id"]
        if iid not in id_to_username:
            continue
        uname = id_to_username[iid]
        
        anom_type = str(row["anomaly_type"])
        sev = str(row["severity"])
        
        # Mapped platform
        plat_mapped = "Active Directory"
        prefix = "ad"
        if "AWS" in str(row["detail"]) or "key" in str(row["detail"]):
            plat_mapped = "AWS IAM"
            prefix = "aws"
        elif "Okta" in str(row["detail"]):
            plat_mapped = "Okta"
            prefix = "okta"
            
        matrix = user_to_matrix.get(uname, {})
        direct = matrix.get(f"{prefix}_direct_privilege", "None")
        effective = matrix.get(f"{prefix}_effective_privilege", "None")
        inherited = matrix.get(f"{prefix}_inherited_privilege", "None")
        chain = f"{direct} -> {inherited} -> {effective}" if inherited != "None" else "Direct Assignment"
        
        incidents_rows.append({
            "username": uname,
            "event_timestamp": "2026-06-20 08:00:00",
            "event_name": f"Threat Alert: {anom_type.replace('_', ' ').title()}",
            "platform": plat_mapped,
            "status": "Alert" if sev == "CRITICAL" else "Warning",
            "ip_address": "0.0.0.0",
            "description": f"{row['detail']}. Remediation guidance: {row['remediation']} [MITRE: {row['mitre']}].",
            "direct_privileges": direct,
            "effective_privileges": effective,
            "inheritance_chain": chain,
            "analyst_context": f"Active threat rule triggered: {row['rule']}. detail: {row['detail']}",
            "confidence_level": "High" if sev == "CRITICAL" else "Medium"
        })
        
    df_incidents = pd.DataFrame(incidents_rows)
    df_incidents = df_incidents.sort_values(by="event_timestamp", ascending=False).reset_index(drop=True)

    # 6. Construct risk_results.csv
    # Aggregated breakdown
    risk_breakdown = [
        {"risk_type": "Offboarding Gap", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Offboarding Gap", na=False)]), "severity": "Critical"},
        {"risk_type": "Token Abuse", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Token Abuse", na=False)]), "severity": "Critical"},
        {"risk_type": "Privilege Spike", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Privilege Spike", na=False)]), "severity": "High"},
        {"risk_type": "Hidden Admin", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Hidden Admin", na=False)]), "severity": "High"},
        {"risk_type": "Dormant Admin", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Dormant Admin", na=False)]), "severity": "Medium"},
        {"risk_type": "Cross-Platform Admin", "count": len(df_unified[df_unified["Detected Risks"].str.contains("Cross-Platform Admin", na=False)]), "severity": "Medium"},
    ]
    df_agg = pd.DataFrame(risk_breakdown)

    # User breakdown records
    user_risk_breakdowns = []
    for _, row in unified_backend.iterrows():
        iid = row["identity_id"]
        uname = id_to_username[iid]
        score_row = risk_scores_backend[risk_scores_backend["identity_id"] == iid].iloc[0]
        
        # Reasons analysis
        reasons = str(score_row["reasons"])
        risk_score = float(score_row["risk_score"])
        
        offboarding_val = 40.0 if "OFFBOARDING_GAP" in reasons else 0.0
        
        # Dormancy contributions
        dormancy_val = 0.0
        if "DORMANT_ADMIN:" in reasons: dormancy_val += 35.0
        if "STALE_TOKEN" in reasons: dormancy_val += 20.0
        if "DORMANT_ADMIN_ROLE_CHANGE" in reasons: dormancy_val += 15.0
        
        # Spread contribution
        spread_val = 30.0 if "CROSS_PLATFORM_ADMIN" in reasons and "CROSS_PLATFORM_ADMIN_JUSTIFIED" not in reasons else 0.0
        
        # Breadth/High Priv contribution
        breadth_val = 0.0
        if "INHERITED_ADMIN" in reasons: breadth_val += 25.0
        if "PRIVILEGE_ESCALATION" in reasons: breadth_val += 35.0
        if "TOKEN_SCOPE_MISMATCH" in reasons: breadth_val += 30.0
        if "LEGITIMATE_HIGH_PRIV" in reasons: breadth_val -= 15.0
        
        # Align totals exactly
        diff = risk_score - (offboarding_val + dormancy_val + spread_val + breadth_val)
        breadth_val += diff
        
        offboarding_val = round(max(0.0, offboarding_val), 1)
        dormancy_val = round(max(0.0, dormancy_val), 1)
        spread_val = round(max(0.0, spread_val), 1)
        breadth_val = round(max(0.0, breadth_val), 1)
        
        # Recommended action lookup
        recommended_action = "No immediate action required."
        user_anoms = anomalies_backend[anomalies_backend["identity_id"] == iid]
        if len(user_anoms) > 0:
            recommended_action = " | ".join(user_anoms["remediation"].dropna().unique())
            
        user_risk_breakdowns.append({
            "username": uname,
            "risk_score": risk_score,
            "privilege_breadth_score": breadth_val,
            "dormancy_score": dormancy_val,
            "platform_spread_score": spread_val,
            "offboarding_score": offboarding_val,
            "risk_breakdown": f"Breadth: {breadth_val} | Dormancy: {dormancy_val} | Spread: {spread_val} | Offboarding: {offboarding_val}",
            "recommended_action": recommended_action
        })
        
    df_user_breakdowns = pd.DataFrame(user_risk_breakdowns)
    df_risk_results = pd.concat([df_agg, df_user_breakdowns], ignore_index=True)

    return df_unified, df_privilege, df_offboarding, df_incidents, df_risk_results

def sync_data_to_disk():
    """Writes the normalized dataframes directly to the dashboard's data directory."""
    print("Initializing central data adapter...")
    df_unified, df_privilege, df_offboarding, df_incidents, df_risk_results = build_normalized_data()
    
    os.makedirs(DASHBOARD_DATA_DIR, exist_ok=True)
    
    # Serialize CSVs to disk
    df_unified.to_csv(os.path.join(DASHBOARD_DATA_DIR, "unified_identities.csv"), index=False)
    df_privilege.to_csv(os.path.join(DASHBOARD_DATA_DIR, "privilege_matrix.csv"), index=False)
    df_offboarding.to_csv(os.path.join(DASHBOARD_DATA_DIR, "offboarding_findings.csv"), index=False)
    df_incidents.to_csv(os.path.join(DASHBOARD_DATA_DIR, "incidents.csv"), index=False)
    df_risk_results.to_csv(os.path.join(DASHBOARD_DATA_DIR, "risk_results.csv"), index=False)
    
    print(f"Data sync complete. 5 datasets synchronized successfully into {DASHBOARD_DATA_DIR}.")
    return True

# Helper getters to load directly into pages
def get_unified_identities():
    return pd.read_csv(os.path.join(DASHBOARD_DATA_DIR, "unified_identities.csv"))

def get_privilege_matrix():
    return pd.read_csv(os.path.join(DASHBOARD_DATA_DIR, "privilege_matrix.csv"))

def get_offboarding_findings():
    return pd.read_csv(os.path.join(DASHBOARD_DATA_DIR, "offboarding_findings.csv"))

def get_incidents():
    return pd.read_csv(os.path.join(DASHBOARD_DATA_DIR, "incidents.csv"))

def get_risk_results():
    return pd.read_csv(os.path.join(DASHBOARD_DATA_DIR, "risk_results.csv"))

if __name__ == "__main__":
    sync_data_to_disk()
