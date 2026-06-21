import pandas as pd
import os
from datetime import datetime

def run_risk_scorer():
    unified     = pd.read_csv("outputs/unified_identities.csv")
    audit       = pd.read_csv("data/audit_events.csv")
    offboarding = pd.read_csv("data/offboarding_records.csv")

    scores  = []
    anomaly_records = []

    for _, row in unified.iterrows():
        iid         = row["identity_id"]
        risk_score  = 0
        reasons     = []
        anomalies   = []

        # ── RULE 1: Offboarding Gap ──
        # Terminated but still active on at least one platform
        if row["is_terminated"] and row["active_somewhere"]:
            risk_score += 40
            active_platforms = [
                p for p in ["AD", "AWS", "Okta"]
                if row.get(f"{p}_status") == "active"
            ]
            reasons.append(f"OFFBOARDING_GAP: Terminated but active on {', '.join(active_platforms)}")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "offboarding_gap",
                "severity"     : "CRITICAL",
                "detail"       : f"Active on {', '.join(active_platforms)} after termination",
                "rule"         : "RULE_1",
                "mitre"        : "T1078 - Valid Accounts",
                "remediation"  : f"Immediately disable accounts on: {', '.join(active_platforms)}"
            })

        # ── RULE 2: Dormant Admin ──
        # Has admin privilege but hasn't logged in for 90+ days
        if row.get("effective_privilege") == "admin" and row.get("days_since_last_login", 0) > 90:
            risk_score += 35
            reasons.append(f"DORMANT_ADMIN: Admin privilege with {row.get('days_since_last_login')} days since last login")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "dormant_admin",
                "severity"     : "HIGH",
                "detail"       : f"No login in {row.get('days_since_last_login')} days but holds admin privilege",
                "rule"         : "RULE_2",
                "mitre"        : "T1078 - Valid Accounts",
                "remediation"  : "Revoke admin privileges or force re-certification"
            })

        # ── RULE 3: Cross-Platform Admin (Unjustified) ──
        # Admin on 2+ platforms WITHOUT a recorded business justification
        is_justified = any(
            row.get(f"{p}_admin_justified") for p in ["AD", "AWS", "Okta"]
        )
        if row.get("is_cross_platform_admin") and not is_justified:
            admin_platforms = str(row.get("admin_platforms", "")).split("|")
            risk_score += 30
            reasons.append(f"CROSS_PLATFORM_ADMIN: Unjustified admin on {', '.join(admin_platforms)}")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "cross_platform_admin",
                "severity"     : "HIGH",
                "detail"       : f"Holds admin on {', '.join(admin_platforms)} simultaneously, with no recorded business justification",
                "rule"         : "RULE_3",
                "mitre"        : "T1098 - Account Manipulation",
                "remediation"  : f"Review and reduce admin scope on {', '.join(admin_platforms)}"
            })
        elif row.get("is_cross_platform_admin") and is_justified:
            # Legitimate high-priv — explicitly note it rather than silently dropping it,
            # so the report shows we evaluated it and made a deliberate call.
            reasons.append("CROSS_PLATFORM_ADMIN_JUSTIFIED: Admin on 2+ platforms, recorded business justification on file")

        # ── RULE 4: Inherited Admin (Hidden Privilege) ──
        # Admin through nested group membership — not directly assigned
        if row.get("inherited_admin"):
            risk_score += 25
            via = row.get("inherited_via", "unknown path")
            reasons.append(f"INHERITED_ADMIN: Hidden admin via {via}")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "inherited_admin",
                "severity"     : "HIGH",
                "detail"       : f"Effective admin through nested group: {via}",
                "rule"         : "RULE_4",
                "mitre"        : "T1098 - Account Manipulation",
                "remediation"  : f"Flatten group hierarchy or remove from {via}"
            })

        # ── RULE 5: Stale API Token ──
        # API key older than 365 days still active
        aws_key_age = row.get("AWS_api_key_age", 0)
        if pd.notna(aws_key_age) and aws_key_age > 365 and row.get("AWS_status") == "active":
            risk_score += 20
            reasons.append(f"STALE_TOKEN: AWS API key is {int(aws_key_age)} days old")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "stale_token",
                "severity"     : "MEDIUM",
                "detail"       : f"AWS API key not rotated in {int(aws_key_age)} days",
                "rule"         : "RULE_5",
                "mitre"        : "T1550 - Use Alternate Authentication Material",
                "remediation"  : "Rotate AWS access key immediately"
            })

        # ── RULE 6: Privilege Escalation in Audit Log ──
        # Unexpected group addition event for this identity
        identity_audit = audit[
            (audit["identity_id"] == iid) &
            (audit["anomaly_type"] == "privilege_escalation")
        ]
        if len(identity_audit) > 0:
            risk_score += 35
            reasons.append(f"PRIVILEGE_ESCALATION: {len(identity_audit)} unexpected privilege change(s) in audit log")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "privilege_escalation",
                "severity"     : "CRITICAL",
                "detail"       : f"{len(identity_audit)} privilege escalation events detected in audit log",
                "rule"         : "RULE_6",
                "mitre"        : "T1098 - Account Manipulation",
                "remediation"  : "Review and revert all recent privilege changes"
            })

        # ── RULE 7: Dormant Admin With Recent Role Change ──
        # Stale on login, but HR just changed their role — ambiguous: stale or transitioning?
        role_change_date = row.get("last_role_change_date")
        if (
            pd.notna(role_change_date)
            and row.get("effective_privilege") == "admin"
            and row.get("days_since_last_login", 0) > 90
        ):
            risk_score += 15
            reasons.append(f"DORMANT_ADMIN_ROLE_CHANGE: Admin dormant {row.get('days_since_last_login')}d, but role changed on {role_change_date} — verify transition is legitimate")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "dormant_admin_role_change",
                "severity"     : "MEDIUM",
                "detail"       : f"Admin inactive {row.get('days_since_last_login')} days, with a role change on {role_change_date}. Could be a legitimate transition (e.g. new role pending access setup) or a stale account riding on an unrelated HR update.",
                "rule"         : "RULE_7",
                "mitre"        : "AC-2 - Account Management (dormancy review)",
                "remediation"  : "Confirm with HR/manager whether this is an active transition; if not, revoke admin access"
            })

        # ── RULE 8: Token Scope Mismatch ──
        # Read-only scoped AWS token used for a write-style action in the audit log
        identity_scope_mismatch = audit[
            (audit["identity_id"] == iid) &
            (audit["anomaly_type"] == "token_scope_mismatch")
        ]
        if len(identity_scope_mismatch) > 0:
            risk_score += 30
            reasons.append(f"TOKEN_SCOPE_MISMATCH: {len(identity_scope_mismatch)} write action(s) on a read-only scoped token")
            anomalies.append({
                "identity_id"  : iid,
                "anomaly_type" : "token_scope_mismatch",
                "severity"     : "HIGH",
                "detail"       : f"{len(identity_scope_mismatch)} write-style API call(s) made using a token provisioned as read-only — possible misconfigured app or compromised credential",
                "rule"         : "RULE_8",
                "mitre"        : "T1550 - Use Alternate Authentication Material",
                "remediation"  : "Investigate the calling application; rotate the token and verify intended scope"
            })

        # ── LEGITIMATE HIGH PRIV TRAP ──
        # IT staff with admin — expected, lower the score
        if row.get("department") == "IT" and row.get("effective_privilege") == "admin":
            risk_score = max(0, risk_score - 15)
            reasons.append("LEGITIMATE_HIGH_PRIV: IT department admin — expected role")

        # ── FINAL SCORE BAND ──
        if risk_score >= 60:
            risk_band = "CRITICAL"
        elif risk_score >= 40:
            risk_band = "HIGH"
        elif risk_score >= 20:
            risk_band = "MEDIUM"
        else:
            risk_band = "LOW"

        scores.append({
            "identity_id"           : iid,
            "name"                  : row.get("name"),
            "type"                  : row.get("type"),
            "department"            : row.get("department"),
            "is_terminated"         : row.get("is_terminated"),
            "effective_privilege"   : row.get("effective_privilege"),
            "is_cross_platform_admin": row.get("is_cross_platform_admin"),
            "inherited_admin"       : row.get("inherited_admin"),
            "days_since_last_login" : row.get("days_since_last_login"),
            "has_offboarding_gap"   : row.get("has_offboarding_gap"),
            "last_role_change_date" : row.get("last_role_change_date"),
            "AWS_api_key_age"       : aws_key_age,
            "risk_score"            : min(risk_score, 100),
            "risk_band"             : risk_band,
            "reasons"               : " | ".join(reasons) if reasons else "No anomalies detected",
            "anomaly_count"         : len(anomalies)
        })

        anomaly_records.extend(anomalies)

    # ── Save outputs ──
    scores_df   = pd.DataFrame(scores)
    anomaly_df  = pd.DataFrame(anomaly_records)

    scores_df.to_csv("outputs/risk_scores.csv", index=False)
    anomaly_df.to_csv("outputs/anomalies.csv", index=False)

    # ── Summary ──
    print(f"\n Risk scoring complete")
    print(f"   Total identities scored : {len(scores_df)}")
    print(f"   CRITICAL                : {len(scores_df[scores_df['risk_band']=='CRITICAL'])}")
    print(f"   HIGH                    : {len(scores_df[scores_df['risk_band']=='HIGH'])}")
    print(f"   MEDIUM                  : {len(scores_df[scores_df['risk_band']=='MEDIUM'])}")
    print(f"   LOW                     : {len(scores_df[scores_df['risk_band']=='LOW'])}")
    print(f"   Total anomalies flagged : {len(anomaly_df)}")
    print(f"\n outputs/risk_scores.csv")
    print(f" outputs/anomalies.csv")

    return scores_df, anomaly_df

if __name__ == "__main__":
    print("\n Running risk scorer...")
    run_risk_scorer()