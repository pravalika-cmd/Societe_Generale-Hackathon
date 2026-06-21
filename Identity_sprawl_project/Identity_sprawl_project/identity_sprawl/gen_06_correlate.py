import pandas as pd
import random
from datetime import timedelta, datetime
from config import SEED, TODAY

random.seed(SEED)

def run_correlation():
    master      = pd.read_csv("data/master_identities.csv")
    snapshots   = pd.read_csv("data/platform_snapshots.csv")
    audit       = pd.read_csv("data/audit_events.csv")
    offboarding = pd.read_csv("data/offboarding_records.csv")

    print("\n Correlating anomalies across platforms...")

    # ── FIX 1: Dormant Admin ──
    # If identity has admin privilege, make sure last_login > 90 days ago
    # so the dormant admin rule actually fires consistently
    admin_ids = snapshots[snapshots["privilege_level"] == "admin"]["identity_id"].unique()
    dormant_admin_ids = random.sample(list(admin_ids), k=min(30, len(admin_ids)))

    for iid in dormant_admin_ids:
        mask = (snapshots["identity_id"] == iid)
        dormant_login = TODAY - timedelta(days=random.randint(95, 400))
        snapshots.loc[mask, "last_login"] = dormant_login.date()

        # Also make sure their audit log shows no recent logins
        audit_mask = (audit["identity_id"] == iid) & (audit["event_type"] == "login")
        if audit_mask.any():
            old_time = TODAY - timedelta(days=random.randint(95, 300))
            audit.loc[audit_mask, "timestamp"] = old_time

    print(f" Fixed {len(dormant_admin_ids)} dormant admin identities")

    # ── FIX 2: Stale API Token Correlation ──
    # If AWS api_key_age > 365, make sure AWS status is active
    # and audit log shows suspicious external IP usage
    stale_mask = (
        snapshots["platform"] == "AWS"
    ) & (
        snapshots["api_key_age_days"] > 365
    )
    stale_ids = snapshots[stale_mask]["identity_id"].unique()

    for iid in stale_ids:
        # Make sure AWS is active (stale token is only risky if still active)
        mask = (snapshots["identity_id"] == iid) & (snapshots["platform"] == "AWS")
        snapshots.loc[mask, "status"] = "active"

    print(f" Fixed {len(stale_ids)} stale token identities")

    # ── FIX 3: Offboarding Gap Correlation ──
    # Terminated users with gaps must have:
    # - AD showing disabled
    # - At least one other platform showing active
    # - Audit log showing recent activity AFTER termination date
    gap_ids = offboarding[
        offboarding["offboarding_gap"] == True
    ]["identity_id"].unique()

    for iid in gap_ids:
        term_row = master[master["identity_id"] == iid]
        if len(term_row) == 0:
            continue

        term_date = term_row["termination_date"].values[0]
        if pd.isna(term_date):
            continue

        term_dt = pd.to_datetime(term_date)

        # AD must be disabled
        ad_mask = (
            snapshots["identity_id"] == iid
        ) & (
            snapshots["platform"] == "AD"
        )
        snapshots.loc[ad_mask, "status"] = "disabled"

        # AWS or Okta must be active (the gap)
        for platform in ["AWS", "Okta"]:
            p_mask = (
                snapshots["identity_id"] == iid
            ) & (
                snapshots["platform"] == platform
            )
            p_data = snapshots[p_mask]
            if len(p_data) > 0 and p_data.iloc[0]["status"] != "not_applicable":
                if random.random() < 0.30:
                    snapshots.loc[p_mask, "status"] = "active"
                    # Add a suspicious post-termination login event
                    post_term = term_dt + timedelta(days=random.randint(1, 60))
                    audit_record = {
                        "event_id"    : f"EVT_GAP_{iid}_{platform}",
                        "identity_id" : iid,
                        "platform"    : platform,
                        "event_type"  : "login",
                        "timestamp"   : post_term,
                        "source_ip"   : f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        "resource"    : None,
                        "action"      : "login_success",
                        "anomaly_type": "offboarding_gap",
                        "severity"    : "CRITICAL"
                    }
                    audit = pd.concat(
                        [audit, pd.DataFrame([audit_record])],
                        ignore_index=True
                    )

    print(f" Fixed {len(gap_ids)} offboarding gap identities")

    # ── FIX 4: Privilege Escalation Correlation ──
    # Identities with privilege_escalation in audit log must show
    # a corresponding group change — timestamp at odd hours
    esc_ids = audit[
        audit["anomaly_type"] == "privilege_escalation"
    ]["identity_id"].unique()

    for iid in esc_ids:
        # Make sure their current snapshot shows elevated/admin privilege
        mask = (snapshots["identity_id"] == iid)
        current_priv = snapshots[mask]["privilege_level"].values
        if len(current_priv) > 0 and current_priv[0] == "standard":
            ad_mask = (
                snapshots["identity_id"] == iid
            ) & (
                snapshots["platform"] == "AD"
            )
            snapshots.loc[ad_mask, "privilege_level"] = "elevated"

    print(f" Fixed {len(esc_ids)} privilege escalation identities")

    # ── FIX 5: Cross Platform Cascade Correlation ──
    # Identities with cascade events must have accounts on all 3 platforms
    cascade_ids = audit[
        audit["anomaly_type"] == "cross_platform_cascade"
    ]["identity_id"].unique()

    for iid in cascade_ids:
        for platform in ["AD", "AWS", "Okta"]:
            mask = (
                snapshots["identity_id"] == iid
            ) & (
                snapshots["platform"] == platform
            )
            p_data = snapshots[mask]
            if len(p_data) > 0:
                if p_data.iloc[0]["status"] == "not_applicable":
                    continue
                snapshots.loc[mask, "status"] = "active"

    print(f" Fixed {len(cascade_ids)} cross-platform cascade identities")

    # ── Save all fixed files ──
    snapshots.to_csv("data/platform_snapshots.csv", index=False)
    audit.to_csv("data/audit_events.csv", index=False)

    print(f"\n Correlation complete")
    print(f"   platform_snapshots.csv updated")
    print(f"   audit_events.csv updated")
    print(f"   Total audit events now: {len(audit)}")

if __name__ == "__main__":
    run_correlation()