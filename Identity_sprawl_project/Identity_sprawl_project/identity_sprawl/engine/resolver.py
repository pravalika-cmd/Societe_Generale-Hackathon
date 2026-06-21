import pandas as pd
import os

def resolve_identities():
    # Load all data
    master = pd.read_csv("data/master_identities.csv")
    snapshots = pd.read_csv("data/platform_snapshots.csv")
    groups = pd.read_csv("data/group_mappings.csv")
    offboarding = pd.read_csv("data/offboarding_records.csv")

    # ── 1. Pivot snapshots so each identity has one row with all platform info ──
    platforms = ["AD", "AWS", "Okta"]
    pivot_records = []

    for iid, group in snapshots.groupby("identity_id"):
        record = {"identity_id": iid}

        for platform in platforms:
            pdata = group[group["platform"] == platform]
            if len(pdata) == 0:
                record[f"{platform}_username"]        = None
                record[f"{platform}_status"]          = "not_found"
                record[f"{platform}_privilege"]       = None
                record[f"{platform}_last_login"]      = None
                record[f"{platform}_mfa"]             = None
                record[f"{platform}_api_key_age"]     = None
                record[f"{platform}_token_scope"]     = None
                record[f"{platform}_admin_justified"] = False
            else:
                row = pdata.iloc[0]
                record[f"{platform}_username"]        = row["platform_username"]
                record[f"{platform}_status"]          = row["status"]
                record[f"{platform}_privilege"]       = row["privilege_level"]
                record[f"{platform}_last_login"]      = row["last_login"]
                record[f"{platform}_mfa"]             = row["mfa_enabled"]
                record[f"{platform}_api_key_age"]     = row["api_key_age_days"]
                record[f"{platform}_token_scope"]     = row["token_scope"] if "token_scope" in row and pd.notna(row.get("token_scope")) else None
                record[f"{platform}_admin_justified"] = bool(row["admin_justified"]) if "admin_justified" in row and pd.notna(row.get("admin_justified")) else False

        pivot_records.append(record)

    platform_pivot = pd.DataFrame(pivot_records)

    # ── 2. Merge with master identity info ──
    unified = master.merge(platform_pivot, on="identity_id", how="left")

    # ── 3. Add cross-platform status summary ──
    def get_platform_statuses(row):
        return {p: row[f"{p}_status"] for p in platforms}

    def is_active_somewhere(row):
        return any(
            row[f"{p}_status"] == "active"
            for p in platforms
        )

    def active_platform_count(row):
        return sum(
            1 for p in platforms
            if row[f"{p}_status"] == "active"
        )

    unified["active_platform_count"] = unified.apply(active_platform_count, axis=1)
    unified["active_somewhere"]      = unified.apply(is_active_somewhere, axis=1)

    # ── 4. Flag offboarding gaps ──
    gap_ids = offboarding[offboarding["offboarding_gap"] == True]["identity_id"].unique()
    unified["has_offboarding_gap"] = unified["identity_id"].isin(gap_ids)

    # ── 5. Add effective privilege from group mappings ──
    # Get highest privilege per identity across all platforms
    priv_order = {"admin": 3, "elevated": 2, "standard": 1, "limited": 0}

    def get_effective_privilege(iid):
        iid_groups = groups[groups["identity_id"] == iid]
        if len(iid_groups) == 0:
            return "standard"
        levels = iid_groups["effective_privilege"].map(
            lambda x: priv_order.get(x, 0)
        )
        max_level = levels.max()
        return {v: k for k, v in priv_order.items()}.get(max_level, "standard")

    def has_nested_admin(iid):
        iid_groups = groups[groups["identity_id"] == iid]
        return bool(iid_groups["is_nested_admin"].any())

    print("   Computing effective privileges...")
    unified["effective_privilege"] = unified["identity_id"].apply(get_effective_privilege)
    unified["has_nested_admin"]    = unified["identity_id"].apply(has_nested_admin)

    # ── 6. Add dormancy flag ──
    # Identity is dormant if last login on any platform > 90 days ago
    from datetime import datetime
    today = datetime.now()

    def days_since_last_login(row):
        dates = []
        for p in platforms:
            val = row[f"{p}_last_login"]
            if pd.notna(val):
                try:
                    dates.append((today - pd.to_datetime(val)).days)
                except:
                    pass
        return min(dates) if dates else 999

    unified["days_since_last_login"] = unified.apply(days_since_last_login, axis=1)
    unified["is_dormant"]            = unified["days_since_last_login"] > 90

    # ── 7. Save ──
    os.makedirs("outputs", exist_ok=True)
    unified.to_csv("outputs/unified_identities.csv", index=False)
    print(f" Resolved {len(unified)} identities -> outputs/unified_identities.csv")
    print(f"   Columns: {list(unified.columns)}")
    return unified


if __name__ == "__main__":
    print("\n Running identity resolver...")
    resolve_identities()