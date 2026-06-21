import pandas as pd
import os

# Full group hierarchy for traversal
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

PRIV_ORDER = {"admin": 3, "elevated": 2, "standard": 1, "limited": 0}

def get_all_ancestors(group_name):
    """Traverse up the hierarchy and return all ancestor groups."""
    ancestors = []
    current = group_name
    visited = set()
    while current:
        if current in visited:
            break
        visited.add(current)
        info = GROUP_HIERARCHY.get(current)
        if not info:
            break
        parent = info["parent"]
        if parent:
            ancestors.append(parent)
        current = parent
    return ancestors

def compute_effective_privilege(direct_groups):
    """
    Given a list of direct group memberships,
    compute the highest effective privilege including inherited ones.
    """
    all_groups = set(direct_groups)

    # Add all ancestors for each direct group
    for g in direct_groups:
        ancestors = get_all_ancestors(g)
        all_groups.update(ancestors)

    # Find highest privilege across all groups
    max_priv = 0
    max_priv_name = "standard"
    inherited_admin = False
    inherited_path = []

    for g in all_groups:
        info = GROUP_HIERARCHY.get(g)
        if not info:
            continue
        level = PRIV_ORDER.get(info["privilege_level"], 0)
        if level > max_priv:
            max_priv = level
            max_priv_name = info["privilege_level"]

        # Track if admin came from inheritance not direct assignment
        if info["privilege_level"] == "admin" and g not in direct_groups:
            inherited_admin = True
            inherited_path.append(g)

    return max_priv_name, inherited_admin, inherited_path, list(all_groups)

def run_privilege_calc():
    unified   = pd.read_csv("outputs/unified_identities.csv")
    snapshots = pd.read_csv("data/platform_snapshots.csv")
    groups_df = pd.read_csv("data/group_mappings.csv")

    results = []

    for _, row in unified.iterrows():
        iid = row["identity_id"]

        # Get all direct group memberships for this identity
        direct_groups = []
        identity_snaps = snapshots[snapshots["identity_id"] == iid]

        for _, snap in identity_snaps.iterrows():
            if pd.notna(snap["role_or_group"]):
                grps = str(snap["role_or_group"]).split("|")
                direct_groups.extend([g.strip() for g in grps])

        direct_groups = list(set(direct_groups))

        # Compute effective privilege
        eff_priv, inherited_admin, inherited_path, all_groups = compute_effective_privilege(direct_groups)

        # Cross-platform admin check
        # Admin on 2+ platforms is a major risk signal
        admin_platforms = []
        for p in ["AD", "AWS", "Okta"]:
            if row.get(f"{p}_privilege") == "admin":
                admin_platforms.append(p)

        is_cross_platform_admin = len(admin_platforms) >= 2

        results.append({
            "identity_id"           : iid,
            "direct_groups"         : "|".join(direct_groups),
            "all_effective_groups"  : "|".join(all_groups),
            "effective_privilege"   : eff_priv,
            "inherited_admin"       : inherited_admin,
            "inherited_via"         : "|".join(inherited_path) if inherited_path else None,
            "admin_platforms"       : "|".join(admin_platforms) if admin_platforms else None,
            "is_cross_platform_admin": is_cross_platform_admin,
            "direct_group_count"    : len(direct_groups),
            "effective_group_count" : len(all_groups),
        })

    priv_df = pd.DataFrame(results)

    # Merge back into unified — drop ANY column we're about to re-add (from this
    # script's own prior runs, plus resolver's first-pass versions) so re-running
    # this script never produces _x/_y suffix collisions.
    cols_to_replace = [c for c in priv_df.columns if c != "identity_id"]
    cols_to_replace += ["has_nested_admin"]  # resolver's first-pass column, superseded here
    unified = unified.drop(columns=[c for c in cols_to_replace if c in unified.columns], errors="ignore")
    unified = unified.merge(priv_df, on="identity_id", how="left")
    unified.to_csv("outputs/unified_identities.csv", index=False)
    
    print(f"Privilege calc complete -> outputs/unified_identities.csv updated")
    print(f"   Inherited admin cases : {priv_df['inherited_admin'].sum()}")
    print(f"   Cross-platform admins : {priv_df['is_cross_platform_admin'].sum()}")
    return unified, priv_df

if __name__ == "__main__":
    print("\n Running privilege calculator...")
    run_privilege_calc()
if __name__ == "__main__":
    print("\n Running privilege calculator...")
    run_privilege_calc()