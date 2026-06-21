import pandas as pd
import random
from config import SEED

random.seed(SEED)

# Updated to match gen_02 group names exactly
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

snapshots = pd.read_csv("data/platform_snapshots.csv")
records   = []

for _, row in snapshots.iterrows():
    if pd.isna(row["role_or_group"]):
        continue
    groups = str(row["role_or_group"]).split("|")
    for group in groups:
        group = group.strip()
        if group not in GROUP_HIERARCHY:
            continue
        info = GROUP_HIERARCHY[group]
        parent = info["parent"]
        is_nested_admin = (
            group in ["GG-Domain-Admins", "GG-Enterprise-Admins",
                      "arn:aws:iam::aws:policy/AdministratorAccess",
                      "arn:aws:iam::aws:policy/IAMFullAccess",
                      "Okta Admin Console"] or
            parent in ["GG-Domain-Admins", "GG-Enterprise-Admins",
                       "arn:aws:iam::aws:policy/AdministratorAccess"]
        )
        records.append({
            "identity_id"      : row["identity_id"],
            "platform"         : row["platform"],
            "direct_group"     : group,
            "parent_group"     : parent,
            "effective_privilege": info["privilege_level"],
            "is_nested_admin"  : is_nested_admin
        })

df = pd.DataFrame(records)
df.to_csv("data/group_mappings.csv", index=False)
print(f" Generated {len(df)} group mapping records -> data/group_mappings.csv")
print(f"   Nested admin entries : {df['is_nested_admin'].sum()}")