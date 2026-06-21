import pandas as pd
import random
from faker import Faker
from config import SEED, TODAY
from datetime import timedelta

fake = Faker()
random.seed(SEED)
Faker.seed(SEED)

master = pd.read_csv("data/master_identities.csv")
records = []

# Justified admin cohorts — these are legitimate, by-design elevated access.
# IT leads: a small subset of human IT staff who genuinely need AD+AWS admin.
it_human_ids = master[(master["department"] == "IT") & (master["type"] != "service_account")]["identity_id"].tolist()
justified_it_ids = set(random.sample(it_human_ids, max(1, int(len(it_human_ids) * 0.75)))) if it_human_ids else set()


# Service accounts: a small subset whose function genuinely requires elevated cross-platform access (e.g. ETL).
svc_ids_all = master[master["type"] == "service_account"]["identity_id"].tolist()
justified_svc_ids = set(random.sample(svc_ids_all, max(1, int(len(svc_ids_all) * 0.5)))) if svc_ids_all else set()

justified_admin_ids = justified_it_ids | justified_svc_ids

# Unjustified cross-platform admin pool — the actual "over-privileged" anomaly.
# These are NOT in justified_admin_ids; they get admin on 2 platforms with no business reason.
non_term_ids = master[master["is_terminated"] == False]["identity_id"].tolist()
eligible_unjustified = [i for i in non_term_ids if i not in justified_admin_ids]
unjustified_admin_ids = set(random.sample(eligible_unjustified, min(40, len(eligible_unjustified))))


# ── Real AD OU Structure ──
AD_OU = {
    "Engineering" : "OU=Engineering,OU=Users,DC=corp,DC=socgen,DC=com",
    "Finance"     : "OU=Finance,OU=Users,DC=corp,DC=socgen,DC=com",
    "HR"          : "OU=HR,OU=Users,DC=corp,DC=socgen,DC=com",
    "IT"          : "OU=IT,OU=Privileged,DC=corp,DC=socgen,DC=com",
    "Sales"       : "OU=Sales,OU=Users,DC=corp,DC=socgen,DC=com",
    "Legal"       : "OU=Legal,OU=Users,DC=corp,DC=socgen,DC=com",
    "External"    : "OU=Contractors,OU=External,DC=corp,DC=socgen,DC=com"
}

# ── Real AD Group Structure ──
AD_GROUPS = {
    "Engineering" : ["GG-Dev-Staff", "GG-Git-Users", "GG-VPN-Access"],
    "Finance"     : ["GG-Finance-Staff", "GG-SAP-Users", "GG-ReadOnly-FS"],
    "HR"          : ["GG-HR-Staff", "GG-HRIS-Access"],
    "IT"          : ["GG-IT-Staff", "GG-Infra-Ops", "GG-ServiceDesk"],
    "Sales"       : ["GG-Sales-Staff", "GG-CRM-Access"],
    "Legal"       : ["GG-Legal-Staff", "GG-DLP-Policy"],
    "External"    : ["GG-Contractors", "GG-Guest-Access"]
}

# ── Real AWS Managed Policies ──
AWS_POLICIES = {
    "Engineering" : ["arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
                     "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                     "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess"],
    "Finance"     : ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                     "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"],
    "HR"          : ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
    "IT" : ["arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess"],
    
    "Sales"       : ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
    "Legal"       : ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
    "External"    : ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}

# ── Real Okta App Assignments ──
OKTA_APPS = {
    "Engineering" : ["GitHub Enterprise", "AWS SSO", "Jira", "Slack", "Confluence"],
    "Finance"     : ["SAP S4HANA", "Workday", "Slack", "Concur"],
    "HR"          : ["Workday", "Slack", "ServiceNow", "BambooHR"],
    "IT"          : ["AWS SSO", "GitHub Enterprise",
                     "ServiceNow", "Slack", "CyberArk"],
    "Sales"       : ["Salesforce", "Slack", "Zoom", "HubSpot"],
    "Legal"       : ["SharePoint", "Slack", "DocuSign", "Relativity"],
    "External"    : ["Jira", "Slack"]
}

def make_ad_username(name, identity_type, svc_name=None):
    """Corporate AD username format: firstname.lastname or svc-name"""
    if identity_type == "service_account":
        return svc_name.lower().replace(" ", "-")
    parts = name.lower().split()
    return f"{parts[0]}.{parts[-1]}"

def make_aws_username(name, identity_type, svc_name=None):
    """AWS IAM username format: firstname-lastname or svc-name-env"""
    if identity_type == "service_account":
        return svc_name.lower().replace(" ", "-")
    parts = name.lower().split()
    return f"{parts[0]}-{parts[-1]}"

def make_okta_username(name, dept, identity_type):
    """Okta username format: firstname.lastname@socgen.com"""
    if identity_type == "service_account":
        return None  # Service accounts don't have Okta
    if dept == "External":
        domain = "external.socgen.com"
    else:
        domain = "socgen.com"
    parts = name.lower().split()
    return f"{parts[0]}.{parts[-1]}@{domain}"

for _, row in master.iterrows():
    iid      = row["identity_id"]
    name     = row["name"]
    dept     = row["department"] if row["department"] in AD_GROUPS else "External"
    is_term  = row["is_terminated"]
    is_svc   = row["type"] == "service_account"
    is_cont  = row["type"] == "contractor"
    svc_name = row["name"] if is_svc else None

    # Offboarding gap decision — independent per platform, so AD/AWS/Okta
    # can disable at different times (or not at all), producing realistic
    # partial-offboarding patterns like "disabled in AD but still active in Okta".
    ad_gap   = is_term and random.random() < 0.25
    aws_gap  = is_term and random.random() < 0.15
    okta_gap = is_term and random.random() < 0.28

    # ── AD ──
    ad_user   = make_ad_username(name, row["type"], svc_name)
    ad_groups = AD_GROUPS.get(dept, ["GG-Guest-Access"]).copy()
    ad_ou     = AD_OU.get(dept, AD_OU["External"])

    # IT staff: small chance of hidden admin via nested group
    if not is_term and (iid in justified_admin_ids or iid in unjustified_admin_ids):
        ad_groups.append("GG-Domain-Admins")

    ad_status    = "active" if ad_gap else ("disabled" if is_term else "active")
    last_login_ad = TODAY - timedelta(days=random.randint(1, 400))

    records.append({
        "identity_id"      : iid,
        "platform"         : "AD",
        "platform_username": ad_user,
        "ou"               : ad_ou,
        "status"           : ad_status,
        "role_or_group"    : "|".join(ad_groups),
        "privilege_level"  : "admin" if "GG-Domain-Admins" in ad_groups else "standard",
        "last_login"       : last_login_ad.date(),
        "mfa_enabled"      : random.choice([True, False]),
        "api_key_age_days" : None,
        "department"       : dept,
        "admin_justified"  : iid in justified_admin_ids,
    })

    # ── AWS IAM ──
    aws_user    = make_aws_username(name, row["type"], svc_name)
    aws_policies = AWS_POLICIES.get(dept, ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]).copy()

    # Small chance non-IT gets admin (over-privilege anomaly)
    if (iid in justified_admin_ids or iid in unjustified_admin_ids) and not is_term:
        aws_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]

    if random.random() < 0.12:
        api_key_age = random.randint(366, 900)  # deliberately stale — ~12% of identities
    else:
        api_key_age = random.randint(1, 200)    # normal, rotated within the year
    aws_status  = "active" if aws_gap else ("inactive" if is_term else "active")
    last_login_aws = TODAY - timedelta(days=random.randint(1, 500))

    records.append({
        "identity_id"      : iid,
        "platform"         : "AWS",
        "platform_username": aws_user,
        "ou"               : None,
        "status"           : aws_status,
        "role_or_group"    : "|".join(aws_policies),
        "privilege_level"  : "admin" if "AdministratorAccess" in " ".join(aws_policies) else "standard",
        "last_login"       : last_login_aws.date(),
        "mfa_enabled"      : random.choice([True, True, False]),
        "api_key_age_days" : api_key_age,
        "department"       : dept,
        "admin_justified"  : iid in justified_admin_ids,
        "token_scope"      : "admin" if "AdministratorAccess" in " ".join(aws_policies) else "read_only",
    })

    # ── Okta ──
    # Contractors get limited Okta, service accounts get none
    if is_svc:
        okta_status = "not_applicable"
        okta_user   = None
        okta_apps   = []
    else:
        okta_user   = make_okta_username(name, dept, row["type"])
        okta_apps   = OKTA_APPS.get(dept, ["Slack"]).copy()
        if dept == "IT" and iid in justified_admin_ids:
            okta_apps.append("Okta Admin Console")
        if is_term:
            okta_status = "active" if okta_gap else "suspended"
        else:
            okta_status = "active"

    last_login_okta = TODAY - timedelta(days=random.randint(1, 300))

    records.append({
        "identity_id"      : iid,
        "platform"         : "Okta",
        "platform_username": okta_user,
        "ou"               : None,
        "status"           : okta_status,
        "role_or_group"    : "|".join(okta_apps) if okta_apps else None,
        "privilege_level"  : "admin" if "Okta Admin Console" in okta_apps else "standard",
        "last_login"       : last_login_okta.date() if okta_status not in ["not_applicable", "suspended"] else None,
        "mfa_enabled"      : random.choice([True, True, True, False]),
        "api_key_age_days" : None,
        "department"       : dept,
        "admin_justified"  : iid in justified_admin_ids,
    })

df = pd.DataFrame(records)
df.to_csv("data/platform_snapshots.csv", index=False)
print(f" Generated {len(df)} platform records -> data/platform_snapshots.csv")