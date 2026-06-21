import os
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# Seed for reproducibility
random.seed(42)
np.random.seed(42)

# Configuration
NUM_IDENTITIES = 300
DEPARTMENTS = ["Finance", "IT", "HR", "Engineering", "Operations", "Sales"]
DEPT_WEIGHTS = [0.12, 0.20, 0.08, 0.35, 0.15, 0.10]
IDENTITY_TYPES = ["Employee", "Contractor", "Service Account"]
IDENTITY_WEIGHTS = [0.75, 0.15, 0.10]
PLATFORMS = ["Active Directory", "AWS IAM", "Okta"]

# Mock Names Pool (First Names + Last Names to construct usernames)
first_names = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", 
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", 
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa", 
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley", 
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", 
    "Kenneth", "Carol", "Kevin", "Amanda", "Brian", "Melissa", "George", "Deborah", 
    "Timothy", "Stephanie", "Ronald", "Rebecca", "Edward", "Laura", "Jason", "Sharon", 
    "Jeffrey", "Cynthia", "Ryan", "Kathleen", "Jacob", "Helen", "Gary", "Amy", 
    "Nicholas", "Shirley", "Eric", "Angela", "Jonathan", "Anna", "Stephen", "Brenda", 
    "Larry", "Pamela", "Justin", "Nicole", "Scott", "Emma", "Brandon", "Samantha", 
    "Benjamin", "Katherine", "Samuel", "Christine", "Gregory", "Debra", "Alexander", "Rachel", 
    "Frank", "Carolyn", "Patrick", "Janet", "Raymond", "Maria", "Jack", "Heather", 
    "Dennis", "Olivia", "Jerry", "Anita", "Tyler", "Madison", "Aaron", "Diana", 
    "Jose", "Abigail", "Adam", "Alice", "Nathan", "Julie", "Henry", "Imani", "Zahra",
    "Siddharth", "Aarav", "Mei", "Chen", "Yuki", "Hiroto", "Mateo", "Sofia", "Amara"
]
last_names = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", 
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", 
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", 
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", 
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", 
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", 
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", 
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy", 
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey", 
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", 
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennet", "Gray", "Mendoza", 
    "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Mehta", "Sharma"
]

# Generate unique names
usernames = []
display_names = []
used_usernames = set()

for i in range(NUM_IDENTITIES - 30): # Reserve some for service accounts
    while True:
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        uname = f"{fn.lower()}.{ln.lower()}"
        dname = f"{fn} {ln}"
        if uname not in used_usernames:
            used_usernames.add(uname)
            usernames.append(uname)
            display_names.append(dname)
            break

# Generate service accounts
for i in range(30):
    services = ["svc-billing", "svc-jenkins", "svc-backup", "svc-monitoring", "svc-deployment", 
                "svc-db-sync", "svc-jira-hook", "svc-okta-sync", "svc-ad-connector", "svc-k8s-agent"]
    sname = f"{random.choice(services)}-{random.randint(100, 999)}"
    usernames.append(sname)
    display_names.append(sname.upper())

# Distribute Risk Categories
# 300 users:
# 1. Offboarding Gaps: 12% (36 users)
# 2. Over-privileged / Dormant Admins: 10% (30 users)
# 3. Privilege Spikes: 7% (21 users)
# 4. Token Abuse: 4% (12 users)
# 5. Legitimate High Privilege: 18% (54 users)
# 6. Normal users: 49% (147 users)

categories = (
    ["offboarding_gap"] * 36 +
    ["over_privileged"] * 30 +
    ["privilege_spike"] * 21 +
    ["token_abuse"] * 12 +
    ["legitimate_admin"] * 54 +
    ["normal"] * 147
)
random.shuffle(categories)

# Main list data
records = []
privilege_matrix = []
offboarding_findings = []
incidents = []

current_time = datetime.now()

for idx, (uname, dname, cat) in enumerate(zip(usernames, display_names, categories)):
    dept = np.random.choice(DEPARTMENTS, p=DEPT_WEIGHTS)
    
    # Service accounts are always Service Accounts type, others Employee or Contractor
    if uname.startswith("svc-"):
        id_type = "Service Account"
        dept = "IT" # IT owns service accounts mostly
    else:
        id_type = np.random.choice(["Employee", "Contractor"], p=[0.85, 0.15])

    # Platform Active/Inactive assignment
    # By default, AD, AWS IAM, Okta
    if cat == "offboarding_gap":
        # Offboarding Gap implies Active Directory is Disabled/Inactive, but AWS or Okta is Active
        ad_status = "Disabled"
        aws_status = random.choice(["Active", "Inactive"])
        okta_status = "Active" if aws_status == "Inactive" else random.choice(["Active", "Inactive"])
        # Ensure at least one is active
        if aws_status == "Inactive" and okta_status == "Inactive":
            okta_status = "Active"
            
        active_platforms = []
        if aws_status == "Active": active_platforms.append("AWS IAM")
        if okta_status == "Active": active_platforms.append("Okta")
    else:
        ad_status = "Active" if random.random() < 0.9 else "Inactive"
        aws_status = "Active" if random.random() < 0.7 else "Inactive"
        okta_status = "Active" if random.random() < 0.85 else "Inactive"
        
        # Ensure at least AD is active for normal users
        if ad_status == "Inactive" and aws_status == "Inactive" and okta_status == "Inactive":
            ad_status = "Active"
            
        active_platforms = []
        if ad_status == "Active": active_platforms.append("Active Directory")
        if aws_status == "Active": active_platforms.append("AWS IAM")
        if okta_status == "Active": active_platforms.append("Okta")

    # Risk details and scores
    detected_risks_list = []
    
    if cat == "offboarding_gap":
        risk_score = random.uniform(85.0, 98.0)
        severity = "Critical"
        detected_risks_list.append("Offboarding Gap")
    elif cat == "token_abuse":
        risk_score = random.uniform(80.0, 95.0)
        severity = "Critical" if risk_score > 90 else "High"
        detected_risks_list.append("Token Abuse")
        # May also have privilege spike
        if random.random() < 0.3:
            detected_risks_list.append("Privilege Spike")
    elif cat == "privilege_spike":
        risk_score = random.uniform(70.0, 84.0)
        severity = "High"
        detected_risks_list.append("Privilege Spike")
        if random.random() < 0.4:
            detected_risks_list.append("Hidden Admin")
    elif cat == "over_privileged":
        risk_score = random.uniform(50.0, 74.0)
        severity = "High" if risk_score > 65 else "Medium"
        detected_risks_list.append("Dormant Admin")
        if random.random() < 0.5:
            detected_risks_list.append("Hidden Admin")
    elif cat == "legitimate_admin":
        risk_score = random.uniform(25.0, 48.0)
        severity = "Medium" if risk_score > 35 else "Low"
        detected_risks_list.append("Cross-Platform Admin")
    else:
        risk_score = random.uniform(2.0, 24.0)
        severity = "Low"
        detected_risks_list.append("None")

    detected_risks = ", ".join(detected_risks_list) if detected_risks_list else "None"

    # Add to unified identities records
    records.append({
        "Rank": 0, # Will sort and rank later
        "User Name": uname,
        "Display Name": dname,
        "Department": dept,
        "Identity Type": id_type,
        "Platforms": ", ".join(active_platforms),
        "Risk Score": round(risk_score, 1),
        "Severity": severity,
        "Detected Risks": detected_risks
    })

    # Privilege Matrix setup
    # Levels: None, User, Read Only, Power User, Admin
    ad_priv = "None"
    aws_priv = "None"
    okta_priv = "None"

    # Assign privilege levels based on categories
    if cat in ["over_privileged", "legitimate_admin", "offboarding_gap"]:
        if "Active Directory" in active_platforms or ad_status == "Disabled":
            ad_priv = "Admin" if random.random() < 0.6 else "Power User"
        if "AWS IAM" in active_platforms:
            aws_priv = "Admin" if random.random() < 0.7 else "Power User"
        if "Okta" in active_platforms:
            okta_priv = "Admin" if random.random() < 0.5 else "Power User"
    elif cat == "privilege_spike":
        # Sudden admin level
        ad_priv = "Admin"
        aws_priv = "Power User"
        okta_priv = "User"
    elif cat == "token_abuse":
        ad_priv = "Power User"
        aws_priv = "Admin"
        okta_priv = "User"
    else: # normal
        if "Active Directory" in active_platforms:
            ad_priv = random.choice(["User", "Read Only"])
        if "AWS IAM" in active_platforms:
            aws_priv = random.choice(["User", "Read Only"])
        if "Okta" in active_platforms:
            okta_priv = random.choice(["User", "Read Only"])

    # Details of privileges
    ad_eff = f"Domain Admin (Inherited)" if ad_priv == "Admin" else ("Account Operator" if ad_priv == "Power User" else "Domain Users")
    ad_dir = "None" if ad_priv == "Admin" else ("Domain Users" if ad_priv == "User" else "Authenticated Users")
    ad_inh = "Domain Admins Group" if ad_priv == "Admin" else "None"

    aws_eff = "AdministratorAccess" if aws_priv == "Admin" else ("PowerUserAccess" if aws_priv == "Power User" else "ReadOnlyAccess")
    aws_dir = "CustomPolicy" if aws_priv == "Admin" and random.random() < 0.5 else "None"
    aws_inh = "IAM-Admin-Group" if aws_priv == "Admin" and aws_dir == "None" else "None"

    okta_eff = "Super Admin" if okta_priv == "Admin" else ("Application Administrator" if okta_priv == "Power User" else "Everyone")
    okta_dir = "None" if okta_priv == "Admin" else "Okta-Users-Group"
    okta_inh = "Okta-Admin-Roles" if okta_priv == "Admin" else "None"

    privilege_matrix.append({
        "username": uname,
        "Active Directory": ad_priv,
        "AWS IAM": aws_priv,
        "Okta": okta_priv,
        "ad_effective_privilege": ad_eff,
        "ad_direct_privilege": ad_dir,
        "ad_inherited_privilege": ad_inh,
        "aws_effective_privilege": aws_eff,
        "aws_direct_privilege": aws_dir,
        "aws_inherited_privilege": aws_inh,
        "okta_effective_privilege": okta_eff,
        "okta_direct_privilege": okta_dir,
        "okta_inherited_privilege": okta_inh
    })

    # Offboarding findings setup
    if cat == "offboarding_gap":
        exposure_days = random.randint(7, 120)
        term_date = (current_time - timedelta(days=exposure_days)).strftime("%Y-%m-%d")
        offboarding_findings.append({
            "User": uname,
            "Termination Date": term_date,
            "AD Status": "Disabled",
            "AWS Status": aws_status,
            "Okta Status": okta_status,
            "Exposure Days": exposure_days,
            "Severity": "Critical" if exposure_days > 30 else ("High" if exposure_days > 15 else "Medium")
        })

    # Incidents / Event Timelines setup
    # We will generate a list of events in the last 30 days.
    # Riskier users get more suspicious events.
    num_events = random.randint(3, 8)
    if cat in ["offboarding_gap", "token_abuse", "privilege_spike"]:
        num_events = random.randint(8, 15)

    base_time = current_time - timedelta(days=30)
    for ev_idx in range(num_events):
        event_time = base_time + timedelta(days=random.randint(0, 29), hours=random.randint(0, 23), minutes=random.randint(0, 59))
        event_name = "Console Login"
        platform = random.choice(active_platforms) if active_platforms else "Okta"
        status = "Success"
        ip_addr = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        desc = "Standard authentication flow verified."

        # Inject specific triggers
        if ev_idx == num_events - 1: # Last event
            if cat == "offboarding_gap":
                event_name = "Lingering Session Activity"
                status = "Warning"
                desc = "Account logged out in Active Directory, but active API calls detected in AWS Console."
                ip_addr = f"103.45.12.{random.randint(1, 254)}" # External IP
            elif cat == "token_abuse":
                event_name = "Token Session Hijack"
                status = "Alert"
                desc = "API access verified with 450 days old expired credentials from a new IP address."
                ip_addr = f"185.220.101.{random.randint(1, 254)}" # Suspicious Tor IP
            elif cat == "privilege_spike":
                event_name = "Privilege Escalation"
                status = "Alert"
                desc = "User added themselves to AWS AdministratorAccess role without ticketing approval."
                ip_addr = f"192.168.1.105"
            elif cat == "over_privileged":
                event_name = "Stale Admin Access"
                status = "Warning"
                desc = "User accessed critical system setting after 120 days of inactivity."
        else:
            # Common events
            common_events = [
                ("MFA Verification Successful", "Success", "Okta", "Multi-factor authentication check passed."),
                ("Policy Read Access", "Success", "AWS IAM", "Described IAM policies successfully."),
                ("Group Member Added", "Success", "Active Directory", "User added to standard engineering group."),
                ("Resource Created", "Success", "AWS IAM", "Created new EC2 micro instance."),
                ("Password Reset Request", "Success", "Okta", "Self-service password reset requested and validated.")
            ]
            ev_data = random.choice(common_events)
            event_name, status, platform, desc = ev_data

        # Determine direct/effective privilege details
        if platform == "Active Directory":
            direct_priv = ad_dir
            effective_priv = ad_eff
            chain = f"{ad_dir} -> {ad_inh} -> {ad_eff}" if ad_inh != "None" else f"{ad_dir} -> {ad_eff}"
        elif platform == "AWS IAM":
            direct_priv = aws_dir
            effective_priv = aws_eff
            chain = f"{aws_dir} -> {aws_inh} -> {aws_eff}" if aws_inh != "None" else f"{aws_dir} -> {aws_eff}"
        else: # Okta
            direct_priv = okta_dir
            effective_priv = okta_eff
            chain = f"{okta_dir} -> {okta_inh} -> {okta_eff}" if okta_inh != "None" else f"{okta_dir} -> {okta_eff}"

        # Determine analyst context and confidence level
        if cat == "offboarding_gap":
            context = "No justification found. Account is deactivated in HR registry (AD disabled) but remains active in cloud infrastructure."
            confidence = "High"
        elif cat == "token_abuse":
            context = "Session hijacking suspected. Stale API credentials used from unverified source IP."
            confidence = "High"
        elif cat == "privilege_spike":
            context = "Temporary access exception. Request #REQ-8491 was approved for emergency database maintenance."
            confidence = "Medium"
        elif cat == "over_privileged":
            context = "Role transition justification. User was moved to Engineering from Ops, but old permissions were not pruned."
            confidence = "Medium"
        elif cat == "legitimate_admin":
            context = "Standard business activity. Account has active approved exceptions for DevOps administrative duties."
            confidence = "Low"
        else:
            context = "No anomalies detected. Access parameters match baseline profile."
            confidence = "Low"

        incidents.append({
            "username": uname,
            "event_timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_name": event_name,
            "platform": platform,
            "status": status,
            "ip_address": ip_addr,
            "description": desc,
            "direct_privileges": direct_priv,
            "effective_privileges": effective_priv,
            "inheritance_chain": chain,
            "analyst_context": context,
            "confidence_level": confidence
        })

# Assign Rank to unified identities based on Risk Score desc
df_identities = pd.DataFrame(records)
df_identities = df_identities.sort_values(by="Risk Score", ascending=False).reset_index(drop=True)
df_identities["Rank"] = df_identities.index + 1

# Convert matrices and dataframes to save CSV
df_privilege = pd.DataFrame(privilege_matrix)
df_offboarding = pd.DataFrame(offboarding_findings)
df_incidents = pd.DataFrame(incidents)

# Save to disk
df_identities.to_csv("data/unified_identities.csv", index=False)
df_privilege.to_csv("data/privilege_matrix.csv", index=False)
df_offboarding.to_csv("data/offboarding_findings.csv", index=False)
df_incidents.to_csv("data/incidents.csv", index=False)

# Create risk_results.csv containing aggregated summary for reports
risk_breakdown = [
    {"risk_type": "Offboarding Gap", "count": 36, "severity": "Critical"},
    {"risk_type": "Token Abuse", "count": 12, "severity": "Critical"},
    {"risk_type": "Privilege Spike", "count": 21, "severity": "High"},
    {"risk_type": "Hidden Admin", "count": 18, "severity": "High"},
    {"risk_type": "Dormant Admin", "count": 30, "severity": "Medium"},
    {"risk_type": "Cross-Platform Admin", "count": 54, "severity": "Medium"},
]

# Write detailed user risk breakdowns
user_risk_breakdowns = []
for idx, (uname, cat) in enumerate(zip(usernames, categories)):
    # Find final score
    row_record = next(r for r in records if r["User Name"] == uname)
    final_score = row_record["Risk Score"]
    
    # Split score
    breadth = 10.0
    dormancy = 5.0
    spread = 5.0
    offboarding = 0.0
    
    if cat == "offboarding_gap":
        offboarding = final_score - 20.0
        breadth = 10.0
        dormancy = 5.0
        spread = 5.0
    elif cat == "token_abuse":
        breadth = 40.0
        spread = final_score - 50.0
        dormancy = 5.0
        offboarding = 5.0
    elif cat == "privilege_spike":
        breadth = final_score - 25.0
        dormancy = 10.0
        spread = 10.0
        offboarding = 5.0
    elif cat == "over_privileged":
        dormancy = final_score - 20.0
        breadth = 10.0
        spread = 5.0
        offboarding = 5.0
    elif cat == "legitimate_admin":
        breadth = final_score - 15.0
        dormancy = 5.0
        spread = 10.0
        offboarding = 0.0
    else: # normal
        breadth = final_score * 0.4
        dormancy = final_score * 0.3
        spread = final_score * 0.3
        offboarding = 0.0
        
    breadth = round(breadth, 1)
    dormancy = round(dormancy, 1)
    spread = round(spread, 1)
    offboarding = round(offboarding, 1)
    
    # Adjust for diff
    diff = round(final_score - (breadth + dormancy + spread + offboarding), 1)
    breadth = round(breadth + diff, 1)
    
    reasons = row_record["Detected Risks"]
    action = "No action required."
    if "Offboarding Gap" in reasons:
        action = "Deactivate AWS/Okta accounts immediately."
    elif "Token Abuse" in reasons:
        action = "Rotate static access keys and enforce MFA."
    elif "Dormant Admin" in reasons:
        action = "Deprovision admin credentials."
    elif "Privilege Spike" in reasons:
        action = "Conduct security review of role assignment."
        
    user_risk_breakdowns.append({
        "username": uname,
        "risk_score": final_score,
        "privilege_breadth_score": breadth,
        "dormancy_score": dormancy,
        "platform_spread_score": spread,
        "offboarding_score": offboarding,
        "risk_breakdown": f"Breadth: {breadth} | Dormancy: {dormancy} | Spread: {spread} | Offboarding: {offboarding}",
        "recommended_action": action
    })

df_agg = pd.DataFrame(risk_breakdown)
df_user_breakdowns = pd.DataFrame(user_risk_breakdowns)
df_risk_results = pd.concat([df_agg, df_user_breakdowns], ignore_index=True)
df_risk_results.to_csv("data/risk_results.csv", index=False)

print("Generated dummy datasets successfully.")
