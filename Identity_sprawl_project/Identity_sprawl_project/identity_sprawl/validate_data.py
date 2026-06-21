import pandas as pd

print("\n HACKATHON DATA VALIDATION REPORT")
print("=" * 50)

# Load all files
master = pd.read_csv("data/master_identities.csv")
snapshots = pd.read_csv("data/platform_snapshots.csv")
groups = pd.read_csv("data/group_mappings.csv")
audit = pd.read_csv("data/audit_events.csv")
offboarding = pd.read_csv("data/offboarding_records.csv")

# ── 1. IDENTITY SNAPSHOTS (required: 200-400) ──
print("\n IDENTITY SNAPSHOTS")
print(f"   Total identities     : {len(master)} (required: 200-400)")
print(f"   Employees            : {len(master[master['type']=='employee'])}")
print(f"   Contractors          : {len(master[master['type']=='contractor'])}")
print(f"   Service Accounts     : {len(master[master['type']=='service_account'])}")
print(f"   Platform records     : {len(snapshots)} (should be ~1200 = 400x3)")

# ── 2. GROUP/ROLE MAPPINGS (required: 100-200) ──
print("\n GROUP/ROLE MAPPINGS")
print(f"   Total mappings       : {len(groups)} (required: 100+)")
print(f"   Nested admin entries : {len(groups[groups['is_nested_admin']==True])}")
print(f"   Platforms covered    : {groups['platform'].unique()}")

# ── 3. AUDIT EVENTS (required: 500-1000) ──
print("\n AUDIT EVENTS")
print(f"   Total events         : {len(audit)} (required: 500-1000)")
print(f"   Event types          : {audit['event_type'].value_counts().to_dict()}")

# ── 4. OFFBOARDING RECORDS (required: 50-100) ──
print("\n OFFBOARDING RECORDS")
total_terminated = len(master[master['is_terminated']==True])
total_gaps = len(offboarding[offboarding['offboarding_gap']==True])
print(f"   Terminated identities: {total_terminated} (required: 50-100)")
print(f"   Offboarding gaps     : {total_gaps}")

# ── 5. ANOMALY MIX ──
print("\n ANOMALY MIX CHECK")
total_identities = len(master)
total_audit = len(audit)

# Orphaned: terminated AND still active on at least one platform
terminated_ids = set(master[master["is_terminated"] == True]["identity_id"])
orphaned = 0
for iid in terminated_ids:
    iid_snaps = snapshots[snapshots["identity_id"] == iid]
    if any(iid_snaps["status"] == "active"):
        orphaned += 1
orphaned_pct = (orphaned / total_identities) * 100
print(f"   Orphaned/stale accounts      : {orphaned_pct:.1f}% (required: 10-15%) [{orphaned} identities]")

# Over-privileged: admin on 2+ platforms (per spec), excluding identities whose
# cross-platform admin is flagged as legitimately justified (e.g. IT role requirement).
admin_counts = (
    snapshots[snapshots["privilege_level"] == "admin"]
    .groupby("identity_id")["platform"]
    .nunique()
)
cross_platform_admin_ids = set(admin_counts[admin_counts >= 2].index)

justified_ids = set(snapshots[snapshots.get("admin_justified", False) == True]["identity_id"]) \
    if "admin_justified" in snapshots.columns else set()

over_priv_ids = cross_platform_admin_ids - justified_ids
over_priv_pct = (len(over_priv_ids) / total_identities) * 100
print(f"   Over-privileged identities   : {over_priv_pct:.1f}% (required: 8-12%) [{len(over_priv_ids)} identities]")

# Privilege escalation: as % of audit events
escalation = len(audit[audit["anomaly_type"] == "privilege_escalation"])
escalation_pct = (escalation / total_audit) * 100
print(f"   Privilege escalation events  : {escalation_pct:.1f}% (required: 5-8%) [{escalation} events]")

# Token abuse: as % of audit events
token_abuse = len(audit[audit["anomaly_type"] == "token_abuse"])
token_pct = (token_abuse / total_audit) * 100
print(f"   Token/credential abuse       : {token_pct:.1f}% (required: 3-5%) [{token_abuse} events]")

# Legitimate high priv: as % of audit events
legit_high = len(audit[audit["anomaly_type"] == "legitimate_high_priv"])
legit_pct = (legit_high / total_audit) * 100
print(f"   Legitimate high-priv         : {legit_pct:.1f}% (required: 15-20%) [{legit_high} events]")

# Normal: events with no anomaly type
normal = len(audit[audit["anomaly_type"].isna()])
normal_pct = (normal / total_audit) * 100
print(f"   Normal activity              : {normal_pct:.1f}% (required: 40-55%) [{normal} events]")

# ── 6. PLATFORM COVERAGE ──
print("\n PLATFORM COVERAGE")
for platform in ["AD", "AWS", "Okta"]:
    count = len(snapshots[snapshots['platform']==platform])
    print(f"   {platform:5s}: {count} records")

# ── 7. PASS/FAIL SUMMARY ──
print("\n" + "=" * 50)
print(" PASS / FAIL SUMMARY")
checks = {
    "Identity count (200-400)"        : 200 <= len(master) <= 400,
    "Audit events (500-1000)"         : 500 <= len(audit) <= 1000,
    "Offboarding records (50-100)"    : 50 <= total_terminated <= 100,
    "Group mappings (100+)"           : len(groups) >= 100,
    "Orphaned accounts (10-15%)"      : 10 <= orphaned_pct <= 15,
    "Over-privileged (8-12%)"         : 8 <= over_priv_pct <= 12,
    "Privilege escalation (5-8%)"     : 5 <= escalation_pct <= 8,
    "Token abuse (3-5%)"              : 3 <= token_pct <= 5,
    "Legitimate high-priv (15-20%)"   : 15 <= legit_pct <= 20,
    "Normal activity (40-55%)"        : 40 <= normal_pct <= 55,
    "All 3 platforms covered"         : len(snapshots["platform"].unique()) == 3,
}

all_pass = True
for check, result in checks.items():
    status = " PASS" if result else " FAIL"
    if not result:
        all_pass = False
    print(f"   {status}  {check}")

print("\n" + (" ALL CHECKS PASSED" if all_pass else "  SOME CHECKS FAILED — fix before engine"))
print("=" * 50)