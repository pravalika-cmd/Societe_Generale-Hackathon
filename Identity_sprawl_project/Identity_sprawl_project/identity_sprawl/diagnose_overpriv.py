import pandas as pd

master = pd.read_csv("data/master_identities.csv")
snapshots = pd.read_csv("data/platform_snapshots.csv")

print("Columns in snapshots:", list(snapshots.columns))
print()

# How many rows actually have admin_justified == True, broken down by platform
if "admin_justified" in snapshots.columns:
    print("admin_justified value counts by platform:")
    print(snapshots.groupby("platform")["admin_justified"].apply(lambda x: x.value_counts().to_dict()))
else:
    print("!! admin_justified column MISSING from platform_snapshots.csv entirely !!")
print()

# Admin counts per identity across platforms
admin_rows = snapshots[snapshots["privilege_level"] == "admin"]
admin_counts = admin_rows.groupby("identity_id")["platform"].nunique()
cross_platform_admin_ids = set(admin_counts[admin_counts >= 2].index)
print(f"Identities with admin on 2+ platforms: {len(cross_platform_admin_ids)}")

# Justified ids per current validator logic
if "admin_justified" in snapshots.columns:
    justified_ids = set(snapshots[snapshots["admin_justified"] == True]["identity_id"])
else:
    justified_ids = set()
print(f"Identities marked admin_justified=True (any platform row): {len(justified_ids)}")

over_priv_ids = cross_platform_admin_ids - justified_ids
print(f"Cross-platform admin MINUS justified = {len(over_priv_ids)}  <-- this should match your validator's 78")
print()

# For the unjustified ones, show which platforms they're admin on
print("Sample of 10 unjustified cross-platform admins, with their admin platforms and department:")
sample_ids = list(over_priv_ids)[:10]
for iid in sample_ids:
    plats = sorted(admin_rows[admin_rows["identity_id"] == iid]["platform"].tolist())
    dept = master[master["identity_id"] == iid]["department"].values
    itype = master[master["identity_id"] == iid]["type"].values
    dept = dept[0] if len(dept) else "?"
    itype = itype[0] if len(itype) else "?"
    print(f"  {iid}  admin_on={plats}  dept={dept}  type={itype}")