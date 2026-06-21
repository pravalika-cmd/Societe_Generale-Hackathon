import pandas as pd
import random
from config import SEED, TODAY
from datetime import timedelta

random.seed(SEED)

master = pd.read_csv("data/master_identities.csv")
snapshots = pd.read_csv("data/platform_snapshots.csv")

terminated = master[master["is_terminated"] == True].copy()
records = []

for _, row in terminated.iterrows():
    iid = row["identity_id"]
    term_date = row["termination_date"]

    user_snapshots = snapshots[snapshots["identity_id"] == iid]

    for _, snap in user_snapshots.iterrows():
        platform_status = snap["status"]
        disabled_in_platform = platform_status in ["disabled", "suspended", "not_applicable"]

        records.append({
            "identity_id": iid,
            "name": row["name"],
            "termination_date": term_date,
            "platform": snap["platform"],
            "platform_status": platform_status,
            "disabled_in_platform": disabled_in_platform,
            "offboarding_gap": not disabled_in_platform,
            "days_since_termination": (TODAY - pd.to_datetime(term_date)).days if term_date else None,
            "risk_flag": "CRITICAL" if not disabled_in_platform else None
        })

df = pd.DataFrame(records)
df.to_csv("data/offboarding_records.csv", index=False)
print(f"[OK] Generated {len(df)} offboarding records -> data/offboarding_records.csv")