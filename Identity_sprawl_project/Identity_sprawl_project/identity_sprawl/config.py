from datetime import datetime, timedelta

TODAY = datetime(2026, 6, 21)

IDENTITY_COUNTS = {
    "employees": 300,
    "contractors": 50,
    "service_accounts": 50
}

PLATFORMS = ["AD", "AWS", "Okta"]

ANOMALY_RATES = {
    "offboarding_gap": 0.12,
    "orphaned_admin": 0.10,
    "dormant_admin": 0.08,
    "privilege_escalation": 0.06,
    "stale_token": 0.04,
    "legitimate_high_priv": 0.18
}

SEED = 42