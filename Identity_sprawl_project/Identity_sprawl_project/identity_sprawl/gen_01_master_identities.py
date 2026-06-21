import pandas as pd
import random
from faker import Faker
from config import IDENTITY_COUNTS, SEED, TODAY
from datetime import timedelta

fake = Faker()
random.seed(SEED)
Faker.seed(SEED)

records = []
identity_id = 1

# Employees
for _ in range(IDENTITY_COUNTS["employees"]):
    name = fake.name()
    dept = random.choice(["Engineering", "Finance", "HR", "IT", "Sales", "Legal"])
    hire_date = TODAY - timedelta(days=random.randint(180, 3000))
    terminated = random.random() < 0.12
    term_date = hire_date + timedelta(days=random.randint(100, 1000)) if terminated else None
    
    # Randomly assign a role change date between hire date and termination/today
    has_role_change = random.random() < 0.25
    if has_role_change:
        end_limit = term_date if terminated else TODAY
        days_diff = (end_limit - hire_date).days
        role_change_date = hire_date + timedelta(days=random.randint(1, max(1, days_diff - 1)))
    else:
        role_change_date = None

    records.append({
        "identity_id": f"ID{identity_id:04d}",
        "name": name,
        "email": fake.company_email(),
        "type": "employee",
        "department": dept,
        "hire_date": hire_date.date(),
        "termination_date": term_date.date() if term_date else None,
        "is_terminated": terminated,
        "last_role_change_date": role_change_date.date() if role_change_date else None,
    })
    identity_id += 1

# Contractors
for _ in range(IDENTITY_COUNTS["contractors"]):
    name = fake.name()
    hire_date = TODAY - timedelta(days=random.randint(30, 730))
    terminated = random.random() < 0.40
    term_date = hire_date + timedelta(days=random.randint(30, 365)) if terminated else None
    records.append({
        "identity_id": f"ID{identity_id:04d}",
        "name": name,
        "email": fake.free_email(),
        "type": "contractor",
        "department": "External",
        "hire_date": hire_date.date(),
        "termination_date": term_date.date() if term_date else None,
        "is_terminated": terminated,
        "manager": f"ID{random.randint(1, 50):04d}"
    })
    identity_id += 1

# Service Accounts
for i in range(IDENTITY_COUNTS["service_accounts"]):
    created = TODAY - timedelta(days=random.randint(90, 1800))
    records.append({
        "identity_id": f"ID{identity_id:04d}",
        "name": f"svc-{fake.word()}-{random.choice(['prod','dev','test'])}",
        "email": None,
        "type": "service_account",
        "department": random.choice(["IT", "Engineering"]),
        "hire_date": created.date(),
        "termination_date": None,
        "is_terminated": False,
        "manager": f"ID{random.randint(1, 50):04d}"
    })
    identity_id += 1

df = pd.DataFrame(records)
df.to_csv("data/master_identities.csv", index=False)
print(f" Generated {len(df)} identities -> data/master_identities.csv")