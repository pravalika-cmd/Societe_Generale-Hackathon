# 🛡️ Guardrail IAM Console
### Identity Sprawl & Privileged Access Abuse Detection Engine for Hybrid Enterprises

![Track](https://img.shields.io/badge/Track-Identity_%26_Access_Risk_Governance-blue)
![Team](https://img.shields.io/badge/Team-PI_%7C_RVCE_College-green)
![Python](https://img.shields.io/badge/Python-3.10%2B-purple)

> *"When a service account is granted Domain Admin in AD and simultaneously given S3 full-access in AWS, the risk is invisible to both teams."* — Problem Statement

Guardrail is our answer to that problem. A full-stack identity risk platform that correlates identities across Active Directory, AWS IAM, and Okta — computing effective privilege through nested group inheritance, scoring risk with an explainable rule engine aligned to MITRE ATT&CK, and surfacing findings through an analyst-grade investigation console with an AI-powered Security Copilot.

---

## ⚡ What Makes This Different

Most identity tools flag individual platform anomalies. Guardrail finds the risks that only appear when you look across all three platforms simultaneously.

- **Nested group inheritance traversal** — detects "hidden admins" whose direct assignment looks standard but whose effective privilege is Domain Admin through 2–3 levels of group nesting. 28 such cases detected in our dataset.
- **Cross-platform unjustified admin detection** — flags identities with admin on 2+ platforms with no recorded business justification, distinct from legitimately privileged users. Exactly 40 flagged vs 95 total cross-platform admins — the distinction between signal and noise.
- **Independent platform offboarding gaps** — each platform's disable status tracked separately, catching the real-world pattern where AD is disabled but Okta/AWS remain active.
- **Explainable scoring, not a black box** — every risk score decomposes into named rules, each citing a MITRE ATT&CK technique, a NIST SP 800-53 control, and a platform-specific remediation command.
- **AI Security Copilot** — powered by Claude, with real backend context injected per query, generating incident narratives, audit notes, and remediation runbooks on demand.

---
## ⚙️ System Architecture & Data Flow

The project consists of a multi-stage Python data generation/analysis pipeline and a Dash dashboard visualizer. Below is the system flow depicting the pipeline steps and the risk engine correlation process.

![System Architecture & Data Flow Diagram](images/architecture_diagram.png)

---

## 📁 Repository Structure

The project is split into two primary components: the data pipeline (backend) and the visual console (frontend).

```
SG_Hackathon/
├── Identity_sprawl_project/       # Backend Risk Analysis Pipeline
│   └── Identity_sprawl_project/
│       └── identity_sprawl/
│           ├── engine/            # Privilege calculations & risk scoring engines
│           ├── data/              # Simulated platform snapshots & audit logs
│           ├── outputs/           # Processed correlation and anomaly outputs
│           ├── run_pipeline.py    # Main script to run the generation & analysis pipeline
│           └── requirements.txt   # Backend dependencies
│
└── Societe Generale/              # Frontend Dashboard & Analyst Console
    ├── app.py                     # Dash application entry point
    ├── pages/                     # Console page layouts & callback logic
    │   ├── executive_summary.py
    │   ├── identity_risk_list.py
    │   ├── cross_platform_privilege.py
    │   ├── offboarding_detector.py
    │   ├── dormancy_analysis.py
    │   ├── incident_drilldown.py
    │   └── risk_reports.py
    ├── utils/                     # Data adaptation, LLM, and prompt utilities
    ├── assets/                    # Styling sheets & static assets
    └── requirements.txt           # Dashboard dependencies
```

## 📊 Results on Simulated Enterprise Data

| Metric | Value |
|---|---|
| Identities assessed | 400 across AD, AWS IAM, Okta |
| Identity coverage | 100% — no identity falls through |
| CRITICAL risk identities | 41 (10.3%) |
| HIGH risk identities | 61 (15.3%) |
| Hidden admin paths detected | 28 via nested group traversal |
| Unjustified cross-platform admins | 40 out of 95 total cross-platform admins |
| Offboarding gaps surfaced | 49 terminated identities still active on ≥1 platform |
| Total anomalies with remediation | 299 structured findings across 8 rule types |
| Alert consolidation | 860 raw events → 299 structured findings (65% reduction) |

---
## 🧠 Risk Engine — 8 Scoring Rules

| Rule | Condition | Points | MITRE | NIST |
|---|---|---|---|---|
| 1. Offboarding Gap | Terminated but active on any platform | +40 | T1078 | AC-2 |
| 2. Dormant Admin | Admin + no login 90+ days | +35 | T1078 | AC-2, AC-6 |
| 3. Unjustified Cross-Platform Admin | Admin on 2+ platforms, no justification | +30 | T1098 | AC-6 |
| 4. Hidden/Inherited Admin | Admin via nested group traversal only | +25 | T1098 | AC-6 |
| 5. Stale API Token | AWS key > 365 days, still active | +20 | T1550 | IA-4 |
| 6. Privilege Escalation | Unexpected group-addition in audit log | +35 | T1098 | AC-2 |
| 7. Dormant Admin + HR Role Change | Inactive 90d + role changed within 60d | +15 | AC-2 | AC-2 |
| 8. Token Scope Mismatch | Read-only token making write API calls | +30 | T1550 | AC-6 |
| Dampener | IT dept + admin = expected role | −15 | — | — |

Score 0–100, capped. Bands: **CRITICAL ≥60 / HIGH ≥40 / MEDIUM ≥20 / LOW <20**

Every triggered rule writes a row to `anomalies.csv` with severity, human-readable detail, MITRE citation, and platform-specific remediation — making every score fully auditable.

---


## 🖥️ Console Screen Previews

Here is a look at the Guardrail IAM Console in action:

### 1. Executive Summary
Provides a high-level visual posture of global risks, active directory/cloud threats, and SOC system integrity status.
![Executive Summary Dashboard](images/executive_summary.png)

### 2. Identity Risk List
Searchable registry of all monitored enterprise identities, displaying threat severity, detected risks, and risk scores.
![Identity Risk List](images/identity_risk_list.png)

### 3. Cross-Platform Privilege View
Maps direct and inherited privilege paths to resolve effective permissions across Active Directory, Okta, and AWS IAM.
![Cross-Platform Privilege View](images/privilege_matrix.png)

### 4. Offboarding Gap Detector
Identifies terminated employees with lingering active cloud platform sessions, calculating real-time security exposure windows.
![Offboarding Gap Detector](images/offboarding_detector.png)

### 5. Dormancy Analysis
Flags stale login tokens, inactive API keys, and dormant admin accounts requiring credential rotation or de-provisioning.
![Dormancy Analysis](images/dormancy_analysis.png)

---

## 🌟 Key Features

1. **Executive Summary Dashboard**: Visualizes global risk postures, system health states, and critical threat counts across AD, Okta, and AWS IAM.
2. **Cross-Platform Privilege View**: Traces identity privileges from direct assignments to nested inheritance chains, mapping effective access.
3. **Offboarding Gap Detector**: Identifies terminated users with lingering active accounts, calculating cumulative security exposure days.
4. **Dormancy Analysis**: Flags high-privileged admin accounts and static API keys that have not authenticated recently.
5. **Incident Drilldown**: Generates structured audit trails with context and MITRE ATT&CK framework mapping for triggered alerts.
6. **Identity Security Copilot**: An LLM-powered AI chat assistant that drafts audit notes, recommends remediation plans, and summarizes active incidents for security analysts.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Run the Backend Pipeline (Optional)
To regenerate/re-correlate the simulated data:
```bash
# Navigate to the backend directory
cd "Identity_sprawl_project/Identity_sprawl_project/identity_sprawl"

# Install backend dependencies
pip install -r requirements.txt

# Run the data generation and analysis pipeline
python run_pipeline.py
```

### 2. Run the Dashboard Frontend
To start the Guardrail IAM visual console:
```bash
# Navigate to the frontend directory
cd "Societe Generale"

# Install frontend dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Open [http://127.0.0.1:8050/](http://127.0.0.1:8050/) in your web browser to view the console.

---

## 🛡️ Security & Compliance
This console helps security teams ensure compliance with key security controls:
* **CIS Controls**: Access Control Management, Account Monitoring.
* **ISO 27001**: Annex A.9 (Access Control).
* **SOX / SOC 2**: Privilege access reviews and user termination verification.

