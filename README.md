# Guardrail IAM Console & Identity Sprawl Detection Engine

An advanced hybrid enterprise risk governance and threat monitoring solution designed to identify identity sprawl, track privileged access abuse, detect offboarding security gaps, and automate security analyst workflows using an integrated Identity Security Copilot.

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

