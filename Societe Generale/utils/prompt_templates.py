import datetime

SYSTEM_PROMPT = """You are Identity Security Copilot, an enterprise-grade AI assistant designed for security analysts.
Your purpose is to augment analyst investigations by providing explainable narratives, remediation steps, risk score analysis, compliance mappings, and audit notes.

CRITICAL RULES:
1. You act ONLY as an analyst advisor. You must NEVER modify risk scores, detect anomalies independently, or execute remediation actions.
2. Rely strictly on the deterministic data provided in the security context.
3. If the user asks general questions outside of identity access management or the active security context, politely redirect them back to the identity under investigation.
4. Always display the mandatory governance disclaimer at the very end of your response.
"""

def get_disclaimer() -> str:
    return "\n\n***\n*Disclaimer: Identity Security Copilot augments analyst investigations using contextual explanations and recommendations. All risk findings originate from deterministic detection logic.*"

def build_context_text(context: dict) -> str:
    """Helper to convert context dictionary into a formatted string block for LLM prompts."""
    return f"""--- IDENTITY SECURITY CONTEXT ---
Username: {context.get('username')}
Department: {context.get('department')}
Identity Type: {context.get('identity_type')}
Risk Score: {context.get('risk_score')} / 100
Severity: {context.get('severity')}
Detected Risks: {context.get('detected_risks')}

PLATFORM PRIVILEGES:
- Active Directory:
  * Assigned: {context.get('ad_privilege')}
  * Direct: {context.get('ad_direct')}
  * Inherited: {context.get('ad_inherited')}
  * Effective: {context.get('ad_effective')}
- AWS IAM:
  * Assigned: {context.get('aws_privilege')}
  * Direct: {context.get('aws_direct')}
  * Inherited: {context.get('aws_inherited')}
  * Effective: {context.get('aws_effective')}
- Okta:
  * Assigned: {context.get('okta_privilege')}
  * Direct: {context.get('okta_direct')}
  * Inherited: {context.get('okta_inherited')}
  * Effective: {context.get('okta_effective')}

RISK BREAKDOWN METRICS:
- Privilege Breadth Score: {context.get('score_breadth')}
- Dormancy/Inactivity Score: {context.get('score_dormancy')}
- Platform Spread Score: {context.get('score_spread')}
- Offboarding Lapse Score: {context.get('score_offboarding')}
- Recommended Action: {context.get('recommended_action')}

FORENSIC EVIDENCE & RECENT INCIDENTS:
Total Alerts Correlated: {context.get('num_events')}
Last Logged Activity: {context.get('last_login')}
Inheritance Group Chain: {context.get('inheritance_chain')}
Analyst Context: {context.get('analyst_context')}
Engine Confidence Level: {context.get('confidence_level')}
---------------------------------"""

def build_prompt(action: str, context: dict, user_query: str = "") -> str:
    ctx_text = build_context_text(context)
    if action == "Explain Incident":
        return f"{ctx_text}\n\nTask: Explain the security incident and overall risk profile for this identity. Discuss the potential security impact and why this user is flagged."
    elif action == "Recommend Remediation":
        return f"{ctx_text}\n\nTask: Provide platform-specific remediation guidance (PowerShell, AWS CLI, Okta API) to neutralize the security gaps identified for this user."
    elif action == "Explain Risk Score":
        return f"{ctx_text}\n\nTask: Explain the math and factors contributing to this identity's risk score. Break down the breadth, inactivity, spread, and offboarding scores."
    elif action == "Compliance Mapping":
        return f"{ctx_text}\n\nTask: Map the findings for this identity to regulatory and control frameworks (NIST SP 800-53, MITRE ATT&CK, GDPR, and CIS Controls) and explain why each applies."
    elif action == "Executive Summary":
        return f"{ctx_text}\n\nTask: Generate an executive summary of these security findings for corporate leadership. Focus on business impact, risk exposure, and high-level priorities. Avoid technical jargon."
    elif action == "Draft Audit Note":
        return f"{ctx_text}\n\nTask: Draft a formal, detailed audit note document mapping controls failures, evidence, and remediation steps suitable for compliance auditors."
    elif action == "Alert Consolidation":
        return f"{ctx_text}\n\nTask: Explain how and why the various multi-platform alerts were correlated and consolidated into a single incident for this user."
    else:
        return f"{ctx_text}\n\nUser Query: {user_query}\n\nTask: Answer the analyst's question based on the security context provided. Do not invent details outside of this context."

def generate_offline_mock(action: str, context: dict, user_query: str = "") -> str:
    """Generates dynamic, context-rich offline analyst reports when LLM APIs are not configured."""
    username = context.get('username', 'N/A')
    dept = context.get('department', 'N/A')
    score = context.get('risk_score', 0)
    sev = context.get('severity', 'N/A')
    risks_str = context.get('detected_risks', 'None')
    risks = [r.strip() for r in risks_str.split(",")]
    
    ad_eff = context.get('ad_effective', 'None')
    aws_eff = context.get('aws_effective', 'None')
    okta_eff = context.get('okta_effective', 'None')
    
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. EXPLAIN INCIDENT Mock Response
    if action == "Explain Incident":
        res = f"### Forensic Incident Narrative: {username}\n\n"
        res += f"**Risk Posture:** {sev} (Risk Score: {score}/100) | **Department:** {dept}\n\n"
        res += "#### Threat Analysis Summary:\n"
        res += f"The identity security engine has flagged **{username}** due to critical threat factors: *{risks_str}*.\n\n"
        
        for r in risks:
            if r == "Hidden Admin":
                res += f"- **Nested Privilege Abuse (Hidden Admin):** The user inherits administrative rights indirectly. In Active Directory, they have effective access to `{ad_eff}`. Because this privilege is not directly assigned, standard active checks failed to audit this path, creating a blind spot.\n"
            elif r == "Offboarding Gap":
                res += f"- **Offboarding Access Loophole:** The primary directory status for {username} is marked as disabled or terminated, but active credentials and active sessions remain open on downstream platforms: AWS Effective Access is `{aws_eff}` and Okta Access is `{okta_eff}`. This creates an unmonitored backdoor.\n"
            elif r == "Dormant Admin":
                res += f"- **Dormant Privilege Risk:** The user possesses elevated administrative access (`{ad_eff}` / `{aws_eff}` / `{okta_eff}`) but has not registered login activity for an extended period. Stale admin credentials are primary targets for credential harvesting and reuse.\n"
            elif r == "Token Abuse":
                res += "- **Exposed Session Tokens:** Detection of long-lived access tokens (exceeding standard rotation policy thresholds) combined with API session usage outside normal business hours suggests potential credential leakage or token hijacking.\n"
            elif r == "Privilege Spike":
                res += "- **Temporary Access Escalation:** An unapproved spike in access permissions was observed, exceeding baseline privilege requirements without a corresponding ITSM service ticket.\n"
                
        res += f"\n#### Forensics Evidence:\n"
        res += f"- **Console Log Correlation:** The engine consolidated `{context.get('num_events')}` distinct cross-platform alerts.\n"
        res += f"- **Engine Confidence:** `{context.get('confidence_level')}`\n"
        res += f"- **Last Recorded Activity:** `{context.get('last_login')}`\n"
        res += f"- **Analyst Note:** \"{context.get('analyst_context')}\"\n\n"
        res += "#### Security Impact:\n"
        res += "If unremediated, this identity posture allows attackers who compromise these credentials to move laterally across directories (Active Directory) to cloud infrastructure (AWS) and SaaS platforms (Okta), bypassing standard termination checks."
        return res + get_disclaimer()

    # 2. RECOMMEND REMEDIATION Mock Response
    elif action == "Recommend Remediation":
        res = f"### Remediation Action Plan: {username}\n\n"
        res += "The following platform-specific commands and actions must be executed to neutralize risk vectors:\n\n"
        
        has_action = False
        for r in risks:
            if r == "Hidden Admin":
                has_action = True
                res += "#### Active Directory (Nested Privilege Resolution):\n"
                res += "- **Action:** Remove the user from the nested group providing the inheritance path.\n"
                res += f"- **Inheritance Chain:** `{context.get('inheritance_chain')}`\n"
                res += f"- **PowerShell Command:**\n"
                res += f"  ```powershell\n  Remove-ADGroupMember -Identity \"{context.get('ad_inherited')}\" -Members \"{username}\"\n  ```\n\n"
            elif r == "Offboarding Gap":
                has_action = True
                res += "#### Cloud & SaaS Access Deprovisioning:\n"
                res += "- **AWS IAM Action:** Detach active policies and revoke security credentials immediately.\n"
                res += "  ```bash\n  aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name " + username + "\n"
                res += "  aws iam delete-login-profile --user-name " + username + "\n  ```\n"
                res += "- **Okta Action:** Deactivate the user lifecycle account via administrative API request:\n"
                res += "  ```http\n  POST /api/v1/users/" + username + "/lifecycle/deactivate HTTP/1.1\n"
                res += "  Host: corporate.okta.com\n"
                res += "  Authorization: SSWS <api_token>\n  ```\n\n"
            elif r == "Dormant Admin":
                has_action = True
                res += "#### Privilege Minimization (Dormant Access):\n"
                res += "- **AWS IAM Action:** Detach high-privilege administrative access policies.\n"
                res += "  ```bash\n  aws iam detach-user-policy --user-name " + username + " --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n  ```\n"
                res += "- **Active Directory Action:** Move user to a low-privileged read-only role or disable group membership:\n"
                res += "  ```powershell\n  Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"" + username + "\"\n  ```\n\n"
            elif r == "Token Abuse":
                has_action = True
                res += "#### Session & Token Invalidation:\n"
                res += "- **AWS Action:** Force access key rotation and invalidate active console sessions.\n"
                res += "  ```bash\n  aws iam delete-access-key --access-key-id <EXPOSED_KEY_ID> --user-name " + username + "\n"
                res += "  aws iam create-access-key --user-name " + username + "\n  ```\n"
                res += "- **Okta Action:** Clear all active browser sessions and force MFA re-enrollment.\n"
                res += "  ```bash\n  curl -X DELETE \"https://corporate.okta.com/api/v1/users/" + username + "/sessions\"\n  ```\n\n"

        if not has_action:
            res += "#### General Access Hygiene:\n"
            res += f"- **Action:** Conduct an access review of the privileges assigned to {username}.\n"
            res += f"- **Recommended Steps:** Validate the `{context.get('recommended_action')}` instruction with the user's supervisor.\n\n"
            
        res += "#### Verification Checklist:\n"
        res += "1. [ ] Run directory sync to ensure AWS/Okta states are updated.\n"
        res += "2. [ ] Validate that all active authentication tokens have been terminated.\n"
        res += "3. [ ] Confirm threat alerts are cleared in the SOC SIEM console."
        return res + get_disclaimer()

    # 3. EXPLAIN RISK SCORE Mock Response
    elif action == "Explain Risk Score":
        res = f"### Risk Score Breakdown: {username}\n\n"
        res += f"**Aggregated Risk Score:** {score} / 100\n\n"
        res += "The overall risk score is calculated dynamically based on four independent risk vectors:\n\n"
        res += f"1. **Privilege Breadth ({context.get('score_breadth')} points):** Measures the absolute number of privileges and roles assigned. Admin permissions across multiple platforms heavily weight this component.\n"
        res += f"2. **Dormancy Factor ({context.get('score_dormancy')} points):** Penalty points applied for inactivity. Gaps between logins create high vulnerability windows for unmonitored abuse.\n"
        res += f"3. **Platform Spread ({context.get('score_spread')} points):** Points representing the user's cross-platform sprawl (Active Directory, AWS, Okta). Spanning multiple identity directories increases key exposure vectors.\n"
        res += f"4. **Offboarding Failure ({context.get('score_offboarding')} points):** Added directly when an account is disabled in AD but active on cloud systems, creating an immediate compliance failure.\n\n"
        res += "#### Score Calculation Logic:\n"
        res += f"$$Risk\\_Score = Breadth\\ ({context.get('score_breadth')}) + Inactivity\\ ({context.get('score_dormancy')}) + Spread\\ ({context.get('score_spread')}) + Offboarding\\ ({context.get('score_offboarding')})$$\n\n"
        res += "This calculation isolates high-impact anomalies (e.g. active admins on cloud who are disabled in HR systems) and flags them for priority SOC investigation."
        return res + get_disclaimer()

    # 4. COMPLIANCE MAPPING Mock Response
    elif action == "Compliance Mapping":
        res = f"### Governance & Compliance Framework Mapping: {username}\n\n"
        res += "The detected anomalies violate several corporate compliance controls and security standards:\n\n"
        
        res += "#### NIST SP 800-53 (Revision 5) Controls:\n"
        res += "- **AC-2 (Account Management):** Failure to terminate accounts during offboarding directly violates AC-2(3) (Disable Accounts).\n"
        res += "- **AC-6 (Least Privilege):** Elevation of effective access through group nesting bypasses least-privilege review controls.\n"
        res += "- **IA-4 (Identifier Management):** Service accounts and static API tokens must be uniquely managed and rotated periodically.\n\n"
        
        res += "#### MITRE ATT&CK Mapping:\n"
        res += "- **T1078 (Valid Accounts):** Attackers leveraging dormant or un-deprovisioned accounts to bypass MFA or defensive detection engines.\n"
        res += "- **T1098 (Account Manipulation):** Unapproved privilege spikes or group modifications to establish persistence.\n"
        res += "- **T1550 (Use Alternate Authentication Material):** Exploitation of long-lived, unrotated API tokens to query cloud instances.\n\n"
        
        res += "#### GDPR (General Data Protection Regulation):\n"
        res += "- **Article 5 (1)(f) (Security Integrity):** Failure to properly restrict access violates the requirement to secure personal data against unauthorized processing.\n"
        res += "- **Article 32 (Security of Processing):** Lack of automated offboarding and static token management exposes networks to unauthorized penetration.\n\n"
        
        res += "#### CIS Critical Security Controls:\n"
        res += "- **Control 5 (Account Management):** Establish and maintain an inventory of accounts (identifying inactive and orphaned items).\n"
        res += "- **Control 6 (Access Control Management):** Implement access rights mapping to role baselines and enforce least-privilege principles."
        return res + get_disclaimer()

    # 5. EXECUTIVE SUMMARY Mock Response
    elif action == "Executive Summary":
        res = f"### Executive Summary: Identity Exposure Report ({username})\n\n"
        res += f"**Subject:** {username} | **Department:** {dept} | **Criticality:** {sev}\n\n"
        res += "**Business Impact Summary:**\n"
        res += f"An audit of corporate identity systems has identified a high-risk security posture on the account assigned to **{username}** in the **{dept}** department. "
        res += f"The detection system has flagged the account with a severity score of `{score}/100`. The root vulnerability involves "
        
        if "Offboarding Gap" in risks_str:
            res += "orphaned access, where a departed user remains active on AWS and Okta cloud environments despite being terminated in the corporate directory. "
        elif "Hidden Admin" in risks_str:
            res += "nested access paths, enabling the user to inherit administrative privileges without authorization, which creates audit evasion risks. "
        else:
            res += "over-privileged, dormant accounts representing significant security debt. "
            
        res += "\n\n**Financial & Operational Risk Exposure:**\n"
        res += "- **Data Compromise Risk:** Unauthorized access to Okta resources could expose customer directories and private database tables.\n"
        res += "- **Infrastructure Damage:** AWS administrative access enables resource destruction, ransom campaigns, or computing resource hijacking.\n"
        res += "- **Regulatory Fine Exposure:** Non-compliance with GDPR Article 32 and SOC 2 identity governance audits may result in corporate penalties.\n\n"
        res += "**Immediate Business Recommendations:**\n"
        res += "1. Enforce automated downstream deprovisioning workflows across IT systems.\n"
        res += "2. Conduct a quarterly review of nested directories to eliminate privilege inheritance loops."
        return res + get_disclaimer()

    # 6. DRAFT AUDIT NOTE Mock Response
    elif action == "Draft Audit Note":
        res = f"### Compliance Audit Record: {username}\n"
        res += f"**Generated:** {now_str} | **Auditor Reference:** AUD-ID-{username.replace('.', '-')}\n"
        res += "------------------------------------------------------------\n\n"
        res += "#### 1. Identity Evaluated\n"
        res += f"- **Target Username:** `{username}`\n"
        res += f"- **Department Assigned:** `{dept}`\n"
        res += f"- **Active Directory Status:** `{context.get('ad_privilege')}`\n"
        res += f"- **AWS IAM Active Privilege:** `{context.get('aws_privilege')}`\n"
        res += f"- **Okta Active Privilege:** `{context.get('okta_privilege')}`\n\n"
        
        res += "#### 2. Audit Findings & Non-Compliance Items\n"
        res += f"The audit engine flags the following non-compliance issues:\n"
        res += f"- **Finding:** {risks_str}\n"
        res += f"- **Effective Privileges Found:** AD=`{ad_eff}`, AWS=`{aws_eff}`, Okta=`{okta_eff}`\n"
        res += f"- **Audit Trail Evidence:** Inactivity length, unrotated session tokens, and lack of offboarding correlation.\n\n"
        
        res += "#### 3. Control Failure Analysis\n"
        res += "- **Control Standard:** SOC 2 CC6.3 (Access Modification/Revocation)\n"
        res += "- **Observation:** Accounts are not revoked consistently upon status change.\n"
        res += "- **Control Standard:** ISO 27001 A.9.2.6 (Removal or adjustment of access rights)\n"
        res += "- **Observation:** Downstream privilege mappings fail to synchronize termination events.\n\n"
        
        res += "#### 4. Remediation Commitment Plan\n"
        res += "- **Action Required:** Revoke downstream tokens, isolate AD membership, and enforce strict API key timeouts.\n"
        res += f"- **Remediation SLA:** 2 Hours (Critical Priority)\n"
        res += "- **Signed Auditor Copy:** Pending SOC confirmation"
        return res + get_disclaimer()

    # 7. ALERT CONSOLIDATION Mock Response
    elif action == "Alert Consolidation":
        res = f"### Alert Consolidation Report: {username}\n\n"
        res += f"**Consolidated Alerts:** {context.get('num_events')} events correlated into 1 Incident\n\n"
        res += "#### Correlation Logic:\n"
        res += f"Security events were correlated under the identity **{username}** using key binding variables across platforms:\n"
        res += f"- **Identity Binding:** Okta username `{username}` matches AD directory logins and AWS IAM user name.\n"
        res += f"- **Time Context Correlation:** Anomalies occurred in temporal proximity, suggesting a unified pattern of threat activity.\n\n"
        res += "#### Correlated Alerts:\n"
        res += "- **Active Directory:** Privilege elevation patterns or un-deprovisioned access attempts.\n"
        res += "- **AWS IAM:** API calls utilizing unrotated access tokens.\n"
        res += "- **Okta:** Login attempts originating from foreign IP addresses and unapproved devices.\n\n"
        res += "#### Consolidation Value:\n"
        res += f"By consolidating `{context.get('num_events')}` separate alerts into a single incident pane, alert fatigue for SOC analysts is reduced by **{(1.0 - 1.0/float(context.get('num_events', 2)))*100.0:.1f}%**, streamlining triaging and investigation."
        return res + get_disclaimer()

    # 8. GENERAL USER QUERY Mock Response
    else:
        # Simple query parser for common terms
        query_lower = user_query.lower()
        if "remediate" in query_lower or "fix" in query_lower or "solve" in query_lower:
            return generate_offline_mock("Recommend Remediation", context)
        elif "compliance" in query_lower or "standards" in query_lower or "nist" in query_lower:
            return generate_offline_mock("Compliance Mapping", context)
        elif "score" in query_lower or "calculate" in query_lower or "math" in query_lower:
            return generate_offline_mock("Explain Risk Score", context)
        elif "executive" in query_lower or "summary" in query_lower or "business" in query_lower:
            return generate_offline_mock("Executive Summary", context)
        elif "audit" in query_lower or "report" in query_lower:
            return generate_offline_mock("Draft Audit Note", context)
        else:
            res = f"### Analyst Copilot Search Response\n\n"
            res += f"Hello, I am reviewing the context for user **{username}** (Department: {dept}, Risk Score: {score}).\n\n"
            res += f"To help with your investigation of **{risks_str}**, you can click any of the quick-action prompts above to generate specific reports or provide more details on what you'd like to investigate."
            return res + get_disclaimer()
