import os
import pandas as pd
from utils.llm_provider import call_llm
from utils.prompt_templates import build_prompt, generate_offline_mock, SYSTEM_PROMPT, get_disclaimer

def get_user_context(username: str) -> dict:
    """Loads all deterministic user details across CSV databases into a single context dict."""
    ctx = {
        "username": "N/A",
        "department": "IT/Ops",
        "identity_type": "User",
        "risk_score": 0,
        "severity": "Low",
        "detected_risks": "None",
        "ad_privilege": "None", "ad_direct": "None", "ad_inherited": "None", "ad_effective": "None",
        "aws_privilege": "None", "aws_direct": "None", "aws_inherited": "None", "aws_effective": "None",
        "okta_privilege": "None", "okta_direct": "None", "okta_inherited": "None", "okta_effective": "None",
        "score_breadth": 0.0, "score_dormancy": 0.0, "score_spread": 0.0, "score_offboarding": 0.0,
        "recommended_action": "No action required.",
        "num_events": 0,
        "last_login": "N/A",
        "inheritance_chain": "Direct Assignment",
        "analyst_context": "None",
        "confidence_level": "High"
    }
    
    if not username:
        # Fallback to the first user in the database if no user is specified
        if os.path.exists("data/unified_identities.csv"):
            try:
                df = pd.read_csv("data/unified_identities.csv")
                if len(df) > 0:
                    username = df.iloc[0]["User Name"]
            except:
                pass
                
    if not username:
        return ctx
        
    ctx["username"] = username
    
    # 1. Load from unified_identities.csv
    if os.path.exists("data/unified_identities.csv"):
        try:
            df = pd.read_csv("data/unified_identities.csv").fillna("None")
            rows = df[df["User Name"] == username]
            if not rows.empty:
                r = rows.iloc[0]
                ctx["department"] = r.get("Department", ctx["department"])
                ctx["identity_type"] = r.get("Identity Type", ctx["identity_type"])
                ctx["risk_score"] = r.get("Risk Score", ctx["risk_score"])
                ctx["severity"] = r.get("Severity", ctx["severity"])
                ctx["detected_risks"] = r.get("Detected Risks", ctx["detected_risks"])
        except Exception:
            pass

    # 2. Load from privilege_matrix.csv
    if os.path.exists("data/privilege_matrix.csv"):
        try:
            df = pd.read_csv("data/privilege_matrix.csv").fillna("None")
            rows = df[df["username"] == username]
            if not rows.empty:
                r = rows.iloc[0]
                ctx["ad_privilege"] = r.get("Active Directory", "None")
                ctx["ad_direct"] = r.get("ad_direct_privilege", "None")
                ctx["ad_inherited"] = r.get("ad_inherited_privilege", "None")
                ctx["ad_effective"] = r.get("ad_effective_privilege", "None")
                
                ctx["aws_privilege"] = r.get("AWS IAM", "None")
                ctx["aws_direct"] = r.get("aws_direct_privilege", "None")
                ctx["aws_inherited"] = r.get("aws_inherited_privilege", "None")
                ctx["aws_effective"] = r.get("aws_effective_privilege", "None")
                
                ctx["okta_privilege"] = r.get("Okta", "None")
                ctx["okta_direct"] = r.get("okta_direct_privilege", "None")
                ctx["okta_inherited"] = r.get("okta_inherited_privilege", "None")
                ctx["okta_effective"] = r.get("okta_effective_privilege", "None")
        except Exception:
            pass

    # 3. Load from risk_results.csv
    if os.path.exists("data/risk_results.csv"):
        try:
            df = pd.read_csv("data/risk_results.csv").fillna("None")
            # We filter out the user records (rows that have 'username' matching)
            rows = df[df["username"] == username]
            if not rows.empty:
                r = rows.iloc[0]
                ctx["score_breadth"] = r.get("privilege_breadth_score", 0.0)
                ctx["score_dormancy"] = r.get("dormancy_score", 0.0)
                ctx["score_spread"] = r.get("platform_spread_score", 0.0)
                ctx["score_offboarding"] = r.get("offboarding_score", 0.0)
                ctx["recommended_action"] = r.get("recommended_action", ctx["recommended_action"])
        except Exception:
            pass

    # 4. Load from incidents.csv (Events list)
    if os.path.exists("data/incidents.csv"):
        try:
            df = pd.read_csv("data/incidents.csv").fillna("None")
            user_evts = df[df["username"] == username]
            ctx["num_events"] = len(user_evts)
            if not user_evts.empty:
                # Sort by timestamp
                user_evts_sorted = user_evts.sort_values(by="event_timestamp", ascending=False)
                ctx["last_login"] = user_evts_sorted.iloc[0].get("event_timestamp", "N/A")
                
                # Fetch custom parameters from first incident matching
                first_inc = user_evts.iloc[0]
                ctx["inheritance_chain"] = first_inc.get("inheritance_chain", ctx["inheritance_chain"])
                ctx["analyst_context"] = first_inc.get("analyst_context", ctx["analyst_context"])
                ctx["confidence_level"] = first_inc.get("confidence_level", ctx["confidence_level"])
        except Exception:
            pass

    return ctx

def query_copilot(username: str, action: str, user_query: str = "") -> str:
    """Executes prompt actions. Calls active API models or falls back to template-based offline mock outputs."""
    context = get_user_context(username)
    
    # Check if there is an active API connection
    prompt = build_prompt(action, context, user_query)
    response = call_llm(prompt, SYSTEM_PROMPT)
    
    if response is None:
        # Fall back to offline mock mode
        response = generate_offline_mock(action, context, user_query)
        
    # Ensure disclaimer is appended exactly once
    disclaimer = get_disclaimer().strip()
    if disclaimer not in response:
        response += "\n\n" + disclaimer
        
    return response
