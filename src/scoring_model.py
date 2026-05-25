from datetime import datetime, timezone

def calculate_reputation_score(abuseipdb_data):
    """
    Calculate reputation score (0-1) based on AbuseIPDB data
    Factors: confidence score, total reports, recency
    """
    confidence = abuseipdb_data.get("abuse_confidence_score", 0) / 100
    
    # Normalize reports (cap at 100 for scoring)
    reports = min(abuseipdb_data.get("total_reports", 0), 100) / 100
    
    # Indicator age decay
    last_reported = abuseipdb_data.get("last_reported")
    age_factor = 1.0
    if last_reported:
        try:
            last_date = datetime.fromisoformat(
                last_reported.replace("Z", "+00:00")
            )
            days_old = (datetime.now(timezone.utc) - last_date).days
            # Decay over 90 days
            age_factor = max(0, 1 - (days_old / 90))
        except:
            age_factor = 0.5
    
    reputation = (confidence * 0.5) + (reports * 0.3) + (age_factor * 0.2)
    return round(min(reputation, 1.0), 3)

def calculate_relevance_score(abuseipdb_data, otx_data, alert_data):
    """
    Calculate relevance score (0-1) based on:
    - Education sector targeting
    - OTX pulse count
    - Alert signature severity
    """
    relevance = 0.0
    
    # OTX pulse count (more pulses = more relevant threat)
    pulse_count = otx_data.get("pulse_count", 0)
    pulse_score = min(pulse_count / 10, 1.0)
    relevance += pulse_score * 0.4
    
    # Alert severity from Suricata
    severity = alert_data.get("alert", {}).get("severity", 3)
    severity_score = (4 - severity) / 3  # Convert 1-3 to 0-1 (1=high)
    relevance += severity_score * 0.4
    
    # Usage type relevance
    usage_type = abuseipdb_data.get("usage_type", "").lower()
    if any(term in usage_type for term in ["datacenter", "hosting", "vpn"]):
        relevance += 0.2
    
    return round(min(relevance, 1.0), 3)

def calculate_recurrence_score(src_ip, alert_history):
    """
    Calculate recurrence score (0-1) based on
    how often this IP has appeared in recent alerts
    """
    count = alert_history.get(src_ip, 0)
    # Normalize: 10+ occurrences = max score
    recurrence = min(count / 10, 1.0)
    return round(recurrence, 3)

def calculate_final_severity(reputation, relevance, recurrence):
    """
    Final severity score using formula:
    Severity = reputation x relevance x recurrence
    Scaled to 0-5 range
    """
    # Weighted combination
    raw_score = (reputation * 0.5) + (relevance * 0.3) + (recurrence * 0.2)
    
    # Scale to 0-5
    final_score = raw_score * 5
    return round(final_score, 2)

def get_severity_label(score):
    """Convert numeric score to human readable label"""
    if score >= 4.0:
        return "CRITICAL"
    elif score >= 3.0:
        return "HIGH"
    elif score >= 2.0:
        return "MEDIUM"
    elif score >= 1.0:
        return "LOW"
    else:
        return "INFORMATIONAL"

def score_alert(alert_data, threat_intel, alert_history):
    """
    Main scoring function
    Returns complete scored alert
    """
    src_ip = alert_data.get("src_ip", "")
    
    abuseipdb_data = threat_intel.get("abuseipdb", {})
    otx_data = threat_intel.get("otx", {})
    
    reputation = calculate_reputation_score(abuseipdb_data)
    relevance = calculate_relevance_score(abuseipdb_data, otx_data, alert_data)
    recurrence = calculate_recurrence_score(src_ip, alert_history)
    
    severity_score = calculate_final_severity(reputation, relevance, recurrence)
    severity_label = get_severity_label(severity_score)
    
    return {
        "severity_score": severity_score,
        "severity_label": severity_label,
        "scoring_breakdown": {
            "reputation": reputation,
            "relevance": relevance,
            "recurrence": recurrence
        },
        "formula": f"({reputation} x 0.5) + ({relevance} x 0.3) + ({recurrence} x 0.2) = {round((reputation*0.5)+(relevance*0.3)+(recurrence*0.2), 3)} x 5 = {severity_score}"
    }