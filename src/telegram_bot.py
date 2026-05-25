import requests
import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_alert(enriched_alert):
    """Send critical alert notification via Telegram"""
    
    severity_score = enriched_alert.get("severity_score", 0)
    severity_label = enriched_alert.get("severity_label", "UNKNOWN")
    src_ip = enriched_alert.get("src_ip", "Unknown")
    signature = enriched_alert.get("alert_signature", "Unknown")
    confidence = enriched_alert.get("threat_intel", {}).get(
        "abuseipdb", {}).get("abuse_confidence_score", 0)
    timestamp = enriched_alert.get("timestamp", "Unknown")
    formula = enriched_alert.get("scoring_breakdown", {}).get("formula", "N/A")

    emoji = "🚨" if severity_label == "CRITICAL" else "⚠️"
    
    message = f"""
{emoji} *{severity_label} SECURITY ALERT* {emoji}

*Threat Score:* {severity_score}/5
*Signature:* {signature}

*Source IP:* `{src_ip}`
*Abuse Confidence:* {confidence}%
*Timestamp:* {timestamp}

*Scoring Breakdown:*
`{formula}`

*Action Required:* Investigate immediately in Kibana dashboard
    """.strip()
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            print(f"Telegram alert sent for {src_ip}")
        else:
            print(f"Telegram error: {response.status_code}")
            
    except Exception as e:
        print(f"Telegram send error: {e}")

def test_connection():
    """Test Telegram bot connection"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "✅ University SOC Alert System connected successfully"
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except:
        return False