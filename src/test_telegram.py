from telegram_bot import send_alert

test_alert = {
    "severity_score": 4.8,
    "severity_label": "CRITICAL",
    "src_ip": "192.168.1.100",
    "alert_signature": "ET CNC Feodo Tracker Reported CnC Server",
    "timestamp": "2026-05-25T19:00:00Z",
    "threat_intel": {
        "abuseipdb": {
            "abuse_confidence_score": 98
        }
    },
    "scoring_breakdown": {
        "formula": "(0.98 x 0.5) + (0.8 x 0.3) + (1.0 x 0.2) = 0.96 x 5 = 4.8"
    }
}

send_alert(test_alert)
print("Test alert sent!")