import json
import time
import os
from datetime import datetime
from elasticsearch import Elasticsearch
from threat_intel_client import get_threat_intel
from scoring_model import score_alert
from telegram_bot import send_alert, test_connection
from dotenv import load_dotenv

load_dotenv()

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "elasticsearch")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")
CRITICAL_THRESHOLD = 4.0

# Track alert history for recurrence scoring
alert_history = {}

def connect_elasticsearch():
    """Connect to Elasticsearch with retry"""
    es = Elasticsearch(
        f"http://{ES_HOST}:{ES_PORT}",
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=30,
        retry_on_timeout=True,
        max_retries=3
    )
    
    for attempt in range(10):
        try:
            info = es.info()
            print(f"Connected to Elasticsearch: {info['version']['number']}")
            return es
        except Exception as e:
            print(f"ES connection attempt {attempt+1} failed: {type(e).__name__}: {e}")
            time.sleep(5)
    
    raise Exception("Could not connect to Elasticsearch")

def create_index(es):
    """Create Elasticsearch index for enriched alerts"""
    index_name = "enriched-alerts"
    
    if not es.indices.exists(index=index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dest_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "alert_signature": {"type": "text"},
                    "alert_severity": {"type": "integer"},
                    "severity_score": {"type": "float"},
                    "severity_label": {"type": "keyword"},
                    "abuse_confidence_score": {"type": "integer"},
                    "total_reports": {"type": "integer"},
                    "country": {"type": "keyword"},
                    "isp": {"type": "keyword"},
                    "otx_pulse_count": {"type": "integer"},
                    "reputation_score": {"type": "float"},
                    "relevance_score": {"type": "float"},
                    "recurrence_score": {"type": "float"},
                    "scoring_formula": {"type": "text"},
                    "enrichment_timestamp": {"type": "date"}
                }
            }
        }
        es.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    return index_name

def process_alert(alert_data, es, index_name):
    """Process a single Suricata alert through enrichment pipeline"""
    
    src_ip = alert_data.get("src_ip", "")
    
    if not src_ip:
        return
    
    # Update alert history for recurrence scoring
    alert_history[src_ip] = alert_history.get(src_ip, 0) + 1
    
    print(f"Processing alert from {src_ip}...")
    
    # Get threat intelligence
    threat_intel = get_threat_intel(src_ip)
    
    # Score the alert
    scoring_result = score_alert(alert_data, threat_intel, alert_history)
    
    # Build enriched alert document
    enriched_alert = {
        "timestamp": alert_data.get("timestamp"),
        "src_ip": src_ip,
        "dest_ip": alert_data.get("dest_ip", ""),
        "src_port": alert_data.get("src_port", 0),
        "dest_port": alert_data.get("dest_port", 0),
        "protocol": alert_data.get("proto", ""),
        "alert_signature": alert_data.get("alert", {}).get("signature", ""),
        "alert_severity": alert_data.get("alert", {}).get("severity", 0),
        "severity_score": scoring_result["severity_score"],
        "severity_label": scoring_result["severity_label"],
        "abuse_confidence_score": threat_intel["abuseipdb"].get(
            "abuse_confidence_score", 0),
        "total_reports": threat_intel["abuseipdb"].get("total_reports", 0),
        "country": threat_intel["abuseipdb"].get("country", "Unknown"),
        "isp": threat_intel["abuseipdb"].get("isp", "Unknown"),
        "otx_pulse_count": threat_intel["otx"].get("pulse_count", 0),
        "reputation_score": scoring_result["scoring_breakdown"]["reputation"],
        "relevance_score": scoring_result["scoring_breakdown"]["relevance"],
        "recurrence_score": scoring_result["scoring_breakdown"]["recurrence"],
        "scoring_formula": scoring_result["formula"],
        "enrichment_timestamp": datetime.utcnow().isoformat()
    }
    
    # Store in Elasticsearch
    es.index(index=index_name, document=enriched_alert, timeout="30s")
    print(f"Stored enriched alert: {scoring_result['severity_label']} "
          f"(score: {scoring_result['severity_score']})")
    
    # Send Telegram alert if critical
    if scoring_result["severity_score"] >= CRITICAL_THRESHOLD:
        enriched_alert["threat_intel"] = threat_intel
        enriched_alert["scoring_breakdown"] = scoring_result["scoring_breakdown"]
        send_alert(enriched_alert)

def process_eve_log(eve_log_path, es, index_name):
    """Process Suricata eve.json log file"""
    
    if not os.path.exists(eve_log_path):
        print(f"eve.json not found at {eve_log_path}, waiting...")
        return 0
    
    processed = 0
    
    with open(eve_log_path, "r") as f:
        for line in f:
            try:
                alert_data = json.loads(line.strip())
                
                # Only process alert events
                if alert_data.get("event_type") == "alert":
                    process_alert(alert_data, es, index_name)
                    processed += 1
                    
            except json.JSONDecodeError:
                continue
    
    return processed

def main():
    print("Starting University SOC Enrichment Engine...")
    
    # Test Telegram connection
    if test_connection():
        print("Telegram bot connected successfully")
    else:
        print("Warning: Telegram connection failed")
    
    # Connect to Elasticsearch
    es = connect_elasticsearch()
    index_name = create_index(es)
    
    eve_log_path = "/alerts/eve.json"
    
    print(f"Monitoring {eve_log_path} for alerts...")
    
    # Process existing alerts then monitor for new ones
    while True:
        processed = process_eve_log(eve_log_path, es, index_name)
        if processed > 0:
            print(f"Processed {processed} alerts")
        time.sleep(5)

if __name__ == "__main__":
    main()