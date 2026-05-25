import requests
import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# Simple in-memory cache to avoid repeated API calls
cache = {}

def check_abuseipdb(ip_address):
    """Query AbuseIPDB for IP reputation"""
    
    if ip_address in cache:
        return cache[ip_address]
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()["data"]
            result = {
                "ip": ip_address,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", None),
                "isp": data.get("isp", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "country": data.get("countryCode", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "source": "abuseipdb"
            }
            cache[ip_address] = result
            return result
        else:
            return default_response(ip_address)
            
    except Exception as e:
        print(f"AbuseIPDB error for {ip_address}: {e}")
        return default_response(ip_address)

def check_otx(ip_address):
    """Query AlienVault OTX for IP reputation"""
    
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            
            result = {
                "ip": ip_address,
                "pulse_count": pulse_count,
                "reputation": data.get("reputation", 0),
                "country": data.get("country_name", "Unknown"),
                "source": "otx"
            }
            return result
        else:
            return {"ip": ip_address, "pulse_count": 0, "source": "otx"}
            
    except Exception as e:
        print(f"OTX error for {ip_address}: {e}")
        return {"ip": ip_address, "pulse_count": 0, "source": "otx"}

def default_response(ip_address):
    """Return default response when API fails"""
    return {
        "ip": ip_address,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "last_reported": None,
        "isp": "Unknown",
        "usage_type": "Unknown",
        "country": "Unknown",
        "is_whitelisted": False,
        "source": "abuseipdb"
    }

def get_threat_intel(ip_address):
    """Get combined threat intelligence from all sources"""
    abuseipdb_data = check_abuseipdb(ip_address)
    otx_data = check_otx(ip_address)
    
    return {
        "abuseipdb": abuseipdb_data,
        "otx": otx_data
    }

if __name__ == "__main__":
    # Test the client
    test_ip = "178.62.3.223"
    print(f"Testing threat intel for {test_ip}")
    result = get_threat_intel(test_ip)
    print(json.dumps(result, indent=2))