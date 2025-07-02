# SOC Automation Script: Log Ingestion & Threat Intelligence Lookup (VirusTotal)
# Step 1: Install required packages if not present
try:
    import requests
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])
    import requests

try:
    import pandas as pd
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pandas'])
    import pandas as pd

# Step 2: Log Ingestion Example (Assume log file is 'sample.log')
def read_log_file(log_path):
    """Read log file and extract possible indicators (IPs, hashes)."""
    import re
    indicators = set()
    with open(log_path, 'r') as f:
        for line in f:
            # Extract IP addresses
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            indicators.update(ips)
            # Extract SHA256 hashes (example)
            hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', line)
            indicators.update(hashes)
    return list(indicators)

def virustotal_lookup(indicator, api_key):
    """Query VirusTotal for an IP or hash indicator."""
    headers = {"x-apikey": api_key}
    if len(indicator) == 64:
        # Assume SHA256 hash
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        # Assume IP address
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

if __name__ == "__main__":
    # Sample usage
    log_indicators = read_log_file('sample.log')
    print("Extracted indicators:", log_indicators)
    VT_API_KEY = "f2c64cddaa4b7e3d1c540075ed8e2f1bfb66809e96cb06864905257517945069"  # Replace with your actual API key
    # Save results to CSV
    import pandas as pd
    results = []
    for ind in log_indicators:
        result = virustotal_lookup(ind, VT_API_KEY)
        print(f"{ind}: {result}")
        results.append({"indicator": ind, "result": result})
    df = pd.DataFrame(results)
    df.to_csv("vt_results.csv", index=False)
    print("Results saved to vt_results.csv")
