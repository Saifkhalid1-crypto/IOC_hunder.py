# ioc_hunter.py

import requests
import csv
import os
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


def fetch_alienvault_iocs():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        iocs = []
        for pulse in data.get('results', []):
            for indicator in pulse.get('indicators', []):
                iocs.append({
                    'type': indicator.get('type'),
                    'indicator': indicator.get('indicator'),
                    'description': pulse.get('name')
                })
        return iocs
    else:
        print("Error fetching IOCs:", response.status_code)
        return []


def enrich_ip(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {}


def enrich_iocs(iocs):
    enriched_list = []
    for ioc in iocs:
        print(f"[*] {ioc['type']}: {ioc['indicator']} ({ioc['description']})")
        enrichment = {}
        if ioc['type'] == 'IPv4':
            enrichment = enrich_ip(ioc['indicator'])
        ioc.update({"enrichment": enrichment})
        enriched_list.append(ioc)
    return enriched_list


def save_to_csv(iocs, filename='iocs_output.csv'):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['type', 'indicator', 'description', 'enrichment']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in iocs:
            writer.writerow({
                'type': ioc['type'],
                'indicator': ioc['indicator'],
                'description': ioc['description'],
                'enrichment': str(ioc.get('enrichment'))
            })


def main():
    iocs = fetch_alienvault_iocs()
    if iocs:
        enriched = enrich_iocs(iocs)
        save_to_csv(enriched)
        print("[+] IOCs collected and saved to iocs_output.csv")
    else:
        print("[-] No IOCs fetched.")


if __name__ == "__main__":
    main()
