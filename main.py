import requests
import datetime
import os

EXCLUDE_LIST_FILE = "Allowed_List.txt"
OUTPUT_FILE = "Full_DNS_Block.txt"

urls = [
    ## Hagezi PRO
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    ## Peter Lowe Blocklist (YoYo List)
    ## "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    ## HaGeZi DynDNS Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    ## HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    ## HaGeZi Badware Hoster DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
    ## HaGeZi The World Most Abused TLDs
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt",
    ## HaGeZi Threat Intelligence Feeds DNS Blocklist MEDIUM
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
]

def load_set_from_file(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as file:
        return {line.strip() for line in file if line.strip()}

exclude_list = load_set_from_file(EXCLUDE_LIST_FILE)

def fetch_list(url):
    retries = 3
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text.splitlines()
        except requests.exceptions.RequestException:
            continue
    return []

def remove_subdomains(domains):
    sorted_domains = sorted(domains, key=lambda d: d.count('.'))
    filtered_domains = set()
    for domain in sorted_domains:
        parts = domain.split('.')
        if not any('.'.join(parts[i:]) in filtered_domains for i in range(1, len(parts))):
            filtered_domains.add(domain)
    return filtered_domains

def generate_header(rule_count):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"""[Adblock Plus]
! Title: Full_DNS_Block
! Description: Linked lists to reduce size
! Homepage: https://github.com/Seple/Full_DNS_Block
! Last modified: {timestamp}
! Number of entries: {rule_count}
"""

all_raw_lines = []

for url in urls:
    lines = fetch_list(url)
    all_raw_lines.extend(lines)

all_domains = set()
for line in all_raw_lines:
    line = line.strip()
    if line.startswith("||"):
        domain = line[2:].split('^')[0].strip()
        if domain:
            all_domains.add(domain)

filtered_domains = {domain for domain in all_domains if not any(domain.endswith(f".{excluded}") or domain == excluded for excluded in exclude_list)}
final_domains = remove_subdomains(filtered_domains)
formatted_domains = {f"||{domain}^" for domain in final_domains}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(generate_header(len(formatted_domains)))
    f.write("\n".join(sorted(formatted_domains)) + "\n")
