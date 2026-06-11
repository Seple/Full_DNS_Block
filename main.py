import requests
import datetime

EXCLUDE_LIST_FILE = "Allowed_List.txt"
OUTPUT_FILE = "Full_DNS_Block.txt"

ADBLOCK_SOURCES = [
    ## HaGeZi PRO
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    ## HaGeZi Dynamic DNS
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
    ## HaGeZi Encrypted DNS/DoH/VPN/TOR/Proxy Bypass
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt",
    ## HaGeZi Badware Hoster DNS
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
    ## HaGeZi Most Abused TLDs Aggressive
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt",
    ## HaGeZi Threat Intelligence Feeds Medium
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
	## Peter Lowe (YoYo List)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
	## EasyPrivacy
    "https://ublockorigin.pages.dev/thirdparties/easyprivacy.txt",
	## # EasyList
    "https://ublockorigin.pages.dev/thirdparties/easylist.txt",
	## TEST
	## # AdGuard Base filter
    "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt",
	## AdGuard Tracking Protection filter
	## TEST
    ## Dandelion Sprout's Anti-Malware
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout%27s%20Anti-Malware%20List.txt",
]

# WARNING: HOST_SOURCES
# HOST = lower precision, more false positives than Adblock filters
# Threat feeds: malware/phishing/ransomware/0-day (URLhaus, ThreatFox, Phishing Army, etc.)
# Rapid Threat Response: fast rotation, not a base for quality filters
# Rules: no ads/general filters; more feeds = larger list, lower performance

HOST_SOURCES = [
    ## Phishing Army
    ## "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
]

REGEX_SOURCES = [
    ## HaGeZi DNS Rebind Protection
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adguard/dns-rebind-protection.txt",
]

def load_set_from_file(filepath):
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

for url in ADBLOCK_SOURCES:
    lines = fetch_list(url)
    all_raw_lines.extend(lines)

for url in HOST_SOURCES:
    lines = fetch_list(url)
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            continue
        parts = line.split()
        if len(parts) == 1:
            domain = parts[0]
        else:
            first = parts[0]
            if first[0].isdigit() or first.startswith("::"):
                domain = parts[1]
            else:
                domain = parts[0]
        all_raw_lines.append(f"||{domain}^")

processed_domains = set()
VALID_MODIFIERS = {'document', 'doc', 'all', 'popup', 'network'}
VALID_ASCII_LDH = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
for line in all_raw_lines:
    line = line.strip()
    if not (line.startswith("||") and "^" in line):
        continue
    parts = line[2:].split('^', 1)
    domain = parts[0].strip().lower()
    remainder = parts[1] if len(parts) > 1 else ""
    if remainder:
        if not remainder.startswith('$'):
            continue
        mod_part = remainder[1:]
        mods = {m.strip() for m in mod_part.split(",") if m.strip()}
        if not mods.issubset(VALID_MODIFIERS):
            continue
    if not domain or len(domain) > 253 or not all(c in VALID_ASCII_LDH for c in domain) or domain.startswith('.') or domain.endswith('.') or any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-') for part in domain.split('.')):
        continue
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2 and all(p.isdigit() for p in domain_parts if p):
        continue
    processed_domains.add(domain)

regex_rules = set()
for url in REGEX_SOURCES:
    lines = fetch_list(url)
    for line in lines:
        line = line.strip()
        if line.startswith('/') and line.endswith('/'):
            regex_rules.add(line)
            
filtered_domains = {domain for domain in processed_domains if domain not in exclude_list}
final_domains = remove_subdomains(filtered_domains)
formatted_domains = {f"||{domain}^" for domain in final_domains}
final_output = sorted(formatted_domains) + sorted(regex_rules)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(generate_header(len(final_output)))
    f.write("\n".join(final_output) + "\n")
