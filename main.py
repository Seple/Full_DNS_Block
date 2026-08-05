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
    ## HaGeZi Most Abused TLDs - Aggressive
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt",
    ## HaGeZi Threat Intelligence Feeds - Medium
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
	## Test_list
    "https://raw.githubusercontent.com/Seple/Full_DNS_Block/refs/heads/main/Test_list.txt",
	## Peter Lowe (YoYo List)
	## "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
	## EasyPrivacy
	## "https://ublockorigin.pages.dev/thirdparties/easyprivacy.txt",
]

OPTIMIZATION_SOURCES = [
    ## HaGeZi Threat Intelligence Feeds - Full
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", 
	## HaGeZi PRO++
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
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

ALLOW_SOURCES = [
    ## HaGeZi Most Abused TLDs Aggressive - Allowlist
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt",
]

def load_set_from_file(filepath):
    allowed_domains = set()
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line.startswith('@@||') and line.endswith('^'):
                domain = line.removeprefix('@@||').removesuffix('^')
                allowed_domains.add(domain.lower())
    return allowed_domains

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
! Last modified: {timestamp} UTC
! Number of entries: {rule_count}
"""

processed_domains = set()
VALID_MODIFIERS = {'document', 'doc', 'all', 'popup', 'network'}
VALID_ASCII_LDH = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
def normalize_adblock_domain(line):
    line = line.strip()
    if not (line.startswith("||") and "^" in line):
        return None
    parts = line[2:].split('^', 1)
    domain = parts[0].strip().lower()
    remainder = parts[1] if len(parts) > 1 else ""
    if remainder:
        if not remainder.startswith('$'):
            return None
        mod_part = remainder[1:]
        mods = {m.strip() for m in mod_part.split(",") if m.strip()}
        if not mods.issubset(VALID_MODIFIERS):
            return None
    if not domain or len(domain) > 253 or not all(c in VALID_ASCII_LDH for c in domain) or domain.startswith('.') or domain.endswith('.') or any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-') for part in domain.split('.')):
        return None
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2 and all(p.isdigit() for p in domain_parts if p):
        return None
    return domain

for url in ADBLOCK_SOURCES:
    lines = fetch_list(url)
    for line in lines:
        domain = normalize_adblock_domain(line)
        if domain:
            processed_domains.add(domain)

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
        domain = normalize_adblock_domain(f"||{domain}^")
        if domain:
            processed_domains.add(domain)

optimization_domains = set()
for url in OPTIMIZATION_SOURCES:
    for line in fetch_list(url):
        domain = normalize_adblock_domain(line)
        if domain:
            optimization_domains.add(domain)

for domain in processed_domains.copy():
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in optimization_domains:
            processed_domains.add(parent)

regex_rules = set()
for url in REGEX_SOURCES:
    lines = fetch_list(url)
    for line in lines:
        line = line.strip()
        if line.startswith('/') and line.endswith('/'):
            regex_rules.add(line)

allow_rules = set()
for url in ALLOW_SOURCES:
    lines = fetch_list(url)
    for line in lines:
        line = line.strip()
        if line.startswith('@@||') and line.endswith('^'):
            allow_rules.add(line)

filtered_domains = {domain for domain in processed_domains if domain not in exclude_list}
final_domains = remove_subdomains(filtered_domains)
formatted_domains = {f"||{domain}^" for domain in final_domains}
final_output = sorted(formatted_domains) + sorted(regex_rules) + sorted(allow_rules)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(generate_header(len(final_output)))
    f.write("\n".join(final_output) + "\n")
