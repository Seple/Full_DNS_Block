import requests
import re
import datetime
import os
from collections import defaultdict

EXCLUDE_LIST_FILE = "Allowed_List.txt"
NO_OPTIMIZATION_LIST_FILE = "No_Optimization_List.txt"

OUTPUT_FILE = "Full_DNS_Block.txt"
OPTIMIZATION_LOG_FILE = "Optimization_suggestion.txt"

THRESHOLD = 100

urls = [
    ## Hagezi PRO
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    ## Peter Lowe Blocklist (YoYo List)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    ## HaGeZi DynDNS Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    ## HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    ## HaGeZi Badware Hoster DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
    # HaGeZi The World Most Abused TLDs - JESZCZE RAZ SPRÓBOWAĆ AGGRESSIVE ???  
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt",
    ## HaGeZi Threat Intelligence Feeds DNS Blocklist MEDIUM
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
]

direct_domain_urls = [

]

def load_set_from_file(filepath):
    if not os.path.exists(filepath):
        print(f"⚠️ Plik {filepath} nie istnieje. Zwracam pusty zbiór.")
        return set()
    with open(filepath, "r", encoding="utf-8") as file:
        return {line.strip() for line in file if line.strip()}

exclude_list = load_set_from_file(EXCLUDE_LIST_FILE)
no_optimization_list = load_set_from_file(NO_OPTIMIZATION_LIST_FILE)

valid_patterns = [
    r"^0\.0\.0\.0\s+([\w.-]+)$",
    r"^127\.0\.0\.1\s+([\w.-]+)$",
    r"^\|\|([\w\.\*\-]+)\^$",
]

def fetch_list(url):
    retries = 3
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            lines = response.text.splitlines()
            print(f"✅ Pobrano: {url} ({len(lines)}/{len(set(lines))})")
            return lines
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                print(f"⚠️ Błąd pobierania {url} (próba {attempt + 1}/{retries})")
            else:
                print(f"❌ Nie udało się pobrać: {url}")
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

def optimize_domains(domains):
    domain_count = defaultdict(int)
    subdomain_map = defaultdict(set)
    for domain in domains:
        parts = domain.split('.')
        if len(parts) > 2:
            main_domain = '.'.join(parts[-2:])
            domain_count[main_domain] += 1
            subdomain_map[main_domain].add(domain)
    optimized_domains = set(domains)
    optimization_results = []
    for main_domain, count in domain_count.items():
        if count > THRESHOLD and main_domain not in domains and main_domain not in no_optimization_list:
            optimized_domains.add(main_domain)
            for subdomain in subdomain_map[main_domain]:
                optimized_domains.discard(subdomain)
            optimization_results.append((main_domain, count))
    return optimized_domains, optimization_results

total_downloaded = 0
all_raw_lines = []

for url in urls:
    lines = fetch_list(url)
    total_downloaded += len(lines)
    all_raw_lines.extend(lines)

for url in direct_domain_urls:
    lines = fetch_list(url)
    total_downloaded += len(lines)
    for line in lines:
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        if not line.startswith("||"):
            line = f"||{line}^"
        all_raw_lines.append(line)

all_domains = set()
for line in all_raw_lines:
    line = line.strip()
    line = re.split(r"[!#;]", line, maxsplit=1)[0].strip()
    if not line:
        continue
    if line.startswith("||") and "^$all" in line:
        line = re.sub(r"\^\$.*$", "^", line)
    if not (line.startswith("0.0.0.0") or line.startswith("||")):
        continue
    for pattern in valid_patterns:
        match = re.match(pattern, line)
        if match:
            all_domains.add(match.group(1))
            break

filtered_domains = {domain for domain in all_domains if not any(domain.endswith(f".{excluded}") or domain == excluded for excluded in exclude_list)}
final_domains, optimization_suggestions = optimize_domains(remove_subdomains(filtered_domains))
formatted_domains = {f"||{domain}^" for domain in final_domains}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(generate_header(len(formatted_domains)))
    f.write("\n".join(sorted(formatted_domains)) + "\n")

with open(OPTIMIZATION_LOG_FILE, "w", encoding="utf-8") as f:
    for domain, count in sorted(optimization_suggestions, key=lambda x: -x[1]):
        f.write(f"{domain}  (usunięto {count} subdomen)\n")

print(f"✅ Nowa lista zapisana w {OUTPUT_FILE}")
print(f"📊 Podsumowanie: Pobranie: {total_downloaded} reguł, Unikalne: {len(all_domains)} reguł, Pozostałe po filtracji: {len(final_domains)} reguł")
print(f"📄 Plik optymalizacji zapisany w {OPTIMIZATION_LOG_FILE}")
