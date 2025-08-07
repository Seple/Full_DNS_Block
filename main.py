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
    # 1Hosts Lite
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    # Hagezi Ultimate
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    # OISD BIG
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    # Peter Lowe's Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    # Steven Black's List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    # Dan Pollock's List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    # AdGuard DNS filter
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    # Malicious URL Blocklist (URLHaus)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    # ShadowWhisperer's Malware List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    # NoCoin Filter List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    # Dandelion Sprout's Anti-Malware List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    # Phishing URL Blocklist (PhishTank and OpenPhish)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    # POL: Polish filters for Pi-hole
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    # Dandelion Sprout's Game Console Adblock List)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",
    # ??? Perflyst and Dandelion Sprout's Smart-TV Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    # HaGeZi's DynDNS Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    # HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    # HaGeZi's Anti-Piracy Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt",
    # HaGeZi's Badware Hoster DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
    # HaGeZi's safesearch not supported DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nosafesearch.txt",
    # HaGeZi's The World's Most Abused TLDs ??? test agresive ???
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt",
    # HaGeZi's Threat Intelligence Feeds DNS Blocklist MEDIUM
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
    # HaGeZi's Threat Intelligence Feeds DNS Blocklist FULL
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    # TEST ??? EasyList Cookie List test ^$third-party ???
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    # AdGuard Tracking Protection filter
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",
    # EasyPrivacy
    "https://easylist.to/easylist/easyprivacy.txt",
    # EasyList
    "https://easylist.to/easylist/easylist.txt",
    # EasyList – Social Widgets
    "https://easylist.to/easylist/fanboy-social.txt",
    # EasyList – Fanboy's Annoyance List
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
]

direct_domain_urls = [
    # Phishing Army
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
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
    r"^\|\|([\w.-]+)\^$",
    r"^\|\|(\*\.[\w.-]+)\^$",
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
