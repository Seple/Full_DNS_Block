<h1 align="center">🛡️ FULL DNS BLOCK 🛡️</h1>

If you want a single, readymade list rather than having to compile one yourself from multiple sources, this script might be exactly what you are looking for. The script downloads multiple publicly available filter lists and processes them through a simple pipeline that validates and normalizes rules, converts supported formats, removes duplicate and redundant entries, applies allowlists, and outputs a single optimized blocklist.

> [!CAUTION]
> This script does not create its own blocklists. It acts as an aggregation tool that relies on publicly available lists maintained by external authors.
> 
> **All rights to these lists belong to their respective creators**❗

<h2 align="center">💡 Concept</h2>

*  **Reduce Size:**
The priority is to minimize memory usage and CPU load on end devices. This is achieved by removing duplicates and redundant subdomains. The carefully selected collection of filters also has a key impact on the final file size.

*  **Maximum effectiveness:**
The choice of sources for the filter collection is not accidental. The selection is aimed at capturing a broad spectrum of threats, striving to limit unwanted content as extensively as possible.

*  **Unobtrusive operation:**
The most effective filter is one that remains unnoticeable. The goal is high aggressiveness in blocking while maintaining discretion and minimizing the risk of false positives, which could disrupt the normal functioning of network services. This effect is achieved through a mix of sources that are balanced yet aggressive where necessary.

---

<h2 align="center">📜 Filter List Collection</h2>

The following filter collection constitutes the foundation. All sources are regularly updated and maintained by reputable providers. The selection is dictated by the desire to maintain a balance between security and connection stability.

* [HaGeZi PRO](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt)

* [HaGeZi Dynamic DNS](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt)

* [HaGeZi Encrypted DNS/DoH/VPN/TOR/Proxy Bypass](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt)

* [HaGeZi Badware Hoster](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt)

* [HaGeZi Most Abused TLDs - Aggressive](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt)

* [HaGeZi Threat Intelligence Feeds - Medium](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt)

* [HaGeZi DNS Rebind Protection](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adguard/dns-rebind-protection.txt)
<br></br>

> [!IMPORTANT]
> **Aggressive Filtering**
> 
> The included set of lists in this collection carries the highest risk of false positives while also providing the greatest reduction in size and a significant security improvement.
> 
>  * [HaGeZi Most Abused TLDs - Aggressive](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt)
> 
> To maintain a balanced compromise between effectiveness and compatibility, the corresponding allowlist provided by the same filter list maintainers is included whenever available.
> 
>  * [HaGeZi Most Abused TLDs Aggressive - Allowlist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt)
> 
> If a legitimate domain is incorrectly blocked, please report it to the maintainers of the respective filter list for the benefit of all users.

> [!NOTE]
> **Extended Filtering**
> 
> Finding the right balance between filtering scope and list size is a challenge. To improve the efficiency of the generated blocklist, additional filtering sources are used to identify parent domains that replace multiple blocked subdomains. This extends filter scope while reducing the overall number of rules.
>
>  * [HaGeZi Threat Intelligence Feeds - Full](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt)
>
>  * [HaGeZi PRO++](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt)

---

<h2 align="center">📥 Download</h2>

This list combines filters addressing advertisements, trackers, telemetry, phishing, malware, scams, and other malicious network activity. Compatibility depends on the formats supported by your software. Before using this list, make sure your software supports the output format.

**Output format:** Adblock syntax: (||domain^, @@||domain^) + AdGuard syntax: (/regex/).

* [Full DNS Block](https://raw.githubusercontent.com/Seple/Full_DNS_Block/refs/heads/main/Full_DNS_Block.txt)

**Intended for:** AdGuard, AdGuard Home.
  
**Potentially compatible with:** Pi-hole, uBlock Origin, and many others.

> [!TIP]
> This list is a supplementary tool for network filtering. It is not an autonomous security solution and should not be used as the primary or sole method of protection. Always integrate it with other security layers and verify its impact on your specific environment before deployment, as incorrect blocking is a known risk. For detailed information about the individual filter lists, including their purpose and scope, please refer to the official documentation of their respective authors. Report incorrect blocking or other issues directly to the maintainers of the original filter lists.

> [!WARNING]
> This script aggregates publicly available blocklists and processes them into a single consolidated list. No blocklist is perfect, and you must account for the possibility of incorrect blocking, which may disrupt the operation of your network and services. The generated list is provided without any warranty of any kind. You use it entirely at your own risk. The author of this script assumes no liability for any damages, service disruptions, or other consequences resulting from the use of this script or its generated output. By using the generated list, the user acknowledges and accepts the above disclaimer.
