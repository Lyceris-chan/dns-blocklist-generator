# sleepy list
sleepy list compiles a DNS blocklist for my AdGuard Home setup by merging multiple sources and removing duplicates. It is built from the credited lists so I can be sound asleep knowing this protects me, and it keeps things quiet when I'm tired of ads and tracking.
This is not my own list. It is a compilation of the credited sources tailored to my use, and I do not provide public support for false blocks or exceptions.

Usage:
- `./compiler.sh`
- `SLEEPY_LIST_EXCLUDED_IDS=37,57,53,46 ./compiler.sh`
- `SLEEPY_LIST_NO_CACHE=1 ./compiler.sh`
- `SLEEPY_LIST_CACHE_DIR=/path/to/cache ./compiler.sh`

Options (env vars):
- `SLEEPY_LIST_EXCLUDED_IDS`: comma-separated list IDs to skip (default: `37,57,53,46`)
- `SLEEPY_LIST_NO_CACHE`: set to `1` to disable both download and parse caching
- `SLEEPY_LIST_CACHE_DIR`: override cache location (default: `.sleepy_list_cache`)
- `SLEEPY_LIST_JOBS`: max parallel downloads/parses (default: `16`)
- `SLEEPY_LIST_KEEP_LISTS`: set to `1` to keep raw list downloads (default: `0`, remove to save space)

Requirements:
- bash
- python3

Outputs:
- `blocklist.txt` (rules grouped by source; header format: `! source count`)
- `diffs.txt` (source-aware diff ordered by list)

Technical notes:
- normalizes inputs into domains, wildcards, regex, IP ranges, and complex rules
- stacks lists starting from the anchor, greedily adding the most unique rules
- optimizes via wildcard coverage, tree shaking, regex simplification, and cross-type de-dupe
- diffing is source-aware and ordered by list
- downloads are cached with conditional requests (ETag/Last-Modified) for faster reruns
- parsed rule sets are cached by content hash to skip re-parsing unchanged lists

Behavior:
- aborts if any list fails to download (avoids stale outputs)
- keeps the final blocklist minimal; diffs carry per-list adds/removes/moves
- credits include used, superseded, excluded, and unused lists with list/creator links

Credits (lists used, superseded, excluded, and unused; auto-updated by the compiler, with list and creator links):
<!-- sleepy-list:credits:start -->
Used lists (included in blocklist):
- 1Hosts (Xtra) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt) - [creator](https://badmojr.github.io/1Hosts/)
- AdGuard DNS filter - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) - [creator](https://github.com/AdguardTeam/AdGuardSDNSFilter)
- AdGuard DNS Popup Hosts filter - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt) - [creator](https://github.com/AdguardTeam/AdGuardSDNSFilter)
- Dan Pollock's List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt) - [creator](https://someonewhocares.org/)
- Dandelion Sprout's Anti Push Notifications - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt) - [creator](https://github.com/DandelionSprout/adfilt)
- Dandelion Sprout's Anti-Malware List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt) - [creator](https://github.com/DandelionSprout/adfilt)
- Dandelion Sprout's Game Console Adblock List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt) - [creator](https://github.com/DandelionSprout/adfilt)
- EasyList Dutch - [list](https://easylist-downloads.adblockplus.org/easylistdutch.txt) - [creator](https://easylist.to/)
- HaGeZi's Apple Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Badware Hoster Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's DNS Rebind Protection - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's DynDNS Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt) - [creator](https://github.com/hagezi/dns-blocklists#bypass)
- HaGeZi's Gambling Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt) - [creator](https://github.com/hagezi/dns-blocklists#gambling)
- HaGeZi's OPPO & Realme Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Pro++ Blocklist (anchor) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Samsung Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's The World's Most Abused TLDs - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Threat Intelligence Feeds - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's URL Shortener Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_68.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Vivo Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Windows/Office Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Xiaomi Tracker Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- Malicious URL Blocklist (URLHaus) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt) - [creator](https://urlhaus.abuse.ch/)
- NoCoin Filter List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt) - [creator](https://github.com/hoshsadiq/adblock-nocoin-list/)
- OISD Blocklist Big - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt) - [creator](https://oisd.nl/)
- Perflyst and Dandelion Sprout's Smart-TV Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt) - [creator](https://github.com/Perflyst/PiHoleBlocklist)
- Peter Lowe's Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt) - [creator](https://pgl.yoyo.org/adservers/)
- Phishing Army - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt) - [creator](https://phishing.army/)
- Phishing URL Blocklist (PhishTank and OpenPhish) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt) - [creator](https://gitlab.com/malware-filter/phishing-filter)
- Scam Blocklist by DurableNapkin - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt) - [creator](https://github.com/durablenapkin/scamblocklist)
- ShadowWhisperer Tracking List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt) - [creator](https://github.com/ShadowWhisperer/BlockLists)
- ShadowWhisperer's Malware List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt) - [creator](https://github.com/ShadowWhisperer/BlockLists)
- Stalkerware Indicators List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt) - [creator](https://github.com/AssoEchap/stalkerware-indicators)
- Steven Black's List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt) - [creator](https://github.com/StevenBlack/hosts)
- The Big List of Hacked Malware Web Sites - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt) - [creator](https://github.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites)
- uBlock filters - Badware risks - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt) - [creator](https://github.com/uBlockOrigin/uAssets)

Superseded lists (auto-skipped because a larger list covers them):
- 1Hosts (Lite) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt) - [creator](https://badmojr.github.io/1Hosts/) - superseded by: 1Hosts (Xtra) - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt) - [creator](https://badmojr.github.io/1Hosts/)
- HaGeZi's Normal Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt) - [creator](https://github.com/hagezi/dns-blocklists) - superseded by: HaGeZi's Pro++ Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Pro Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt) - [creator](https://github.com/hagezi/dns-blocklists) - superseded by: HaGeZi's Pro++ Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- HaGeZi's Ultimate Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt) - [creator](https://github.com/hagezi/dns-blocklists) - superseded by: HaGeZi's Pro++ Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt) - [creator](https://github.com/hagezi/dns-blocklists)
- OISD Blocklist Small - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt) - [creator](https://oisd.nl/) - superseded by: OISD Blocklist Big - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt) - [creator](https://oisd.nl/)

Excluded lists (skipped via SLEEPY_LIST_EXCLUDED_IDS):
- AWAvenue Ads Rule - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt) - [creator](https://awavenue.top/)
- HaGeZi's Anti-Piracy Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt) - [creator](https://github.com/hagezi/dns-blocklists#piracy)
- No Google - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt) - [creator](https://github.com/nickspaargaren/no-google)
- ShadowWhisperer's Dating List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt) - [creator](https://github.com/ShadowWhisperer/BlockLists)

Unused lists (available but not selected after stacking):
- HaGeZi's Allowlist Referral - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt) - [creator](https://github.com/hagezi/dns-blocklists#referral)
- Ukrainian Security Filter - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt) - [creator](https://github.com/braveinnovators/ukrainian-security-filter)
- CHN: AdRules DNS List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt) - [creator](https://github.com/Cats-Team/AdRules)
- CHN: anti-AD - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt) - [creator](https://anti-ad.net/)
- HUN: Hufilter - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt) - [creator](https://github.com/hufilter/hufilter)
- IDN: ABPindo - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt) - [creator](https://github.com/ABPindo/indonesianadblockrules)
- IRN: PersianBlocker list - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt) - [creator](https://github.com/MasterKia/PersianBlocker)
- ISR: EasyList Hebrew - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt) - [creator](https://github.com/easylist/EasyListHebrew)
- KOR: List-KR DNS - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt) - [creator](https://github.com/List-KR/List-KR)
- KOR: YousList - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt) - [creator](https://github.com/yous/YousList)
- LIT: EasyList Lithuania - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt) - [creator](https://github.com/EasyList-Lithuania/easylist_lithuania)
- MKD: Macedonian Pi-hole Blocklist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt) - [creator](https://github.com/cchevy/macedonian-pi-hole-blocklist)
- NOR: Dandelion Sprouts nordiske filtre - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt) - [creator](https://github.com/DandelionSprout/adfilt)
- POL: CERT Polska List of malicious domains - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt) - [creator](https://cert.pl/posts/2020/03/ostrzezenia_phishing/)
- POL: Polish filters for Pi-hole - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt) - [creator](https://www.certyficate.it/)
- SWE: Frellwit's Swedish Hosts File - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt) - [creator](https://github.com/lassekongo83/Frellwits-filter-lists/)
- TUR: turk-adlist - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt) - [creator](https://github.com/bkrucarci/turk-adlist)
- TUR: Turkish Ad Hosts - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt) - [creator](https://github.com/symbuzzer/Turkish-Ad-Hosts)
- VNM: ABPVN List - [list](https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt) - [creator](http://abpvn.com/)
<!-- sleepy-list:credits:end -->
