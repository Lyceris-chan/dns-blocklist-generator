#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="https://adguardteam.github.io/HostlistsRegistry/assets"
TEMP_DIR="$ROOT_DIR/temp_downloads"
CACHE_DIR="${SLEEPY_LIST_CACHE_DIR:-$ROOT_DIR/.sleepy_list_cache}"
LISTS_DIR="$CACHE_DIR/lists"
LISTS_JSON="$TEMP_DIR/lists.json"
MANIFEST="$TEMP_DIR/manifest.tsv"
DEFAULT_ANCHOR="HaGeZi's Pro++ Blocklist"
ANCHOR_NAME="${SLEEPY_LIST_ANCHOR:-$DEFAULT_ANCHOR}"
EXCLUDED_IDS="${SLEEPY_LIST_EXCLUDED_IDS:-37,57,53,46}"
NO_CACHE="${SLEEPY_LIST_NO_CACHE:-0}"
KEEP_LISTS="${SLEEPY_LIST_KEEP_LISTS:-0}"
PARSE_MODE="${SLEEPY_LIST_PARSE_MODE:-thread}"
CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
DEFAULT_JOBS="$CPU_COUNT"
if [[ "$DEFAULT_JOBS" -lt 4 ]]; then
  DEFAULT_JOBS=4
fi
if [[ "$DEFAULT_JOBS" -gt 16 ]]; then
  DEFAULT_JOBS=16
fi
CONCURRENCY="${SLEEPY_LIST_JOBS:-$DEFAULT_JOBS}"

rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
if [[ "$NO_CACHE" == "1" ]]; then
  LISTS_DIR="$TEMP_DIR/lists"
fi
mkdir -p "$LISTS_DIR"

cat > "$LISTS_JSON" <<'JSON'
[
  { "RefId": 999, "Id": "easylistdutch.txt", "Name": "EasyList Dutch", "Category": "Specific", "ExternalUrl": "https://easylist-downloads.adblockplus.org/easylistdutch.txt", "Homepage": "https://easylist.to/" },
  { "RefId": 24, "Id": "filter_24.txt", "Name": "1Hosts (Lite)", "Category": "General" },
  { "RefId": 70, "Id": "filter_70.txt", "Name": "1Hosts (Xtra)", "Category": "General" },
  { "RefId": 1, "Id": "filter_1.txt", "Name": "AdGuard DNS filter", "Category": "General" },
  { "RefId": 59, "Id": "filter_59.txt", "Name": "AdGuard DNS Popup Hosts filter", "Category": "General" },
  { "RefId": 53, "Id": "filter_53.txt", "Name": "AWAvenue Ads Rule", "Category": "General" },
  { "RefId": 4, "Id": "filter_4.txt", "Name": "Dan Pollock's List", "Category": "General" },
  { "RefId": 34, "Id": "filter_34.txt", "Name": "HaGeZi's Normal Blocklist", "Category": "Base" },
  { "RefId": 48, "Id": "filter_48.txt", "Name": "HaGeZi's Pro Blocklist", "Category": "Base" },
  { "RefId": 51, "Id": "filter_51.txt", "Name": "HaGeZi's Pro++ Blocklist", "Category": "Base" },
  { "RefId": 49, "Id": "filter_49.txt", "Name": "HaGeZi's Ultimate Blocklist", "Category": "Base" },
  { "RefId": 5, "Id": "filter_5.txt", "Name": "OISD Blocklist Small", "Category": "General" },
  { "RefId": 27, "Id": "filter_27.txt", "Name": "OISD Blocklist Big", "Category": "General" },
  { "RefId": 3, "Id": "filter_3.txt", "Name": "Peter Lowe's Blocklist", "Category": "General" },
  { "RefId": 69, "Id": "filter_69.txt", "Name": "ShadowWhisperer Tracking List", "Category": "General" },
  { "RefId": 33, "Id": "filter_33.txt", "Name": "Steven Black's List", "Category": "General" },
  { "RefId": 39, "Id": "filter_39.txt", "Name": "Dandelion Sprout's Anti Push Notifications", "Category": "Privacy" },
  { "RefId": 6, "Id": "filter_6.txt", "Name": "Dandelion Sprout's Game Console Adblock List", "Category": "Other" },
  { "RefId": 45, "Id": "filter_45.txt", "Name": "HaGeZi's Allowlist Referral", "Category": "Base" },
  { "RefId": 46, "Id": "filter_46.txt", "Name": "HaGeZi's Anti-Piracy Blocklist", "Category": "Specific" },
  { "RefId": 67, "Id": "filter_67.txt", "Name": "HaGeZi's Apple Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 47, "Id": "filter_47.txt", "Name": "HaGeZi's Gambling Blocklist", "Category": "Specific" },
  { "RefId": 66, "Id": "filter_66.txt", "Name": "HaGeZi's OPPO & Realme Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 61, "Id": "filter_61.txt", "Name": "HaGeZi's Samsung Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 65, "Id": "filter_65.txt", "Name": "HaGeZi's Vivo Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 63, "Id": "filter_63.txt", "Name": "HaGeZi's Windows/Office Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 60, "Id": "filter_60.txt", "Name": "HaGeZi's Xiaomi Tracker Blocklist", "Category": "Privacy" },
  { "RefId": 37, "Id": "filter_37.txt", "Name": "No Google", "Category": "Privacy" },
  { "RefId": 7, "Id": "filter_7.txt", "Name": "Perflyst and Dandelion Sprout's Smart-TV Blocklist", "Category": "Specific" },
  { "RefId": 57, "Id": "filter_57.txt", "Name": "ShadowWhisperer's Dating List", "Category": "Specific" },
  { "RefId": 62, "Id": "filter_62.txt", "Name": "Ukrainian Security Filter", "Category": "Regional" },
  { "RefId": 29, "Id": "filter_29.txt", "Name": "CHN: AdRules DNS List", "Category": "Regional" },
  { "RefId": 21, "Id": "filter_21.txt", "Name": "CHN: anti-AD", "Category": "Regional" },
  { "RefId": 35, "Id": "filter_35.txt", "Name": "HUN: Hufilter", "Category": "Regional" },
  { "RefId": 22, "Id": "filter_22.txt", "Name": "IDN: ABPindo", "Category": "Regional" },
  { "RefId": 19, "Id": "filter_19.txt", "Name": "IRN: PersianBlocker list", "Category": "Regional" },
  { "RefId": 43, "Id": "filter_43.txt", "Name": "ISR: EasyList Hebrew", "Category": "Regional" },
  { "RefId": 25, "Id": "filter_25.txt", "Name": "KOR: List-KR DNS", "Category": "Regional" },
  { "RefId": 15, "Id": "filter_15.txt", "Name": "KOR: YousList", "Category": "Regional" },
  { "RefId": 36, "Id": "filter_36.txt", "Name": "LIT: EasyList Lithuania", "Category": "Regional" },
  { "RefId": 20, "Id": "filter_20.txt", "Name": "MKD: Macedonian Pi-hole Blocklist", "Category": "Regional" },
  { "RefId": 13, "Id": "filter_13.txt", "Name": "NOR: Dandelion Sprouts nordiske filtre", "Category": "Regional" },
  { "RefId": 41, "Id": "filter_41.txt", "Name": "POL: CERT Polska List of malicious domains", "Category": "Regional" },
  { "RefId": 14, "Id": "filter_14.txt", "Name": "POL: Polish filters for Pi-hole", "Category": "Regional" },
  { "RefId": 17, "Id": "filter_17.txt", "Name": "SWE: Frellwit's Swedish Hosts File", "Category": "Regional" },
  { "RefId": 26, "Id": "filter_26.txt", "Name": "TUR: turk-adlist", "Category": "Regional" },
  { "RefId": 40, "Id": "filter_40.txt", "Name": "TUR: Turkish Ad Hosts", "Category": "Regional" },
  { "RefId": 16, "Id": "filter_16.txt", "Name": "VNM: ABPVN List", "Category": "Regional" },
  { "RefId": 30, "Id": "filter_30.txt", "Name": "Phishing URL Blocklist (PhishTank and OpenPhish)", "Category": "Security" },
  { "RefId": 12, "Id": "filter_12.txt", "Name": "Dandelion Sprout's Anti-Malware List", "Category": "Security" },
  { "RefId": 55, "Id": "filter_55.txt", "Name": "HaGeZi's Badware Hoster Blocklist", "Category": "Security" },
  { "RefId": 71, "Id": "filter_71.txt", "Name": "HaGeZi's DNS Rebind Protection", "Category": "Security" },
  { "RefId": 54, "Id": "filter_54.txt", "Name": "HaGeZi's DynDNS Blocklist", "Category": "Security" },
  { "RefId": 52, "Id": "filter_52.txt", "Name": "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass", "Category": "Security" },
  { "RefId": 56, "Id": "filter_56.txt", "Name": "HaGeZi's The World's Most Abused TLDs", "Category": "Security" },
  { "RefId": 44, "Id": "filter_44.txt", "Name": "HaGeZi's Threat Intelligence Feeds", "Category": "Security" },
  { "RefId": 68, "Id": "filter_68.txt", "Name": "HaGeZi's URL Shortener Blocklist", "Category": "Security" },
  { "RefId": 8, "Id": "filter_8.txt", "Name": "NoCoin Filter List", "Category": "Security" },
  { "RefId": 18, "Id": "filter_18.txt", "Name": "Phishing Army", "Category": "Security" },
  { "RefId": 10, "Id": "filter_10.txt", "Name": "Scam Blocklist by DurableNapkin", "Category": "Security" },
  { "RefId": 42, "Id": "filter_42.txt", "Name": "ShadowWhisperer's Malware List", "Category": "Security" },
  { "RefId": 31, "Id": "filter_31.txt", "Name": "Stalkerware Indicators List", "Category": "Security" },
  { "RefId": 9, "Id": "filter_9.txt", "Name": "The Big List of Hacked Malware Web Sites", "Category": "Security" },
  { "RefId": 50, "Id": "filter_50.txt", "Name": "uBlock filters - Badware risks", "Category": "Security" },
  { "RefId": 11, "Id": "filter_11.txt", "Name": "Malicious URL Blocklist (URLHaus)", "Category": "Security" }
]
JSON

python3 "$ROOT_DIR/compiler.py" \
  --base-url "$BASE_URL" \
  --lists-json "$LISTS_JSON" \
  --manifest "$MANIFEST" \
  --lists-dir "$LISTS_DIR" \
  --cache-dir "$CACHE_DIR" \
  --blocklist "$ROOT_DIR/blocklist.txt" \
  --diffs "$ROOT_DIR/diffs.txt" \
  --readme "$ROOT_DIR/README.md" \
  --anchor "$ANCHOR_NAME" \
  --excluded-ids "$EXCLUDED_IDS" \
  --concurrency "$CONCURRENCY" \
  --parse-mode "$PARSE_MODE" \
  $( [[ "$NO_CACHE" == "1" ]] && echo "--no-cache" ) \
  $( [[ "$KEEP_LISTS" == "1" ]] && echo "--keep-lists" )

rm -rf "$TEMP_DIR"
