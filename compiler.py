#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
import gzip
import hashlib
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import shutil


DOMAIN_RE = re.compile(
    r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)
IP_RE = re.compile(r"^\^?(\d{1,3}\.){3}\d{1,3}")
HOSTS_RE = re.compile(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+(.+)")
URL_RE = re.compile(r"^(https?://|www\.)", re.IGNORECASE)
REGEX_SIMPLIFY_RE = re.compile(r"^\^/\^([a-z0-9\.-]+)\\\.([a-z0-9\.-]+)\$/$")


def parse_args():
    parser = argparse.ArgumentParser(description="sleepy list compiler (bash runner)")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--lists-json", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--lists-dir", required=True)
    parser.add_argument("--cache-dir")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--keep-lists", action="store_true")
    parser.add_argument("--blocklist", required=True)
    parser.add_argument("--diffs", required=True)
    parser.add_argument("--readme", required=True)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--excluded-ids", required=True)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--parse-mode", default="thread")
    return parser.parse_args()


def load_lists_config(path, base_url):
    with open(path, "r", encoding="utf-8") as handle:
        entries = json.load(handle)

    all_entries = []
    for entry in entries:
        url = entry.get("ExternalUrl") or f"{base_url}/{entry['Id']}"
        homepage = entry.get("Homepage") or ""
        all_entries.append(
            {
                "filename": entry["Id"],
                "name": entry["Name"],
                "category": entry["Category"],
                "ref_id": entry["RefId"],
                "url": url,
                "homepage": homepage,
            }
        )
    return all_entries


def build_manifest_rows(all_entries, excluded_ids):
    rows = []
    for entry in all_entries:
        if entry["ref_id"] in excluded_ids:
            continue
        rows.append(
            [
                entry["filename"],
                entry["name"],
                entry["category"],
                str(entry["ref_id"]),
                entry["url"],
                entry["homepage"],
            ]
        )
    return rows


def load_cache_meta(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def compute_sha256(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def safe_sha256(path):
    try:
        return compute_sha256(path)
    except OSError:
        return ""


def load_parsed_cache(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
        rules = {}
        for key, items in data.get("rules", {}).items():
            rules[key] = set(items)
        return {
            "name": data.get("name"),
            "filename": data.get("filename"),
            "rules": rules,
            "stats": data.get("stats", {}),
        }
    except (OSError, json.JSONDecodeError):
        return None


def load_registry_cache(cache_path):
    if not cache_path:
        return {}, {}
    payload = load_cache_meta(cache_path)
    filters = payload.get("filters")
    if not isinstance(filters, dict):
        return {}, payload
    return filters, payload


def parse_task(entry, lists_dir, meta, cache_entry, parse_cache_dir):
    filename = entry["filename"]
    path = os.path.join(lists_dir, filename)
    if parse_cache_dir and cache_entry:
        if meta.get("etag") and cache_entry.get("etag") == meta.get("etag"):
            cached = load_parsed_cache(cache_entry.get("path", ""))
            if cached:
                return cached, True, None
        if meta.get("last_modified") and cache_entry.get("last_modified") == meta.get("last_modified"):
            cached = load_parsed_cache(cache_entry.get("path", ""))
            if cached:
                return cached, True, None
        if (
            meta.get("status") == "downloaded"
            and not meta.get("etag")
            and not meta.get("last_modified")
            and cache_entry.get("sha256")
            and os.path.exists(path)
        ):
            sha256 = compute_sha256(path)
            if sha256 == cache_entry.get("sha256"):
                cached = load_parsed_cache(cache_entry.get("path", ""))
                if cached:
                    return cached, True, None
        if meta.get("status") == "cached" and cache_entry.get("sha256") and os.path.exists(path):
            sha256 = compute_sha256(path)
            if sha256 == cache_entry.get("sha256"):
                cached = load_parsed_cache(cache_entry.get("path", ""))
                if cached:
                    return cached, True, None

    result, sha256 = parse_list(entry, lists_dir)
    if not result:
        return None, False, None

    update = None
    if parse_cache_dir and sha256:
        cache_path = os.path.join(parse_cache_dir, f"{filename}-{sha256}.json.gz")
        try:
            save_parsed_cache(cache_path, result)
            update = {
                "sha256": sha256,
                "path": cache_path,
                "etag": meta.get("etag"),
                "last_modified": meta.get("last_modified"),
                "url": meta.get("url"),
            }
        except OSError:
            update = None
    return result, False, update


def load_run_state(path):
    state = load_cache_meta(path)
    if isinstance(state, dict) and state.get("version") == 1:
        return state
    return {}


def save_parsed_cache(path, result):
    payload = {
        "name": result["name"],
        "filename": result["filename"],
        "rules": {
            "Domains": list(result["rules"]["Domains"]),
            "Wildcards": list(result["rules"]["Wildcards"]),
            "Regex": list(result["rules"]["Regex"]),
            "IPRanges": list(result["rules"]["IPRanges"]),
            "Complex": list(result["rules"]["Complex"]),
        },
        "stats": result["stats"],
    }
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)


def save_cache_meta(path, data):
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
    except OSError:
        return


def write_manifest(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerows(rows)


def load_manifest(path):
    entries = []
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        for row in reader:
            if not row:
                continue
            padded = row + [""] * (6 - len(row))
            filename, name, category, ref_id, url, homepage = padded[:6]
            entries.append(
                {
                    "filename": filename,
                    "name": name,
                    "category": category,
                    "ref_id": int(ref_id) if ref_id else None,
                    "url": url,
                    "homepage": homepage,
                }
            )
    return entries


def normalize_rule(line):
    if not line:
        return None, None
    if line[0] in ("!", "#"):
        return None, None
    if line.startswith("@@"):
        return "Exception", None

    clean = line.strip()
    rule_type = None
    rule = None

    if clean.startswith("/") and clean.endswith("/") and len(clean) > 1:
        rule_type = "Regex"
        rule = clean
    elif IP_RE.match(clean) and not clean.startswith("/"):
        rule_type = "IPRanges"
        rule = clean
    elif clean.startswith("||"):
        if "$" in clean:
            rule_type = "Complex"
            rule = clean
        else:
            extracted = clean[2:].split("^", 1)[0].strip()
            if "*" in extracted:
                rule_type = "Wildcards"
                rule = extracted
            else:
                rule_type = "Domains"
                rule = extracted
    else:
        host_match = HOSTS_RE.match(clean)
        if host_match:
            rule_type = "Domains"
            rule = host_match.group(2).split("#", 1)[0].strip()
        elif URL_RE.match(clean):
            if not clean.startswith("http"):
                clean = f"http://{clean}"
            try:
                parsed = urllib.parse.urlparse(clean)
            except ValueError:
                return None, None
            if parsed.hostname:
                rule_type = "Domains"
                rule = parsed.hostname
        elif DOMAIN_RE.match(clean) and not re.search(r"[#\$\^\|\*]", clean):
            rule_type = "Domains"
            rule = clean
        elif re.search(r"[\$\^]", clean) or ("/" in clean and not clean.startswith("/")):
            rule_type = "Complex"
            rule = clean

    if not rule_type or not rule:
        return None, None

    rule = rule.rstrip(".").lower()
    if rule_type in ("Domains", "Wildcards"):
        if len(rule) <= 3 or "." not in rule or " " in rule:
            return None, None

    return rule_type, rule


def parse_list(entry, lists_dir):
    path = os.path.join(lists_dir, entry["filename"])
    if not os.path.exists(path):
        return None, None

    hasher = hashlib.sha256()
    rules = {
        "Domains": set(),
        "Wildcards": set(),
        "Regex": set(),
        "IPRanges": set(),
        "Complex": set(),
    }
    stats = {"total_lines": 0, "parsed_rules": 0, "exceptions": 0}

    try:
        with open(path, "rb") as handle:
            for raw in handle:
                hasher.update(raw)
                stats["total_lines"] += 1
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                rule_type, rule = normalize_rule(line)
                if rule_type == "Exception":
                    stats["exceptions"] += 1
                    continue
                if rule_type and rule:
                    rules[rule_type].add(rule)
                    stats["parsed_rules"] += 1
    except OSError:
        return None, None

    if any(rules[key] for key in rules):
        return (
            {
                "name": entry["name"],
                "filename": entry["filename"],
                "rules": rules,
                "stats": stats,
            },
            hasher.hexdigest(),
        )
    return None, None


def add_rules(master, rules, source):
    added = 0
    for rule in rules:
        if rule not in master:
            master[rule] = source
            added += 1
    return added


def domain_has_wildcard(domain, suffixes):
    parts = domain.split(".")
    for idx in range(1, len(parts)):
        suffix = ".".join(parts[idx:])
        if suffix in suffixes:
            return True
    return False


def update_readme_credits(
    readme_path,
    credit_order,
    anchor,
    list_meta_by_name,
    all_list_names,
    excluded_names,
    superseded_map,
    cache_dir=None,
    no_cache=False,
):
    if not os.path.exists(readme_path):
        return

    registry_meta = {}
    cache_path = None
    cached_filters = {}
    cached_payload = {}
    if cache_dir and not no_cache:
        cache_path = os.path.join(cache_dir, "registry_meta.json")
        cached_filters, cached_payload = load_registry_cache(cache_path)
    headers = {"User-Agent": "sleepy-list/1.0"}
    if cached_payload.get("etag"):
        headers["If-None-Match"] = cached_payload["etag"]
    if cached_payload.get("last_modified"):
        headers["If-Modified-Since"] = cached_payload["last_modified"]
    request = urllib.request.Request(
        "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
            for filt in data.get("filters", []):
                registry_meta[int(filt["filterId"])] = {
                    "download": filt.get("downloadUrl"),
                    "homepage": filt.get("homepage"),
                }
            if cache_path:
                payload = {
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                    "filters": {str(k): v for k, v in registry_meta.items()},
                }
                save_cache_meta(cache_path, payload)
    except urllib.error.HTTPError as err:
        if err.code == 304 and cached_filters:
            registry_meta = {
                int(k): v
                for k, v in cached_filters.items()
                if isinstance(v, dict)
            }
        elif cached_filters:
            registry_meta = {
                int(k): v
                for k, v in cached_filters.items()
                if isinstance(v, dict)
            }
        else:
            print("  [!] Failed to load registry metadata; using local URLs.")
    except Exception:
        if cached_filters:
            registry_meta = {
                int(k): v
                for k, v in cached_filters.items()
                if isinstance(v, dict)
            }
        else:
            print("  [!] Failed to load registry metadata; using local URLs.")

    start_marker = "<!-- sleepy-list:credits:start -->"
    end_marker = "<!-- sleepy-list:credits:end -->"
    with open(readme_path, "r", encoding="utf-8") as handle:
        lines = [line.rstrip("\n") for line in handle]

    try:
        start_index = lines.index(start_marker)
        end_index = lines.index(end_marker)
    except ValueError:
        print("  [!] README credits markers not found; skipping update.")
        return

    if end_index <= start_index:
        print("  [!] README credits markers invalid; skipping update.")
        return

    def resolve_links(name):
        meta = list_meta_by_name.get(name, {})
        ref_id = meta.get("ref_id")
        download = meta.get("download")
        homepage = meta.get("homepage")
        if ref_id is not None and ref_id in registry_meta:
            download = registry_meta[ref_id].get("download") or download
            homepage = registry_meta[ref_id].get("homepage") or homepage
        list_link = f"[list]({download})" if download else "list"
        creator_link = f"[creator]({homepage})" if homepage else "creator"
        return list_link, creator_link

    def build_line(name, suffix=None, display_name=None):
        list_link, creator_link = resolve_links(name)
        shown = display_name or name
        line = f"- {shown} - {list_link} - {creator_link}"
        if suffix:
            line = f"{line} - {suffix}"
        return line

    block = [start_marker]

    prefix_re = re.compile(r"^[A-Z]{2,3}: ")

    def sort_key(name):
        return (1 if prefix_re.match(name) else 0, name.casefold())

    used_names = sorted({anchor, *credit_order}, key=sort_key)
    block.append("Used lists (included in blocklist):")
    for name in used_names:
        display = f"{name} (anchor)" if name == anchor else name
        block.append(build_line(name, display_name=display))

    superseded_pairs = sorted(
        superseded_map.items(),
        key=lambda item: (sort_key(item[0]), sort_key(item[1])),
    )
    if superseded_pairs:
        block.append("")
        block.append("Superseded lists (auto-skipped because a larger list covers them):")
        for name, superseder in superseded_pairs:
            superseder_list, superseder_creator = resolve_links(superseder)
            suffix = f"superseded by: {superseder} - {superseder_list} - {superseder_creator}"
            block.append(build_line(name, suffix=suffix))

    excluded_only = sorted(
        (name for name in excluded_names if name in all_list_names),
        key=sort_key,
    )
    if excluded_only:
        block.append("")
        block.append("Excluded lists (skipped via SLEEPY_LIST_EXCLUDED_IDS):")
        for name in excluded_only:
            block.append(build_line(name))

    unused_names = sorted(
        (
            name
            for name in all_list_names
            if name not in used_names
            and name not in superseded_map
            and name not in excluded_names
        ),
        key=sort_key,
    )
    if unused_names:
        block.append("")
        block.append("Unused lists (available but not selected after stacking):")
        for name in unused_names:
            block.append(build_line(name))
    block.append(end_marker)

    new_lines = lines[:start_index] + block + lines[end_index + 1 :]
    if new_lines != lines:
        with open(readme_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(new_lines) + "\n")
        print("  [OK] Updated README credits.")
    else:
        print("  [OK] README credits already up to date.")


def update_readme_manifest(readme_path, manifest_hash):
    if not os.path.exists(readme_path):
        return

    start_marker = "<!-- sleepy-list:manifest:start -->"
    end_marker = "<!-- sleepy-list:manifest:end -->"
    with open(readme_path, "r", encoding="utf-8") as handle:
        lines = [line.rstrip("\n") for line in handle]

    try:
        start_index = lines.index(start_marker)
        end_index = lines.index(end_marker)
    except ValueError:
        print("  [!] README manifest markers not found; skipping update.")
        return

    if end_index <= start_index:
        print("  [!] README manifest markers invalid; skipping update.")
        return

    block = [start_marker, f"- manifest hash: `{manifest_hash}`", end_marker]
    new_lines = lines[:start_index] + block + lines[end_index + 1 :]
    if new_lines != lines:
        with open(readme_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(new_lines) + "\n")
        print("  [OK] Updated README manifest hash.")


def main():
    args = parse_args()
    excluded_ids = {int(x) for x in args.excluded_ids.split(",") if x}
    os.makedirs(args.lists_dir, exist_ok=True)
    cache_dir = None if args.no_cache else (args.cache_dir or args.lists_dir)
    cache_meta_path = None
    parse_cache_index_path = None
    parse_cache_index = {}
    cache_meta = {}
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        cache_meta_path = os.path.join(cache_dir, "metadata.json")
        cache_meta = load_cache_meta(cache_meta_path)
        parse_cache_index_path = os.path.join(cache_dir, "parsed_index.json")
        parse_cache_index = load_cache_meta(parse_cache_index_path)

    print("[1/7] Preparing manifest...")
    all_entries = load_lists_config(args.lists_json, args.base_url)
    manifest_rows = build_manifest_rows(all_entries, excluded_ids)
    write_manifest(args.manifest, manifest_rows)
    manifest_hash = safe_sha256(args.manifest)

    entries = load_manifest(args.manifest)
    category_map = {entry["name"]: entry["category"] for entry in entries}
    list_meta_by_name = {
        entry["name"]: {
            "ref_id": entry["ref_id"],
            "download": entry["url"],
            "homepage": entry["homepage"],
        }
        for entry in all_entries
    }
    all_list_names = [entry["name"] for entry in all_entries]
    excluded_names = {
        entry["name"] for entry in all_entries if entry["ref_id"] in excluded_ids
    }

    run_state_path = None
    run_state = {}
    lists_json_hash = ""
    compiler_hash = ""
    current_files = []
    if cache_dir and not args.no_cache:
        run_state_path = os.path.join(cache_dir, "run_state.json")
        run_state = load_run_state(run_state_path)
        lists_json_hash = safe_sha256(args.lists_json)
        compiler_hash = safe_sha256(os.path.abspath(__file__))
        current_files = sorted(entry["filename"] for entry in entries)

    print("[2/7] Downloading lists...")

    def download_one(entry):
        url = entry["url"]
        dest = os.path.join(args.lists_dir, entry["filename"])
        headers = {"User-Agent": "sleepy-list/1.0"}
        cache_info = cache_meta.get(entry["filename"])
        if cache_info and cache_info.get("url") != url:
            cache_info = None
        if not args.no_cache and cache_info and os.path.exists(dest):
            if cache_info.get("etag"):
                headers["If-None-Match"] = cache_info["etag"]
            if cache_info.get("last_modified"):
                headers["If-Modified-Since"] = cache_info["last_modified"]
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                tmp_dest = f"{dest}.tmp"
                with open(tmp_dest, "wb") as handle:
                    shutil.copyfileobj(response, handle)
                os.replace(tmp_dest, dest)
                return (
                    "downloaded",
                    entry["filename"],
                    {
                        "etag": response.headers.get("ETag"),
                        "last_modified": response.headers.get("Last-Modified"),
                        "url": url,
                    },
                )
        except urllib.error.HTTPError as err:
            if err.code == 304 and os.path.exists(dest):
                return ("cached", entry["filename"], None)
            return ("failed", entry["filename"], None)
        except Exception:
            if os.path.exists(dest):
                os.remove(dest)
            return ("failed", entry["filename"], None)

    downloaded = 0
    cached = 0
    failed = 0
    download_status = {}
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, 16))) as executor:
        futures = {executor.submit(download_one, entry): entry for entry in entries}
        for future in as_completed(futures):
            entry = futures[future]
            status, filename, meta_update = future.result()
            download_status[filename] = status
            if status == "downloaded":
                downloaded += 1
                if meta_update is not None:
                    cache_meta[filename] = meta_update
            elif status == "cached":
                cached += 1
            else:
                failed += 1
                print(f"  [!] Failed: {entry['name']}")
    if cache_meta_path and not args.no_cache:
        save_cache_meta(cache_meta_path, cache_meta)
    if failed:
        raise SystemExit(f"Failed to download {failed} lists; aborting to avoid stale output.")
    print(f"  [OK] Successfully downloaded {downloaded} lists ({cached} cached)")

    if run_state_path and run_state and not args.no_cache:
        outputs_exist = all(
            os.path.exists(path)
            for path in (args.blocklist, args.diffs, args.readme)
        )
        cached_only = True
        if run_state.get("list_hashes"):
            previous_hashes = run_state.get("list_hashes", {})
            for entry in entries:
                filename = entry["filename"]
                status = download_status.get(filename)
                if status == "cached":
                    continue
                path = os.path.join(args.lists_dir, filename)
                if os.path.exists(path):
                    current_hash = safe_sha256(path)
                    if current_hash and current_hash == previous_hashes.get(filename):
                        continue
                cached_only = False
                break
        else:
            cached_only = all(
                download_status.get(entry["filename"]) == "cached" for entry in entries
            )
        same_state = (
            run_state.get("lists_json_sha256") == lists_json_hash
            and run_state.get("compiler_sha256") == compiler_hash
            and run_state.get("anchor") == args.anchor
            and run_state.get("excluded_ids") == args.excluded_ids
            and run_state.get("files") == current_files
        )
        if outputs_exist and cached_only and same_state:
            print("[3/7] Parsing lists...")
            print("  [OK] No list or config changes detected; skipping parse/build.")
            update_readme_manifest(args.readme, manifest_hash)
            return

    print("[3/7] Parsing lists...")
    parsed_lists = {}
    total_parsed = 0
    total_exceptions = 0
    parse_targets = [
        entry
        for entry in entries
        if os.path.exists(os.path.join(args.lists_dir, entry["filename"]))
    ]

    download_meta_by_filename = {}
    for entry in entries:
        meta = cache_meta.get(entry["filename"], {}).copy()
        meta["status"] = download_status.get(entry["filename"], "unknown")
        meta.setdefault("url", entry["url"])
        download_meta_by_filename[entry["filename"]] = meta

    parse_cache_dir = None
    if cache_dir and not args.no_cache:
        parse_cache_dir = os.path.join(cache_dir, "parsed")
        os.makedirs(parse_cache_dir, exist_ok=True)

    workers = max(1, min(args.concurrency, 16))
    parse_mode = args.parse_mode.lower()
    if parse_mode == "auto":
        parse_mode = "process" if workers > 1 else "thread"
    if parse_mode == "process" and sys.platform == "win32":
        parse_mode = "thread"
    executor_cls = ProcessPoolExecutor if parse_mode == "process" else ThreadPoolExecutor

    cached_parses = 0
    parse_cache_updates = {}
    with executor_cls(max_workers=workers) as executor:
        futures = {}
        for entry in parse_targets:
            filename = entry["filename"]
            meta = download_meta_by_filename.get(filename, {})
            cache_entry = parse_cache_index.get(filename)
            future = executor.submit(
                parse_task,
                entry,
                args.lists_dir,
                meta,
                cache_entry,
                parse_cache_dir,
            )
            futures[future] = entry
        completed = 0
        total_jobs = len(futures)
        for future in as_completed(futures):
            result, cache_hit, cache_update = future.result()
            completed += 1
            if result:
                parsed_lists[result["name"]] = result
                total_parsed += result["stats"]["parsed_rules"]
                total_exceptions += result["stats"]["exceptions"]
                if cache_hit:
                    cached_parses += 1
                if cache_update:
                    parse_cache_updates[result["filename"]] = cache_update
            if total_jobs:
                percent = round((completed / total_jobs) * 100)
                if result:
                    print(
                        f"  [OK] [{percent}%] {result['name']}: {result['stats']['parsed_rules']} rules"
                    )

    if parse_cache_index_path and parse_cache_updates and not args.no_cache:
        parse_cache_index.update(parse_cache_updates)
        save_cache_meta(parse_cache_index_path, parse_cache_index)

    if parse_cache_dir and parse_cache_index_path and not args.no_cache:
        referenced = {
            entry.get("path")
            for entry in parse_cache_index.values()
            if isinstance(entry, dict) and entry.get("path")
        }
        if not args.keep_lists:
            for entry in parse_targets:
                path = os.path.join(args.lists_dir, entry["filename"])
                cache_entry = parse_cache_index.get(entry["filename"], {})
                if cache_entry.get("path") and os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        for root, _, files in os.walk(parse_cache_dir):
            for name in files:
                path = os.path.join(root, name)
                if path not in referenced:
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    cache_note = f" ({cached_parses} cached)" if cached_parses else ""
    print(f"  [OK] Parsed {total_parsed} rules from {len(parsed_lists)} lists{cache_note}")

    print("[4/7] Stacking lists (tracking primary source)...")
    anchor_name = args.anchor
    if anchor_name not in parsed_lists:
        raise SystemExit(f"Anchor list '{anchor_name}' not found.")

    master_domains = {}
    master_wildcards = {}
    master_regex = {}
    master_ipranges = {}
    master_complex = {}

    anchor = parsed_lists[anchor_name]
    add_rules(master_domains, anchor["rules"]["Domains"], anchor_name)
    add_rules(master_wildcards, anchor["rules"]["Wildcards"], anchor_name)
    add_rules(master_regex, anchor["rules"]["Regex"], anchor_name)
    add_rules(master_ipranges, anchor["rules"]["IPRanges"], anchor_name)
    add_rules(master_complex, anchor["rules"]["Complex"], anchor_name)

    candidates = [
        name
        for name in parsed_lists.keys()
        if name != anchor_name and category_map.get(name) != "Regional"
    ]

    if "1Hosts (Xtra)" in parsed_lists and "1Hosts (Lite)" in candidates:
        candidates.remove("1Hosts (Lite)")
        print("  - Culled: 1Hosts (Lite) [superseded by Xtra]")
    if "OISD Blocklist Big" in parsed_lists and "OISD Blocklist Small" in candidates:
        candidates.remove("OISD Blocklist Small")
        print("  - Culled: OISD Blocklist Small [superseded by Big]")
    if anchor_name == "HaGeZi's Pro++ Blocklist":
        for name in ("HaGeZi's Ultimate Blocklist", "HaGeZi's Normal Blocklist", "HaGeZi's Pro Blocklist"):
            if name in candidates:
                candidates.remove(name)
                print(f"  - Culled: {name} [superseded by Pro++]")

    list_contributions = []
    while candidates:
        best_name = None
        max_unique = 0
        for name in candidates:
            rules = parsed_lists[name]["rules"]
            unique = (
                len(rules["Domains"] - master_domains.keys())
                + len(rules["Wildcards"] - master_wildcards.keys())
                + len(rules["Regex"] - master_regex.keys())
                + len(rules["IPRanges"] - master_ipranges.keys())
                + len(rules["Complex"] - master_complex.keys())
            )
            if unique > max_unique:
                max_unique = unique
                best_name = name
        if not best_name or max_unique == 0:
            break

        winner = parsed_lists[best_name]
        total_added = 0
        total_added += add_rules(master_domains, winner["rules"]["Domains"], best_name)
        total_added += add_rules(master_wildcards, winner["rules"]["Wildcards"], best_name)
        total_added += add_rules(master_regex, winner["rules"]["Regex"], best_name)
        total_added += add_rules(master_ipranges, winner["rules"]["IPRanges"], best_name)
        total_added += add_rules(master_complex, winner["rules"]["Complex"], best_name)
        list_contributions.append(
            {
                "name": best_name,
                "unique": total_added,
                "category": category_map.get(best_name, ""),
            }
        )
        candidates.remove(best_name)
        print(f"  + {best_name} (+{total_added})")

    print("[5/7] Applying optimizations...")
    wildcard_suffixes = {w.lstrip("*").lstrip(".") for w in master_wildcards.keys()}
    wildcard_covered = []
    for domain in master_domains.keys():
        if domain_has_wildcard(domain, wildcard_suffixes):
            wildcard_covered.append(domain)
    for domain in wildcard_covered:
        master_domains.pop(domain, None)
    print(f"  [OK] Removed {len(wildcard_covered)} covered by wildcards")

    domain_set = set(master_domains.keys())
    tree_removed = []
    for domain in domain_set:
        parts = domain.split(".")
        for idx in range(1, len(parts)):
            parent = ".".join(parts[idx:])
            if parent in domain_set:
                tree_removed.append(domain)
                break
    for domain in tree_removed:
        master_domains.pop(domain, None)
    print(f"  [OK] Tree shaking removed {len(tree_removed)} redundant subdomains")

    simplified_regex = {}
    regex_simplified = 0
    for rule, source in master_regex.items():
        match = REGEX_SIMPLIFY_RE.match(rule)
        if match:
            simple = (match.group(1) + "." + match.group(2)).replace("\\.", ".")
            if simple not in master_domains:
                master_domains[simple] = source
                regex_simplified += 1
        else:
            simplified_regex[rule] = source
    master_regex = simplified_regex
    print(f"  [OK] Simplified {regex_simplified} regex patterns")

    wildcards_to_remove = [
        wildcard
        for wildcard in master_wildcards.keys()
        if wildcard.lstrip("*").lstrip(".") in master_domains
    ]
    for wildcard in wildcards_to_remove:
        master_wildcards.pop(wildcard, None)
    print(f"  [OK] Removed {len(wildcards_to_remove)} cross-type duplicates")

    print("[6/7] Generating source-aware diff...")
    previous_rules = {}
    previous_source_order = []
    if os.path.exists(args.blocklist):
        current_source = "Unknown"
        with open(args.blocklist, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                header_match = re.match(r"^! \[(.+?)\] - \d+ rules$", line)
                if header_match:
                    candidate = header_match.group(1)
                    if candidate in list_meta_by_name:
                        current_source = candidate
                        if current_source not in previous_source_order:
                            previous_source_order.append(current_source)
                    continue
                compact_match = re.match(r"^! (.+?) (\d+)$", line)
                if compact_match:
                    candidate = compact_match.group(1)
                    if candidate in list_meta_by_name:
                        current_source = candidate
                        if current_source not in previous_source_order:
                            previous_source_order.append(current_source)
                    continue
                if line.startswith("!"):
                    continue
                if line not in previous_rules:
                    previous_rules[line] = current_source

    new_rules = {}
    for rule, source in master_domains.items():
        new_rules[f"||{rule}^"] = source
    for rule, source in master_wildcards.items():
        new_rules[f"||{rule}^"] = source
    for rule, source in master_regex.items():
        new_rules[rule] = source
    for rule, source in master_ipranges.items():
        new_rules[rule] = source
    for rule, source in master_complex.items():
        new_rules[rule] = source

    removed_by_source = {}
    moved_by_source = {}
    added_by_source = {}
    added = removed = moved = 0

    def add_bucket(bucket, source, value):
        bucket.setdefault(source, []).append(value)

    for rule, old_source in previous_rules.items():
        if rule not in new_rules:
            add_bucket(removed_by_source, old_source, rule)
            removed += 1

    for rule, new_source in new_rules.items():
        if rule not in previous_rules:
            add_bucket(added_by_source, new_source, rule)
            added += 1
        elif previous_rules[rule] != new_source:
            old_source = previous_rules[rule]
            add_bucket(moved_by_source, old_source, f"{rule} [Moved: {old_source} -> {new_source}]")
            moved += 1

    diff_lines = [
        "! =========================================================================",
        f"! sleepy list diff report: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "! =========================================================================",
        "",
        f"! SUMMARY: Added {added} | Removed {removed} | Moved {moved}",
        "! ORDER: Anchor + contributors, then legacy-only lists",
        "",
        "! --- CHANGES BY LIST (ORDERED) ---",
    ]

    ordered_sources = []
    source_order = [anchor_name] + [
        entry["name"]
        for entry in sorted(list_contributions, key=lambda item: item["unique"], reverse=True)
    ]
    for source in source_order:
        if source and source not in ordered_sources:
            ordered_sources.append(source)
    for source in previous_source_order:
        if source not in ordered_sources:
            ordered_sources.append(source)
    all_change_sources = (
        list(removed_by_source.keys())
        + list(moved_by_source.keys())
        + list(added_by_source.keys())
    )
    for source in sorted(set(all_change_sources)):
        if source not in ordered_sources:
            ordered_sources.append(source)

    for source in ordered_sources:
        removed_items = removed_by_source.get(source, [])
        moved_items = moved_by_source.get(source, [])
        added_items = added_by_source.get(source, [])
        if not removed_items and not moved_items and not added_items:
            continue
        diff_lines.append(
            f"! [{source}] Removed: {len(removed_items)} | Moved: {len(moved_items)} | Added: {len(added_items)}"
        )
        for item in sorted(removed_items):
            diff_lines.append(f"- {item}")
        for item in sorted(moved_items):
            diff_lines.append(f"~ {item}")
        for item in sorted(added_items):
            diff_lines.append(f"+ {item}")
        diff_lines.append("")

    if previous_rules:
        if added == 0 and removed == 0 and moved == 0 and os.path.exists(args.diffs):
            print("  [OK] No changes detected; leaving diffs as-is.")
        else:
            with open(args.diffs, "w", encoding="utf-8") as handle:
                handle.write("\n".join(diff_lines) + "\n")
            print(f"  [OK] Saved diffs to: {args.diffs}")
    else:
        with open(args.diffs, "w", encoding="utf-8") as handle:
            handle.write("! No previous blocklist found to compare against.\n")
        print("  [!] Skipped diff generation (no previous file)")

    print("[7/7] Writing blocklist...")
    rules_by_source = {}

    def add_to_source(rules_map, prefix="", suffix=""):
        for rule, source in rules_map.items():
            rules_by_source.setdefault(source, []).append(f"{prefix}{rule}{suffix}")

    add_to_source(master_complex)
    add_to_source(master_regex)
    add_to_source(master_ipranges)
    add_to_source(master_wildcards, "||", "^")
    add_to_source(master_domains, "||", "^")

    blocklist_lines = []
    for source in sorted(rules_by_source.keys()):
        rules = rules_by_source.get(source)
        if not rules:
            continue
        rules_sorted = sorted(rules)
        blocklist_lines.append(f"! {source} {len(rules_sorted)}")
        blocklist_lines.extend(rules_sorted)

    with open(args.blocklist, "w", encoding="utf-8") as handle:
        handle.write("\n".join(blocklist_lines) + "\n")
    print(f"  [OK] Saved blocklist to: {args.blocklist}")

    print("README:")
    update_readme_manifest(args.readme, manifest_hash)
    credit_order = [entry["name"] for entry in sorted(list_contributions, key=lambda item: item["unique"], reverse=True)]
    superseded_map = {}
    if "1Hosts (Xtra)" in all_list_names and "1Hosts (Lite)" in all_list_names:
        superseded_map["1Hosts (Lite)"] = "1Hosts (Xtra)"
    if "OISD Blocklist Big" in all_list_names and "OISD Blocklist Small" in all_list_names:
        superseded_map["OISD Blocklist Small"] = "OISD Blocklist Big"
    if anchor_name == "HaGeZi's Pro++ Blocklist":
        for name in (
            "HaGeZi's Ultimate Blocklist",
            "HaGeZi's Normal Blocklist",
            "HaGeZi's Pro Blocklist",
        ):
            if name in all_list_names:
                superseded_map[name] = anchor_name

    update_readme_credits(
        args.readme,
        credit_order,
        anchor_name,
        list_meta_by_name,
        all_list_names,
        excluded_names,
        superseded_map,
        cache_dir=cache_dir,
        no_cache=args.no_cache,
    )

    if run_state_path and not args.no_cache:
        if not lists_json_hash:
            lists_json_hash = safe_sha256(args.lists_json)
        if not compiler_hash:
            compiler_hash = safe_sha256(os.path.abspath(__file__))
        current_files = sorted(entry["filename"] for entry in entries)
        list_hashes = {}
        for entry in entries:
            cache_entry = parse_cache_index.get(entry["filename"], {})
            if isinstance(cache_entry, dict):
                list_hashes[entry["filename"]] = cache_entry.get("sha256")
        run_state = {
            "version": 1,
            "lists_json_sha256": lists_json_hash,
            "compiler_sha256": compiler_hash,
            "anchor": args.anchor,
            "excluded_ids": args.excluded_ids,
            "files": current_files,
            "list_hashes": list_hashes,
        }
        save_cache_meta(run_state_path, run_state)


if __name__ == "__main__":
    main()
