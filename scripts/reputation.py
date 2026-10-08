#!/usr/bin/env python3
"""Look up the package's hashes on VirusTotal and MalwareBazaar.

usage: reputation.py <report-dir>

Only hashes are sent, never file content. Reads report.json and manifest.tsv,
writes reputation.json. Each service is skipped when its key is not set:
  VT_API_KEY              VirusTotal API key
  MALWAREBAZAAR_AUTH_KEY  abuse.ch Auth-Key
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VT_URL = os.environ.get("VT_API_URL", "https://www.virustotal.com/api/v3/files/")
MB_URL = os.environ.get("MB_API_URL", "https://mb-api.abuse.ch/api/v1/")
# The free VirusTotal tier allows 4 lookups a minute and 500 a day.
VT_MAX_FILES = int(os.environ.get("VT_MAX_FILES", "8"))
VT_INTERVAL = float(os.environ.get("VT_INTERVAL", "15.5"))
MB_MAX_FILES = int(os.environ.get("MB_MAX_FILES", "50"))
# Engines that must agree before a VirusTotal result counts as a detection;
# one or two is usually a heuristic false positive.
VT_THRESHOLD = int(os.environ.get("VT_THRESHOLD", "3"))


def targets(report_dir):
    """The RPM itself, then its executables: launchers first, biggest first."""
    with open(os.path.join(report_dir, "report.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    items, seen = [(report["sha256"], "(the RPM)")], {report["sha256"]}
    elves = []
    try:
        with open(os.path.join(report_dir, "manifest.tsv"), encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 4 and parts[2] == "elf":
                    elves.append((parts[0], int(parts[1]), parts[3]))
    except OSError:
        pass
    elves.sort(key=lambda e: ("/bin/" not in e[2] and "/libexec/" not in e[2], -e[1]))
    for sha256, _, path in elves:
        if sha256 not in seen:
            seen.add(sha256)
            items.append((sha256, path))
    return items


RETRY_WAIT = float(os.environ.get("REPUTATION_RETRY_WAIT", "60"))


def fetch(request):
    """Returns (status code, parsed JSON or None)."""
    # Several scans can run at once and share the per-minute quota, so a
    # rate-limit answer is retried before giving up.
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 4:
                return error.code, None
            time.sleep(RETRY_WAIT)
        except (urllib.error.URLError, OSError, ValueError):
            return 0, None


def virustotal(items, key):
    out = {"status": "ok", "queried": 0, "unknown": 0, "not_queried": 0, "results": []}
    if not key:
        return {"status": "not configured"}
    for index, (sha256, path) in enumerate(items):
        if index >= VT_MAX_FILES:
            out["not_queried"] = len(items) - index
            break
        if index:
            time.sleep(VT_INTERVAL)
        code, body = fetch(urllib.request.Request(VT_URL + sha256, headers={"x-apikey": key}))
        if code == 404:
            out["queried"] += 1
            out["unknown"] += 1
        elif code == 200 and body:
            out["queried"] += 1
            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            out["results"].append({
                "sha256": sha256, "path": path,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "engines": sum(int(v) for v in stats.values() if isinstance(v, int)),
                "last_analysis": attrs.get("last_analysis_date"),
                "link": "https://www.virustotal.com/gui/file/" + sha256,
            })
        else:
            out["status"] = {429: "quota exceeded", 401: "key rejected"}.get(code, f"error (HTTP {code})")
            out["not_queried"] = len(items) - index
            break
    return out


def malwarebazaar(items, key):
    out = {"status": "ok", "queried": 0, "unknown": 0, "not_queried": 0, "results": []}
    if not key:
        return {"status": "not configured"}
    for index, (sha256, path) in enumerate(items):
        if index >= MB_MAX_FILES:
            out["not_queried"] = len(items) - index
            break
        data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        code, body = fetch(urllib.request.Request(MB_URL, data=data, headers={"Auth-Key": key}))
        status = (body or {}).get("query_status")
        if code == 200 and status == "ok" and body.get("data"):
            out["queried"] += 1
            entry = body["data"][0]
            out["results"].append({
                "sha256": sha256, "path": path,
                "signature": entry.get("signature"), "tags": entry.get("tags") or [],
                "first_seen": entry.get("first_seen"),
                "link": "https://bazaar.abuse.ch/sample/" + sha256 + "/",
            })
        elif code == 200 and status in ("hash_not_found", "no_results"):
            out["queried"] += 1
            out["unknown"] += 1
        else:
            out["status"] = {401: "key rejected", 403: "key rejected", 429: "quota exceeded"}.get(
                code, f"error (HTTP {code}, {status})")
            out["not_queried"] = len(items) - index
            break
    return out


def main():
    report_dir = sys.argv[1]
    items = targets(report_dir)
    result = {
        "virustotal": virustotal(items, os.environ.get("VT_API_KEY", "").strip()),
        "malwarebazaar": malwarebazaar(items, os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()),
        "hits": [],
    }
    for entry in result["virustotal"].get("results", []):
        if entry["malicious"] >= VT_THRESHOLD:
            result["hits"].append({
                "source": "VirusTotal", "path": entry["path"], "sha256": entry["sha256"],
                "detail": f"{entry['malicious']} of {entry['engines']} engines call it malicious",
                "link": entry["link"]})
    for entry in result["malwarebazaar"].get("results", []):
        result["hits"].append({
            "source": "MalwareBazaar", "path": entry["path"], "sha256": entry["sha256"],
            "detail": "known malware sample" + (f" ({entry['signature']})" if entry["signature"] else ""),
            "link": entry["link"]})
    with open(os.path.join(report_dir, "reputation.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    for name in ("virustotal", "malwarebazaar"):
        print(f"{name}: {result[name]['status']}, queried {result[name].get('queried', 0)}")
    print(f"hits: {len(result['hits'])}")


if __name__ == "__main__":
    main()
