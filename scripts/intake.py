#!/usr/bin/env python3
"""Find RPMs newly released on OpenRepos and queue them for scanning.

usage: intake.py <state.json>

Reads the OpenRepos app listing (most recently updated first), visits the
page of every app updated since the last run, and queues the RPMs uploaded
with that update. At most INTAKE_MAX_SCANS are dispatched in any 60 minutes,
however often this runs, and one at a time: each scan is started only once
the previous one has finished. The rest wait in the queue.

The first run only records the current time as the starting point: packages
released before Coastguard started watching are not scanned.

Environment:
  INTAKE_MAX_SCANS  scans dispatched per rolling hour (default 5)
  INTAKE_DRY_RUN    print what would be dispatched, dispatch nothing
"""
import datetime
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

SITE = "https://openrepos.net"
USER_AGENT = "Coastguard (+https://github.com/SpecSierra/Coastguard)"
CRAWL_DELAY = 10          # seconds, from the site's robots.txt
MAX_PAGES = 5             # listing pages read to catch up after downtime
MAX_APPS = 15             # app pages visited per run
MAX_SCANS = int(os.environ.get("INTAKE_MAX_SCANS", "5"))
SEEN_CAP = 20000
SCAN_WAIT = 20 * 60       # seconds to wait for one scan before leaving the rest queued
# File dates on the app page are site-local time (UTC+3) with minute
# precision, and an upload can precede the app's "updated" stamp. The margin
# only has to be generous: URLs already queued once are never queued again.
SITE_UTC_OFFSET = 3 * 3600
UPLOAD_MARGIN = 6 * 3600

# Only files OpenRepos itself hosts are ever handed to the scanner.
RPM_URL = re.compile(r"https://openrepos\.net/sites/default/files/packages/\d+/[A-Za-z0-9._+~%-]+\.rpm")
FILE_ROW = re.compile(
    r'<a href="(?P<url>[^"]+\.rpm)"[^>]*>[^<]*</a></span></td>\s*<td>[^<]*</td>\s*'
    r"<td>(?P<day>\d\d)/(?P<month>\d\d)/(?P<year>\d{4}) - (?P<hour>\d\d):(?P<minute>\d\d)</td>")

_last_request = 0.0


def fetch(url, headers=None):
    global _last_request
    wait = CRAWL_DELAY - (time.time() - _last_request)
    if wait > 0:
        time.sleep(wait)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8", "replace")
    finally:
        _last_request = time.time()


def updated_apps(cursor):
    """Apps updated after the cursor, oldest first."""
    apps = []
    for page in range(MAX_PAGES):
        # Without this header the API answers with an empty list.
        listing = json.loads(fetch(f"{SITE}/api/v1/apps?page={page}",
                                   {"Warehouse-Platform": "SailfishOS"}))
        if not listing:
            break
        fresh = [a for a in listing if int(a["updated"]) > cursor]
        apps += fresh
        if len(fresh) < len(listing):
            break
    return sorted(apps, key=lambda a: int(a["updated"]))


def parse_files(page):
    """(url, upload time as a UTC epoch) for every RPM attached to an app page."""
    files = []
    for match in FILE_ROW.finditer(page):
        url = html.unescape(match["url"])
        if not RPM_URL.fullmatch(url):
            continue
        local = datetime.datetime(int(match["year"]), int(match["month"]), int(match["day"]),
                                  int(match["hour"]), int(match["minute"]),
                                  tzinfo=datetime.timezone.utc)
        files.append((url, int(local.timestamp()) - SITE_UTC_OFFSET))
    return files


def scans_active():
    """True while any scan run is queued or running."""
    result = subprocess.run(
        ["gh", "run", "list", "--workflow", "scan.yml", "--limit", "20", "--json", "status"],
        capture_output=True, text=True)
    if result.returncode != 0:
        # Unknown is treated as busy: better to wait than to overlap.
        print(f"could not list scan runs: {result.stderr.strip()}", file=sys.stderr)
        return True
    return any(run["status"] != "completed" for run in json.loads(result.stdout))


def wait_for_scans():
    """Returns True once no scan is running, False if that took too long."""
    deadline = time.time() + SCAN_WAIT
    time.sleep(15)  # a freshly dispatched run takes a moment to appear
    while scans_active():
        if time.time() > deadline:
            return False
        time.sleep(20)
    return True


def dispatch(item):
    if os.environ.get("INTAKE_DRY_RUN"):
        print(f"would scan {item['url']}")
        return True
    result = subprocess.run(
        ["gh", "workflow", "run", "scan.yml", "-f", f"rpm_url={item['url']}",
         "-f", f"app_page={item['page']}"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"dispatch failed for {item['url']}: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"scan dispatched: {item['url']}")
    return True


def main():
    state_path = sys.argv[1]
    try:
        with open(state_path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = None
    if state is None:
        state = {"cursor": int(time.time()), "queue": [], "seen": []}
        print("first run: watching for releases from now on, nothing scanned")
    else:
        seen = set(state["seen"])
        try:
            apps = updated_apps(state["cursor"])
        except (urllib.error.URLError, OSError, ValueError) as error:
            print(f"could not read the app listing: {error}", file=sys.stderr)
            apps = []
        print(f"{len(apps)} app(s) updated since the last run")
        for app in apps[:MAX_APPS]:
            page_url = f"{SITE}/node/{int(app['appid'])}"
            try:
                files = parse_files(fetch(page_url))
            except (urllib.error.URLError, OSError) as error:
                # Leave the cursor before this app so the next run retries it.
                print(f"could not read {page_url}: {error}", file=sys.stderr)
                break
            fresh = [url for url, uploaded in files
                     if uploaded >= state["cursor"] - UPLOAD_MARGIN and url not in seen]
            print(f"{app.get('title')!r}: {len(fresh)} new RPM(s) of {len(files)}")
            for url in fresh:
                seen.add(url)
                state["seen"].append(url)
                state["queue"].append({"url": url, "page": page_url, "appid": int(app["appid"]),
                                       "title": str(app.get("title"))[:200]})
            state["cursor"] = int(app["updated"])

    # The limit is per rolling hour, not per run: a manual run shortly before
    # a scheduled one must not double it.
    now = int(time.time())
    recent = [t for t in state.get("dispatched", []) if t > now - 3600]
    budget = max(0, MAX_SCANS - len(recent))
    dry_run = bool(os.environ.get("INTAKE_DRY_RUN"))
    if budget and state["queue"] and not dry_run and scans_active():
        print("a scan is still running; nothing started this time")
        budget = 0
    remaining, sent = [], 0
    for item in state["queue"]:
        if sent < budget and dispatch(item):
            sent += 1
            recent.append(int(time.time()))
            # One at a time: the next scan starts when this one is done.
            if not dry_run and not wait_for_scans():
                print("scan still running after 20 minutes; the rest stay queued")
                budget = 0
        else:
            remaining.append(item)
    state["queue"] = remaining
    state["dispatched"] = recent
    state["seen"] = state["seen"][-SEEN_CAP:]
    state["last_run"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{sent} scan(s) dispatched ({len(recent)} in the last hour, limit {MAX_SCANS}), "
          f"{len(remaining)} waiting in the queue")

    os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
