#!/usr/bin/env python3
"""Store a scan in the results tree and compare it with the previous version.

usage: store_result.py <store-dir> <report-dir> [<run-url>]

<store-dir> is a checkout of the results branch. Per package it holds:
  packages/<name>/index.json              every scanned build, oldest first
  packages/<name>/<sha256>.json           the full result
  packages/<name>/<sha256>.manifest.tsv   sha256, size, kind, path per file

The comparison uses the stored result of the previous build, not its RPM, so
it still works after the developer has deleted that version from OpenRepos.

Writes final.md and final-verdict into <report-dir>. Exit 0 when stored,
3 when the scan has no verdict worth storing.
"""
import datetime
import json
import os
import re
import shutil
import sys

LIST_CAP = 500  # entries kept per list in the stored diff


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def manifest(path):
    files = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 4:
                    files[parts[3]] = parts[0]
    except OSError:
        return None
    return files


def load_index(pkgdir):
    index = load(os.path.join(pkgdir, "index.json"))
    if index is not None:
        return index
    # Results stored before the index existed.
    index = []
    if os.path.isdir(pkgdir):
        for name in sorted(os.listdir(pkgdir)):
            if re.fullmatch(r"[0-9a-f]{64}\.json", name):
                old = load(os.path.join(pkgdir, name), {})
                index.append({"sha256": name[:64], "package": old.get("package"),
                              "buildtime": old.get("buildtime") or 0,
                              "first_seen": old.get("scanned"), "last_scanned": old.get("scanned"),
                              "verdict": old.get("verdict")})
    return index


def order(entry):
    return (entry.get("buildtime") or 0, entry.get("first_seen") or "")


def added_removed(old, new):
    old, new = set(old or []), set(new or [])
    return sorted(new - old), sorted(old - new)


def compare(old, new, old_files, new_files):
    """A flat list of changes; "attention" marks the ones a reviewer should read."""
    changes = []

    def change(area, kind, item, attention=False, detail=None):
        entry = {"area": area, "change": kind, "item": item, "attention": attention}
        if detail:
            entry["detail"] = detail
        changes.append(entry)

    oi, ni = old.get("inspect") or {}, new.get("inspect") or {}

    if old.get("verdict") != new.get("verdict"):
        change("verdict", "changed", f"{old.get('verdict')} -> {new.get('verdict')}",
               new.get("verdict") == "detected")

    old_apps = {a["desktop"]: a for a in (oi.get("sailjail") or {}).get("apps", [])}
    new_apps = {a["desktop"]: a for a in (ni.get("sailjail") or {}).get("apps", [])}
    for desktop, app in new_apps.items():
        before = old_apps.get(desktop)
        if before is None:
            change("launcher entry", "added", desktop, True,
                   f"sandbox {app['sandbox']}, permissions: {', '.join(app['permissions']) or 'none'}")
            continue
        if before["sandbox"] != app["sandbox"]:
            change("sandbox", "changed", desktop, app["sandbox"] != "declared",
                   f"{before['sandbox']} -> {app['sandbox']}")
        added, removed = added_removed(before["permissions"], app["permissions"])
        for perm in added:
            change("permission", "added", perm, True, desktop)
        for perm in removed:
            change("permission", "removed", perm, False, desktop)
        if before.get("exec") != app.get("exec"):
            change("launcher command", "changed", desktop, True,
                   f"{before.get('exec')} -> {app.get('exec')}")
    for desktop in old_apps.keys() - new_apps.keys():
        change("launcher entry", "removed", desktop)
    added, removed = added_removed((oi.get("sailjail") or {}).get("shipped_profiles"),
                                   (ni.get("sailjail") or {}).get("shipped_profiles"))
    for path in added:
        change("shipped sandbox profile", "added", path, True)
    for path in removed:
        change("shipped sandbox profile", "removed", path)

    for key, label, ident, describe in (
        ("systemd", "systemd unit", "path",
         lambda u: f"as {u.get('user')}: {' ; '.join(u.get('exec_start') or [])}"
                   f" ({'; '.join(u.get('enabled_by') or []) or 'not enabled by the package'})"),
        ("dbus", "D-Bus activation", "path",
         lambda s: f"{s.get('bus')} bus, {s.get('name')}: {s.get('exec')}"),
    ):
        before = {u[ident]: u for u in (oi.get("services") or {}).get(key, [])}
        after = {u[ident]: u for u in (ni.get("services") or {}).get(key, [])}
        for path, unit in after.items():
            if path not in before:
                change(label, "added", path, True, describe(unit))
            elif describe(before[path]) != describe(unit):
                change(label, "changed", path, True, f"{describe(before[path])} -> {describe(unit)}")
        for path in before.keys() - after.keys():
            change(label, "removed", path)
    added, removed = added_removed((oi.get("services") or {}).get("autostart"),
                                   (ni.get("services") or {}).get("autostart"))
    for path in added:
        change("autostart entry", "added", path, True)
    for path in removed:
        change("autostart entry", "removed", path)

    before = {p["path"]: ", ".join(p["why"]) for p in oi.get("privileged_files") or []}
    after = {p["path"]: ", ".join(p["why"]) for p in ni.get("privileged_files") or []}
    for path, why in after.items():
        if before.get(path) != why:
            change("privileged file", "added" if path not in before else "changed", path, True, why)
    for path in before.keys() - after.keys():
        change("privileged file", "removed", path)

    old_hooks, new_hooks = oi.get("system_integration") or {}, ni.get("system_integration") or {}
    for label in sorted(set(old_hooks) | set(new_hooks)):
        added, removed = added_removed(old_hooks.get(label), new_hooks.get(label))
        for path in added:
            change("system hook", "added", path, True, label)
        for path in removed:
            change("system hook", "removed", path, False, label)

    def scriptlet_lines(inspect):
        lines = {}
        for script in inspect.get("scriptlets") or []:
            body = script.get("body")
            source = body.splitlines() if body is not None else script.get("notable", [])
            lines.setdefault(script["type"], set()).update(
                line.strip() for line in source if line.strip() and not line.lstrip().startswith("#"))
        return lines
    old_lines, new_lines = scriptlet_lines(oi), scriptlet_lines(ni)
    for kind in sorted(set(old_lines) | set(new_lines)):
        added, removed = added_removed(old_lines.get(kind), new_lines.get(kind))
        for line in added[:40]:
            change("install scriptlet", "added", line[:300], True, kind)
        for line in removed[:40]:
            change("install scriptlet", "removed", line[:300], False, kind)

    added, removed = added_removed([i["rule"] for i in old.get("indicators") or []],
                                   [i["rule"] for i in new.get("indicators") or []])
    for rule in added:
        change("indicator", "added", rule, True)
    for rule in removed:
        change("indicator", "removed", rule)

    old_net, new_net = oi.get("network") or {}, ni.get("network") or {}
    counts = {}
    if "hosts_scripts" in old_net and "hosts_scripts" in new_net:
        old_all = set(old_net["hosts_scripts"]) | set(old_net["hosts_binaries"])
        added_scripts = sorted(set(new_net["hosts_scripts"]) - old_all)
        added_binaries = sorted(set(new_net["hosts_binaries"]) - old_all)
        removed = sorted(old_all - set(new_net["hosts_scripts"]) - set(new_net["hosts_binaries"]))
        for host in added_scripts[:LIST_CAP]:
            change("host", "added", host, True, "in scripts/QML/config")
        for host in added_binaries[:LIST_CAP]:
            change("host", "added", host, False, "only in binaries")
        for host in removed[:LIST_CAP]:
            change("host", "removed", host)
        counts["hosts"] = {"added": len(added_scripts) + len(added_binaries), "removed": len(removed)}

    if old_files is not None and new_files is not None:
        added = sorted(new_files.keys() - old_files.keys())
        removed = sorted(old_files.keys() - new_files.keys())
        changed = sorted(p for p in new_files.keys() & old_files.keys() if new_files[p] != old_files[p])
        for path in added[:LIST_CAP]:
            change("file", "added", path)
        for path in removed[:LIST_CAP]:
            change("file", "removed", path)
        for path in changed[:LIST_CAP]:
            change("file", "changed", path)
        counts["files"] = {"added": len(added), "removed": len(removed), "changed": len(changed),
                           "unchanged": len(new_files) - len(added) - len(changed)}
    return changes, counts


def code(value, limit=200):
    text = re.sub(r"[`\r\n\t]+", " ", str(value))[:limit]
    return f"`{text}`" if text else "-"


def reputation_markdown(reputation):
    out = ["### Hash reputation", ""]
    if not reputation:
        return out + ["Not run.", ""]
    for key, label in (("virustotal", "VirusTotal"), ("malwarebazaar", "MalwareBazaar")):
        service = reputation.get(key) or {}
        if service.get("status") == "not configured":
            out.append(f"- {label}: not configured (no API key in the repository secrets)")
            continue
        line = (f"- {label}: {service.get('status')}; {service.get('queried', 0)} hash(es) looked up, "
                f"{service.get('unknown', 0)} unknown to the service")
        if service.get("not_queried"):
            line += f", {service['not_queried']} not looked up (limit)"
        out.append(line)
        for entry in service.get("results", []):
            if key == "virustotal":
                out.append(f"  - {code(entry['path'])}: {entry['malicious']} malicious, "
                           f"{entry['suspicious']} suspicious of {entry['engines']} engines")
            else:
                out.append(f"  - :warning: {code(entry['path'])}: known sample {code(entry.get('signature'))}")
    for hit in reputation.get("hits", []):
        out.append(f"- :rotating_light: {hit['source']}: {code(hit['path'])} {hit['detail']}")
    return out + [""]


def diff_markdown(diff):
    if diff is None:
        return ["### Changes since the previous version", "",
                "No earlier build of this package has been scanned, so there is nothing to compare with.", ""]
    base = diff["baseline"]
    out = [f"### Changes since {code(base.get('package'))}", ""]
    changes = diff["changes"]
    attention = [c for c in changes if c["attention"]]
    quiet = [c for c in changes if not c["attention"] and c["area"] not in ("file", "host")]
    if not changes:
        out.append("Nothing changed: same files, same declarations.")
    if attention:
        out.append("**Worth reviewing**")
        out.append("")
        for c in attention[:60]:
            out.append(f"- :warning: {c['area']} {c['change']}: {code(c['item'])}"
                       + (f" ({code(c['detail'], 300)})" if c.get("detail") else ""))
        if len(attention) > 60:
            out.append(f"- ... and {len(attention) - 60} more in the stored result")
        out.append("")
    if quiet:
        out.append("**Other changes**")
        out.append("")
        for c in quiet[:40]:
            out.append(f"- {c['area']} {c['change']}: {code(c['item'])}"
                       + (f" ({code(c['detail'], 300)})" if c.get("detail") else ""))
        out.append("")
    counts = diff.get("counts") or {}
    if "files" in counts:
        f = counts["files"]
        out.append(f"**Files**: {f['added']} added, {f['removed']} removed, {f['changed']} changed, "
                   f"{f['unchanged']} unchanged")
        shown = [c for c in changes if c["area"] == "file"][:25]
        if shown:
            out.append("")
            out += [f"- {c['change']}: {code(c['item'])}" for c in shown]
            total = f["added"] + f["removed"] + f["changed"]
            if total > len(shown):
                out.append(f"- ... and {total - len(shown)} more")
        out.append("")
    else:
        out += ["**Files**: the previous result has no file list, so files were not compared.", ""]
    if "hosts" in counts:
        h = counts["hosts"]
        quiet_hosts = [c["item"] for c in changes
                       if c["area"] == "host" and c["change"] == "added" and not c["attention"]]
        out.append(f"**Hosts**: {h['added']} added, {h['removed']} removed"
                   + (". New in binaries only: " + ", ".join(code(x) for x in quiet_hosts[:20])
                      + (f" (+{len(quiet_hosts) - 20} more)" if len(quiet_hosts) > 20 else "")
                      if quiet_hosts else ""))
        out.append("")
    return out


def main():
    store, report_dir = sys.argv[1], sys.argv[2]
    run_url = sys.argv[3] if len(sys.argv) > 3 else None
    report = load(os.path.join(report_dir, "report.json"))

    def finish(verdict, lines, rc):
        with open(os.path.join(report_dir, "final-verdict"), "w", encoding="utf-8") as fh:
            fh.write(verdict + "\n")
        with open(os.path.join(report_dir, "final.md"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        sys.exit(rc)

    if not report or report.get("verdict") not in ("clean", "detected"):
        # An incomplete scan is not a verdict and must not replace one.
        finish((report or {}).get("verdict") or "error", ["Scan has no verdict; nothing stored."], 3)

    # Both values end up in a path and come from the scanned package.
    sha256, name = str(report.get("sha256")), str(report.get("name"))
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        sys.exit("bad sha256 in report")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", name):
        name = "_unnamed"

    reputation = load(os.path.join(report_dir, "reputation.json"))
    report["signature_verdict"] = report["verdict"]
    if reputation:
        report["reputation"] = reputation
        if reputation.get("hits"):
            report["verdict"] = "detected"
    if run_url:
        report["run"] = run_url

    pkgdir = os.path.join(store, "packages", name)
    os.makedirs(pkgdir, exist_ok=True)
    index = load_index(pkgdir)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mine = next((e for e in index if e["sha256"] == sha256), None)
    if mine is None:
        mine = {"sha256": sha256, "first_seen": report.get("scanned") or now}
        index.append(mine)
    mine.update(package=report.get("package"), version=report.get("version"),
                arch=report.get("arch"),
                buildtime=report.get("buildtime") or 0,
                last_scanned=report.get("scanned") or now, verdict=report["verdict"])
    index.sort(key=order)

    # The build just before this one, by RPM build time. Prefer the same
    # architecture: comparing aarch64 with armv7hl changes every binary.
    earlier = index[:index.index(mine)][::-1]
    baseline = next((e for e in earlier if e.get("arch") == mine["arch"]),
                    earlier[0] if earlier else None)
    diff = None
    if baseline:
        old = load(os.path.join(pkgdir, baseline["sha256"] + ".json"))
        if old:
            changes, counts = compare(
                old, report,
                manifest(os.path.join(pkgdir, baseline["sha256"] + ".manifest.tsv")),
                manifest(os.path.join(report_dir, "manifest.tsv")))
            diff = {"baseline": {k: baseline.get(k) for k in ("sha256", "package", "last_scanned")},
                    "changes": changes, "counts": counts}
    report["diff"] = diff

    with open(os.path.join(pkgdir, sha256 + ".json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    if os.path.exists(os.path.join(report_dir, "manifest.tsv")):
        shutil.copyfile(os.path.join(report_dir, "manifest.tsv"),
                        os.path.join(pkgdir, sha256 + ".manifest.tsv"))
    with open(os.path.join(pkgdir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
        fh.write("\n")

    lines = [f"## Coastguard result: {report['verdict']}", "",
             f"Stored as `packages/{name}/{sha256}.json` on the `results` branch.", ""]
    lines += reputation_markdown(reputation) + diff_markdown(diff)
    print(f"{name}: {report['verdict']} ({sha256})")
    finish(report["verdict"], lines, 0)


if __name__ == "__main__":
    main()
