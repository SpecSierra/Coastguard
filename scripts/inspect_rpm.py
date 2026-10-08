#!/usr/bin/env python3
"""Static inspection of an unpacked RPM: what the package would set up on a
Sailfish OS device. Reads files only; nothing from the package is executed.

usage: inspect_rpm.py <payload-dir> <filemeta.tsv> <scriptlets.txt> <report-dir>
                      [<nested-dir>]

<nested-dir> holds content unpacked from archives inside the payload; it is
searched for network addresses only, since nothing in it is an installed path.

Writes inspect.json, inspect.md, urls.txt and manifest.tsv into <report-dir>. This describes
what the package declares and embeds, not what it does at runtime.
"""
import configparser
import hashlib
import ipaddress
import json
import mmap
import os
import re
import stat
import sys
from collections import defaultdict
from urllib.parse import urlsplit

MAX_TEXT = 256 * 1024  # config-like files larger than this are not parsed
MAX_SCRIPTLET = 16 * 1024  # stored per scriptlet so later versions can be diffed

# Hosts that appear in almost every binary as XML namespaces, licence texts
# or documentation examples.
BORING_HOSTS = re.compile(
    r"(^|\.)(w3\.org|xmlsoap\.org|purl\.org|xmlpull\.org|example\.(com|org|net)"
    r"|apache\.org|gnu\.org|opensource\.org|creativecommons\.org"
    r"|localhost|schemas\.[a-z0-9.-]+|ns\.adobe\.com|unicode\.org|ietf\.org"
    r"|rfc-editor\.org|iana\.org)$"
)

# Services often used to fetch second-stage payloads or exfiltrate data.
NOTABLE_HOSTS = re.compile(
    r"(pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|ngrok\.(io|app)"
    r"|trycloudflare\.com|serveo\.net|discord(app)?\.com/api/webhooks"
    r"|api\.telegram\.org|\.onion$|duckdns\.org|no-ip\.(com|org)|dyndns\.org"
    r"|raw\.githubusercontent\.com|gist\.githubusercontent\.com|bit\.ly|tinyurl\.com)"
)

URL_RE = re.compile(
    rb"(?:https?|wss?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}"
)

# Places where a package hooks itself into the system.
INTEGRATION = [
    ("sudoers", r"^etc/sudoers(\.d/|$)"),
    ("polkit", r"^(etc|usr/share)/polkit-1/"),
    ("udev rules", r"^(etc|lib|usr/lib)/udev/rules\.d/"),
    ("cron", r"^(etc/cron|var/spool/cron)"),
    ("first-boot / oneshot scripts", r"^usr/lib/oneshot\.d/"),
    ("login shell hooks", r"^etc/profile(\.d/|$)"),
    ("dynamic linker config", r"^etc/ld\.so\.(conf|preload)"),
    ("package repositories", r"^(etc/zypp/repos\.d/|usr/share/ssu/|etc/ssu/)"),
    ("privileged launcher grant", r"^usr/share/mapplauncherd/privileges(\.d/|$)"),
    ("D-Bus system policy", r"^(etc|usr/share)/dbus-1/system\.d/"),
    ("kernel modules / sysctl", r"^(etc/modules-load\.d/|etc/sysctl\.d/|lib/modules/)"),
    ("system UI patches", r"^usr/share/patchmanager/"),
    ("files in a home directory", r"^(home|root)/"),
]

# Scriptlets run as root at install time; these are the lines worth reading.
SCRIPTLET_NOTABLE = re.compile(
    r"\b(systemctl|systemd-run|curl|wget|nc|ncat|setcap|chown|chmod|pkcon|zypper"
    r"|rpm|ssu|useradd|usermod|groupadd|crontab|dconf|base64|eval|insmod|modprobe"
    r"|mount|su|sudo|devel-su|ssh|scp|iptables|killall|pkill)\b"
    r"|/etc/sudoers|/home/|>\s*/etc/|\|\s*(ba)?sh\b"
)


def rel_files(root):
    """Yield (relative path, absolute path, lstat) for everything in the payload."""
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in files + [d for d in dirs if os.path.islink(os.path.join(base, d))]:
            full = os.path.join(base, name)
            yield os.path.relpath(full, root), full, os.lstat(full)


def read_text(full, st):
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT:
        return ""
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def ini(text):
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        # Unit files repeat keys and use line continuations; fall back to a
        # forgiving line parser.
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        parser.optionxform = str
        section = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                if not parser.has_section(section):
                    parser.add_section(section)
            elif section and "=" in line and not line.startswith(("#", ";")):
                key, value = line.split("=", 1)
                old = parser.get(section, key.strip(), fallback=None)
                value = value.strip()
                parser.set(section, key.strip(), f"{old}\n{value}" if old else value)
    return parser


def get(parser, section, key):
    return parser.get(section, key, fallback=None) if parser.has_section(section) else None


# Lines in a sandbox profile that take protections away rather than grant one
# more directory: dropped filters, system D-Bus access, the whole home dir.
PROFILE_LOOSENING = re.compile(
    r"^\s*(ignore\s+\S.*|noblacklist\s+\S.*|caps\.keep\s+\S.*|allow-debuggers"
    r"|dbus-system\.(talk|own|call|broadcast)\s+\S.*|dbus-(user|system)\s+none"
    r"|writable-(etc|var|run-user)|whitelist\s+(\$\{HOME\}|~)/?)\s*$")


def inspect_sailjail(entries):
    apps, profiles, loosening = [], [], []
    for rel, full, st in entries:
        if re.match(r"^(etc|usr/share)/sailjail/", rel) or rel.startswith("etc/firejail/"):
            profiles.append("/" + rel)
            for line in read_text(full, st).splitlines():
                if PROFILE_LOOSENING.match(line) and len(loosening) < 40:
                    loosening.append({"file": "/" + rel, "line": line.strip()[:200]})
        if not re.match(r"^usr/share/applications/[^/]+\.desktop$", rel):
            continue
        parser = ini(read_text(full, st))
        if not parser.has_section("Desktop Entry"):
            continue
        app = {
            "desktop": "/" + rel,
            "name": get(parser, "Desktop Entry", "Name"),
            "exec": get(parser, "Desktop Entry", "Exec"),
            "hidden": (get(parser, "Desktop Entry", "NoDisplay") or "").lower() == "true",
        }
        if parser.has_section("X-Sailjail"):
            perms = get(parser, "X-Sailjail", "Permissions") or ""
            disabled = (get(parser, "X-Sailjail", "Sandboxing") or "").lower() == "disabled"
            app.update(
                sandbox="disabled" if disabled else "declared",
                permissions=[p.strip() for p in perms.split(";") if p.strip()],
                organization=get(parser, "X-Sailjail", "OrganizationName"),
                application=get(parser, "X-Sailjail", "ApplicationName"),
            )
        else:
            app.update(sandbox="none", permissions=[])
        apps.append(app)
    return {"apps": apps, "shipped_profiles": sorted(profiles),
            "profile_loosening": loosening}


def inspect_services(entries, scriptlet_text):
    unit_re = re.compile(
        r"^(etc|lib|usr/lib)/systemd/(system|user)/([^/]+\.(service|timer|socket|path|mount))$"
    )
    wants = defaultdict(list)  # unit name -> targets that pull it in
    for rel, full, st in entries:
        m = re.match(r"^(?:etc|lib|usr/lib)/systemd/(?:system|user)/([^/]+)\.(wants|requires)/([^/]+)$", rel)
        if m:
            wants[m.group(3)].append(m.group(1))

    systemd, dbus, autostart = [], [], []
    for rel, full, st in entries:
        m = unit_re.match(rel)
        if m and stat.S_ISREG(st.st_mode):
            parser = ini(read_text(full, st))
            name = m.group(3)
            enabled = [f"wanted by {t} (shipped symlink)" for t in sorted(wants.get(name, []))]
            if re.search(r"systemctl[^\n]*\b(enable|start|restart)\b[^\n]*" + re.escape(name.rsplit(".", 1)[0]), scriptlet_text):
                enabled.append("enabled or started from an install scriptlet")
            systemd.append({
                "path": "/" + rel,
                "scope": m.group(2),
                "exec_start": (get(parser, "Service", "ExecStart") or "").split("\n") if get(parser, "Service", "ExecStart") else [],
                # A system unit without User= runs as root.
                "user": get(parser, "Service", "User") or ("root" if m.group(2) == "system" else "device user"),
                "install_wanted_by": get(parser, "Install", "WantedBy"),
                "enabled_by": enabled,
            })
        m = re.match(r"^usr/share/dbus-1/(services|system-services)/[^/]+\.service$", rel)
        if m and stat.S_ISREG(st.st_mode):
            parser = ini(read_text(full, st))
            dbus.append({
                "path": "/" + rel,
                "bus": "system" if m.group(1) == "system-services" else "session",
                "name": get(parser, "D-BUS Service", "Name"),
                "exec": get(parser, "D-BUS Service", "Exec"),
                "user": get(parser, "D-BUS Service", "User"),
                "systemd_service": get(parser, "D-BUS Service", "SystemdService"),
            })
        if re.match(r"^etc/xdg/autostart/[^/]+\.desktop$", rel):
            autostart.append("/" + rel)
    return {"systemd": systemd, "dbus": dbus, "autostart": sorted(autostart)}


def inspect_integration(entries):
    found = defaultdict(list)
    for rel, full, st in entries:
        for label, pattern in INTEGRATION:
            if re.search(pattern, rel):
                found[label].append("/" + rel)
    return {label: sorted(paths) for label, paths in found.items()}


def inspect_filemeta(path):
    """setuid/setgid bits and file capabilities, from the RPM header."""
    privileged = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 5:
                    continue
                mode, owner, group, caps, name = parts
                reasons = []
                if len(mode) == 10 and mode[0] == "-":
                    if mode[3] in "sS":
                        reasons.append(f"setuid {owner}")
                    if mode[6] in "sS":
                        reasons.append(f"setgid {group}")
                # rpm prints "(none)" for a file without capabilities.
                if caps.strip() not in ("", "(none)"):
                    reasons.append(f"capabilities {caps.strip()}")
                if reasons:
                    privileged.append({"path": name, "mode": mode, "owner": owner,
                                       "group": group, "why": reasons})
    except OSError:
        pass
    return privileged


def inspect_scriptlets(text):
    scriptlets, current = [], None
    header = re.compile(r"^(\w+) (scriptlet|program)\b(?: \(using ([^)]+)\))?(.*)$")
    for line in text.splitlines():
        m = header.match(line)
        if m and m.group(1).startswith(("pre", "post", "trigger", "verify", "filetrigger", "transfiletrigger")):
            current = {"type": m.group(1), "interpreter": m.group(3), "lines": 0,
                       "notable": [], "body": ""}
            if m.group(2) == "program":
                current["interpreter"] = m.group(4).lstrip(": ").strip() or None
            scriptlets.append(current)
            continue
        if current is None:
            continue
        if len(current["body"]) < MAX_SCRIPTLET:
            current["body"] += line[:1000] + "\n"
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current["lines"] += 1
        if SCRIPTLET_NOTABLE.search(line) and len(current["notable"]) < 40:
            current["notable"].append(line.strip()[:300])
    return scriptlets


def valid_host(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", host))


def inspect_network(entries, nested, scriptlets_path, report_dir):
    hosts = {}
    notable, seen_notable = [], set()
    urls = {}
    sources = [("/" + rel, full, st) for rel, full, st in entries]
    sources += [("nested/" + rel, full, st) for rel, full, st in nested]
    sources = [s for s in sources if stat.S_ISREG(s[2].st_mode) and s[2].st_size]
    if os.path.getsize(scriptlets_path):
        sources.append(("(install scriptlets)", scriptlets_path, os.lstat(scriptlets_path)))
    ignored = set()
    for label, full, st in sources:
        try:
            fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(fd, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            kind = "binary" if b"\0" in data[:8192] else "script"
            for match in URL_RE.finditer(data):
                url = match.group().decode("ascii", "replace").rstrip(".,;:'\")]}")
                try:
                    parts = urlsplit(url)
                    host, port = (parts.hostname or "").lower().rstrip("."), parts.port
                except ValueError:
                    continue
                if not valid_host(host):
                    continue
                reason = None
                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_loopback or ip.is_unspecified:
                        ignored.add(host)
                        continue
                    reason = "hard-coded IP address"
                except ValueError:
                    if BORING_HOSTS.search(host):
                        ignored.add(host)
                        continue
                    if NOTABLE_HOSTS.search(host + parts.path):
                        reason = "paste, tunnel, webhook or raw-download service"
                    elif port and port not in (80, 443):
                        reason = f"non-standard port {port}"
                entry = hosts.setdefault(host, {"host": host, "urls": set(), "in": set(),
                                               "files": [], "plain_http": False})
                entry["urls"].add(url)
                entry["in"].add(kind)
                entry["plain_http"] |= parts.scheme in ("http", "ws", "ftp")
                if label not in entry["files"] and len(entry["files"]) < 3:
                    entry["files"].append(label)
                if len(urls) < 50000:
                    urls.setdefault(url, label)
                if reason and (host, reason) not in seen_notable and len(notable) < 100:
                    seen_notable.add((host, reason))
                    notable.append({"url": url[:200], "why": reason, "file": label, "in": kind})

    with open(os.path.join(report_dir, "urls.txt"), "w", encoding="utf-8") as fh:
        for url, label in sorted(urls.items()):
            fh.write(f"{url}\t{label}\n")

    # Hosts named in readable scripts/QML say more than the thousands baked
    # into a large binary, so they sort first.
    ordered = sorted(hosts.values(), key=lambda h: ("script" not in h["in"], -len(h["urls"]), h["host"]))
    listed = [{"host": h["host"], "urls": len(h["urls"]), "in": sorted(h["in"]),
               "plain_http": h["plain_http"], "files": h["files"]} for h in ordered[:300]]
    return {
        "hosts_total": len(hosts),
        "hosts_in_scripts": sum("script" in h["in"] for h in hosts.values()),
        "hosts": listed,
        # Complete lists, so the next version can be compared with this one.
        "hosts_scripts": sorted(h for h, e in hosts.items() if "script" in e["in"])[:5000],
        "hosts_binaries": sorted(h for h, e in hosts.items() if "script" not in e["in"])[:5000],
        "notable": notable,
        "ignored_hosts": len(ignored),
    }


def write_manifest(entries, report_dir):
    """sha256, size, kind and path of every payload file."""
    with open(os.path.join(report_dir, "manifest.tsv"), "w", encoding="utf-8") as out:
        for rel, full, st in entries:
            if not stat.S_ISREG(st.st_mode):
                continue
            digest, head = hashlib.sha256(), b""
            try:
                fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    for block in iter(lambda: fh.read(1 << 20), b""):
                        head = head or block[:4]
                        digest.update(block)
            except OSError:
                continue
            kind = "elf" if head == b"\x7fELF" else "script" if head[:2] == b"#!" else "other"
            path = re.sub(r"[\x00-\x1f\x7f]", "?", "/" + rel)
            out.write(f"{digest.hexdigest()}\t{st.st_size}\t{kind}\t{path}\n")


def code(value, limit=160):
    """Render an untrusted string as inline code."""
    text = re.sub(r"[`\r\n\t]+", " ", str(value))[:limit]
    return f"`{text}`" if text else "-"


def markdown(result):
    out = ["### What the package sets up (static inspection)", ""]
    jail = result["sailjail"]
    out.append("**Sailjail sandbox**")
    out.append("")
    if not jail["apps"]:
        out.append("No launcher (`.desktop`) entry: nothing here is started as a sandboxed app.")
    for app in jail["apps"]:
        if app["sandbox"] == "declared":
            perms = ", ".join(app["permissions"]) or "none"
            state = f"sandboxed, permissions: {code(perms, 400)}"
            if not (app.get("organization") and app.get("application")):
                state += " (no OrganizationName/ApplicationName, so no private data dir)"
        elif app["sandbox"] == "disabled":
            state = ":warning: sandbox explicitly disabled (`Sandboxing=Disabled`)"
        else:
            state = ":warning: no `[X-Sailjail]` section, the app declares no sandbox profile"
        out.append(f"- {code(app['desktop'])}: {state}; runs {code(app['exec'])}")
    if jail["shipped_profiles"]:
        out.append("- ships its own sandbox profile/permission files: "
                   + ", ".join(code(p) for p in jail["shipped_profiles"][:20]))
    for item in jail["profile_loosening"][:20]:
        out.append(f"  - :warning: loosens the sandbox: {code(item['line'])} in {code(item['file'])}")
    out.append("")

    svc = result["services"]
    out.append("**Services and autostart**")
    out.append("")
    if not (svc["systemd"] or svc["dbus"] or svc["autostart"]):
        out.append("None.")
    for unit in svc["systemd"]:
        enabled = "; ".join(unit["enabled_by"]) or "not enabled by the package"
        out.append(f"- systemd {unit['scope']} unit {code(unit['path'])} as {code(unit['user'])}: "
                   f"{code(' ; '.join(unit['exec_start']))} ({enabled})")
    for service in svc["dbus"]:
        out.append(f"- D-Bus {service['bus']} activation {code(service['name'])}: {code(service['exec'])}"
                   + (f" as {code(service['user'])}" if service["user"] else ""))
    for path in svc["autostart"]:
        out.append(f"- autostart entry {code(path)}")
    out.append("")

    out.append("**Privileges and system hooks**")
    out.append("")
    empty = True
    for item in result["privileged_files"]:
        empty = False
        out.append(f"- :warning: {code(item['path'])}: {', '.join(item['why'])}")
    for label, paths in result["system_integration"].items():
        empty = False
        more = f" (+{len(paths) - 5} more)" if len(paths) > 5 else ""
        out.append(f"- {label}: " + ", ".join(code(p) for p in paths[:5]) + more)
    if empty:
        out.append("No setuid/setgid files, file capabilities or system hooks.")
    out.append("")

    out.append("**Install scriptlets (run as root)**")
    out.append("")
    if not result["scriptlets"]:
        out.append("None.")
    for script in result["scriptlets"]:
        out.append(f"- `{script['type']}`: {script['lines']} line(s)"
                   + (f", {len(script['notable'])} worth reading:" if script["notable"] else ""))
        for line in script["notable"][:15]:
            out.append(f"  - {code(line, 200)}")
    out.append("")

    net = result["network"]
    out.append("**Network addresses embedded in the files**")
    out.append("")
    out.append(f"{net['hosts_total']} host(s), {net['hosts_in_scripts']} of them in readable "
               f"scripts/QML/config. Full list in `urls.txt`. Addresses built at runtime or "
               f"obfuscated do not show up here.")
    out.append("")
    for item in net["notable"][:25]:
        out.append(f"- :warning: {code(item['url'])}: {item['why']} (in {code(item['file'])})")
    scripts = [h for h in net["hosts"] if "script" in h["in"]]
    binaries = [h for h in net["hosts"] if "script" not in h["in"]]
    if scripts:
        out.append("- in scripts/QML/config: " + ", ".join(
            code(h["host"]) + (" (plain http)" if h["plain_http"] else "") for h in scripts[:60])
            + (f" (+{net['hosts_in_scripts'] - 60} more)" if net["hosts_in_scripts"] > 60 else ""))
    if binaries:
        rest = net["hosts_total"] - net["hosts_in_scripts"]
        out.append("- only in binaries, most referenced first: "
                   + ", ".join(code(h["host"]) for h in binaries[:25])
                   + (f" (+{rest - 25} more)" if rest > 25 else ""))
    out.append("")
    return "\n".join(out)


def main():
    payload, filemeta, scriptlets_path, report_dir = sys.argv[1:5]
    entries = sorted(rel_files(payload))
    nested = sorted(rel_files(sys.argv[5])) if len(sys.argv) > 5 else []
    write_manifest(entries, report_dir)
    with open(scriptlets_path, encoding="utf-8", errors="replace") as fh:
        scriptlet_text = fh.read()
    result = {
        "sailjail": inspect_sailjail(entries),
        "services": inspect_services(entries, scriptlet_text),
        "system_integration": inspect_integration(entries),
        "privileged_files": inspect_filemeta(filemeta),
        "scriptlets": inspect_scriptlets(scriptlet_text),
        "network": inspect_network(entries, nested, scriptlets_path, report_dir),
    }
    with open(os.path.join(report_dir, "inspect.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(os.path.join(report_dir, "inspect.md"), "w", encoding="utf-8") as fh:
        fh.write(markdown(result))


if __name__ == "__main__":
    main()
