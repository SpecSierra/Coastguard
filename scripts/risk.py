#!/usr/bin/env python3
"""Risk grade of a scanned package.

The malware verdict only says whether known malware was recognised. The grade
answers a different question: how much does this package get to do on the
device, and did that just change? It is computed from what the package
declares and installs, which malware cannot hide the way it hides code.

Grades, the highest reason wins:
  high    something a reviewer should look at before anyone installs this
  medium  privileges or behaviour that deserve a look
  low     nothing unusual

Every reason is listed with its own level; "info" reasons never raise the
grade. The rules are deliberately few and readable. They are heuristics:
legitimate system tools score high, and a low grade is not a safety promise.
"""
import re

LEVELS = {"info": 0, "medium": 1, "high": 2}
GRADES = {0: "low", 1: "medium", 2: "high"}

# Permissions that open personal data. Declaring one is normal for an app
# that needs it, so it is only information, until an update adds one.
SENSITIVE_PERMISSIONS = {
    "Accounts", "CallRecordings", "CommunicationHistory", "Contacts", "Email",
    "Messages", "Phone", "Secrets",
}

# System hooks (labels from inspect_rpm.py) by how much they hand over.
HOOK_LEVELS = {
    "sudoers": "high",
    "dynamic linker config": "high",
    "kernel modules / sysctl": "high",
    "polkit": "medium",
    "udev rules": "medium",
    "cron": "medium",
    "first-boot / oneshot scripts": "medium",
    "login shell hooks": "medium",
    "package repositories": "medium",
    "privileged launcher grant": "medium",
    "D-Bus system policy": "medium",
    "system UI patches": "info",
    "files in a home directory": "medium",
}

# Indicator rules (rules/sailfish.yar) that describe behaviour rather than
# access to one kind of data.
BEHAVIOUR_INDICATORS = {
    "Downloads_And_Runs_Shell_Code", "Reverse_Shell_Pattern", "Cryptocurrency_Mining",
    "Edits_Sudoers", "Tampers_With_Other_Apps_Sandbox", "Gains_Root_With_Devel_Su",
    "Installs_Packages_At_Runtime", "Reads_Raw_Input_Devices",
}

# Install scriptlets run as root. What a line does decides its level.
SCRIPTLET_RULES = [
    ("high", "fetches from the network",
     re.compile(r"\b(curl|wget|nc|ncat|ssh|scp)\b")),
    ("high", "runs downloaded or decoded code",
     re.compile(r"\|\s*(ba)?sh\b|\beval\b|\bbase64\b")),
    ("high", "grants elevated privileges",
     re.compile(r"\bsetcap\b|/etc/sudoers|\bchmod\b[^\n]*(\+s|\b[2467][0-7]{3}\b)")),
    ("medium", "installs packages or adds repositories",
     re.compile(r"\b(pkcon|zypper|ssu)\b|\brpm\s+-")),
    ("medium", "changes users or loads kernel modules",
     re.compile(r"\b(useradd|usermod|groupadd|insmod|modprobe|crontab|iptables)\b")),
]


def _indicator_name(rule):
    return rule.replace("Coastguard_Indicator_", "")


def assess(report, diff=None):
    """Returns {"grade": ..., "reasons": [{"level", "text"}, ...]}, the
    reasons most serious first."""
    reasons = []

    def add(level, text):
        if not any(r["text"] == text for r in reasons):
            reasons.append({"level": level, "text": text})

    inspect = report.get("inspect") or {}
    sailjail = inspect.get("sailjail") or {}
    apps = sailjail.get("apps") or []
    services = (inspect.get("services") or {}).get("systemd") or []
    nested = report.get("nested") or {}

    if report.get("verdict") == "detected":
        add("high", "Recognised as known malware")
    if inspect.get("error"):
        add("medium", "The package could not be inspected, so this grade is incomplete")

    # --- sandbox -------------------------------------------------------------
    unsandboxed = [a for a in apps if a.get("sandbox") == "disabled"]
    undeclared = [a for a in apps if a.get("sandbox") == "none"]
    if unsandboxed:
        add("medium", "The app turns the Sailjail sandbox off")
    if undeclared:
        add("info", "The app declares no Sailjail sandbox profile")
    loosening = sailjail.get("profile_loosening") or []
    if loosening:
        add("medium", f"Its own sandbox profile loosens the sandbox ({len(loosening)} rule(s), "
                      f"such as \"{loosening[0]['line'][:60]}\")")
    elif sailjail.get("shipped_profiles"):
        add("info", "Ships its own sandbox profile")
    sensitive = sorted({p for a in apps for p in a.get("permissions") or []} & SENSITIVE_PERMISSIONS)
    if sensitive:
        add("info", "Asks for access to personal data: " + ", ".join(sensitive))

    # --- services and privileges ---------------------------------------------
    root_units = [u for u in services if u.get("user") == "root" and u.get("scope") == "system"]
    started = [u for u in root_units if u.get("enabled_by")]
    if started:
        add("medium", f"Installs and starts {len(started)} background service(s) running as root")
    elif root_units:
        add("medium", f"Installs {len(root_units)} service(s) that would run as root")
    if root_units and (unsandboxed or undeclared):
        add("high", "Runs a root service while the app itself is not sandboxed")
    if any(u.get("scope") == "user" for u in services) or (inspect.get("services") or {}).get("autostart"):
        add("info", "Starts automatically in the background")

    for item in inspect.get("privileged_files") or []:
        why = ", ".join(item.get("why") or [])
        add("high" if "root" in why or "capabilities" in why else "medium",
            f"Installs a file with elevated privileges ({why})")

    for label in sorted(inspect.get("system_integration") or {}):
        add(HOOK_LEVELS.get(label, "medium"), f"Hooks into the system: {label}")

    # --- install scriptlets ----------------------------------------------------
    for script in inspect.get("scriptlets") or []:
        lines = (script.get("body") or "\n".join(script.get("notable") or [])).splitlines()
        for line in lines:
            if line.lstrip().startswith("#"):
                continue
            for level, what, pattern in SCRIPTLET_RULES:
                if pattern.search(line):
                    add(level, f"Its install script, run as root, {what}")

    # --- indicators ------------------------------------------------------------
    for indicator in report.get("indicators") or []:
        name = _indicator_name(indicator["rule"])
        label = name.replace("_", " ").lower()
        in_scriptlet = any(f.endswith("scriptlets.txt") for f in indicator.get("files") or [])
        if name in BEHAVIOUR_INDICATORS:
            add("high" if in_scriptlet else "medium", f"Contains code that {label}")
        elif unsandboxed or undeclared:
            # Outside the sandbox nothing stands between this code and the data.
            add("medium", f"Contains code that {label}, and is not sandboxed")
        else:
            add("info", f"Contains code that {label}")

    # --- network ---------------------------------------------------------------
    for item in (inspect.get("network") or {}).get("notable") or []:
        if item.get("in") == "script":
            add("medium", f"A script refers to a {item.get('why')}")

    # --- things the scan could not see ---------------------------------------
    if nested.get("encrypted"):
        add("medium", "Contains a password-protected archive that could not be scanned")
    if nested.get("limits_hit") or nested.get("error"):
        add("medium", "Part of the content was too large or too deeply packed to scan")

    # --- what this version changed -------------------------------------------
    for change in (diff or {}).get("changes") or []:
        area, kind, item = change.get("area"), change.get("change"), str(change.get("item"))
        if area == "sandbox" and kind == "changed":
            detail = change.get("detail") or ""
            if detail.startswith("declared ->"):
                add("high", "This version drops the sandbox the previous one had")
        elif area == "permission" and kind == "added":
            add("medium" if item in SENSITIVE_PERMISSIONS else "info",
                f"This version newly asks for the {item} permission")
        elif area == "systemd unit" and kind == "added":
            add("medium", "This version adds a background service")
        elif area in ("privileged file", "shipped sandbox profile") and kind == "added":
            add("medium", f"This version adds a {area}")
        elif area == "system hook" and kind == "added":
            add("medium", f"This version adds a system hook ({change.get('detail')})")
        elif area == "indicator" and kind == "added":
            add("medium", f"This version adds code that {_indicator_name(item).replace('_', ' ').lower()}")

    reasons.sort(key=lambda r: -LEVELS[r["level"]])
    top = max((LEVELS[r["level"]] for r in reasons), default=0)
    return {"grade": GRADES[top], "reasons": reasons}


def markdown(risk):
    labels = {"low": "low: nothing unusual", "medium": "medium: worth a look",
              "high": "high: review before installing"}
    marks = {"high": ":rotating_light:", "medium": ":warning:", "info": ""}
    out = [f"### Risk grade: {labels[risk['grade']]}", ""]
    if not risk["reasons"]:
        out.append("Nothing in what the package declares or installs stands out.")
    for reason in risk["reasons"]:
        out.append(f"- {marks[reason['level']]} {reason['text']}".replace("-  ", "- "))
    out += ["", "The grade describes how much the package gets to do on the device, from what it "
            "declares and installs. It is a set of heuristics, not a verdict.", ""]
    return out
