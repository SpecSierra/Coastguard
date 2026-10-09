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


def _count(number, noun):
    return f"{number} {noun}" + ("" if number == 1 else "s")


def _indicator_name(rule):
    return rule.replace("Coastguard_Indicator_", "")


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")


def assess(report, diff=None):
    """Returns {"grade": ..., "reasons": [{"level", "id", "text"}, ...]}, the
    reasons most serious first. A reason whose id the developer explained in
    the package (see README, "Explaining a flag") also carries "explanation".
    That text is the developer's own claim and never changes the grade."""
    reasons = []

    def add(level, ident, text):
        if not any(r["id"] == ident for r in reasons):
            reasons.append({"level": level, "id": ident, "text": text})

    inspect = report.get("inspect") or {}
    sailjail = inspect.get("sailjail") or {}
    apps = sailjail.get("apps") or []
    services = (inspect.get("services") or {}).get("systemd") or []
    network = inspect.get("network") or {}
    nested = report.get("nested") or {}

    if report.get("verdict") == "detected":
        add("high", "malware", "Known malware")
    if inspect.get("error"):
        add("medium", "inspection-failed", "Inspection failed, grade incomplete")

    # --- sandbox -------------------------------------------------------------
    unsandboxed = [a for a in apps if a.get("sandbox") == "disabled"]
    undeclared = [a for a in apps if a.get("sandbox") == "none"]
    if unsandboxed:
        add("medium", "sandbox-off", "Sandbox turned off")
    if undeclared:
        add("info", "no-sandbox-profile", "No sandbox profile declared")
    loosening = sailjail.get("profile_loosening") or []
    if loosening:
        add("medium", "sandbox-loosened",
            f"Own profile loosens the sandbox ({_count(len(loosening), 'rule')})")
    elif sailjail.get("shipped_profiles"):
        add("info", "own-sandbox-profile", "Own sandbox profile")
    sensitive = sorted({p for a in apps for p in a.get("permissions") or []} & SENSITIVE_PERMISSIONS)
    if sensitive:
        add("info", "personal-data", "Personal data: " + ", ".join(sensitive))

    # --- services and privileges ---------------------------------------------
    root_units = [u for u in services if u.get("user") == "root" and u.get("scope") == "system"]
    started = [u for u in root_units if u.get("enabled_by")]
    if started:
        add("medium", "root-services", f"{_count(len(started), 'root service')}, started at install")
    elif root_units:
        add("medium", "root-services", _count(len(root_units), "root service"))
    if root_units and (unsandboxed or undeclared):
        add("high", "root-service-no-sandbox", "Root service and no sandbox")
    if any(u.get("scope") == "user" for u in services) or (inspect.get("services") or {}).get("autostart"):
        add("info", "background-start", "Starts in the background")

    privileged = inspect.get("privileged_files") or []
    if privileged:
        whys = sorted({w for item in privileged for w in item.get("why") or []})
        add("high" if any("root" in w or "capabilities" in w for w in whys) else "medium",
            "privileged-files",
            f"{_count(len(privileged), 'privileged file')} ({', '.join(whys)[:80]})")

    for label in sorted(inspect.get("system_integration") or {}):
        add(HOOK_LEVELS.get(label, "medium"), "hook-" + _slug(label), f"System hook: {label}")

    # --- install scriptlets ----------------------------------------------------
    for script in inspect.get("scriptlets") or []:
        lines = (script.get("body") or "\n".join(script.get("notable") or [])).splitlines()
        for line in lines:
            if line.lstrip().startswith("#"):
                continue
            for level, what, pattern in SCRIPTLET_RULES:
                if pattern.search(line):
                    add(level, "install-script-" + _slug(what), f"Install script {what}")

    # --- indicators ------------------------------------------------------------
    for indicator in report.get("indicators") or []:
        name = _indicator_name(indicator["rule"])
        label = name.replace("_", " ").lower()
        in_scriptlet = any(f.endswith("scriptlets.txt") for f in indicator.get("files") or [])
        if name in BEHAVIOUR_INDICATORS:
            add("high" if in_scriptlet else "medium", "code-" + _slug(name), f"Code that {label}")
        elif unsandboxed or undeclared:
            # Outside the sandbox nothing stands between this code and the data.
            add("medium", "code-" + _slug(name), f"Unsandboxed code that {label}")
        else:
            add("info", "code-" + _slug(name), f"Code that {label}")

    # --- embedded addresses ----------------------------------------------------
    for item in network.get("known_bad") or []:
        add("high" if item.get("in") == "script" else "medium", "malware-host",
            f"Names a known malware host ({str(item.get('host'))[:60]})")
    for item in network.get("notable") or []:
        if item.get("in") == "script":
            add("medium", "script-address", f"Script uses a {item.get('why')}")
    unlisted = sum(b.get("unlisted_count") or 0 for b in network.get("bulk") or []
                   if b.get("on_public_lists") is not None)
    if unlisted:
        add("info", "bulk-hosts", f"{_count(unlisted, 'host')} in a bulk list are on no public block list")

    # --- things the scan could not see ---------------------------------------
    if nested.get("encrypted"):
        add("medium", "encrypted-archive", "Password-protected archive, not scanned")
    if nested.get("limits_hit") or nested.get("error"):
        add("medium", "scan-limits", "Content too large to scan fully")

    # --- what this version changed -------------------------------------------
    for change in (diff or {}).get("changes") or []:
        area, kind, item = change.get("area"), change.get("change"), str(change.get("item"))
        if area == "sandbox" and kind == "changed":
            detail = change.get("detail") or ""
            if detail.startswith("declared ->"):
                add("high", "new-sandbox-dropped", "New: sandbox dropped")
        elif area == "permission" and kind == "added":
            add("medium" if item in SENSITIVE_PERMISSIONS else "info",
                "new-permission-" + _slug(item), f"New permission: {item}")
        elif area == "systemd unit" and kind == "added":
            add("medium", "new-service", "New background service")
        elif area in ("privileged file", "shipped sandbox profile") and kind == "added":
            add("medium", "new-" + _slug(area), f"New {area}")
        elif area == "system hook" and kind == "added":
            add("medium", "new-hook-" + _slug(change.get("detail")),
                f"New system hook: {change.get('detail')}")
        elif area == "indicator" and kind == "added":
            add("medium", "new-code-" + _slug(_indicator_name(item)),
                f"New code that {_indicator_name(item).replace('_', ' ').lower()}")

    explanations = inspect.get("explanations") or {}
    for reason in reasons:
        if reason["id"] in explanations:
            reason["explanation"] = explanations[reason["id"]]
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
        out.append(f"- {marks[reason['level']]} {reason['text']} (`{reason.get('id', '')}`)"
                   .replace("-  ", "- "))
        if reason.get("explanation"):
            out.append(f"  - Developer's explanation (their own claim, not verified): "
                       f"{reason['explanation']}")
    out += ["", "The grade describes how much the package gets to do on the device, from what it "
            "declares and installs. It is a set of heuristics, not a verdict. A flag is a prompt "
            "to explain, not an accusation: developers can answer each one by its id, see "
            "[Explaining a flag](https://github.com/SpecSierra/Coastguard#explaining-a-flag).", ""]
    return out
