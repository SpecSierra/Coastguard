#!/usr/bin/env bash
# Prove the scanner can both pass and fail: build a harmless RPM and one
# carrying the EICAR test file, and check each gets the right verdict. More
# packages check nested unpacking, the static inspection, the indicator rules
# and the comparison between two versions.
#
# usage: selftest.sh <yara-rules> <clamav-db-dir>
set -euo pipefail

rules=$(realpath "$1")
clamdb=$(realpath "$2")
scripts=$(dirname "$(realpath "$0")")/../scripts
scan=$scripts/scan.sh
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/SOURCES" "$top/SPECS"

# Host lists of our own, so the address checks do not depend on what the
# public lists contain today.
export COASTGUARD_HOSTLISTS=$top/hostlists
mkdir -p "$COASTGUARD_HOSTLISTS/public" "$COASTGUARD_HOSTLISTS/malicious"
for n in $(seq 1 148); do echo "||ads$n.coastguard-blocklist.test^"; done \
    > "$COASTGUARD_HOSTLISTS/public/list.txt"
echo "127.0.0.1 c2.coastguard-malware.test" > "$COASTGUARD_HOSTLISTS/malicious/list.txt"
tree=$top/SOURCES/tree

build_rpm() { # <name> <%post body> [<version>]; packages everything under $tree
    local version=${3:-1}
    cat > "$top/SPECS/$1.spec" <<SPEC
%global __os_install_post %{nil}
%global debug_package %{nil}
Name: $1
Version: $version
Release: 1
Summary: Coastguard self-test package
License: Public Domain
BuildArch: noarch
%description
Coastguard self-test package.
%install
cp -a %{_sourcedir}/tree/. %{buildroot}/
%post
$2
%files
/*
SPEC
    rpmbuild -bb --quiet --define "_topdir $top" "$top/SPECS/$1.spec" >&2
    rm -rf "$tree"
    echo "$top/RPMS/noarch/$1-$version-1.noarch.rpm"
}

expect() { # <label> <expected rc> <rpm> <report dir>
    local rc=0
    "$scan" "$3" "$rules" "$clamdb" "$4" || rc=$?
    if [ "$rc" -ne "$2" ]; then
        echo "FAIL: $1: expected exit $2, got $rc" >&2
        exit 1
    fi
    echo "ok: $1 (exit $rc)"
}

check() { # <report dir> <label> <jq filter that must be true>
    jq -e "$3" "$top/$1/report.json" > /dev/null \
        || { echo "FAIL: $2" >&2; jq . "$top/$1/report.json" >&2; exit 1; }
    echo "ok: $2"
}

# --- clean ------------------------------------------------------------------
mkdir -p "$tree/usr/share/coastguard-clean"
echo 'nothing to see here' > "$tree/usr/share/coastguard-clean/payload"
clean_rpm=$(build_rpm coastguard-clean 'true')
expect "clean package passes" 0 "$clean_rpm" "$top/report-clean"
check report-clean "clean package has no indicators" '.indicators == []'

# --- EICAR ------------------------------------------------------------------
mkdir -p "$tree/usr/share/coastguard-eicar"
# Assembled at runtime so this repository never contains the test file.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD' \
    '-ANTIVIRUS-TEST-FILE!$H+H*' > "$tree/usr/share/coastguard-eicar/payload"
eicar_rpm=$(build_rpm coastguard-eicar 'echo EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
expect "EICAR package is detected" 1 "$eicar_rpm" "$top/report-eicar"
check report-eicar "ClamAV flags the payload" '.clamav | any(test("payload/.*FOUND$"))'
check report-eicar "YARA flags the payload"   '.yara | any(test(" payload/"))'
check report-eicar "YARA flags the scriptlet" '.yara | any(test(" scriptlets.txt$"))'

# --- nested content -----------------------------------------------------------
# The marker is only reachable by unpacking: once inside a zip, once inside a
# zlib stream embedded in an ELF file, the way Qt compiles resources in.
mkdir -p "$tree/usr/share/cg-nested" "$tree/usr/bin"
python3 -I - "$tree" <<'PY'
import os, sys, zipfile, zlib
tree = sys.argv[1]
marker = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
with zipfile.ZipFile(tree + "/usr/share/cg-nested/data.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("inner/readme.txt", marker * 20 + b" https://zipped.coastguard-selftest.io/x")
blob = zlib.compress(b"import QtQuick 2.0 // " + marker + b" " * 200)
with open(tree + "/usr/bin/cg-nested", "wb") as fh:
    fh.write(b"\x7fELF" + os.urandom(4096) + blob + os.urandom(4096))
PY
nested_rpm=$(build_rpm coastguard-nested 'true')
expect "marker hidden in nested content is detected" 1 "$nested_rpm" "$top/report-nested"
check report-nested "YARA sees inside the zip" '.yara | any(test("nested/.*data.zip.unpacked/"))'
check report-nested "YARA sees the embedded zlib stream" '.yara | any(test("nested/.*cg-nested.carved/"))'
check report-nested "host found inside the zip" \
    '.inspect.network.hosts | any(.host == "zipped.coastguard-selftest.io")'
check report-nested "unpacking is counted" '.nested.archives == 1 and .nested.carved_streams >= 1'

# --- inspection -------------------------------------------------------------
units=$tree/usr/lib/systemd/system
mkdir -p "$tree/usr/share/applications" "$tree/usr/share/cg/qml" \
    "$units/multi-user.target.wants" "$tree/etc/sudoers.d" "$tree/usr/bin"
printf '[Desktop Entry]\nName=Jailed\nExec=/usr/bin/cg\n\n[X-Sailjail]\nPermissions=Internet;Location\nOrganizationName=org.coastguard\nApplicationName=cg\n' \
    > "$tree/usr/share/applications/cg-jailed.desktop"
printf '[Desktop Entry]\nName=Open\nExec=/usr/bin/cg\n\n[X-Sailjail]\nSandboxing=Disabled\n' \
    > "$tree/usr/share/applications/cg-open.desktop"
printf '[Unit]\nDescription=test\n[Service]\nExecStart=/usr/bin/cg --daemon\n[Install]\nWantedBy=multi-user.target\n' \
    > "$units/cg.service"
ln -s ../cg.service "$units/multi-user.target.wants/cg.service"
echo 'fetch("https://telemetry.coastguard-selftest.io/v1"); fetch("http://203.0.113.7:8080/x")' \
    > "$tree/usr/share/cg/qml/main.qml"
echo 'nobody ALL=(ALL) NOPASSWD: ALL' > "$tree/etc/sudoers.d/cg"
# A bulk list: 148 hosts that a public block list knows, and two it does not.
{ for n in $(seq 1 148); do echo "https://ads$n.coastguard-blocklist.test/x"; done
  echo "https://hidden.coastguard-selftest.io/x"; echo "https://own-rule.coastguard-selftest.io/x"; } \
    > "$tree/usr/share/cg/filters.dat"
echo 'fetch("https://c2.coastguard-malware.test/beacon")' > "$tree/usr/share/cg/qml/beacon.qml"
# The developer's answer to one flag, with markup that must not survive.
mkdir -p "$tree/usr/share/coastguard"
echo '{"root-services": "Sets the CPU governor, <b>see</b> [docs](http://x).", "Not An Id": "x"}' \
    > "$tree/usr/share/coastguard/cg.json"
mkdir -p "$tree/etc/sailjail/permissions"
printf 'whitelist ${HOME}/.local/share/cg\nignore seccomp\ndbus-system.talk org.freedesktop.login1\n' \
    > "$tree/etc/sailjail/permissions/cg.profile"
printf '#!/bin/sh\ntrue\n' > "$tree/usr/bin/cg"
chmod 4755 "$tree/usr/bin/cg"
echo 'db = "/home/defaultuser/.local/share/commhistory/commhistory.db"' \
    > "$tree/usr/share/cg/qml/history.qml"
cp -a "$tree" "$top/tree-v1"
inspect_rpm=$(build_rpm coastguard-inspect 'systemctl enable cg.service')
expect "inspection package is not a detection" 0 "$inspect_rpm" "$top/report-inspect"
check report-inspect "indicator rule fires without changing the verdict" \
    '.verdict == "clean" and (.indicators | any(.rule == "Coastguard_Indicator_Reads_Messages_Or_Call_History"))'
i=.inspect
check report-inspect "declared sandbox and its permissions" \
    "$i.sailjail.apps | any(.sandbox == \"declared\" and .permissions == [\"Internet\", \"Location\"])"
check report-inspect "disabled sandbox" "$i.sailjail.apps | any(.sandbox == \"disabled\")"
check report-inspect "root systemd service, enabled twice over" \
    "$i.services.systemd | any(.user == \"root\" and (.enabled_by | length) == 2)"
check report-inspect "setuid binary, and only that one" \
    "$i.privileged_files | map(.path) == [\"/usr/bin/cg\"]"
check report-inspect "sandbox profile: loosening rules found, plain whitelist ignored" \
    "$i.sailjail.profile_loosening | map(.line) == [\"ignore seccomp\", \"dbus-system.talk org.freedesktop.login1\"]"
check report-inspect "sudoers drop-in" "$i.system_integration.sudoers == [\"/etc/sudoers.d/cg\"]"
check report-inspect "scriptlet command" "$i.scriptlets | any(.notable | any(test(\"systemctl\")))"
check report-inspect "host from QML" \
    "$i.network.hosts | any(.host == \"telemetry.coastguard-selftest.io\" and (.in | index(\"script\")))"
check report-inspect "hard-coded IP" "$i.network.notable | any(.why == \"hard-coded IP address\")"
check report-inspect "bulk file: only the two hosts on no public list are named" \
    "$i.network.bulk == [{file: \"/usr/share/cg/filters.dat\", hosts: 150, on_public_lists: 148, unlisted: [\"hidden.coastguard-selftest.io\", \"own-rule.coastguard-selftest.io\"], unlisted_count: 2, known_bad: 0}]"
check report-inspect "bulk hosts stay out of the app's own list" \
    "$i.network.hosts | all(.host | test(\"coastguard-blocklist\") | not)"
check report-inspect "known-malware host in a script" \
    "$i.network.known_bad | map(.host) == [\"c2.coastguard-malware.test\"]"
check report-inspect "developer explanation read, markup stripped, bad key dropped" \
    "$i.explanations == {\"root-services\": \"Sets the CPU governor, b see /b docs http://x .\"}"
# --- comparison with the previous version -----------------------------------
# Version 2 asks for one more permission, talks to a new host, adds a root
# service and changes a file.
sleep 1  # RPM build times have one-second resolution and order the builds
mv "$top/tree-v1" "$tree"
sed -i 's/Permissions=Internet;Location/Permissions=Internet;Location;Contacts/' \
    "$tree/usr/share/applications/cg-jailed.desktop"
echo 'fetch("https://new-host.coastguard-selftest.io/v2")' >> "$tree/usr/share/cg/qml/main.qml"
printf '[Service]\nExecStart=/usr/bin/cg --second\n' > "$units/cg-second.service"
v2_rpm=$(build_rpm coastguard-inspect 'systemctl enable cg.service
systemctl enable cg-second.service' 2)
expect "second version is not a detection" 0 "$v2_rpm" "$top/report-v2"

store=$top/store
python3 -I "$scripts/reputation.py" "$top/report-inspect"
python3 -I "$scripts/store_result.py" "$store" "$top/report-inspect" > /dev/null
python3 -I "$scripts/store_result.py" "$store" "$top/report-v2" > /dev/null
cat "$top/report-v2/final.md"
v2=$store/packages/coastguard-inspect/$(jq -r .sha256 "$top/report-v2/report.json").json
diff_check() { # <label> <jq filter over .diff.changes>
    jq -e ".diff.changes | $2" "$v2" > /dev/null \
        || { echo "FAIL: $1" >&2; jq .diff "$v2" >&2; exit 1; }
    echo "ok: $1"
}
jq -e '.diff == null' "$store/packages/coastguard-inspect/$(jq -r .sha256 "$top/report-inspect/report.json").json" > /dev/null \
    || { echo "FAIL: first version should have no baseline" >&2; exit 1; }
echo "ok: first version has nothing to compare with"
diff_check "diff: new permission" 'any(.area == "permission" and .change == "added" and .item == "Contacts")'
diff_check "diff: new root service" 'any(.area == "systemd unit" and .change == "added" and (.item | endswith("cg-second.service")))'
diff_check "diff: new scriptlet line" 'any(.area == "install scriptlet" and .change == "added" and (.item | test("cg-second")))'
diff_check "diff: new host" 'any(.area == "host" and .change == "added" and .item == "new-host.coastguard-selftest.io")'
diff_check "diff: changed file" 'any(.area == "file" and .change == "changed" and (.item | endswith("main.qml")))'
diff_check "diff: unchanged things stay quiet" 'all(.item != "Internet" and .item != "telemetry.coastguard-selftest.io")'
jq -e '.[0].summary.sandbox == "disabled" and .[0].summary.root_services == 1
       and (.[1].summary.permissions | index("Contacts"))
       and .[1].summary.changes.attention_count >= 4
       and (.[1].summary.changes.attention | any(.item == "Contacts"))' \
    "$store/packages/coastguard-inspect/index.json" > /dev/null \
    || { echo "FAIL: index summary" >&2; jq . "$store/packages/coastguard-inspect/index.json" >&2; exit 1; }
jq -e '.[0].summary.checks == {"clamav": "pass", "yara": "pass", "virustotal": "not run", "malwarebazaar": "not run"}' \
    "$store/packages/coastguard-inspect/index.json" > /dev/null \
    || { echo "FAIL: per-check status" >&2; exit 1; }
echo "ok: index carries a compact summary per build"
report_md=$store/packages/coastguard-inspect/$(jq -r .sha256 "$top/report-v2/report.json").md
grep -q 'high risk' "$report_md" && grep -q 'Changes since' "$report_md" \
    && grep -q 'Sailjail sandbox' "$report_md" \
    && jq -e '.[1].summary.report | endswith(".md")' "$store/packages/coastguard-inspect/index.json" > /dev/null \
    || { echo "FAIL: readable report" >&2; cat "$report_md" >&2; exit 1; }
echo "ok: a readable report page is stored next to each result"
# Risk grade: v1 runs a root service unsandboxed and ships a setuid binary and
# a sudoers file; v2 also newly asks for Contacts. The clean package is low.
jq -e '.[0].summary.risk.grade == "high"
       and (.[0].summary.risk.reasons | any(.level == "high" and (.text | test("Root service and no sandbox"))))
       and (.[0].summary.risk.reasons | any(.level == "high" and (.text | test("sudoers"))))
       and (.[1].summary.risk.reasons | any(.text | test("New permission: Contacts")))' \
    "$store/packages/coastguard-inspect/index.json" > /dev/null \
    || { echo "FAIL: risk grade" >&2; jq '.[].summary.risk' "$store/packages/coastguard-inspect/index.json" >&2; exit 1; }
python3 -I "$scripts/store_result.py" "$store" "$top/report-clean" > /dev/null
jq -e '.[0].summary.risk == {"grade": "low", "reasons": []}' \
    "$store/packages/coastguard-clean/index.json" > /dev/null \
    || { echo "FAIL: clean package should grade low" >&2; jq '.[].summary.risk' "$store/packages/coastguard-clean/index.json" >&2; exit 1; }
jq -e '(.[0].summary.risk.reasons | any(.id == "root-services" and (.explanation | test("CPU governor"))))
       and (.[0].summary.risk.reasons | any(.id == "malware-host" and .level == "high"))
       and (.[0].summary.risk.reasons | all(has("id")))' \
    "$store/packages/coastguard-inspect/index.json" > /dev/null \
    || { echo "FAIL: reason ids and explanations" >&2; jq '.[0].summary.risk' "$store/packages/coastguard-inspect/index.json" >&2; exit 1; }
grep -q "Developer's explanation" "$report_md" && grep -q 'Known-malware check (ClamAV, YARA): nothing recognised' "$report_md" \
    && ! grep -q 'Hash reputation' "$report_md" \
    || { echo "FAIL: report page wording" >&2; cat "$report_md" >&2; exit 1; }
echo "ok: risk grade is high for the privileged package, low for the clean one"
echo "ok: flags carry ids and the developer's explanation; a clean malware check is one line"
jq -e '.reputation.virustotal.status == "not configured"' \
    "$store/packages/coastguard-inspect/$(jq -r .sha256 "$top/report-inspect/report.json").json" > /dev/null \
    || { echo "FAIL: reputation block missing" >&2; exit 1; }
echo "ok: reputation is skipped cleanly without API keys"
# --- intake -----------------------------------------------------------------
# Offline: the OpenRepos file table is parsed, and only URLs on OpenRepos' own
# file store are accepted.
python3 -I - "$scripts" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import intake
row = ('<tr class="odd"><td><span class="file"><img class="file-icon" /> <a href="%s" '
       'type="application/x-redhat-package-manager; length=1">x</a></span></td><td>1 MB</td>'
       '<td>08/10/2026 - 17:32</td> </tr>')
good = "https://openrepos.net/sites/default/files/packages/5903/harbour-x-0.4.8-1.aarch64.rpm"
page = row % good + row % "https://evil.example/sites/default/files/packages/1/x.rpm" \
    + row % "https://openrepos.net/sites/default/files/packages/1/../../x.rpm"
files = intake.parse_files(page)
assert [url for url, _ in files] == [good], files
assert files[0][1] == 1791469920, files  # 17:32 site time is 14:32 UTC
PY
echo "ok: intake parses the file table and rejects foreign URLs"
echo "self-test passed"
